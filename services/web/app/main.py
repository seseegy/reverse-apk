"""Aplikasi web reverse-apk (M0): login, dashboard status, uji antrean."""

from __future__ import annotations

import asyncio
import logging
import mimetypes
from pathlib import Path

import redis
from fastapi import FastAPI, Form, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import status as system_status
from .config import load_settings
from .security import (
    LoginLimiter,
    Session,
    SessionManager,
    new_token,
    tokens_equal,
    verify_password,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("reverse-apk")

# Image slim tidak selalu punya /etc/mime.types lengkap; daftarkan font secara eksplisit.
mimetypes.add_type("font/woff2", ".woff2")

BASE_DIR = Path(__file__).resolve().parent
settings = load_settings()
sessions = SessionManager(settings.secret_key, settings.session_max_age)
limiter = LoginLimiter(settings.login_max_fails, settings.login_window, settings.login_lock)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
redis_conn = redis.Redis.from_url(
    settings.redis_url, socket_connect_timeout=2, socket_timeout=2, health_check_interval=30
)

app = FastAPI(title="reverse-apk", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

if settings.load_password_hash() is None:
    log.warning(
        "Password admin belum diatur (%s). Login akan selalu gagal. Jalankan `make password`.",
        settings.admin_password_hash_file,
    )

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; "
    "frame-ancestors 'none'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    h = response.headers
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    if not request.url.path.startswith("/static/"):
        h["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------- helpers


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def current_session(request: Request) -> Session | None:
    return sessions.loads(request.cookies.get(settings.session_cookie))


def set_cookie(response: Response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )


def render(request: Request, name: str, context: dict, status_code: int = 200) -> Response:
    return templates.TemplateResponse(request, name, context, status_code=status_code)


def login_page(
    request: Request,
    *,
    error: str | None = None,
    username: str = "",
    status_code: int = 200,
    retry_after: int = 0,
) -> Response:
    token = new_token()
    response = render(
        request,
        "login.html",
        {"error": error, "username": username, "csrf": token, "retry_after": retry_after},
        status_code,
    )
    set_cookie(response, settings.login_cookie, token, max_age=1800)
    return response


def format_wait(seconds: int) -> str:
    minutes, secs = divmod(seconds, 60)
    if minutes and secs:
        return f"{minutes} menit {secs} detik"
    if minutes:
        return f"{minutes} menit"
    return f"{secs} detik"


# ---------------------------------------------------------------- routes


@app.get("/healthz", include_in_schema=False)
async def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.get("/robots.txt", include_in_schema=False)
async def robots() -> PlainTextResponse:
    return PlainTextResponse("User-agent: *\nDisallow: /\n")


@app.get("/login", include_in_schema=False)
async def login_get(request: Request) -> Response:
    if current_session(request):
        return RedirectResponse("/", status_code=303)
    return login_page(request)


@app.post("/login", include_in_schema=False)
async def login_post(
    request: Request,
    username: str = Form("", max_length=128),
    password: str = Form("", max_length=1024),
    csrf: str = Form("", max_length=256),
) -> Response:
    ip = client_ip(request)

    if not tokens_equal(request.cookies.get(settings.login_cookie), csrf):
        return login_page(
            request, error="Formulir kedaluwarsa. Silakan coba lagi.", username=username,
            status_code=400,
        )

    wait = limiter.retry_after(ip)
    if wait:
        log.warning("login diblokir sementara ip=%s sisa=%ss", ip, wait)
        return login_page(
            request,
            error=f"Terlalu banyak percobaan gagal. Coba lagi dalam {format_wait(wait)}.",
            username=username,
            status_code=429,
            retry_after=wait,
        )

    stored = settings.load_password_hash()
    user_ok = tokens_equal(username.strip(), settings.admin_username)
    ok = await run_in_threadpool(verify_password, stored, password, user_ok=user_ok)

    if not ok:
        limiter.register_failure(ip)
        log.warning("login gagal ip=%s", ip)
        await asyncio.sleep(0.6)  # memperlambat tebakan beruntun
        return login_page(
            request, error="Username atau password salah.", username=username, status_code=401
        )

    limiter.register_success(ip)
    log.info("login berhasil ip=%s", ip)
    session = Session(user=settings.admin_username, csrf=new_token())
    response = RedirectResponse("/", status_code=303)
    set_cookie(response, settings.session_cookie, sessions.dumps(session), settings.session_max_age)
    response.delete_cookie(settings.login_cookie, path="/")
    return response


@app.post("/logout", include_in_schema=False)
async def logout(request: Request, csrf: str = Form("", max_length=256)) -> Response:
    session = current_session(request)
    if session and tokens_equal(session.csrf, csrf):
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(settings.session_cookie, path="/")
        return response
    return RedirectResponse("/login" if not session else "/", status_code=303)


@app.get("/", include_in_schema=False)
async def dashboard(request: Request) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    status = await run_in_threadpool(
        system_status.collect, redis_conn, settings.data_dir, settings.disk_warn_percent
    )
    return render(
        request,
        "dashboard.html",
        {"user": session.user, "csrf": session.csrf, "status": status},
    )


@app.post("/selftest", include_in_schema=False)
async def selftest(request: Request, csrf: str = Form("", max_length=256)) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if not tokens_equal(session.csrf, csrf):
        return PlainTextResponse("CSRF token tidak valid", status_code=403)
    try:
        await run_in_threadpool(system_status.enqueue_selftest, redis_conn)
    except redis.RedisError:
        log.exception("gagal mengantre selftest")
    return RedirectResponse("/", status_code=303)
