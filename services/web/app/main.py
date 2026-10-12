"""Aplikasi web reverse-apk: login, dashboard APK, upload, status analisis, uji antrean."""

from __future__ import annotations

import asyncio
import logging
import mimetypes
from contextlib import closing

import redis
from fastapi import FastAPI, Form, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import status as system_status
from .context import (
    BASE_DIR,
    client_ip,
    current_session,
    db,
    init_storage,
    limiter,
    redis_conn,
    render,
    sessions,
    set_cookie,
    settings,
)
from .routes_apk import router as apk_router
from .routes_files import router as files_router
from .routes_storage import router as storage_router
from .security import (
    Session,
    new_token,
    tokens_equal,
    verify_password,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("reverse-apk")

# Image slim tidak selalu punya /etc/mime.types lengkap; daftarkan font secara eksplisit.
mimetypes.add_type("font/woff2", ".woff2")

init_storage()  # direktori data + migrasi skema; gagal cepat bila volume tidak bisa ditulis

app = FastAPI(title="reverse-apk", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(apk_router)
app.include_router(files_router)
app.include_router(storage_router)

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
    _apply_security_headers(request, response)
    return response


def _apply_security_headers(request: Request, response: Response) -> None:
    """Dipakai middleware di atas DAN handler galat 500 (yang dijalankan Starlette di luar middleware ini)."""
    h = response.headers
    # Rute boleh memasang CSP yang LEBIH ketat (mis. penyajian berkas pengguna: "default-src 'none'; sandbox"); jangan ditimpa.
    if "content-security-policy" not in h:
        h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    # Jangan menimpa Cache-Control yang sudah ditetapkan rute (SSE memakai "no-store, no-transform").
    if not request.url.path.startswith("/static/") and "cache-control" not in h:
        h["Cache-Control"] = "no-store"


# ---------------------------------------------------------------- halaman galat (BE-12)
# Galat yang terjadi SEBELUM isi rute berjalan (alamat tak dikenal, metode salah, parameter tidak valid) dan galat tak terduga.
# Siapa yang bertanya ditentukan dari header Accept: navigasi browser mengirim text/html dan mendapat halaman; fetch()/EventSource/
# skrip mendapat JSON {"error": ...} seperti respons rute lain (app.js membaca d.error). Rute yang menangani galatnya sendiri tidak
# terpengaruh (mis. /analyses/999999 -> ?notice=not_found, API tanpa sesi -> 401).

ERROR_TEXT: dict[int, tuple[str, str, str]] = {   # status -> (judul halaman, penjelasan, pesan JSON)
    404: ("Halaman tidak ditemukan", "Alamat ini tidak ada di aplikasi. Mungkin salah ketik, atau tautannya sudah lama.", "Tidak ditemukan."),
    405: ("Aksi tidak tersedia", "Alamat ini tidak menerima permintaan seperti itu. Gunakan tombol dan menu di aplikasi.",
          "Metode tidak diizinkan."),
    422: ("Permintaan tidak valid", "Ada bagian alamat yang tidak valid, misalnya teks pencarian terlalu panjang.",
          "Parameter permintaan tidak valid."),
    500: ("Terjadi galat di server", "Permintaan Anda tidak bisa diselesaikan. Kejadiannya tercatat di log server; coba lagi sebentar lagi.",
          "Galat internal server."),
}
GENERIC_ERROR = ("Permintaan tidak bisa diproses", "Server menolak permintaan ini.", "Permintaan tidak bisa diproses.")

# Cadangan bila template halaman galat sendiri ikut gagal dirender (tanpa gaya/skrip inline: tetap patuh CSP).
FALLBACK_500 = ('<!doctype html><html lang="id"><head><meta charset="utf-8"><title>Terjadi galat di server</title></head><body>'
                "<h1>Terjadi galat di server</h1><p>Permintaan Anda tidak bisa diselesaikan. Coba lagi sebentar lagi.</p>"
                '<p><a href="/">Kembali ke beranda</a></p></body></html>')


def _wants_html(request: Request) -> bool:
    return "text/html" in request.headers.get("accept", "")


def _error_response(request: Request, status_code: int, headers: dict | None = None) -> Response:
    heading, message, api_message = ERROR_TEXT.get(status_code, GENERIC_ERROR)
    if not _wants_html(request):
        return JSONResponse({"error": api_message}, status_code=status_code, headers=headers)
    session = current_session(request)
    if session is None and status_code < 500:
        # Belum login: sama seperti setiap halaman lain (dan tidak membocorkan rute mana yang ada). 500 tidak diarahkan, agar
        # halaman login yang rusak tidak berputar ke dirinya sendiri.
        return RedirectResponse("/login", status_code=303)
    try:
        response = render(request, "error.html", {
            "status_code": status_code, "heading": heading, "message": message,
            "user": session.user if session else None, "csrf": session.csrf if session else ""}, status_code)
    except Exception:  # noqa: BLE001 - halaman galat tidak boleh menjadi sumber galat baru
        log.exception("gagal merender halaman galat %s", status_code)
        response = HTMLResponse(FALLBACK_500 if status_code >= 500 else f"<!doctype html><title>{status_code}</title>", status_code)
    for k, v in (headers or {}).items():
        response.headers[k] = v
    return response


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
    """404 (alamat tak dikenal, berkas statis tak ada), 405 (metode salah, header Allow dipertahankan), dan HTTPException lain."""
    return _error_response(request, exc.status_code, exc.headers)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError) -> Response:
    """Parameter tidak valid. Id di PATH yang tidak valid (/analyses/abc, /analyses/0) = data tidak ada, sama seperti id yang tidak ada."""
    if _wants_html(request) and current_session(request) is not None and any((e.get("loc") or ("",))[0] == "path" for e in exc.errors()):
        return RedirectResponse("/?notice=not_found", status_code=303)
    return _error_response(request, 422)


@app.exception_handler(Exception)
async def server_error(request: Request, exc: Exception) -> Response:
    """Galat tak terduga. Starlette menjalankan handler ini DI LUAR middleware, jadi header keamanan dipasang di sini. Galatnya tetap
    diteruskan Starlette ke uvicorn sesudahnya, sehingga traceback lengkap muncul di log server (tidak dicatat dua kali di sini)."""
    response = _error_response(request, 500)
    _apply_security_headers(request, response)
    return response


# ---------------------------------------------------------------- helpers
# client_ip, current_session, set_cookie, render ada di context.py (dipakai bersama routes_apk.py).


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
    """Liveness: proses hidup. Sengaja murah dan tidak menyentuh dependensi (dipakai Caddy `health_uri` dan healthcheck compose)."""
    return JSONResponse({"status": "ok"})


READY_TIMEOUT = 5.0


def _probe_ready() -> None:
    with closing(db()) as conn:
        conn.execute("SELECT 1").fetchone()
    redis_conn.ping()


@app.get("/readyz", include_in_schema=False)
async def readyz() -> JSONResponse:
    """Readiness: SQLite bisa dibuka dan Redis menjawab PING. Publik tanpa sesi seperti /healthz, jadi badannya minimal (tidak menyebut
    komponen mana yang rusak); rincian ada di log server. Sengaja TIDAK dipakai Caddy: saat Redis mati situs tetap harus tampil agar
    kartu Status sistem di dashboard bisa menunjukkan masalahnya, bukan 503 dari proxy."""
    try:
        await asyncio.wait_for(run_in_threadpool(_probe_ready), READY_TIMEOUT)
    except Exception as exc:  # noqa: BLE001 - apa pun yang salah berarti belum siap (termasuk TimeoutError)
        log.warning("readyz gagal: %s", type(exc).__name__)
        return JSONResponse({"status": "unavailable"}, status_code=503)
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


# Dashboard "/" ada di routes_apk.py (daftar APK + status sistem).


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
