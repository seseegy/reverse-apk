"""Objek bersama aplikasi (konfigurasi, sesi, templates, Redis, tata letak data) dan helper tampilan.

Dipisah dari main.py supaya modul rute (routes_apk.py) bisa memakainya tanpa import melingkar.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import redis
from fastapi import Request
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from rvcore import db as rvdb
from rvcore import store
from rvcore.paths import Layout

from .config import load_settings
from .security import LoginLimiter, Session, SessionManager

log = logging.getLogger("reverse-apk")

BASE_DIR = Path(__file__).resolve().parent

settings = load_settings()
sessions = SessionManager(settings.secret_key, settings.session_max_age)
limiter = LoginLimiter(settings.login_max_fails, settings.login_window, settings.login_lock)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
redis_conn = redis.Redis.from_url(
    settings.redis_url, socket_connect_timeout=2, socket_timeout=2, health_check_interval=30
)
layout = Layout(settings.data_dir)

STALE_TMP_SECONDS = 3600


def init_storage() -> None:
    """Siapkan direktori + skema DB. Dipanggil sekali saat startup; gagal cepat bila volume tak bisa ditulis."""
    for d in (layout.uploads, layout.uploads_tmp, layout.work, layout.db_dir):
        d.mkdir(parents=True, exist_ok=True)
    rvdb.migrate(layout.db_path)
    # Sisa unggahan yang terputus (proses mati di tengah jalan).
    cutoff = time.time() - STALE_TMP_SECONDS
    for p in layout.uploads_tmp.iterdir():
        try:
            if p.is_file() and p.stat().st_mtime < cutoff:
                p.unlink()
        except OSError:
            pass


def db():
    """Koneksi SQLite baru. Pemanggil bertanggung jawab menutupnya (gunakan `with closing(db())`)."""
    return rvdb.connect(layout.db_path)


# ---------------------------------------------------------------- sesi & respons


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


# ---------------------------------------------------------------- format tampilan


def fmt_bytes(n: int | float | None) -> str:
    if n is None:
        return "–"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def fmt_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "–"
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h} j {m} m"
    if m:
        return f"{m} m {sec} d"
    return f"{sec} d"


def iso_utc(ts: float | None) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fmt_utc(ts: float | None) -> str:
    if ts is None:
        return "–"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def fmt_hms(ts: float | None) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")


def code_url(analysis_id: int, file: str | None, line: int | None = None) -> str | None:
    """Tautan ke penampil kode untuk path relatif terhadap work/<id>/ (mis. 'jadx/sources/com/x/A.java')."""
    from urllib.parse import quote

    if not file:
        return None
    for prefix, root in (("jadx/sources/", "java"), ("jadx/resources/", "jres"), ("apktool/", "smali")):
        if file.startswith(prefix):
            q = f"?root={root}&path={quote(file[len(prefix):], safe='/')}"
            if line:
                q += f"&line={int(line)}"
            return f"/analyses/{int(analysis_id)}/code{q}"
    return None


templates.env.globals["code_url"] = code_url
templates.env.filters["bytes"] = fmt_bytes
templates.env.filters["duration"] = fmt_duration
templates.env.filters["isoutc"] = iso_utc
templates.env.filters["utc"] = fmt_utc
templates.env.filters["hms"] = fmt_hms
templates.env.globals["STATUS_LABEL"] = store.STATUS_LABEL
templates.env.globals["STATE_LABEL"] = store.STATE_LABEL
