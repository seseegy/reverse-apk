"""Konfigurasi aplikasi dari environment. Gagal cepat bila konfigurasi tidak aman."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

log = logging.getLogger("reverse-apk.config")

MIN_SECRET_LEN = 32


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return int(raw)


@dataclass(frozen=True)
class Settings:
    secret_key: str
    admin_username: str
    admin_password_hash_file: Path
    redis_url: str
    data_dir: Path
    cookie_secure: bool
    session_max_age: int
    login_max_fails: int
    login_window: int
    login_lock: int
    disk_warn_percent: int

    @property
    def session_cookie(self) -> str:
        # Prefiks __Host- mewajibkan Secure + Path=/ + tanpa Domain (hanya valid via HTTPS).
        return "__Host-rv_session" if self.cookie_secure else "rv_session"

    @property
    def login_cookie(self) -> str:
        return "__Host-rv_login" if self.cookie_secure else "rv_login"

    def load_password_hash(self) -> str | None:
        try:
            value = self.admin_password_hash_file.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return None
        return value or None


def load_settings() -> Settings:
    secret = os.environ.get("SECRET_KEY", "")
    if len(secret) < MIN_SECRET_LEN:
        raise RuntimeError(
            f"SECRET_KEY wajib diisi dan minimal {MIN_SECRET_LEN} karakter. "
            "Jalankan `make init` untuk membuatnya."
        )

    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        host = os.environ.get("REDIS_HOST", "redis")
        port = os.environ.get("REDIS_PORT", "6379")
        password = os.environ.get("REDIS_PASSWORD", "")
        auth = f":{quote(password, safe='')}@" if password else ""
        redis_url = f"redis://{auth}{host}:{port}/0"

    return Settings(
        secret_key=secret,
        admin_username=os.environ.get("ADMIN_USERNAME", "admin").strip() or "admin",
        admin_password_hash_file=Path(
            os.environ.get("ADMIN_PASSWORD_HASH_FILE", "/run/secrets/admin_password_hash")
        ),
        redis_url=redis_url,
        data_dir=Path(os.environ.get("DATA_DIR", "/data")),
        cookie_secure=_bool("COOKIE_SECURE", True),
        session_max_age=_int("SESSION_MAX_AGE", 12 * 3600),
        login_max_fails=_int("LOGIN_MAX_FAILS", 5),
        login_window=_int("LOGIN_WINDOW", 15 * 60),
        login_lock=_int("LOGIN_LOCK", 15 * 60),
        disk_warn_percent=_int("DISK_WARN_PERCENT", 80),
    )
