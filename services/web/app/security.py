"""Sesi bertanda tangan, CSRF, verifikasi password, dan pembatas percobaan login."""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

_hasher = PasswordHasher()  # argon2id dengan parameter bawaan yang aman
# Hash tiruan agar waktu respons sama baik username benar maupun salah.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(24))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str, *, user_ok: bool) -> bool:
    """Selalu menjalankan satu verifikasi argon2 supaya tidak bocor lewat waktu respons."""
    target = stored_hash if (stored_hash and user_ok) else _DUMMY_HASH
    try:
        ok = _hasher.verify(target, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        ok = False
    return bool(ok and stored_hash and user_ok)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def tokens_equal(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())


@dataclass
class Session:
    user: str
    csrf: str


class SessionManager:
    def __init__(self, secret_key: str, max_age: int) -> None:
        self._s = URLSafeTimedSerializer(secret_key, salt="reverse-apk.session.v1")
        self._max_age = max_age

    def dumps(self, session: Session) -> str:
        return self._s.dumps({"u": session.user, "c": session.csrf})

    def loads(self, cookie: str | None) -> Session | None:
        if not cookie:
            return None
        try:
            data = self._s.loads(cookie, max_age=self._max_age)
            return Session(user=str(data["u"]), csrf=str(data["c"]))
        except (BadSignature, SignatureExpired, KeyError, TypeError):
            return None


class LoginLimiter:
    """Pembatas percobaan gagal per IP (di memori; aplikasi berjalan 1 proses).

    Sengaja per-IP, bukan per-username: pembatas per-username dapat dipakai penyerang
    untuk mengunci pemilik akun. Penundaan tetap pada kegagalan memperlambat tebakan.
    """

    def __init__(self, max_fails: int, window: int, lock: int) -> None:
        self.max_fails = max_fails
        self.window = window
        self.lock = lock
        self._fails: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._mu = threading.Lock()

    def _prune(self, now: float) -> None:
        for ip in [k for k, t in self._locked_until.items() if t <= now]:
            del self._locked_until[ip]
        for ip in list(self._fails):
            self._fails[ip] = [t for t in self._fails[ip] if now - t < self.window]
            if not self._fails[ip]:
                del self._fails[ip]

    def retry_after(self, ip: str) -> int:
        """Detik tersisa sebelum IP boleh mencoba lagi (0 = boleh)."""
        now = time.monotonic()
        with self._mu:
            self._prune(now)
            until = self._locked_until.get(ip, 0.0)
            return max(0, int(until - now + 0.999)) if until > now else 0

    def register_failure(self, ip: str) -> None:
        now = time.monotonic()
        with self._mu:
            self._prune(now)
            hits = self._fails.setdefault(ip, [])
            hits.append(now)
            if len(hits) >= self.max_fails:
                self._locked_until[ip] = now + self.lock
                self._fails.pop(ip, None)

    def register_success(self, ip: str) -> None:
        with self._mu:
            self._fails.pop(ip, None)
            self._locked_until.pop(ip, None)
