"""Lingkungan uji untuk aplikasi web: data di direktori sementara, Redis dan provider AI sengaja TIDAK terjangkau.

Variabel lingkungan HARUS diisi sebelum `app` diimpor: konfigurasi dibaca dan skema DB dibuat saat impor (context.py / main.py).
Tidak ada yang keluar ke jaringan: Redis 127.0.0.1:1 dan AI 127.0.0.1:9 menolak koneksi seketika.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import threading
import time
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = tempfile.mkdtemp(prefix="reverse-apk-test-")
API_KEY = "test-api-key-not-real-0123"

os.environ.update({
    "SECRET_KEY": "test-secret-key-0123456789abcdef0123456789abcdef",
    "COOKIE_SECURE": "false",
    "DATA_DIR": DATA_DIR,
    "ADMIN_PASSWORD_HASH_FILE": os.path.join(DATA_DIR, "admin_password_hash"),
    "REDIS_URL": "redis://127.0.0.1:1/0",
    "AI_BASE_URL": "http://127.0.0.1:9/v1",
    "AI_API_KEY": API_KEY,
    "AI_MODEL": "test-model",
    "AI_MODELS_FILE": str(ROOT / "config" / "ai_models.json"),
    "MIN_FREE_GB": "0",
})
for sub in ("services/web", "services", "services/runner"):     # app, rvcore, analyzer (dipakai redaksi secret)
    sys.path.insert(0, str(ROOT / sub))

from fastapi.testclient import TestClient  # noqa: E402

from app import context  # noqa: E402
from app.ai import chat as ai_chat  # noqa: E402
from app.ai import provider  # noqa: E402
from app.main import app  # noqa: E402
from app.security import Session, new_token  # noqa: E402
from rvcore import store  # noqa: E402
from rvcore.db import tx  # noqa: E402

BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
FETCH = {"Accept": "*/*"}


@pytest.fixture(scope="session")
def seeded() -> SimpleNamespace:
    """Satu APK + analisis, dan sesi login (cookie + token CSRF)."""
    with closing(context.db()) as conn, tx(conn):
        _apk_id, aid = store.create_apk_with_analysis(conn, sha256="a" * 64, md5="b" * 32, filename="uji.apk", size=1, options={})
    csrf = new_token()
    return SimpleNamespace(aid=aid, csrf=csrf, cookie=context.sessions.dumps(Session(user="admin", csrf=csrf)))


@pytest.fixture
def client(seeded) -> TestClient:
    """Klien yang SUDAH login. Galat server dikembalikan sebagai respons (bukan dilempar) agar status 500 bisa diperiksa."""
    c = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
    c.cookies.set(context.settings.session_cookie, seeded.cookie)
    return c


@pytest.fixture
def anon() -> TestClient:
    return TestClient(app, raise_server_exceptions=False, follow_redirects=False)


@pytest.fixture
def json_headers(seeded) -> dict[str, str]:
    return {"X-CSRF-Token": seeded.csrf, "Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def fast_provider_retries(monkeypatch):
    """Provider uji selalu menolak koneksi; tanpa ini tiap giliran chat menunggu ±11 dtk jeda percobaan ulang."""
    monkeypatch.setattr(provider, "RETRY_DELAYS", (0.0, 0.0, 0.0))


@pytest.fixture
def blocking_turns(monkeypatch):
    """Giliran chat yang BERHENTI sampai event di-set: untuk menguji perilaku saat giliran masih berjalan, tanpa bergantung pada waktu."""
    release = threading.Event()

    def run_turn(**kw):
        release.wait(30)
        return ai_chat.agent.TurnResult(content="ok", model="test-model")

    monkeypatch.setattr(ai_chat.agent, "run_turn", run_turn)
    yield release
    release.set()


# ---------------------------------------------------------------- pembantu
def query(sql: str, *params):
    conn = sqlite3.connect(str(context.layout.db_path))
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def wait_for(predicate, timeout: float = 15.0, step: float = 0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    raise AssertionError("kondisi tidak terpenuhi dalam batas waktu")


def wait_turn_done(session_id: int):
    return wait_for(lambda: (t := ai_chat.REGISTRY.get(session_id)) is not None and t.done and t)
