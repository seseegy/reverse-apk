"""Lingkungan uji untuk aplikasi web: data di direktori sementara, Redis dan provider AI sengaja TIDAK terjangkau.

Variabel lingkungan HARUS diisi sebelum `app` diimpor: konfigurasi dibaca dan skema DB dibuat saat impor (context.py / main.py).
Tidak ada yang keluar ke jaringan: Redis 127.0.0.1:1 dan AI 127.0.0.1:9 menolak koneksi seketika.
"""

from __future__ import annotations

import hashlib
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
    """Kueri langsung ke DB uji. isolation_level=None (autocommit) WAJIB: tanpa itu DELETE pembersihan fixture ter-rollback saat
    koneksi ditutup, baris biaya menumpuk antar tes, dan hasil tes jadi bergantung urutan."""
    conn = sqlite3.connect(str(context.layout.db_path), isolation_level=None)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def new_analysis(tag: str) -> int:
    """Analisis baru yang bersih (tanpa berkas/sesi chat), agar tes tidak bergantung pada data yang dibuat tes lain."""
    digest = hashlib.sha256(tag.encode()).hexdigest()
    with closing(context.db()) as conn, tx(conn):
        _apk_id, aid = store.create_apk_with_analysis(conn, sha256=digest, md5=digest[:32], filename=f"{tag}.apk", size=1, options={})
    return aid


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


def within_call(seconds: float, fn, *args, **kwargs):
    """Jalankan `fn` di utas; gagal (AssertionError) bila menggantung lebih dari `seconds` (FIFO yang dibuka tanpa O_NONBLOCK, dll.).
    Mengembalikan (hasil, pengecualian|None). Dipakai tes yang menguji berkas tak tepercaya: tes tidak boleh ikut menggantung bila kodenya salah."""
    box: dict = {}

    def target():
        try:
            box["value"] = fn(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001
            box["exc"] = exc

    th = threading.Thread(target=target, daemon=True)
    th.start()
    th.join(seconds)
    assert not th.is_alive(), f"menggantung lebih dari {seconds} detik"
    return box.get("value"), box.get("exc")


# ---------------------------------------------------------------- meniru kontainer: proses uid 10001 NYATA
# Pelajaran 3: jangan menyimpulkan "jalan" dari skenario pemilik-sama. Tes yang menyangkut izin/uid/mount menjalankan kodenya sebagai uid 10001 lewat setpriv
# (dan, bila perlu, di dalam `unshare -m` dengan bind `ro` / tmpfs `noexec`). Dilewati bersih bila bukan root, tanpa setpriv, atau interpreter tak bisa dijalankan uid itu.
import shutil  # noqa: E402
import subprocess  # noqa: E402

SETPRIV, UNSHARE = shutil.which("setpriv"), shutil.which("unshare")
REAL_PY = os.path.realpath(os.path.join(sys.base_prefix, "bin", f"python{sys.version_info.major}.{sys.version_info.minor}"))
PY_LIB = os.path.join(os.path.dirname(os.path.dirname(REAL_PY)), "lib")
CLEAN_ENV = ["env", "-i", "PATH=/usr/bin:/bin", f"LD_LIBRARY_PATH={PY_LIB}", "PYTHONDONTWRITEBYTECODE=1", f"PYTHONPATH={ROOT / 'services'}"]
AS_10001 = [SETPRIV, "--reuid=10001", "--regid=10001", "--clear-groups", *CLEAN_ENV, REAL_PY] if SETPRIV else []


def _can_drop() -> bool:
    if os.geteuid() != 0 or not SETPRIV:
        return False
    try:
        r = subprocess.run([*AS_10001, "-c", "import os, sys; sys.exit(0 if sys.version_info >= (3, 12) and os.getuid() == 10001 else 1)"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


CAN_DROP = _can_drop()
need_uid = pytest.mark.skipif(not CAN_DROP, reason="butuh root + setpriv + interpreter yang bisa dijalankan uid 10001 (izin diabaikan bagi root)")
need_mount = pytest.mark.skipif(not (CAN_DROP and UNSHARE), reason="butuh uid 10001 + unshare -m")


def open_to_10001(path: Path) -> Path:
    """Folder sementara milik root yang bisa dilintasi uid 10001 (tmp_path pytest berizin 0700 dan tak terlintasi)."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o755)
    return path


def as_user(extra: dict[str, str], *argv: str) -> list[str]:
    """Perintah proses uid 10001 dengan environment bersih ditambah `extra` (AS_10001 berakhir dengan interpreter; `env -i` menerima NAMA=nilai sebelum perintah)."""
    return [*AS_10001[:-1], *[f"{k}={v}" for k, v in extra.items()], AS_10001[-1], *argv]
