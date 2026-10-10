"""SQLite (mode WAL) bersama untuk web dan worker: koneksi, transaksi, dan migrasi skema.

Catatan operasional: mode WAL memakai berkas memori-bersama (-shm), jadi basis data HARUS berada
di filesystem lokal host (volume Docker biasa di VPS Linux). Jangan taruh di NFS/SMB/virtiofs.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

# Skema versi 1 (M1). Tabel finding / ai_call / chat_* ditambahkan oleh migrasi milestone berikutnya.
_MIGRATIONS: list[str] = [
    """
    CREATE TABLE apk (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        sha256           TEXT    NOT NULL UNIQUE,
        md5              TEXT    NOT NULL,
        filename_display TEXT    NOT NULL,
        size             INTEGER NOT NULL,
        package          TEXT,
        app_label        TEXT,
        version_name     TEXT,
        version_code     TEXT,
        min_sdk          TEXT,
        target_sdk       TEXT,
        created_at       REAL    NOT NULL
    );

    CREATE TABLE analysis (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        apk_id           INTEGER NOT NULL REFERENCES apk(id) ON DELETE CASCADE,
        status           TEXT    NOT NULL,
        options          TEXT    NOT NULL DEFAULT '{}',
        ai_enabled       INTEGER NOT NULL DEFAULT 0,
        attempt          INTEGER NOT NULL DEFAULT 1,
        cancel_requested INTEGER NOT NULL DEFAULT 0,
        error_code       TEXT,
        error            TEXT,
        tool_versions    TEXT,
        created_at       REAL    NOT NULL,
        started_at       REAL,
        finished_at      REAL,
        updated_at       REAL    NOT NULL
    );
    CREATE INDEX analysis_apk    ON analysis(apk_id);
    CREATE INDEX analysis_status ON analysis(status);

    CREATE TABLE analysis_stage (
        analysis_id INTEGER NOT NULL REFERENCES analysis(id) ON DELETE CASCADE,
        name        TEXT    NOT NULL,
        position    INTEGER NOT NULL,
        status      TEXT    NOT NULL DEFAULT 'pending',
        detail      TEXT,
        started_at  REAL,
        finished_at REAL,
        PRIMARY KEY (analysis_id, name)
    );

    CREATE TABLE artifact (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER NOT NULL REFERENCES analysis(id) ON DELETE CASCADE,
        kind        TEXT    NOT NULL,
        path        TEXT    NOT NULL,
        size        INTEGER NOT NULL DEFAULT 0,
        files       INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX artifact_analysis ON artifact(analysis_id);

    CREATE TABLE analysis_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER NOT NULL REFERENCES analysis(id) ON DELETE CASCADE,
        ts          REAL    NOT NULL,
        stage       TEXT,
        level       TEXT    NOT NULL,
        message     TEXT    NOT NULL
    );
    CREATE INDEX analysis_log_analysis ON analysis_log(analysis_id, id);

    CREATE TABLE audit_log (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        ts     REAL NOT NULL,
        action TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '{}'
    );
    """,
]

SCHEMA_VERSION = len(_MIGRATIONS)


def connect(path: str | Path) -> sqlite3.Connection:
    """Koneksi baru (autocommit; transaksi eksplisit lewat `tx`). Satu koneksi per thread/tugas."""
    conn = sqlite3.connect(str(path), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


@contextmanager
def tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Transaksi tulis. BEGIN IMMEDIATE mengambil kunci tulis di awal sehingga tidak ada deadlock upgrade."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def migrate(path: str | Path) -> None:
    """Terapkan migrasi yang belum ada. Aman dipanggil bersamaan oleh web dan worker."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        with tx(conn):
            current = conn.execute("PRAGMA user_version").fetchone()[0]
            if current > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Skema DB (v{current}) lebih baru dari kode ini (v{SCHEMA_VERSION}). "
                    "Update kode sebelum menjalankan."
                )
            for version in range(current, SCHEMA_VERSION):
                # executescript() meng-commit sendiri; jalankan per pernyataan agar tetap satu transaksi.
                for statement in _split_statements(_MIGRATIONS[version]):
                    conn.execute(statement)
                conn.execute(f"PRAGMA user_version = {version + 1}")
    finally:
        conn.close()


def _split_statements(script: str) -> list[str]:
    # Skrip migrasi kita sederhana (tanpa trigger/';' di dalam string), jadi pemisahan di ';' aman.
    return [s.strip() for s in script.split(";") if s.strip()]
