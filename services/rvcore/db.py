"""SQLite (mode WAL) bersama untuk web dan worker: koneksi, transaksi, dan migrasi skema.

Catatan operasional: mode WAL memakai berkas memori-bersama (-shm), jadi basis data HARUS berada
di filesystem lokal host (volume Docker biasa di VPS Linux). Jangan taruh di NFS/SMB/virtiofs.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

# Skema versi 1 (M1). Tabel finding / ai_call / chat_* / build ditambahkan oleh migrasi milestone berikutnya.
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
    # --- v2 (M2): temuan analisis statis + tahap pipeline "analyzing"
    """
    CREATE TABLE finding (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER NOT NULL REFERENCES analysis(id) ON DELETE CASCADE,
        category    TEXT    NOT NULL,
        severity    TEXT    NOT NULL,
        rule_id     TEXT    NOT NULL,
        title       TEXT    NOT NULL,
        description TEXT    NOT NULL DEFAULT '',
        evidence    TEXT    NOT NULL DEFAULT '[]',
        secret      TEXT,
        occurrences INTEGER NOT NULL DEFAULT 1,
        source      TEXT    NOT NULL DEFAULT 'static',
        created_at  REAL    NOT NULL
    );
    CREATE INDEX finding_analysis ON finding(analysis_id, severity);

    INSERT INTO analysis_stage (analysis_id, name, position, status, detail)
        SELECT id, 'analyzing', 3, 'skipped', 'dibuat sebelum M2 - jalankan analisis statis untuk mengisinya'
        FROM analysis
    """,
    # --- v3 (M4): pencatatan panggilan AI + sesi chat
    """
    CREATE TABLE ai_call (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id       INTEGER REFERENCES analysis(id) ON DELETE SET NULL,
        session_id        INTEGER,
        purpose           TEXT    NOT NULL,
        model             TEXT    NOT NULL,
        prompt_tokens     INTEGER NOT NULL DEFAULT 0,
        completion_tokens INTEGER NOT NULL DEFAULT 0,
        cached_tokens     INTEGER NOT NULL DEFAULT 0,
        cost_credits      REAL    NOT NULL DEFAULT 0,
        estimated         INTEGER NOT NULL DEFAULT 0,
        ok                INTEGER NOT NULL DEFAULT 1,
        error             TEXT,
        created_at        REAL    NOT NULL
    );
    CREATE INDEX ai_call_created ON ai_call(created_at);
    CREATE INDEX ai_call_session ON ai_call(session_id);

    CREATE TABLE chat_session (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id  INTEGER NOT NULL REFERENCES analysis(id) ON DELETE CASCADE,
        title        TEXT,
        cost_credits REAL    NOT NULL DEFAULT 0,
        created_at   REAL    NOT NULL,
        updated_at   REAL    NOT NULL
    );
    CREATE INDEX chat_session_analysis ON chat_session(analysis_id);

    CREATE TABLE chat_message (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL REFERENCES chat_session(id) ON DELETE CASCADE,
        role       TEXT    NOT NULL,
        content    TEXT    NOT NULL DEFAULT '',
        tool_calls TEXT,
        citations  TEXT,
        model      TEXT,
        created_at REAL    NOT NULL
    );
    CREATE INDEX chat_message_session ON chat_message(session_id, id)
    """,
    # --- v4: lampiran pengguna + berkas buatan AI (isi berkas ada di disk: /data/files/<analysis_id>/{up,ai}/)
    #   kind  'upload' = lampiran pengguna (path = nama acak di disk, `name` = nama tampilan)
    #         'ai'     = dibuat AI lewat write_file (path = path relatif di folder ai/, mis. frida/hook.js)
    #   pending=1: sudah diunggah tetapi belum dikirim bersama pesan; yang menggantung lama dibersihkan.
    #   message_file mengaitkan berkas dengan pesan: 'attachment' (pesan pengguna) / 'output' (jawaban AI).
    """
    CREATE TABLE analysis_file (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER NOT NULL REFERENCES analysis(id) ON DELETE CASCADE,
        kind        TEXT    NOT NULL CHECK (kind IN ('upload', 'ai')),
        path        TEXT    NOT NULL,
        name        TEXT    NOT NULL,
        media       TEXT    NOT NULL DEFAULT 'binary' CHECK (media IN ('image', 'text', 'binary')),
        mime        TEXT    NOT NULL DEFAULT '',
        size        INTEGER NOT NULL DEFAULT 0,
        sha256      TEXT    NOT NULL DEFAULT '',
        revision    INTEGER NOT NULL DEFAULT 1,
        pending     INTEGER NOT NULL DEFAULT 0,
        created_at  REAL    NOT NULL,
        updated_at  REAL    NOT NULL
    );
    CREATE UNIQUE INDEX analysis_file_path ON analysis_file(analysis_id, kind, path);
    CREATE INDEX analysis_file_list ON analysis_file(analysis_id, kind, id);

    CREATE TABLE message_file (
        message_id INTEGER NOT NULL REFERENCES chat_message(id) ON DELETE CASCADE,
        file_id    INTEGER NOT NULL REFERENCES analysis_file(id) ON DELETE CASCADE,
        role       TEXT    NOT NULL CHECK (role IN ('attachment', 'output')),
        revision   INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (message_id, file_id)
    );
    CREATE INDEX message_file_file ON message_file(file_id)
    """,
    # --- v5 (B-1c): permintaan build APK + persetujuan manual (isi artefak ada di disk: /data/builds/<analysis_id>/<build_id>/)
    #   status  : awaiting_approval -> approved -> queued -> building -> signing -> done; cabang rejected / failed / cancelled
    #             (tabel transisi yang sah ada di rvcore.store.BUILD_TRANSITIONS; semua perubahan status lewat fungsi store)
    #   diff_sha256 = hash diff yang DISETUJUI; 'approved' dan seterusnya wajib membawa bukti persetujuan (approved_at + hash/versi
    #   pernyataan wewenang), 'done' wajib verify_ok=1 + seluruh kolom keluaran. CHECK boleh dipakai di sini karena tabel baru.
    #   Indeks unik parsial: paling banyak SATU build aktif (belum final) per analisis, ditegakkan DB (bukan hanya SELECT-lalu-INSERT).
    #   ON DELETE CASCADE: hapus analisis/apk menghapus baris build; DIREKTORI artefak build dihapus Tahap 2 (bukan di sini).
    #   Catatan aturan migrasi: tanpa ';' selain pemisah pernyataan, tanpa trigger, tanpa komentar SQL (_split_statements memecah di ';').
    """
    CREATE TABLE build (
        id                         INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id                INTEGER NOT NULL REFERENCES analysis(id) ON DELETE CASCADE,
        status                     TEXT    NOT NULL DEFAULT 'awaiting_approval'
            CHECK (status IN ('awaiting_approval', 'approved', 'queued', 'building', 'signing',
                              'done', 'rejected', 'failed', 'cancelled')),
        requested_by               TEXT    NOT NULL
            CHECK (length(requested_by) <= 40 AND (requested_by = 'user' OR requested_by GLOB 'ai:[0-9]*')),
        source_kind                TEXT    NOT NULL CHECK (source_kind IN ('apk', 'xapk', 'apks')),
        diff_sha256                TEXT    NOT NULL
            CHECK (length(diff_sha256) = 64 AND diff_sha256 NOT GLOB '*[^0-9a-f]*'),
        diff_summary               TEXT    NOT NULL DEFAULT '{}' CHECK (length(diff_summary) <= 8192),
        note                       TEXT    NOT NULL DEFAULT '' CHECK (length(note) <= 2000),
        created_at                 REAL    NOT NULL,
        updated_at                 REAL    NOT NULL,
        approved_at                REAL,
        approval_statement_sha256  TEXT
            CHECK (approval_statement_sha256 IS NULL OR (length(approval_statement_sha256) = 64
                   AND approval_statement_sha256 NOT GLOB '*[^0-9a-f]*')),
        approval_statement_version INTEGER CHECK (approval_statement_version IS NULL OR approval_statement_version >= 1),
        rejected_reason            TEXT    CHECK (rejected_reason IS NULL OR length(rejected_reason) <= 500),
        started_at                 REAL,
        finished_at                REAL,
        error_code                 TEXT    CHECK (error_code IS NULL OR length(error_code) <= 40),
        error_text                 TEXT    CHECK (error_text IS NULL OR length(error_text) <= 500),
        cancel_requested           INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0, 1)),
        output_name                TEXT    CHECK (output_name IS NULL OR length(output_name) <= 120),
        output_sha256              TEXT
            CHECK (output_sha256 IS NULL OR (length(output_sha256) = 64 AND output_sha256 NOT GLOB '*[^0-9a-f]*')),
        output_size                INTEGER CHECK (output_size IS NULL OR output_size >= 0),
        output_format              TEXT    CHECK (output_format IS NULL OR output_format IN ('apk', 'xapk', 'apks')),
        cert_sha256                TEXT
            CHECK (cert_sha256 IS NULL OR (length(cert_sha256) = 64 AND cert_sha256 NOT GLOB '*[^0-9a-f]*')),
        verify_ok                  INTEGER CHECK (verify_ok IS NULL OR verify_ok IN (0, 1)),
        stage_log                  TEXT    CHECK (stage_log IS NULL OR length(stage_log) <= 4000),
        CHECK (status NOT IN ('approved', 'queued', 'building', 'signing', 'done')
               OR (approved_at IS NOT NULL AND approval_statement_sha256 IS NOT NULL
                   AND approval_statement_version IS NOT NULL)),
        CHECK (status <> 'done'
               OR (COALESCE(verify_ok, 0) = 1 AND output_name IS NOT NULL AND output_sha256 IS NOT NULL
                   AND output_size IS NOT NULL AND output_format IS NOT NULL AND cert_sha256 IS NOT NULL)),
        CHECK (output_format IS NULL OR output_format = source_kind)
    );
    CREATE INDEX build_analysis ON build(analysis_id, id DESC);
    CREATE INDEX build_status ON build(status);
    CREATE UNIQUE INDEX build_one_open_per_analysis ON build(analysis_id)
        WHERE status IN ('awaiting_approval', 'approved', 'queued', 'building', 'signing')
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
