"""Migrasi skema v5 (tabel `build`): dari DB v4 SUNGGUHAN berisi data, idempoten, atomik, dan strukturnya terkunci.

DB v4 dibuat dari statement `_MIGRATIONS[:4]` yang ASLI (bukan tiruan), lalu diisi di semua tabel v1-v4. Tes memakai DB sendiri
di `tmp_path`, jadi tidak menyentuh DB bersama dari conftest.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from rvcore import db as rvdb
from rvcore import store

COLUMNS = [
    "id", "analysis_id", "status", "requested_by", "source_kind", "diff_sha256", "diff_summary", "note", "created_at",
    "updated_at", "approved_at", "approval_statement_sha256", "approval_statement_version", "rejected_reason", "started_at",
    "finished_at", "error_code", "error_text", "cancel_requested", "output_name", "output_sha256", "output_size",
    "output_format", "cert_sha256", "verify_ok", "stage_log",
]


def make_v4(path: Path) -> None:
    """DB v4 asli: jalankan 4 migrasi pertama persis seperti `migrate()` lalu isi data di SEMUA tabel."""
    conn = rvdb.connect(path)
    try:
        for script in rvdb._MIGRATIONS[:4]:
            for statement in rvdb._split_statements(script):
                conn.execute(statement)
        conn.execute("PRAGMA user_version = 4")
        t = 1700000000.0
        for i, (sha, name) in enumerate((("a" * 64, "satu.apk"), ("b" * 64, "dua.apk")), 1):
            conn.execute("INSERT INTO apk (sha256, md5, filename_display, size, package, created_at) VALUES (?,?,?,?,?,?)",
                         (sha, "m" * 32, name, 1000 * i, f"com.contoh.p{i}", t))
        for apk_id, status in ((1, "done"), (1, "failed"), (2, "queued")):
            conn.execute("INSERT INTO analysis (apk_id, status, created_at, updated_at) VALUES (?,?,?,?)", (apk_id, status, t, t))
        for pos, name in enumerate(("validating", "apktool", "jadx", "analyzing")):
            conn.execute("INSERT INTO analysis_stage (analysis_id, name, position, status) VALUES (1,?,?,'ok')", (name, pos))
        conn.execute("INSERT INTO artifact (analysis_id, kind, path, size, files) VALUES (1,'apktool','apktool',10,2)")
        conn.execute("INSERT INTO analysis_log (analysis_id, ts, stage, level, message) VALUES (1,?, 'apktool','info','mulai')", (t,))
        conn.execute("INSERT INTO finding (analysis_id, category, severity, rule_id, title, created_at) VALUES (1,'manifest','low','r1','T',?)", (t,))
        conn.execute("INSERT INTO ai_call (analysis_id, session_id, purpose, model, created_at) VALUES (NULL, NULL,'chat','m',?)", (t,))
        conn.execute("INSERT INTO ai_call (analysis_id, session_id, purpose, model, created_at) VALUES (1, 1,'chat','m',?)", (t,))
        conn.execute("INSERT INTO chat_session (analysis_id, title, created_at, updated_at) VALUES (1,'s',?,?)", (t, t))
        conn.execute("INSERT INTO chat_message (session_id, role, content, created_at) VALUES (1,'user','halo',?)", (t,))
        conn.execute("INSERT INTO chat_message (session_id, role, content, created_at) VALUES (1,'assistant','hai',?)", (t,))
        conn.execute("INSERT INTO analysis_file (analysis_id, kind, path, name, created_at, updated_at) VALUES (1,'upload','abc','log.txt',?,?)", (t, t))
        conn.execute("INSERT INTO analysis_file (analysis_id, kind, path, name, created_at, updated_at) VALUES (1,'ai','frida/h.js','h.js',?,?)", (t, t))
        conn.execute("INSERT INTO message_file (message_id, file_id, role) VALUES (1,1,'attachment')")
        conn.execute("INSERT INTO message_file (message_id, file_id, role) VALUES (2,2,'output')")
        conn.execute("INSERT INTO audit_log (ts, action, detail) VALUES (?, 'upload', '{}')", (t,))
    finally:
        conn.close()


def snapshot(path: Path) -> dict[str, list[tuple]]:
    conn = sqlite3.connect(str(path))
    try:
        names = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
            "AND name NOT IN ('build', 'ai_setting') ORDER BY name")]   # tabel pasca-v4 (v5 build, v6 ai_setting) tidak dihitung: yang dibuktikan utuh adalah data v1-v4
        return {n: [tuple(r) for r in conn.execute(f"SELECT * FROM {n} ORDER BY rowid")] for n in names}
    finally:
        conn.close()


def master(path: Path) -> list[tuple[str, str, str]]:
    conn = sqlite3.connect(str(path))
    try:
        return [(t, n, re.sub(r"\s+", " ", s or "")) for t, n, s in conn.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")]
    finally:
        conn.close()


def user_version(path: Path) -> int:
    conn = sqlite3.connect(str(path))
    try:
        return conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()


def test_schema_version_is_6():
    assert rvdb.SCHEMA_VERSION == 6 == len(rvdb._MIGRATIONS)


def test_v4_database_with_real_data_migrates_intact(tmp_path):
    path = tmp_path / "v4.sqlite"
    make_v4(path)
    assert user_version(path) == 4
    before = snapshot(path)
    assert before["apk"] and before["analysis"] and before["chat_message"] and before["message_file"] and before["audit_log"]
    assert not any(n == "build" for _t, n, _s in master(path))

    rvdb.migrate(path)

    assert user_version(path) == 6
    assert snapshot(path) == before, "data v1-v4 harus utuh persis setelah migrasi"
    conn = rvdb.connect(path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM build").fetchone()[0] == 0
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        # Data lama langsung bisa dipakai: analisis 1 'done' dengan tahap apktool ok.
        bid = store.create_build(conn, 1, requested_by="ai:1", source_kind="apk", diff_sha256="c" * 64, diff_summary={"files": 1})
        assert store.get_build(conn, bid)["status"] == "awaiting_approval"
        # Analisis 2 (hasil v4) belum selesai -> ditolak dengan pesan yang jelas.
        with pytest.raises(store.BuildStateError, match="belum siap"):
            store.create_build(conn, 3, requested_by="user", source_kind="apk", diff_sha256="c" * 64, diff_summary={})
        conn.execute("DELETE FROM apk WHERE id = 1")
        assert conn.execute("SELECT COUNT(*) FROM build").fetchone()[0] == 0, "hapus apk harus meng-cascade ke build"
    finally:
        conn.close()


def test_migration_is_idempotent(tmp_path):
    path = tmp_path / "v4.sqlite"
    make_v4(path)
    rvdb.migrate(path)
    snap, mast = snapshot(path), master(path)
    for _ in range(2):
        rvdb.migrate(path)
        assert user_version(path) == 6
        assert snapshot(path) == snap and master(path) == mast


def test_fresh_database_equals_stepwise_migrated_schema(tmp_path):
    fresh, stepwise = tmp_path / "fresh.sqlite", tmp_path / "step.sqlite"
    rvdb.migrate(fresh)
    make_v4(stepwise)
    rvdb.migrate(stepwise)
    assert master(fresh) == master(stepwise)
    assert user_version(fresh) == 6


def test_build_table_structure(tmp_path):
    path = tmp_path / "t.sqlite"
    rvdb.migrate(path)
    conn = rvdb.connect(path)
    try:
        info = conn.execute("PRAGMA table_info(build)").fetchall()
        assert [r["name"] for r in info] == COLUMNS and len(COLUMNS) == 26
        by = {r["name"]: r for r in info}
        assert by["status"]["dflt_value"] == "'awaiting_approval'" and by["status"]["notnull"] == 1
        assert by["cancel_requested"]["dflt_value"] == "0" and by["cancel_requested"]["notnull"] == 1
        assert by["verify_ok"]["notnull"] == 0 and by["approved_at"]["notnull"] == 0
        idx = {r[1]: r for r in conn.execute("PRAGMA index_list(build)")}
        assert {"build_analysis", "build_status", "build_one_open_per_analysis"} <= set(idx)
        assert idx["build_one_open_per_analysis"][2] == 1 and idx["build_one_open_per_analysis"][4] == 1   # unik + parsial
        assert [r[2] for r in conn.execute("PRAGMA index_info(build_analysis)")] == ["analysis_id", "id"]
        fk = conn.execute("PRAGMA foreign_key_list(build)").fetchall()
        assert len(fk) == 1 and fk[0]["table"] == "analysis" and fk[0]["on_delete"] == "CASCADE"
    finally:
        conn.close()


def test_newer_schema_is_refused(tmp_path):
    path = tmp_path / "t.sqlite"
    rvdb.migrate(path)
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA user_version = 99")
    conn.close()
    with pytest.raises(RuntimeError, match="lebih baru"):
        rvdb.migrate(path)


def test_v5_follows_migration_string_rules():
    """`_split_statements` memecah di SETIAP ';' (juga di komentar/literal): v5 = 1 tabel + 3 indeks, tanpa trigger."""
    script = rvdb._MIGRATIONS[4]
    statements = rvdb._split_statements(script)
    assert len(statements) == 4
    assert statements[0].startswith("CREATE TABLE build") and all(s.startswith("CREATE") for s in statements)
    assert "TRIGGER" not in script.upper() and "--" not in script


def test_failed_migration_is_atomic(tmp_path, monkeypatch):
    path = tmp_path / "v4.sqlite"
    make_v4(path)
    before = snapshot(path)
    broken = list(rvdb._MIGRATIONS[:4]) + [rvdb._MIGRATIONS[4] + ";\n CREATE TABLE rusak ("]
    monkeypatch.setattr(rvdb, "_MIGRATIONS", broken)
    with pytest.raises(sqlite3.OperationalError):
        rvdb.migrate(path)
    assert user_version(path) == 4
    assert not any(n in ("build", "rusak") for _t, n, _s in master(path)), "tabel build tidak boleh setengah jadi"
    assert snapshot(path) == before
