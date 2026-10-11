"""Log paket AI, audit log aksi berkas/chat, dan /readyz (audit BE-04, BE-05, BE-11; PR #26)."""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from contextlib import closing

import fakeredis
import pytest

import app.main as main_mod
from app import context
from app.ai import chat as ai_chat
from app.ai import tools as T
from app.ai.config import load_ai_config
from app.ai.redact import Redactor
from rvcore import store

from conftest import API_KEY, query, wait_turn_done

AI_LOGGER = "reverse-apk.ai"


def audit(action: str) -> list[dict]:
    return [json.loads(d) for (d,) in query("SELECT detail FROM audit_log WHERE action = ? ORDER BY id", action)]


def tool_ctx(seeded):
    return T.ToolContext(seeded.aid, context.layout.work, load_ai_config(), context.db, Redactor(True), files=context.file_store)


# ================================================================== BE-11 /readyz
@pytest.fixture
def healthy(monkeypatch):
    monkeypatch.setattr(main_mod, "redis_conn", fakeredis.FakeRedis())


def broken_db():
    return sqlite3.connect("/tidak/ada/direktori/x.sqlite")


def test_readyz_ok(anon, healthy):
    r = anon.get("/readyz")                              # tanpa sesi: dipakai untuk pemantauan
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert r.headers["cache-control"] == "no-store" and r.headers["x-content-type-options"] == "nosniff"


def test_readyz_redis_down(anon):
    r = anon.get("/readyz")                              # Redis uji memang tidak terjangkau
    assert r.status_code == 503 and r.json() == {"status": "unavailable"}


def test_readyz_db_broken(anon, healthy, monkeypatch):
    monkeypatch.setattr(main_mod, "db", broken_db)
    r = anon.get("/readyz")
    assert r.status_code == 503 and r.json() == {"status": "unavailable"}   # tanpa menyebut komponen yang rusak


def test_readyz_has_timeout(anon, healthy, monkeypatch):
    monkeypatch.setattr(main_mod, "READY_TIMEOUT", 0.5)
    monkeypatch.setattr(main_mod, "db", lambda: (time.sleep(2), sqlite3.connect(":memory:"))[1])
    t0 = time.monotonic()
    assert anon.get("/readyz").status_code == 503
    assert time.monotonic() - t0 < 1.8


def test_healthz_stays_cheap(anon, monkeypatch):
    monkeypatch.setattr(main_mod, "db", broken_db)
    assert anon.get("/healthz").json() == {"status": "ok"}


# ================================================================== BE-04 logging
def test_provider_failure_logged_without_secrets(client, seeded, json_headers, caplog):
    caplog.set_level(logging.INFO, logger=AI_LOGGER)
    secret_text = "RAHASIA-PESAN-UJI-123"
    sid = client.post(f"/analyses/{seeded.aid}/chat/send", content=json.dumps({"text": secret_text}), headers=json_headers).json()["session_id"]
    turn = wait_turn_done(sid)
    warnings = [r.getMessage() for r in caplog.records if r.name == AI_LOGGER and r.levelno == logging.WARNING]
    assert any("kind=network" in m and f"session={sid}" in m and f"analysis={seeded.aid}" in m and "test-model" in m for m in warnings)
    assert sum("coba ulang" in m for m in warnings) >= 1
    everything = caplog.text
    assert API_KEY not in everything and secret_text not in everything
    assert [d for e, d in turn.log if e == "final"][0]["stopped"] == "error"


def test_unexpected_turn_error_logged(client, seeded, json_headers, caplog, monkeypatch):
    caplog.set_level(logging.INFO, logger=AI_LOGGER)

    def boom(**kw):
        raise RuntimeError(f"meledak {API_KEY}")

    monkeypatch.setattr(ai_chat.agent, "run_turn", boom)
    sid = client.post(f"/analyses/{seeded.aid}/chat/send", content='{"text":"x"}', headers=json_headers).json()["session_id"]
    turn = wait_turn_done(sid)
    errors = [r.getMessage() for r in caplog.records if r.name == AI_LOGGER and r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "RuntimeError" in errors[0] and f"session={sid}" in errors[0] and "chat.py:" in errors[0]
    assert API_KEY not in errors[0] and "[kunci-disembunyikan]" in errors[0]
    assert [d for e, d in turn.log if e == "final"][0]["error"] == "Galat internal (RuntimeError)."    # yang dilihat pengguna tetap


def test_tool_errors_logged(seeded, caplog, monkeypatch):
    caplog.set_level(logging.INFO, logger=AI_LOGGER)
    ctx = tool_ctx(seeded)
    original = T.TOOLS["get_manifest"]

    def bad(ctx_, args):
        raise ValueError(f"rusak {API_KEY}")

    monkeypatch.setitem(T.TOOLS, "get_manifest", (bad, original[1]))
    out, ok = T.run_tool(ctx, "get_manifest", "{}")
    assert not ok and "galat internal tool (ValueError)" in out
    errors = [r.getMessage() for r in caplog.records if r.name == AI_LOGGER and r.levelno == logging.ERROR]
    assert len(errors) == 1 and "get_manifest" in errors[0] and API_KEY not in errors[0]

    caplog.clear()
    out, ok = T.run_tool(ctx, "tool_fiktif", "{}")
    assert not ok
    assert [r.levelno for r in caplog.records if r.name == AI_LOGGER] == [logging.INFO]   # penolakan biasa bukan ERROR


# ================================================================== BE-05 audit log
def test_upload_and_delete_audited(client, seeded):
    up0, del0 = len(audit("file_upload")), len(audit("file_delete"))
    r = client.post(f"/api/files/upload?analysis={seeded.aid}", content=b"hello world isi rahasia",
                    headers={"X-CSRF-Token": seeded.csrf, "X-File-Name": "catatan.txt", "Content-Type": "application/octet-stream"})
    assert r.status_code == 201
    fid = r.json()["id"]
    rows = audit("file_upload")[up0:]
    assert len(rows) == 1
    d = rows[0]
    assert (d["analysis_id"], d["file_id"], d["name"], d["size"]) == (seeded.aid, fid, "catatan.txt", 23)
    assert len(d["sha256"]) == 64 and d["ip"] and "isi rahasia" not in json.dumps(d)

    assert client.post(f"/analyses/{seeded.aid}/files/{fid}/delete", headers={"X-CSRF-Token": seeded.csrf}).json() == {"ok": True}
    rows = audit("file_delete")[del0:]
    assert len(rows) == 1 and rows[0]["file_id"] == fid and rows[0]["kind"] == "upload" and rows[0]["size"] == 23
    assert client.post(f"/analyses/{seeded.aid}/files/{fid}/delete", headers={"X-CSRF-Token": seeded.csrf}).status_code == 404
    assert len(audit("file_delete")) == del0 + 1          # yang sudah tidak ada tidak dicatat lagi


def test_ai_file_writes_audited(seeded):
    fs = context.file_store
    n0 = len(audit("ai_file_write"))
    res = fs.write_ai(seeded.aid, "frida/audit.js", "console.log('isi-rahasia');\n")
    fs.write_ai(seeded.aid, "frida/audit.js", "console.log(2);\n")
    fs.edit_ai(seeded.aid, "frida/audit.js", "console.log(2);", "console.log(3);")
    with pytest.raises(Exception):
        fs.write_ai(seeded.aid, "../luar.py", "x")         # ditolak -> tidak dicatat
    rows = audit("ai_file_write")[n0:]
    assert [(r["revision"], r["created"], r["via"]) for r in rows] == [(1, True, "write_file"), (2, False, "write_file"), (3, False, "edit_file")]
    assert rows[0]["file_id"] == res["id"] and rows[0]["path"] == "frida/audit.js" and len(rows[0]["sha256"]) == 64
    assert "isi-rahasia" not in json.dumps(rows)

    out, ok = T.run_tool(tool_ctx(seeded), "write_file", json.dumps({"path": "laporan/audit.md", "content": "# a\n"}))
    assert ok and audit("ai_file_write")[-1]["path"] == "laporan/audit.md"


def test_chat_session_delete_audited(client, seeded):
    n0 = len(audit("chat_session_delete"))
    with closing(context.db()) as conn:
        sid = store.create_chat_session(conn, seeded.aid, "akan dihapus")
    assert client.post(f"/analyses/{seeded.aid}/chat/{sid}/delete", data={"csrf": "salah"}).status_code == 403
    assert client.post(f"/analyses/{seeded.aid}/chat/{sid}/delete", data={"csrf": seeded.csrf}).status_code == 303
    client.post(f"/analyses/{seeded.aid}/chat/{sid}/delete", data={"csrf": seeded.csrf})        # sudah tidak ada
    rows = audit("chat_session_delete")[n0:]
    assert len(rows) == 1 and rows[0]["session_id"] == sid and rows[0]["analysis_id"] == seeded.aid


def test_audit_failure_never_blocks_user(client, seeded, caplog, monkeypatch):
    def locked(conn, action, detail=None):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "audit", locked)
    r = client.post(f"/api/files/upload?analysis={seeded.aid}", content=b"data",
                    headers={"X-CSRF-Token": seeded.csrf, "X-File-Name": "dua.txt", "Content-Type": "application/octet-stream"})
    assert r.status_code == 201
    assert context.file_store.write_ai(seeded.aid, "catatan/gagal-audit.md", "isi\n")["path"] == "catatan/gagal-audit.md"
    assert sum("gagal mencatat audit" in rec.getMessage() for rec in caplog.records if rec.levelno >= logging.ERROR) >= 2
