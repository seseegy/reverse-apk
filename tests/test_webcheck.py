"""Tahap 5: pembantu `app.webcheck` (verifikasi VPS tanpa browser) diuji terhadap aplikasi NYATA yang dijalankan uvicorn di utas, dengan DB/layout `conftest`.

Dibuktikan: sesi pemilik dari SECRET_KEY diterima aplikasi, halaman build dibaca (hash kolom tersembunyi), persetujuan lewat web meniru formulir (dengan dan tanpa pernyataan),
unduhan dihitung hash isinya, dan keluaran hanya baris `kunci=nilai`. Tidak dibuktikan: kontainer Docker nyata.
"""

from __future__ import annotations

import hashlib
import socket
import threading
import time

import pytest
import uvicorn
from test_web_build_ui import env, mk_build, mk_done, new_analysis, query, status_of  # noqa: F401 - `env` adalah fixture

from app import webcheck
from app.main import app


@pytest.fixture
def server():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    assert srv.started
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    t.join(5)


def run(capsys, base, *args) -> tuple[int, dict[str, str]]:
    code = webcheck.main(["--base", base, *args])
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln]
    assert all("=" in ln and ln.split("=", 1)[0].replace("_", "").isalnum() for ln in lines), out
    return code, dict(ln.split("=", 1) for ln in lines)


def test_get_build_page_reports_the_hidden_hash_and_the_form_parts(server, env, capsys):
    aid = new_analysis("wc-page")
    bid = mk_build(aid)
    h = query("SELECT diff_sha256 FROM build WHERE id = ?", bid)[0][0]
    code, kv = run(capsys, server, "get", f"/analyses/{aid}/build/{bid}")
    assert code == 0 and kv["status"] == "200" and kv["form_diff_sha256"] == h and kv["has_checkbox"] == "1" and kv["has_statement"] == "1" and kv["nosniff"] == "1"


def test_approve_via_the_form_queues_the_build_and_without_the_statement_does_not(server, env, capsys):
    aid = new_analysis("wc-approve")
    bid = mk_build(aid)
    code, kv = run(capsys, server, "approve", str(aid), str(bid), "--no-statement")
    assert kv["status"] == "303" and kv["location"].endswith("notice=pernyataan_wajib") and status_of(bid) == "awaiting_approval"
    code, kv = run(capsys, server, "approve", str(aid), str(bid), "--hash", "0" * 64)
    assert kv["location"].endswith("notice=diff_berubah") and status_of(bid) == "awaiting_approval"
    code, kv = run(capsys, server, "approve", str(aid), str(bid))
    assert code == 0 and kv["location"].endswith("notice=disetujui") and status_of(bid) == "queued"
    row = query("SELECT detail FROM audit_log WHERE action = 'build_approved' ORDER BY id DESC LIMIT 1")[0][0]
    assert '"via": "ui"' in row


def test_download_prints_the_body_hash_and_save_writes_the_file(server, env, capsys, tmp_path):
    aid = new_analysis("wc-download")
    bid, name, payload = mk_done(aid)
    out = tmp_path / "hasil.apk"
    code, kv = run(capsys, server, "get", f"/analyses/{aid}/build/{bid}/download", "--save", str(out))
    assert code == 0 and kv["sha256"] == hashlib.sha256(payload).hexdigest() and int(kv["bytes"]) == len(payload) and out.read_bytes() == payload
    assert kv["content_type"] == "application/vnd.android.package-archive" and name in kv["content_disposition"]
    out.unlink()
    (__import__("app.context", fromlist=["x"]).layout.build_dir(aid, bid) / name).write_bytes(b"lain")
    code, kv = run(capsys, server, "get", f"/analyses/{aid}/build/{bid}/download")
    assert code == 3 and kv["status"] == "409"


def test_post_adds_the_csrf_field_and_usage_errors_are_64(server, env, capsys):
    aid = new_analysis("wc-post")
    bid = mk_build(aid)
    code, kv = run(capsys, server, "post", f"/analyses/{aid}/build/{bid}/cancel")
    assert code == 0 and kv["location"].endswith("notice=dibatalkan") and status_of(bid) == "cancelled"
    assert webcheck.main(["--base", server, "get", "tanpa-garis-miring"]) == 64
    assert webcheck.main(["--base", server, "approve", "x", "y"]) == 64
    assert webcheck.main(["--base", server]) == 64


def test_connection_failure_is_reported_as_a_stable_code(capsys):
    code, kv = run(capsys, "http://127.0.0.1:1", "get", "/healthz")
    assert code == 3 and kv["kode"] == "sambungan_gagal"
