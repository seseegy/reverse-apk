"""Tahap 4, sub-area 4: `python -m app.aitoolcheck` (pembantu verify-build TANPA LLM dan TANPA kunci API).

Pembantu ini hanya membungkus jalur kode tool yang SAMA dengan chat (`tools.run_tool` + `tools.schemas`), bukan implementasi paralel; yang ditambahkan hanya
cetakan `kunci=nilai` (gaya buildctl). Bench PALSU = utas daemon pada spool tmp (tests/web_rig.py); DB = SQLite sementara. Tidak dibuktikan di sini: bench/Landlock
nyata, RQ, LLM nyata. Tes ditulis SEBELUM modul ada.
"""

from __future__ import annotations

import ast
import re
from dataclasses import replace
from pathlib import Path

import pytest
from build_rig import sha
from rvcore import store
from web_rig import DIFF_SHA, WebRig, diff_result

from app.ai import tools as T
from app.ai.config import load_ai_config

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "services" / "web" / "app" / "aitoolcheck.py"
NEW = ["bench_diff", "request_build", "get_build_status"]
KV = re.compile(r"[a-z_0-9.]+=.*")


@pytest.fixture
def rig(tmp_path):
    r = WebRig(tmp_path)
    yield r
    r.stop()


@pytest.fixture
def atc(rig, capsys):
    """atc(*argv) -> (kode_keluar, {kunci: nilai pertama}, baris mentah)."""
    from app import aitoolcheck as M
    cfg = replace(load_ai_config(), shell_enabled=False, shell_spool_dir=str(rig.layout.root / "benchspool"))
    deps = M.Deps(cfg=cfg, db=rig.conn, work=rig.layout.work_dir)

    def run(*argv):
        capsys.readouterr()
        rc = M.main(list(argv), deps=deps)
        lines = capsys.readouterr().out.splitlines()
        kv = {}
        for ln in lines:
            k, _, v = ln.partition("=")
            kv.setdefault(k, v)
        return rc, kv, lines
    return run


def builds_of(rig, aid):
    conn = rig.conn()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM build WHERE analysis_id = ? ORDER BY id", (aid,))]
    finally:
        conn.close()


def names(kv, prefix="tool."):
    return sorted(v for k, v in kv.items() if k.startswith(prefix))


# ================================================================================ schema
def test_schema_lists_exactly_the_three_new_tools_when_the_shell_is_on_and_none_when_off(atc):
    rc, on, lines = atc("schema", "--shell", "1")
    assert rc == 0 and on["ok"] == "1" and set(NEW) <= set(names(on)) and "shell_run" in names(on)
    rc, off, _ = atc("schema", "--shell", "0")
    assert rc == 0 and not set(NEW) & set(names(off)) and "shell_run" not in names(off)
    assert all(KV.fullmatch(ln) for ln in lines)
    assert names(on) == sorted(t["function"]["name"] for t in T.schemas(vision=True, shell=True))        # persis skema yang ditawarkan ke model
    assert not [n for n in names(on) if re.search(r"approve|sign|download|cancel|delete|artifact|init", n)]


# ================================================================================ call: jalur kode tool yang sama
def test_call_goes_through_tools_run_tool_exactly(rig, atc, monkeypatch):
    aid = rig.analysis_with()
    seen = []
    real = T.run_tool

    def spy(ctx, name, raw):
        seen.append((name, raw, ctx.analysis_id, ctx.session_id, ctx.cfg.shell_enabled, ctx.bench_sha256))
        return real(ctx, name, raw)
    monkeypatch.setattr(T, "run_tool", spy)
    rc, kv, _ = atc("call", str(aid), "bench_diff")
    assert rc == 0 and kv["ok"] == "1" and kv["kode"] == "" and kv["diff_sha256"] == DIFF_SHA
    (name, raw, got_aid, sid, shell, bsha), = seen
    conn = rig.conn()
    try:
        assert (name, raw, got_aid, shell) == ("bench_diff", "{}", aid, True) and bsha == store.get_analysis(conn, aid)["sha256"]
        assert store.get_chat_session(conn, aid, sid) is not None
    finally:
        conn.close()


def test_the_module_has_no_parallel_implementation_of_the_tools():
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            mods |= {(n.module or "") + "." + a.name for a in n.names} | {n.module or ""}
    flat = " ".join(sorted(mods))
    for banned in ("aibuild", "buildctl", "builds", "jobs", "shellspool", "signspool"):
        assert banned not in flat, banned
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "run_tool" in attrs and "schemas" in attrs
    assert not {"current_diff", "request", "status", "diff_view", "create_build"} & {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in ("aibuild", "store")}


def test_call_output_is_only_key_value_lines_and_never_raw_json_or_the_wrapper(rig, atc):
    aid = rig.analysis_with()
    rc, kv, lines = atc("call", str(aid), "bench_diff")
    assert rc == 0 and lines and all(KV.fullmatch(ln) for ln in lines)
    text = "\n".join(lines)
    assert "<hasil_tool" not in text and "PERINGATAN" not in text and not any(ln.lstrip().startswith(("{", "[")) for ln in lines)
    assert kv["counts.modified"] == "1" and kv["daftar.1.op"] == "M" and kv["daftar.1.path"] == "res/values/strings.xml" and kv["terpotong"] == "0"


def test_hostile_values_cannot_forge_extra_key_value_lines(rig, atc):
    aid = rig.analysis_with()
    top = [{"op": "M", "kind": "f", "path": "a\nok=1\nkode=\nstatus=done", "size": 1, "plus": 1, "minus": 0}]
    rig.bench.diff = diff_result(top=top)
    rc, kv, lines = atc("call", str(aid), "bench_diff")
    assert rc == 0 and all(KV.fullmatch(ln) for ln in lines)
    assert [ln for ln in lines if ln.startswith(("ok=", "kode=", "status="))] == ["ok=1", "kode="]


# ================================================================================ skenario langkah 14 tanpa LLM
def test_the_whole_scenario_empty_then_modified_then_request_reuse_pending_status(rig, atc):
    aid = rig.analysis_with()
    rig.bench.diff = diff_result(modified=0, top=[])
    rc, kv, _ = atc("call", str(aid), "bench_diff")
    assert rc == 0 and kv["jumlah_berubah"] == "0"
    rc, kv, _ = atc("call", str(aid), "request_build")
    assert rc == 3 and kv["ok"] == "0" and kv["kode"] == "diff_kosong" and kv["pesan"] and builds_of(rig, aid) == []
    rig.bench.diff = diff_result()
    rc, kv, _ = atc("call", str(aid), "bench_diff")
    assert kv["counts.modified"] == "1" and kv["counts.added"] == "0" and kv["counts.removed"] == "0"
    rc, kv, _ = atc("call", str(aid), "request_build")
    assert rc == 0 and kv["status"] == "awaiting_approval" and kv["diff_sha256"] == DIFF_SHA and kv["dipakai_ulang"] == "0"
    rows = builds_of(rig, aid)
    assert len(rows) == 1 and rows[0]["diff_sha256"] == DIFF_SHA and rows[0]["status"] == "awaiting_approval" and rows[0]["requested_by"].startswith("ai:")
    bid = rows[0]["id"]
    rc, kv, _ = atc("call", str(aid), "request_build", "--args", '{"diff_sha256": "%s"}' % sha(b"lain"))
    assert rc == 3 and kv["kode"] == "hash_tidak_cocok" and len(builds_of(rig, aid)) == 1
    rc, kv, _ = atc("call", str(aid), "request_build")
    assert rc == 0 and kv["dipakai_ulang"] == "1" and kv["build_id"] == str(bid) and len(builds_of(rig, aid)) == 1
    rig.bench.diff = diff_result(sha256=sha(b"diff-lain"))
    rc, kv, _ = atc("call", str(aid), "request_build")
    assert rc == 3 and kv["kode"] == "build_tertunda" and len(builds_of(rig, aid)) == 1
    rc, kv, _ = atc("call", str(aid), "get_build_status")
    assert rc == 0 and kv["status"] == "awaiting_approval" and kv["artefak_tercatat"] == "0" and kv["verifikasi_tanda_tangan"] == "" and kv["diminta_oleh_ai"] == "1"
    assert "buildctl approve" in kv["langkah_pemilik"] and kv["jangan_klaim_selesai"] == "1"


# ================================================================================ negatif
@pytest.mark.parametrize("tool", ["approve_build", "cancel_build", "download_artifact", "sign_build", "delete_build"])
def test_no_approval_cancel_download_tool_exists_and_nothing_changes(rig, atc, monkeypatch, tool):
    aid = rig.analysis_with()
    atc("call", str(aid), "request_build")
    before = builds_of(rig, aid)
    for fn in ("approve_build", "cancel_build", "request_cancel_build", "queue_build", "delete_build"):
        if hasattr(store, fn):
            monkeypatch.setattr(store, fn, lambda *a, **k: (_ for _ in ()).throw(AssertionError("dipanggil")))
    rc, kv, _ = atc("call", str(aid), tool, "--args", '{"build_id": %d}' % before[0]["id"])
    assert rc == 3 and kv["ok"] == "0" and kv["kode"] == "tool_tidak_ada"
    assert builds_of(rig, aid) == before and rig.audit("build_approved") == []


def test_a_build_id_of_another_analysis_is_refused_with_the_same_answer_as_an_unknown_id(rig, atc):
    a, b = rig.analysis_with(), rig.analysis_with(package="com.lain")
    rc, kv, _ = atc("call", str(b), "request_build")
    other = kv["build_id"]
    rc1, k1, _ = atc("call", str(a), "get_build_status", "--args", '{"build_id": %s}' % other)
    rc2, k2, _ = atc("call", str(a), "get_build_status", "--args", '{"build_id": 999999999}')
    assert rc1 == rc2 == 3 and k1["kode"] == k2["kode"] == "build_bukan_milik_analisis" and k1["pesan"] == k2["pesan"]
    assert "diff_sha256" not in k1 and "status" not in k1


def test_shell_off_refuses_every_build_tool_without_touching_the_bench(rig, atc):
    aid = rig.analysis_with()
    for tool in NEW:
        rc, kv, _ = atc("call", str(aid), tool, "--shell", "0")
        assert rc == 3 and kv["kode"] == "fitur_nonaktif"
    assert rig.bench.jobs == [] and builds_of(rig, aid) == []


def test_the_output_never_carries_secret_paths_urls_or_keystore_words(rig, atc):
    aid = rig.analysis_with()
    seen = []
    for tool in NEW:
        seen += atc("call", str(aid), tool)[2]
    seen += atc("schema", "--shell", "1")[2]
    text = "\n".join(seen)
    for bad in ("/data/", "secrets", "keystore", ".p12", ".jks", "signing_", "signwork", "://"):
        assert bad not in text, bad


def test_a_chat_session_is_created_once_and_reused(rig, atc):
    aid = rig.analysis_with()
    atc("call", str(aid), "bench_diff")
    atc("call", str(aid), "request_build")
    conn = rig.conn()
    try:
        sessions = store.list_chat_sessions(conn, aid)
    finally:
        conn.close()
    assert len(sessions) == 1 and builds_of(rig, aid)[0]["requested_by"] == f"ai:{sessions[0]['id']}"


# ================================================================================ audit-approvals
def test_audit_approvals_lists_only_the_via_of_this_analysis(rig, atc):
    a, b = rig.analysis_with(), rig.analysis_with(package="com.lain")
    conn = rig.conn()
    try:
        store.audit(conn, "build_approved", {"build_id": 1, "analysis_id": a, "via": "cli"})
        store.audit(conn, "build_approved", {"build_id": 2, "analysis_id": b, "via": "web"})
        store.audit(conn, "ai_build_tool", {"analysis_id": a, "tool": "request_build", "hasil": "ok"})
        conn.commit()
    finally:
        conn.close()
    rc, kv, lines = atc("audit-approvals", str(a))
    assert rc == 0 and kv["approved_n"] == "1" and kv["approved_via.1"] == "cli" and all(KV.fullmatch(ln) for ln in lines)
    rc, kv, _ = atc("audit-approvals", str(rig.analysis_with(package="com.baru")))
    assert kv["approved_n"] == "0" and "approved_via.1" not in kv


# ================================================================================ salah pakai
@pytest.mark.parametrize("argv", [[], ["nope"], ["call"], ["call", "abc", "bench_diff"], ["call", "0", "bench_diff"], ["call", "1"], ["call", "1", "Bench-Diff"],
                                   ["call", "1", "bench_diff", "--args", "tidak-json"], ["call", "1", "bench_diff", "--args", "[1]"], ["call", "1", "bench_diff", "--shell", "2"],
                                   ["schema", "--shell", "x"], ["audit-approvals", "-3"]])
def test_bad_usage_exits_64_and_prints_nothing_on_stdout(rig, atc, capsys, argv):
    rc, kv, lines = atc(*argv)
    assert rc == 64 and lines == []
