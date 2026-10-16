"""FEAT E: NB-2 (analisis ulang/hapus ditolak selama ada build aktif), `approve_build(via=...)`, hapus `builds/` + `bench/` saat analisis dihapus, dan
penjaga "AI tidak punya jalan ke approve/sign/download" (G-AI).

Ada dua jenis bukti: (1) store dengan DB sementara (`Rig`), (2) lapisan web dengan DB/layout konteks `conftest` (rute `retry`, `_delete`, `plan_decompile`), termasuk
proses uid 10001 NYATA (setpriv) yang menghapus pohon `builds/<id>` berisi direktori mode 000 dan berkas 444 (pelajaran 3: jangan menyimpulkan dari skenario pemilik-sama).
Tidak dibuktikan di sini: volume/kontainer Docker nyata.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from contextlib import closing
from pathlib import Path

import pytest
from build_rig import Rig, plant_symlink, victim, victim_intact
from conftest import ROOT, as_user, need_uid, open_to_10001
from rvcore import store
from web_rig import ctx_analysis, ctx_build

SERVICES = ROOT / "services"
ACTIVE = ["awaiting_approval", "approved", "queued", "building", "signing"]
FINAL = ["done", "failed", "cancelled", "rejected"]


@pytest.fixture
def rig(tmp_path):
    r = Rig(tmp_path)
    yield r
    r.stop()


def make_build(rig: Rig, aid: int, status: str) -> int:
    """Build dengan status tepat `status` lewat fungsi store yang sah (tanpa SQL langsung)."""
    if status == "rejected":
        bid = rig.build(aid, upto="awaiting_approval")
        conn = rig.conn()
        store.reject_build(conn, bid, "tidak")
        conn.close()
        return bid
    if status in ("done", "failed", "cancelled"):
        return rig.final_build(aid, status, make_dir=False)
    bid = rig.build(aid, upto={"awaiting_approval": "awaiting_approval", "approved": "approved"}.get(status, "queued"))
    conn = rig.conn()
    try:
        if status in ("building", "signing"):
            assert store.claim_build(conn, bid)
        if status == "signing":
            store.mark_signing(conn, bid)
    finally:
        conn.close()
    assert rig.row(bid)["status"] == status
    return bid


# ====================================================================================== NB-2 di store
@pytest.mark.parametrize("status", ACTIVE)
def test_full_reset_is_refused_while_a_build_is_active(rig, status):
    aid = rig.analysis()
    make_build(rig, aid, status)
    conn = rig.conn()
    assert store.reset_for_retry(conn, aid) is False
    assert store.get_analysis(conn, aid)["status"] == store.DONE, "analisis tidak boleh disentuh sama sekali oleh reset yang ditolak"
    assert conn.execute("SELECT COUNT(*) FROM analysis_stage WHERE analysis_id = ? AND status = 'ok'", (aid,)).fetchone()[0] >= 1
    conn.close()


@pytest.mark.parametrize("status", ACTIVE)
def test_static_only_reset_is_still_accepted_with_an_active_build(rig, status):
    """A-09 (a): `only_stage='analyzing'` tidak menghapus apktool/ (store.py), jadi tetap boleh."""
    aid = rig.analysis()
    make_build(rig, aid, status)
    conn = rig.conn()
    assert store.reset_for_retry(conn, aid, only_stage="analyzing") is True
    assert store.get_analysis(conn, aid)["status"] == store.QUEUED
    conn.close()


@pytest.mark.parametrize("status", ACTIVE)
def test_delete_apk_is_refused_while_a_build_is_active(rig, status):
    aid = rig.analysis()
    make_build(rig, aid, status)
    conn = rig.conn()
    apk_id = store.get_analysis(conn, aid)["apk_id"]
    assert store.delete_apk(conn, apk_id) is None
    assert store.get_analysis(conn, aid) is not None and store.get_build(conn, rig_first_build(conn, aid)) is not None
    conn.close()


def rig_first_build(conn, aid: int) -> int:
    return conn.execute("SELECT MIN(id) FROM build WHERE analysis_id = ?", (aid,)).fetchone()[0]


@pytest.mark.parametrize("status", FINAL)
def test_a_final_build_does_not_block_reset_or_delete(rig, status):
    aid = rig.analysis()
    make_build(rig, aid, status)
    conn = rig.conn()
    assert store.reset_for_retry(conn, aid) is True
    assert store.finish_analysis(conn, aid, store.DONE)
    apk_id = store.get_analysis(conn, aid)["apk_id"]
    assert store.delete_apk(conn, apk_id) == [aid]
    assert conn.execute("SELECT COUNT(*) FROM build WHERE analysis_id = ?", (aid,)).fetchone()[0] == 0, "CASCADE menghapus baris build final"
    conn.close()


def test_an_active_build_of_another_analysis_does_not_block(rig):
    a, b = rig.analysis(), rig.analysis()
    make_build(rig, a, "queued")
    conn = rig.conn()
    assert store.reset_for_retry(conn, b) is True
    assert store.delete_apk(conn, store.get_analysis(conn, b)["apk_id"]) is None, "analisis b sendiri sedang antre setelah reset"
    assert store.finish_analysis(conn, b, store.DONE)
    assert store.delete_apk(conn, store.get_analysis(conn, b)["apk_id"]) == [b]
    conn.close()


def test_the_nb2_check_and_the_reset_are_one_transaction(rig):
    """Penjaga ada DI DALAM transaksi pembaruan analisis: AST `reset_for_retry`/`delete_apk` memeriksa build aktif sebelum UPDATE/DELETE pertama (BEGIN IMMEDIATE)."""
    tree = ast.parse((SERVICES / "rvcore" / "store.py").read_text(encoding="utf-8"))
    for fn in ("reset_for_retry", "delete_apk"):
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == fn)
        src = ast.unparse(node)
        assert "active_build" in src or "BUILD_ACTIVE" in src, fn


# ====================================================================================== approve_build(via=...)
def audit_rows(rig: Rig, action: str) -> list[dict]:
    conn = rig.conn()
    try:
        return [json.loads(r["detail"]) for r in conn.execute("SELECT detail FROM audit_log WHERE action = ?", (action,))]
    finally:
        conn.close()


def approve(rig: Rig, bid: int, **kw):
    conn = rig.conn()
    try:
        diff = store.get_build(conn, bid)["diff_sha256"]
        store.approve_build(conn, bid, diff_sha256=diff, statement_sha256=store.approval_statement_sha256(), statement_version=1, **kw)
    finally:
        conn.close()


def test_approve_via_cli_is_recorded_in_the_audit_detail(rig):
    bid = rig.build(rig.analysis(), upto="awaiting_approval")
    approve(rig, bid, via="cli")
    assert audit_rows(rig, "build_approved")[0]["via"] == "cli"


def test_approve_via_defaults_to_ui(rig):
    bid = rig.build(rig.analysis(), upto="awaiting_approval")
    approve(rig, bid)
    assert audit_rows(rig, "build_approved")[0]["via"] == "ui"


@pytest.mark.parametrize("via", ["", "CLI", "api", "ai", None, 1, "cli ", "ui\n"])
def test_approve_via_outside_the_fixed_list_is_an_input_error_and_changes_nothing(rig, via):
    bid = rig.build(rig.analysis(), upto="awaiting_approval")
    with pytest.raises(store.BuildInputError):
        approve(rig, bid, via=via)
    assert rig.row(bid)["status"] == "awaiting_approval" and audit_rows(rig, "build_approved") == []


# ====================================================================================== G-AI: AI tidak punya jalan ke approve/sign/download
def test_ai_tools_registry_is_unchanged_and_has_nothing_about_approve_build_or_sign():
    from app.ai import tools
    assert set(tools.TOOLS) == {"class_info", "edit_file", "find_callees", "find_paths", "find_xrefs", "get_class", "get_findings", "get_manifest", "get_method",
                                "get_overview", "list_classes", "list_dir", "list_files", "list_packages", "list_strings", "read_file", "search_code", "shell_run",
                                "view_image", "write_file", "bench_diff", "request_build", "get_build_status"}
    assert not [k for k in tools.TOOLS if re.search(r"approve|sign|download|cancel|delete|artifact|init", k)]
    assert {k for k in tools.TOOLS if "build" in k or "diff" in k} == {"bench_diff", "request_build", "get_build_status"}


def test_no_ai_module_imports_builds_buildctl_or_enqueue_build():
    bad = []
    for p in (SERVICES / "web" / "app" / "ai").rglob("*.py"):
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                mods = {(node.module or "").split(".")[-1], *(a.name for a in node.names)}
                if mods & {"builds", "buildctl", "enqueue_build"}:
                    bad.append((p.name, ast.unparse(node)))
            elif isinstance(node, ast.Import) and any(a.name.split(".")[-1] in {"builds", "buildctl"} for a in node.names):
                bad.append((p.name, ast.unparse(node)))
    assert not bad, bad


def test_the_web_route_set_is_unchanged_by_feat_e():
    """Tidak ada rute web baru (persetujuan hanya lewat CLI pemilik). Cuplikan: jumlah dan hash himpunan (metode, path); tak ada path yang menyebut build/approve/sign."""
    from app import routes_apk, routes_files, routes_storage
    from app.main import app
    pairs = sorted({(m, r.path) for rt in (routes_apk.router, routes_files.router, routes_storage.router, app.router) for r in rt.routes
                    if hasattr(r, "methods") for m in r.methods})
    assert len(pairs) == 47
    assert hashlib.sha256("\n".join(f"{m} {p}" for m, p in pairs).encode()).hexdigest() == "4808f03a2a5bd393bd24a60477c3a75fe3b7c835e1fa090c82774c4f8de70aa8"
    assert not [p for _m, p in pairs if any(w in p for w in ("build", "approve", "sign", "bench"))]       # (`download` sudah ada untuk berkas pengguna/AI di Tahap 1)


def test_routes_apk_does_not_import_the_build_layer():
    names = {n.module or "" for n in ast.walk(ast.parse((SERVICES / "web" / "app" / "routes_apk.py").read_text(encoding="utf-8"))) if isinstance(n, ast.ImportFrom)}
    assert not {m for m in names if m.endswith("builds") or m.endswith("buildctl")}
    src = (SERVICES / "web" / "app" / "routes_apk.py").read_text(encoding="utf-8")
    assert "app.builds" not in src and "from . import builds" not in src


# ====================================================================================== web: konteks conftest (DB + layout bersama)
def populate(aid: int, bid: int | None = None) -> dict[str, Path]:
    from app import context
    lay = context.layout
    paths = {"work": lay.work_dir(aid) / "apktool", "bench": lay.bench / str(aid) / "project"}
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)
        (p / "f.txt").write_text("isi")
    if bid is not None:
        paths["builds"] = lay.builds / str(aid) / str(bid)
        paths["builds"].mkdir(parents=True, exist_ok=True)
        (paths["builds"] / "build.log").write_text("log")
    return paths


def test_delete_removes_work_bench_and_builds_of_every_analysis():
    from app import routes_apk
    apk_id, aid = ctx_analysis("nb-hapus-semua")
    paths = populate(aid, 7)
    assert routes_apk._delete(apk_id, "uji") == "deleted"
    for name, p in paths.items():
        assert not p.exists(), name
    from app import context
    assert not os.path.lexists(context.layout.builds / str(aid)), "folder <aid> di builds ikut hilang"
    assert not os.path.lexists(context.layout.bench / str(aid))


def test_delete_with_a_running_build_is_busy_and_removes_nothing():
    from app import routes_apk
    for status in ACTIVE:
        apk_id, aid = ctx_analysis(f"nb-hapus-busy-{status}")
        ctx_build(aid, status)
        paths = populate(aid, 3)
        assert routes_apk._delete(apk_id, "uji") == "busy", status
        assert all(p.exists() for p in paths.values()), status


def test_delete_after_the_build_finished_is_accepted():
    from app import context, routes_apk
    apk_id, aid = ctx_analysis("nb-hapus-final")
    bid = ctx_build(aid, "queued")
    with closing(context.db()) as conn:
        assert store.request_cancel_build(conn, bid) == "cancelled"
    paths = populate(aid, bid)
    assert routes_apk._delete(apk_id, "uji") == "deleted" and not any(p.exists() for p in paths.values())


def test_delete_with_builds_aid_replaced_by_a_symlink_only_unlinks_the_link(tmp_path):
    from app import context, routes_apk
    apk_id, aid = ctx_analysis("nb-hapus-symlink")
    korban = victim(tmp_path)
    context.layout.builds.mkdir(parents=True, exist_ok=True)
    plant_symlink(context.layout.builds / str(aid), korban)
    assert routes_apk._delete(apk_id, "uji") == "deleted"
    assert victim_intact(korban), "sasaran symlink tidak boleh disentuh"
    assert not os.path.lexists(context.layout.builds / str(aid))


def test_delete_with_the_builds_root_missing_is_quiet_and_still_cleans_the_rest(tmp_path, monkeypatch, caplog):
    from app import context, routes_apk
    apk_id, aid = ctx_analysis("nb-hapus-tanpa-akar")
    paths = populate(aid)
    monkeypatch.setattr(context.layout, "builds", tmp_path / "tidak-ada")
    with caplog.at_level("ERROR", logger="reverse-apk"):
        assert routes_apk._delete(apk_id, "uji") == "deleted"
    assert not paths["work"].exists() and not paths["bench"].exists()
    assert not [r for r in caplog.records if r.levelname == "ERROR"], "akar builds yang belum ada bukan galat"


def test_one_failed_removal_does_not_stop_the_others(monkeypatch, caplog):
    """`builds/<id>` gagal dihapus (OSError) -> dicatat (log.exception) tetapi bench, upload, dan balasan tetap berjalan."""
    from app import routes_apk
    apk_id, aid = ctx_analysis("nb-hapus-sebagian")
    paths = populate(aid, 9)

    def boom(*_a, **_k):
        raise PermissionError("ditolak")
    monkeypatch.setattr(routes_apk, "rmtree_at", boom)
    with caplog.at_level("ERROR", logger="reverse-apk"):
        assert routes_apk._delete(apk_id, "uji") == "deleted"
    assert paths["builds"].exists(), "yang gagal dihapus tetap ada (yatim R-16, dibersihkan pemilik)"
    assert not paths["bench"].exists() and not paths["work"].exists()
    assert [r for r in caplog.records if "builds" in r.getMessage()], "kegagalan dicatat"


def test_the_busy_reply_of_the_apk_delete_route_is_unchanged(client, seeded):
    apk_id, aid = ctx_analysis("nb-rute-hapus")
    ctx_build(aid, "queued")
    r = client.post(f"/apks/{apk_id}/delete", data={"csrf": seeded.csrf})
    assert r.status_code == 303 and r.headers["location"] == f"/analyses/{aid}?notice=busy"


def test_retry_route_is_busy_with_an_active_build_but_static_rerun_is_accepted(client, seeded):
    from app import routes_apk
    apk_id, aid = ctx_analysis("nb-rute-ulang")
    ctx_build(aid, "awaiting_approval")
    r = client.post(f"/analyses/{aid}/retry", data={"csrf": seeded.csrf})
    assert r.status_code == 303 and r.headers["location"] == f"/analyses/{aid}?notice=busy"
    from app import context
    with closing(context.db()) as conn:
        assert store.get_analysis(conn, aid)["status"] == store.DONE, "reset penuh yang ditolak tidak mengubah analisis"
    assert routes_apk._restart_static(aid, "uji") == "ok"
    with closing(context.db()) as conn:
        assert store.get_analysis(conn, aid)["status"] == store.QUEUED


# ====================================================================================== A-09 (b): Penyimpanan -> "Bersihkan hasil dekompilasi"
def test_decompile_cleanup_is_skipped_while_a_build_is_active():
    from app import context, storage_clean
    for status in ("awaiting_approval", "queued", "building"):
        _apk, aid = ctx_analysis(f"nb-dekompilasi-{status}")
        ctx_build(aid, status)
        for name in storage_clean.DECOMPILE_DIRS:
            (context.layout.work_dir(aid) / name).mkdir(parents=True, exist_ok=True)
            (context.layout.work_dir(aid) / name / "f").write_text("x")
        with closing(context.db()) as conn:
            plan = storage_clean.plan_decompile(context.layout, conn, aid)
        assert plan.items == [], status
        assert any("ada build aktif" in why for _what, why in plan.skipped), (status, plan.skipped)
        assert all((context.layout.work_dir(aid) / n / "f").exists() for n in storage_clean.DECOMPILE_DIRS)


def test_decompile_cleanup_is_offered_again_once_the_build_is_final():
    from app import context, storage_clean
    _apk, aid = ctx_analysis("nb-dekompilasi-final")
    bid = ctx_build(aid, "queued")
    (context.layout.work_dir(aid) / storage_clean.DECOMPILE_DIRS[0]).mkdir(parents=True, exist_ok=True)
    with closing(context.db()) as conn:
        assert store.request_cancel_build(conn, bid) == "cancelled"
        plan = storage_clean.plan_decompile(context.layout, conn, aid)
    assert [i.label for i in plan.items] and not [w for _x, w in plan.skipped if "build aktif" in w]


# ====================================================================================== uid 10001 NYATA (meniru kontainer web)
DRIVER = textwrap.dedent('''
    import json, os, sys
    from contextlib import closing
    from app import context, routes_apk
    from rvcore import store
    from rvcore.db import tx
    context.init_storage()
    lay = context.layout
    with closing(context.db()) as conn, tx(conn):
        apk_id, aid = store.create_apk_with_analysis(conn, sha256="c" * 64, md5="d" * 32, filename="x.apk", size=1, options={})
    with closing(context.db()) as conn:
        store.set_stage(conn, aid, "apktool", store.OK)
        store.finish_analysis(conn, aid, store.DONE)
    b = lay.builds / str(aid) / "1"
    deep = b / "src" / "res" / "values" / "dalam"
    deep.mkdir(parents=True)
    for f in (b / "build.log", b / "src" / "res" / "values" / "strings.xml", deep / "x"):
        pass
    (b / "build.log").write_text("log"); os.chmod(b / "build.log", 0o444)
    (b / "src" / "res" / "values" / "strings.xml").write_text("x"); os.chmod(b / "src" / "res" / "values" / "strings.xml", 0o444)
    (deep / "x").write_text("x")
    os.chmod(deep, 0o000)                                   # direktori tanpa izin apa pun
    os.chmod(b / "src" / "res" / "values", 0o500)           # tanpa izin tulis
    os.chmod(b / "src", 0o555)
    (lay.bench / str(aid) / "project" / "res").mkdir(parents=True)
    (lay.bench / str(aid) / "project" / "res" / "a.xml").write_text("a"); os.chmod(lay.bench / str(aid) / "project" / "res", 0o555)
    (lay.work_dir(aid) / "apktool").mkdir(parents=True)
    res = routes_apk._delete(apk_id, "uji")
    print(json.dumps({"res": res, "builds": os.path.lexists(lay.builds / str(aid)), "bench": os.path.lexists(lay.bench / str(aid)),
                      "work": os.path.lexists(lay.work_dir(aid)), "upload": lay.upload_path("c" * 64).exists()}))
''')


@need_uid
def test_uid10001_web_deletes_a_builds_tree_with_mode000_dirs_and_mode444_files():
    """Tiruan kontainer web: runner (uid 10001) meninggalkan direktori 000 dan berkas 444 di `builds/<id>/<bid>`; `_delete` (uid 10001) harus menghapus semuanya."""
    shared = open_to_10001(Path(tempfile.mkdtemp(prefix="rv-web-")))
    try:
        data = shared / "data"
        data.mkdir()
        for d in (data, shared):
            os.chown(d, 10001, 10001)
        site = next(p for p in sys.path if p.endswith("site-packages") and (Path(p) / "fastapi").is_dir())
        script = shared / "driver.py"
        script.write_text(DRIVER)
        env = {"PYTHONPATH": f"{SERVICES}:{SERVICES / 'web'}:{SERVICES / 'runner'}:{site}", "SECRET_KEY": "test-secret-key-0123456789abcdef0123456789abcdef",
               "DATA_DIR": str(data), "REDIS_URL": "redis://127.0.0.1:1/0", "COOKIE_SECURE": "false"}
        r = subprocess.run(as_user(env, str(script)), capture_output=True, text=True, timeout=120, cwd=str(shared))
        assert r.returncode == 0, (r.stdout, r.stderr[-2000:])
        out = json.loads(r.stdout.splitlines()[-1])
        assert out == {"res": "deleted", "builds": False, "bench": False, "work": False, "upload": False}, out
    finally:
        shutil.rmtree(shared, ignore_errors=True)
