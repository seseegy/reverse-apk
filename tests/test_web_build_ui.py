"""Tahap 5: rute web build (`app/routes_build.py`): tab Build, LAYAR PERSETUJUAN, aksi POST (CSRF), polling status, dan unduhan salin-lalu-hash-lalu-bandingkan.

Klien uji = TestClient atas aplikasi NYATA dengan DB/layout sementara dari `conftest`. Bench palsu (utas daemon, protokol spool nyata) dan Redis palsu (`fakeredis`, RQ nyata)
disuntik lewat `routes_build._deps`. Tidak dibuktikan di sini: browser nyata, bench/runner/signer/Redis nyata, Docker.
"""

from __future__ import annotations

import ast
import hashlib
import itertools
import json
import os
import re
import time
from contextlib import closing
from types import SimpleNamespace

import pytest
from conftest import BROWSER, FETCH, ROOT, query
from rvcore import shellspool, store
from web_rig import DIFF_SHA, FakeBench, diff_result, live_redis

from app import builds, context, routes_build

OWNER_CERT = "c" * 64


def sha(data: bytes | str) -> str:
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


@pytest.fixture
def env(monkeypatch):
    bench = FakeBench(context.layout.root).__enter__()
    r = live_redis()
    deps = builds.Deps(layout=context.layout, db=context.db, redis=r, bench_spool=shellspool.make_spool(context.layout.root / "benchspool"),
                       op_pickup_timeout=3.0, poll=0.02, job_timeout=3300)
    monkeypatch.setattr(routes_build, "_deps", lambda: deps)
    yield SimpleNamespace(bench=bench, redis=r, deps=deps)
    bench.__exit__(None, None, None)


_COUNTER = itertools.count(1)


def new_analysis(tag: str) -> int:
    """Analisis `done` baru yang bersih; penghitung membuat tag unik meski tes diparametrisasi atau dijalankan ulang."""
    from web_rig import ctx_analysis
    return ctx_analysis(f"{tag}-{next(_COUNTER)}")[1]


def summary(top=None, **over) -> dict:
    data = {"v": 1, "counts": {"added": 1, "modified": 2, "removed": 0}, "bytes": {"added": 10, "modified": 300, "removed": 0},
            "kinds": {"smali": 1, "res": 1, "manifest": 1, "aset": 0, "lib": 0, "lain": 0}, "lines": {"plus": 5, "minus": 2, "files": 3, "skipped_files": 0},
            "skipped": {"symlink": 0, "special": 0, "root_ignored": 0, "vanished": 0}, "truncated": False,
            "top": top if top is not None else [
                {"op": "M", "kind": "f", "path": "smali/com/x/A.smali", "size": 2000, "plus": 4, "minus": 1},
                {"op": "M", "kind": "f", "path": "res/values/strings.xml", "size": 100, "plus": 1, "minus": 1},
                {"op": "A", "kind": "f", "path": "AndroidManifest.xml", "size": 10, "plus": None, "minus": None}]}
    data.update(over)
    return data


def mk_build(aid: int, *, status: str = "awaiting_approval", requested_by: str = "user", diff: str | None = None, data: dict | None = None, kind: str = "apk") -> int:
    h = diff or sha(f"d-{aid}-{status}-{requested_by}-{time.time()}")
    with closing(context.db()) as conn:
        bid = store.create_build(conn, aid, requested_by=requested_by, source_kind=kind, diff_sha256=h, diff_summary=data or summary())
        if status != "awaiting_approval":
            store.approve_build(conn, bid, diff_sha256=h, statement_sha256=store.approval_statement_sha256(), statement_version=1)
            if status in ("queued", "building", "signing", "done"):
                store.queue_build(conn, bid)
            if status in ("building", "signing", "done"):
                assert store.claim_build(conn, bid)
            if status in ("signing", "done"):
                store.mark_signing(conn, bid)
    return bid


def mk_done(aid: int, payload: bytes = b"PK-signed-apk-bytes" * 50, *, kind: str = "apk", script: bytes | None = None, write: bool = True) -> tuple[int, str, bytes]:
    bid = mk_build(aid, status="signing", kind=kind)
    name = f"com.contoh.app-modified-{bid}.{kind}"
    log = ""
    if script is not None:
        log = f"install_script=com.contoh.app-modified-{bid}-install.sh sha256={sha(script)}"
    with closing(context.db()) as conn:
        store.finish_build(conn, bid, output_name=name, output_sha256=sha(payload), output_size=len(payload), output_format=kind, cert_sha256=OWNER_CERT, verify_ok=1,
                           stage_log=log or None)
    if write:
        d = context.layout.build_dir(aid, bid)
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_bytes(payload)
        if script is not None:
            (d / f"com.contoh.app-modified-{bid}-install.sh").write_bytes(script)
    return bid, name, payload


def status_of(bid: int) -> str:
    return query("SELECT status FROM build WHERE id = ?", bid)[0][0]


def audits(action: str) -> list[dict]:
    return [json.loads(r[0]) for r in query("SELECT detail FROM audit_log WHERE action = ? ORDER BY id", action)]


def form(seeded, **over) -> dict:
    return {"csrf": seeded.csrf, **over}


# ====================================================================================== sesi dan CSRF
@pytest.mark.parametrize("path", ["/analyses/{a}/build", "/analyses/{a}/build/{b}"])
def test_pages_without_a_session_redirect_to_login(anon, seeded, path):
    aid = new_analysis("ui-anon-page")
    bid = mk_build(aid)
    r = anon.get(path.format(a=aid, b=bid), headers=BROWSER)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_status_and_downloads_without_a_session_are_401(anon):
    aid = new_analysis("ui-anon-api")
    bid, _name, _ = mk_done(aid)
    for suffix in ("status", "live", "download", "script"):
        assert anon.get(f"/analyses/{aid}/build/{bid}/{suffix}", headers=FETCH).status_code == 401, suffix


@pytest.mark.parametrize("action", ["init", "request", "{b}/approve", "{b}/reject", "{b}/cancel", "{b}/requeue"])
def test_every_post_without_a_session_redirects_to_login_and_changes_nothing(anon, env, action):
    aid = new_analysis(f"ui-anon-post-{action.replace('/', '-')}")
    bid = mk_build(aid)
    r = anon.post(f"/analyses/{aid}/build/{action.format(b=bid)}", data={"csrf": "x", "diff_sha256": "0" * 64, "statement": "1", "statement_version": "1"})
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert status_of(bid) == "awaiting_approval" and env.bench.jobs == []


@pytest.mark.parametrize("action", ["init", "request", "{b}/approve", "{b}/reject", "{b}/cancel", "{b}/requeue"])
@pytest.mark.parametrize("csrf", [None, "", "salah"])
def test_every_post_without_a_valid_csrf_token_is_403_and_changes_nothing(client, env, action, csrf):
    aid = new_analysis(f"ui-csrf-{action.replace('/', '-')}-{csrf}")
    bid = mk_build(aid)
    data = {"diff_sha256": query("SELECT diff_sha256 FROM build WHERE id = ?", bid)[0][0], "statement": "1", "statement_version": "1"}
    if csrf is not None:
        data["csrf"] = csrf
    r = client.post(f"/analyses/{aid}/build/{action.format(b=bid)}", data=data)
    assert r.status_code == 403
    assert status_of(bid) == "awaiting_approval" and env.bench.jobs == []
    assert all(a["build_id"] != bid for a in audits("build_approved"))


# ====================================================================================== persetujuan
def test_approve_with_the_stored_hash_and_the_statement_queues_the_build_and_audits_via_ui(client, seeded, env):
    aid = new_analysis("ui-approve-ok")
    bid = mk_build(aid)
    h = query("SELECT diff_sha256 FROM build WHERE id = ?", bid)[0][0]
    r = client.post(f"/analyses/{aid}/build/{bid}/approve", data=form(seeded, diff_sha256=h, statement="1", statement_version="1"))
    assert r.status_code == 303 and r.headers["location"] == f"/analyses/{aid}/build/{bid}?notice=disetujui"
    assert status_of(bid) == "queued"
    from rq import Queue
    assert any(str(j).startswith(f"build-{bid}-") for j in Queue("jobs", connection=env.redis).job_ids)
    (audit,) = [a for a in audits("build_approved") if a["build_id"] == bid]
    assert audit["via"] == "ui" and audit["diff_sha256"] == h and audit["statement_version"] == 1
    assert audit["statement_sha256"] == store.approval_statement_sha256()


def test_approve_without_the_statement_checkbox_is_refused(client, seeded, env):
    aid = new_analysis("ui-approve-nostmt")
    bid = mk_build(aid)
    h = query("SELECT diff_sha256 FROM build WHERE id = ?", bid)[0][0]
    for stmt in ("", "0", "on", "true"):
        r = client.post(f"/analyses/{aid}/build/{bid}/approve", data=form(seeded, diff_sha256=h, statement=stmt, statement_version="1"))
        assert r.status_code == 303 and r.headers["location"].endswith("?notice=pernyataan_wajib"), stmt
    r = client.post(f"/analyses/{aid}/build/{bid}/approve", data=form(seeded, diff_sha256=h, statement_version="1"))
    assert r.headers["location"].endswith("?notice=pernyataan_wajib")
    assert status_of(bid) == "awaiting_approval" and not [a for a in audits("build_approved") if a["build_id"] == bid]


def test_approve_with_a_wrong_hash_is_diff_berubah_and_records_no_approval(client, seeded, env):
    aid = new_analysis("ui-approve-wronghash")
    bid = mk_build(aid)
    r = client.post(f"/analyses/{aid}/build/{bid}/approve", data=form(seeded, diff_sha256="0" * 64, statement="1", statement_version="1"))
    assert r.status_code == 303 and r.headers["location"].endswith("?notice=diff_berubah")
    assert status_of(bid) == "awaiting_approval" and not [a for a in audits("build_approved") if a["build_id"] == bid]
    page = client.get(r.headers["location"], headers=BROWSER).text
    assert "Diff berubah sejak diajukan" in page and "TIDAK dicatat" in page


@pytest.mark.parametrize("bad", ["", "xyz", "A" * 64, "0" * 63, "0" * 65])
def test_approve_with_a_malformed_hash_is_rejected(client, seeded, env, bad):
    aid = new_analysis(f"ui-approve-badhash-{len(bad)}-{bad[:3]}")
    bid = mk_build(aid)
    r = client.post(f"/analyses/{aid}/build/{bid}/approve", data=form(seeded, diff_sha256=bad, statement="1", statement_version="1"))
    assert r.status_code == 303 and "notice=" in r.headers["location"] and not r.headers["location"].endswith("disetujui")
    assert status_of(bid) == "awaiting_approval"


@pytest.mark.parametrize("version", ["", "0", "2", "abc", "-1", "1.0"])
def test_approve_with_an_unknown_statement_version_is_rejected(client, seeded, env, version):
    aid = new_analysis(f"ui-approve-version-{version}")
    bid = mk_build(aid)
    h = query("SELECT diff_sha256 FROM build WHERE id = ?", bid)[0][0]
    r = client.post(f"/analyses/{aid}/build/{bid}/approve", data=form(seeded, diff_sha256=h, statement="1", statement_version=version))
    assert r.headers["location"].endswith("?notice=masukan_tidak_valid") and status_of(bid) == "awaiting_approval"


def test_approve_a_build_of_another_analysis_is_not_found_and_does_nothing(client, seeded, env):
    a1, a2 = new_analysis("ui-approve-cross-1"), new_analysis("ui-approve-cross-2")
    bid = mk_build(a1)
    h = query("SELECT diff_sha256 FROM build WHERE id = ?", bid)[0][0]
    r = client.post(f"/analyses/{a2}/build/{bid}/approve", data=form(seeded, diff_sha256=h, statement="1", statement_version="1"))
    assert r.headers["location"] == f"/analyses/{a2}/build?notice=build_tidak_ada"
    assert status_of(bid) == "awaiting_approval"
    for suffix in ("reject", "cancel"):
        r = client.post(f"/analyses/{a2}/build/{bid}/{suffix}", data=form(seeded))
        assert r.headers["location"].endswith("notice=build_tidak_ada") and status_of(bid) == "awaiting_approval"


def test_approving_twice_is_idempotent_and_does_not_record_a_second_approval(client, seeded, env):
    aid = new_analysis("ui-approve-twice")
    bid = mk_build(aid)
    h = query("SELECT diff_sha256 FROM build WHERE id = ?", bid)[0][0]
    data = form(seeded, diff_sha256=h, statement="1", statement_version="1")
    client.post(f"/analyses/{aid}/build/{bid}/approve", data=data)
    r = client.post(f"/analyses/{aid}/build/{bid}/approve", data=data)
    assert r.headers["location"].endswith("notice=disetujui")
    assert len([a for a in audits("build_approved") if a["build_id"] == bid]) == 1


def test_approve_with_a_dead_queue_leaves_the_build_queued_and_says_so(client, seeded, monkeypatch):
    from web_rig import dead_redis
    aid = new_analysis("ui-approve-deadredis")
    bid = mk_build(aid)
    h = query("SELECT diff_sha256 FROM build WHERE id = ?", bid)[0][0]
    deps = builds.Deps(layout=context.layout, db=context.db, redis=dead_redis(), bench_spool=shellspool.make_spool(context.layout.root / "benchspool"), poll=0.02)
    monkeypatch.setattr(routes_build, "_deps", lambda: deps)
    r = client.post(f"/analyses/{aid}/build/{bid}/approve", data=form(seeded, diff_sha256=h, statement="1", statement_version="1"))
    assert r.headers["location"].endswith("?notice=disetujui_antrean_mati") and status_of(bid) == "queued"
    page = client.get(f"/analyses/{aid}/build/{bid}", headers=BROWSER).text
    assert "Kirim ulang ke antrean" in page


def test_requeue_only_works_for_already_approved_builds_and_never_approves(client, seeded, env):
    aid = new_analysis("ui-requeue")
    waiting = mk_build(aid)
    r = client.post(f"/analyses/{aid}/build/{waiting}/requeue", data=form(seeded))
    assert r.headers["location"].endswith("?notice=status_salah") and status_of(waiting) == "awaiting_approval"
    client.post(f"/analyses/{aid}/build/{waiting}/cancel", data=form(seeded))
    queued = mk_build(aid, status="queued")
    r = client.post(f"/analyses/{aid}/build/{queued}/requeue", data=form(seeded))
    assert r.headers["location"].endswith("?notice=dikirim_ulang")
    from rq import Queue
    assert any(str(j).startswith(f"build-{queued}-") for j in Queue("jobs", connection=env.redis).job_ids)


# ====================================================================================== tolak dan batalkan
def test_reject_marks_the_build_rejected_with_a_cleaned_reason_and_audits_without_the_text(client, seeded, env):
    aid = new_analysis("ui-reject")
    bid = mk_build(aid)
    r = client.post(f"/analyses/{aid}/build/{bid}/reject", data=form(seeded, reason="tidak\x00 cocok <b>x</b>"))
    assert r.headers["location"].endswith("?notice=ditolak") and status_of(bid) == "rejected"
    (a,) = [x for x in audits("build_rejected") if x["build_id"] == bid]
    assert "reason" not in json.dumps(a) and "cocok" not in json.dumps(a)
    page = client.get(f"/analyses/{aid}/build/{bid}", headers=BROWSER).text
    assert "&lt;b&gt;x&lt;/b&gt;" in page and "<b>x</b>" not in page
    r = client.post(f"/analyses/{aid}/build/{bid}/reject", data=form(seeded))
    assert r.headers["location"].endswith("?notice=status_salah")


def test_cancel_a_waiting_build_and_request_cancel_for_a_running_one(client, seeded, env):
    aid = new_analysis("ui-cancel")
    waiting = mk_build(aid)
    r = client.post(f"/analyses/{aid}/build/{waiting}/cancel", data=form(seeded))
    assert r.headers["location"].endswith("?notice=dibatalkan") and status_of(waiting) == "cancelled"
    running = mk_build(aid, status="building")
    r = client.post(f"/analyses/{aid}/build/{running}/cancel", data=form(seeded))
    assert r.headers["location"].endswith("?notice=pembatalan_diminta") and status_of(running) == "building"
    assert query("SELECT cancel_requested FROM build WHERE id = ?", running)[0][0] == 1
    r = client.post(f"/analyses/{aid}/build/{waiting}/cancel", data=form(seeded))
    assert r.headers["location"].endswith("?notice=sudah_final")


# ====================================================================================== siapkan ruang kerja dan ajukan
def test_init_workspace_button_sends_init_to_the_bench_and_reports(client, seeded, env):
    aid = new_analysis("ui-init")
    r = client.post(f"/analyses/{aid}/build/init", data=form(seeded))
    assert r.headers["location"] == f"/analyses/{aid}/build?notice=ruang_kerja_siap"
    job = env.bench.jobs[0]
    assert job["op"] == "init" and job["analysis_id"] == aid and job["force"] is False
    from web_rig import init_result
    env.bench.init = init_result(created=False, reason="exists")
    r = client.post(f"/analyses/{aid}/build/init", data=form(seeded))
    assert r.headers["location"].endswith("?notice=ruang_kerja_ada")


def test_request_button_creates_an_awaiting_build_requested_by_the_user(client, seeded, env):
    aid = new_analysis("ui-request")
    env.bench.diff = diff_result(sha256=DIFF_SHA)
    r = client.post(f"/analyses/{aid}/build/request", data=form(seeded))
    assert r.status_code == 303
    m = re.fullmatch(rf"/analyses/{aid}/build/(\d+)\?notice=diminta", r.headers["location"])
    assert m, r.headers["location"]
    row = query("SELECT status, requested_by, diff_sha256 FROM build WHERE id = ?", int(m.group(1)))[0]
    assert tuple(row) == ("awaiting_approval", "user", DIFF_SHA)
    again = client.post(f"/analyses/{aid}/build/request", data=form(seeded))
    assert again.headers["location"].endswith("?notice=build_aktif")


def test_request_with_no_changes_maps_to_a_fixed_message_and_unknown_codes_to_generic(client, seeded, env):
    aid = new_analysis("ui-request-errors")
    env.bench.diff = diff_result(modified=0, top=[])
    r = client.post(f"/analyses/{aid}/build/request", data=form(seeded))
    assert r.headers["location"].endswith("?notice=tidak_ada_perubahan")
    # bench mati (heartbeat basi) dibuktikan di test_web_builds.py; di sini cukup pemetaan galat yang stabil
    assert routes_build.notice_code("bench_mati") == "bench_mati" and routes_build.notice_code("kode-aneh-dari-bench") == "gagal"


def test_every_builds_error_code_raised_by_the_web_layer_has_a_fixed_notice_or_download_message():
    src = (ROOT / "services" / "web" / "app" / "builds.py").read_text(encoding="utf-8")
    codes = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "BuildsError" and node.args and isinstance(node.args[0], ast.Constant):
            codes.add(node.args[0].value)
    mapped = set(routes_build.NOTICES) | set(routes_build.DOWNLOAD_ERRORS)
    missing = {c for c in codes if c not in mapped}
    # kode dinamis/diteruskan dari bench atau khusus CLI dipetakan ke `gagal` (pesan tetap); yang wajib dipetakan: semua yang literal di rute.
    assert missing <= {"waktu_habis", "berkas_tidak_ada", "hash_tidak_cocok", "belum_selesai", "skrip_tidak_ada", "ruang_disk", "skrip_tidak_lolos_lint"} | {"build_tidak_ada"}, missing
    assert all(routes_build.notice_code(c) in routes_build.NOTICES for c in codes)


# ====================================================================================== tampilan layar persetujuan
def test_approval_screen_shows_summary_statement_hash_and_a_required_checkbox(client, seeded, env):
    aid = new_analysis("ui-screen")
    bid = mk_build(aid)
    h = query("SELECT diff_sha256 FROM build WHERE id = ?", bid)[0][0]
    html = client.get(f"/analyses/{aid}/build/{bid}", headers=BROWSER).text
    assert store.approval_statement() in html
    assert re.search(r'<input id="stmt" type="checkbox" name="statement" value="1" required>', html)
    assert f'name="diff_sha256" value="{h}"' in html and f'name="csrf" value="{seeded.csrf}"' in html and 'name="statement_version" value="1"' in html
    assert "Setujui dan bangun" in html and "Tolak" in html and "Batalkan build" in html
    for text in ("Berkas baru", "Berkas diubah", "Berkas dihapus", "Baris ditambah", "Smali (kode)", "Resource", "Manifes"):
        assert text in html, text
    for text in ("Hal yang tidak dijanjikan", "Tanda tangan berbeda dari aslinya", "bukan “pasti jalan”", "Tidak ada uji jalan", builds.LIMIT_NOTICE):
        assert text in html, text


def test_files_are_grouped_by_kind_and_sorted_by_most_changed_first(client, env):
    aid = new_analysis("ui-order")
    top = [{"op": "M", "kind": "f", "path": "smali/a/Kecil.smali", "size": 10, "plus": 1, "minus": 0},
           {"op": "M", "kind": "f", "path": "smali/a/Besar.smali", "size": 5, "plus": 50, "minus": 20},
           {"op": "A", "kind": "f", "path": "smali_classes2/b/Tengah.smali", "size": 900, "plus": 5, "minus": 0},
           {"op": "R", "kind": "f", "path": "lib/arm64-v8a/libx.so", "size": 4000, "plus": None, "minus": None}]
    bid = mk_build(aid, data=summary(top=top))
    html = client.get(f"/analyses/{aid}/build/{bid}", headers=BROWSER).text
    assert html.index("Besar.smali") < html.index("Tengah.smali") < html.index("Kecil.smali")
    assert html.index("Smali (kode)") < html.index("Library native")
    assert "Dihapus" in html and "Baru" in html and "Diubah" in html


def test_filter_by_kind_and_by_path_text(client, env):
    aid = new_analysis("ui-filter")
    bid = mk_build(aid)
    url = f"/analyses/{aid}/build/{bid}"
    both = client.get(url, headers=BROWSER).text
    assert "A.smali" in both and "strings.xml" in both and "AndroidManifest.xml" in both
    smali = client.get(url + "?kind=smali", headers=BROWSER).text
    assert "A.smali" in smali.split("Ringkasan perubahan")[1] and "values/strings.xml" not in smali.split("Daftar memuat")[1]
    q = client.get(url + "?q=STRINGS", headers=BROWSER).text.split("Daftar memuat")[1]
    assert "strings.xml" in q and "A.smali" not in q
    none = client.get(url + "?q=tidak-ada-yang-cocok", headers=BROWSER).text
    assert "Tidak ada berkas yang cocok" in none
    assert "A.smali" in client.get(url + "?kind=ngawur", headers=BROWSER).text, "kind tak dikenal diabaikan, bukan galat"


def test_overlong_query_text_is_a_validation_error_not_a_reflected_page(client, env):
    aid = new_analysis("ui-filter-long")
    bid = mk_build(aid)
    r = client.get(f"/analyses/{aid}/build/{bid}?q=" + "a" * 81, headers=BROWSER)
    assert r.status_code == 422 and "a" * 81 not in r.text


def test_build_requested_by_the_ai_is_flagged_prominently(client, env):
    aid = new_analysis("ui-ai")
    bid = mk_build(aid, requested_by="ai:42")
    html = client.get(f"/analyses/{aid}/build/{bid}", headers=BROWSER).text
    assert "diminta oleh AI" in html and "sesi percakapan #42" in html and "Permintaan ini dibuat oleh asisten AI" in html
    lst = client.get(f"/analyses/{aid}/build", headers=BROWSER).text
    assert "diminta oleh AI" in lst
    other = new_analysis("ui-user")
    own = mk_build(other, requested_by="user")
    assert "diminta oleh AI" not in client.get(f"/analyses/{other}/build/{own}", headers=BROWSER).text


EVIL = '<script>alert(1)</script>'


def test_untrusted_text_from_the_diff_and_errors_is_escaped_never_raw(client, env):
    aid = new_analysis("ui-xss")
    top = [{"op": "M", "kind": "f", "path": f"smali/{EVIL}/\"><img src=x onerror=alert(2)>.smali", "size": 1, "plus": 1, "minus": 1}]
    bid = mk_build(aid, data=summary(top=top))
    html = client.get(f"/analyses/{aid}/build/{bid}", headers=BROWSER).text.replace("<wbr>", "")   # path diberi <wbr> setelah "/"
    assert EVIL not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert '"><img src=x' not in html and "&lt;img src=x onerror=alert(2)&gt;" in html
    # nilai query yang dipantulkan ke atribut input
    q = client.get(f"/analyses/{aid}/build/{bid}?q=%22%3E%3Cscript%3Ealert(3)%3C/script%3E", headers=BROWSER).text
    assert "<script>alert(3)" not in q and "&#34;&gt;&lt;script&gt;alert(3)" in q
    # galat/log/alasan dari runner
    other = new_analysis("ui-xss-failed")
    fid = mk_build(other, status="signing")
    with closing(context.db()) as conn:
        store.fail_build(conn, fid, error_code="build_failed", error_text=f"boom {EVIL}", stage_log=f"build: x\n{EVIL}")
    failed = client.get(f"/analyses/{other}/build/{fid}", headers=BROWSER).text
    assert EVIL not in failed and "&lt;script&gt;alert(1)&lt;/script&gt;" in failed


def test_pages_have_no_inline_script_and_no_unsafe_filter(client, env):
    aid = new_analysis("ui-csp")
    bid = mk_build(aid, status="queued")
    for url in (f"/analyses/{aid}/build", f"/analyses/{aid}/build/{bid}"):
        r = client.get(url, headers=BROWSER)
        assert not re.search(r"<script(?![^>]*\bsrc=)", r.text) and " style=" not in r.text and "onclick" not in r.text
        assert "script-src 'self'" in r.headers["content-security-policy"] and '/static/js/build.js' in r.text
    for tpl in ("build.html", "build_detail.html", "_build_parts.html"):
        assert "|safe" not in (ROOT / "services/web/app/templates" / tpl).read_text(encoding="utf-8"), tpl


def test_build_tab_is_in_the_navigation_and_marks_a_live_build(client, env):
    aid = new_analysis("ui-tab")
    html = client.get(f"/analyses/{aid}/manifest", headers=BROWSER).text
    assert f'href="/analyses/{aid}/build"' in html and "ada build aktif" not in html
    mk_build(aid)
    html = client.get(f"/analyses/{aid}/manifest", headers=BROWSER).text
    assert "ada build aktif: Menunggu persetujuan" in html


def test_list_page_shows_statuses_in_indonesian_and_polls_only_running_builds(client, env):
    aid = new_analysis("ui-list")
    done, _name, _ = mk_done(aid)
    html = client.get(f"/analyses/{aid}/build", headers=BROWSER).text
    assert "Selesai" in html and "Siapkan ruang kerja" in html and "Ajukan build dari ruang kerja" in html and "data-build-poll" not in html
    bid = mk_build(aid, status="building")
    html = client.get(f"/analyses/{aid}/build", headers=BROWSER).text
    assert "Membangun" in html and f'data-build-poll="/analyses/{aid}/build/{bid}/status"' in html and 'data-build-status="building"' in html
    assert "disabled" in html.split("Ajukan build dari ruang kerja")[0].rsplit("<button", 1)[1], "tombol ajukan nonaktif selama ada build aktif"


def test_notice_codes_render_fixed_texts_and_unknown_codes_are_ignored(client, env):
    aid = new_analysis("ui-notice")
    html = client.get(f"/analyses/{aid}/build?notice=ruang_kerja_siap", headers=BROWSER).text
    assert "Ruang kerja disiapkan dari hasil apktool" in html
    evil = client.get(f"/analyses/{aid}/build?notice=%3Cscript%3E", headers=BROWSER).text
    assert "<script>" not in evil


def test_status_endpoint_is_light_json_for_polling_and_scoped_to_the_analysis(client, env):
    a1, a2 = new_analysis("ui-status-1"), new_analysis("ui-status-2")
    bid = mk_build(a1, status="queued")
    r = client.get(f"/analyses/{a1}/build/{bid}/status", headers=FETCH)
    assert r.status_code == 200 and r.json() == {"status": "queued", "label": "Antre", "final": False, "cancel_requested": False}
    assert r.headers["cache-control"] == "no-store"
    assert client.get(f"/analyses/{a2}/build/{bid}/status", headers=FETCH).status_code == 404


def test_badging_and_warnings_are_shown_on_a_finished_build(client, env):
    aid = new_analysis("ui-badging")
    payload = b"PK-apk" * 20
    bid, _n, _p = mk_done(aid, payload)
    lines = "\n".join(__import__("rvcore.buildproto", fromlist=["x"]).badging_stage_lines(
        {"package": "com.contoh.app", "version_code": 7, "version_name": "1.2.3", "min_sdk": 19, "target_sdk": 21}, {"package": "com.lain", "version_code": "7", "version_name": "1"}))
    with closing(context.db()) as conn:
        conn.execute("UPDATE build SET stage_log = ? WHERE id = ?", (lines, bid))
        conn.commit()
    html = client.get(f"/analyses/{aid}/build/{bid}", headers=BROWSER).text
    assert "com.contoh.app" in html and "versionCode" in html and "1.2.3" in html and "targetSdkVersion" in html
    assert "target_sdk_di_bawah_23" in html and "Android 14 ke atas menolak" in html and "paket_beda_dari_analisis" in html
    assert f"/analyses/{aid}/build/{bid}/download" in html and sha(payload) in html


# ====================================================================================== unduhan
def tmp_entries() -> list[str]:
    return sorted(os.listdir(context.layout.files_tmp))


def test_download_serves_the_verified_copy_with_safe_headers_and_audits(client, env):
    aid = new_analysis("dl-ok")
    before = tmp_entries()
    bid, name, payload = mk_done(aid)
    r = client.get(f"/analyses/{aid}/build/{bid}/download", headers=FETCH)
    assert r.status_code == 200 and r.content == payload
    h = r.headers
    assert h["content-type"] == "application/vnd.android.package-archive"
    assert h["content-disposition"] == f'attachment; filename="{name}"' and h["x-content-type-options"] == "nosniff" and h["cache-control"] == "no-store"
    assert h["content-length"] == str(len(payload)) and "sandbox" in h["content-security-policy"]
    (a,) = [x for x in audits("build_download") if x["build_id"] == bid]
    assert a["analysis_id"] == aid and a["output_sha256"] == sha(payload) and a["which"] == "artifact" and a["size"] == len(payload) and len(a["diff_sha256"]) == 64
    assert tmp_entries() == before, "salinan sementara tidak tersisa"
    assert routes_build._DL_SLOTS.acquire(blocking=False) and routes_build._DL_SLOTS.acquire(blocking=False)
    routes_build._DL_SLOTS.release()
    routes_build._DL_SLOTS.release()


@pytest.mark.parametrize("kind", ["xapk", "apks"])
def test_bundle_download_is_a_zip_and_the_script_is_plain_text(client, env, kind):
    from rvcore import installscript
    aid = new_analysis(f"dl-bundle-{kind}")
    script = installscript.render(kind, "com.contoh.app-modified-1." + kind, "com.contoh.app", "base.apk", ["split_config.arm64_v8a.apk"], []).encode()
    bid, name, payload = mk_done(aid, kind=kind, script=script)
    r = client.get(f"/analyses/{aid}/build/{bid}/download", headers=FETCH)
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip" and r.content == payload
    s = client.get(f"/analyses/{aid}/build/{bid}/script", headers=FETCH)
    assert s.status_code == 200 and s.content == script and s.headers["content-type"].startswith("text/plain")
    assert s.headers["content-disposition"] == f'attachment; filename="com.contoh.app-modified-{bid}-install.sh"' and s.headers["x-content-type-options"] == "nosniff"
    assert [x["which"] for x in audits("build_download") if x["build_id"] == bid] == ["artifact", "script"]


def test_script_for_a_single_apk_build_is_404(client, env):
    aid = new_analysis("dl-noscript")
    bid, _n, _p = mk_done(aid)
    assert client.get(f"/analyses/{aid}/build/{bid}/script", headers=FETCH).status_code == 404


def test_a_script_changed_after_publication_is_409_without_bytes(client, env):
    from rvcore import installscript
    aid = new_analysis("dl-script-changed")
    script = installscript.render("xapk", "a-modified-1.xapk", "com.contoh.app", "base.apk", ["split_config.arm64_v8a.apk"], []).encode()
    bid, _n, _p = mk_done(aid, kind="xapk", script=script)
    (context.layout.build_dir(aid, bid) / f"com.contoh.app-modified-{bid}-install.sh").write_bytes(script + b"\nrm -rf /\n")
    r = client.get(f"/analyses/{aid}/build/{bid}/script", headers=FETCH)
    assert r.status_code == 409 and b"rm -rf" not in r.content


@pytest.mark.parametrize("mutate", ["flip", "grow", "shrink", "empty"])
def test_a_tampered_artifact_is_409_with_a_clear_message_and_no_bytes_and_no_leftovers(client, env, mutate):
    aid = new_analysis(f"dl-tamper-{mutate}")
    before = tmp_entries()
    bid, name, payload = mk_done(aid)
    path = context.layout.build_dir(aid, bid) / name
    path.write_bytes({"flip": b"X" + payload[1:], "grow": payload + b"extra", "shrink": payload[:-1], "empty": b""}[mutate])
    r = client.get(f"/analyses/{aid}/build/{bid}/download", headers=FETCH)
    assert r.status_code == 409 and "TIDAK sama" in r.text and "tidak ada byte yang dikirim" in r.text
    assert payload[:20] not in r.content and "content-disposition" not in r.headers
    assert not [a for a in audits("build_download") if a["build_id"] == bid], "tidak ada unduhan yang dicatat bila ditolak"
    assert tmp_entries() == before
    assert routes_build._DL_SLOTS.acquire(blocking=False) and routes_build._DL_SLOTS.acquire(blocking=False)
    routes_build._DL_SLOTS.release()
    routes_build._DL_SLOTS.release()


def test_download_requires_a_done_build_owned_by_the_analysis(client, env):
    a1, a2 = new_analysis("dl-scope-1"), new_analysis("dl-scope-2")
    bid, _n, _p = mk_done(a1)
    assert client.get(f"/analyses/{a2}/build/{bid}/download", headers=FETCH).status_code == 404
    for status in ("awaiting_approval", "queued", "building", "signing"):
        other = new_analysis(f"dl-notdone-{status}")
        b = mk_build(other, status=status)
        r = client.get(f"/analyses/{other}/build/{b}/download", headers=FETCH)
        assert r.status_code == 409 and "belum selesai" in r.text.lower(), status
    failed_aid = new_analysis("dl-failed")
    f = mk_build(failed_aid, status="queued")
    with closing(context.db()) as conn:
        store.fail_build(conn, f, error_code="build_failed", error_text="x")
    assert client.get(f"/analyses/{failed_aid}/build/{f}/download", headers=FETCH).status_code == 409
    assert client.get(f"/analyses/{a1}/build/999999/download", headers=FETCH).status_code == 404


def test_missing_symlinked_and_fifo_artifacts_are_404_and_never_hang(client, env, tmp_path):
    aid = new_analysis("dl-special")
    bid, name, payload = mk_done(aid)
    path = context.layout.build_dir(aid, bid) / name
    secret = tmp_path / "rahasia.txt"
    secret.write_bytes(payload)                                  # hash SAMA: hanya penolakan symlink yang mencegah penyajian
    path.unlink()
    assert client.get(f"/analyses/{aid}/build/{bid}/download", headers=FETCH).status_code == 404
    path.symlink_to(secret)
    r = client.get(f"/analyses/{aid}/build/{bid}/download", headers=FETCH)
    assert r.status_code == 404 and payload[:10] not in r.content
    path.unlink()
    os.mkfifo(path)
    t0 = time.monotonic()
    assert client.get(f"/analyses/{aid}/build/{bid}/download", headers=FETCH).status_code == 404 and time.monotonic() - t0 < 5
    path.unlink()
    path.mkdir()
    assert client.get(f"/analyses/{aid}/build/{bid}/download", headers=FETCH).status_code == 404


def test_a_symlinked_build_directory_is_not_followed(client, env, tmp_path):
    aid = new_analysis("dl-symdir")
    bid, name, payload = mk_done(aid)
    d = context.layout.build_dir(aid, bid)
    elsewhere = tmp_path / "lain"
    elsewhere.mkdir()
    (elsewhere / name).write_bytes(payload)
    (d / name).unlink()
    d.rmdir()
    d.symlink_to(elsewhere)
    assert client.get(f"/analyses/{aid}/build/{bid}/download", headers=FETCH).status_code == 404


def test_a_database_name_that_is_not_a_plain_file_name_is_refused(client, env):
    aid = new_analysis("dl-badname")
    bid, name, payload = mk_done(aid)
    with closing(context.db()) as conn:                            # kolom hanya dibatasi panjang; nama jahat harus ditolak di rute
        conn.execute("UPDATE build SET output_name = ? WHERE id = ?", ("../../etc/passwd", bid))
        conn.commit()
    r = client.get(f"/analyses/{aid}/build/{bid}/download", headers=FETCH)
    assert r.status_code == 404 and "passwd" not in r.text


def test_disk_space_and_slot_exhaustion_are_reported_not_crashed(client, env, monkeypatch):
    aid = new_analysis("dl-resources")
    bid, _n, _p = mk_done(aid)
    import shutil
    monkeypatch.setattr(builds.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(10, 9, 1))
    r = client.get(f"/analyses/{aid}/build/{bid}/download", headers=FETCH)
    assert r.status_code == 507 and "Ruang disk" in r.text
    monkeypatch.undo()
    monkeypatch.setattr(routes_build, "_deps", lambda: env.deps)
    held = [routes_build._DL_SLOTS.acquire(blocking=False) for _ in range(routes_build.DOWNLOAD_SLOTS)]
    try:
        r = client.get(f"/analyses/{aid}/build/{bid}/download", headers=FETCH)
        assert r.status_code == 503 and r.headers["retry-after"] == "5"
    finally:
        for ok in held:
            if ok:
                routes_build._DL_SLOTS.release()
    assert client.get(f"/analyses/{aid}/build/{bid}/download", headers=FETCH).status_code == 200


def test_a_client_that_hangs_up_mid_download_releases_the_slot_and_leaves_no_file(client, env):
    aid = new_analysis("dl-disconnect")
    before = tmp_entries()
    payload = os.urandom(3 * 1024 * 1024)
    bid, _n, _p = mk_done(aid, payload)
    with client.stream("GET", f"/analyses/{aid}/build/{bid}/download", headers=FETCH) as r:
        assert r.status_code == 200
        next(r.iter_bytes(1024))
    deadline = time.monotonic() + 5
    freed = False
    while time.monotonic() < deadline:
        got = [routes_build._DL_SLOTS.acquire(blocking=False) for _ in range(routes_build.DOWNLOAD_SLOTS)]
        for ok in got:
            if ok:
                routes_build._DL_SLOTS.release()
        if all(got):
            freed = True
            break
        time.sleep(0.05)
    assert freed and tmp_entries() == before


def test_open_download_copy_is_anonymous_and_closes_idempotently(env, tmp_path):
    aid = new_analysis("dl-unit")
    bid, name, payload = mk_done(aid)
    released = []
    copy = builds.open_download(env.deps, bid, analysis_id=aid, which="artifact", tmp_dir=tmp_path, release=lambda: released.append(1))
    assert os.listdir(tmp_path) == [] or all(not n.startswith("dl") for n in os.listdir(tmp_path)), "tanpa nama di disk"
    assert copy.fh.read() == payload and copy.size == len(payload) and copy.sha256 == sha(payload) and copy.media_type == builds.APK_MIME
    copy.close()
    copy.close()
    assert released == [1] and copy.fh.closed


def test_open_download_releases_the_slot_on_every_failure(env, tmp_path):
    aid = new_analysis("dl-release")
    released = []
    with pytest.raises(builds.BuildsError):
        builds.open_download(env.deps, 987654, analysis_id=aid, which="artifact", tmp_dir=tmp_path, release=lambda: released.append(1))
    bid, name, payload = mk_done(aid)
    (context.layout.build_dir(aid, bid) / name).write_bytes(b"lain")
    with pytest.raises(builds.BuildsError) as ei:
        builds.open_download(env.deps, bid, analysis_id=aid, which="artifact", tmp_dir=tmp_path, release=lambda: released.append(1))
    assert ei.value.kode == "hash_tidak_cocok" and released == [1, 1] and os.listdir(tmp_path) == []


# ====================================================================================== invarian: AI tidak punya jalur ke rute ini
def test_no_ai_module_imports_the_web_build_routes():
    ai_files = sorted((ROOT / "services/web/app/ai").glob("*.py")) + [ROOT / "services/web/app/aibuild.py"]
    for path in ai_files:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = [a.name for a in node.names] if isinstance(node, (ast.Import, ast.ImportFrom)) else []
            if isinstance(node, ast.ImportFrom) and node.module:
                names.append(node.module)
            assert not [n for n in names if n.split(".")[-1] in ("routes_build", "builds", "buildctl")], (path.name, names)
