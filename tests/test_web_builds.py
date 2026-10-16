"""FEAT E: lapisan web `app/builds.py` (+ `jobs.enqueue_build`): init/diff/request/approve/cancel/status/artifact-info.

Bench PALSU = utas daemon pada `benchspool` tmp dengan protokol nyata (tests/web_rig.py); Redis = `fakeredis` (RQ nyata `Queue.enqueue`), dan jalur "Redis mati"
memakai klien ke port yang menolak koneksi. Runner/signer palsu (tests/build_rig.py) hanya dipakai untuk menghasilkan build `done` lewat `run_build` asli (cap waktu A-04).
Tidak dibuktikan di sini: RQ/Redis nyata, bench/runner/signer nyata, kontainer.
"""

from __future__ import annotations

import ast
import json
import os
import re
import time

import pytest
from build_rig import OWNER, sha
from conftest import ROOT, within_call
from rvcore import store
from web_rig import DIFF_SHA, WebRig, dead_redis, diff_result, init_result, live_redis

WEB = ROOT / "services" / "web" / "app"


@pytest.fixture
def W():
    import app.builds as wb
    return wb


@pytest.fixture
def rig(tmp_path):
    r = WebRig(tmp_path)
    yield r
    r.stop()


def kode(W, fn, *a, **kw) -> str:
    with pytest.raises(W.BuildsError) as ei:
        fn(*a, **kw)
    return ei.value.kode


# ====================================================================================== jobs.enqueue_build (E.3)
def test_enqueue_build_sends_run_build_with_the_documented_job_id_and_ttls(rig):
    from app import jobs
    from rq import Queue
    jid = jobs.enqueue_build(rig.redis, 42, 3300)
    assert re.fullmatch(r"build-42-[0-9a-f]{8}", jid)
    q = Queue("jobs", connection=rig.redis)
    job = q.fetch_job(jid)
    assert job.func_name == "tasks.run_build" and job.args == (42,) and job.timeout == 3300
    assert (job.result_ttl, job.failure_ttl) == (300, 86400)
    assert q.job_ids == [jid]


# ====================================================================================== init
def test_init_workspace_sends_only_integers_and_bools_and_returns_normalised_numbers(rig, W):
    aid = rig.analysis()
    res = W.init_workspace(rig.deps(), aid)
    assert res["created"] is True and res["reason"] == "created" and (res["files"], res["dirs"], res["bytes"]) == (3, 1, 30)
    job = rig.bench.jobs[0]
    assert set(job) == {"job_id", "op", "analysis_id", "force", "timeout", "created"} and job["op"] == "init" and job["force"] is False and job["analysis_id"] == aid


def test_init_force_is_forwarded_only_when_asked(rig, W):
    aid = rig.analysis()
    W.init_workspace(rig.deps(), aid, force=True)
    assert rig.bench.jobs[0]["force"] is True


def test_init_refuses_unknown_and_unfinished_analyses_without_touching_the_bench(rig, W):
    assert kode(W, W.init_workspace, rig.deps(), 987654) == "analisis_tidak_ada"
    aid = rig.analysis_with(status=store.QUEUED)
    assert kode(W, W.init_workspace, rig.deps(), aid) == "analisis_belum_siap"
    assert rig.bench.jobs == []


@pytest.mark.parametrize("bad", [1_000_000_000, 2**31 - 1, 10**12])
def test_ids_beyond_the_spool_pattern_are_rejected_before_the_bench_is_touched(rig, W, bad):
    d = rig.deps()
    for fn in (W.init_workspace, W.workspace_diff, W.request_build):
        assert kode(W, fn, d, bad) == "id_terlalu_besar", fn.__name__
    for fn in (W.cancel_build, W.get_status, W.artifact_info):
        assert kode(W, fn, d, bad) == "id_terlalu_besar", fn.__name__
    assert kode(W, W.approve_build, d, bad, DIFF_SHA) == "id_terlalu_besar"
    assert rig.bench.jobs == []


@pytest.mark.parametrize("bad", [True, 0, -3, "1", 1.0, None])
def test_ids_that_are_not_plain_positive_ints_are_rejected(rig, W, bad):
    assert kode(W, W.init_workspace, rig.deps(), bad) in {"id_tidak_valid", "id_terlalu_besar"}
    assert rig.bench.jobs == []


def test_init_with_a_dead_bench_fails_fast_with_bench_mati(tmp_path, W):
    r = WebRig(tmp_path, bench=False)
    try:
        aid = r.analysis()
        assert kode(W, W.init_workspace, r.deps(), aid) == "bench_mati"
    finally:
        r.stop()


@pytest.mark.parametrize(("bench_code", "expected"), [("baseline_tidak_ada", "baseline_tidak_ada"), ("kuota", "kuota"), ("anehnya", "gagal")])
def test_init_maps_bench_refusals_to_stable_codes(rig, W, bench_code, expected):
    rig.bench.init = init_result(status="refused", created=False, reason="", code=bench_code, message="ditolak")
    assert kode(W, W.init_workspace, rig.deps(), rig.analysis()) == expected


def test_init_force_with_an_active_build_is_refused_and_the_bench_is_never_asked(rig, W):
    """A-15 (M100): `init --force` mereset project dari baseline; selama ada build aktif (awaiting_approval..signing) ditolak dan baseline lama utuh."""
    for upto in ("awaiting_approval", "approved", "queued"):
        aid = rig.analysis()
        rig.build(aid, upto=upto)
        project = rig.layout.bench / str(aid) / "project"
        project.mkdir(parents=True)
        (project / "karya.txt").write_text("pekerjaan lama")
        assert kode(W, W.init_workspace, rig.deps(), aid, force=True) == "build_aktif", upto
        assert (project / "karya.txt").read_text() == "pekerjaan lama"
    assert rig.bench.jobs == []
    aid = rig.analysis()
    bid = rig.build(aid)
    conn = rig.conn()
    assert store.claim_build(conn, bid)
    conn.close()
    assert kode(W, W.init_workspace, rig.deps(), aid, force=True) == "build_aktif"
    assert rig.bench.jobs == []
    # tanpa force, init tetap idempoten dan tidak ditolak
    assert W.init_workspace(rig.deps(), aid)["created"] is True


# ====================================================================================== diff
def test_workspace_diff_normalises_the_bench_result_and_adds_the_system_trace_name(rig, W):
    aid = rig.analysis()
    res = W.workspace_diff(rig.deps(), aid)
    assert res["diff_sha256"] == DIFF_SHA and res["counts"] == {"added": 0, "modified": 1, "removed": 0}
    assert res["jejak_sistem"] == "assets/reverse-apk-modified.txt" and res["peringatan"] == ""
    assert res["top"][0]["path"] == "res/values/strings.xml"
    job = rig.bench.jobs[0]
    assert set(job) == {"job_id", "op", "analysis_id", "timeout", "created"} and job["op"] == "diff"


def test_workspace_diff_names_with_newlines_and_bidi_cannot_forge_lines(rig, W):
    rig.bench.diff = diff_result(top=[{"op": "A", "kind": "f", "path": "a\npersetujuan=pemilik-lewat-CLI\u202e", "size": 1, "plus": None, "minus": None}])
    res = W.workspace_diff(rig.deps(), rig.analysis())
    assert "\n" not in res["top"][0]["path"] and "\u202e" not in res["top"][0]["path"]


def test_workspace_diff_maps_bench_refusals(rig, W):
    aid = rig.analysis()
    for bench_code, expected in (("belum_init", "belum_init"), ("tree_too_large", "pohon_terlalu_besar"), ("project_tidak_valid", "gagal")):
        rig.bench.diff = {"status": "refused", "code": bench_code, "message": "x"}
        assert kode(W, W.workspace_diff, rig.deps(), aid) == expected
    rig.bench.diff = {"status": "ok", "diff_sha256": "bukan-hex"}          # status ok tanpa hash sah = gagal (parse_diff_result)
    assert kode(W, W.workspace_diff, rig.deps(), aid) == "gagal"


def test_diff_warns_when_project_looks_like_a_wiped_baseline(rig, W):
    aid = rig.analysis()
    rig.bench.diff = diff_result(modified=0, removed=900, base_entries=1000, top=[])
    assert W.workspace_diff(rig.deps(), aid)["peringatan"] == "baseline_tidak_utuh"
    rig.bench.diff = diff_result(modified=0, removed=899, base_entries=1000, top=[])
    assert W.workspace_diff(rig.deps(), aid)["peringatan"] == ""
    rig.bench.diff = diff_result(modified=0, removed=5, base_entries=0, top=[])
    assert W.workspace_diff(rig.deps(), aid)["peringatan"] == ""


# ====================================================================================== request
def test_request_build_stores_a_bounded_summary_and_returns_the_hash(rig, W):
    aid = rig.analysis()
    res = W.request_build(rig.deps(), aid, note="catatan")
    row = rig.row(res["build_id"])
    assert row["status"] == "awaiting_approval" and row["diff_sha256"] == DIFF_SHA == res["diff_sha256"] and row["requested_by"] == "user"
    summary = json.loads(row["diff_summary"])
    assert summary["v"] == 1 and summary["counts"] == {"added": 0, "modified": 1, "removed": 0} and summary["top"][0]["path"] == "res/values/strings.xml"
    assert res["jejak_sistem"] == "assets/reverse-apk-modified.txt" and res["status"] == "awaiting_approval"


def test_request_without_changes_is_refused(rig, W):
    rig.bench.diff = diff_result(modified=0, top=[])
    assert kode(W, W.request_build, rig.deps(), rig.analysis()) == "tidak_ada_perubahan"


def test_request_refuses_unknown_bundle_formats_unfinished_and_apktool_less_analyses(rig, W):
    bundle = rig.analysis_with(options={"deobf": False, "bundle": {"format": "apkm", "splits": 2}})
    assert kode(W, W.request_build, rig.deps(), bundle) == "paket_belum_didukung"
    assert kode(W, W.request_build, rig.deps(), rig.analysis_with(options={"deobf": False, "bundle": "xapk"})) == "paket_belum_didukung"
    assert kode(W, W.request_build, rig.deps(), rig.analysis_with(status=store.QUEUED)) == "analisis_belum_siap"
    assert kode(W, W.request_build, rig.deps(), rig.analysis_with(apktool=store.FAILED)) == "apktool_tidak_ada"
    assert kode(W, W.request_build, rig.deps(), 424242) == "analisis_tidak_ada"


@pytest.mark.parametrize("fmt", ["xapk", "apks"])
def test_request_xapk_apks_diterima_dengan_source_kind(rig, W, fmt):
    aid = rig.analysis_with(options={"deobf": False, "bundle": {"format": fmt, "splits": 2}})
    res = W.request_build(rig.deps(), aid)
    assert rig.row(res["build_id"])["source_kind"] == fmt and res["status"] == "awaiting_approval"


def test_request_apk_biasa_tetap_source_kind_apk(rig, W):
    assert rig.row(W.request_build(rig.deps(), rig.analysis())["build_id"])["source_kind"] == "apk"


@pytest.mark.parametrize("fmt,want", [("apk", 3300), ("xapk", 3300 + 3200), ("apks", 3300 + 3200)])
def test_approve_job_timeout_memakai_margin_menurut_format(rig, W, fmt, want):
    from rq import Queue
    aid = rig.analysis_with(options={"deobf": False, "bundle": {"format": fmt}} if fmt != "apk" else {})
    bid = W.request_build(rig.deps(), aid)["build_id"]
    W.approve_build(rig.deps(), bid, rig.row(bid)["diff_sha256"], via="cli")
    job = Queue("jobs", connection=rig.redis).fetch_job(rig.queue_ids()[0])
    assert job.timeout == want


def test_request_with_an_active_build_is_refused_with_build_aktif(rig, W):
    aid = rig.analysis()
    rig.build(aid, upto="awaiting_approval")
    n = len(rig.bench.jobs)
    assert kode(W, W.request_build, rig.deps(), aid) == "build_aktif"
    assert len(rig.bench.jobs) == n, "tidak perlu menghitung diff bila sudah ada build aktif"


def test_request_summary_is_halved_until_it_fits_and_marked_truncated(rig, W):
    """40 entri `top` dengan path 300 karakter melebihi 7000; dipotong separuh-demi-separuh (40->20->10->5->2->1->0) sampai muat, tersimpan di store (<= 8192)."""
    top = [{"op": "A", "kind": "f", "path": f"{i:02d}" + "x" * 298, "size": 5, "plus": 1, "minus": 0} for i in range(40)]
    rig.bench.diff = diff_result(added=40, modified=0, top=top)
    aid = rig.analysis()
    res = W.request_build(rig.deps(), aid)
    raw = rig.row(res["build_id"])["diff_summary"]
    summary = json.loads(raw)
    assert len(raw) <= 7000 and summary["truncated"] is True and len(summary["top"]) in {20, 10, 5, 2, 1, 0} and len(summary["top"]) < 40
    assert len(summary["top"]) == 20 or len(json.dumps({**summary, "top": summary["top"] * 2}, sort_keys=True, ensure_ascii=False)) > 7000, "tidak boleh dipotong lebih dari perlu"


def test_summary_that_cannot_shrink_below_the_limit_is_refused_synthetically(rig, W, monkeypatch):
    """`ringkasan_terlalu_besar` mustahil dengan bidang bertipe tetap; terjangkau hanya bila batas diperkecil (sintetis)."""
    monkeypatch.setattr(W, "SUMMARY_MAX_CHARS", 10)
    assert kode(W, W.request_build, rig.deps(), rig.analysis()) == "ringkasan_terlalu_besar"


def test_summary_nesting_depth_is_small_enough_for_the_store(rig, W):
    def depth(x, d=0):
        if isinstance(x, dict):
            return max([depth(v, d + 1) for v in x.values()] or [d + 1])
        if isinstance(x, list):
            return max([depth(v, d + 1) for v in x] or [d + 1])
        return d
    res = W.request_build(rig.deps(), rig.analysis())
    assert depth(json.loads(rig.row(res["build_id"])["diff_summary"])) <= 4


# ====================================================================================== approve
def requested(rig, W, **kw):
    aid = rig.analysis()
    res = W.request_build(rig.deps(), aid)
    return aid, res["build_id"], res["diff_sha256"]


def test_approve_is_bound_to_the_hash_and_a_wrong_hash_changes_nothing(rig, W):
    _aid, bid, h = requested(rig, W)
    assert kode(W, W.approve_build, rig.deps(), bid, "0" * 64) == "diff_berubah"
    assert rig.row(bid)["status"] == "awaiting_approval" and rig.queue_ids() == []
    assert rig.audit("build_approved") == []


@pytest.mark.parametrize("bad", ["", "abc", "A" * 64, "g" * 64, "0" * 63, "0" * 65, None, 5])
def test_approve_rejects_malformed_hashes(rig, W, bad):
    _aid, bid, _h = requested(rig, W)
    assert kode(W, W.approve_build, rig.deps(), bid, bad) == "hash_tidak_valid"
    assert rig.row(bid)["status"] == "awaiting_approval"


def test_approve_queues_then_enqueues_and_audits_the_channel(rig, W):
    _aid, bid, h = requested(rig, W)
    res = W.approve_build(rig.deps(), bid, h, via="cli")
    assert (res["status"], res["enqueued"], res["hold"]) == ("queued", True, False)
    assert res["pernyataan_versi"] == 1 and res["pernyataan_sha256"] == store.approval_statement_sha256()
    ids = rig.queue_ids()
    assert len(ids) == 1 and re.fullmatch(rf"build-{bid}-[0-9a-f]{{8}}", ids[0])
    from rq import Queue
    job = Queue("jobs", connection=rig.redis).fetch_job(ids[0])
    assert job.func_name == "tasks.run_build" and job.args == (bid,) and job.timeout == 3300
    detail = rig.audit("build_approved")
    assert len(detail) == 1 and detail[0]["via"] == "cli" and detail[0]["diff_sha256"] == h and detail[0]["build_id"] == bid


def test_approve_defaults_to_via_ui(rig, W):
    _aid, bid, h = requested(rig, W)
    W.approve_build(rig.deps(), bid, h)
    assert rig.audit("build_approved")[0]["via"] == "ui"


def test_approve_is_idempotent_and_never_duplicates_the_job(rig, W):
    _aid, bid, h = requested(rig, W)
    W.approve_build(rig.deps(), bid, h)
    again = W.approve_build(rig.deps(), bid, h)
    assert again["status"] == "queued" and again["enqueued"] is True
    assert len(rig.queue_ids()) == 1
    assert len(rig.audit("build_approved")) == 1, "persetujuan kedua tidak mencatat persetujuan baru"
    assert kode(W, W.approve_build, rig.deps(), bid, "1" * 64) == "diff_berubah"


def test_approve_on_other_statuses_is_status_salah(rig, W):
    aid, bid, h = requested(rig, W)
    W.approve_build(rig.deps(), bid, h)
    conn = rig.conn()
    assert store.claim_build(conn, bid)
    conn.close()
    assert kode(W, W.approve_build, rig.deps(), bid, h) == "status_salah"
    done = rig.final_build(rig.analysis(), "done")
    assert kode(W, W.approve_build, rig.deps(), done, sha(b"x")) == "status_salah"
    assert kode(W, W.approve_build, rig.deps(), 31337, h) == "build_tidak_ada"


def test_hold_approves_and_queues_without_a_job_and_a_second_approve_releases_it(rig, W):
    _aid, bid, h = requested(rig, W)
    res = W.approve_build(rig.deps(), bid, h, hold=True, via="cli")
    assert (res["status"], res["enqueued"], res["hold"]) == ("queued", False, True) and rig.queue_ids() == []
    W.approve_build(rig.deps(), bid, h, hold=True, via="cli")
    assert rig.queue_ids() == [], "hold berulang tetap tidak mengantre"
    res = W.approve_build(rig.deps(), bid, h)
    assert res["enqueued"] is True and len(rig.queue_ids()) == 1 and rig.row(bid)["status"] == "queued"
    assert len(rig.audit("build_approved")) == 1


def test_redis_down_leaves_the_build_queued_without_a_job_and_approve_again_recovers(tmp_path, W):
    r = WebRig(tmp_path, redis_conn=dead_redis())
    try:
        aid = r.analysis()
        res = W.request_build(r.deps(), aid)
        bid, h = res["build_id"], res["diff_sha256"]
        out = W.approve_build(r.deps(), bid, h, via="cli")
        assert out["status"] == "queued" and out["enqueued"] is False and out["galat"]
        assert r.row(bid)["status"] == "queued"                           # D10: bukan `approved`
        r.redis = live_redis()                       # Redis pulih
        out = W.approve_build(r.deps(), bid, h, via="cli")
        assert out["enqueued"] is True and len(r.queue_ids()) == 1 and len(r.audit("build_approved")) == 1
    finally:
        r.stop()


def test_approved_without_queue_state_is_recovered_by_approve(rig, W):
    """Proses mati di antara `approve` dan `queue_build`: status `approved` -> approve ulang memajukan ke `queued` lalu mengantre."""
    aid = rig.analysis()
    bid = rig.build(aid, upto="approved")
    h = rig.row(bid)["diff_sha256"]
    out = W.approve_build(rig.deps(), bid, h)
    assert out["status"] == "queued" and out["enqueued"] is True and len(rig.queue_ids()) == 1


# ====================================================================================== cancel
def test_cancel_outcomes(rig, W):
    aid = rig.analysis()
    bid = rig.build(aid, upto="awaiting_approval")
    assert W.cancel_build(rig.deps(), bid)["hasil"] == "cancelled" and rig.row(bid)["status"] == "cancelled"
    assert kode(W, W.cancel_build, rig.deps(), bid) == "sudah_final"
    aid2 = rig.analysis()
    b2 = rig.build(aid2)
    conn = rig.conn()
    assert store.claim_build(conn, b2)
    conn.close()
    assert W.cancel_build(rig.deps(), b2)["hasil"] == "requested" and rig.row(b2)["cancel_requested"] == 1
    assert kode(W, W.cancel_build, rig.deps(), 5555) == "build_tidak_ada"


# ====================================================================================== status
def test_status_explains_every_status(rig, W):
    d = rig.deps()
    aid = rig.analysis()
    b1 = rig.build(aid, upto="awaiting_approval")
    s = W.get_status(d, b1)
    assert s["status"] == "awaiting_approval" and f"approve --diff-sha256 {rig.row(b1)['diff_sha256']}" in s["alasan"]
    conn = rig.conn()
    store.request_cancel_build(conn, b1)
    conn.close()

    aid2 = rig.analysis()
    b2 = rig.build(aid2)                                               # queued, tanpa job
    assert "tanpa job" in W.get_status(d, b2)["alasan"] and "approve lagi" in W.get_status(d, b2)["alasan"]
    from app import jobs
    jobs.enqueue_build(rig.redis, 999, 100)                            # satu pekerjaan lain di depan
    jobs.enqueue_build(rig.redis, b2, 100)
    alasan = W.get_status(d, b2)["alasan"]
    assert "antre di worker" in alasan and "1 pekerjaan di depan" in alasan and "runner" in alasan and "signer" in alasan

    conn = rig.conn()
    assert store.claim_build(conn, b2)
    conn.close()
    rig.redis.set("runner:heartbeat", json.dumps({"ts": time.time(), "state": "busy", "job": f"a{aid2}-build-aaaaaaaaaaaa"}))
    assert "membangun" in W.get_status(d, b2)["alasan"]
    conn = rig.conn()
    store.mark_signing(conn, b2, stage_log="signing_mulai=%f" % time.time())
    conn.close()
    rig.redis.set("signer:heartbeat", json.dumps({"ts": time.time(), "state": "busy", "keystore_state": "ok", "cert_sha256": OWNER}))
    assert "tanda tangan" in W.get_status(d, b2)["alasan"]

    done = rig.final_build(rig.analysis(), "done")
    s = W.get_status(d, done)
    assert f"x-modified-{done}.apk" in s["alasan"] and s["verify_ok"] == 1 and s["output_size"] == 1

    failed = rig.final_build(rig.analysis(), "failed")
    s = W.get_status(d, failed)
    assert s["error_code"] == "build_failed" and "build_failed" in s["alasan"]


def test_status_hints_make_up_for_signer_unavailable(rig, W):
    aid = rig.analysis()
    bid = rig.build(aid)
    conn = rig.conn()
    store.fail_build(conn, bid, error_code="signer_unavailable", error_text="signer mati")
    conn.close()
    assert "make up" in W.get_status(rig.deps(), bid)["alasan"]


def test_status_flags_a_dead_runner_and_signer_for_queued_builds(rig, W):
    aid = rig.analysis()
    bid = rig.build(aid)
    from app import jobs
    jobs.enqueue_build(rig.redis, bid, 100)
    alasan = W.get_status(rig.deps(), bid)["alasan"]
    assert "MATI" in alasan and "signer_unavailable" in alasan
    rig.redis.set("runner:heartbeat", json.dumps({"ts": time.time(), "state": "idle", "job": None}))
    rig.redis.set("signer:heartbeat", json.dumps({"ts": time.time(), "state": "idle", "keystore_state": "ok", "cert_sha256": OWNER}))
    alasan = W.get_status(rig.deps(), bid)["alasan"]
    assert "MATI" not in alasan and "idle" in alasan and "hidup" in alasan
    rig.redis.set("runner:heartbeat", json.dumps({"ts": time.time() - 500, "state": "idle", "job": None}))
    assert "MATI" in W.get_status(rig.deps(), bid)["alasan"], "detak basi = mati"
    rig.redis.set("runner:heartbeat", "bukan json")
    assert "MATI" in W.get_status(rig.deps(), bid)["alasan"], "detak rusak diperlakukan sebagai mati, tidak melempar"


def test_status_survives_redis_down(tmp_path, W):
    r = WebRig(tmp_path, redis_conn=dead_redis())
    try:
        bid = r.build(r.analysis())
        s = W.get_status(r.deps(), bid)
        assert s["status"] == "queued" and "tidak terjangkau" in s["alasan"]
    finally:
        r.stop()


def test_status_prints_the_timeline_stamps_of_a_real_run_build(rig, W):
    """A-04: cap approved_at/started_at/signing_mulai/finished_at + durasi turunannya dari DB hasil `run_build` asli (runner/signer palsu)."""
    rig.start()
    aid = rig.analysis()
    bid = rig.build(aid)
    rig.run(bid)
    s = W.get_status(rig.deps(), bid)
    assert s["status"] == "done"
    row = rig.row(bid)
    mulai = rig.stage_log_field(bid, "signing_mulai")
    assert s["approved_at"] == row["approved_at"] and s["started_at"] == row["started_at"] and s["finished_at"] == row["finished_at"] and s["signing_mulai"] == mulai
    assert s["waktu_antre"] == pytest.approx(row["started_at"] - row["approved_at"]) and s["waktu_build"] == pytest.approx(mulai - row["started_at"])
    assert s["waktu_tanda_tangan"] == pytest.approx(row["finished_at"] - mulai)
    assert all(s[k] >= 0 for k in ("waktu_antre", "waktu_build", "waktu_tanda_tangan"))


def test_status_omits_stamps_that_do_not_exist_yet(rig, W):
    s = W.get_status(rig.deps(), rig.build(rig.analysis(), upto="awaiting_approval"))
    assert s["signing_mulai"] is None and s["waktu_antre"] is None and s["waktu_build"] is None and s["waktu_tanda_tangan"] is None


def test_status_by_analysis_lists_builds_and_folders_without_following_symlinks(rig, W, tmp_path):
    aid = rig.analysis()
    done = rig.final_build(aid, "done")
    other = rig.final_build(aid, "failed", make_dir=False)
    (rig.layout.builds / str(aid) / "bukan-angka").mkdir()
    (rig.layout.builds / str(aid) / "07").mkdir()
    s = W.get_status(rig.deps(), analysis_id=aid)
    assert s["build_dirs"] == [done] and s["builds"] == [{"build_id": done, "status": "done"}, {"build_id": other, "status": "failed"}]
    korban = tmp_path / "korban"
    (korban / "5").mkdir(parents=True)
    (korban / "5" / "penting").write_text("jangan disentuh")
    aid2 = rig.analysis()
    (rig.layout.builds / str(aid2)).symlink_to(korban)
    s = W.get_status(rig.deps(), analysis_id=aid2)
    assert s["build_dirs"] == [] and (korban / "5" / "penting").read_text() == "jangan disentuh"
    assert kode(W, W.get_status, rig.deps(), 1, 1) == "argumen_salah"
    assert kode(W, W.get_status, rig.deps()) == "argumen_salah"


def test_status_unknown_build(rig, W):
    assert kode(W, W.get_status, rig.deps(), 4040) == "build_tidak_ada"


# ====================================================================================== artifact_info
def test_artifact_info_rehashes_the_file_on_disk(rig, W):
    aid = rig.analysis()
    bid = rig.final_build(aid, "done")
    res = W.artifact_info(rig.deps(), bid)
    assert res["cocok"] is True and res["disk_sha256"] == res["output_sha256"] == sha(b"a") and res["output_name"] == f"x-modified-{bid}.apk"
    assert res["cert_sha256"] == OWNER and res["output_size"] == 1


def test_artifact_info_detects_a_changed_file_and_reports_both_hashes(rig, W):
    aid = rig.analysis()
    bid = rig.final_build(aid, "done")
    (rig.bdir(aid, bid) / f"x-modified-{bid}.apk").write_bytes(b"b")
    with pytest.raises(W.BuildsError) as ei:
        W.artifact_info(rig.deps(), bid)
    assert ei.value.kode == "hash_tidak_cocok" and ei.value.extra["cocok"] is False and ei.value.extra["disk_sha256"] == sha(b"b")


def test_artifact_info_refuses_missing_special_and_symlinked_artifacts(rig, W, tmp_path):
    aid = rig.analysis()
    bid = rig.final_build(aid, "done")
    art = rig.bdir(aid, bid) / f"x-modified-{bid}.apk"
    art.unlink()
    assert kode(W, W.artifact_info, rig.deps(), bid) == "berkas_tidak_ada"
    os.mkfifo(art)
    _res, exc = within_call(5, W.artifact_info, rig.deps(), bid)
    assert exc is not None and exc.kode == "berkas_tidak_ada", "FIFO tidak boleh menggantung pembaca"
    art.unlink()
    target = tmp_path / "luar.apk"
    target.write_bytes(b"a")
    art.symlink_to(target)
    assert kode(W, W.artifact_info, rig.deps(), bid) == "berkas_tidak_ada", "symlink tidak diikuti"


def test_artifact_info_with_a_planted_aid_symlink_reads_nothing_outside(rig, W, tmp_path):
    aid = rig.analysis()
    bid = rig.final_build(aid, "done")
    korban = tmp_path / "korban"
    (korban / str(bid)).mkdir(parents=True)
    (korban / str(bid) / f"x-modified-{bid}.apk").write_bytes(b"a")
    (rig.layout.builds / str(aid)).rename(rig.layout.builds / f"{aid}.dipindah")
    (rig.layout.builds / str(aid)).symlink_to(korban)
    assert kode(W, W.artifact_info, rig.deps(), bid) == "berkas_tidak_ada"


def test_artifact_info_states(rig, W):
    aid = rig.analysis()
    assert kode(W, W.artifact_info, rig.deps(), rig.build(aid)) == "belum_selesai"
    assert kode(W, W.artifact_info, rig.deps(), 777) == "build_tidak_ada"


# ====================================================================================== kode: bentuk dan jalur
def _names(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return tree, {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}


def test_builds_py_uses_no_string_path_mutation_of_builds_and_does_not_import_ai_tools():
    """§3 butir 6 / §7.7: konsumen web memakai rantai-dirfd (open_dir_chain), bukan Path.mkdir/rename/safe_rmtree/shutil.rmtree; dan tidak mengimpor `ai.tools` (A-14)."""
    tree, names = _names(WEB / "builds.py")
    assert not names & {"safe_rmtree", "rmtree", "mkdir", "makedirs", "rmdir", "rename", "replace", "build_dir", "builds_dir"}, names
    assert "open_dir_chain" in names
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").endswith("ai.tools") and not (node.module == "ai" and any(a.name == "tools" for a in node.names)), ast.dump(node)
            assert not (node.level and node.module == "ai"), "from .ai import ..."
        if isinstance(node, ast.Import):
            assert not any(a.name.endswith("ai.tools") for a in node.names)


def test_builds_py_is_the_only_module_that_builds_init_requests():
    """G-AI: `shellspool.build_init_request` hanya dirujuk `app/builds.py` (op `init` bukan jalur AI); op `diff` juga hanya dari sana."""
    refs: dict[str, set[str]] = {}
    for p in (ROOT / "services").rglob("*.py"):
        _t, names = _names(p)
        for n in ("build_init_request", "build_diff_request"):
            if n in names and p.name != "shellspool.py":
                refs.setdefault(n, set()).add(str(p.relative_to(ROOT)))
    assert refs == {"build_init_request": {"services/web/app/builds.py"}, "build_diff_request": {"services/web/app/builds.py"}}, refs


def test_build_summary_caps_are_below_the_store_limit(W):
    assert W.SUMMARY_MAX_CHARS == 7000 and W.SUMMARY_MAX_CHARS < store.BUILD_SUMMARY_MAX


def test_compose_passes_the_build_timeouts_to_web_and_the_job_timeout_is_derived_from_them(monkeypatch, W):
    """OP-01: env yang dibaca kode HARUS diteruskan compose. Web memakainya hanya untuk `job_timeout` RQ (TIMEOUT_BUILD + TIMEOUT_SIGN + 600)."""
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    block = re.search(r"(?ms)^  web:\n(.*?)(?=^  [a-z_]+:\n)", text).group(1)
    assert "TIMEOUT_BUILD: ${TIMEOUT_BUILD:-1800}" in block and "TIMEOUT_SIGN: ${TIMEOUT_SIGN:-900}" in block
    for k in ("TIMEOUT_BUILD", "TIMEOUT_SIGN"):
        monkeypatch.delenv(k, raising=False)
    assert W.job_timeout_from_env() == 1800 + 900 + 600
    monkeypatch.setenv("TIMEOUT_BUILD", "100")
    monkeypatch.setenv("TIMEOUT_SIGN", "50")
    assert W.job_timeout_from_env() == 750
    monkeypatch.setenv("TIMEOUT_BUILD", "1")             # klem 10..3600 (sama dengan worker)
    monkeypatch.setenv("TIMEOUT_SIGN", "banyak")
    assert W.job_timeout_from_env() == 10 + 900 + 600
