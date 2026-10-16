"""Tahap 4, sub-area 1: layanan berlingkup-analisis `app/aibuild.py` (diff terikat analisis, request_build, status).

Bench PALSU = utas daemon pada `benchspool` tmp dengan protokol nyata (tests/web_rig.py); DB = SQLite sementara. Tidak dibuktikan di sini: bench/Landlock nyata, RQ, LLM.
Tes ditulis SEBELUM modul ada.
"""

from __future__ import annotations

import json

import pytest
from build_rig import sha
from rvcore import store
from web_rig import DIFF_SHA, WebRig, diff_result

SID = 7


@pytest.fixture
def A():
    import app.aibuild as ab
    return ab


@pytest.fixture
def rig(tmp_path):
    r = WebRig(tmp_path)
    yield r
    r.stop()


def scope(A, rig, aid, **over):
    values = dict(analysis_id=aid, session_id=SID, db=rig.conn, spool=rig._bench_spool, enabled=True, pickup_timeout=3.0, poll=0.02)
    values.update(over)
    return A.Scope(**values)


def fail(A, fn, *a, **kw):
    with pytest.raises(A.BuildScopeError) as ei:
        fn(*a, **kw)
    return ei.value


def builds_of(rig, aid):
    conn = rig.conn()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM build WHERE analysis_id = ? ORDER BY id", (aid,))]
    finally:
        conn.close()


def make_active(rig, aid, status, diff=None):
    """Build aktif milik pemilik pada status tepat `status` (tanpa lewat jalur AI)."""
    bid = rig.build(aid, upto="awaiting_approval" if status == "awaiting_approval" else "approved" if status == "approved" else "queued")
    conn = rig.conn()
    try:
        if status in ("building", "signing"):
            assert store.claim_build(conn, bid)
        if status == "signing":
            store.mark_signing(conn, bid)
        if diff:
            conn.execute("UPDATE build SET diff_sha256 = ? WHERE id = ?", (diff, bid))
            conn.commit()
    finally:
        conn.close()
    return bid


# ====================================================================================== diff dihitung ulang & terikat analisis
def test_current_diff_asks_the_bench_for_the_scope_analysis_only(A, rig):
    aid = rig.analysis()
    res = A.current_diff(scope(A, rig, aid))
    assert res["diff_sha256"] == DIFF_SHA and res["counts"]["modified"] == 1
    assert len(rig.bench.jobs) == 1 and rig.bench.jobs[0]["op"] == "diff" and rig.bench.jobs[0]["analysis_id"] == aid
    assert set(rig.bench.jobs[0]) == {"job_id", "op", "analysis_id", "timeout", "created"}


def test_request_signature_has_no_analysis_or_session_parameter_from_the_model(A):
    import inspect
    for fn in (A.request, A.status, A.current_diff):
        names = set(inspect.signature(fn).parameters)
        assert not names & {"analysis_id", "session_id", "note", "catatan"}, (fn.__name__, names)
    assert set(inspect.signature(A.Scope).parameters) >= {"analysis_id", "session_id", "db", "spool"}


def test_request_uses_the_fresh_bench_hash_and_creates_awaiting_approval_for_the_ai(A, rig):
    aid = rig.analysis()
    res = A.request(scope(A, rig, aid), None, None)
    assert res["status"] == "awaiting_approval" and res["diff_sha256"] == DIFF_SHA and res["dipakai_ulang"] is False
    rows = builds_of(rig, aid)
    assert len(rows) == 1 and rows[0]["id"] == res["build_id"]
    assert rows[0]["status"] == "awaiting_approval" and rows[0]["requested_by"] == f"ai:{SID}" and rows[0]["diff_sha256"] == DIFF_SHA
    assert rows[0]["source_kind"] == "apk" and rows[0]["note"] == "Diminta oleh AI (chat)."
    assert rows[0]["approved_at"] is None and rows[0]["approval_statement_sha256"] is None
    assert json.loads(rows[0]["diff_summary"])["counts"]["modified"] == 1
    assert "buildctl approve" in res["langkah_pemilik"] and DIFF_SHA in res["langkah_pemilik"]
    assert [a for a in rig.audit("build_approved")] == []


def test_the_hash_stored_is_the_fresh_one_not_a_stale_one(A, rig):
    aid = rig.analysis()
    rig.bench.diff = diff_result(sha256=sha(b"baru"))
    res = A.request(scope(A, rig, aid), None, None)
    assert res["diff_sha256"] == sha(b"baru") and builds_of(rig, aid)[0]["diff_sha256"] == sha(b"baru")


def test_a_model_hash_that_differs_from_the_fresh_one_is_rejected_and_nothing_is_created(A, rig):
    aid = rig.analysis()
    err = fail(A, A.request, scope(A, rig, aid), sha(b"lain"), None)
    assert err.kode == "hash_tidak_cocok" and builds_of(rig, aid) == []
    assert len(rig.bench.jobs) == 1                                   # tetap dihitung ulang dari bench


def test_a_model_hash_that_matches_is_accepted_but_never_stored_blindly(A, rig):
    aid = rig.analysis()
    res = A.request(scope(A, rig, aid), DIFF_SHA, None)
    assert res["diff_sha256"] == DIFF_SHA and builds_of(rig, aid)[0]["diff_sha256"] == DIFF_SHA


@pytest.mark.parametrize("bad", ["A" * 64, "a" * 63, "g" * 64, "a" * 64 + "\n", 12, True, ["a" * 64], ""])
def test_malformed_model_hashes_are_argument_errors_before_the_bench(A, rig, bad):
    aid = rig.analysis()
    assert fail(A, A.request, scope(A, rig, aid), bad, None).kode == "argumen_tidak_valid"
    assert rig.bench.jobs == [] and builds_of(rig, aid) == []


def test_empty_diff_is_refused_as_diff_kosong(A, rig):
    aid = rig.analysis()
    rig.bench.diff = diff_result(modified=0, top=[])
    assert fail(A, A.request, scope(A, rig, aid), None, None).kode == "diff_kosong"
    assert builds_of(rig, aid) == []


def test_a_nearly_wiped_project_is_refused_as_baseline_tidak_utuh(A, rig):
    aid = rig.analysis()
    rig.bench.diff = diff_result(modified=0, removed=95, base_entries=100, top=[])
    assert fail(A, A.request, scope(A, rig, aid), None, None).kode == "baseline_tidak_utuh"
    assert builds_of(rig, aid) == []


# ====================================================================================== kebijakan build tertunda
@pytest.mark.parametrize("status", ["approved", "queued", "building", "signing"])
def test_a_non_awaiting_active_build_refuses_cheaply_without_asking_the_bench(A, rig, status):
    aid = rig.analysis()
    bid = make_active(rig, aid, status)
    err = fail(A, A.request, scope(A, rig, aid), None, None)
    assert err.kode == "build_tertunda" and str(bid) in err.pesan
    assert rig.bench.jobs == [] and len(builds_of(rig, aid)) == 1


def test_an_awaiting_build_with_a_different_hash_is_refused(A, rig):
    aid = rig.analysis()
    make_active(rig, aid, "awaiting_approval", diff=sha(b"lama"))
    assert fail(A, A.request, scope(A, rig, aid), None, None).kode == "build_tertunda"
    assert len(builds_of(rig, aid)) == 1


def test_an_owner_awaiting_build_with_the_same_hash_is_reused_without_a_new_row(A, rig):
    aid = rig.analysis()
    bid = make_active(rig, aid, "awaiting_approval", diff=DIFF_SHA)
    res = A.request(scope(A, rig, aid), None, None)
    assert res["dipakai_ulang"] is True and res["build_id"] == bid and len(builds_of(rig, aid)) == 1


def test_calling_twice_reuses_the_same_build_and_the_reuse_is_not_a_turn_limit_hit(A, rig):
    aid = rig.analysis()
    first = A.request(scope(A, rig, aid), None, None)
    again = A.request(scope(A, rig, aid), None, None, build_requests=1)
    assert again["dipakai_ulang"] is True and again["build_id"] == first["build_id"] and len(builds_of(rig, aid)) == 1


def test_after_a_request_a_changed_project_gives_build_tertunda(A, rig):
    aid = rig.analysis()
    A.request(scope(A, rig, aid), None, None)
    rig.bench.diff = diff_result(sha256=sha(b"berubah"))
    assert fail(A, A.request, scope(A, rig, aid), None, None).kode == "build_tertunda"
    assert len(builds_of(rig, aid)) == 1


def test_one_new_build_per_turn_is_enforced_only_when_no_build_is_active(A, rig):
    aid = rig.analysis()
    assert fail(A, A.request, scope(A, rig, aid), None, None, build_requests=1).kode == "batas_giliran"
    assert builds_of(rig, aid) == []


def test_a_race_in_create_build_maps_to_build_tertunda_or_generic(A, rig, monkeypatch):
    aid = rig.analysis()

    def boom(*a, **kw):
        raise store.BuildStateError("Sudah ada build aktif (#1, X). Rahasia /data/keystore")

    monkeypatch.setattr(store, "create_build", boom)
    err = fail(A, A.request, scope(A, rig, aid), None, None)
    assert err.kode == "gagal" and "keystore" not in err.pesan and "/data" not in err.pesan          # tidak ada build aktif -> sisa
    monkeypatch.undo()
    make_active(rig, aid, "awaiting_approval", diff=DIFF_SHA)
    # build aktif milik sama hash -> reuse; bila lawan balapan muncul SETELAH pemeriksaan, create_build ditolak -> build_tertunda
    real_active = store.active_build
    calls = {"n": 0}

    def active_then_gone(conn, a):
        calls["n"] += 1
        return None if calls["n"] <= 2 else real_active(conn, a)

    monkeypatch.setattr(store, "active_build", active_then_gone)
    monkeypatch.setattr(store, "create_build", boom)
    assert fail(A, A.request, scope(A, rig, aid), None, None).kode == "build_tertunda"


def test_build_input_error_is_the_generic_code_with_a_fixed_message(A, rig, monkeypatch):
    aid = rig.analysis()
    monkeypatch.setattr(store, "create_build", lambda *a, **kw: (_ for _ in ()).throw(store.BuildInputError("detail /data/x.jks")))
    err = fail(A, A.request, scope(A, rig, aid), None, None)
    assert err.kode == "gagal" and "jks" not in err.pesan


# ====================================================================================== gerbang & fail closed
def test_disabled_scope_or_missing_session_fails_closed_before_any_io(A, rig):
    aid = rig.analysis()
    for kw in ({"enabled": False}, {"session_id": None}, {"session_id": 0}, {"session_id": True}, {"session_id": "7"}):
        assert fail(A, A.request, scope(A, rig, aid, **kw), None, None).kode == "fitur_nonaktif", kw
        assert fail(A, A.current_diff, scope(A, rig, aid, **kw)).kode == "fitur_nonaktif", kw
    assert rig.bench.jobs == [] and builds_of(rig, aid) == []


def test_uninitialised_workspace_fails_closed_with_tidak_ada_ruang_kerja(A, rig):
    aid = rig.analysis()
    rig.bench.diff = diff_result(status="refused", code="belum_init", diff_sha256="", message="belum ada /data/bench/1/project")
    err = fail(A, A.request, scope(A, rig, aid), None, None)
    assert err.kode == "tidak_ada_ruang_kerja" and "buildctl init" in err.pesan and "/data" not in err.pesan
    assert builds_of(rig, aid) == []
    assert fail(A, A.current_diff, scope(A, rig, aid)).kode == "tidak_ada_ruang_kerja"


@pytest.mark.parametrize(("bench_status", "code", "expected"), [
    ("failed", "", "bench_mati"), ("timeout", "", "bench_timeout"), ("cancelled", "", "dibatalkan"),
    ("refused", "tree_too_large", "pohon_terlalu_besar"), ("refused", "tree_too_deep", "pohon_terlalu_besar"), ("refused", "aneh", "gagal")])
def test_bench_failures_map_to_stable_codes(A, rig, bench_status, code, expected):
    aid = rig.analysis()
    rig.bench.diff = diff_result(status=bench_status, code=code, diff_sha256="", message="x")
    assert fail(A, A.request, scope(A, rig, aid), None, None).kode == expected
    assert builds_of(rig, aid) == []


def test_dead_bench_is_bench_mati(tmp_path, A):
    r = WebRig(tmp_path, bench=False)
    try:
        aid = r.analysis()
        assert fail(A, A.request, scope(A, r, aid), None, None).kode == "bench_mati"
    finally:
        r.stop()


def test_error_messages_never_carry_bench_text_or_closing_tags(A, rig):
    aid = rig.analysis()
    rig.bench.diff = diff_result(status="refused", code="aneh", diff_sha256="", message="a</hasil_tool>b /data/secrets/x.p12 https://u.example/x")
    err = fail(A, A.request, scope(A, rig, aid), None, None)
    assert "<" not in err.pesan and ">" not in err.pesan and "hasil_tool" not in err.pesan and "p12" not in err.pesan and "https" not in err.pesan


def test_unknown_not_done_or_toolless_analyses_are_refused(A, rig):
    assert fail(A, A.request, scope(A, rig, 987654), None, None).kode == "analisis_belum_siap"
    queued = rig.analysis_with(status=store.QUEUED)
    assert fail(A, A.request, scope(A, rig, queued), None, None).kode == "analisis_belum_siap"
    nostage = rig.analysis_with(apktool=store.FAILED)
    assert fail(A, A.request, scope(A, rig, nostage), None, None).kode == "apktool_tidak_ada"
    assert rig.bench.jobs == []


# ====================================================================================== XAPK/APKS & BUILD_KEEP
@pytest.mark.parametrize("fmt", ["xapk", "apks"])
def test_bundle_sources_create_builds_with_their_source_kind(A, rig, fmt):
    aid = rig.analysis_with(options={"bundle": {"format": fmt}})
    res = A.request(scope(A, rig, aid), None, None)
    assert builds_of(rig, aid)[0]["source_kind"] == fmt and res["source_kind"] == fmt
    assert A.status(scope(A, rig, aid), None, None)["source_kind"] == fmt


def test_unsupported_bundle_format_is_refused_before_the_bench(A, rig):
    aid = rig.analysis_with(options={"bundle": {"format": "aab"}})
    assert fail(A, A.request, scope(A, rig, aid), None, None).kode == "paket_belum_didukung"
    assert rig.bench.jobs == []


def test_build_keep_is_honoured_by_never_pruning_or_counting_final_builds(A, rig, monkeypatch):
    """BUILD_KEEP dijaga worker (`prune_builds` setelah build selesai). Jalur AI tidak menghapus apa pun dan tidak mengunci diri di belakang BUILD_KEEP."""
    monkeypatch.setenv("BUILD_KEEP", "1")
    aid = rig.analysis()
    old = [rig.final_build(aid, "failed") for _ in range(3)]
    monkeypatch.setattr(store, "prune_builds", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("prune")), raising=False)
    monkeypatch.setattr(store, "build_keep", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("keep")), raising=False)
    res = A.request(scope(A, rig, aid), None, None)
    ids = [b["id"] for b in builds_of(rig, aid)]
    assert ids == old + [res["build_id"]] and res["status"] == "awaiting_approval"


# ====================================================================================== status
def test_status_without_any_build_is_a_success_not_an_error(A, rig):
    aid = rig.analysis()
    res = A.status(scope(A, rig, aid), None, None)
    assert res["ada_build"] is False and res["jangan_klaim_selesai"] is True and "belum ada build" in res["ringkas"]


def test_status_defaults_to_the_active_build_then_the_latest(A, rig):
    aid = rig.analysis()
    done = rig.final_build(aid, "done")
    assert A.status(scope(A, rig, aid), None, None)["build_id"] == done
    active = rig.build(aid, upto="awaiting_approval", requested_by=f"ai:{SID}")
    res = A.status(scope(A, rig, aid), None, None)
    assert res["build_id"] == active and res["status"] == "awaiting_approval" and res["diminta_oleh_ai"] is True
    assert res["artefak_tercatat"] is False and res["verifikasi_tanda_tangan"] is None and res["jangan_klaim_selesai"] is True
    assert "buildctl approve" in res["langkah_pemilik"]


def test_status_of_a_done_build_reports_flags_but_no_artifact_identity(A, rig):
    aid = rig.analysis()
    bid = rig.final_build(aid, "done")
    res = A.status(scope(A, rig, aid), bid, None)
    assert res["status"] == "done" and res["artefak_tercatat"] is True and res["verifikasi_tanda_tangan"] is True and res["jangan_klaim_selesai"] is False
    assert res["diminta_oleh_ai"] is False and res["format_keluaran"] == "apk" and res["jumlah_split"] is None
    blob = json.dumps(res)
    row = rig.row(bid)
    for secret in (row["output_name"], row["output_sha256"], row["cert_sha256"]):
        assert secret not in blob
    assert not {"output_name", "output_sha256", "cert_sha256", "output_size"} & set(res)


def test_status_output_keys_are_a_fixed_whitelist(A, rig):
    aid = rig.analysis()
    bid = rig.final_build(aid, "done")
    assert set(A.status(scope(A, rig, aid), bid, None)) == {
        "ringkas", "ada_build", "build_id", "status", "tahap", "diminta_oleh_ai", "source_kind", "format_keluaran", "jumlah_split", "artefak_tercatat",
        "verifikasi_tanda_tangan", "kode_galat", "pesan_galat", "log_tahap", "petunjuk", "diff_sha256", "langkah_pemilik", "jangan_klaim_selesai"}


def test_build_id_of_another_analysis_or_a_missing_one_is_refused_identically(A, rig):
    mine, other = rig.analysis(), rig.analysis()
    foreign = rig.build(other, upto="awaiting_approval")
    e1 = fail(A, A.status, scope(A, rig, mine), foreign, None)
    e2 = fail(A, A.status, scope(A, rig, mine), 999_999, None)
    assert e1.kode == e2.kode == "build_bukan_milik_analisis" and e1.pesan == e2.pesan
    assert str(foreign) not in e1.pesan and str(other) not in e1.pesan


@pytest.mark.parametrize("bad", [True, False, 0, -1, 2**70, 1_000_000_000, "1", 1.0, [1], {"a": 1}])
def test_bad_build_ids_are_argument_errors_before_touching_the_db(A, rig, bad):
    aid = rig.analysis()
    calls = []
    sc = scope(A, rig, aid, db=lambda: calls.append(1) or rig.conn())
    assert fail(A, A.status, sc, bad, None).kode == "argumen_tidak_valid" and calls == []


def test_status_sanitises_error_text_and_whitelists_stage_log_lines(A, rig):
    aid = rig.analysis()
    bid = rig.build(aid, upto="queued", source_kind="apks")
    conn = rig.conn()
    try:
        assert store.claim_build(conn, bid)
        log = ("build: 12.5 dtk, 2048 B, puncak memori 300 MiB\ntanda_tangan: 3.1 dtk (2 berkas, v2 dan v3)\nsplit_n=4\nperingatan=a_b,c\n"
               "install_script=rahasia.apks sha256=" + "a" * 64 + "\nsigning_mulai=123.4\nnotes: /data/keystore/x.jks\nlain: https://u.example/x")
        store.fail_build(conn, bid, error_code="signer_unavailable", error_text="gagal /data/secrets/ks.jks di https://u.example/z <b>x</b>", stage_log=log)
    finally:
        conn.close()
    res = A.status(scope(A, rig, aid), bid, None)
    assert res["status"] == "failed" and res["kode_galat"] == "signer_unavailable" and res["jumlah_split"] == 4 and res["petunjuk"] == A.HINTS["signer_unavailable"]
    blob = json.dumps(res).lower()
    for needle in ("/data", "keystore", ".jks", "https", "://", "install_script", "signing_mulai", "notes", "rahasia.apks", "a" * 64, "<b>", "secrets"):
        assert needle not in blob, needle
    assert "12.5 dtk" in res["log_tahap"] and "split_n=4" in res["log_tahap"] and "peringatan=a_b,c" in res["log_tahap"]


def test_unknown_error_code_is_reported_as_tidak_dikenal(A, rig):
    aid = rig.analysis()
    bid = rig.build(aid, upto="queued")
    conn = rig.conn()
    try:
        store.fail_build(conn, bid, error_code="timeout", error_text="x")
        conn.execute("UPDATE build SET error_code = ? WHERE id = ?", ("Kode/Aneh", bid))      # store menolak kode semacam ini; DB bisa saja rusak/diubah
        conn.commit()
    finally:
        conn.close()
    assert A.status(scope(A, rig, aid), bid, None)["kode_galat"] == "tidak_dikenal"


def test_status_redactor_is_applied_and_status_is_read_only(A, rig):
    aid = rig.analysis()
    bid = rig.build(aid, upto="queued")
    conn = rig.conn()
    try:
        store.fail_build(conn, bid, error_code="timeout", error_text="token SUPERRAHASIA bocor")
    finally:
        conn.close()
    before = builds_of(rig, aid)
    res = A.status(scope(A, rig, aid), bid, lambda t: t.replace("SUPERRAHASIA", "[x]"))
    assert "SUPERRAHASIA" not in json.dumps(res) and builds_of(rig, aid) == before and rig.bench.jobs == []


# ====================================================================================== jalur AI tidak bisa menyetujui
def test_the_ai_path_never_reaches_approval_even_if_every_approver_is_booby_trapped(A, rig, monkeypatch):
    aid = rig.analysis()
    for name in ("approve_build", "queue_build", "claim_build", "mark_signing", "finish_build", "request_cancel_build", "cancel_build", "delete_build", "reject_build"):
        monkeypatch.setattr(store, name, lambda *a, **kw: (_ for _ in ()).throw(AssertionError("terlarang")))
    res = A.request(scope(A, rig, aid), None, None)
    A.status(scope(A, rig, aid), res["build_id"], None)
    A.request(scope(A, rig, aid), None, None)
    assert builds_of(rig, aid)[0]["status"] == "awaiting_approval" and len(builds_of(rig, aid)) == 1
