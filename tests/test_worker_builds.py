"""FEAT D: worker `run_build` (claim -> runner -> signer -> verifikasi -> nama artefak buatan sistem -> finish_build -> prune BUILD_KEEP -> pemulihan).

Runner dan signer PALSU = utas daemon di atas spool tmp dengan protokol NYATA (tests/build_rig.py); DB SQLite sementara; ukuran kecil. Yang dibuktikan di sini:
alur status, tiap mode gagal, pembatalan di tiga tahap, jaminan A-04 (`signing_mulai` + cap waktu DB monoton), A-17 (prune saat `builds/<aid>` ditanam symlink, tujuan
rename berupa direktori), kegagalan-tertutup terhadap runner yang menanam symlink di `builds/`, serta proses uid 10001 NYATA (setpriv) atas pohon berizin 000/444 dan milik root.
Tidak dibuktikan di sini: RQ/Redis nyata (fakeredis saja), kontainer/volume Docker nyata, runner dan signer nyata.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import threading
import time
from pathlib import Path

import build_rig as br
import pytest
from build_rig import HANG, OWNER, Rig, bm, failure_result, sha, signed_result
from conftest import AS_10001, ROOT, need_uid, open_to_10001, within_call
from rvcore import buildproto, signspool, store

SERVICES = ROOT / "services"


@pytest.fixture
def rig(tmp_path):
    r = Rig(tmp_path)
    yield r
    r.stop()


@pytest.fixture
def B(monkeypatch):
    """Modul `builds` dengan jeda polling dipercepat (sebelum FEAT D: ModuleNotFoundError)."""
    mod = bm()
    monkeypatch.setattr(mod, "POLL_INTERVAL", 0.02)
    return mod


def listing_clean(rig: Rig, aid: int, bid: int) -> None:
    """Tidak ada sisa sementara pada status final apa pun: yang boleh tinggal hanya build.log dan artefak berimbuhan `-modified-`."""
    left = rig.listing(aid, bid)
    assert "src" not in left and "unsigned.apk" not in left and "signed.apk" not in left, left
    assert not [n for n in left if n.startswith(".sign-")], left


# ====================================================================================== jalur sukses
def test_success_path_names_the_artifact_itself_and_records_the_timeline(rig, B):
    aid = rig.analysis(package="com.contoh.app")
    seen: dict = {}

    def runner(r, job_id, job):
        seen["runner_status"] = rig.row(job["build_id"])["status"]
        return br.FakeRunner.default(r, job_id, job)

    def signer(s, job_id, job):
        seen["signer_status"] = rig.row(job["build_id"])["status"]
        return br.FakeSigner.default(s, job_id, job)

    rig.start(runner=runner, signer=signer)
    bid = rig.build(aid, note="../../etc/passwd", requested_by="ai:7")
    assert rig.row(bid)["status"] == "queued"
    rig.run(bid)
    row = rig.row(bid)
    name = f"com.contoh.app-modified-{bid}.apk"
    assert seen == {"runner_status": "building", "signer_status": "signing"}
    assert (row["status"], row["error_code"], row["verify_ok"], row["output_format"], row["cert_sha256"]) == ("done", None, 1, "apk", OWNER)
    assert row["output_name"] == name
    data = (rig.bdir(aid, bid) / name).read_bytes()
    assert (row["output_sha256"], row["output_size"]) == (sha(data), len(data)) and data.endswith(b"+SIGNED")
    assert rig.listing(aid, bid) == sorted(["build.log", name])               # src/, unsigned.apk, signed.apk hilang; build.log tinggal
    # permintaan ke runner dan signer hanya berisi bilangan bulat dan hash (tanpa path)
    job = rig.runner.jobs[0]
    assert set(job) == {"job_id", "stage", "analysis_id", "build_id", "diff_sha256", "sha256", "timeout", "created"}
    assert job["diff_sha256"] == row["diff_sha256"] and job["timeout"] == 30 and job["stage"] == "build"
    sign_job = rig.signer.jobs[0]
    assert sign_job["expect_sha256"] == sha(data[: -len(b"+SIGNED")]) and sign_job["timeout"] == 30
    assert not any(rig.layout.spool.glob("*/*.json")) and not any(rig.layout.signspool.glob("*/*.json")), "berkas job dibersihkan"


def test_timeline_stage_log_has_signing_mulai_between_the_db_stamps(rig, B):
    """A-04: antre = started-approved; build = signing_mulai-started; tanda tangan = finished-signing_mulai. Cap DB: approved <= started < signing_mulai < finished."""
    aid = rig.analysis()
    rig.start()
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    mulai = rig.stage_log_field(bid, "signing_mulai")
    assert row["status"] == "done" and mulai is not None
    assert row["approved_at"] <= row["started_at"] < mulai < row["finished_at"]
    assert re.search(r"(?m)^build: .*123 MiB", row["stage_log"]) and re.search(r"(?m)^tanda_tangan: ", row["stage_log"])
    assert "/data" not in row["stage_log"]


def test_signing_mulai_is_written_at_the_building_to_signing_transition(rig, B):
    """Cap sudah ada di stage_log SAAT status `signing` (ditulis `mark_signing`), bukan hanya di akhir."""
    aid = rig.analysis()
    seen: dict = {}

    def signer(s, job_id, job):
        seen["row"] = dict(rig.row(job["build_id"]))
        return br.FakeSigner.default(s, job_id, job)

    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    assert seen["row"]["status"] == "signing" and re.search(r"(?m)^signing_mulai=\d+\.\d+$", seen["row"]["stage_log"])


# ====================================================================================== validasi masukan dan klaim
@pytest.mark.parametrize("bad", [True, False, "1", 1.0, 0, -1, 1_000_000_000, None, [1], b"1"])
def test_run_build_rejects_ids_that_are_not_plain_ints_in_range_before_touching_anything(B, monkeypatch, bad):
    monkeypatch.setattr(B, "connect", lambda *a, **k: (_ for _ in ()).throw(AssertionError("tidak boleh membuka DB")))
    B.run_build(bad)


def test_run_build_with_unknown_row_only_logs_a_warning(rig, B, caplog):
    rig.start()
    with caplog.at_level(logging.WARNING):
        rig.run(4242)
    assert any("4242" in r.getMessage() and r.levelno == logging.WARNING for r in caplog.records)
    assert rig.runner.jobs == []


@pytest.mark.parametrize("upto", ["awaiting_approval", "approved"])
def test_run_build_skips_builds_that_are_not_queued(rig, B, upto):
    aid = rig.analysis()
    rig.start()
    bid = rig.build(aid, upto=upto)
    rig.run(bid)
    assert rig.row(bid)["status"] == upto and rig.runner.jobs == [] and rig.signer.jobs == []


def test_run_build_skips_final_and_cancelled_builds_without_a_job(rig, B):
    aid = rig.analysis()
    rig.start()
    done = rig.final_build(aid, "done")
    rig.run(done)
    bid = rig.build(aid)
    assert store.request_cancel_build(rig.conn(), bid) == "cancelled"
    rig.run(bid)
    assert rig.row(done)["status"] == "done" and rig.row(bid)["status"] == "cancelled" and rig.runner.jobs == []


def test_claim_is_compare_and_set_so_two_callers_build_exactly_once(rig, B):
    aid = rig.analysis()

    def slow(r, job_id, job):
        time.sleep(0.4)
        return br.FakeRunner.default(r, job_id, job)

    rig.start(runner=slow)
    bid = rig.build(aid)
    threads = [threading.Thread(target=rig.run, args=(bid,)) for _ in range(2)]
    [t.start() for t in threads]
    [t.join(30) for t in threads]
    assert len(rig.runner.jobs) == 1 and len(rig.signer.jobs) == 1 and rig.row(bid)["status"] == "done"


def test_a_build_already_claimed_elsewhere_is_left_alone(rig, B):
    aid = rig.analysis()
    rig.start()
    bid = rig.build(aid)
    assert store.claim_build(rig.conn(), bid)
    rig.run(bid)                                          # status building != queued
    assert rig.runner.jobs == [] and rig.row(bid)["status"] == "building"


# ====================================================================================== pra-cek signer (gagal cepat)
def test_dead_signer_fails_fast_from_queued_and_the_runner_is_never_used(rig, B):
    aid = rig.analysis()
    rig.start(signer=False)
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"]) == ("failed", "signer_unavailable")
    assert row["started_at"] is None and rig.runner.jobs == [] and "make up" in row["error_text"]
    assert not rig.bdir(aid, bid).exists(), "tidak ada folder: tidak ada kerja yang terbuang"


@pytest.mark.parametrize("state", ["missing", "unreadable", "invalid", "stale"])
def test_keystore_not_ok_fails_fast_with_signer_unavailable(rig, B, state):
    aid = rig.analysis()
    rig.start(keystore_state=state)
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"]) == ("failed", "signer_unavailable") and rig.runner.jobs == []
    assert state in row["error_text"]


def test_stale_signer_heartbeat_fails_fast(rig, B):
    aid = rig.analysis()
    rig.start()
    rig.signer.beating = False
    time.sleep(0.3)
    rig.signer.spool.heartbeat_file.write_text(json.dumps({"ts": time.time() - 120, "pid": 1, "state": "idle", "job": None,
                                                          "keystore": {"state": "ok", "detail": "", "cert_sha256": OWNER}}))
    bid = rig.build(aid)
    rig.run(bid)
    assert rig.row(bid)["error_code"] == "signer_unavailable" and rig.runner.jobs == []


def test_signer_dying_after_the_build_is_signer_unavailable_and_artifacts_are_dropped(rig, B, monkeypatch):
    aid = rig.analysis()
    rig.start()
    bid = rig.build(aid)

    def boom(*a, **k):
        raise signspool.SignerUnavailable("Signer berhenti merespons saat penandatanganan berjalan.")

    monkeypatch.setattr(signspool, "submit_and_wait", boom)
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"]) == ("failed", "signer_unavailable") and "berhenti merespons" in row["error_text"]
    listing_clean(rig, aid, bid)


# ====================================================================================== runner: kode galat dipetakan 1:1
def failing(result: dict):
    """Runner yang gagal tetapi (seperti runner terkompromi/terpotong) meninggalkan sisa: src/, unsigned.apk parsial, build.log."""
    def behave(r, job_id, job):
        br.FakeRunner.default(r, job_id, job)
        return result
    return behave


@pytest.mark.parametrize("code", [c for c in buildproto.BUILD_ERROR_CODES if c != "cancelled"])
def test_every_runner_error_code_maps_one_to_one_to_fail_build(rig, B, code):
    status = code if code in ("timeout", "aborted") else "failed"
    aid = rig.analysis()
    rig.start(runner=failing({"status": status, "error_code": code, "error_text": "", "elapsed": 2.0}))
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"], row["error_text"]) == ("failed", code, buildproto.ERROR_TEXT[code])
    assert rig.signer.jobs == [] and row["finished_at"] is not None
    listing_clean(rig, aid, bid)
    assert "build.log" in rig.listing(aid, bid)


def test_build_failed_carries_the_filtered_error_line_and_a_short_stage_log(rig, B):
    aid = rig.analysis()
    tail = "I: x\n" + "z" * 1900 + "\nW: /data/builds/1/2/src/res/a.xml tidak ada"
    rig.start(runner=failing({"status": "failed", "error_code": "build_failed", "error_text": "error: resource tidak ketemu di /data/work/1/apktool/res",
                              "elapsed": 4.0, "peak_mem_mib": 300, "apktool_log_tail": tail}))
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert row["error_code"] == "build_failed" and row["error_text"].startswith(buildproto.ERROR_TEXT["build_failed"])
    assert "resource tidak ketemu" in row["error_text"] and "/data" not in row["error_text"]
    assert "/data" not in row["stage_log"] and "tidak ada" in row["stage_log"] and row["stage_log"].count("z") <= 1500


@pytest.mark.parametrize("raw,want", [
    ({"status": "aborted", "error_code": "runner_restart", "message": "runner dimulai ulang"}, "aborted"),      # A-11: bawaan abort_orphans
    ({"status": "failed", "error_code": "tool_error", "message": "x"}, "internal"),                              # A-11: jalur pengecualian main
    ({"status": "ok", "output_size": 5}, "bad_result"),                                                           # klaim ok tanpa hash
    ({"status": "mungkin", "error_code": "build_failed"}, "bad_result"),
    ({"status": "failed", "error_code": ["tak", "hashable"]}, "internal"),
])
def test_runner_results_are_normalised_before_use(rig, B, raw, want):
    aid = rig.analysis()
    rig.start(runner=failing(raw))
    bid = rig.build(aid)
    rig.run(bid)
    assert (rig.row(bid)["status"], rig.row(bid)["error_code"]) == ("failed", want) and rig.signer.jobs == []


def test_a_corrupt_runner_result_file_is_bad_result(rig, B):
    def corrupt(r, job_id, job):
        (r.spool.results / f"{job_id}.json").write_bytes(b"{rusak")
        return HANG
    aid = rig.analysis()
    rig.start(runner=corrupt)
    bid = rig.build(aid)
    rig.run(bid)
    assert rig.row(bid)["error_code"] == "bad_result"


@pytest.mark.parametrize("kind", ["fifo", "symlink_zero", "oversize"])
def test_hostile_runner_result_files_never_hang_or_exhaust_the_worker(rig, B, kind):
    def hostile(r, job_id, job):
        path = r.spool.results / f"{job_id}.json"
        if kind == "fifo":
            os.mkfifo(path)
        elif kind == "symlink_zero":
            path.symlink_to("/dev/zero")
        else:
            path.write_text(json.dumps({"status": "failed", "error_code": "build_failed", "apktool_log_tail": "x" * (70 * 1024)}))
        return HANG
    aid = rig.analysis()
    rig.start(runner=hostile)
    bid = rig.build(aid)
    _, exc = within_call(20, rig.run, bid)
    assert exc is None and (rig.row(bid)["status"], rig.row(bid)["error_code"]) == ("failed", "bad_result")


def test_unclaimed_job_is_withdrawn_after_the_pickup_timeout(rig, B):
    aid = rig.analysis()
    rig.start(runner=False)
    bid = rig.build(aid)
    rig.run(bid, pickup_timeout=1)
    row = rig.row(bid)
    assert (row["status"], row["error_code"]) == ("failed", "runner_unavailable")
    assert not list(rig.layout.spool.glob("requests/*.json")), "request ditarik kembali"
    assert rig.signer.jobs == []
    listing_clean(rig, aid, bid)


def test_runner_that_stops_its_heartbeat_after_pickup_is_runner_unavailable(rig, B, monkeypatch):
    monkeypatch.setattr(B, "RUNNER_STALE_AFTER", 0.6)
    aid = rig.analysis()

    def go_silent(r, job_id, job):
        r.beating = False
        return HANG
    rig.start(runner=go_silent)
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"]) == ("failed", "runner_unavailable") and rig.signer.jobs == []


def test_a_fifo_as_runner_heartbeat_does_not_hang_the_worker(rig, B, monkeypatch):
    monkeypatch.setattr(B, "RUNNER_STALE_AFTER", 0.6)
    aid = rig.analysis()

    def fifo_beat(r, job_id, job):
        r.beating = False
        time.sleep(0.3)
        r.spool.heartbeat_file.unlink()
        os.mkfifo(r.spool.heartbeat_file)
        return HANG
    rig.start(runner=fifo_beat)
    bid = rig.build(aid)
    _, exc = within_call(20, rig.run, bid)
    assert exc is None and rig.row(bid)["error_code"] == "runner_unavailable"


def test_runner_that_never_finishes_is_asked_to_cancel_then_times_out(rig, B, monkeypatch):
    monkeypatch.setattr(B, "GRACE", 0.3)
    aid = rig.analysis()
    seen: dict = {}

    def endless(r, job_id, job):
        seen["cancel_asked"] = r.wait_cancel(job_id, 10)
        return HANG
    rig.start(runner=endless)
    bid = rig.build(aid)
    rig.run(bid, timeout_build=1)
    row = rig.row(bid)
    assert seen["cancel_asked"] is True
    assert (row["status"], row["error_code"]) == ("failed", "timeout") and rig.signer.jobs == []


# ====================================================================================== pembatalan
def test_cancel_while_the_job_is_still_waiting_withdraws_it(rig, B):
    aid = rig.analysis()
    rig.start(runner=False)
    bid = rig.build(aid)
    threading.Timer(0.4, lambda: store.request_cancel_build(rig.conn(), bid)).start()
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"]) == ("cancelled", "cancelled")
    assert not list(rig.layout.spool.glob("requests/*.json")) and rig.signer.jobs == []


def test_cancel_while_building_asks_the_runner_and_ends_cancelled(rig, B):
    aid = rig.analysis()
    seen: dict = {}

    def runner(r, job_id, job):
        br.FakeRunner.default(r, job_id, job)
        assert store.request_cancel_build(rig.conn(), job["build_id"]) == "requested"
        seen["asked"] = r.wait_cancel(job_id)
        return {"status": "cancelled", "error_code": "cancelled", "error_text": "", "elapsed": 1.0}
    rig.start(runner=runner)
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert seen["asked"] is True and (row["status"], row["error_code"]) == ("cancelled", "cancelled") and rig.signer.jobs == []
    listing_clean(rig, aid, bid)


def test_runner_cancelled_without_a_db_request_is_failed_not_cancelled(rig, B):
    """Runner membatalkan sendiri (mis. pembersihan yatim saat restart) tanpa permintaan pengguna: `cancel_build` akan ditolak store, jadi build gagal."""
    aid = rig.analysis()
    rig.start(runner=failing({"status": "cancelled", "error_code": "cancelled", "error_text": "", "elapsed": 1.0}))
    bid = rig.build(aid)
    rig.run(bid)
    assert (rig.row(bid)["status"], rig.row(bid)["error_code"]) == ("failed", "cancelled")


def test_cancel_requested_just_before_signing_wins_over_mark_signing(rig, B):
    aid = rig.analysis()

    def runner(r, job_id, job):
        res = br.FakeRunner.default(r, job_id, job)
        store.request_cancel_build(rig.conn(), job["build_id"])
        return res                                          # runner selesai OK, tetapi pembatalan sudah masuk
    rig.start(runner=runner)
    bid = rig.build(aid)
    rig.run(bid)
    assert rig.row(bid)["status"] == "cancelled" and rig.signer.jobs == []
    listing_clean(rig, aid, bid)


def test_cancel_while_signing_stops_the_signer_job_and_cleans_up(rig, B):
    aid = rig.analysis()
    seen: dict = {}

    def signer(s, job_id, job):
        assert store.request_cancel_build(rig.conn(), job["build_id"]) == "requested"
        seen["asked"] = s.wait_cancel(job_id)
        return failure_result("cancelled")
    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    assert seen["asked"] is True and (rig.row(bid)["status"], rig.row(bid)["error_code"]) == ("cancelled", "cancelled")
    listing_clean(rig, aid, bid)


def test_finish_losing_to_a_late_cancel_deletes_the_artifact_and_cancels(rig, B, monkeypatch):
    aid = rig.analysis()
    raised: list = []
    real = store.finish_build

    def spy(*a, **k):
        try:
            return real(*a, **k)
        except store.BuildStateError as exc:
            raised.append(exc)
            raise
    monkeypatch.setattr(store, "finish_build", spy)

    def signer(s, job_id, job):
        store.request_cancel_build(rig.conn(), job["build_id"])
        return br.FakeSigner.default(s, job_id, job)                 # penanda tangan sudah terlanjur selesai
    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    assert len(raised) == 1 and rig.row(bid)["status"] == "cancelled"
    assert rig.listing(aid, bid) == ["build.log"], "artefak yang sudah dinamai ikut dihapus"


def test_cancel_build_losing_the_race_is_caught_and_never_escapes_to_rq(rig, B, monkeypatch, caplog):
    aid = rig.analysis()
    monkeypatch.setattr(store, "cancel_build", lambda *a, **k: (_ for _ in ()).throw(store.BuildStateError("kalah balapan")))

    def signer(s, job_id, job):
        store.request_cancel_build(rig.conn(), job["build_id"])
        return br.FakeSigner.default(s, job_id, job)
    rig.start(signer=signer)
    bid = rig.build(aid)
    with caplog.at_level(logging.WARNING):
        rig.run(bid)                                                  # tidak melempar
    assert rig.listing(aid, bid) == ["build.log"] and any(r.levelno == logging.WARNING for r in caplog.records)


def test_finish_after_recovery_marked_the_row_failed_is_caught_and_the_artifact_deleted(rig, B, caplog):
    """Worker baru sudah menandai baris `failed/interrupted` (recover_stuck_builds) saat worker lama masih menyelesaikan: tidak ada pengecualian, artefak dibuang."""
    aid = rig.analysis()

    def signer(s, job_id, job):
        store.recover_stuck_builds(rig.conn())
        return br.FakeSigner.default(s, job_id, job)
    rig.start(signer=signer)
    bid = rig.build(aid)
    with caplog.at_level(logging.WARNING):
        rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"]) == ("failed", "interrupted") and rig.listing(aid, bid) == ["build.log"]


# ====================================================================================== signer: hasil dan verifikasi
@pytest.mark.parametrize("code", sorted(c for c in signspool.ERROR_CODES if c != "cancelled"))
def test_signer_error_codes_become_sign_prefixed_failures_and_artifacts_are_dropped(rig, B, code):
    aid = rig.analysis()

    def signer(s, job_id, job):
        (s.layout.build_dir(job["analysis_id"], job["build_id"]) / ".sign-signed.tmp").write_bytes(b"sisa")
        return failure_result(code)
    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"], row["error_text"]) == ("failed", f"sign_{code}", signspool.ERROR_TEXT[code])
    listing_clean(rig, aid, bid)


def test_certificate_must_equal_the_owner_read_NOW_not_at_the_start(rig, B):
    aid = rig.analysis()

    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        s.keystore["cert_sha256"] = br.OTHER                       # kunci diganti di tengah jalan
        time.sleep(0.5)                                           # detak jantung berikutnya membawa sertifikat baru
        return res
    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"]) == ("failed", "sign_cert_mismatch") and row["verify_ok"] is None
    listing_clean(rig, aid, bid)


def test_a_result_signed_with_another_certificate_is_rejected(rig, B):
    aid = rig.analysis()

    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        return {**res, "cert_sha256": br.OTHER}
    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    assert rig.row(bid)["error_code"] == "sign_cert_mismatch"
    listing_clean(rig, aid, bid)


def test_owner_certificate_that_cannot_be_confirmed_is_a_mismatch(rig, B):
    aid = rig.analysis()

    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        s.beating = False
        time.sleep(0.3)
        s.spool.heartbeat_file.write_text(json.dumps({"ts": time.time() - 25, "pid": 1, "state": "idle", "job": None,
                                                      "keystore": {"state": "ok", "detail": "", "cert_sha256": OWNER}}))
        return res
    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    assert rig.row(bid)["error_code"] == "sign_cert_mismatch"


def test_input_hash_differing_from_the_runner_output_is_artifact_changed(rig, B):
    aid = rig.analysis()

    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        return {**res, "input_sha256": sha(b"dukun")}
    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    assert rig.row(bid)["error_code"] == "artifact_changed"
    listing_clean(rig, aid, bid)


@pytest.mark.parametrize("over", [
    {"verify": {"v1": False, "v2": True, "v3": False}},
    {"verify": {"v1": False, "v2": False, "v3": True}},
    {"signer_count": 2},
    {"output_size": 0},
    {"ok": "true"},
])
def test_incoherent_or_weak_signer_results_are_sign_bad_result(rig, B, over):
    aid = rig.analysis()

    def signer(s, job_id, job):
        return {**br.FakeSigner.default(s, job_id, job), **over}
    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    assert rig.row(bid)["error_code"] == "sign_bad_result"
    listing_clean(rig, aid, bid)


def good_result(**over):
    res = signed_result(sha(b"in"), b"out", **over)
    return res


def test_check_sign_result_enforces_every_condition_independently_of_the_normaliser(B):
    base = good_result()
    runner_sha = sha(b"in")
    assert B._check_sign_result(base, OWNER, runner_sha) is None
    cases = [
        ({**base, "ok": False}, "sign_bad_result"),
        ({**base, "ok": 1}, "sign_bad_result"),
        ({**base, "cert_sha256": br.OTHER}, "sign_cert_mismatch"),
        ({**base, "verify": {"v1": None, "v2": False, "v3": True}}, "sign_bad_result"),
        ({**base, "verify": {"v1": None, "v2": True, "v3": False}}, "sign_bad_result"),
        ({**base, "signer_count": 2}, "sign_bad_result"),
        ({**base, "signer_count": None}, "sign_bad_result"),
        ({**base, "output_size": 0}, "sign_bad_result"),
        ({**base, "input_sha256": sha(b"lain")}, "artifact_changed"),
        ({**base, "input_sha256": None}, "artifact_changed"),
    ]
    for res, code in cases:
        got = B._check_sign_result(res, OWNER, runner_sha)
        assert got is not None and got[0] == code, (res, got)
    assert B._check_sign_result(base, None, runner_sha)[0] == "sign_cert_mismatch"


# ====================================================================================== penamaan dan terbit artefak
@pytest.mark.parametrize("package,display,want", [
    ("com.contoh.app", "x.apk", "com.contoh.app-modified-7.apk"),
    (None, "Foto Saya (1).apk", "Foto_Saya_1_-modified-7.apk"),
    ("../../etc/passwd", "x.apk", "etc_passwd-modified-7.apk"),
    ("", "", "app-modified-7.apk"),
    (None, None, "app-modified-7.apk"),
    ("...", "---.apk", "app-modified-7.apk"),
    ("\u043f\u0430\u043a\u0435\u0442", "x.apk", "x-modified-7.apk"),
    ("a" * 200, "x.apk", "a" * 80 + "-modified-7.apk"),
    ("-rf", "x.apk", "rf-modified-7.apk"),
    ("x\ny\x00z", "x.apk", "x_y_z-modified-7.apk"),
])
def test_artifact_name_is_derived_from_the_package_or_filename_only(B, package, display, want):
    name = B.artifact_name(package, display, 7)
    assert name == want and store._OUTPUT_NAME_RE.fullmatch(name)


def test_artifact_name_ignores_note_and_requested_by(rig, B):
    aid = rig.analysis(package="com.contoh.app")
    rig.start()
    bid = rig.build(aid, note="nama=../../../etc/shadow; rm -rf /", requested_by="ai:99999")
    rig.run(bid)
    assert rig.row(bid)["output_name"] == f"com.contoh.app-modified-{bid}.apk"


def test_a_directory_squatting_on_the_destination_name_is_removed_and_the_artifact_still_publishes(rig, B):
    """A-17: tujuan rename berupa direktori (berisi direktori mode 000) -> rmtree_at lalu rename; tak pernah EISDIR tak tertangani."""
    aid = rig.analysis(package="com.contoh.app")

    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        bdir = s.layout.build_dir(job["analysis_id"], job["build_id"])
        squat = bdir / f"com.contoh.app-modified-{job['build_id']}.apk"
        (squat / "dalam" / "lagi").mkdir(parents=True)
        (squat / "dalam" / "lagi" / "f").write_text("x")
        os.chmod(squat / "dalam" / "lagi", 0o000)
        return res
    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    path = rig.bdir(aid, bid) / row["output_name"]
    assert row["status"] == "done" and path.is_file() and not path.is_symlink() and sha(path.read_bytes()) == row["output_sha256"]


def test_an_existing_file_at_the_destination_name_is_replaced(rig, B):
    aid = rig.analysis(package="com.contoh.app")

    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        (s.layout.build_dir(job["analysis_id"], job["build_id"]) / f"com.contoh.app-modified-{job['build_id']}.apk").write_bytes(b"palsu")
        return res
    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert row["status"] == "done" and sha((rig.bdir(aid, bid) / row["output_name"]).read_bytes()) == row["output_sha256"]


def tamper(kind: str, victim_file: Path | None = None):
    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        signed = s.layout.build_dir(job["analysis_id"], job["build_id"]) / "signed.apk"
        if kind == "content":
            signed.write_bytes(b"X" * signed.stat().st_size)         # ukuran sama, isi lain
        elif kind == "size":
            signed.write_bytes(signed.read_bytes() + b"tambahan")
        elif kind == "missing":
            signed.unlink()
        elif kind == "hardlink":
            os.link(signed, signed.with_name("tautan"))
        elif kind == "symlink":
            signed.unlink()
            signed.symlink_to(victim_file)
        elif kind == "fifo":
            signed.unlink()
            os.mkfifo(signed)
        elif kind == "directory":
            signed.unlink()
            signed.mkdir()
        return res
    return signer


@pytest.mark.parametrize("kind", ["content", "size", "missing", "hardlink", "symlink", "fifo", "directory"])
def test_signed_apk_that_is_not_exactly_what_the_signer_reported_is_artifact_changed(rig, B, kind):
    aid = rig.analysis()
    secret = rig.root / "rahasia.bin"
    secret.write_bytes(b"jangan disentuh")
    rig.start(signer=tamper(kind, secret))
    bid = rig.build(aid)
    _, exc = within_call(20, rig.run, bid)
    row = rig.row(bid)
    assert exc is None and (row["status"], row["error_code"]) == ("failed", "artifact_changed")
    assert secret.read_bytes() == b"jangan disentuh"
    left = rig.listing(aid, bid)
    assert not [n for n in left if "-modified-" in n] and "signed.apk" not in left and "unsigned.apk" not in left, left


def test_file_swapped_between_the_hash_and_the_rename_is_caught_by_the_inode_check(rig, B, monkeypatch):
    """Balapan terakhir: runner mengganti `signed.apk` SETELAH di-hash dari fd dan SEBELUM rename; yang terbit bukan berkas yang di-hash -> artifact_changed dan dihapus."""
    aid = rig.analysis()
    real = B._rename_over

    def swap_then_rename(bfd, src, dst):
        size = os.stat(src, dir_fd=bfd).st_size
        os.unlink(src, dir_fd=bfd)
        fd = os.open(src, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=bfd)
        os.write(fd, b"Y" * size)
        os.close(fd)
        real(bfd, src, dst)
    monkeypatch.setattr(B, "_rename_over", swap_then_rename)
    rig.start()
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"]) == ("failed", "artifact_changed")
    assert not [n for n in rig.listing(aid, bid) if "-modified-" in n], rig.listing(aid, bid)


# ====================================================================================== runner terkompromi menanam symlink di builds/
def test_symlinked_or_squatted_folders_planted_before_the_build_are_replaced_without_following(rig, B, tmp_path):
    aid = rig.analysis()
    rig.start()
    bid = rig.build(aid)
    v = br.victim(tmp_path)
    (rig.layout.builds / str(aid)).symlink_to(v)                    # <aid> ditanam
    rig.run(bid)
    assert rig.row(bid)["status"] == "done" and br.victim_intact(v)
    assert (rig.layout.builds / str(aid)).is_dir() and not (rig.layout.builds / str(aid)).is_symlink()

    aid2 = rig.analysis()
    bid2 = rig.build(aid2)
    (rig.layout.builds / str(aid2)).mkdir()
    (rig.layout.builds / str(aid2) / str(bid2)).symlink_to(v)          # <bid> ditanam
    rig.run(bid2)
    assert rig.row(bid2)["status"] == "done" and br.victim_intact(v)

    aid3 = rig.analysis()
    bid3 = rig.build(aid3)
    (rig.layout.builds / str(aid3)).write_text("berkas menyamar jadi folder")
    rig.run(bid3)
    assert rig.row(bid3)["status"] == "done"


def test_stale_leftovers_in_the_build_folder_are_removed_before_building(rig, B):
    aid = rig.analysis()
    bid = rig.build(aid)
    d = rig.bdir(aid, bid)
    (d / "src" / "a" / "b").mkdir(parents=True)
    (d / "src" / "a" / "b" / "f").write_text("lama")
    os.chmod(d / "src" / "a" / "b", 0o000)
    (d / "stale.txt").write_text("lama")
    os.mkfifo(d / ".sign-x")
    rig.start()
    _, exc = within_call(20, rig.run, bid)
    row = rig.row(bid)
    assert exc is None and row["status"] == "done"
    assert rig.listing(aid, bid) == sorted(["build.log", row["output_name"]])


def test_aid_swapped_for_a_symlink_before_naming_fails_closed_and_the_target_is_untouched(rig, B, tmp_path):
    aid = rig.analysis()
    v = br.victim(tmp_path)

    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        br.plant_symlink(s.layout.builds / str(job["analysis_id"]), v)       # runner menukar <aid> setelah signer menerbitkan
        return res
    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"]) == ("failed", "artifact_changed") and br.victim_intact(v)
    assert (rig.layout.builds / str(aid)).is_symlink(), "worker tidak menghapus apa pun lewat symlink"


def test_bid_swapped_for_a_symlink_before_naming_fails_closed(rig, B, tmp_path):
    aid = rig.analysis()
    v = br.victim(tmp_path)

    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        br.plant_symlink(s.layout.build_dir(job["analysis_id"], job["build_id"]), v)
        return res
    rig.start(signer=signer)
    bid = rig.build(aid)
    rig.run(bid)
    assert rig.row(bid)["error_code"] == "artifact_changed" and br.victim_intact(v)


def test_aid_swapped_for_a_symlink_before_prune_unlinks_only_the_link_and_only_the_targeted_rows(rig, B, tmp_path, monkeypatch):
    """A-17: `builds/<aid>` jadi symlink tepat sebelum prune -> entri itu di-unlink; HANYA baris build yang ditargetkan prune dihapus."""
    aid = rig.analysis()
    old = [rig.final_build(aid, "done") for _ in range(3)]
    v = br.victim(tmp_path)
    real = store.finish_build

    def planting(*a, **k):
        out = real(*a, **k)
        br.plant_symlink(rig.layout.builds / str(aid), v)
        return out
    monkeypatch.setattr(store, "finish_build", planting)
    rig.start()
    bid = rig.build(aid)
    rig.run(bid, keep=2)
    assert rig.row(bid)["status"] == "done" and br.victim_intact(v)
    assert not (rig.layout.builds / str(aid)).is_symlink() and not (rig.layout.builds / str(aid)).exists(), "symlink di-unlink"
    assert [rig.exists(i) for i in old] == [False, False, True], "hanya baris yang ditargetkan prune (dua tertua) hilang"
    assert rig.exists(bid)


def test_victim_work_dir_survives_every_plant_point(rig, B, tmp_path):
    """Sasaran symlink = `work/<n>` sungguhan (baseline analisis): tak boleh tersentuh di titik tanam mana pun."""
    aid = rig.analysis()
    base = rig.layout.work / "77" / "apktool"
    base.mkdir(parents=True)
    (base / "AndroidManifest.xml").write_text("<manifest/>")
    (rig.layout.builds / str(aid)).symlink_to(rig.layout.work / "77")
    rig.start()
    bid = rig.build(aid)
    rig.run(bid)
    assert (base / "AndroidManifest.xml").read_text() == "<manifest/>" and rig.row(bid)["status"] == "done"


# ====================================================================================== bersih pada SETIAP status final
def test_unsigned_apk_and_scratch_are_removed_on_every_final_status(rig, B):
    scenarios = {
        "done": dict(),
        "runner_fail": dict(runner=failing({"status": "failed", "error_code": "no_output", "error_text": "", "elapsed": 1})),
        "sign_fail": dict(signer=lambda s, j, job: (s.layout.build_dir(job["analysis_id"], job["build_id"]).joinpath(".sign-signed.tmp").write_bytes(b"x"),
                                                    failure_result("sign_failed"))[1]),
    }
    for name, kw in scenarios.items():
        aid = rig.analysis()
        rig.stop()
        rig.start(**kw)
        bid = rig.build(aid)
        rig.run(bid)
        listing_clean(rig, aid, bid)
        assert rig.row(bid)["status"] == ("done" if name == "done" else "failed"), name


# ====================================================================================== prune BUILD_KEEP
def test_prune_removes_old_finals_directory_first_never_touches_active_and_returns_ids(rig, B, monkeypatch):
    aid = rig.analysis()
    done = [rig.final_build(aid, "done") for _ in range(4)]
    bad = [rig.final_build(aid, "failed"), rig.final_build(aid, "cancelled"), rig.final_build(aid, "failed")]
    active = rig.build(aid, upto="awaiting_approval")
    rig.bdir(aid, active).mkdir()
    (rig.bdir(aid, active) / "penting").write_text("x")
    order: list = []
    real = store.delete_build

    def spy(conn, bid):
        order.append((bid, rig.bdir(aid, bid).exists()))
        return real(conn, bid)
    monkeypatch.setattr(store, "delete_build", spy)
    conn = rig.conn()
    gone = B.prune_analysis(conn, rig.layout, aid, keep=2)
    assert gone == sorted(done[:2] + bad[:1]) and all(not exists for _, exists in order), order
    assert [i for i in done + bad if rig.exists(i)] == done[2:] + bad[1:]
    assert rig.row(active)["status"] == "awaiting_approval" and (rig.bdir(aid, active) / "penting").read_text() == "x"


def test_prune_oserror_keeps_the_row_logs_a_warning_and_retries_next_time(rig, B, monkeypatch, caplog):
    aid = rig.analysis()
    ids = [rig.final_build(aid, "done") for _ in range(3)]
    real = B.rmtree_at

    def flaky(fd, name):
        if name == str(ids[0]):
            raise PermissionError(13, "ditolak")
        return real(fd, name)
    monkeypatch.setattr(B, "rmtree_at", flaky)
    with caplog.at_level(logging.WARNING):
        assert B.prune_analysis(rig.conn(), rig.layout, aid, keep=1) == [ids[1]]
    assert rig.exists(ids[0]) and not rig.exists(ids[1]) and rig.exists(ids[2]) and rig.bdir(aid, ids[0]).exists()
    assert any(r.levelno == logging.WARNING for r in caplog.records)
    monkeypatch.setattr(B, "rmtree_at", real)
    assert B.prune_analysis(rig.conn(), rig.layout, aid, keep=1) == [ids[0]]
    assert not rig.exists(ids[0]) and not rig.bdir(aid, ids[0]).exists()


def test_prune_with_a_symlinked_aid_unlinks_it_and_deletes_only_the_targeted_rows(rig, B, tmp_path):
    aid = rig.analysis()
    ids = [rig.final_build(aid, "done") for _ in range(4)]
    other = rig.analysis()
    other_bid = rig.final_build(other, "done")
    v = br.victim(tmp_path)
    br.plant_symlink(rig.layout.builds / str(aid), v)
    assert B.prune_analysis(rig.conn(), rig.layout, aid, keep=2) == ids[:2]
    assert [rig.exists(i) for i in ids] == [False, False, True, True], "build final lain analisis itu TIDAK ikut dihapus"
    assert br.victim_intact(v) and not (rig.layout.builds / str(aid)).exists()
    assert rig.exists(other_bid) and rig.bdir(other, other_bid).is_dir(), "analisis lain utuh"


def test_prune_without_a_folder_still_deletes_the_rows(rig, B):
    aid = rig.analysis()
    ids = [rig.final_build(aid, "done", make_dir=False) for _ in range(3)]
    assert B.prune_analysis(rig.conn(), rig.layout, aid, keep=1) == ids[:2]


def test_prune_follows_build_keep_from_the_environment(rig, B, monkeypatch):
    aid = rig.analysis()
    ids = [rig.final_build(aid, "done") for _ in range(3)]
    monkeypatch.setenv("BUILD_KEEP", "2")
    assert B.prune_analysis(rig.conn(), rig.layout, aid) == ids[:1]


def test_prune_for_uses_its_own_connection_and_prints_the_pruned_ids(rig, B, monkeypatch, capsys):
    aid = rig.analysis()
    ids = [rig.final_build(aid, "done") for _ in range(3)]
    monkeypatch.setenv("DATA_DIR", str(rig.layout.root))
    monkeypatch.setenv("BUILD_KEEP", "1")
    B.prune_for(aid)
    assert capsys.readouterr().out.strip() == "pruned=" + ",".join(str(i) for i in ids[:2])
    B.prune_for(aid)
    assert capsys.readouterr().out.strip() == "pruned="


def test_run_build_prunes_after_a_final_status_by_default_keep(rig, B):
    aid = rig.analysis()
    old = [rig.final_build(aid, "done") for _ in range(3)]
    rig.start()
    bid = rig.build(aid)
    rig.run(bid, keep=2)
    assert rig.row(bid)["status"] == "done" and [rig.exists(i) for i in old] == [False, False, True]


# ====================================================================================== pemulihan setelah restart
def test_reconcile_fails_stuck_builds_cleans_their_scratch_and_sweeps_no_orphans(rig, B):
    a1, a2, a3 = rig.analysis(), rig.analysis(), rig.analysis()
    b1 = rig.build(a1)
    b2 = rig.build(a2)
    b3 = rig.build(a3)
    conn = rig.conn()
    assert store.claim_build(conn, b1)
    assert store.claim_build(conn, b2)
    store.mark_signing(conn, b2)
    for aid, bid in ((a1, b1), (a2, b2), (a3, b3)):
        d = rig.bdir(aid, bid)
        (d / "src" / "res").mkdir(parents=True)
        for n in ("unsigned.apk", "signed.apk", ".sign-signed.tmp", "build.log"):
            (d / n).write_text("x")
    orphan = rig.layout.builds / "999" / "1"
    orphan.mkdir(parents=True)
    (orphan / "f").write_text("yatim")
    assert B.reconcile(rig.layout) == [b1, b2]
    for bid in (b1, b2):
        row = rig.row(bid)
        assert (row["status"], row["error_code"]) == ("failed", "interrupted")
    assert rig.listing(a1, b1) == ["build.log"] and rig.listing(a2, b2) == ["build.log"]
    assert rig.row(b3)["status"] == "queued" and "unsigned.apk" in rig.listing(a3, b3), "build antre tak disentuh"
    assert (orphan / "f").read_text() == "yatim", "tanpa sapu yatim"
    assert B.reconcile(rig.layout) == []                               # idempoten


def test_reconcile_does_not_follow_a_planted_symlink(rig, B, tmp_path):
    aid = rig.analysis()
    bid = rig.build(aid)
    assert store.claim_build(rig.conn(), bid)
    v = br.victim(tmp_path)
    (rig.layout.builds / str(aid)).symlink_to(v)
    assert B.reconcile(rig.layout) == [bid] and br.victim_intact(v)


def redis_pair():
    import fakeredis
    import rq
    conn = fakeredis.FakeStrictRedis()
    return conn, rq.Queue("jobs", connection=conn)


def test_requeue_orphans_sends_queued_and_approved_builds_without_a_job_once(rig, B, monkeypatch):
    from rq.job import Job
    monkeypatch.setenv("DATA_DIR", str(rig.layout.root))
    monkeypatch.setenv("TIMEOUT_BUILD", "100")
    monkeypatch.setenv("TIMEOUT_SIGN", "50")
    a1, a2, a3, a4 = (rig.analysis() for _ in range(4))
    queued, approved = rig.build(a1, upto="queued"), rig.build(a2, upto="approved")
    waiting = rig.build(a3, upto="awaiting_approval")
    has_job = rig.build(a4, upto="queued")
    conn, queue = redis_pair()
    queue.enqueue("tasks.run_build", has_job, job_id=f"build-{has_job}-aaaaaaaa")
    assert B.requeue_orphans(conn) == sorted([queued, approved])
    assert rig.row(approved)["status"] == "queued" and rig.row(waiting)["status"] == "awaiting_approval"
    ids = queue.job_ids
    for bid in (queued, approved):
        job_id = next(j for j in ids if j.startswith(f"build-{bid}-"))
        assert re.fullmatch(rf"build-{bid}-[0-9a-f]{{8}}", job_id)
        job = Job.fetch(job_id, connection=conn)
        assert (job.func_name, job.args, job.timeout, job.result_ttl, job.failure_ttl) == ("tasks.run_build", (bid,), 750, 300, 86400)
    assert len([j for j in ids if j.startswith(f"build-{has_job}-")]) == 1 and not any(j.startswith(f"build-{waiting}-") for j in ids)
    assert B.requeue_orphans(conn) == [], "duplikat aman"


def test_requeue_orphans_survives_redis_failure_and_recovers_later(rig, B, monkeypatch, caplog):
    import redis
    import rq
    monkeypatch.setenv("DATA_DIR", str(rig.layout.root))
    aid = rig.analysis()
    bid = rig.build(aid, upto="approved")
    conn, queue = redis_pair()
    real = rq.Queue.enqueue
    monkeypatch.setattr(rq.Queue, "enqueue", lambda *a, **k: (_ for _ in ()).throw(redis.ConnectionError("mati")))
    with caplog.at_level(logging.WARNING):
        assert B.requeue_orphans(conn) == []                                   # tidak melempar: worker tetap naik
    assert any(r.levelno == logging.WARNING for r in caplog.records) and rig.row(bid)["status"] == "queued"
    monkeypatch.setattr(rq.Queue, "enqueue", real)
    assert B.requeue_orphans(conn) == [bid] and any(j.startswith(f"build-{bid}-") for j in queue.job_ids)


# ====================================================================================== worker.py, tasks.py, Dockerfile, compose
def test_tasks_run_build_delegates_without_coercing_the_argument(B, monkeypatch):
    import tasks
    seen: list = []
    monkeypatch.setattr(B, "run_build", lambda build_id, *a, **k: seen.append(build_id))
    tasks.run_build(5)
    tasks.run_build("5")                                                    # validasi `type is int` ada di builds, bukan dikoersi diam-diam
    assert seen == [5, "5"]


def test_heartbeat_loop_publishes_the_signer_heartbeat_only_while_it_is_alive(rig, monkeypatch):
    import fakeredis
    import worker
    monkeypatch.setenv("DATA_DIR", str(rig.layout.root))
    monkeypatch.setattr(worker, "HEARTBEAT_EVERY", 0.05)
    conn = fakeredis.FakeStrictRedis()
    rig.start(runner=False)
    stop = threading.Event()
    th = threading.Thread(target=worker.heartbeat_loop, args=(conn, stop), daemon=True)
    th.start()
    try:
        deadline = time.monotonic() + 10
        while conn.get("signer:heartbeat") is None and time.monotonic() < deadline:
            time.sleep(0.05)
        raw = conn.get("signer:heartbeat")
        assert raw is not None, "worker harus meneruskan detak signer ke Redis"
        data = json.loads(raw)
        assert set(data) == {"ts", "state", "keystore_state", "cert_sha256"}
        assert (data["state"], data["keystore_state"], data["cert_sha256"]) == ("idle", "ok", OWNER) and abs(data["ts"] - time.time()) < 5
        assert 0 < conn.ttl("signer:heartbeat") <= 30
        rig.signer.beating = False                                          # signer mati: tidak ada detak baru
        time.sleep(0.3)
        rig.signer.spool.heartbeat_file.write_text(json.dumps({"ts": time.time() - 120, "pid": 1, "state": "idle", "job": None,
                                                              "keystore": {"state": "ok", "detail": "", "cert_sha256": OWNER}}))
        conn.delete("signer:heartbeat")
        time.sleep(0.5)
        assert conn.get("signer:heartbeat") is None, "signer tidak hidup -> tidak ditulis"
        assert conn.get("worker:heartbeat") is not None
    finally:
        stop.set()
        th.join(5)


def test_worker_main_recovers_in_the_documented_order(rig, B, monkeypatch):
    import fakeredis
    import pipeline
    import worker
    calls: list = []
    monkeypatch.setenv("DATA_DIR", str(rig.layout.root))
    monkeypatch.setattr(worker.redis.Redis, "from_url", staticmethod(lambda *a, **k: fakeredis.FakeStrictRedis()))
    monkeypatch.setattr(worker, "migrate", lambda p: calls.append("migrate"))
    monkeypatch.setattr(pipeline, "reconcile", lambda *a, **k: calls.append("pipeline.reconcile") or [])
    monkeypatch.setattr(B, "reconcile", lambda *a, **k: calls.append("builds.reconcile") or [])
    monkeypatch.setattr(worker, "requeue_orphans", lambda *a, **k: calls.append("worker.requeue_orphans") or [])
    monkeypatch.setattr(B, "requeue_orphans", lambda *a, **k: calls.append("builds.requeue_orphans") or [])

    class FakeWorker:
        def __init__(self, *a, **k): pass
        def work(self, **k): calls.append("work")
    monkeypatch.setattr(worker, "Worker", FakeWorker)
    worker.main()
    assert calls == ["migrate", "pipeline.reconcile", "builds.reconcile", "worker.requeue_orphans", "builds.requeue_orphans", "work"]


def worker_modules_imported() -> set[str]:
    present = {p.stem for p in (SERVICES / "worker").glob("*.py")}
    found: set[str] = set()
    for rel in ("tasks.py", "worker.py", "pipeline.py", "builds.py"):
        tree = ast.parse((SERVICES / "worker" / rel).read_text(encoding="utf-8"))
        for node in ast.walk(tree):                                          # termasuk impor malas di dalam fungsi
            if isinstance(node, ast.Import):
                found |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
    return found & present


def test_every_worker_module_imported_by_the_entry_points_is_copied_into_the_image():
    text = (SERVICES / "worker" / "Dockerfile").read_text(encoding="utf-8")
    copied = set(re.findall(r"worker/(\w+)\.py", text))
    need = worker_modules_imported()
    assert "builds" in need and "pipeline" in need
    assert need <= copied, f"modul tidak ikut COPY: {sorted(need - copied)}"


def test_compose_passes_the_build_timeouts_to_the_worker_and_the_code_reads_them(monkeypatch):
    from test_build_compose import block
    env = block("worker")
    assert "TIMEOUT_BUILD: ${TIMEOUT_BUILD:-1800}" in env and "TIMEOUT_SIGN: ${TIMEOUT_SIGN:-900}" in env
    assert not re.search(r"(?i)keystore|signer|SIGNER_", env), "blok worker tidak boleh menyebut signer/keystore (invarian 2a)"
    src = (SERVICES / "worker" / "builds.py").read_text(encoding="utf-8")
    read = set(re.findall(r'environ(?:\.get)?\(\s*"([A-Z_]+)"|_env_int\(\s*"([A-Z_]+)"', src))
    names = {a or b for a, b in read}
    assert {"TIMEOUT_BUILD", "TIMEOUT_SIGN", "DATA_DIR"} <= names
    for name in names - {"RUNNER_PICKUP_TIMEOUT"}:
        assert re.search(rf"\b{name}:", env), f"{name} dibaca worker tetapi tidak diteruskan compose (pola OP-01)"


def test_build_config_reads_and_clamps_the_timeouts(B, monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    for var in ("TIMEOUT_BUILD", "TIMEOUT_SIGN", "RUNNER_PICKUP_TIMEOUT", "BUILD_KEEP"):
        monkeypatch.delenv(var, raising=False)
    cfg = B.BuildConfig.from_env()
    assert (cfg.timeout_build, cfg.timeout_sign, cfg.pickup_timeout) == (1800, 900, 120) and cfg.layout.root == tmp_path
    for raw, want in (("5", 10), ("99999", 3600), ("abc", 1800), ("", 1800), ("600", 600)):
        monkeypatch.setenv("TIMEOUT_BUILD", raw)
        assert B.BuildConfig.from_env().timeout_build == want, raw
    for raw, want in (("5", 10), ("99999", 3600), ("x", 900), ("30", 30)):
        monkeypatch.setenv("TIMEOUT_SIGN", raw)
        assert B.BuildConfig.from_env().timeout_sign == want, raw


def test_requeue_job_timeout_covers_build_plus_sign_plus_margin(B, monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("TIMEOUT_BUILD", "1800")
    monkeypatch.setenv("TIMEOUT_SIGN", "900")
    assert B.BuildConfig.from_env().job_timeout == 1800 + 900 + 600


def test_builds_uses_only_dirfd_relative_operations_on_builds():
    """Penutupan rantai-dirfd (A-03/§7.7): `builds.py` tidak memakai jalur string untuk mengubah `builds/` (tanpa safe_rmtree, shutil.rmtree, mkdir, Path.rename)."""
    tree = ast.parse((SERVICES / "worker" / "builds.py").read_text(encoding="utf-8"))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {"safe_rmtree", "rmtree", "mkdir", "makedirs", "rmdir", "replace", "build_dir", "builds_dir", "unlink_path"}, names
    need_kw = {"rename": {"src_dir_fd", "dst_dir_fd"}, "unlink": {"dir_fd"}, "lstat": {"dir_fd"}, "stat": {"dir_fd"}}
    seen = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
            if node.func.attr in need_kw:
                seen += 1
                assert {k.arg for k in node.keywords} >= need_kw[node.func.attr], ast.unparse(node)
    assert seen >= 3, "tes harus benar-benar melihat panggilan os.rename/unlink/lstat"


# ====================================================================================== proses uid 10001 NYATA (meniru kontainer worker)
DRIVER = textwrap.dedent('''
    import json, os, sys
    sys.path.insert(0, sys.argv[1])
    import build_rig as br
    mode, root = sys.argv[2], sys.argv[3]
    rig = br.Rig(root)
    if mode == "setup":
        aid = rig.analysis()
        bid = rig.build(aid)
        print(json.dumps([aid, bid]))
        sys.exit(0)
    aid, bid = int(sys.argv[4]), int(sys.argv[5])

    def runner(r, job_id, job):
        res = br.FakeRunner.default(r, job_id, job)
        d = r.layout.build_dir(job["analysis_id"], job["build_id"])
        if mode == "junk":
            os.makedirs(d / "src" / "res" / "values" / "dalam")
            (d / "src" / "res" / "values" / "strings.xml").write_text("x")
            os.chmod(d / "src" / "res" / "values" / "strings.xml", 0o444)
            os.chmod(d / "src" / "res" / "values" / "dalam", 0o000)     # direktori tanpa izin apa pun
            os.chmod(d / "src" / "res" / "values", 0o500)               # tanpa izin tulis
        return res
    rig.start(runner=runner)
    rig.run(bid)
    row = rig.row(bid)
    print(json.dumps({"status": row["status"], "code": row["error_code"], "text": row["error_text"], "listing": rig.listing(aid, bid), "name": row["output_name"]}))
    rig.stop()
''')


def run_driver(shared: Path, *args: str) -> subprocess.CompletedProcess:
    script = shared / "driver.py"
    script.write_text(DRIVER)
    return subprocess.run([*AS_10001, str(script), str(ROOT / "tests"), *args], capture_output=True, text=True, timeout=120, cwd=str(shared))


@need_uid
def test_uid10001_worker_cleans_mode000_and_mode444_junk_left_in_the_build_folder():
    shared = open_to_10001(Path(tempfile.mkdtemp(prefix="rv-worker-")))
    try:
        os.chown(shared, 10001, 10001)
        r = run_driver(shared, "setup", str(shared / "d"))
        assert r.returncode == 0, r.stderr
        aid, bid = json.loads(r.stdout)
        r = run_driver(shared, "junk", str(shared / "d"), str(aid), str(bid))
        assert r.returncode == 0, (r.stdout, r.stderr)
        out = json.loads(r.stdout.splitlines()[-1])
        assert out["status"] == "done" and out["listing"] == sorted(["build.log", out["name"]]), out
    finally:
        shutil.rmtree(shared, ignore_errors=True)


@need_uid
def test_uid10001_worker_fails_closed_on_a_root_owned_directory_it_cannot_remove():
    """Sisa milik uid LAIN (root) berisi isi di folder build: worker tidak boleh mogok atau mengabaikannya; build gagal `internal`, isi tak hilang (pelajaran 3)."""
    shared = open_to_10001(Path(tempfile.mkdtemp(prefix="rv-worker-")))
    try:
        os.chown(shared, 10001, 10001)
        r = run_driver(shared, "setup", str(shared / "d"))
        aid, bid = json.loads(r.stdout)
        squat = shared / "d" / "data" / "builds" / str(aid) / str(bid) / "src" / "milik_root"
        squat.mkdir(parents=True)
        (squat / "f").write_text("milik root")
        for p in (squat.parent, squat.parent.parent, squat.parent.parent.parent):
            os.chown(p, 10001, 10001)                                       # folder build milik 10001; hanya `milik_root` milik root
        os.chmod(squat, 0o755)
        r = run_driver(shared, "plain", str(shared / "d"), str(aid), str(bid))
        assert r.returncode == 0, (r.stdout, r.stderr)
        out = json.loads(r.stdout.splitlines()[-1])
        assert out["status"] == "failed" and out["code"] == "internal" and "tidak aman" in out["text"], out
        assert (squat / "f").read_text() == "milik root"
    finally:
        shutil.rmtree(shared, ignore_errors=True)

