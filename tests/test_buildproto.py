"""Protokol tahap `build` (rvcore/buildproto.py + spool.py): validasi di sisi PENERIMA (runner), normalisasi hasil yang TIDAK tepercaya (worker), pemetaan status->kode
(A-11), dan jaminan ukuran hasil <= 8 KiB (signkeys.read_small menolak, tidak memotong)."""

from __future__ import annotations

import json
import re

import pytest
from rvcore import buildproto as B
from rvcore import spool
from rvcore.paths import MAX_PROTO_ID

H = "ab" * 32
G = "cd" * 32


def good(**over):
    job = {"job_id": "a5-build-abcdef12", "stage": "build", "analysis_id": 5, "build_id": 7, "diff_sha256": H, "sha256": G, "timeout": 600}
    job.update(over)
    return job


# ======================================================================================== spool: tahap build ada, tahap lain tidak berubah
def test_spool_knows_the_build_stage_and_old_stages_are_unchanged():
    assert spool.TOOL_STAGES == ("apktool", "jadx", "analyze", "build")
    assert spool.JOB_ID_RE.match(spool.new_job_id(7, "build")) and spool.new_job_id(7, "build").startswith("a7-build-")
    for stage in ("apktool", "jadx", "analyze"):
        assert spool.JOB_ID_RE.match(spool.new_job_id(7, stage))
    assert spool.STAGE_OUT_DIR == {"apktool": "apktool", "jadx": "jadx", "analyze": "index"}, "keluaran build bukan di work/"
    assert not spool.JOB_ID_RE.match("a7-sign-abcdef12") and not spool.JOB_ID_RE.match("a7-build-ABCDEF12")
    with pytest.raises(ValueError):
        spool.new_job_id(7, "sign")


# ======================================================================================== validate_build_request (sisi runner)
def test_valid_request_returns_clamped_fields():
    r = B.validate_build_request(good())
    assert (r.analysis_id, r.build_id, r.diff_sha256, r.sha256, r.timeout) == (5, 7, H, G, 600)
    assert B.validate_build_request(good(timeout=1)).timeout == 10 and B.validate_build_request(good(timeout=10 ** 9)).timeout == 3600
    assert B.validate_build_request(good(analysis_id=MAX_PROTO_ID, build_id=MAX_PROTO_ID)).analysis_id == MAX_PROTO_ID


@pytest.mark.parametrize("mut", [
    {"stage": "apktool"}, {"stage": None}, {"stage": "BUILD"},
    {"analysis_id": "5"}, {"analysis_id": 5.0}, {"analysis_id": True}, {"analysis_id": 0}, {"analysis_id": -1}, {"analysis_id": MAX_PROTO_ID + 1}, {"analysis_id": None},
    {"analysis_id": "../etc"}, {"build_id": "7"}, {"build_id": True}, {"build_id": 0}, {"build_id": 10 ** 9}, {"build_id": 2 ** 31},
    {"diff_sha256": ""}, {"diff_sha256": "A" * 64}, {"diff_sha256": "a" * 63}, {"diff_sha256": "a" * 65}, {"diff_sha256": "g" * 64}, {"diff_sha256": "a" * 64 + "\n"},
    {"diff_sha256": None}, {"diff_sha256": 5},
    {"sha256": ""}, {"sha256": "A" * 64}, {"sha256": "a" * 63}, {"sha256": None},
    {"timeout": "600"}, {"timeout": 600.0}, {"timeout": True}, {"timeout": None},
])
def test_invalid_requests_are_rejected(mut):
    with pytest.raises(ValueError):
        B.validate_build_request(good(**mut))


@pytest.mark.parametrize("missing", ["stage", "analysis_id", "build_id", "diff_sha256", "sha256", "timeout"])
def test_missing_fields_are_rejected(missing):
    job = good()
    del job[missing]
    with pytest.raises(ValueError):
        B.validate_build_request(job)


@pytest.mark.parametrize("bad", [None, [], "x", 5, True])
def test_non_dict_request_is_rejected(bad):
    with pytest.raises(ValueError):
        B.validate_build_request(bad)


def test_path_fields_in_the_request_are_never_read():
    plain = B.validate_build_request(good())
    evil = B.validate_build_request(good(path="/etc/passwd", src="/data/bench/1/project", out="/tmp/x", output="../..", unsigned="/x", home="/root", argv=["rm", "-rf"]))
    assert plain == evil
    assert not {f for f in B.BuildRequest.__dataclass_fields__} & {"path", "src", "out"}


def test_build_build_request_roundtrips_through_the_validator_and_matches_the_spool_id_pattern():
    job = B.build_build_request(5, 7, H, G, 600)
    assert spool.JOB_ID_RE.match(job["job_id"]) and job["stage"] == "build" and set(job) == {"job_id", "stage", "analysis_id", "build_id", "diff_sha256", "sha256", "timeout", "created"}
    assert B.validate_build_request(job).build_id == 7
    for args in ((True, 7, H, G, 600), (5, 0, H, G, 600), (5, 7, "x", G, 600), (5, 7, H, "x", 600), (5, 7, H, G, "600"), (MAX_PROTO_ID + 1, 7, H, G, 600)):
        with pytest.raises(ValueError):
            B.build_build_request(*args)
    assert len(json.dumps(job)) < spool.MAX_REQUEST_BYTES


# ======================================================================================== kode galat
def test_every_error_code_has_one_indonesian_sentence_and_nothing_else():
    assert set(B.ERROR_TEXT) == set(B.BUILD_ERROR_CODES) | {"bad_result"}
    for code, text in B.ERROR_TEXT.items():
        assert text and "\n" not in text and not re.search(r"/data|/tmp|/opt", text), code
        assert re.fullmatch(r"[a-z][a-z0-9_]{0,39}", code)
    assert "hash diff tidak sama" in B.ERROR_TEXT["workspace_changed"] and "ajukan build baru" in B.ERROR_TEXT["workspace_changed"]


# ======================================================================================== parse_build_result (hasil TIDAK tepercaya)
OK = {"status": "ok", "output_size": 4096, "output_sha256": H, "elapsed": 12.5, "peak_mem_mib": 800, "apktool_log_tail": "I: Building apk file...", "files": 12, "bytes": 3000}


def test_a_coherent_success_is_ok():
    r = B.parse_build_result(OK)
    assert r["ok"] is True and r["status"] == "ok" and r["error_code"] is None and r["output_sha256"] == H and r["output_size"] == 4096
    assert r["elapsed"] == 12.5 and r["peak_mem_mib"] == 800 and r["files"] == 12 and r["apktool_log_tail"] == "I: Building apk file..."


@pytest.mark.parametrize("mut", [
    {"output_sha256": None}, {"output_sha256": "A" * 64}, {"output_sha256": "a" * 63}, {"output_sha256": 5}, {"output_size": 0}, {"output_size": -1}, {"output_size": True},
    {"output_size": "4096"}, {"output_size": None}, {"error_code": "build_failed"},
])
def test_incoherent_success_is_bad_result_never_ok(mut):
    r = B.parse_build_result({**OK, **mut})
    assert r["ok"] is False and r["error_code"] == "bad_result" and r["error_text"] == B.ERROR_TEXT["bad_result"] and r["output_sha256"] is None and r["output_size"] == 0


@pytest.mark.parametrize("raw", [None, [], "x", 5, True, {}, {"status": "nonsense"}, {"status": ["ok"]}, {"status": "warn"}, {"ok": True}, {"status": None, "ok": True, "output_sha256": H}])
def test_garbage_is_bad_result(raw):
    r = B.parse_build_result(raw)
    assert r["ok"] is False and r["error_code"] == "bad_result"


def test_only_status_ok_can_be_ok_a_bare_ok_flag_is_ignored():
    assert B.parse_build_result({**OK, "status": "failed", "ok": True})["ok"] is False
    assert B.parse_build_result({"ok": True, "output_sha256": H, "output_size": 5})["ok"] is False


@pytest.mark.parametrize("code", B.BUILD_ERROR_CODES)
def test_known_failure_codes_are_kept(code):
    r = B.parse_build_result({"status": "failed", "error_code": code, "error_text": "teks"})
    assert r["ok"] is False and r["error_code"] == code and r["error_text"] == "teks"


def test_status_is_mapped_to_a_code_first_a11():
    """A-11: hasil bawaan abort_orphans (aborted + runner_restart), jalur pengecualian main (failed + tool_error), dan JSON rusak dipetakan benar."""
    orphan = B.parse_build_result({"status": "aborted", "error_code": "runner_restart", "message": "Runner dimulai ulang saat job berjalan."})
    assert (orphan["status"], orphan["error_code"]) == ("aborted", "aborted") and "dimulai ulang" in orphan["error_text"]
    boom = B.parse_build_result({"status": "failed", "error_code": "tool_error", "message": "galat internal runner: ValueError"})
    assert (boom["status"], boom["error_code"]) == ("failed", "internal")
    assert B.parse_build_result({"status": "timeout", "error_code": "timeout"})["error_code"] == "timeout"
    assert B.parse_build_result({"status": "cancelled"})["error_code"] == "cancelled"
    assert B.parse_build_result({"status": "failed", "error_code": "kode-ngawur"})["error_code"] == "internal"
    assert B.parse_build_result({"status": "failed"})["error_code"] == "internal"
    assert B.parse_build_result("{rusak")["error_code"] == "bad_result"


def test_error_text_is_scrubbed_bounded_and_falls_back_to_the_fixed_sentence():
    r = B.parse_build_result({"status": "failed", "error_code": "build_failed", "error_text": "gagal di /data/builds/3/7/src/res/x.xml\x07 " + "z" * 900})
    assert "/data" not in r["error_text"] and "\x07" not in r["error_text"] and len(r["error_text"]) <= B.ERROR_TEXT_MAX
    assert B.parse_build_result({"status": "failed", "error_code": "build_failed"})["error_text"] == B.ERROR_TEXT["build_failed"]
    log = B.parse_build_result({**OK, "apktool_log_tail": "x" * 9000})["apktool_log_tail"]
    assert len(log) == B.LOG_TAIL_MAX


def test_numbers_are_forced_to_safe_types():
    r = B.parse_build_result({**OK, "elapsed": float("inf"), "peak_mem_mib": -5, "files": "9", "bytes": True})
    assert r["elapsed"] == 0.0 and r["peak_mem_mib"] is None and r["files"] == 0 and r["bytes"] == 0
    assert B.parse_build_result({**OK, "elapsed": float("nan")})["elapsed"] == 0.0 and B.parse_build_result({**OK, "elapsed": 1e9})["elapsed"] == 0.0


def test_unknown_fields_are_dropped():
    r = B.parse_build_result({**OK, "path": "/etc/passwd", "extra": 1})
    assert "path" not in r and "extra" not in r


# ======================================================================================== dump_result (ukuran dijamin kecil)
def test_dump_result_with_every_field_at_maximum_stays_under_8_kib():
    fat = {"status": "failed", "error_code": "build_failed", "error_text": "e" * 5000, "output_size": 2 ** 40, "output_sha256": H, "elapsed": 1234567.89,
           "apktool_log_tail": "é" * 20000, "files": 600000, "bytes": 3 * 1024 ** 3, "peak_mem_mib": 3072, "message": "m" * 5000, "job_id": "a999999999-build-abcdef12",
           "finished": 1234567890.123456}
    out = B.dump_result(fat)
    assert len(json.dumps(out, ensure_ascii=False).encode()) <= B.RESULT_MAX_BYTES and "message" not in out
    assert len(out["error_text"]) <= B.ERROR_TEXT_MAX and len(out["apktool_log_tail"]) <= B.LOG_TAIL_MAX


def test_dump_result_drops_the_log_tail_before_truncating_the_error_text(monkeypatch):
    monkeypatch.setattr(B, "RESULT_MAX_BYTES", 400)
    out = B.dump_result({"status": "failed", "error_code": "build_failed", "error_text": "e" * 300, "apktool_log_tail": "x" * 2000})
    assert out["apktool_log_tail"] == "" and out["error_text"].startswith("e")
    monkeypatch.setattr(B, "RESULT_MAX_BYTES", 100)
    out = B.dump_result({"status": "failed", "error_code": "build_failed", "error_text": "e" * 300, "apktool_log_tail": "x" * 2000})
    assert len(json.dumps(out)) <= 200 and len(out["error_text"]) < 300


def test_a_dumped_result_roundtrips_through_the_worker_reader_limits(tmp_path):
    from rvcore.signkeys import read_small
    out = B.dump_result({"status": "ok", "output_size": 5, "output_sha256": H, "elapsed": 1.0, "apktool_log_tail": "x" * 5000})
    path = tmp_path / "r.json"
    path.write_text(json.dumps(out))
    raw = read_small(path, 64 * 1024)
    assert raw is not None and B.parse_build_result(json.loads(raw))["ok"] is True
