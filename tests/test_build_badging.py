"""Tahap 5, FR-9.24 sisa dan FR-9.41: badging APK hasil (package, versionCode, versionName, minSdk, targetSdk).

Lapisan: (1) normalisasi/format/parse baris stage_log di `rvcore.buildproto`; (2) hasil runner TIDAK tepercaya -> `parse_build_result` menormalkan ketat; (3) worker
`run_build` mencatat baris badging, membandingkan dengan analisis asal (tidak memblokir), memperingatkan target SDK < 23, dan MENGGAGALKAN build bila badging tidak terbaca
(sebelum signer dipanggil). Runner/signer palsu (tests/build_rig.py); aapt2 nyata TIDAK dipakai di sini.
"""

from __future__ import annotations

import build_rig as br
import pytest
from build_rig import BADGING, Rig, bm
from rvcore import buildproto, store


@pytest.fixture
def rig(tmp_path):
    r = Rig(tmp_path)
    yield r
    r.stop()


@pytest.fixture
def B(monkeypatch):
    mod = bm()
    monkeypatch.setattr(mod, "POLL_INTERVAL", 0.02)
    return mod


def good(**over):
    return {**BADGING, **over}


# ====================================================================================== buildproto
def test_normalize_badging_keeps_valid_fields_and_sanitises_version_name():
    got = buildproto.normalize_badging({"package": "com.contoh.app", "version_code": 7, "version_name": "1.2 beta<script>", "min_sdk": 21, "target_sdk": 34})
    assert got == {"package": "com.contoh.app", "version_code": 7, "version_name": "1.2_beta_script_", "min_sdk": 21, "target_sdk": 34}


@pytest.mark.parametrize("raw", [None, [], "x", {}, {"package": ""}, {"package": "1abc"}, {"package": "a b"}, {"package": "a" * 300}, {"package": ["a"]},
                                 {"package": "com.x;rm -rf"}, {"package": "com.x\nbadging: paket=palsu"}])
def test_normalize_badging_rejects_unusable_packages(raw):
    assert buildproto.normalize_badging(raw) is None


def test_normalize_badging_drops_bad_numbers_instead_of_failing():
    got = buildproto.normalize_badging({"package": "a.b", "version_code": "7", "version_name": 5, "min_sdk": -1, "target_sdk": True})
    assert got["version_code"] is None and got["version_name"] == "" and got["min_sdk"] is None and got["target_sdk"] is None


def test_version_name_is_truncated_to_64():
    got = buildproto.normalize_badging({"package": "a.b", "version_name": "v" * 500})
    assert len(got["version_name"]) == buildproto.VERSION_NAME_MAX


def test_stage_lines_have_the_fixed_text_format():
    lines = buildproto.badging_stage_lines(good(), {"package": "com.contoh.app", "version_code": "7", "version_name": "1.2.3"})
    assert lines == ["badging: paket=com.contoh.app versionCode=7 versionName=1.2.3 minSdk=21 targetSdk=34",
                     "banding: paket=sama versionCode=sama versionName=sama"]


def test_target_sdk_below_23_warns_and_does_not_raise():
    lines = buildproto.badging_stage_lines(good(target_sdk=22))
    assert "peringatan: target_sdk_di_bawah_23" in lines
    assert buildproto.badging_warnings(good(target_sdk=23)) == []
    assert buildproto.badging_warnings(good(target_sdk=None, min_sdk=19)) == ["target_sdk_di_bawah_23"], "target tak tertulis = minSdk"
    assert buildproto.badging_warnings(good(target_sdk=None, min_sdk=None)) == ["target_sdk_tidak_diketahui"]


def test_comparison_with_the_origin_analysis_warns_but_never_blocks():
    lines = buildproto.badging_stage_lines(good(), {"package": "com.lain", "version_code": "99", "version_name": "9"})
    assert "banding: paket=beda versionCode=beda versionName=beda" in lines
    assert "peringatan: paket_beda_dari_analisis" in lines and "peringatan: version_code_beda_dari_analisis" in lines
    unknown = buildproto.badging_stage_lines(good(), {"package": None, "version_code": "", "version_name": None})
    assert "banding: paket=tidak_diketahui versionCode=tidak_diketahui versionName=tidak_diketahui" in unknown


def test_stage_log_round_trip_for_the_ui():
    log = "build: 1.0 dtk\n" + "\n".join(buildproto.badging_stage_lines(good(target_sdk=21), {"package": "com.contoh.app", "version_code": "8", "version_name": "1.2.3"})) + "\nsigning_mulai=1.0"
    parsed = buildproto.parse_badging_stage_log(log)
    assert parsed["badging"] == {"package": "com.contoh.app", "version_code": "7", "version_name": "1.2.3", "min_sdk": "21", "target_sdk": "21"}
    assert parsed["banding"] == {"paket": "sama", "versionCode": "beda", "versionName": "sama"}
    assert parsed["peringatan"] == ["target_sdk_di_bawah_23", "version_code_beda_dari_analisis"]
    assert buildproto.parse_badging_stage_log(None) == {"badging": None, "banding": None, "peringatan": []}


def test_parse_build_result_normalises_runner_badging_and_never_trusts_it():
    base = {"status": "ok", "output_size": 5, "output_sha256": "ab" * 32}
    ok = buildproto.parse_build_result({**base, "badging": {"package": "a.b", "version_code": 3, "version_name": "x y", "min_sdk": 1, "target_sdk": 2, "extra": "buang"}})
    assert ok["ok"] and ok["badging"] == {"package": "a.b", "version_code": 3, "version_name": "x_y", "min_sdk": 1, "target_sdk": 2}
    assert buildproto.parse_build_result(base)["badging"] is None
    assert buildproto.parse_build_result({**base, "badging": {"package": "bukan paket!"}})["badging"] is None
    failed = buildproto.parse_build_result({"status": "failed", "error_code": "build_failed", "badging": good()})
    assert failed["ok"] is False and failed["badging"] is None


# ====================================================================================== worker
def test_worker_records_badging_lines_before_signing_and_keeps_them_in_the_final_log(rig, B):
    aid = rig.analysis(package="com.contoh.app")
    rig.start()
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert row["status"] == "done"
    log = row["stage_log"]
    assert "badging: paket=com.contoh.app versionCode=7 versionName=1.2.3 minSdk=21 targetSdk=34" in log
    assert "banding: paket=sama versionCode=tidak_diketahui versionName=tidak_diketahui" in log, "analisis uji tanpa versi"
    assert "peringatan: target_sdk_di_bawah_23" not in log
    assert log.index("badging:") < log.index("signing_mulai=")


def test_worker_warns_on_low_target_sdk_without_blocking(rig, B):
    aid = rig.analysis()
    rig.start(runner=lambda r, jid, job: {**br.FakeRunner.default(r, jid, job), "badging": good(target_sdk=19, min_sdk=19)})
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert row["status"] == "done" and "peringatan: target_sdk_di_bawah_23" in row["stage_log"]


def test_worker_notes_a_package_that_differs_from_the_analysis_but_still_finishes(rig, B):
    aid = rig.analysis(package="com.asal.app")
    rig.start()
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert row["status"] == "done"
    assert "banding: paket=beda" in row["stage_log"] and "peringatan: paket_beda_dari_analisis" in row["stage_log"]


@pytest.mark.parametrize("badging", [None, {"package": "bukan paket!"}, "teks"])
def test_worker_fails_the_build_when_badging_is_unreadable_and_never_calls_the_signer(rig, B, badging):
    aid = rig.analysis()
    rig.start(runner=lambda r, jid, job: {**br.FakeRunner.default(r, jid, job), "badging": badging})
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"]) == ("failed", "badging_unreadable")
    assert "FR-9.24" in row["error_text"] and rig.signer.jobs == []
    assert "unsigned.apk" not in rig.listing(aid, bid)


def test_the_error_code_is_accepted_by_the_store_and_has_a_fixed_text():
    assert bm().SIGN_TEXT["badging_unreadable"]
    assert store._ERROR_CODE_RE.fullmatch("badging_unreadable")
