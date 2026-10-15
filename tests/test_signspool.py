"""Protokol signspool (`rvcore/signspool.py`): id, request, hasil, klaim aman, detak jantung, dan `submit_and_wait`.

Semua masukan di volume `signspool` TIDAK TEPERCAYA di kedua sisi (signer memproses APK tak tepercaya; worker tak boleh percaya signer). Tes yang bisa
menggantung (FIFO, symlink ke /dev/zero, berkas raksasa) berjalan di utas dengan `join(5)` dan harus selesai < 1 dtk.
"""

from __future__ import annotations

import json
import os
import threading
import time

import pytest

from rvcore import signkeys, signspool as S
from rvcore.fsutil import atomic_write_json
from rvcore.paths import Layout
from rvcore.signspool import SignSpool, SignerUnavailable

EXP = "e" * 64                      # expect_sha256 / input_sha256 tiruan (hash unsigned.apk menurut runner)
GOOD = {"ok": True, "error_code": None, "error_text": "", "output_name": "signed.apk", "output_size": 1234,
        "output_sha256": "b" * 64, "input_sha256": EXP, "cert_sha256": "c" * 64, "verify": {"v1": False, "v2": True, "v3": True}, "signer_count": 1, "elapsed": 1.5}
KS_OK = {"state": "ok", "detail": "", "cert_sha256": "c" * 64}


@pytest.fixture
def sp(tmp_path):
    s = SignSpool(tmp_path / "signspool")
    s.ensure_dirs()
    return s


def bounded(fn, *args, limit=1.0, **kwargs):
    """Jalankan di utas; gagal bila menggantung > 5 dtk atau memakan > `limit` dtk."""
    box: dict = {}

    def target():
        t0 = time.monotonic()
        try:
            box["r"] = fn(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001
            box["exc"] = exc
        box["dt"] = time.monotonic() - t0

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "menggantung"
    assert "exc" not in box, repr(box.get("exc"))
    assert box["dt"] < limit, f"terlalu lambat: {box['dt']:.2f} dtk"
    return box["r"]


def jid(aid=1, bid=1, tail="abcdef12"):
    return f"g{aid}-{bid}-{tail}"


def req(job_id=None, **extra):
    job_id = job_id or jid()
    return {"job_id": job_id, "op": "sign", "analysis_id": 1, "build_id": 1, "timeout": 60, "expect_sha256": EXP, "created": 1.0, **extra}


# ------------------------------------------------------------------------------------------------------------ id
@pytest.mark.parametrize("good", ["g1-1-abcdef12", "g2147483647-2147483647-00000000", "g0-0-abcdef12", "g1234567890-1-0123abcd"])
def test_job_id_accepts(good):
    assert S.JOB_ID_RE.match(good)


@pytest.mark.parametrize("bad", ["", "g1-1-abcdef12\n", "g１-1-abcdef12", "g1-１-abcdef12", "g1-1-ABCDEF12", "g11111111111-1-abcdef12", "g1-11111111111-abcdef12",
                                 "g1-abcdef12", "g-1-abcdef12", "g1-1-abcdef1", "g1-1-abcdef123", "../g1-1-abcdef12", "g1-1-abcdef12/x", "a1-apktool-abcdef12",
                                 "s1-abcdef123456", " g1-1-abcdef12", "g1-1-abcdef12 ", "g1--1-abcdef12", "g1-1-abcdefg2"])
def test_job_id_rejects(bad):
    assert not S.JOB_ID_RE.match(bad), repr(bad)


def test_new_job_id_matches_and_is_unique():
    ids = {S.new_job_id(3, 4) for _ in range(50)}
    assert len(ids) == 50 and all(S.JOB_ID_RE.match(i) and i.startswith("g3-4-") for i in ids)


@pytest.mark.parametrize("bad", ["1", "../x", 1.0, True, False, None, 0, -1, 2**31, 10**12, b"1", [1]])
def test_sender_side_validation_rejects(bad):
    with pytest.raises(ValueError):
        S.new_job_id(bad, 1)
    with pytest.raises(ValueError):
        S.new_job_id(1, bad)
    with pytest.raises(ValueError):
        S.build_sign_request(bad, 1, 60, EXP)
    with pytest.raises(ValueError):
        S.build_sign_request(1, bad, 60, EXP)
    with pytest.raises(ValueError):
        S.build_sign_request(1, 1, bad, EXP)


def test_build_sign_request_shape():
    r = S.build_sign_request(5, 6, 120, EXP)
    assert set(r) == {"job_id", "op", "analysis_id", "build_id", "timeout", "expect_sha256", "created"} and r["expect_sha256"] == EXP
    assert r["op"] == "sign" and (r["analysis_id"], r["build_id"], r["timeout"]) == (5, 6, 120) and isinstance(r["created"], float)
    assert S.JOB_ID_RE.match(r["job_id"]) and r["job_id"].startswith("g5-6-")
    assert S.build_sign_request(2**31 - 1, 2**31 - 1, 2**31 - 1, EXP)["analysis_id"] == 2**31 - 1


# --------------------------------------------------------------------------------------------------- validate_request
def test_validate_request_returns_ids_and_clamped_timeout():
    assert S.validate_request(req(timeout=60), jid()) == (1, 1, 60, EXP)
    assert S.validate_request(req(timeout=1), jid())[2] == 10
    assert S.validate_request(req(timeout=10**9), jid())[2] == 3600
    assert S.validate_request(req(jid(12, 34), analysis_id=12, build_id=34), jid(12, 34)) == (12, 34, 60, EXP)


@pytest.mark.parametrize("mut", [
    {"op": "verify"}, {"op": None}, {"op": "SIGN"}, {"analysis_id": "1"}, {"analysis_id": 1.0}, {"analysis_id": True}, {"analysis_id": 0}, {"analysis_id": -1},
    {"analysis_id": 2**31}, {"analysis_id": 2}, {"build_id": "1"}, {"build_id": True}, {"build_id": 0}, {"build_id": 2**31}, {"build_id": 3},
    {"timeout": "60"}, {"timeout": 60.0}, {"timeout": True}, {"timeout": None}, {"job_id": jid(tail="00000000")}, {"analysis_id": "../etc"},
    # A-02: expect_sha256 wajib heks-64 huruf kecil
    {"expect_sha256": ""}, {"expect_sha256": "E" * 64}, {"expect_sha256": "e" * 63}, {"expect_sha256": "e" * 65}, {"expect_sha256": "g" * 64}, {"expect_sha256": None},
    {"expect_sha256": 5}, {"expect_sha256": "e" * 64 + "\n"},
])
def test_validate_request_rejects(mut):
    with pytest.raises(ValueError):
        S.validate_request({**req(), **mut}, jid())


def test_validate_request_rejects_non_dict_and_bad_job_id():
    for bad in (None, [], "x", 5):
        with pytest.raises(ValueError):
            S.validate_request(bad, jid())
    with pytest.raises(ValueError):
        S.validate_request(req("../x"), "../x")
    with pytest.raises(ValueError):
        S.validate_request({k: v for k, v in req().items() if k != "timeout"}, jid())
    with pytest.raises(ValueError):
        S.validate_request({k: v for k, v in req().items() if k != "expect_sha256"}, jid())


def test_path_input_and_out_fields_are_never_used():
    plain = S.validate_request(req(), jid())
    evil = S.validate_request(req(path="/etc/passwd", input="/etc/shadow", out="/tmp/x", dir="../..", unsigned="/x"), jid())
    assert plain == evil


# ------------------------------------------------------------------------------------------------------- parse_result
def test_parse_result_accepts_a_coherent_success_and_forces_output_name():
    r = S.parse_result({**GOOD, "output_name": "../../etc/passwd", "extra": "dibuang"})
    assert r["ok"] is True and r["output_name"] == "signed.apk" and r["error_code"] is None and "extra" not in r
    assert (r["output_size"], r["output_sha256"], r["cert_sha256"], r["signer_count"]) == (1234, "b" * 64, "c" * 64, 1)
    assert r["verify"] == {"v1": False, "v2": True, "v3": True} and r["elapsed"] == 1.5


@pytest.mark.parametrize("raw", [{**GOOD, "ok": "true"}, {**GOOD, "ok": 1}, {**GOOD, "ok": "True"}, {**GOOD, "ok": None}, {k: v for k, v in GOOD.items() if k != "ok"},
                                 {"status": "ok", "message": "x"}])
def test_only_literal_true_is_success(raw):
    r = S.parse_result(raw)
    assert r["ok"] is False


@pytest.mark.parametrize("mut", [
    {"output_sha256": "B" * 64}, {"output_sha256": "b" * 63}, {"output_sha256": None}, {"cert_sha256": "z" * 64}, {"cert_sha256": None},
    {"input_sha256": None}, {"input_sha256": "E" * 64}, {"input_sha256": "e" * 63}, {"input_sha256": 5},
    {"output_size": 0}, {"output_size": -5}, {"output_size": True}, {"output_size": "1234"}, {"signer_count": 2}, {"signer_count": 0}, {"signer_count": None},
    {"signer_count": True}, {"verify": {"v2": True}}, {"verify": {"v2": True, "v3": 1}}, {"verify": {"v2": False, "v3": True}}, {"verify": []}, {"verify": None},
])
def test_incoherent_success_is_rejected_as_bad_result(mut):
    r = S.parse_result({**GOOD, **mut})
    assert r["ok"] is False and r["error_code"] == "bad_result" and r["error_text"] == "hasil signer rusak"


@pytest.mark.parametrize("raw", [None, [], "x", 5, 1.5, True, {}, [GOOD], {"ok": {"a": 1}}, {"verify": "x", "elapsed": float("nan")},
                                 {"error_code": ["x"], "error_text": {"a": 1}}, {"elapsed": float("inf")}, {"output_size": 10**40}, {"verify": {"v1": "x"}}])
def test_parse_result_never_raises_and_is_not_ok(raw):
    r = S.parse_result(raw)
    assert r["ok"] is False and r["error_code"] in S.ERROR_CODES | {"bad_result"} and isinstance(r["error_text"], str) and r["error_text"]
    assert r["elapsed"] == 0.0 or r["elapsed"] >= 0


def test_error_codes_outside_the_list_become_bad_result():
    assert S.parse_result({"ok": False, "error_code": "rm -rf /", "error_text": "x"})["error_code"] == "bad_result"
    assert S.parse_result({"ok": False, "error_code": 5})["error_code"] == "bad_result"
    assert S.parse_result({"ok": False})["error_code"] == "bad_result"
    for code in S.ERROR_CODES:
        r = S.parse_result({"ok": False, "error_code": code, "error_text": "teks khusus"})
        assert r["error_code"] == code and r["error_text"] == "teks khusus" and r["ok"] is False
        assert S.parse_result({"ok": False, "error_code": code})["error_text"] == S.ERROR_TEXT[code]


def test_error_text_is_stripped_of_control_chars_and_truncated():
    r = S.parse_result({"ok": False, "error_code": "sign_failed", "error_text": "a\x00b\x1b[31mc\nd\re" + "x" * 1000})
    assert len(r["error_text"]) <= 300
    assert all(ch.isprintable() for ch in r["error_text"]) and "\x00" not in r["error_text"] and "\n" not in r["error_text"]
    assert r["error_text"].startswith("ab[31mcde")


def test_spool_made_failure_is_mapped_to_bad_request():
    """`Spool.finish` menulis {status,error_code,message} tanpa kunci ok untuk request rusak."""
    r = S.parse_result({"status": "failed", "error_code": "bad_request", "message": "request tidak valid", "job_id": jid(), "finished": 1.0})
    assert r["ok"] is False and r["error_code"] == "bad_request" and r["error_text"] == "request tidak valid"


def test_error_text_covers_every_code():
    assert set(S.ERROR_TEXT) == set(S.ERROR_CODES) | {"bad_result"}
    assert len(S.ERROR_CODES) == 18
    for code, text in S.ERROR_TEXT.items():
        assert text and len(text) <= 300 and text == text.strip(), code
        assert all(ch.isprintable() for ch in text), code
    assert S.ERROR_TEXT["bad_result"] == "hasil signer rusak"


def test_constants():
    assert (S.MAX_REQUEST_BYTES, S.MAX_RESULT_BYTES, S.MAX_HEARTBEAT_BYTES, S.HEARTBEAT_STALE_AFTER) == (4096, 64 * 1024, 16 * 1024, 20.0)
    assert S.OPEN_FLAGS is signkeys.OPEN_FLAGS and S.read_small is signkeys.read_small
    assert issubclass(SignerUnavailable, Exception) and SignerUnavailable("x").message == "x"


def test_layout_has_a_separate_signspool_root(tmp_path):
    assert Layout(tmp_path).signspool == tmp_path / "signspool"


# -------------------------------------------------------------------------------------------------- SignSpool basics
def test_spool_is_isolated_from_the_runner_protocol(sp, tmp_path):
    assert sp.heartbeat_file == tmp_path / "signspool" / "signer.hb" and sp.max_request == 4096 and sp.id_re is S.JOB_ID_RE
    with pytest.raises(ValueError):
        sp.submit({"job_id": "a1-apktool-deadbeef"})
    assert S.make_spool(tmp_path / "x").root == tmp_path / "x"


def test_submit_claim_finish_roundtrip(sp):
    r = req()
    sp.submit(r)
    assert sp.is_waiting(r["job_id"]) and sp.claim_next() == (r["job_id"], r)
    assert sp.running_job_ids() == [r["job_id"]] and sp.claim_next() is None
    sp.finish(r["job_id"], dict(GOOD))
    assert sp.running_job_ids() == [] and S.parse_result(json.loads((sp.results / f"{r['job_id']}.json").read_bytes()))["ok"] is True
    assert S.read_result(sp, r["job_id"])["ok"] is True


def test_claims_oldest_first_by_lstat_mtime(sp):
    a, b, c = jid(1, 1, "00000001"), jid(1, 1, "00000002"), jid(1, 1, "00000003")
    for i, j in enumerate((b, c, a)):
        sp.submit(req(j))
    now = time.time()
    for j, age in ((a, 30), (b, 20), (c, 10)):
        os.utime(sp.requests / f"{j}.json", (now - age, now - age))
    assert [sp.claim_next()[0] for _ in range(3)] == [a, b, c]


def test_names_that_do_not_match_are_discarded(sp):
    for name in ("junk.json", "g1-1-abcdef12.txt", "g1-1-ABCDEF12.json", "g1-1-abcdef12.json.bak", "x"):
        (sp.requests / name).write_text("{}")
    assert sp.claim_next() is None
    assert list(sp.requests.iterdir()) == []


def test_mismatched_content_and_garbage_are_answered_bad_request(sp):
    cases = {
        jid(tail="00000001"): b"not json",
        jid(tail="00000002"): b"[1,2,3]",
        jid(tail="00000003"): json.dumps(req(jid(tail="ffffffff"))).encode(),
        jid(tail="00000004"): b"\xff\xfe\x00bad",
        jid(tail="00000005"): b"[" * 4000,
        jid(tail="00000006"): b"",
        jid(tail="00000007"): json.dumps(req(jid(tail="00000007"), pad="x" * 5000)).encode(),
    }
    for j, data in cases.items():
        (sp.requests / f"{j}.json").write_bytes(data)
    assert bounded(sp.claim_next) is None
    for j in cases:
        r = S.read_result(sp, j)
        assert (r["ok"], r["error_code"], r["error_text"]) == (False, "bad_request", "request tidak valid"), j
    assert sp.running_job_ids() == []


def test_a_good_request_after_bad_ones_is_still_claimed(sp):
    (sp.requests / f"{jid(tail='00000001')}.json").write_bytes(b"junk")
    good = req(jid(tail="00000002"))
    sp.submit(good)
    now = time.time()
    os.utime(sp.requests / f"{jid(tail='00000001')}.json", (now - 10, now - 10))
    assert bounded(sp.claim_next) == (good["job_id"], good)


# ------------------------------------------------------------------------------- claim_next: berkas khusus (tak menggantung)
def plant_fifo(path):
    os.mkfifo(path)


def plant_zero_link(path):
    path.symlink_to("/dev/zero")


def plant_big_link(path):
    big = path.parent.parent / "big.bin"
    with open(big, "wb") as fh:
        fh.truncate(512 * 1024 * 1024)            # sparse; read_text akan memakan 512 MiB
    path.symlink_to(big)


def plant_valid_link(path):
    real = path.parent.parent / "real.json"
    real.write_text(json.dumps(req(path.stem)))
    path.symlink_to(real)


def plant_dir(path):
    path.mkdir()
    (path / "isi").write_text("x")


@pytest.mark.parametrize("plant", [plant_fifo, plant_zero_link, plant_big_link, plant_valid_link, plant_dir])
def test_claim_next_answers_bad_request_fast_for_special_files(sp, plant):
    j = jid(tail="0000dead")
    plant(sp.requests / f"{j}.json")
    assert bounded(sp.claim_next) is None
    r = S.read_result(sp, j)
    assert (r["ok"], r["error_code"]) == (False, "bad_request")
    assert not os.path.lexists(sp.running / f"{j}.json") and sp.running_job_ids() == []


def swap_after_rename(monkeypatch, make):
    real_rename = os.rename

    def swapping(src, dst, *a, **kw):
        real_rename(src, dst, *a, **kw)
        if str(dst).endswith(".json") and os.path.dirname(str(dst)).endswith("running"):
            os.unlink(dst)
            make(dst)

    monkeypatch.setattr(os, "rename", swapping)


@pytest.mark.parametrize("make", [os.mkfifo, lambda p: os.symlink("/dev/zero", p), lambda p: os.mkdir(p)])
def test_claim_next_survives_a_swap_after_the_rename(sp, monkeypatch, make):
    j = jid(tail="0000beef")
    sp.submit(req(j))
    swap_after_rename(monkeypatch, make)
    assert bounded(sp.claim_next) is None
    monkeypatch.undo()
    r = S.read_result(sp, j)
    assert (r["ok"], r["error_code"]) == (False, "bad_request")
    assert sp.running_job_ids() == []


def test_claim_next_does_not_follow_symlinks_when_sorting(sp, monkeypatch):
    """Urutan memakai lstat: tidak ada pemanggilan stat yang mengikuti symlink (mis. ke FIFO di luar spool)."""
    (sp.requests / f"{jid(tail='0000feed')}.json").symlink_to("/nonexistent/target")
    assert bounded(sp.claim_next) is None
    assert S.read_result(sp, jid(tail="0000feed"))["error_code"] == "bad_request"


def test_two_spools_claim_a_request_exactly_once(tmp_path):
    root = tmp_path / "signspool"
    SignSpool(root).ensure_dirs()
    for rnd in range(15):
        j = jid(tail=f"{rnd:08x}")
        SignSpool(root).submit(req(j))
        barrier = threading.Barrier(2)
        wins: list = []

        def racer():
            s = SignSpool(root)
            barrier.wait()
            got = s.claim_next()
            if got:
                wins.append(got[0])

        ts = [threading.Thread(target=racer) for _ in range(2)]
        [t.start() for t in ts]
        [t.join(5) for t in ts]
        assert wins == [j], rnd
        SignSpool(root).finish(j, dict(GOOD))


def test_orphans_are_visible_after_a_restart(sp, tmp_path):
    r = req()
    sp.submit(r)
    assert sp.claim_next()[0] == r["job_id"]
    assert SignSpool(tmp_path / "signspool").running_job_ids() == [r["job_id"]]       # daemon baru menjawab 'aborted'
    sp.finish(r["job_id"], {"ok": False, "error_code": "aborted", "error_text": "x"})
    assert SignSpool(tmp_path / "signspool").running_job_ids() == []
    assert S.read_result(sp, r["job_id"])["error_code"] == "aborted"


def test_cancel_roundtrip_and_invalid_ids_are_ignored(sp):
    j = jid()
    assert not sp.cancel_requested(j)
    sp.request_cancel(j)
    assert sp.cancel_requested(j)
    sp.request_cancel("../x")
    assert [p.name for p in sp.cancel.iterdir()] == [j]
    sp.finish(j, {"ok": False, "error_code": "cancelled", "error_text": "x"})
    assert not sp.cancel_requested(j)


# -------------------------------------------------------------------------------------------------- signer.hb / status
def test_heartbeat_schema_and_normalized_status(sp):
    sp.write_signer_heartbeat("busy", jid(), {"state": "ok", "detail": "d" * 500, "cert_sha256": "c" * 64})
    raw = json.loads(sp.heartbeat_file.read_bytes())
    assert set(raw) == {"ts", "pid", "state", "job", "keystore"} and set(raw["keystore"]) == {"state", "detail", "cert_sha256"}
    assert raw["pid"] == os.getpid() and raw["job"] == jid() and len(raw["keystore"]["detail"]) == 300
    st = S.signer_status(sp)
    assert st["hidup"] is True and 0 <= st["umur"] < 5 and st["state"] == "busy" and st["job"] == jid() and st["pid"] == os.getpid()
    assert st["keystore"] == {"state": "ok", "detail": "d" * 300, "cert_sha256": "c" * 64}


def test_status_without_heartbeat_is_dead(sp):
    st = S.signer_status(sp)
    assert st["hidup"] is False and st["umur"] is None and st["keystore"]["state"] is None


def test_status_age_comes_from_ts_not_mtime(sp):
    sp.write_signer_heartbeat("idle", None, KS_OK)
    old = time.time() - 3600
    os.utime(sp.heartbeat_file, (old, old))
    assert S.signer_status(sp)["hidup"] is True                   # mtime lama tidak berpengaruh
    atomic_write_json(sp.heartbeat_file, sp.tmp, {"ts": time.time() - 25, "pid": 1, "state": "idle", "job": None, "keystore": KS_OK})
    st = S.signer_status(sp)
    assert st["hidup"] is False and 24 < st["umur"] < 40


@pytest.mark.parametrize("hb", [
    [], "x", 5, {"ts": "now"}, {"ts": True}, {"ts": None}, {"ts": float("nan")}, {"ts": float("inf")}, {},
])
def test_status_with_garbage_heartbeat_is_dead(sp, hb):
    sp.heartbeat_file.write_text(json.dumps(hb))
    assert S.signer_status(sp)["hidup"] is False


def test_status_normalizes_hostile_fields(sp):
    atomic_write_json(sp.heartbeat_file, sp.tmp, {"ts": time.time(), "pid": "x", "state": "<script>", "job": "../x",
                                                   "keystore": {"state": "wat", "detail": "a\x00b\nc", "cert_sha256": "NOPE"}})
    st = S.signer_status(sp)
    assert st["hidup"] is True and st["state"] is None and st["job"] is None and st["pid"] is None
    assert st["keystore"] == {"state": None, "detail": "abc", "cert_sha256": None}
    atomic_write_json(sp.heartbeat_file, sp.tmp, {"ts": time.time(), "keystore": "x"})
    assert S.signer_status(sp)["keystore"]["state"] is None


def test_status_survives_hostile_heartbeat_files(sp):
    hb = sp.heartbeat_file

    def fifo():
        os.mkfifo(hb)

    def zero():
        hb.symlink_to("/dev/zero")

    def big():
        hb.write_bytes(b"{" + b" " * (10 * 1024 * 1024) + b"}")

    def over_limit():
        hb.write_text(json.dumps({"ts": time.time(), "keystore": {"state": "ok", "detail": "x" * 20000}}))

    def directory():
        hb.mkdir()

    for make in (fifo, zero, big, over_limit, directory):
        if hb.is_symlink() or hb.is_file():
            hb.unlink()
        elif hb.is_dir():
            hb.rmdir()
        elif os.path.lexists(hb):
            hb.unlink()
        make()
        st = bounded(S.signer_status, sp)
        assert st["hidup"] is False, make.__name__


# --------------------------------------------------------------------------------------------------------- read_result
def test_read_result_missing_is_none(sp):
    assert S.read_result(sp, jid()) is None


def test_read_result_corrupt_is_bad_result(sp):
    j = jid()
    (sp.results / f"{j}.json").write_bytes(b"{not json")
    r = S.read_result(sp, j)
    assert (r["ok"], r["error_code"], r["error_text"]) == (False, "bad_result", "hasil signer rusak")
    (sp.results / f"{j}.json").write_bytes(b" " * (S.MAX_RESULT_BYTES + 1))
    assert S.read_result(sp, j)["error_code"] == "bad_result"
    (sp.results / f"{j}.json").write_bytes(json.dumps({**GOOD, "ok": "true"}).encode())
    assert S.read_result(sp, j)["ok"] is False


@pytest.mark.parametrize("plant", [plant_fifo, plant_zero_link, plant_big_link, plant_dir])
def test_read_result_for_special_files_is_bad_result_fast(sp, plant):
    j = jid()
    plant(sp.results / f"{j}.json")
    r = bounded(S.read_result, sp, j)
    assert (r["ok"], r["error_code"]) == (False, "bad_result")


@pytest.mark.parametrize("make", [os.mkfifo, lambda p: os.symlink("/dev/zero", p)])
def test_result_swapped_between_check_and_open_is_bad_result(sp, monkeypatch, make):
    j = jid()
    (sp.results / f"{j}.json").write_text(json.dumps(GOOD))
    real_open = os.open

    def swapping(path, flags, *a, **kw):
        if str(path).endswith(f"{j}.json"):
            os.unlink(path)
            make(path)
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", swapping)
    r = bounded(S.read_result, sp, j)
    assert (r["ok"], r["error_code"]) == (False, "bad_result")


def test_result_deleted_between_check_and_open_is_not_yet_done(sp, monkeypatch):
    j = jid()
    (sp.results / f"{j}.json").write_text(json.dumps(GOOD))
    real_open = os.open

    def deleting(path, flags, *a, **kw):
        if str(path).endswith(f"{j}.json"):
            os.unlink(path)
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", deleting)
    assert S.read_result(sp, j) is None


# ---------------------------------------------------------------------------------------------------- submit_and_wait
class FakeDaemon:
    """Signer palsu di utas: menulis detak jantung dan menjawab job sesuai `mode`."""

    def __init__(self, root, mode="ok", ks=None):
        self.spool = SignSpool(root)
        self.mode = mode
        self.ks = ks or KS_OK
        self.beating = True
        self.claimed: list[str] = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def loop(self):
        while not self.stop.is_set():
            if self.beating:
                self.spool.write_signer_heartbeat("idle", None, self.ks)
            if self.mode != "ignore":
                got = self.spool.claim_next()
                if got:
                    self.handle(*got)
            time.sleep(0.01)

    def handle(self, job_id, job):
        self.claimed.append(job_id)
        if self.mode == "ok":
            self.spool.finish(job_id, dict(GOOD))
        elif self.mode == "hold_until_cancel":
            while not self.spool.cancel_requested(job_id) and not self.stop.is_set():
                time.sleep(0.01)
            self.spool.finish(job_id, {"ok": False, "error_code": "cancelled", "error_text": "dibatalkan"})
        elif self.mode == "hold_deaf":
            self.beating = False
            while not self.stop.is_set():
                time.sleep(0.01)

    def __enter__(self):
        self.spool.ensure_dirs()
        self.spool.write_signer_heartbeat("idle", None, self.ks)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(5)


def residue(sp):
    return {d.name: sorted(p.name for p in d.iterdir()) for d in (sp.requests, sp.running, sp.results, sp.cancel) if any(d.iterdir())}


def test_submit_and_wait_success(sp, tmp_path):
    with FakeDaemon(tmp_path / "signspool") as d:
        r = S.submit_and_wait(sp, 7, 8, expect_sha256=EXP, timeout=60, poll=0.01)
    assert r["ok"] is True and r["output_sha256"] == "b" * 64 and len(d.claimed) == 1 and d.claimed[0].startswith("g7-8-")
    assert residue(sp) == {}


def test_submit_and_wait_fails_fast_without_a_heartbeat(sp):
    t0 = time.monotonic()
    with pytest.raises(SignerUnavailable) as ei:
        S.submit_and_wait(sp, 1, 1, expect_sha256=EXP, timeout=60, poll=0.01)
    assert time.monotonic() - t0 < 1 and "tidak aktif" in ei.value.message and residue(sp) == {}


def test_submit_and_wait_fails_fast_on_a_stale_heartbeat(sp):
    atomic_write_json(sp.heartbeat_file, sp.tmp, {"ts": time.time() - 25, "pid": 1, "state": "idle", "job": None, "keystore": KS_OK})
    with pytest.raises(SignerUnavailable):
        S.submit_and_wait(sp, 1, 1, expect_sha256=EXP, timeout=60, poll=0.01)
    assert residue(sp) == {}


@pytest.mark.parametrize("state,detail", [("unreadable", "mode 600 milik uid 1000 ... make keystore-access"), ("missing", "tidak ada"), ("stale", "make restart"),
                                          ("invalid", "rusak")])
def test_submit_and_wait_fails_fast_when_the_keystore_is_not_ok(sp, tmp_path, state, detail):
    with FakeDaemon(tmp_path / "signspool", mode="ignore", ks={"state": state, "detail": detail, "cert_sha256": None}):
        with pytest.raises(SignerUnavailable) as ei:
            S.submit_and_wait(sp, 1, 1, expect_sha256=EXP, timeout=60, poll=0.01)
    assert state in ei.value.message and detail in ei.value.message and residue(sp) == {}


def test_submit_and_wait_rejects_invalid_ids_as_unavailable(sp, tmp_path):
    with FakeDaemon(tmp_path / "signspool", mode="ignore"):
        with pytest.raises(SignerUnavailable) as ei:
            S.submit_and_wait(sp, "../x", 1, expect_sha256=EXP, timeout=60, poll=0.01)
    assert "tidak valid" in ei.value.message


def test_request_not_picked_up_is_withdrawn(sp, tmp_path):
    with FakeDaemon(tmp_path / "signspool", mode="ignore"):
        with pytest.raises(SignerUnavailable) as ei:
            S.submit_and_wait(sp, 1, 1, expect_sha256=EXP, timeout=60, pickup_timeout=0.3, poll=0.01)
    assert "tidak mengambil" in ei.value.message and residue(sp) == {}


def test_cancel_before_pickup_withdraws_the_request(sp, tmp_path):
    ev = threading.Event()
    ev.set()
    with FakeDaemon(tmp_path / "signspool", mode="ignore"):
        r = S.submit_and_wait(sp, 1, 1, expect_sha256=EXP, timeout=60, cancel=ev, poll=0.01)
    assert (r["ok"], r["error_code"], r["error_text"]) == (False, "cancelled", "dibatalkan sebelum berjalan") and residue(sp) == {}


def test_cancel_while_running_returns_the_daemons_answer(sp, tmp_path):
    ev = threading.Event()
    threading.Timer(0.3, ev.set).start()
    with FakeDaemon(tmp_path / "signspool", mode="hold_until_cancel") as d:
        t0 = time.monotonic()
        r = S.submit_and_wait(sp, 1, 1, expect_sha256=EXP, timeout=60, cancel=ev, poll=0.01)
    assert r["error_code"] == "cancelled" and time.monotonic() - t0 < 4 and len(d.claimed) == 1 and residue(sp) == {}


def test_expired_job_asks_for_cancel_then_gives_up(sp, tmp_path, monkeypatch):
    monkeypatch.setattr(S, "MIN_TIMEOUT", 0)

    class Deaf(FakeDaemon):
        def handle(self, job_id, job):                 # tetap berdetak, tetapi tidak pernah menjawab maupun menghormati pembatalan
            self.claimed.append(job_id)
            while not self.stop.is_set():
                time.sleep(0.01)

    asked: list[str] = []
    real_cancel = sp.request_cancel
    monkeypatch.setattr(sp, "request_cancel", lambda job_id: (asked.append(job_id), real_cancel(job_id)))
    with Deaf(tmp_path / "signspool") as d:
        t0 = time.monotonic()
        with pytest.raises(SignerUnavailable) as ei:
            S.submit_and_wait(sp, 1, 1, expect_sha256=EXP, timeout=1, grace=0.2, poll=0.01)
    assert "tidak menjawab" in ei.value.message and time.monotonic() - t0 < 5 and len(d.claimed) == 1 and residue(sp) == {}
    assert asked == d.claimed                   # meminta batal, lalu menyerah; forget() membersihkan berkasnya


def test_daemon_that_stops_beating_mid_job_is_detected(sp, tmp_path, monkeypatch):
    monkeypatch.setattr(S, "HEARTBEAT_STALE_AFTER", 0.3)
    with FakeDaemon(tmp_path / "signspool", mode="hold_deaf"):
        with pytest.raises(SignerUnavailable) as ei:
            S.submit_and_wait(sp, 1, 1, expect_sha256=EXP, timeout=60, poll=0.01)
    assert "berhenti merespons" in ei.value.message and residue(sp) == {}


def test_hostile_result_for_a_job_is_never_trusted(sp, tmp_path):
    class Liar(FakeDaemon):
        def handle(self, job_id, job):
            self.claimed.append(job_id)
            self.spool.finish(job_id, {**GOOD, "ok": "true", "output_name": "../../x"})

    with Liar(tmp_path / "signspool"):
        r = S.submit_and_wait(sp, 1, 1, expect_sha256=EXP, timeout=60, poll=0.01)
    assert r["ok"] is False and r["output_name"] == "signed.apk"
