"""Protokol spool berkas (worker -> runner). Sebelumnya TANPA tes. Dikunci dulu sebelum `Spool` diparameterkan untuk bench, supaya perilaku
yang dipakai worker dan runner terbukti tidak berubah."""

from __future__ import annotations

import json
import os
import time

import pytest

from rvcore import spool as S
from rvcore.spool import Spool


@pytest.fixture
def sp(tmp_path):
    s = Spool(tmp_path / "spool")
    s.ensure_dirs()
    return s


def job(aid=1, stage="apktool", **extra):
    return {"job_id": S.new_job_id(aid, stage), "analysis_id": aid, "stage": stage, **extra}


def test_job_ids_are_validated():
    assert S.JOB_ID_RE.match(S.new_job_id(7, "jadx"))
    for bad in ("", "x", "a1-shell-deadbeef", "a1-apktool-DEADBEEF", "a1-apktool-deadbee", "../a1-apktool-deadbeef", "a1-apktool-deadbeef/x", "a-apktool-deadbeef"):
        assert not S.JOB_ID_RE.match(bad), bad
    with pytest.raises(ValueError):
        S.new_job_id(1, "shell")


def test_submit_claim_finish_result_roundtrip(sp):
    j = job(note="halo")
    sp.submit(j)
    assert sp.is_waiting(j["job_id"]) and sp.claim_next() == (j["job_id"], j)
    assert not sp.is_waiting(j["job_id"]) and sp.running_job_ids() == [j["job_id"]]
    assert sp.result(j["job_id"]) is None
    sp.finish(j["job_id"], {"status": "ok"})
    r = sp.result(j["job_id"])
    assert r["status"] == "ok" and r["job_id"] == j["job_id"] and "finished" in r
    assert sp.running_job_ids() == []
    sp.forget(j["job_id"])
    assert sp.result(j["job_id"]) is None


def test_claim_is_atomic_and_oldest_first(sp):
    a, b = job(1), job(2)
    sp.submit(a); os.utime(sp.requests / f"{a['job_id']}.json", (1, 1))
    sp.submit(b)
    assert sp.claim_next()[0] == a["job_id"]
    assert sp.claim_next()[0] == b["job_id"]
    assert sp.claim_next() is None


def test_submit_rejects_bad_ids(sp):
    with pytest.raises(ValueError):
        sp.submit({"job_id": "a1-shell-deadbeef"})
    with pytest.raises(ValueError):
        sp.submit({"job_id": "../../etc/passwd"})
    assert list(sp.requests.iterdir()) == []


def test_claim_discards_files_with_bad_names_and_bad_content(sp):
    (sp.requests / "liar.json").write_text("{}")
    (sp.requests / "a1-apktool-deadbeef.json").write_text("bukan json")
    (sp.requests / "a2-apktool-deadbeef.json").write_text(json.dumps({"job_id": "a9-apktool-deadbeef"}))
    assert sp.claim_next() is None
    assert not (sp.requests / "liar.json").exists()
    assert sp.result("a1-apktool-deadbeef")["error_code"] == "bad_request"
    assert sp.result("a2-apktool-deadbeef")["error_code"] == "bad_request"


def test_oversized_request_is_refused_by_the_runner_side(sp):
    j = job(note="x" * (S.MAX_REQUEST_BYTES + 10))
    sp.submit(j)
    assert sp.claim_next() is None
    assert sp.result(j["job_id"])["error_code"] == "bad_request"


def test_cancel_flag_and_withdraw(sp):
    j = job(); sp.submit(j)
    assert sp.withdraw(j["job_id"]) is True and sp.withdraw(j["job_id"]) is False
    sp.request_cancel(j["job_id"])
    assert sp.cancel_requested(j["job_id"])
    sp.request_cancel("../evil"); sp.request_cancel("a1-shell-deadbeef")
    assert sorted(p.name for p in sp.cancel.iterdir()) == [j["job_id"]]
    sp.finish(j["job_id"], {"status": "cancelled"})
    assert not sp.cancel_requested(j["job_id"])


def test_corrupt_result_is_reported_not_raised(sp):
    (sp.results / "a1-apktool-deadbeef.json").write_text("{rusak")
    assert sp.result("a1-apktool-deadbeef")["error_code"] == "bad_result"


def test_heartbeat_age(sp):
    assert sp.read_heartbeat() is None and sp.heartbeat_age() is None
    sp.write_heartbeat("idle")
    assert 0 <= sp.heartbeat_age() < 5 and sp.read_heartbeat()["state"] == "idle"
    sp.heartbeat_file.write_text(json.dumps({"ts": time.time() - 100}))
    assert 95 < sp.heartbeat_age() < 110
    sp.heartbeat_file.write_text("[]")
    assert sp.heartbeat_age() is None
