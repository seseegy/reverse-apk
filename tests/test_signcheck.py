"""services/worker/signcheck.py: satu-satunya pintu bash <-> rvcore.signspool / Layout untuk `make signer-verify` (Tahap 2a, FEAT-004).

Daemon PALSU di utas membalas lewat SignSpool (protokol nyata: heartbeat, claim_next, finish). Kelompok NYATA (test_real_*) menjalankan signer-daemon asli
dengan Build-Tools 37 + JDK 21 dan dilewati bersih tanpa env berikut (CI tidak punya alat itu):
  SIGNER_TEST_BUILD_TOOLS=<.../build-tools/android-37.0> SIGNER_TEST_JAVA_HOME=<jdk21> SIGNER_TEST_APK=<unsigned.apk>
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import tracemalloc
import zipfile
from pathlib import Path

import pytest
from conftest import within_call
from rvcore import signspool
from rvcore.paths import Layout

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "services/worker/signcheck.py"
AID = 2147483000
OWNER = hashlib.sha256(b"sertifikat pemilik").hexdigest()
OTHER = hashlib.sha256(b"sertifikat lain").hexdigest()
SHA = hashlib.sha256(b"signed.apk").hexdigest()


def load():
    spec = importlib.util.spec_from_file_location("signcheck_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def sc():
    return load()


@pytest.fixture
def layout(tmp_path):
    lay = Layout(tmp_path / "data")
    lay.builds.mkdir(parents=True)
    return lay


@pytest.fixture(autouse=True)
def no_diag(monkeypatch):
    monkeypatch.delenv("SIGNCHECK_DIAG", raising=False)


@pytest.fixture
def diag(monkeypatch):
    monkeypatch.setenv("SIGNCHECK_DIAG", "1")


def call(sc, layout, capsys, *argv, stdin: bytes | None = None):
    rc = sc.main([str(a) for a in argv], layout=layout, stdin=io.BytesIO(stdin if stdin is not None else b""))
    return rc, capsys.readouterr().out


def success_result(**over):
    res = {"ok": True, "error_code": None, "error_text": "", "output_name": "signed.apk", "output_size": 4321, "output_sha256": SHA, "input_sha256": SHA, "cert_sha256": OWNER,
           "verify": {"v1": False, "v2": True, "v3": True}, "signer_count": 1, "elapsed": 1.5}
    res.update(over)
    return res


def failure_result(code="input_missing"):
    return {"ok": False, "error_code": code, "error_text": signspool.ERROR_TEXT[code], "output_name": "signed.apk", "output_size": 0, "output_sha256": None,
            "cert_sha256": None, "verify": {"v1": None, "v2": False, "v3": False}, "signer_count": None, "elapsed": 0.3}


class FakeDaemon:
    """Daemon penanda tangan palsu: detak jantung + SignSpool.claim_next/finish nyata, jawaban dari `behave(job_id, job)`."""

    def __init__(self, layout, keystore_state="ok", keystore=None):
        self.spool = signspool.make_spool(layout.signspool)
        self.spool.ensure_dirs()
        self.seen: list[dict] = []
        self.behave = lambda job_id, job: success_result()
        self.keystore = keystore or {"state": keystore_state, "detail": "", "cert_sha256": OWNER if keystore_state == "ok" else None}
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        last = 0.0
        while not self.stop.is_set():
            if time.monotonic() - last > 0.3:
                self.spool.write_signer_heartbeat("idle", None, self.keystore)
                last = time.monotonic()
            claimed = self.spool.claim_next()
            if claimed is None:
                time.sleep(0.02)
                continue
            job_id, job = claimed
            self.seen.append(job)
            try:
                signspool.validate_request(job, job_id)
            except ValueError:
                self.spool.finish(job_id, failure_result("bad_request"))
                continue
            self.spool.finish(job_id, self.behave(job_id, job))

    def __enter__(self):
        self.spool.write_signer_heartbeat("idle", None, self.keystore)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(5)


@pytest.fixture
def daemon(layout):
    with FakeDaemon(layout) as d:
        yield d


def kv_lines(out: str) -> dict[str, str]:
    return dict(ln.split("=", 1) for ln in out.splitlines() if "=" in ln)


HASIL_RE = re.compile(r"HASIL ok=(1|0) code=(\S+) cert=(\S+) sha=(\S+) size=(\d+) v1=(1|0|-) v2=(1|0) v3=(1|0) signers=(\d+|-) elapsed=\d+\.\d\Z")


# ================================================================================ penjaga sentinel dan gerbang DIAG
ALL_IDS_COMMANDS = [("put",), ("sign",), ("ls",), ("clean",), ("put-garbage",), ("put-symlink",), ("put-big", "--size-mb", "1", "--entries", "1"),
                    ("bad-request", "--kind", "traversal")]


@pytest.mark.parametrize("cmd", ALL_IDS_COMMANDS, ids=lambda c: c[0])
@pytest.mark.parametrize("aid", ["1", "5", "2146999999", "0", "abc", "2147483648", "-1", "２１４７４８３０００"])
def test_every_subcommand_rejects_non_sentinel_analysis_ids(sc, layout, capsys, diag, cmd, aid):
    rc, out = call(sc, layout, capsys, cmd[0], aid, "1", *cmd[1:], stdin=b"x")
    assert rc == 64 and out.startswith("GALAT: ") and "sentinel" in out
    assert not list(layout.builds.iterdir()), "id non-sentinel tidak boleh membuat folder apa pun"


@pytest.mark.parametrize("cmd", [c for c in ALL_IDS_COMMANDS if c[0] != "clean"], ids=lambda c: c[0])
@pytest.mark.parametrize("bid", ["0", "8", "-1", "x", "99999"])
def test_every_subcommand_rejects_build_ids_outside_1_to_7(sc, layout, capsys, diag, cmd, bid):
    rc, out = call(sc, layout, capsys, cmd[0], AID, bid, *cmd[1:], stdin=b"x")
    assert rc == 64 and "build_id" in out
    assert not list(layout.builds.iterdir())


def test_clean_rejects_build_ids_outside_1_to_7_and_accepts_1_through_7(sc, layout, capsys):
    assert call(sc, layout, capsys, "clean", AID, 8)[0] == 64
    for bid in range(1, 8):
        assert call(sc, layout, capsys, "clean", AID, bid) == (0, "dibersihkan=0\n")


@pytest.mark.parametrize("cmd", [c for c in ALL_IDS_COMMANDS if c[0] in ("put-garbage", "put-symlink", "put-big", "bad-request")], ids=lambda c: c[0])
def test_diagnostic_subcommands_exit_64_without_signcheck_diag(sc, layout, capsys, cmd):
    rc, out = call(sc, layout, capsys, cmd[0], AID, 1, *cmd[1:], stdin=b"x")
    assert rc == 64 and "SIGNCHECK_DIAG=1" in out and not list(layout.builds.iterdir())


def test_diagnostic_gate_needs_exactly_one(sc, layout, capsys, monkeypatch):
    for value in ("0", "true", "", "2"):
        monkeypatch.setenv("SIGNCHECK_DIAG", value)
        assert call(sc, layout, capsys, "put-garbage", AID, 2)[0] == 64


def test_always_on_subcommands_do_not_need_the_diag_flag(sc, layout, capsys):
    assert call(sc, layout, capsys, "status")[0] == 0
    assert call(sc, layout, capsys, "df")[0] == 0
    assert call(sc, layout, capsys, "ls", AID, 1) == (0, "")


def test_usage_errors_exit_64_not_argparse_2(sc, layout, capsys):
    for argv in ([], ["tidak-ada"], ["sign"], ["sign", str(AID)], ["sign", str(AID), "1", "--timeout", "x"], ["put", str(AID), "1", "--bogus"]):
        rc, out = call(sc, layout, capsys, *argv)
        assert rc == 64 and out.startswith("GALAT: "), argv


# ================================================================================ status
def test_status_with_dead_signer_is_zero_with_hidup_0(sc, layout, capsys):
    rc, out = call(sc, layout, capsys, "status")
    assert rc == 0 and out.splitlines() == ["hidup=0", "umur_hb=-", "keystore=-", "cert_sha256=-", "detail="]


def test_status_reports_alive_signer_keystore_and_certificate(sc, layout, capsys, daemon):
    rc, out = call(sc, layout, capsys, "status")
    kv = kv_lines(out)
    assert rc == 0 and [ln.split("=")[0] for ln in out.splitlines()] == ["hidup", "umur_hb", "keystore", "cert_sha256", "detail"]
    assert kv["hidup"] == "1" and kv["keystore"] == "ok" and kv["cert_sha256"] == OWNER and re.fullmatch(r"\d+\.\d", kv["umur_hb"])


def test_status_shows_keystore_problem_detail_as_one_sanitised_line(sc, layout, capsys):
    ks = {"state": "unreadable", "detail": "baris satu\nbaris dua\x07 dan make keystore-access", "cert_sha256": None}
    with FakeDaemon(layout, keystore=ks):
        rc, out = call(sc, layout, capsys, "status")
    lines = out.splitlines()
    assert rc == 0 and len(lines) == 5 and kv_lines(out)["keystore"] == "unreadable" and "make keystore-access" in lines[4] and "\x07" not in out


def test_status_stale_heartbeat_is_hidup_0_but_still_exit_0(sc, layout, capsys):
    spool = signspool.make_spool(layout.signspool)
    spool.ensure_dirs()
    spool.heartbeat_file.write_text(json.dumps({"ts": time.time() - 120, "pid": 1, "state": "idle", "job": None,
                                                "keystore": {"state": "ok", "detail": "", "cert_sha256": OWNER}}))
    rc, out = call(sc, layout, capsys, "status")
    assert rc == 0 and kv_lines(out)["hidup"] == "0"


def test_status_hangs_on_nothing_when_heartbeat_is_a_fifo(sc, layout, capsys):
    """Warisan 2a (non-blocking): tes FIFO TANPA batas waktu akan ikut menggantung bila kodenya regresi; kini dibungkus `within_call`."""
    spool = signspool.make_spool(layout.signspool)
    spool.ensure_dirs()
    os.mkfifo(spool.heartbeat_file)
    started = time.monotonic()
    (rc, out), exc = within_call(5, call, sc, layout, capsys, "status")
    assert exc is None and rc == 0 and kv_lines(out)["hidup"] == "0" and time.monotonic() - started < 2


# ================================================================================ put / ls / df / clean
def test_put_writes_unsigned_apk_atomically_and_prints_size_and_sha(sc, layout, capsys):
    data = os.urandom(3 * 1024 * 1024 + 17)
    rc, out = call(sc, layout, capsys, "put", AID, 1, stdin=data)
    bdir = layout.build_dir(AID, 1)
    assert rc == 0 and out.splitlines() == [f"ditulis={len(data)}", f"sha256={hashlib.sha256(data).hexdigest()}"]
    assert [p.name for p in bdir.iterdir()] == ["unsigned.apk"] and (bdir / "unsigned.apk").read_bytes() == data


def test_put_replaces_an_existing_symlink_without_following_it(sc, layout, capsys, tmp_path):
    victim = tmp_path / "korban"
    victim.write_text("jangan ditimpa")
    bdir = layout.build_dir(AID, 4)
    bdir.mkdir(parents=True)
    (bdir / "unsigned.apk").symlink_to(victim)
    rc, _ = call(sc, layout, capsys, "put", AID, 4, stdin=b"PK-data")
    assert rc == 0 and victim.read_text() == "jangan ditimpa" and not (bdir / "unsigned.apk").is_symlink()


class Endless:
    def __init__(self, total):
        self.left = total

    def read(self, n):
        n = min(n, self.left)
        self.left -= n
        return b"\0" * n


def test_put_over_64_mib_fails_with_code_2_and_leaves_no_partial_file(sc, layout, capsys):
    rc = sc.main(["put", str(AID), "1"], layout=layout, stdin=Endless(65 * 1024 * 1024))
    out = capsys.readouterr().out
    assert rc == 2 and out.startswith("GALAT: ") and "64 MiB" in out
    assert list(layout.build_dir(AID, 1).iterdir()) == []


def test_put_exactly_64_mib_is_accepted(sc, layout, capsys):
    assert sc.main(["put", str(AID), "1"], layout=layout, stdin=Endless(64 * 1024 * 1024)) == 0
    assert layout.build_dir(AID, 1).joinpath("unsigned.apk").stat().st_size == 64 * 1024 * 1024


def test_put_cleans_the_temp_file_when_the_input_stream_breaks(sc, layout, capsys):
    class Broken:
        calls = 0

        def read(self, n):
            Broken.calls += 1
            if Broken.calls > 1:
                raise OSError(5, "Input/output error")
            return b"x" * 100

    rc = sc.main(["put", str(AID), "1"], layout=layout, stdin=Broken())
    assert rc == 2 and capsys.readouterr().out.startswith("GALAT: ") and list(layout.build_dir(AID, 1).iterdir()) == []


def test_ls_lists_sorted_names_and_missing_folder_is_empty(sc, layout, capsys):
    assert call(sc, layout, capsys, "ls", AID, 2) == (0, "")
    bdir = layout.build_dir(AID, 2)
    bdir.mkdir(parents=True)
    for name in ("unsigned.apk", ".sign-signed.tmp", "a.txt"):
        (bdir / name).write_text("x")
    assert call(sc, layout, capsys, "ls", AID, 2) == (0, ".sign-signed.tmp\na.txt\nunsigned.apk\n")


def test_df_prints_free_mib_of_the_builds_volume(sc, layout, capsys, monkeypatch):
    rc, out = call(sc, layout, capsys, "df")
    assert rc == 0 and re.fullmatch(r"bebas_mib=\d+\n", out)
    monkeypatch.setattr(sc.os, "statvfs", lambda p: os.statvfs_result((4096, 4096, 100000, 50000, 50000, 0, 0, 0, 0, 255)))
    assert call(sc, layout, capsys, "df") == (0, f"bebas_mib={50000 * 4096 // (1024 * 1024)}\n")


def test_df_error_is_exit_2(sc, layout, capsys, tmp_path):
    rc, out = call(sc, Layout(tmp_path / "tidak-ada"), capsys, "df")
    assert rc == 2 and out.startswith("GALAT: ")


def test_clean_removes_only_the_sentinel_build_folders_and_its_spool_leftovers(sc, layout, capsys):
    for bid in (1, 2):
        (layout.build_dir(AID, bid)).mkdir(parents=True)
        (layout.build_dir(AID, bid) / "unsigned.apk").write_text("x")
    other = layout.build_dir(AID + 1, 1)
    other.mkdir(parents=True)
    real = layout.build_dir(7, 1)
    real.mkdir(parents=True)
    spool = signspool.make_spool(layout.signspool)
    spool.ensure_dirs()
    mine, mine2, theirs = f"g{AID}-1-aaaaaaaa", f"g{AID}-2-bbbbbbbb", "g7-1-cccccccc"
    for folder in (spool.requests, spool.running, spool.results):
        for name in (mine, mine2, theirs):
            (folder / f"{name}.json").write_text("{}")
    (spool.cancel / mine).write_text("")
    # clean AID BID: hanya satu build_id
    assert call(sc, layout, capsys, "clean", AID, 1) == (0, "dibersihkan=1\n")
    assert not layout.build_dir(AID, 1).exists() and layout.build_dir(AID, 2).exists()
    assert not (spool.results / f"{mine}.json").exists() and (spool.results / f"{mine2}.json").exists() and not (spool.cancel / mine).exists()
    # clean AID: semuanya, tetapi tidak menyentuh id lain
    assert call(sc, layout, capsys, "clean", AID) == (0, "dibersihkan=1\n")
    assert not layout.builds_dir(AID).exists() and other.exists() and real.exists()
    assert sorted(p.name for p in spool.results.iterdir()) == [f"{theirs}.json"] and sorted(p.name for p in spool.requests.iterdir()) == [f"{theirs}.json"]
    assert call(sc, layout, capsys, "clean", AID) == (0, "dibersihkan=0\n")


def test_clean_never_follows_a_symlinked_build_folder(sc, layout, capsys, tmp_path):
    victim = tmp_path / "korban"
    victim.mkdir()
    (victim / "penting").write_text("x")
    layout.builds_dir(AID).symlink_to(victim)
    assert call(sc, layout, capsys, "clean", AID) == (0, "dibersihkan=1\n")
    assert (victim / "penting").exists() and not layout.builds_dir(AID).exists()


# ================================================================================ A-03: rantai-dirfd (runner kini menulis akar `builds`)
def _plant_symlinked_aid(layout, tmp_path, name="korban"):
    """`builds/<AID>` ditukar jadi symlink ke direktori berisi penanda (yang dilakukan runner terkompromi)."""
    victim = tmp_path / name
    (victim / "1").mkdir(parents=True)
    (victim / "1" / "unsigned.apk").write_bytes(b"jangan disentuh")
    (victim / "penting").write_text("x")
    layout.builds_dir(AID).symlink_to(victim)
    return victim


def test_clean_aid_bid_with_a_symlinked_aid_refuses_and_leaves_the_target_intact(sc, layout, capsys, tmp_path):
    victim = _plant_symlinked_aid(layout, tmp_path)
    rc, out = call(sc, layout, capsys, "clean", AID, 1)
    assert rc == 2 and out.startswith("GALAT: ") and "bukan direktori biasa" in out
    assert (victim / "1" / "unsigned.apk").read_bytes() == b"jangan disentuh" and (victim / "penting").exists()
    assert layout.builds_dir(AID).is_symlink(), "symlinknya tidak dihapus oleh `clean AID BID`; `clean AID` yang meng-unlink-nya"


@pytest.mark.parametrize("cmd", [("put", 1), ("put-garbage", 1), ("put-symlink", 1), ("ls", 1)])
def test_writers_never_follow_a_symlinked_aid(sc, layout, capsys, tmp_path, diag, cmd):
    victim = _plant_symlinked_aid(layout, tmp_path)
    before = sorted(p.name for p in (victim / "1").iterdir())
    rc, out = call(sc, layout, capsys, cmd[0], AID, cmd[1], stdin=b"isi")
    assert (rc == 0 and cmd[0] == "ls" and out == "") or (rc == 2 and out.startswith("GALAT: "))
    assert sorted(p.name for p in (victim / "1").iterdir()) == before and (victim / "1" / "unsigned.apk").read_bytes() == b"jangan disentuh"


def test_writers_never_follow_a_symlinked_bid(sc, layout, capsys, tmp_path):
    victim = tmp_path / "korban-bid"
    victim.mkdir()
    (victim / "penting").write_text("x")
    layout.builds_dir(AID).mkdir(parents=True)
    layout.build_dir(AID, 1).symlink_to(victim)
    rc, out = call(sc, layout, capsys, "put", AID, 1, stdin=b"isi")
    assert rc == 2 and out.startswith("GALAT: ") and [p.name for p in victim.iterdir()] == ["penting"]


def test_signcheck_has_no_path_based_mutation_of_builds():
    """Penjaga struktural A-03: tidak ada `safe_rmtree`/`shutil.rmtree`/`Path.mkdir`/`.rename`/`os.replace` berbasis jalur pada `builds` di signcheck.py."""
    import ast

    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {"safe_rmtree", "rmtree", "mkdir", "makedirs", "rename"}, names & {"safe_rmtree", "rmtree", "mkdir", "makedirs", "rename"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "replace" and getattr(node.func.value, "id", "") == "os":
            assert {k.arg for k in node.keywords} >= {"src_dir_fd", "dst_dir_fd"}, "os.replace harus relatif dir_fd"


# ================================================================================ expect_sha256 (A-02, sisi klien) dan FIFO ber-batas waktu
def test_sign_sends_the_sha256_of_the_unsigned_apk_it_read_through_the_nofollow_chain(sc, layout, capsys, daemon):
    bdir = layout.build_dir(AID, 1)
    bdir.mkdir(parents=True)
    (bdir / "unsigned.apk").write_bytes(b"isi apk")
    assert call(sc, layout, capsys, "sign", AID, 1)[0] == 0
    assert daemon.seen[0]["expect_sha256"] == hashlib.sha256(b"isi apk").hexdigest()
    assert call(sc, layout, capsys, "sign", AID, 1, "--expect-sha256", "ab" * 32)[0] == 0
    assert daemon.seen[1]["expect_sha256"] == "ab" * 32


@pytest.mark.parametrize("kind", ["missing", "symlink", "fifo", "dir"])
def test_sign_sends_a_zero_hash_for_a_missing_or_unsafe_input_and_never_hangs(sc, layout, capsys, daemon, tmp_path, kind):
    bdir = layout.build_dir(AID, 1)
    bdir.mkdir(parents=True)
    apk = bdir / "unsigned.apk"
    target = tmp_path / "t.apk"
    target.write_bytes(b"rahasia")
    {"missing": lambda: None, "symlink": lambda: apk.symlink_to(target), "fifo": lambda: os.mkfifo(apk), "dir": lambda: apk.mkdir()}[kind]()
    (rc, out), exc = within_call(5, call, sc, layout, capsys, "sign", AID, 1)
    assert exc is None and rc == 0
    assert daemon.seen[0]["expect_sha256"] == "0" * 64, "signer sendiri yang menjawab input_missing/input_unsafe"


def test_sign_rejects_a_malformed_expect_sha256_before_contacting_the_signer(sc, layout, capsys, daemon):
    for bad in ("zz", "AB" * 32, "ab" * 31):
        assert call(sc, layout, capsys, "sign", AID, 1, "--expect-sha256", bad)[0] == 64
    assert not daemon.seen


# ================================================================================ diagnostik: put-garbage / put-symlink
def test_put_garbage_and_symlink(sc, layout, capsys, diag):
    assert call(sc, layout, capsys, "put-garbage", AID, 2) == (0, "ditulis=10\n")
    bdir2 = layout.build_dir(AID, 2)
    assert (bdir2 / "unsigned.apk").read_bytes() == b"bukan zip\n" and [p.name for p in bdir2.iterdir()] == ["unsigned.apk"]
    assert call(sc, layout, capsys, "put-symlink", AID, 4) == (0, "dibuat=symlink\n")
    link = layout.build_dir(AID, 4) / "unsigned.apk"
    assert link.is_symlink() and os.readlink(link) == "/etc/hostname"
    assert call(sc, layout, capsys, "put-symlink", AID, 4) == (0, "dibuat=symlink\n"), "idempoten"


# ================================================================================ sign: kontrak kode keluar dan format
def test_sign_prints_exact_hasil_line_and_exits_0_without_expectations(sc, layout, capsys, daemon):
    rc, out = call(sc, layout, capsys, "sign", AID, 1)
    assert rc == 0 and out.splitlines() == [f"HASIL ok=1 code=- cert={OWNER} sha={SHA} size=4321 v1=0 v2=1 v3=1 signers=1 elapsed=1.5"]
    assert HASIL_RE.fullmatch(out.strip())
    job = daemon.seen[0]
    assert job["analysis_id"] == AID and job["build_id"] == 1 and "path" not in job and "input" not in job


def test_sign_failure_without_expectations_is_still_exit_0(sc, layout, capsys, daemon):
    daemon.behave = lambda *_: failure_result("verify_failed")
    rc, out = call(sc, layout, capsys, "sign", AID, 1)
    assert rc == 0 and out.splitlines() == ["HASIL ok=0 code=verify_failed cert=- sha=- size=0 v1=- v2=0 v3=0 signers=- elapsed=0.3"]
    assert HASIL_RE.fullmatch(out.strip())


def test_sign_expect_ok_passes_only_with_the_owner_certificate(sc, layout, capsys, daemon):
    assert call(sc, layout, capsys, "sign", AID, 1, "--expect-ok", "--owner-sha256", OWNER)[0] == 0
    assert call(sc, layout, capsys, "sign", AID, 1, "--expect-ok", "--owner-sha256", OWNER.upper())[0] == 0, "dibandingkan huruf kecil"
    rc, out = call(sc, layout, capsys, "sign", AID, 1, "--expect-ok", "--owner-sha256", OTHER)
    lines = out.splitlines()
    assert rc == 3 and HASIL_RE.fullmatch(lines[0]) and lines[1].startswith("ALASAN: ") and "pemilik" in lines[1] and len(lines) == 2


def test_sign_expect_ok_never_exits_0_when_the_job_failed(sc, layout, capsys, daemon):
    daemon.behave = lambda *_: failure_result("cert_mismatch")
    rc, out = call(sc, layout, capsys, "sign", AID, 1, "--expect-ok", "--owner-sha256", OWNER)
    lines = out.splitlines()
    assert rc == 3 and lines[0].startswith("HASIL ok=0 code=cert_mismatch") and lines[1].startswith("ALASAN: ") and "cert_mismatch" in lines[1]


@pytest.mark.parametrize("over", [
    {"signer_count": 2}, {"verify": {"v1": False, "v2": True, "v3": False}}, {"verify": {"v1": False, "v2": False, "v3": True}},
    {"ok": "true"}, {"ok": 1}, {"cert_sha256": "zz"}, {"output_size": 0}, {"output_sha256": None},
])
def test_sign_expect_ok_rejects_incoherent_or_weak_results(sc, layout, capsys, daemon, over):
    daemon.behave = lambda *_: success_result(**over)
    rc, out = call(sc, layout, capsys, "sign", AID, 1, "--expect-ok", "--owner-sha256", OWNER)
    assert rc == 3 and "ALASAN: " in out and "ok=1" not in out.splitlines()[0]


def test_sign_expect_error_passes_only_with_the_exact_code(sc, layout, capsys, daemon):
    daemon.behave = lambda *_: failure_result("input_missing")
    assert call(sc, layout, capsys, "sign", AID, 3, "--expect-error", "input_missing")[0] == 0
    rc, out = call(sc, layout, capsys, "sign", AID, 3, "--expect-error", "align_failed")
    assert rc == 3 and "ALASAN: " in out and "input_missing" in out
    daemon.behave = lambda *_: success_result()
    rc, out = call(sc, layout, capsys, "sign", AID, 3, "--expect-error", "input_missing")
    assert rc == 3 and "berhasil" in out.splitlines()[1]


def test_sign_argument_validation(sc, layout, capsys, daemon):
    assert call(sc, layout, capsys, "sign", AID, 1, "--expect-ok")[0] == 64
    assert call(sc, layout, capsys, "sign", AID, 1, "--expect-ok", "--owner-sha256", "bukan-heks")[0] == 64
    assert call(sc, layout, capsys, "sign", AID, 1, "--expect-ok", "--owner-sha256", OWNER, "--expect-error", "timeout")[0] == 64
    assert call(sc, layout, capsys, "sign", AID, 1, "--expect-error", "kode-ngawur")[0] == 64
    assert not daemon.seen, "salah pakai tidak boleh sampai ke signer"


def test_sign_with_dead_signer_is_exit_2_with_galat_line(sc, layout, capsys):
    rc, out = call(sc, layout, capsys, "sign", AID, 1, "--expect-ok", "--owner-sha256", OWNER)
    assert rc == 2 and out.startswith("GALAT: ") and len(out.splitlines()) == 1 and "Signer tidak aktif" in out


def test_sign_with_bad_keystore_is_exit_2(sc, layout, capsys):
    with FakeDaemon(layout, keystore_state="missing"):
        rc, out = call(sc, layout, capsys, "sign", AID, 1)
    assert rc == 2 and out.startswith("GALAT: ") and "missing" in out


def test_sign_end_to_end_with_the_real_protocol_files_cleaned_up(sc, layout, capsys, daemon):
    call(sc, layout, capsys, "sign", AID, 1)
    spool = daemon.spool
    assert not list(spool.requests.iterdir()) and not list(spool.running.iterdir()) and not list(spool.results.iterdir())


# ================================================================================ bad-request
def test_bad_request_traversal_is_answered_bad_request(sc, layout, capsys, diag, daemon):
    rc, out = call(sc, layout, capsys, "bad-request", AID, 1, "--kind", "traversal", "--expect-error", "bad_request")
    assert rc == 0 and HASIL_RE.fullmatch(out.strip()) and "code=bad_request" in out
    raw = daemon.seen[0]
    assert raw["analysis_id"] == "../etc" and raw["path"] == "/etc/passwd" and signspool.JOB_ID_RE.match(raw["job_id"])
    assert raw["job_id"].startswith(f"g{AID}-1-")


def test_bad_request_expectation_mismatch_is_exit_3(sc, layout, capsys, diag, daemon):
    rc, out = call(sc, layout, capsys, "bad-request", AID, 1, "--kind", "traversal", "--expect-error", "cert_mismatch")
    assert rc == 3 and "ALASAN: " in out
    rc, out = call(sc, layout, capsys, "bad-request", AID, 1, "--kind", "traversal")
    assert rc == 0, "tanpa --expect-error selalu 0 bila job berjalan"


def test_bad_request_with_dead_signer_or_unknown_kind(sc, layout, capsys, diag):
    rc, out = call(sc, layout, capsys, "bad-request", AID, 1, "--kind", "traversal", "--expect-error", "bad_request")
    assert rc == 2 and out.startswith("GALAT: ")
    assert call(sc, layout, capsys, "bad-request", AID, 1, "--kind", "lain")[0] == 64


# ================================================================================ put-big (STREAMING)
def tiny_apk() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"manifest" * 20)
        zf.writestr("classes.dex", b"dex\n035\x00" + bytes(range(256)))
        zf.writestr("res/layout/a.xml", b"<x/>" * 30)
    return buf.getvalue()


def test_put_big_64_mib_single_entry_uses_less_than_8_mib_of_python_memory(sc, layout, capsys, diag):
    base = tiny_apk()
    tracemalloc.start()
    try:
        rc = sc.main(["put-big", str(AID), "5", "--size-mb", "64", "--entries", "1"], layout=layout, stdin=io.BytesIO(base))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    out = capsys.readouterr().out
    apk = layout.build_dir(AID, 5) / "unsigned.apk"
    assert rc == 0 and peak < 8 * 1024 * 1024, f"puncak {peak / 1048576:.1f} MiB"
    assert kv_lines(out) == {"ditulis": str(apk.stat().st_size), "entri": "4"}
    assert apk.stat().st_size > 64 * 1024 * 1024 and [p.name for p in apk.parent.iterdir()] == ["unsigned.apk"]
    with zipfile.ZipFile(apk) as zf:
        big = zf.getinfo("assets/f000000.bin")
        assert big.file_size == 64 * 1024 * 1024 and big.compress_type == zipfile.ZIP_STORED
        assert zf.read("classes.dex") == b"dex\n035\x00" + bytes(range(256)), "entri APK dasar disalin utuh"


def test_put_big_60000_entries_makes_a_valid_zip(sc, layout, capsys, diag):
    rc, out = call(sc, layout, capsys, "put-big", AID, 6, "--size-mb", "1", "--entries", "60000", stdin=tiny_apk())
    apk = layout.build_dir(AID, 6) / "unsigned.apk"
    assert rc == 0 and kv_lines(out)["entri"] == "60003"
    with zipfile.ZipFile(apk) as zf:
        infos = zf.infolist()
        assert len(infos) == 60003 and len({i.filename for i in infos}) == 60003
        assert sum(i.file_size for i in infos if i.filename.startswith("assets/")) == 1024 * 1024
        assert zf.testzip() is None


def test_put_big_jar_meta_adds_three_tiny_meta_inf_entries(sc, layout, capsys, diag):
    rc, out = call(sc, layout, capsys, "put-big", AID, 7, "--size-mb", "1", "--entries", "3", "--jar-meta", stdin=tiny_apk())
    assert rc == 0 and kv_lines(out)["entri"] == "9"
    with zipfile.ZipFile(layout.build_dir(AID, 7) / "unsigned.apk") as zf:
        meta = {n: zf.read(n) for n in zf.namelist() if n.startswith("META-INF/")}
    assert sorted(meta) == ["META-INF/CERT.RSA", "META-INF/CERT.SF", "META-INF/MANIFEST.MF"] and all(len(v) <= 64 for v in meta.values())
    rc, out = call(sc, layout, capsys, "put-big", AID, 7, "--size-mb", "1", "--entries", "3", stdin=tiny_apk())
    with zipfile.ZipFile(layout.build_dir(AID, 7) / "unsigned.apk") as zf:
        assert not [n for n in zf.namelist() if n.startswith("META-INF/")], "tanpa --jar-meta tidak ada META-INF"


@pytest.mark.parametrize("args", [["--size-mb", "1101", "--entries", "1"], ["--size-mb", "0", "--entries", "1"], ["--size-mb", "1", "--entries", "0"],
                                  ["--size-mb", "1", "--entries", "70001"], ["--size-mb", "2000", "--entries", "1"]])
def test_put_big_rejects_out_of_range_arguments_with_64(sc, layout, capsys, diag, args):
    rc, out = call(sc, layout, capsys, "put-big", AID, 5, *args, stdin=tiny_apk())
    assert rc == 64 and out.startswith("GALAT: ")
    assert not list(layout.builds.iterdir()) or not any(layout.build_dir(AID, 5).glob("*"))


def test_put_big_checks_free_disk_before_writing(sc, layout, capsys, diag, monkeypatch):
    monkeypatch.setattr(sc, "free_mib", lambda path: 64 + 100 - 1)
    rc, out = call(sc, layout, capsys, "put-big", AID, 5, "--size-mb", "100", "--entries", "1", stdin=tiny_apk())
    assert rc == 2 and "ruang disk tidak cukup" in out and "butuh 164" in out and list(layout.build_dir(AID, 5).iterdir()) == []
    monkeypatch.setattr(sc, "free_mib", lambda path: 64 + 1)
    assert call(sc, layout, capsys, "put-big", AID, 5, "--size-mb", "1", "--entries", "1", stdin=tiny_apk())[0] == 0


def test_put_big_removes_the_temp_file_on_error_and_on_keyboard_interrupt(sc, layout, capsys, diag, monkeypatch):
    bdir = layout.build_dir(AID, 5)
    monkeypatch.setattr(sc.os, "urandom", lambda n: (_ for _ in ()).throw(OSError(28, "No space left on device")))
    rc, out = call(sc, layout, capsys, "put-big", AID, 5, "--size-mb", "2", "--entries", "1", stdin=tiny_apk())
    assert rc == 2 and out.startswith("GALAT: ") and list(bdir.iterdir()) == []
    monkeypatch.setattr(sc.os, "urandom", lambda n: (_ for _ in ()).throw(KeyboardInterrupt()))
    rc, out = call(sc, layout, capsys, "put-big", AID, 5, "--size-mb", "2", "--entries", "1", stdin=tiny_apk())
    assert rc == 2 and "dihentikan" in out and list(bdir.iterdir()) == []


def test_put_big_rejects_a_non_zip_base_and_leaves_nothing(sc, layout, capsys, diag):
    rc, out = call(sc, layout, capsys, "put-big", AID, 5, "--size-mb", "1", "--entries", "1", stdin=b"bukan zip")
    assert rc == 2 and out.startswith("GALAT: ") and list(layout.build_dir(AID, 5).iterdir()) == []
    rc, out = call(sc, layout, capsys, "put-big", AID, 5, "--size-mb", "1", "--entries", "1", stdin=b"")
    assert rc == 2


def test_put_big_replaces_an_existing_unsigned_apk_atomically(sc, layout, capsys, diag):
    bdir = layout.build_dir(AID, 5)
    bdir.mkdir(parents=True)
    (bdir / "unsigned.apk").write_bytes(b"lama")
    assert call(sc, layout, capsys, "put-big", AID, 5, "--size-mb", "1", "--entries", "2", stdin=tiny_apk())[0] == 0
    assert zipfile.is_zipfile(bdir / "unsigned.apk") and [p.name for p in bdir.iterdir()] == ["unsigned.apk"]


# ================================================================================ proses nyata (python signcheck.py) dan Dockerfile
def test_worker_dockerfile_copies_signcheck_into_the_image():
    text = (ROOT / "services/worker/Dockerfile").read_text(encoding="utf-8")
    assert "worker/signcheck.py" in text
    assert SCRIPT.is_file() and "COPY rvcore ./rvcore" in text


def test_script_runs_as_a_real_process_with_exit_codes(layout, tmp_path):
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "services"), "DATA_DIR": str(layout.root), "PYTHONDONTWRITEBYTECODE": "1"}
    run = lambda *a, **kw: subprocess.run([sys.executable, str(SCRIPT), *a], capture_output=True, text=True, timeout=60, env={**env, **kw.get("env", {})})  # noqa: E731
    r = run("status")
    assert r.returncode == 0 and r.stdout.splitlines()[0] == "hidup=0"
    r = run("put-garbage", str(AID), "2")
    assert r.returncode == 64 and "SIGNCHECK_DIAG=1" in r.stdout
    r = run("put-garbage", str(AID), "2", env={"SIGNCHECK_DIAG": "1"})
    assert r.returncode == 0 and r.stdout == "ditulis=10\n"
    r = run("sign", "5", "1")
    assert r.returncode == 64
    r = run("sign", str(AID), "1")
    assert r.returncode == 2 and r.stdout.startswith("GALAT: ")


# ================================================================================ NYATA (daemon asli + Build-Tools 37 + JDK 21)
REAL_VARS = ("SIGNER_TEST_BUILD_TOOLS", "SIGNER_TEST_JAVA_HOME", "SIGNER_TEST_APK")
real_only = pytest.mark.skipif(not all(os.environ.get(v) for v in REAL_VARS),
                               reason="alat nyata tidak ada (set SIGNER_TEST_BUILD_TOOLS, SIGNER_TEST_JAVA_HOME, SIGNER_TEST_APK)")
WRAPPER = ('#!/bin/sh\nexec java -Xmx256m -XX:MaxDirectMemorySize=64m --enable-native-access=ALL-UNNAMED -Duser.home="$HOME" '
           '-Djava.io.tmpdir=/tmp -jar {bt}/lib/apksigner.jar "$@"\n')


@pytest.fixture
def real_daemon(tmp_path):
    bt, jh, apk = Path(os.environ["SIGNER_TEST_BUILD_TOOLS"]), Path(os.environ["SIGNER_TEST_JAVA_HOME"]), Path(os.environ["SIGNER_TEST_APK"])
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "apksigner").write_text(WRAPPER.format(bt=bt))
    (bindir / "apksigner").chmod(0o755)
    (bindir / "zipalign").symlink_to(bt / "zipalign")
    (bindir / "java").symlink_to(jh / "bin" / "java")
    (bindir / "keytool").symlink_to(jh / "bin" / "keytool")
    secrets = tmp_path / "run-secrets"
    secrets.mkdir()
    home = tmp_path / "kt-home"
    home.mkdir()
    pw = os.urandom(32).hex()
    (secrets / "signing_keystore_pass").write_text(pw + "\n")
    kenv = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8"}
    subprocess.run([str(bindir / "keytool"), "-genkeypair", "-keystore", str(secrets / "signing_keystore"), "-storetype", "PKCS12", "-alias", "reverse-apk",
                    "-keyalg", "RSA", "-keysize", "3072", "-sigalg", "SHA256withRSA", "-validity", "3650", "-dname", "CN=pemilik-signcheck",
                    "-storepass:file", str(secrets / "signing_keystore_pass")], check=True, capture_output=True, env=kenv, timeout=240)
    der = subprocess.run([str(bindir / "keytool"), "-exportcert", "-alias", "reverse-apk", "-keystore", str(secrets / "signing_keystore"), "-storetype", "PKCS12",
                          "-storepass:file", str(secrets / "signing_keystore_pass")], check=True, capture_output=True, env=kenv, timeout=60).stdout
    owner = hashlib.sha256(der).hexdigest()
    data = tmp_path / "data"
    lay = Layout(data)
    lay.builds.mkdir(parents=True)                         # volume `builds` ada (titik mount di image); signcheck tidak membuat akar volume
    boot = f"""
import importlib.machinery, importlib.util, sys
from pathlib import Path
sys.path.insert(0, {str(ROOT / 'services')!r})
loader = importlib.machinery.SourceFileLoader('signer_daemon_main', {str(ROOT / 'services/signer/signer-daemon')!r})
spec = importlib.util.spec_from_loader('signer_daemon_main', loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)
m.TOOL_HOME_ROOT = Path({str(tmp_path / 'tool-home')!r}); m.TOOL_PATH = {str(bindir)!r}; m.TICK = 0.1; m.KEY_RECHECK = 1.0; m.TERM_GRACE = 0.5
sys.exit(m.main())
"""
    env = {"PATH": "/usr/bin:/bin", "DATA_DIR": str(data), "SIGNER_SECRETS_DIR": str(secrets), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.Popen([sys.executable, "-c", boot], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.monotonic() + 60
        spool = signspool.make_spool(lay.signspool)
        while time.monotonic() < deadline and signspool.signer_status(spool)["keystore"]["state"] != "ok":
            time.sleep(0.2)
        assert signspool.signer_status(spool)["keystore"]["state"] == "ok", "daemon nyata tidak siap"
        yield type("Real", (), {"layout": lay, "owner": owner, "apk": apk, "pw": pw, "bt": bt, "bindir": bindir, "jh": jh})()
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            log = proc.communicate(timeout=30)[0]
        except subprocess.TimeoutExpired:
            proc.kill()
            log = proc.communicate()[0]
    assert pw not in log


@real_only
def test_real_end_to_end_status_put_sign_negatives_and_clean(sc, real_daemon, capsys, monkeypatch):
    lay, apk = real_daemon.layout, real_daemon.apk.read_bytes()
    monkeypatch.setenv("SIGNCHECK_DIAG", "1")
    rc, out = call(sc, lay, capsys, "status")
    kv = kv_lines(out)
    assert rc == 0 and kv["hidup"] == "1" and kv["keystore"] == "ok" and kv["cert_sha256"] == real_daemon.owner
    rc, out = call(sc, lay, capsys, "put", AID, 1, stdin=apk)
    assert rc == 0 and kv_lines(out)["sha256"] == hashlib.sha256(apk).hexdigest()
    rc, out = call(sc, lay, capsys, "sign", AID, 1, "--timeout", "300", "--expect-ok", "--owner-sha256", real_daemon.owner)
    assert rc == 0 and HASIL_RE.fullmatch(out.strip()) and f"cert={real_daemon.owner}" in out, out
    signed = lay.build_dir(AID, 1) / "signed.apk"
    assert {"signed.apk", "unsigned.apk"} <= set(call(sc, lay, capsys, "ls", AID, 1)[1].split())
    assert f"size={signed.stat().st_size}" in out and f"sha={hashlib.sha256(signed.read_bytes()).hexdigest()}" in out
    # sertifikat pemilik LAIN -> kode 3 (tidak pernah 0)
    rc, out = call(sc, lay, capsys, "sign", AID, 1, "--timeout", "300", "--expect-ok", "--owner-sha256", OTHER)
    assert rc == 3 and "ALASAN: " in out
    # negatif
    assert call(sc, lay, capsys, "sign", AID, 3, "--timeout", "60", "--expect-error", "input_missing")[0] == 0
    assert call(sc, lay, capsys, "put-garbage", AID, 2)[0] == 0
    assert call(sc, lay, capsys, "sign", AID, 2, "--timeout", "60", "--expect-error", "align_failed")[0] == 0
    assert call(sc, lay, capsys, "ls", AID, 2) == (0, "unsigned.apk\n")
    assert call(sc, lay, capsys, "put-symlink", AID, 4)[0] == 0
    assert call(sc, lay, capsys, "sign", AID, 4, "--timeout", "60", "--expect-error", "input_unsafe")[0] == 0
    assert call(sc, lay, capsys, "bad-request", AID, 1, "--kind", "traversal", "--expect-error", "bad_request")[0] == 0
    assert call(sc, lay, capsys, "clean", AID) == (0, "dibersihkan=1\n")
    assert not lay.builds_dir(AID).exists()
    assert real_daemon.pw not in "".join(p.read_text() for p in (lay.signspool / "results").glob("*.json"))


@real_only
def test_real_put_big_with_jar_meta_is_accepted_by_the_real_daemon_and_keeps_meta_inf(sc, real_daemon, capsys, monkeypatch):
    lay = real_daemon.layout
    monkeypatch.setenv("SIGNCHECK_DIAG", "1")
    rc, out = call(sc, lay, capsys, "put-big", AID, 7, "--size-mb", "4", "--entries", "200", "--jar-meta", stdin=real_daemon.apk.read_bytes())
    assert rc == 0 and kv_lines(out)["entri"] == str(len(zipfile.ZipFile(real_daemon.apk).infolist()) + 200 + 3)
    rc, out = call(sc, lay, capsys, "sign", AID, 7, "--timeout", "300", "--expect-ok", "--owner-sha256", real_daemon.owner)
    assert rc == 0, out
    names = zipfile.ZipFile(lay.build_dir(AID, 7) / "signed.apk").namelist()
    assert "META-INF/MANIFEST.MF" in names and sum(n.startswith("assets/f") for n in names) == 200
    assert call(sc, lay, capsys, "clean", AID)[1] == "dibersihkan=1\n"
