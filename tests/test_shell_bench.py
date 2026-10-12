"""Shell terisolasi untuk AI (PRD 09, Bagian C), sisi BENCH: protokol, kebijakan akses, pengurungan Landlock nyata, dan eksekutor.

Lapisan diuji TERPISAH supaya mutasi pada satu lapis tidak tertutup lapis lain:
  1. shellspool : id, validasi, parser hasil dari bench (TIDAK TEPERCAYA), perilaku klien (mati/sibuk/batal/waktu)
  2. policy     : DAFTAR PUTIH apa yang boleh dibaca/ditulis; index/ tertutup
  3. kernel     : pengurungan NYATA (dilewati dengan alasan tertulis bila Landlock tidak ada; buktinya ada di `make bench-selftest`)
  4. executor   : batas waktu, keluaran, proses yatim, gagal tertutup
Sisi web (tool shell_run, prompt, UI) ada di test_shell_tool.py.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "services" / "bench"))

from bench import executor as E  # noqa: E402
from bench import landlock as LL  # noqa: E402
from bench import policy as P  # noqa: E402
from rvcore import shellspool as SP  # noqa: E402

SHA = "a" * 64
OTHER = "b" * 64
SECRET = "AKIAIOSFODNN7EXAMPLE"          # kunci contoh dokumentasi AWS, bukan rahasia sungguhan

needs_landlock = pytest.mark.skipif(LL.abi_version() < 1, reason="Landlock tidak tersedia di kernel/lingkungan ini (dibuktikan nyata oleh `make bench-selftest`)")


# ================================================================================ lapis 1: protokol
@pytest.fixture
def sp(tmp_path):
    s = SP.make_spool(tmp_path / "benchspool")
    s.ensure_dirs()
    return s


def beat(sp):
    sp.write_heartbeat("idle")


def test_job_ids_are_the_bench_pattern_and_cannot_be_runner_ids():
    from rvcore import spool as RS
    assert SP.JOB_ID_RE.match(SP.new_job_id(7))
    for bad in ("a1-apktool-deadbeef", "s1-DEADBEEFDEAD", "s1-deadbeefdea", "../s1-deadbeefdead", "s-deadbeefdead", "s1-deadbeefdead/x"):
        assert not SP.JOB_ID_RE.match(bad), bad
    assert not RS.JOB_ID_RE.match(SP.new_job_id(7)), "id bench tidak boleh dikenali spool runner"


def test_runner_spool_refuses_bench_ids_and_bench_spool_refuses_runner_ids(tmp_path):
    from rvcore.spool import Spool
    runner = Spool(tmp_path / "r")
    runner.ensure_dirs()
    with pytest.raises(ValueError):
        runner.submit({"job_id": SP.new_job_id(1)})
    bench = SP.make_spool(tmp_path / "b")
    bench.ensure_dirs()
    with pytest.raises(ValueError):
        bench.submit({"job_id": "a1-apktool-deadbeef"})


@pytest.mark.parametrize("command,sha", [("", None), ("   ", None), ("a\x00b", None), ("x" * (SP.MAX_COMMAND_CHARS + 1), None),
                                          ("id", "../etc/passwd"), ("id", "A" * 64), (["id"], None)],
                         ids=["kosong", "spasi", "NUL", "terlalu-panjang", "sha-traversal", "sha-huruf-besar", "bukan-teks"])
def test_build_run_request_rejects_bad_input(command, sha):
    with pytest.raises(ValueError):
        SP.build_run_request(1, command, 5, sha)


def test_build_run_request_carries_only_numbers_and_text():
    j = SP.build_run_request(7, "ls", 30, SHA)
    assert set(j) == {"job_id", "op", "analysis_id", "command", "timeout", "sha256", "created"} and j["analysis_id"] == 7 and j["sha256"] == SHA


@pytest.mark.parametrize("raw", [None, [], "teks", 5, {"status": "ok", "exit_code": "banyak"}, {"status": "<script>", "stdout": ["x"]},
                                 {"status": "ok", "stdout": 123, "exit_code": True}],
                         ids=["none", "list", "str", "int", "exit-str", "status-html", "exit-bool"])
def test_parse_result_never_raises_and_normalises_types(raw):
    r = SP.parse_result(raw)
    assert r["status"] in SP.STATUSES and isinstance(r["stdout"], str) and isinstance(r["stderr"], str)
    assert r["exit_code"] is None or (isinstance(r["exit_code"], int) and not isinstance(r["exit_code"], bool))


def test_parse_result_clamps_lengths_and_drops_unknown_fields():
    r = SP.parse_result({"status": "ok", "stdout": "A" * (SP.MAX_STREAM_CHARS * 3), "exit_code": 99999, "message": "m" * 5000, "kunci_aneh": "x", "signal": 9999})
    assert len(r["stdout"]) == SP.MAX_STREAM_CHARS and r["exit_code"] == 255 and len(r["message"]) == 600 and r["signal"] == 64 and "kunci_aneh" not in r


def test_read_result_refuses_oversized_symlinked_and_corrupt_files(sp, tmp_path):
    jid = SP.new_job_id(1)
    assert SP.read_result(sp, jid) is None
    path = sp.results / f"{jid}.json"
    path.write_text("x" * (SP.MAX_RESULT_BYTES + 1))
    assert SP.read_result(sp, jid)["status"] == "failed" and "terlalu besar" in SP.read_result(sp, jid)["message"]
    path.write_text("{rusak")
    assert SP.read_result(sp, jid)["status"] == "failed"
    secret = tmp_path / "rahasia.json"
    secret.write_text(json.dumps({"status": "ok", "stdout": "RAHASIA-WEB"}))
    path.unlink()
    os.symlink(secret, path)
    r = SP.read_result(sp, jid)
    assert r["status"] == "failed" and "RAHASIA-WEB" not in json.dumps(r), "web tidak boleh mengikuti symlink yang ditanam bench"


def test_run_command_fails_fast_when_bench_is_dead_and_leaves_nothing(sp):
    t = time.monotonic()
    with pytest.raises(SP.BenchUnavailable) as ei:
        SP.run_command(sp, 1, "ls", timeout=5)
    assert time.monotonic() - t < 1 and "tidak aktif" in ei.value.message and list(sp.requests.iterdir()) == []
    sp.heartbeat_file.write_text(json.dumps({"ts": time.time() - 500}))
    with pytest.raises(SP.BenchUnavailable):
        SP.run_command(sp, 1, "ls", timeout=5)


def fake_bench(sp, result, delay=0.0):
    """Bench palsu: ambil satu request, tunggu, tulis hasil."""
    def run():
        for _ in range(300):
            c = sp.claim_next()
            if c:
                time.sleep(delay)
                sp.finish(c[0], result)
                return
            time.sleep(0.02)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def test_run_command_roundtrip_and_cleanup(sp):
    beat(sp)
    t = fake_bench(sp, {"status": "ok", "exit_code": 0, "stdout": "halo", "duration_ms": 12})
    r = SP.run_command(sp, 3, "echo halo", timeout=5, sha256=SHA)
    t.join()
    assert r["status"] == "ok" and r["stdout"] == "halo" and r["exit_code"] == 0
    assert [p.name for d in (sp.requests, sp.running, sp.results, sp.cancel) for p in d.iterdir()] == []


def test_request_not_picked_up_is_withdrawn(sp):
    beat(sp)
    with pytest.raises(SP.BenchUnavailable) as ei:
        SP.run_command(sp, 1, "ls", timeout=5, pickup_timeout=0.3, poll=0.02)
    assert "sibuk" in ei.value.message and list(sp.requests.iterdir()) == []


def test_cancel_before_pickup_withdraws_and_reports_cancelled(sp):
    beat(sp)
    ev = threading.Event()
    ev.set()
    r = SP.run_command(sp, 1, "sleep 99", timeout=60, cancel=ev, poll=0.02)
    assert r["status"] == "cancelled" and list(sp.requests.iterdir()) == []


def test_cancel_while_running_asks_bench_to_cancel(sp):
    beat(sp)
    ev = threading.Event()
    seen = {}

    def bench():
        for _ in range(300):
            c = sp.claim_next()
            if c:
                for _ in range(200):
                    if sp.cancel_requested(c[0]):
                        seen["cancel"] = True
                        sp.finish(c[0], {"status": "cancelled"})
                        return
                    time.sleep(0.02)
                return
            time.sleep(0.02)
    threading.Thread(target=bench, daemon=True).start()
    threading.Timer(0.3, ev.set).start()
    r = SP.run_command(sp, 1, "sleep 99", timeout=60, cancel=ev, poll=0.02)
    assert r["status"] == "cancelled" and seen.get("cancel") is True


def test_bench_that_claims_then_never_answers_is_given_up(sp):
    beat(sp)

    def bench():
        for _ in range(300):
            if sp.claim_next():
                return                                  # mengklaim lalu diam
            time.sleep(0.02)
    threading.Thread(target=bench, daemon=True).start()
    t = time.monotonic()
    with pytest.raises(SP.BenchUnavailable) as ei:
        SP.run_command(sp, 1, "sleep 99", timeout=1, grace=0.3, poll=0.02)
    assert time.monotonic() - t < 10 and "tidak menjawab" in ei.value.message and list(sp.running.iterdir()) == []


def test_bench_dying_mid_command_is_detected(sp):
    beat(sp)

    def bench():
        for _ in range(300):
            if sp.claim_next():
                sp.heartbeat_file.write_text(json.dumps({"ts": time.time() - 500}))      # detak jantung berhenti
                return
            time.sleep(0.02)
    threading.Thread(target=bench, daemon=True).start()
    with pytest.raises(SP.BenchUnavailable) as ei:
        SP.run_command(sp, 1, "sleep 99", timeout=60, poll=0.02)
    assert "berhenti merespons" in ei.value.message


def test_oversized_result_written_by_a_hostile_bench_is_contained(sp):
    beat(sp)

    def bench():
        for _ in range(300):
            c = sp.claim_next()
            if c:
                (sp.results / f"{c[0]}.json").write_text("x" * (SP.MAX_RESULT_BYTES + 5))
                return
            time.sleep(0.02)
    threading.Thread(target=bench, daemon=True).start()
    assert SP.run_command(sp, 1, "ls", timeout=5, poll=0.02)["status"] == "failed"


def test_workspace_dir_is_built_from_an_integer_only():
    assert SP.workspace_dir("/data/bench", 5) == Path("/data/bench/5")
    assert SP.workspace_dir("/data/bench", "7") == Path("/data/bench/7")
    for bad in ("../x", "1/../2", "a", None):
        with pytest.raises((ValueError, TypeError)):
            SP.workspace_dir("/data/bench", bad)


# ================================================================================ lapis 2: kebijakan
DIRS = P.Dirs(Path("/data"))


def rules(aid=1, sha=SHA):
    return {r.path: r for r in P.rules_for(DIRS, aid, sha, Path("/tmp/job-x"))}


def test_policy_allows_only_the_visible_parts_of_this_analysis():
    r = rules()
    for ok in ("/data/work/1/apktool", "/data/work/1/jadx", "/data/work/1/logs", "/data/work/1/manifest.json", f"/data/uploads/{SHA}.apk"):
        assert ok in r and r[ok].rights == LL.RO, ok
    assert r["/data/bench/1"].rights == LL.RW and r["/tmp/job-x"].rights == LL.RW and not r["/data/bench/1"].optional


def test_policy_never_mentions_index_other_analyses_or_sensitive_roots():
    paths = list(rules())
    assert "index" not in "\n".join(paths), "work/<id>/index (rahasia mentah) tidak boleh punya aturan"
    for forbidden in ("/data/work/2", "/data/bench/2", "/data/db", "/data/files", "/data/spool", "/data/benchspool", f"/data/uploads/{OTHER}.apk"):
        assert not any(p == forbidden or p.startswith(forbidden + "/") for p in paths), forbidden
    for root in ("/data", "/data/work", "/data/uploads", "/data/bench", "/data/work/1"):
        assert root not in paths, f"{root} tidak boleh punya aturan (membuka daftar isinya)"


def test_policy_system_dirs_are_read_only_and_only_workspace_and_scratch_are_writable():
    r = rules()
    for p in P.SYSTEM_RO:
        assert r[p].rights == LL.RO and r[p].optional
    writable = sorted(p for p, x in r.items() if x.rights & LL.WRITE_FILE and p not in P.DEVICES)
    assert writable == ["/data/bench/1", "/tmp/job-x"]


def test_policy_ignores_a_bad_sha256_instead_of_building_a_path_from_it():
    for bad in ("../../etc/passwd", "A" * 64, "a" * 63, "", None, "a" * 64 + "/x"):
        assert not any("uploads" in p for p in rules(sha=bad)), bad
        assert "APK" not in P.env_for(DIRS, 1, bad, Path("/tmp/j"), "s1-x")


def test_policy_workspace_path_cannot_be_traversed():
    for bad in ("../x", "1/../2", "a", None):
        with pytest.raises((ValueError, TypeError)):
            P.workspace(DIRS, bad)
    assert P.workspace(DIRS, 12) == Path("/data/bench/12")


def test_policy_env_has_no_secrets_and_fixed_paths():
    e = P.env_for(DIRS, 1, SHA, Path("/tmp/j"), "s1-x")
    assert e["WS"] == "/data/bench/1" and e["WORK"] == "/data/work/1" and e["APK"] == f"/data/uploads/{SHA}.apk" and e["PATH"].startswith("/usr/local/bin")
    assert not [k for k in e if any(t in k for t in ("KEY", "SECRET", "TOKEN", "PASSWORD", "REDIS"))]


# ================================================================================ lapis 3 + 4: kernel nyata
@pytest.fixture
def box(tmp_path):
    """Data umpan: setiap yang seharusnya tertutup berisi UMPAN yang tidak boleh muncul di keluaran."""
    data = tmp_path / "data"
    for d in ("work/1/apktool", "work/1/jadx", "work/1/logs", "work/1/index", "work/2/apktool", "uploads", "bench/1", "bench/2", "db"):
        (data / d).mkdir(parents=True)
    (data / "work/1/apktool/AndroidManifest.xml").write_text("<manifest/>")
    (data / "work/1/jadx/A.java").write_text("class A {}")
    (data / "work/1/index/findings.jsonl").write_text(f'{{"secret": "{SECRET}"}}')
    (data / "work/2/apktool/x.txt").write_text("UMPAN-ANALISIS2")
    (data / "bench/2/c.txt").write_text("UMPAN-BENCH2")
    (data / "db/app.sqlite").write_text("UMPAN-DB")
    (data / "uploads" / f"{SHA}.apk").write_bytes(b"PK\x03\x04apk")
    (data / "uploads" / f"{OTHER}.apk").write_text("UMPAN-APKLAIN")
    return P.Dirs(data), data


def run(box, cmd, timeout=15, output_bytes=4096, **kw):
    dirs, _ = box
    limits = E.Limits(max_timeout=30, output_bytes=output_bytes, nproc=4096)
    return E.run_confined(dirs, limits, analysis_id=1, command=cmd, timeout=timeout, sha256=SHA, job_id="s1-test", **kw)


@needs_landlock
def test_own_analysis_is_readable_and_workspace_is_writable(box):
    r = run(box, "cat $WORK/apktool/AndroidManifest.xml && cat $WORK/jadx/A.java && echo halo > $WS/a.txt && cat $WS/a.txt && python3 -c 'print(6*7)'")
    assert r["status"] == "ok" and r["exit_code"] == 0 and "<manifest/>" in r["stdout"] and "halo" in r["stdout"] and "42" in r["stdout"], r


@needs_landlock
@pytest.mark.parametrize("cmd", [
    "cat $WORK/index/findings.jsonl", "ls $WORK/index", "cat $WORK/../2/apktool/x.txt", "cat /proc/self/root$WORK/index/findings.jsonl",
    "cat $WS/../2/c.txt", "ls $(dirname $WS)", "ls $(dirname $WORK)", "ls $(dirname $APK)",
    "cat $(dirname $WORK)/2/apktool/x.txt", "cat $(dirname $APK)/" + OTHER + ".apk", "cat $(dirname $(dirname $WORK))/db/app.sqlite",
    "echo x > $WORK/apktool/hack", "rm $WORK/apktool/AndroidManifest.xml", "mv $WORK/apktool/AndroidManifest.xml $WS/x", "ln $WORK/jadx/A.java $WS/t",
    "ln -s $WORK/index $WS/s && cat $WS/s/findings.jsonl", "echo x > $(dirname $WS)/2/hack",
], ids=lambda c: c[:48])
def test_everything_outside_the_whitelist_is_denied_and_nothing_leaks(box, cmd):
    r = run(box, cmd)
    assert r["status"] == "ok" and r["exit_code"] != 0, r
    assert SECRET not in r["stdout"] + r["stderr"] and "UMPAN" not in r["stdout"] + r["stderr"]
    _, data = box
    assert not (data / "work/1/apktool/hack").exists() and (data / "work/1/apktool/AndroidManifest.xml").exists() and not (data / "bench/2/hack").exists()


@needs_landlock
def test_a_command_that_exits_120_to_122_is_not_mistaken_for_a_confinement_failure(box):
    for code in (120, 121, 122):
        r = run(box, f"exit {code}")
        assert r["status"] == "ok" and r["exit_code"] == code, (code, r)


@needs_landlock
def test_confinement_failure_fails_closed_and_the_command_never_runs(box, tmp_path):
    """Landlock dimatikan di proses pembantu: perintah TIDAK boleh jalan (tidak ada jalur 'lanjut tanpa pengurungan')."""
    helper = tmp_path / "py_nolandlock.sh"
    helper.write_text(f"#!/bin/sh\nexec {sys.executable} -c \"import sys; sys.path.insert(0, '{ROOT}/services/bench'); sys.path.insert(0, '{ROOT}/services'); "
                      f"import bench.landlock as L; L.abi_version = lambda: 0; import bench.confined_exec as C; sys.exit(C.main(['x', sys.argv[-1]]))\" \"$@\"\n")
    helper.chmod(0o755)
    _, data = box
    r = run(box, "echo BOCOR > $WS/bocor.txt", python=str(helper))
    assert r["status"] == "refused" and "TIDAK dijalankan" in r["message"] and not (data / "bench/1/bocor.txt").exists(), r


def test_a_helper_that_exits_zero_without_the_marker_is_refused_not_ok(box, tmp_path):
    bad = tmp_path / "gagal.sh"
    bad.write_text("#!/bin/sh\nexit 0\n")
    bad.chmod(0o755)
    r = run(box, "echo halo", python=str(bad))
    assert r["status"] == "refused" and "TIDAK dijalankan" in r["message"], "exit 0 tanpa penanda terkurung tidak boleh dianggap berhasil"


def test_workspace_over_quota_is_refused_before_anything_runs(box):
    dirs, data = box
    (data / "bench/1/besar").write_bytes(b"x" * 200_000)
    r = E.run_confined(dirs, E.Limits(workspace_bytes=100_000), analysis_id=1, command="echo hai", timeout=5, sha256=SHA, job_id="s1-quota")
    assert r["status"] == "refused" and "kuota" in r["message"].lower()


def test_workspace_that_is_a_symlink_is_refused(box, tmp_path):
    dirs, data = box
    shutil.rmtree(data / "bench/1")
    outside = tmp_path / "luar"
    outside.mkdir()
    os.symlink(outside, data / "bench/1")
    r = E.run_confined(dirs, E.Limits(), analysis_id=1, command="echo hai > $WS/x", timeout=5, sha256=SHA, job_id="s1-sym")
    assert r["status"] == "refused" and not (outside / "x").exists()


@needs_landlock
def test_timeout_and_cancel_stop_the_command(box):
    t = time.monotonic()
    r = run(box, "sleep 30", timeout=1)
    assert r["status"] == "timeout" and time.monotonic() - t < 10
    flag = threading.Event()
    threading.Timer(0.5, flag.set).start()
    t = time.monotonic()
    r = run(box, "sleep 30", cancel=flag.is_set)
    assert r["status"] == "cancelled" and time.monotonic() - t < 10


@needs_landlock
def test_output_is_bounded_and_keeps_head_and_tail(box):
    r = run(box, "echo AWAL; head -c 2000000 /dev/zero | tr '\\0' A; echo AKHIR", output_bytes=2048)
    assert r["truncated"] and len(r["stdout"]) < 4000 and r["stdout"].startswith("AWAL") and r["stdout"].endswith("AKHIR\n") and "dihilangkan" in r["stdout"]


@needs_landlock
def test_orphans_and_setsid_survivors_are_killed_and_do_not_stall_the_result(box):
    E.enable_subreaper()
    t = time.monotonic()
    r = run(box, "(sleep 60 &); (setsid sleep 60 &); echo mulai")
    time.sleep(0.4)
    assert r["status"] == "ok" and r["stdout"] == "mulai\n" and time.monotonic() - t < 5, "pipa yang dipegang yatim tidak boleh menahan hasil"
    assert E._children_of(os.getpid()) == []


def test_capture_bounds_memory_and_counts_omitted():
    c = E.Capture(1000)
    for _ in range(50):
        c.feed(b"x" * 500)
    assert len(c.head) + len(c.tail) <= 1000 and c.omitted == 50 * 500 - 1000
    assert "dihilangkan" in c.text()


def test_handled_rights_follow_the_kernel_abi():
    for abi in (1, 2, 3, 4, 5, 6):
        assert LL.handled_fs(abi) & LL.FS_V1 == LL.FS_V1
    assert LL.handled_fs(0) == 0 and LL.handled_fs(1) & LL.REFER == 0 and LL.handled_fs(2) & LL.REFER and LL.handled_fs(3) & LL.TRUNCATE


def test_confinement_without_landlock_raises_instead_of_degrading(monkeypatch):
    monkeypatch.setattr(LL, "abi_version", lambda: 0)
    with pytest.raises(LL.LandlockError):
        LL.Confinement([LL.Rule("/tmp", LL.RO)])


@needs_landlock
def test_missing_required_rule_path_is_an_error_but_optional_is_skipped():
    with pytest.raises(LL.LandlockError):
        LL.Confinement([LL.Rule("/tidak/ada/sama/sekali", LL.RO)])
    LL.Confinement([LL.Rule("/tidak/ada/sama/sekali", LL.RO, optional=True), LL.Rule("/tmp", LL.RO)]).close()


# ================================================================================ tiap lapis pengurungan diuji SENDIRI-SENDIRI
# Pelajaran: bila dua lapis menjaga hal yang sama, mematikan salah satu tidak mengubah hasil akhir dan mutasi tunggal lolos. Maka tiap lapis dipaksa
# gagal sendirian (syscall disimulasikan), dan pemanggil HARUS menolak menjalankan perintah.
@needs_landlock
def test_failing_restrict_self_is_an_error_not_a_silent_success(monkeypatch):
    c = LL.Confinement([LL.Rule("/tmp", LL.RO)])
    real = LL._sys
    monkeypatch.setattr(LL, "_sys", lambda num, *a: -1 if num == LL.SYS_RESTRICT else real(num, *a))
    with pytest.raises(LL.LandlockError, match="restrict_self"):
        c.apply()
    monkeypatch.setattr(LL, "_sys", real)
    c.close()


@needs_landlock
def test_failing_no_new_privs_is_an_error_not_a_silent_success(monkeypatch):
    c = LL.Confinement([LL.Rule("/tmp", LL.RO)])

    class FakeLibc:
        def prctl(self, *a):
            return -1
    monkeypatch.setattr(LL, "_libc", FakeLibc())
    with pytest.raises(LL.LandlockError, match="NO_NEW_PRIVS"):
        c.apply()
    c.close()


@needs_landlock
def test_a_syscall_failure_when_adding_a_rule_is_an_error(monkeypatch):
    real = LL._sys
    monkeypatch.setattr(LL, "_sys", lambda num, *a: -1 if num == LL.SYS_ADD else real(num, *a))
    with pytest.raises(LL.LandlockError, match="menambah aturan"):
        LL.Confinement([LL.Rule("/tmp", LL.RO)])


def _helper_script(tmp_path, body: str):
    """Skrip python pembantu yang menjalankan confined_exec.main dengan sebagian fungsi dimatikan, untuk menguji lapis-lapisnya satu per satu."""
    h = tmp_path / "py_helper.sh"
    h.write_text(f"#!/bin/sh\nexec {sys.executable} -c \"import sys; sys.path.insert(0, '{ROOT}/services/bench'); sys.path.insert(0, '{ROOT}/services'); "
                 f"{body}; import bench.confined_exec as C; sys.exit(C.main(['x', sys.argv[-1]]))\" \"$@\"\n")
    h.chmod(0o755)
    return str(h)


@needs_landlock
def test_layer_1_alone_a_landlock_error_stops_the_command_even_if_the_canary_were_skipped(box, tmp_path):
    """Lapis 'LandlockError -> keluar' diuji SENDIRIAN: kenari dibuat selalu lulus, jadi hanya lapis ini yang bisa menolak."""
    h = _helper_script(tmp_path, "import bench.landlock as L; L.abi_version = lambda: 0; import os; os.listdir = lambda p: (_ for _ in ()).throw(PermissionError())")
    _, data = box
    r = run(box, "echo BOCOR > $WS/bocor.txt", python=h)
    assert r["status"] == "refused" and "pengurungan keamanan tidak bisa dipasang" in r["message"] and not (data / "bench/1/bocor.txt").exists(), r


@needs_landlock
def test_layer_2_alone_the_canary_stops_a_confinement_that_silently_did_nothing(box, tmp_path):
    """Lapis kenari diuji SENDIRIAN: pengurungan 'berhasil' tetapi tidak efektif (restrict_self dibuat no-op). Kenari terbaca -> perintah ditolak."""
    h = _helper_script(tmp_path, "import bench.landlock as L; L.Confinement.apply = lambda self: None")
    _, data = box
    r = run(box, "echo BOCOR > $WS/bocor.txt", python=h)
    assert r["status"] == "refused" and "tidak efektif" in r["message"] and not (data / "bench/1/bocor.txt").exists(), r


@needs_landlock
def test_the_marker_is_only_written_after_confinement_and_canary_pass(box, tmp_path):
    h = _helper_script(tmp_path, "import bench.landlock as L; L.Confinement.apply = lambda self: None")
    r = run(box, "echo halo", python=h)
    assert r["status"] == "refused" and r["stdout"] == "", "bash tidak boleh sempat berjalan: stdout harus kosong"


def test_cleanup_always_runs_the_orphan_sweep_and_removes_scratch(box, monkeypatch):
    """Penyapu akhir (reap_descendants) dan penghapusan scratch dipanggil di `finally`, juga saat perintah selesai normal."""
    calls = {"reap": 0, "rmtree": []}
    real_reap, real_rm = E.reap_descendants, shutil.rmtree
    monkeypatch.setattr(E, "reap_descendants", lambda *a, **k: (calls.__setitem__("reap", calls["reap"] + 1), real_reap(*a, **k))[1])
    monkeypatch.setattr(E.shutil, "rmtree", lambda p, *a, **k: (calls["rmtree"].append(str(p)), real_rm(p, *a, **k))[1])
    run(box, "true")
    assert calls["reap"] >= 2 and any("job-s1-test" in p for p in calls["rmtree"])
    assert not any(Path(p).exists() for p in calls["rmtree"] if "job-s1-test" in p)


def test_requested_timeout_is_capped_by_the_server_limit(box):
    dirs, _ = box
    seen = {}
    real = E.subprocess.Popen

    def spy(cmd, **kw):
        seen["spec"] = json.loads(cmd[-1])
        return real(cmd, **kw)
    E.subprocess.Popen = spy
    try:
        t = time.monotonic()
        r = E.run_confined(dirs, E.Limits(max_timeout=2), analysis_id=1, command="sleep 20", timeout=99999, sha256=SHA, job_id="s1-cap")
    finally:
        E.subprocess.Popen = real
    assert r["status"] in ("timeout", "refused") and time.monotonic() - t < 12 and seen["spec"]["cpu_seconds"] == 2 + 5


@needs_landlock
def test_an_inconclusive_canary_is_a_refusal_not_a_pass(box, tmp_path):
    """Kenari yang tidak bisa diperiksa (folder hilang / galat I/O) berarti pengurungan TIDAK terbukti: perintah ditolak, bukan dilewatkan."""
    h = _helper_script(tmp_path, "import os; _real = os.listdir; os.listdir = lambda p: (_ for _ in ()).throw(FileNotFoundError()) if 'bench' in str(p) else _real(p)")
    _, data = box
    r = run(box, "echo BOCOR > $WS/bocor.txt", python=h)
    assert r["status"] == "refused" and "tidak efektif" in r["message"] and not (data / "bench/1/bocor.txt").exists(), r


@needs_landlock
def test_a_command_that_leaves_children_in_its_own_group_has_them_killed_on_timeout(box):
    E.enable_subreaper()
    r = run(box, "sleep 300 & sleep 300 & wait", timeout=1)
    time.sleep(0.5)
    assert r["status"] == "timeout" and E._children_of(os.getpid()) == []
    left = []
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                cmd = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\x00")
            except OSError:
                continue
            if cmd[:2] == [b"sleep", b"300"]:
                left.append(int(pid))
    assert left == [], f"proses 'sleep 300' masih hidup: {left}"


def _run_with_hard_deadline(fn, seconds):
    """Jalankan `fn` di thread dan GAGAL CEPAT bila melewati `seconds`. Tes yang bisa menggantung (mutan tanpa SIGKILL) tidak boleh menahan CI."""
    box_ = {}
    t = threading.Thread(target=lambda: box_.update(r=fn()), daemon=True)
    t.start()
    t.join(seconds)
    return box_.get("r"), t.is_alive()


@needs_landlock
def test_a_command_that_ignores_sigterm_is_still_killed_at_timeout(box):
    """AI bisa menulis `trap '' TERM`. Tanpa SIGKILL, proses kebal itu hidup selamanya dan menahan hasil. Harus berakhir di dekat batas + masa tenggang."""
    E.enable_subreaper()
    t = time.monotonic()
    r, hung = _run_with_hard_deadline(
        lambda: run(box, "trap '' TERM; (trap '' TERM; while :; do sleep 1; done) & while :; do sleep 1; done", timeout=1), 12)
    assert not hung, "perintah yang mengabaikan SIGTERM menggantung: SIGKILL tidak dikirim"
    time.sleep(0.5)
    assert r["status"] == "timeout" and time.monotonic() - t < 12
    assert E._children_of(os.getpid()) == []


# ================================================================================ penyapu ruang kerja yatim (menghapus data: diuji ketat)
@pytest.fixture
def daemon(tmp_path, monkeypatch):
    """Muat bench-daemon (skrip tanpa .py) dengan DATA_DIR sementara."""
    import importlib.machinery
    import importlib.util
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("BENCH_SPOOL", str(tmp_path / "sp"))
    loader = importlib.machinery.SourceFileLoader("bench_daemon_under_test", str(ROOT / "services/bench/bench-daemon"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    (tmp_path / "bench").mkdir()
    (tmp_path / "work").mkdir()
    return mod, tmp_path


def make_ws(base, aid, age_hours=2.0, content="isi"):
    ws = base / "bench" / str(aid) / "salinan" / "res"
    ws.mkdir(parents=True)
    f = ws / "strings.xml"
    f.write_text(content)
    old = time.time() - age_hours * 3600
    for p in (f, ws, ws.parent, ws.parent.parent):
        os.utime(p, (old, old))
    return ws.parent.parent


def test_sweeper_removes_only_old_workspaces_whose_analysis_is_gone(daemon):
    mod, base = daemon
    (base / "work" / "other").mkdir()                       # work/ tidak kosong -> penyapu boleh bekerja
    gone_old = make_ws(base, 1, age_hours=5)
    gone_recent = make_ws(base, 2, age_hours=0.1)
    alive_old = make_ws(base, 3, age_hours=5)
    (base / "work" / "3").mkdir()
    assert mod.sweep_orphan_workspaces() == 1
    assert not gone_old.exists() and gone_recent.exists() and alive_old.exists()


def test_sweeper_uses_activity_deep_in_the_tree_not_the_root_folder_mtime(daemon):
    """Regresi (terbukti): mtime folder akar tidak berubah saat berkas di subfolder diedit; penyapu menghapus ruang kerja yang baru diedit pengguna."""
    mod, base = daemon
    (base / "work" / "x").mkdir()
    ws = make_ws(base, 7, age_hours=5)
    old = time.time() - 5 * 3600
    (ws / "salinan" / "res" / "strings.xml").write_text("diedit barusan")      # mtime BERKAS baru, folder-folder di atasnya tua
    for p in (ws, ws / "salinan", ws / "salinan" / "res"):
        os.utime(p, (old, old))
    assert time.time() - ws.stat().st_mtime > 4 * 3600, "prasyarat: mtime folder akar tua"
    assert mod.sweep_orphan_workspaces() == 0 and (ws / "salinan" / "res" / "strings.xml").read_text() == "diedit barusan"


def test_sweeper_keeps_a_workspace_that_a_command_just_touched(daemon):
    mod, base = daemon
    (base / "work" / "x").mkdir()
    ws = make_ws(base, 8, age_hours=5)
    E.touch_activity(ws)
    assert (ws / E.ACTIVITY_MARK).exists() and mod.sweep_orphan_workspaces() == 0 and ws.exists()


def test_sweeper_does_nothing_when_work_is_empty_or_missing(daemon):
    """Volume `work` belum terpasang / kosong BUKAN berarti semua analisis dihapus."""
    mod, base = daemon
    ws = make_ws(base, 9, age_hours=50)
    assert mod.sweep_orphan_workspaces() == 0 and ws.exists()          # work/ kosong
    shutil.rmtree(base / "work")
    assert mod.sweep_orphan_workspaces() == 0 and ws.exists()          # work/ hilang


def test_sweeper_ignores_non_numeric_names_and_symlinks(daemon, tmp_path_factory):
    mod, base = daemon
    (base / "work" / "x").mkdir()
    keep = base / "bench" / "catatan"
    keep.mkdir()
    os.utime(keep, (1, 1))
    outside = tmp_path_factory.mktemp("luar")
    (outside / "milik-orang-lain.txt").write_text("JANGAN DIHAPUS")
    os.symlink(outside, base / "bench" / "5")
    os.utime(outside / "milik-orang-lain.txt", (1, 1))                 # isi target juga TUA: bila symlink diikuti, target tampak yatim dan akan disapu
    os.utime(outside, (1, 1))
    os.utime(base / "bench" / "5", (1, 1), follow_symlinks=False)      # tautan itu sendiri terlihat TUA; kalau tidak, masa tenggang yang menyelamatkan, bukan cek symlink
    assert not (base / "work" / "5").exists(), "prasyarat: tidak ada analisis 5, jadi satu-satunya penahan adalah pemeriksaan symlink"
    assert mod.sweep_orphan_workspaces() == 0
    assert keep.exists() and (outside / "milik-orang-lain.txt").read_text() == "JANGAN DIHAPUS"
    assert os.path.islink(base / "bench" / "5"), "tautan itu sendiri juga tidak boleh disentuh (bukan milik penyapu)"


def test_sweeper_respects_the_grace_period_boundary(daemon):
    mod, base = daemon
    (base / "work" / "x").mkdir()
    ws = make_ws(base, 10, age_hours=0)
    newest = E.latest_activity(ws)
    assert mod.sweep_orphan_workspaces(now=newest + mod.ORPHAN_GRACE_SECONDS - 5) == 0 and ws.exists()
    assert mod.sweep_orphan_workspaces(now=newest + mod.ORPHAN_GRACE_SECONDS + 5) == 1 and not ws.exists()


def test_latest_activity_does_not_follow_symlinks(tmp_path):
    root = tmp_path / "ws"
    (root / "a").mkdir(parents=True)
    f = root / "a" / "f"
    f.write_text("x")
    outside = tmp_path / "luar"
    outside.mkdir()
    (outside / "baru").write_text("y")                          # target symlink berisi berkas BARU
    os.symlink(outside, root / "tautan")                        # membuat entri mengubah mtime folder induk: atur waktu SETELAH semuanya dibuat
    for p in (f, root / "a", root):
        os.utime(p, (1000, 1000))
    os.utime(root / "tautan", (1000, 1000), follow_symlinks=False)
    assert E.latest_activity(root) == 1000, "symlink tidak boleh diikuti (mtime target yang baru tidak boleh terhitung)"


def test_latest_activity_sees_a_new_file_buried_deep_in_the_tree(tmp_path):
    root = tmp_path / "ws"
    deep = root / "a" / "b" / "c"
    deep.mkdir(parents=True)
    for p in (deep, deep.parent, deep.parent.parent, root):
        os.utime(p, (1000, 1000))
    (deep / "baru.txt").write_text("x")
    os.utime(deep, (1000, 1000))
    assert E.latest_activity(root) > time.time() - 60


def test_latest_activity_treats_a_tree_too_big_to_scan_as_active(tmp_path, monkeypatch):
    """Pohon yang terlalu besar untuk diperiksa penuh TIDAK boleh dianggap 'lama' (itu berarti menghapus data yang tak sempat dinilai)."""
    root = tmp_path / "ws"
    root.mkdir()
    for i in range(12):
        (root / f"f{i}").write_text("x")
        os.utime(root / f"f{i}", (1000, 1000))
    os.utime(root, (1000, 1000))
    assert E.latest_activity(root) == 1000                                           # di bawah batas: nilai sebenarnya
    monkeypatch.setattr(E, "MAX_SCAN_ENTRIES", 5)
    assert E.latest_activity(root) > time.time() - 60, "melewati batas pemindaian harus dianggap aktif (waktu sekarang), bukan lama"


def test_every_command_marks_its_workspace_as_used_even_when_it_is_refused(box):
    """Penyapu mengandalkan penanda ini. Jika run_confined berhenti menyentuhnya, ruang kerja yang sedang dipakai tampak 'lama' dan bisa disapu."""
    dirs, data = box
    mark = data / "bench/1" / E.ACTIVITY_MARK
    assert not mark.exists()
    old = time.time() - 10 * 3600
    helper_refuses = "/bin/false"                                           # pembantu yang tidak pernah menulis penanda terkurung -> perintah ditolak
    r = E.run_confined(dirs, E.Limits(), analysis_id=1, command="true", timeout=5, sha256=SHA, job_id="s1-mark", python=helper_refuses)
    assert r["status"] == "refused" and mark.exists(), "penanda harus disentuh di AWAL perintah (sebelum bisa ditolak)"
    os.utime(mark, (old, old))
    E.run_confined(dirs, E.Limits(), analysis_id=1, command="true", timeout=5, sha256=SHA, job_id="s1-mark", python=helper_refuses)
    assert time.time() - mark.stat().st_mtime < 60


@needs_landlock
def test_a_successful_command_refreshes_the_marker_at_the_end_too(box):
    """Perintah panjang: penanda di AWAL sudah tua saat selesai. Hanya sentuhan di AKHIR yang membuat mtime-nya sama dengan waktu selesai."""
    dirs, data = box
    mark = data / "bench/1" / E.ACTIVITY_MARK
    t0 = time.time()
    r = run(box, "sleep 2.2")
    assert r["status"] == "ok"
    assert mark.stat().st_mtime >= t0 + 2.0, "penanda harus diperbarui di akhir perintah, bukan hanya di awal"
