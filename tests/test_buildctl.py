"""FEAT E: CLI pemilik `python -m app.buildctl` (analyze/init/shell/diff/request/approve/status/wait/cancel/artifact-info/delete).

Dipanggil sebagai fungsi (`buildctl.main(argv, deps=..., stdin=...)`) terhadap DB/layout konteks `conftest`, bench PALSU (tests/web_rig.py), dan `fakeredis`. Yang dibuktikan:
format keluaran `kunci=nilai` (tidak bisa dipalsukan nama berkas buatan AI), kode keluar 0/3/64, label persetujuan, `analyze -` (stdin, batas ukuran, `--uniq`, `--name`,
bundle), `delete` (analysis_id -> apk_id), dan A-14: CLI tidak pernah memanggil `ai.tools.shell_run` walau `AI_SHELL_ENABLED=0`.
Tidak dibuktikan di sini: `docker compose exec` nyata, stdin dari shell host, bench/RQ nyata.
"""

from __future__ import annotations

import ast
import inspect
import io
import json
import os
import re
import threading
import time
from contextlib import closing
import pytest
from build_rig import sha
from conftest import ROOT
from rvcore import shellspool, store
from test_bundle import apk_bytes, xapk
from web_rig import DIFF_SHA, FakeBench, ctx_analysis, ctx_build, dead_redis, diff_result, live_redis

KV = re.compile(r"^[a-z_0-9.]+=.*$")
BLOCK = re.compile(r"^[oel]\| ")


@pytest.fixture
def ctl_mod():
    from app import buildctl
    return buildctl


@pytest.fixture
def env(monkeypatch, ctl_mod):
    """Deps CLI atas konteks `conftest` + bench palsu + Redis palsu. `AI_SHELL_ENABLED=0` (bawaan compose) sepanjang tes."""
    import app.builds as wb
    from app import context
    monkeypatch.setenv("AI_SHELL_ENABLED", "0")
    monkeypatch.setattr(ctl_mod, "POLL", 0.02)
    bench = FakeBench(context.layout.root).__enter__()
    deps = wb.Deps(layout=context.layout, db=context.db, redis=live_redis(), bench_spool=shellspool.make_spool(context.layout.root / "benchspool"),
                   now=time.time, job_timeout=3300, op_pickup_timeout=3.0, poll=0.02)
    deps.bench = bench                                              # untuk tes
    yield deps
    bench.__exit__(None, None, None)


class Out:
    def __init__(self, code: int, text: str, err: str) -> None:
        self.code, self.text, self.err = code, text, err
        self.lines = text.splitlines()
        self.kv: dict[str, str] = {}
        for ln in self.lines:
            if KV.match(ln):
                k, v = ln.split("=", 1)
                self.kv[k] = v

    def __getitem__(self, key: str) -> str:
        return self.kv[key]

    def block(self, prefix: str) -> list[str]:
        return [ln[3:] for ln in self.lines if ln.startswith(prefix + "| ")]


@pytest.fixture
def ctl(capsys, env, ctl_mod):
    def run(*argv: str, stdin: bytes = b"", deps=None) -> Out:
        code = ctl_mod.main(list(argv), deps=deps or env, stdin=io.BytesIO(stdin))
        cap = capsys.readouterr()
        return Out(code, cap.out, cap.err)
    return run


def assert_wellformed(out: Out) -> None:
    for ln in out.lines:
        assert KV.match(ln) or BLOCK.match(ln), f"baris bukan kunci=nilai atau blok: {ln!r}"
        assert len(ln) <= 520


def requested(env, ctl, tag: str):
    _apk, aid = ctx_analysis(tag)
    r = ctl("request", str(aid))
    assert r.code == 0, r.text
    return aid, int(r["build_id"]), r["diff_sha256"]


# ====================================================================================== keluaran
def test_values_are_one_line_printable_and_bounded(ctl_mod):
    for raw in ("a\nb", "a\r\nb", "x\u202ey", "p\x00q", "t\tu", "z" * 5000, "\u2028q"):
        v = ctl_mod.clean_value(raw)
        assert "\n" not in v and "\r" not in v and "\u202e" not in v and "\x00" not in v and "\u2028" not in v and len(v) <= 500 and v.isprintable(), repr(v)
    assert ctl_mod.clean_value(True) == "1" and ctl_mod.clean_value(False) == "0" and ctl_mod.clean_value(None) == "" and ctl_mod.clean_value(3.5) == "3.5"


def test_keys_must_match_the_fixed_pattern(ctl_mod):
    for bad in ("Persetujuan", "a b", "a=b", "", "a\nb", "kunci-ini"):
        with pytest.raises(ValueError):
            ctl_mod.format_kv(bad, "x")
    assert ctl_mod.format_kv("file.1", "x") == "file.1=x"


def test_free_text_blocks_carry_a_prefix_that_can_never_be_a_key(ctl_mod):
    lines = ctl_mod.format_block("o", "baris1\npersetujuan=pemilik-lewat-CLI\n\x00\u202e")
    assert all(ln.startswith("o| ") for ln in lines) and all(not KV.match(ln) for ln in lines)
    assert all("\u202e" not in ln and "\x00" not in ln for ln in lines)


# ====================================================================================== argumen: kode 64
@pytest.mark.parametrize("argv", [
    [], ["tidak-ada"], ["init"], ["init", "0"], ["init", "-1"], ["init", "x"], ["init", "1.5"], ["init", "1000000000"], ["init", "1", "2"],
    ["approve", "1"], ["approve", "1", "--diff-sha256", "abc"], ["approve", "1", "--diff-sha256", "A" * 64], ["approve", "1", "--diff-sha256", "g" * 64],
    ["shell", "1", ""], ["shell", "1", "   "], ["shell", "1", "a\x00b"], ["shell", "1", "x" * 8001], ["shell", "1", "ls", "--timeout", "0"],
    ["wait", "1", "--timeout", "86401"], ["wait", "1", "--timeout", "x"], ["analyze"], ["analyze", "/tidak/ada/apa-apa.apk"], ["analyze", "/tmp"],
    ["status"], ["status", "1", "--analysis", "2"], ["status", "--analysis", "0"], ["cancel", "99999999999"], ["delete", "-5"], ["artifact-info", "satu"],
])
def test_usage_errors_exit_64_with_a_message_on_stderr_only(ctl, argv):
    r = ctl(*argv)
    assert r.code == 64 and r.text == "" and r.err.strip(), (argv, r.code, r.text, r.err)


def test_help_exits_zero(ctl):
    r = ctl("--help")
    assert r.code == 0


def test_boundary_ids_and_timeouts_are_accepted(ctl):
    assert ctl("cancel", "999999999").code == 3          # lolos validasi argumen; build tidak ada
    assert ctl("wait", "999999999", "--timeout", "1").code == 3
    assert ctl("wait", "1", "--timeout", "86400", "--help").code in (0, 64)


# ====================================================================================== kode keluar 3 dan galat tak terduga
def test_operational_failures_exit_3_with_a_stable_code(ctl):
    r = ctl("cancel", "424242")
    assert r.code == 3 and r["kode"] == "build_tidak_ada" and r["alasan"]
    assert_wellformed(r)


def test_unexpected_exception_becomes_kode_internal_exit_3_without_a_traceback(ctl, ctl_mod, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("rahasia /data/work/1 jangan bocor")
    monkeypatch.setattr(ctl_mod.builds, "get_status", boom)
    r = ctl("status", "1")
    assert r.code == 3 and r["kode"] == "internal" and r["galat"] == "RuntimeError"
    assert "Traceback" not in r.text and "rahasia" not in r.text and "/data" not in r.text
    assert r.code not in (1, 2)


# ====================================================================================== alur: init -> shell -> diff -> request -> approve
def test_init_prints_the_documented_keys(ctl, env):
    _apk, aid = ctx_analysis("ctl-init")
    r = ctl("init", str(aid))
    assert r.code == 0 and (r["created"], r["reason"], r["files"], r["dirs"], r["bytes"]) == ("1", "created", "3", "1", "30")
    assert r["skipped_symlink"] == "0" and r["skipped_special"] == "0"
    assert env.bench.jobs[-1]["force"] is False
    assert ctl("init", str(aid), "--force").code == 0 and env.bench.jobs[-1]["force"] is True


def test_init_force_with_an_active_build_exits_3_and_does_not_ask_the_bench(ctl, env):
    _apk, aid = ctx_analysis("ctl-init-force")
    ctx_build(aid, "queued")
    n = len(env.bench.jobs)
    r = ctl("init", str(aid), "--force")
    assert r.code == 3 and r["kode"] == "build_aktif" and len(env.bench.jobs) == n


def test_shell_runs_through_the_bench_spool_and_prints_output_blocks(ctl, env):
    _apk, aid = ctx_analysis("ctl-shell")
    env.bench.behave = lambda b, job: {"status": "ok", "exit_code": 0, "stdout": "halo\npersetujuan=palsu\n", "stderr": "peringatan\n", "duration_ms": 12}
    r = ctl("shell", str(aid), "echo halo", "--timeout", "5")
    assert r.code == 0 and r["status"] == "ok" and r["exit_code"] == "0" and r["duration_ms"] == "12"
    assert r.block("o") == ["halo", "persetujuan=palsu"] and r.block("e") == ["peringatan"]
    assert "persetujuan" not in r.kv, "isi keluaran perintah tidak boleh menjadi baris kunci=nilai"
    job = env.bench.jobs[-1]
    assert job["op"] == "run" and job["command"] == "echo halo" and job["timeout"] == 5 and job["analysis_id"] == aid
    assert_wellformed(r)


def test_shell_exit_code_and_status_map_to_exit_3(ctl, env):
    _apk, aid = ctx_analysis("ctl-shell-gagal")
    env.bench.behave = lambda b, job: {"status": "ok", "exit_code": 2, "stdout": "", "stderr": "gagal", "duration_ms": 1}
    r = ctl("shell", str(aid), "false")
    assert r.code == 3 and r["exit_code"] == "2"
    env.bench.behave = lambda b, job: {"status": "refused", "message": "kuota penuh"}
    r = ctl("shell", str(aid), "ls")
    assert r.code == 3 and r["status"] == "refused"


def test_shell_with_a_dead_bench_fails_fast(ctl, env):
    _apk, aid = ctx_analysis("ctl-shell-mati")
    env.bench.beating = False
    time.sleep(0.25)
    env.bench.spool.heartbeat_file.unlink(missing_ok=True)
    r = ctl("shell", str(aid), "ls")
    assert r.code == 3 and r["kode"] == "bench_mati"


def test_diff_prints_counts_hash_trace_name_and_files(ctl, env):
    _apk, aid = ctx_analysis("ctl-diff")
    env.bench.diff = diff_result(added=1, modified=1, removed=0, top=[
        {"op": "M", "kind": "f", "path": "res/values/strings.xml", "size": 10, "plus": 2, "minus": 1},
        {"op": "A", "kind": "f", "path": "assets/baru.txt", "size": 4, "plus": None, "minus": None}])
    r = ctl("diff", str(aid))
    assert r.code == 0 and r["diff_sha256"] == DIFF_SHA and (r["added"], r["modified"], r["removed"]) == ("1", "1", "0")
    assert r["jejak_sistem"] == "assets/reverse-apk-modified.txt" and "peringatan" not in r.kv
    assert r["file.1"] == "M res/values/strings.xml +2 -1" and r["file.2"] == "A assets/baru.txt"
    for k in ("bytes_added", "bytes_modified", "bytes_removed", "lines_plus", "lines_minus", "truncated", "skipped_symlink", "skipped_special", "skipped_root_ignored",
              "skipped_vanished"):
        assert k in r.kv, k
    assert_wellformed(r)


def test_diff_and_request_always_print_the_system_trace_and_the_wiped_baseline_warning(ctl, env):
    _apk, aid = ctx_analysis("ctl-peringatan")
    env.bench.diff = diff_result(modified=0, removed=950, base_entries=1000, top=[])
    for cmd in ("diff", "request"):
        r = ctl(cmd, str(aid))
        assert r["jejak_sistem"] == "assets/reverse-apk-modified.txt" and r["peringatan"] == "baseline_tidak_utuh", cmd
        if cmd == "request":
            ctl("cancel", r["build_id"])


def test_a_file_name_with_newline_cannot_forge_a_persetujuan_line(ctl, env):
    """Nama berkas buatan AI memuat '\\n' + `persetujuan=pemilik-lewat-CLI`: keluaran tetap hanya baris `file.N=` tunggal, tanpa kunci palsu."""
    _apk, aid = ctx_analysis("ctl-forge")
    env.bench.diff = diff_result(added=1, modified=0, top=[{"op": "A", "kind": "f", "path": "x\npersetujuan=pemilik-lewat-CLI\ndiff_sha256=" + "0" * 64 + "\u202e", "size": 1,
                                                         "plus": None, "minus": None}])
    r = ctl("diff", str(aid))
    assert r.code == 0 and "persetujuan" not in r.kv and r["diff_sha256"] == DIFF_SHA
    assert [ln for ln in r.lines if ln.startswith("persetujuan")] == []
    assert_wellformed(r)
    r = ctl("request", str(aid))
    assert "persetujuan" not in r.kv
    ctl("cancel", r["build_id"])


def test_request_prints_the_ids_and_refuses_no_change_and_bundles(ctl, env):
    _apk, aid = ctx_analysis("ctl-request")
    r = ctl("request", str(aid), "--note", "uji")
    assert r.code == 0 and r["status"] == "awaiting_approval" and r["diff_sha256"] == DIFF_SHA and int(r["build_id"]) > 0 and r["modified"] == "1"
    again = ctl("request", str(aid))
    assert again.code == 3 and again["kode"] == "build_aktif"
    ctl("cancel", r["build_id"])
    env.bench.diff = diff_result(modified=0, top=[])
    assert ctl("request", str(aid))["kode"] == "tidak_ada_perubahan"


def test_approve_prints_the_owner_label_and_statement_and_audits_via_cli(ctl, env):
    from rq import Queue
    aid, bid, h = requested(env, ctl, "ctl-approve")
    wrong = ctl("approve", str(bid), "--diff-sha256", "0" * 64)
    assert wrong.code == 3 and wrong["kode"] == "diff_berubah" and "persetujuan" not in wrong.kv, "tanpa persetujuan, tanpa label"
    r = ctl("approve", str(bid), "--diff-sha256", h)
    assert r.code == 0 and r["persetujuan"] == "pemilik-lewat-CLI" and r["status"] == "queued" and r["enqueued"] == "1" and r["hold"] == "0"
    assert r["pernyataan_versi"] == "1" and r["pernyataan_sha256"] == store.approval_statement_sha256() and r["build_id"] == str(bid)
    ids = Queue("jobs", connection=env.redis).job_ids
    assert any(i.startswith(f"build-{bid}-") for i in ids)
    from app import context
    with closing(context.db()) as conn:
        rows = [json.loads(x["detail"]) for x in conn.execute("SELECT detail FROM audit_log WHERE action = 'build_approved'")]
    assert [x for x in rows if x["build_id"] == bid][0]["via"] == "cli"
    assert_wellformed(r)


def test_approve_hold_prints_hold_and_does_not_enqueue(ctl, env):
    from rq import Queue
    aid, bid, h = requested(env, ctl, "ctl-hold")
    r = ctl("approve", str(bid), "--diff-sha256", h, "--hold")
    assert r.code == 0 and r["hold"] == "1" and r["enqueued"] == "0" and r["status"] == "queued" and r["persetujuan"] == "pemilik-lewat-CLI"
    assert not any(i.startswith(f"build-{bid}-") for i in Queue("jobs", connection=env.redis).job_ids)
    r = ctl("approve", str(bid), "--diff-sha256", h)
    assert r.code == 0 and r["enqueued"] == "1"


def test_approve_with_redis_down_exits_3_but_the_state_is_recorded(ctl, env):
    from app import context
    aid, bid, h = requested(env, ctl, "ctl-redis-mati")
    env.redis = dead_redis()
    r = ctl("approve", str(bid), "--diff-sha256", h)
    assert r.code == 3 and r["status"] == "queued" and r["enqueued"] == "0" and r["kode"] == "antrean_mati"
    with closing(context.db()) as conn:
        assert store.get_build(conn, bid)["status"] == "queued"
    env.redis = live_redis()
    assert ctl("approve", str(bid), "--diff-sha256", h).code == 0


def test_cancel_and_status_and_artifact_info(ctl, env):
    from app import context
    aid, bid, h = requested(env, ctl, "ctl-status")
    st = ctl("status", str(bid))
    assert st.code == 0 and st["status"] == "awaiting_approval" and h in st["alasan"] and st["analysis_id"] == str(aid) and st["build_id"] == str(bid)
    assert st["cancel_requested"] == "0" and st["diff_sha256"] == h
    assert_wellformed(st)
    assert ctl("artifact-info", str(bid)).code == 3 and ctl("artifact-info", str(bid))["kode"] == "belum_selesai"
    c = ctl("cancel", str(bid))
    assert c.code == 0 and c["hasil"] == "cancelled"
    again = ctl("cancel", str(bid))
    assert again.code == 3 and again["kode"] == "sudah_final"
    by_analysis = ctl("status", "--analysis", str(aid))
    assert by_analysis.code == 0 and by_analysis["builds"] == f"{bid}:cancelled" and by_analysis["build_dirs"] == ""
    # build selesai dengan artefak di disk: artifact-info mencocokkan hash disk dan DB
    _apk2, aid2 = ctx_analysis("ctl-artifact")
    bid2 = ctx_build(aid2, "signing")
    name = f"x-modified-{bid2}.apk"
    d = context.layout.builds / str(aid2) / str(bid2)
    d.mkdir(parents=True)
    (d / name).write_bytes(b"isi-apk")
    with closing(context.db()) as conn:
        store.finish_build(conn, bid2, output_name=name, output_sha256=sha(b"isi-apk"), output_size=7, output_format="apk", cert_sha256=sha(b"cert"), verify_ok=1,
                           stage_log="signing_mulai=%f" % time.time())
    ok = ctl("artifact-info", str(bid2))
    assert ok.code == 0 and ok["cocok"] == "1" and ok["disk_sha256"] == ok["output_sha256"] == sha(b"isi-apk") and ok["output_name"] == name and ok["output_size"] == "7"
    (d / name).write_bytes(b"diubah!")
    bad = ctl("artifact-info", str(bid2))
    assert bad.code == 3 and bad["kode"] == "hash_tidak_cocok" and bad["cocok"] == "0" and bad["disk_sha256"] == sha(b"diubah!")
    st = ctl("status", str(bid2))
    assert st["status"] == "done" and st["verify_ok"] == "1" and st["signing_mulai"] and "waktu_tanda_tangan" in st.kv and "waktu_antre" in st.kv
    assert_wellformed(st)


def test_status_prints_stage_log_as_a_free_text_block(ctl, env):
    from app import context
    _apk, aid = ctx_analysis("ctl-stage-log")
    bid = ctx_build(aid, "building")
    with closing(context.db()) as conn:
        store.mark_signing(conn, bid, stage_log="signing_mulai=1.5\nbuild: 3 dtk\npersetujuan=palsu")
    st = ctl("status", str(bid))
    assert any(x.startswith("signing_mulai=1.5") for x in st.block("l")) and "persetujuan" not in st.kv
    assert_wellformed(st)


# ====================================================================================== wait
def test_wait_returns_zero_on_done_and_traces_the_status_changes(ctl, env):
    from app import context
    _apk, aid = ctx_analysis("ctl-wait-ok")
    bid = ctx_build(aid, "queued")

    def advance():
        time.sleep(0.15)
        with closing(context.db()) as conn:
            assert store.claim_build(conn, bid)
        time.sleep(0.15)
        with closing(context.db()) as conn:
            store.mark_signing(conn, bid, stage_log="signing_mulai=%f" % time.time())
        time.sleep(0.15)
        d = context.layout.builds / str(aid) / str(bid)
        d.mkdir(parents=True)
        with closing(context.db()) as conn:
            store.finish_build(conn, bid, output_name=f"a-modified-{bid}.apk", output_sha256=sha(b"1"), output_size=1, output_format="apk", cert_sha256=sha(b"c"), verify_ok=1)
    th = threading.Thread(target=advance)
    th.start()
    r = ctl("wait", str(bid), "--timeout", "20", "--trace")
    th.join()
    assert r.code == 0 and r["status"] == "done" and float(r["elapsed"]) > 0.2
    trace = [r[k] for k in sorted((k for k in r.kv if k.startswith("trace.")), key=lambda k: int(k.split(".")[1]))]
    seq = [t.split("@")[0] for t in trace]
    assert seq[0] == "queued" and seq[-1] == "done" and "building" in seq and "signing" in seq, seq
    assert all(re.fullmatch(r"[a-z_]+@\d+(\.\d+)?", t) for t in trace)
    assert seq.index("building") < seq.index("signing") < seq.index("done")


def test_wait_without_trace_prints_no_trace_keys(ctl, env):
    _apk, aid = ctx_analysis("ctl-wait-notrace")
    bid = ctx_build(aid, "queued")
    from app import context
    with closing(context.db()) as conn:
        store.fail_build(conn, bid, error_code="build_failed", error_text="rusak")
    r = ctl("wait", str(bid), "--timeout", "5")
    assert r.code == 3 and r["status"] == "failed" and r["error_code"] == "build_failed" and not [k for k in r.kv if k.startswith("trace.")]


def test_wait_times_out_with_a_stable_code(ctl, env):
    _apk, aid = ctx_analysis("ctl-wait-timeout")
    bid = ctx_build(aid, "queued")
    t0 = time.monotonic()
    r = ctl("wait", str(bid), "--timeout", "1")
    assert r.code == 3 and r["kode"] == "waktu_habis" and r["status"] == "queued" and 0.9 <= time.monotonic() - t0 < 10


def test_wait_for_an_unknown_build_fails_without_waiting(ctl):
    t0 = time.monotonic()
    r = ctl("wait", "31337", "--timeout", "30")
    assert r.code == 3 and r["kode"] == "build_tidak_ada" and time.monotonic() - t0 < 5


# ====================================================================================== analyze
def part_files() -> list[str]:
    from app import context
    return sorted(p.name for p in context.layout.uploads_tmp.glob("*.part")) if context.layout.uploads_tmp.exists() else []


def finish_analysis_later(delay: float = 0.2, status: str = store.DONE):
    from app import context

    def go():
        time.sleep(delay)
        with closing(context.db()) as conn:
            for row in conn.execute("SELECT id FROM analysis WHERE status = ?", (store.QUEUED,)).fetchall():
                store.finish_analysis(conn, row["id"], status)
    th = threading.Thread(target=go)
    th.start()
    return th


def test_analyze_stdin_defaults_the_name_to_cli_sha8_and_records_options(ctl, env):
    from app import context
    data = apk_bytes("ctl-analyze-stdin")
    r = ctl("analyze", "-", "--no-wait", stdin=data)
    sha8 = sha(data)[:8]
    assert r.code == 0 and r["duplicate"] == "0" and r["sha256"] == sha(data) and r["status"] == "queued" and int(r["analysis_id"]) > 0
    with closing(context.db()) as conn:
        row = store.get_analysis(conn, int(r["analysis_id"]))
    assert row["filename_display"] == f"cli-{sha8}.apk" and json.loads(row["options"]) == {"deobf": False}
    assert part_files() == []
    assert context.layout.upload_path(sha(data)).read_bytes() == data
    from rq import Queue
    assert any(i.startswith(f"analysis-{r['analysis_id']}-") for i in Queue("jobs", connection=env.redis).job_ids)
    with closing(context.db()) as conn:
        det = [json.loads(x["detail"]) for x in conn.execute("SELECT detail FROM audit_log WHERE action = 'upload'")]
    assert [x for x in det if x["sha256"] == sha(data)][0]["ip"] == "cli"


def test_analyze_name_is_always_cleaned(ctl, env):
    from app import context
    r = ctl("analyze", "-", "--no-wait", "--name", "../../etc/x\u202e.apk", stdin=apk_bytes("ctl-analyze-name"))
    with closing(context.db()) as conn:
        name = store.get_analysis(conn, int(r["analysis_id"]))["filename_display"]
    assert "/" not in name and "\u202e" not in name and name.endswith(".apk") and name.startswith("x")


def test_analyze_bundle_records_options_and_request_refuses_it(ctl, env):
    """A-08 (M96): `options.bundle` terisi, jadi `request` menolak `paket_belum_didukung`."""
    from app import context
    r = ctl("analyze", "-", "--no-wait", "--name", "paket.xapk", stdin=xapk("ctl-analyze-xapk"))
    assert r.code == 0
    aid = int(r["analysis_id"])
    with closing(context.db()) as conn:
        opts = json.loads(store.get_analysis(conn, aid)["options"])
        store.set_stage(conn, aid, "apktool", store.OK)
        assert store.finish_analysis(conn, aid, store.DONE)
    assert opts["deobf"] is False and opts["bundle"]["format"] == "xapk"
    req = ctl("request", str(aid))
    assert req.code == 3 and req["kode"] == "paket_belum_didukung"


def test_analyze_waits_for_done_and_prints_elapsed(ctl, env):
    th = finish_analysis_later(0.3)
    r = ctl("analyze", "-", "--timeout", "20", stdin=apk_bytes("ctl-analyze-wait"))
    th.join()
    assert r.code == 0 and r["status"] == "done" and float(r["elapsed"]) >= 0.2
    assert_wellformed(r)


def test_analyze_exits_3_when_the_analysis_fails_or_times_out(ctl, env):
    th = finish_analysis_later(0.2, store.FAILED)
    r = ctl("analyze", "-", "--timeout", "20", stdin=apk_bytes("ctl-analyze-gagal"))
    th.join()
    assert r.code == 3 and r["status"] == "failed" and r["kode"] == "analisis_gagal"
    r = ctl("analyze", "-", "--timeout", "1", stdin=apk_bytes("ctl-analyze-habis"))
    assert r.code == 3 and r["kode"] == "waktu_habis" and r["status"] == "queued"


def test_analyze_duplicate_is_reported_and_not_enqueued_again(ctl, env):
    from rq import Queue
    data = apk_bytes("ctl-analyze-dup")
    first = ctl("analyze", "-", "--no-wait", stdin=data)
    n = len(Queue("jobs", connection=env.redis).job_ids)
    second = ctl("analyze", "-", "--no-wait", stdin=data)
    assert second.code == 0 and second["duplicate"] == "1" and second["analysis_id"] == first["analysis_id"] and second["apk_id"] == first["apk_id"]
    assert len(Queue("jobs", connection=env.redis).job_ids) == n and part_files() == []


def test_analyze_uniq_gives_a_fresh_sha256_every_run_and_still_validates(ctl, env):
    """D8: `--uniq` menambah satu entri acak sehingga sha256 unik tiap run (tidak dedup ke analisis nyata pemilik)."""
    data = apk_bytes("ctl-analyze-uniq")
    a = ctl("analyze", "-", "--uniq", "--no-wait", stdin=data)
    b = ctl("analyze", "-", "--uniq", "--no-wait", stdin=data)
    assert a.code == b.code == 0 and a["duplicate"] == b["duplicate"] == "0" and a["sha256"] != b["sha256"] != sha(data) and a["sha256"] != sha(data)
    from app import context
    import zipfile
    for r in (a, b):
        p = context.layout.upload_path(r["sha256"])
        assert sha(p.read_bytes()) == r["sha256"], "hash dihitung ulang atas berkas akhir"
        with zipfile.ZipFile(p) as zf:
            extra = [n for n in zf.namelist() if n.startswith("assets/uniq-")]
            assert len(extra) == 1 and re.fullmatch(r"assets/uniq-[0-9a-f]{16,}\.txt", extra[0])
    assert part_files() == []


def test_analyze_rejects_oversized_stdin_and_cleans_the_part_file(ctl, env, ctl_mod, monkeypatch):
    monkeypatch.setattr(ctl_mod, "CHUNK", 1000)
    monkeypatch.setattr(ctl_mod, "max_upload_bytes", lambda: 5000)
    big = apk_bytes("ctl-analyze-besar") + b"\0" * 20_000
    r = ctl("analyze", "-", "--no-wait", stdin=big)
    assert r.code == 3 and r["kode"] == "terlalu_besar" and part_files() == []
    from app import context
    assert not context.layout.upload_path(sha(big)).exists()


def test_analyze_stops_reading_at_the_limit_instead_of_slurping_everything(ctl, env, ctl_mod, monkeypatch):
    """M82: batas ukuran dijaga SAMBIL membaca (aliran dihentikan), bukan setelah seluruh stdin dibaca."""
    monkeypatch.setattr(ctl_mod, "CHUNK", 1000)
    monkeypatch.setattr(ctl_mod, "max_upload_bytes", lambda: 5000)
    pulled = []

    class Endless(io.RawIOBase):
        def readable(self):
            return True

        def readinto(self, b):
            pulled.append(len(b))
            b[:] = b"\0" * len(b)
            return len(b)
    code = ctl_mod.main(["analyze", "-", "--no-wait"], deps=env, stdin=io.BufferedReader(Endless(), buffer_size=1000))
    assert code == 3 and sum(pulled) < 50_000, sum(pulled)
    assert part_files() == []


def test_analyze_validation_failures_exit_3_with_the_apk_check_code_and_clean_up(ctl, env):
    r = ctl("analyze", "-", "--no-wait", stdin=b"bukan zip sama sekali")
    assert r.code == 3 and r["kode"] == "not_zip" and part_files() == []
    r = ctl("analyze", "-", "--no-wait", stdin=b"")
    assert r.code == 3 and r["kode"] == "empty"
    from app import context
    with closing(context.db()) as conn:
        rej = [json.loads(x["detail"]) for x in conn.execute("SELECT detail FROM audit_log WHERE action = 'upload_rejected'")]
    assert {"not_zip", "empty"} <= {x["code"] for x in rej} and all(x["ip"] == "cli" for x in rej if x["code"] in {"not_zip", "empty"})


def test_analyze_path_argument_reads_a_regular_file(ctl, env, tmp_path):
    p = tmp_path / "uji.apk"
    data = apk_bytes("ctl-analyze-path")
    p.write_bytes(data)
    r = ctl("analyze", str(p), "--no-wait")
    assert r.code == 0 and r["sha256"] == sha(data) and part_files() == []
    assert p.read_bytes() == data, "berkas sumber tidak disentuh"


def test_analyze_with_redis_down_marks_the_analysis_failed_and_exits_3(ctl, env):
    from app import context
    env.redis = dead_redis()
    r = ctl("analyze", "-", "--no-wait", stdin=apk_bytes("ctl-analyze-redis"))
    assert r.code == 3 and r["kode"] == "antrean_mati" and int(r["analysis_id"]) > 0
    with closing(context.db()) as conn:
        assert store.get_analysis(conn, int(r["analysis_id"]))["status"] == store.FAILED


def test_analyze_cleans_the_part_file_on_ctrl_c(ctl, env, ctl_mod):
    class Interrupted(io.RawIOBase):
        n = 0

        def readable(self):
            return True

        def readinto(self, b):
            Interrupted.n += 1
            if Interrupted.n > 2:
                raise KeyboardInterrupt
            b[:5] = b"PK\x03\x04\x00"
            return 5
    with pytest.raises(KeyboardInterrupt):
        ctl_mod.main(["analyze", "-", "--no-wait"], deps=env, stdin=io.BufferedReader(Interrupted(), buffer_size=5))
    assert part_files() == []


# ====================================================================================== delete
def test_delete_maps_the_analysis_id_to_its_apk_id_and_reports_leftovers(ctl, env):
    """M84: `delete <aid>` mencari apk_id dari analysis_id (bukan memakai aid sebagai apk_id)."""
    from app import context
    from rvcore.db import tx
    with closing(context.db()) as conn, tx(conn):                      # geser penomoran: analisis lebih banyak daripada apk
        dummy_apk, _a = store.create_apk_with_analysis(conn, sha256=sha(b"dummy-del"), md5="e" * 32, filename="d.apk", size=1, options={})
        for _ in range(3):
            store._insert_analysis(conn, dummy_apk, {}, False)
    apk_id, aid = ctx_analysis("ctl-delete")
    assert apk_id != aid
    with closing(context.db()) as conn:
        other = conn.execute("SELECT id FROM apk WHERE id = ?", (aid,)).fetchone()
    populate_dirs(aid)
    r = ctl("delete", str(aid))
    assert r.code == 0 and r["hasil"] == "deleted" and (r["builds_ada"], r["bench_ada"], r["work_ada"]) == ("0", "0", "0")
    with closing(context.db()) as conn:
        assert conn.execute("SELECT 1 FROM apk WHERE id = ?", (apk_id,)).fetchone() is None
        assert conn.execute("SELECT 1 FROM analysis WHERE id = ?", (aid,)).fetchone() is None
        if other is not None:
            assert conn.execute("SELECT 1 FROM apk WHERE id = ?", (aid,)).fetchone() is not None, "apk lain dengan id == aid tidak boleh ikut terhapus"
    assert_wellformed(r)


def populate_dirs(aid: int) -> None:
    from app import context
    for p in (context.layout.builds / str(aid) / "1", context.layout.bench / str(aid) / "project", context.layout.work_dir(aid) / "apktool"):
        p.mkdir(parents=True, exist_ok=True)
        (p / "f").write_text("x")


def test_delete_is_busy_with_an_active_build_and_removes_nothing(ctl, env):
    from app import context
    apk_id, aid = ctx_analysis("ctl-delete-busy")
    ctx_build(aid, "approved")
    populate_dirs(aid)
    r = ctl("delete", str(aid))
    assert r.code == 3 and r["hasil"] == "busy" and r["kode"] == "busy"
    assert (context.layout.builds / str(aid) / "1" / "f").exists() and (context.layout.bench / str(aid) / "project" / "f").exists()
    with closing(context.db()) as conn:
        assert store.get_analysis(conn, aid) is not None


def test_delete_unknown_analysis(ctl):
    r = ctl("delete", "909090")
    assert r.code == 3 and r["kode"] == "analisis_tidak_ada"


def test_delete_exits_3_when_a_directory_survives(ctl, env, monkeypatch):
    from app import routes_apk
    apk_id, aid = ctx_analysis("ctl-delete-sisa")
    populate_dirs(aid)
    monkeypatch.setattr(routes_apk, "rmtree_at", lambda *a, **k: (_ for _ in ()).throw(PermissionError("x")))
    r = ctl("delete", str(aid))
    assert r.code == 3 and r["hasil"] == "deleted" and r["builds_ada"] == "1" and r["bench_ada"] == "0" and r["work_ada"] == "0"


# ====================================================================================== A-14: tidak ada jalur ke ai.tools
def test_no_command_ever_reaches_ai_tools_shell_run_even_with_ai_shell_disabled(ctl, env, monkeypatch):
    """Jaminan tingkat PERILAKU (A-14, M81): `ai.tools.shell_run` diganti agar melempar; semua perintah dijalankan dengan AI_SHELL_ENABLED=0 -> tak pernah terpicu,
    `shell` tetap berhasil lewat `shellspool.run_command`."""
    from app.ai import tools
    calls = []

    def tripwire(*a, **k):
        calls.append((a, k))
        raise AssertionError("buildctl memanggil ai.tools.shell_run")
    monkeypatch.setattr(tools, "shell_run", tripwire)
    monkeypatch.setitem(tools.TOOLS, "shell_run", (tripwire, tools.TOOLS["shell_run"][1]))
    assert os.environ["AI_SHELL_ENABLED"] == "0"
    from app import context
    apk_id, aid = ctx_analysis("ctl-a14")
    results = [
        ctl("analyze", "-", "--no-wait", stdin=apk_bytes("ctl-a14-apk")),
        ctl("init", str(aid)),
        ctl("shell", str(aid), "echo a14"),
        ctl("diff", str(aid)),
        ctl("request", str(aid)),
    ]
    bid = int(results[-1]["build_id"])
    h = results[-1]["diff_sha256"]
    results += [ctl("status", str(bid)), ctl("approve", str(bid), "--diff-sha256", h, "--hold"), ctl("cancel", str(bid)), ctl("wait", str(bid), "--timeout", "2"),
                ctl("artifact-info", str(bid)), ctl("status", "--analysis", str(aid)), ctl("delete", str(aid))]
    assert all(r.code in (0, 3) for r in results), [(r.code, r.text) for r in results]
    assert results[2].code == 0 and results[2]["status"] == "ok", "shell berjalan walau AI_SHELL_ENABLED=0"
    assert calls == []
    assert context.settings is not None


def test_buildctl_and_builds_do_not_import_ai_tools_directly():
    for name in ("buildctl.py", "builds.py"):
        tree = ast.parse((ROOT / "services" / "web" / "app" / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert not (mod.endswith("ai.tools") or mod.endswith(".ai") or mod == "ai" or (mod.startswith("ai.") or mod.startswith("app.ai"))), (name, ast.unparse(node))
                assert not any(a.name == "tools" for a in node.names if "ai" in mod.split(".")), (name, ast.unparse(node))
            elif isinstance(node, ast.Import):
                assert not any("ai.tools" in a.name or a.name.endswith(".ai") for a in node.names), (name, ast.unparse(node))


def test_buildctl_does_not_use_string_path_mutation_of_builds():
    """Tanpa safe_rmtree/shutil.rmtree/Layout.build_dir(s); mutasi path (mkdir/rmdir/rename/unlink) tidak boleh menyentuh `builds` (hapus lewat routes_apk._delete)."""
    tree = ast.parse((ROOT / "services" / "web" / "app" / "buildctl.py").read_text(encoding="utf-8"))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {"safe_rmtree", "rmtree", "build_dir", "builds_dir", "rmtree_at"}, names
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"mkdir", "makedirs", "rmdir", "rename", "replace", "unlink"}:
            assert "builds" not in ast.unparse(node), ast.unparse(node)


def test_private_routes_apk_helpers_used_by_the_cli_keep_their_names_and_shape():
    """buildctl memakai `_store_upload`, `_limits`, `_delete`, `_reject_audit`, `_mark_enqueue_failed` dari routes_apk: nama/parameter berubah = tes ini gagal."""
    from app import routes_apk
    sig = lambda f: list(inspect.signature(getattr(routes_apk, f)).parameters)  # noqa: E731
    assert sig("_store_upload") == ["received", "name", "options", "ip"]
    assert sig("_limits") == []
    assert sig("_delete") == ["apk_id", "ip"]
    assert sig("_reject_audit") == ["code", "name", "ip", "sha256"]
    assert sig("_mark_enqueue_failed") == ["analysis_id"]


def test_module_docstring_documents_the_accepted_transitive_import():
    """A-14: impor transitif `ai.tools` (lewat routes_apk/app.context) DITERIMA dan didokumentasikan; jaminannya adalah perilaku."""
    src = (ROOT / "services" / "web" / "app" / "buildctl.py").read_text(encoding="utf-8")
    doc = ast.get_docstring(ast.parse(src)) or ""
    assert "ai.tools" in doc and "transitif" in doc.lower() and "AI_SHELL_ENABLED" in doc


def test_module_runs_as_python_dash_m_entry_point():
    src = (ROOT / "services" / "web" / "app" / "buildctl.py").read_text(encoding="utf-8")
    assert 'if __name__ == "__main__"' in src and "sys.exit(main())" in src
