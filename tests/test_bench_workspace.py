"""Op bench `init` dan `diff` (Tahap 2b, FEAT B): protokol shellspool, logika ruang kerja, validasi daemon, uid 10001, bind `ro`, dan daemon NYATA.

Lapisan diuji terpisah supaya mutasi pada satu lapis tidak tertutup lapis lain:
  1. shellspool  : pembangun permintaan (id int murni, force bool), parser hasil (bench TIDAK TEPERCAYA), klien `run_op`, pembacaan hasil yang tahan FIFO/symlink
  2. workspace   : `init` tidak menimpa, `force`, kuota, statvfs, symlink umpan, pembatalan/tenggat; `diff` kanonik
  3. daemon      : validasi di sisi PENERIMA (id, force, op tak dikenal, bidang jalur diabaikan)
  4. uid 10001   : berkas milik root/uid lain, mode 600, induk tak bisa ditulis, bind `ro` + tmpfs `noexec` (bukan skenario pemilik-sama)
  5. daemon nyata: proses `bench-daemon` sebagai uid 10001 dengan Landlock nyata (dilewati bersih bila tak tersedia)
  6. statis      : Dockerfile/compose bench tanpa `builds`, tidak ada pemanggil `init` di kode tool AI
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SERVICES = ROOT / "services"
sys.path.insert(0, str(SERVICES / "bench"))

from bench import executor as E  # noqa: E402
from bench import landlock as LL  # noqa: E402
from bench import policy as P  # noqa: E402
from bench import workspace as W  # noqa: E402
from rvcore import shellspool as SP  # noqa: E402
from rvcore import treediff as T  # noqa: E402
from rvcore.paths import MAX_PROTO_ID  # noqa: E402

BASE_FILES = {
    "AndroidManifest.xml": "<manifest/>\n",
    "apktool.yml": "version: 3.0.3\n",
    "res/values/strings.xml": '<resources><string name="app_name">Contoh</string></resources>\n',
    "res/values-v21/styles.xml": "<resources/>\n",
    "smali/com/x/A.smali": ".class public Lcom/x/A;\n",
    "assets/data.bin": b"\x00\x01\x02\x03",
}
needs_landlock = pytest.mark.skipif(LL.abi_version() < 1, reason="Landlock tidak tersedia di kernel/lingkungan ini")


@contextmanager
def within(seconds: int):
    """Gagal (bukan menggantung) bila blok lebih lama dari `seconds`: open() FIFO tanpa O_NONBLOCK menunggu selamanya."""
    def _boom(_sig, _frame):
        raise TimeoutError(f"menggantung lebih dari {seconds} dtk")
    old = signal.signal(signal.SIGALRM, _boom)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def put(root: Path, rel: str, data: bytes | str = b"", mode: int = 0o644) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data.encode() if isinstance(data, str) else data)
    os.chmod(p, mode)
    return p


def mkbase(data: Path, aid: int = 1) -> Path:
    base = data / "work" / str(aid) / "apktool"
    for rel, content in BASE_FILES.items():
        put(base, rel, content)
    return base


@pytest.fixture
def box(tmp_path):
    data = tmp_path / "data"
    (data / "bench").mkdir(parents=True)
    mkbase(data)
    return P.Dirs(data), data


QUOTA = 64 * 1024 * 1024


def init(dirs, aid=1, force=False, quota=QUOTA, **kw):
    kw.setdefault("timeout", 60)
    return W.op_init(dirs, quota, aid, force, **kw)


def diff(dirs, aid=1, **kw):
    kw.setdefault("timeout", 60)
    return W.op_diff(dirs, aid, **kw)


def ws_of(data: Path, aid: int = 1) -> Path:
    return data / "bench" / str(aid)


def dump(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}


# ================================================================================ 1. shellspool
@pytest.fixture
def sp(tmp_path):
    s = SP.make_spool(tmp_path / "benchspool")
    s.ensure_dirs()
    s.write_heartbeat("idle")
    return s


@pytest.mark.parametrize("aid", ["5", True, False, 0, -1, 10**9, 2**31, 5.0, None, b"5", "../x"],
                         ids=["str", "True", "False", "nol", "negatif", "1e9", "2^31", "float", "none", "bytes", "traversal"])
def test_builders_accept_only_a_plain_int_in_range(aid):
    with pytest.raises(ValueError):
        SP.build_init_request(aid)
    with pytest.raises(ValueError):
        SP.build_diff_request(aid)


def test_builders_accept_the_whole_valid_range_and_make_valid_job_ids():
    for aid in (1, 7, MAX_PROTO_ID):
        for job in (SP.build_init_request(aid), SP.build_diff_request(aid)):
            assert SP.JOB_ID_RE.match(job["job_id"]) and job["analysis_id"] == aid


@pytest.mark.parametrize("force", ["true", 1, 0, None, "", [True]], ids=["str", "1", "0", "none", "kosong", "list"])
def test_init_request_force_must_be_a_real_bool(force):
    with pytest.raises(ValueError):
        SP.build_init_request(1, force)


def test_requests_carry_only_numbers_and_bools_and_clamp_the_timeout():
    j = SP.build_init_request(7, True, timeout=10**6)
    assert set(j) == {"job_id", "op", "analysis_id", "force", "timeout", "created"} and j["op"] == "init" and j["force"] is True and j["timeout"] == SP.OP_MAX_TIMEOUT
    d = SP.build_diff_request(7, timeout=30)
    assert set(d) == {"job_id", "op", "analysis_id", "timeout", "created"} and d["op"] == "diff" and d["timeout"] == 30
    for bad in (0, -5, "30", True, 1.5):
        with pytest.raises(ValueError):
            SP.build_diff_request(7, timeout=bad)
    assert json.dumps(j)                                        # bisa diserialisasi


GOOD_SHA = "a" * 64


@pytest.mark.parametrize("raw", [None, [], "teks", 5, {"status": ["ok"]}, {"status": {"a": 1}}, {"status": "<script>"}, {"created": "true", "reason": ["x"]},
                                 {"status": "ok", "files": "banyak", "dirs": -5, "bytes": 10**30, "skipped": "x"}],
                         ids=["none", "list", "str", "int", "status-list", "status-dict", "status-html", "tipe-salah", "angka-salah"])
def test_parse_init_result_never_raises_and_normalises_types(raw):
    r = SP.parse_init_result(raw)
    assert set(r) == {"status", "created", "reason", "code", "files", "dirs", "bytes", "skipped", "message"}
    assert r["status"] in SP.STATUSES and isinstance(r["created"], bool) and r["created"] is False
    assert r["reason"] in ("", "created", "exists", "reset")
    assert all(isinstance(r[k], int) and 0 <= r[k] <= SP.COUNT_MAX for k in ("files", "dirs", "bytes"))
    assert set(r["skipped"]) == {"symlink", "special", "root_ignored", "vanished"} and all(type(v) is int and v >= 0 for v in r["skipped"].values())


def test_parse_init_result_keeps_valid_fields_drops_unknown_and_cleans_text():
    r = SP.parse_init_result({"status": "ok", "created": True, "reason": "reset", "code": "kuota", "files": 3, "dirs": 2, "bytes": 99, "kunci_aneh": "x",
                              "skipped": {"symlink": 1, "special": 2, "root_ignored": 3, "vanished": 4, "lain": 9}, "message": "baris1\nbaris2\u202e" + "m" * 700})
    assert (r["status"], r["created"], r["reason"], r["code"], r["files"]) == ("ok", True, "reset", "kuota", 3) and "kunci_aneh" not in r
    assert r["skipped"] == {"symlink": 1, "special": 2, "root_ignored": 3, "vanished": 4}
    assert "\n" not in r["message"] and "\u202e" not in r["message"] and len(r["message"]) == 600
    assert SP.parse_init_result({"status": "ok", "code": "Bad Code!"})["code"] == ""


def good_diff(**over):
    d = {"status": "ok", "diff_sha256": GOOD_SHA, "counts": {"added": 1, "modified": 2, "removed": 3}, "entries_total": 6, "base_entries": 10,
         "bytes": {"added": 1, "modified": 2, "removed": 3}, "kinds": {"smali": 1, "res": 2, "manifest": 0, "aset": 0, "lib": 0, "lain": 3},
         "lines": {"plus": 5, "minus": 4, "files": 2, "skipped_files": 1}, "skipped": {"symlink": 0, "special": 0, "root_ignored": 1, "vanished": 0},
         "top": [{"op": "M", "kind": "f", "path": "res/values/strings.xml", "size": 80, "plus": 1, "minus": 1}], "truncated": False, "message": ""}
    d.update(over)
    return d


def test_parse_diff_result_roundtrips_a_good_result():
    r = SP.parse_diff_result(good_diff())
    assert r["status"] == "ok" and r["diff_sha256"] == GOOD_SHA and r["counts"] == {"added": 1, "modified": 2, "removed": 3}
    assert r["top"] == [{"op": "M", "kind": "f", "path": "res/values/strings.xml", "size": 80, "plus": 1, "minus": 1}] and r["lines"]["skipped_files"] == 1


@pytest.mark.parametrize("sha", ["", "zz" * 32, "A" * 64, "a" * 63, "a" * 65, None, 5, ["a" * 64], "a" * 64 + "\n"],
                         ids=["kosong", "bukan-hex", "huruf-besar", "63", "65", "none", "int", "list", "newline"])
def test_parse_diff_result_ok_without_a_valid_hash_becomes_failed(sha):
    r = SP.parse_diff_result(good_diff(diff_sha256=sha))
    assert r["status"] == "failed" and r["diff_sha256"] == ""


@pytest.mark.parametrize("raw", [None, [], "x", 3, {"status": ["ok"]}, {"status": "ok", "counts": 5, "top": "bukan-list", "kinds": [], "bytes": None}],
                         ids=["none", "list", "str", "int", "status-list", "tipe-salah"])
def test_parse_diff_result_never_raises(raw):
    r = SP.parse_diff_result(raw)
    assert r["status"] in SP.STATUSES and r["top"] == [] and r["diff_sha256"] == "" and r["status"] != "ok"
    assert r["counts"] == {"added": 0, "modified": 0, "removed": 0}


def test_parse_diff_result_cleans_top_paths_caps_the_list_and_drops_bad_items():
    evil = "res/\nSTATUS=ok\u202egpj.exe\x00\udcff" + "p" * 400
    top = [{"op": "A", "kind": "f", "path": evil, "size": 10**30, "plus": "x", "minus": True}] + [{"op": "Z", "kind": "f", "path": "x"}, "bukan-dict", {"op": "M", "kind": "q"}]
    top += [{"op": "R", "kind": "d", "path": f"d{i}", "size": 0} for i in range(100)]
    r = SP.parse_diff_result(good_diff(top=top))
    assert len(r["top"]) <= SP.TOP_MAX
    first = r["top"][0]
    assert first["path"].isprintable() and "\n" not in first["path"] and "\u202e" not in first["path"] and len(first["path"]) <= SP.TOP_PATH_MAX
    assert first["size"] == SP.COUNT_MAX and first["plus"] is None and first["minus"] is None
    assert all(t["op"] in "AMR" and t["kind"] in "fd" for t in r["top"])


def test_parse_result_survives_an_unhashable_status():
    """Regresi: `{"status": []}` dari bench dulu memicu TypeError (list tak bisa dicari di frozenset) di jalur yang dijanjikan 'tidak pernah melempar'."""
    for bad in ([], {}, [1], {"a": 1}):
        assert SP.parse_result({"status": bad})["status"] == "failed"


def fake_bench(sp, result, delay=0.0):
    def run():
        for _ in range(300):
            c = sp.claim_next()
            if c:
                run.job = c[1]
                time.sleep(delay)
                sp.finish(c[0], result)
                return
            time.sleep(0.02)
    run.job = None
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.run_fn = run
    return t


def test_run_op_roundtrip_normalises_with_the_matching_parser_and_cleans_up(sp):
    t = fake_bench(sp, {"status": "ok", "created": True, "reason": "created", "files": 4, "kunci_aneh": "x", "stdout": "tidak dipakai"})
    r = SP.run_op(sp, SP.build_init_request(3), SP.parse_init_result)
    t.join()
    assert r["status"] == "ok" and r["created"] is True and r["files"] == 4 and "kunci_aneh" not in r and "stdout" not in r
    assert t.run_fn.job["op"] == "init" and t.run_fn.job["analysis_id"] == 3
    assert [p.name for d in (sp.requests, sp.running, sp.results, sp.cancel) for p in d.iterdir()] == []
    t = fake_bench(sp, good_diff())
    r = SP.run_op(sp, SP.build_diff_request(3), SP.parse_diff_result)
    t.join()
    assert r["diff_sha256"] == GOOD_SHA and t.run_fn.job["op"] == "diff"


def test_run_op_turns_a_hostile_ok_without_hash_into_failed(sp):
    t = fake_bench(sp, {"status": "ok", "diff_sha256": "../../etc/passwd"})
    assert SP.run_op(sp, SP.build_diff_request(3), SP.parse_diff_result)["status"] == "failed"
    t.join()


def test_run_op_refuses_other_ops_and_fails_fast_when_bench_is_dead(tmp_path):
    s = SP.make_spool(tmp_path / "dead")
    s.ensure_dirs()
    with pytest.raises(ValueError):
        SP.run_op(s, SP.build_run_request(1, "ls", 5, None), SP.parse_result)
    t0 = time.monotonic()
    with pytest.raises(SP.BenchUnavailable):
        SP.run_op(s, SP.build_diff_request(1), SP.parse_diff_result)
    assert time.monotonic() - t0 < 1 and list(s.requests.iterdir()) == []


def test_run_op_withdraws_an_unclaimed_request_and_cancel_before_pickup_reports_cancelled(sp):
    with pytest.raises(SP.BenchUnavailable):
        SP.run_op(sp, SP.build_diff_request(1), SP.parse_diff_result, pickup_timeout=0.3, poll=0.02)
    assert list(sp.requests.iterdir()) == []
    ev = threading.Event()
    ev.set()
    r = SP.run_op(sp, SP.build_init_request(1), SP.parse_init_result, cancel=ev, poll=0.02)
    assert r["status"] == "cancelled" and r["created"] is False and list(sp.requests.iterdir()) == []


def test_run_op_default_pickup_is_longer_than_a_shell_command_wait():
    assert SP.OP_PICKUP_TIMEOUT >= 120 and SP.OP_MAX_TIMEOUT == 600


@pytest.mark.parametrize("parser", [SP.parse_result, SP.parse_init_result, SP.parse_diff_result], ids=["run", "init", "diff"])
def test_read_result_never_hangs_on_fifo_or_symlink_to_a_device_and_rejects_oversize(sp, tmp_path, parser):
    """A-13: bench yang terkompromi menanam FIFO / symlink→/dev/zero di results/. Web tidak boleh menggantung atau mengikuti symlink."""
    jid = SP.new_job_id(1)
    path = sp.results / f"{jid}.json"
    os.mkfifo(path)
    with within(5):
        r = SP.read_result(sp, jid, parser)
    assert r["status"] == "failed"
    path.unlink()
    os.symlink("/dev/zero", path)
    with within(5):
        r = SP.read_result(sp, jid, parser)
    assert r["status"] == "failed"
    path.unlink()
    secret = tmp_path / "rahasia.json"
    secret.write_text(json.dumps(good_diff(message="RAHASIA-WEB")))
    os.symlink(secret, path)
    assert "RAHASIA-WEB" not in json.dumps(SP.read_result(sp, jid, parser))
    path.unlink()
    path.write_text("x" * (SP.MAX_RESULT_BYTES + 1))
    assert SP.read_result(sp, jid, parser)["status"] == "failed"
    path.write_text("[" * 100_000)                                # JSON terlalu dalam -> RecursionError di json, bukan galat tak tertangkap
    assert SP.read_result(sp, jid, parser)["status"] == "failed"


# ================================================================================ 2. logika ruang kerja
def test_init_copies_the_baseline_into_ws_project_and_marks_activity(box):
    dirs, data = box
    r = init(dirs)
    assert r["status"] == "ok" and r["created"] is True and r["reason"] == "created" and r["files"] == len(BASE_FILES)
    proj = ws_of(data) / "project"
    assert dump(proj) == dump(data / "work/1/apktool") and stat.S_IMODE(proj.stat().st_mode) == 0o755
    assert (ws_of(data) / ".last-used").exists(), "penanda aktivitas seperti penyapu yatim"
    assert not (ws_of(data) / ".project.tmp").exists()
    assert stat.S_IMODE(ws_of(data).stat().st_mode) == 0o700


def test_init_copies_with_copy_tree_safe_semantics_symlink_fifo_and_build_dirs_are_dropped(box):
    """Baseline dari APK tak tepercaya bisa memuat symlink/FIFO/`build/`: salinan tidak mengikuti symlink, tidak menggantung pada FIFO, dan membuang cache `build/`."""
    dirs, data = box
    base = data / "work/1/apktool"
    outside = data / "luar.txt"
    outside.write_text("RAHASIA-LUAR")
    os.symlink(outside, base / "res/tautan.txt")
    os.symlink(data, base / "smali/loop")
    os.mkfifo(base / "assets/pipa")
    put(base, "build/apk/classes.dex", "DEX-LAMA")
    put(base, "dist/lama.apk", "x")
    with within(10):
        r = init(dirs)
    assert r["status"] == "ok" and r["files"] == len(BASE_FILES)
    assert r["skipped"] == {"symlink": 2, "special": 1, "root_ignored": 2, "vanished": 0}
    proj = ws_of(data) / "project"
    assert dump(proj) == {k: v for k, v in dump(base).items() if not k.startswith(("build/", "dist/"))}
    assert not any(p.is_symlink() for p in proj.rglob("*")) and not (proj / "build").exists() and "RAHASIA-LUAR" not in json.dumps(sorted(dump(proj)))
    assert diff(dirs)["counts"] == {"added": 0, "modified": 0, "removed": 0}, "baseline dengan entri khusus tetap menghasilkan diff kosong terhadap salinannya"


def test_every_op_refreshes_the_last_used_marker_even_when_it_changes_nothing(box):
    """Penyapu yatim memakai `.last-used`: op yang tidak menyalin (exists/refused/diff) tetap menandai ruang kerja sebagai dipakai."""
    dirs, data = box
    init(dirs)
    mark = ws_of(data) / ".last-used"
    old = time.time() - 7200

    def aged() -> None:
        os.utime(mark, (old, old))
    aged()
    assert init(dirs)["reason"] == "exists" and mark.stat().st_mtime > old + 3600, "init yang tidak menyalin"
    aged()
    assert diff(dirs)["status"] == "ok" and mark.stat().st_mtime > old + 3600, "diff"
    aged()
    shutil.rmtree(data / "work/1/apktool")
    assert init(dirs, force=True)["status"] == "refused" and mark.stat().st_mtime > old + 3600, "init yang ditolak"


def test_init_does_not_overwrite_ai_work_without_force(box):
    dirs, data = box
    init(dirs)
    proj = ws_of(data) / "project"
    put(proj, "res/values/strings.xml", "<resources>PEKERJAAN-AI</resources>")
    put(proj, "baru/catatan.txt", "milik AI")
    (proj / "smali/com/x/A.smali").unlink()
    before = dump(proj)
    r = init(dirs)
    assert r["status"] == "ok" and r["created"] is False and r["reason"] == "exists" and "force" in r["message"]
    assert dump(proj) == before, "nol perubahan"


@pytest.mark.parametrize("kind", ["dir-kosong", "berkas", "symlink-ke-luar"])
def test_init_without_force_leaves_any_existing_project_alone(box, kind):
    dirs, data = box
    ws = ws_of(data)
    ws.mkdir(mode=0o700)
    outside = data / "luar"
    outside.mkdir()
    put(outside, "penanda.txt", "utuh")
    p = ws / "project"
    {"dir-kosong": lambda: p.mkdir(), "berkas": lambda: p.write_text("aku berkas"), "symlink-ke-luar": lambda: os.symlink(outside, p)}[kind]()
    r = init(dirs)
    assert r["status"] == "ok" and r["created"] is False and r["reason"] == "exists"
    assert (outside / "penanda.txt").read_text() == "utuh" and sorted(os.listdir(outside)) == ["penanda.txt"]
    assert p.is_symlink() == (kind == "symlink-ke-luar") and p.is_file() == (kind == "berkas")


def test_force_resets_to_baseline_and_removes_new_files(box):
    dirs, data = box
    init(dirs)
    proj = ws_of(data) / "project"
    put(proj, "res/values/strings.xml", "diubah")
    put(proj, "baru.txt", "baru")
    (proj / "build/apk").mkdir(parents=True)
    r = init(dirs, force=True)
    assert r["status"] == "ok" and r["created"] is True and r["reason"] == "reset"
    assert dump(proj) == dump(data / "work/1/apktool") and not (ws_of(data) / ".project.tmp").exists()


def test_force_replaces_a_symlinked_project_without_touching_its_target(box):
    dirs, data = box
    outside = data / "luar"
    outside.mkdir()
    put(outside, "penanda.txt", "utuh")
    ws = ws_of(data)
    ws.mkdir(mode=0o700)
    os.symlink(outside, ws / "project")
    r = init(dirs, force=True)
    assert r["status"] == "ok" and r["reason"] == "reset"
    assert not (ws / "project").is_symlink() and (ws / "project").is_dir()
    assert dump(outside) == {"penanda.txt": b"utuh"}


def test_a_failed_force_keeps_the_old_project(box, monkeypatch):
    dirs, data = box
    init(dirs)
    proj = ws_of(data) / "project"
    put(proj, "pekerjaan.txt", "penting")

    def boom(*a, **k):
        raise PermissionError(13, "secret/path/xyz")
    monkeypatch.setattr(T, "copy_tree_safe", boom)
    r = init(dirs, force=True)
    assert r["status"] == "failed" and "PermissionError" in r["message"] and "secret/path" not in r["message"]
    assert (proj / "pekerjaan.txt").read_text() == "penting" and not (ws_of(data) / ".project.tmp").exists()


def test_init_stale_tmp_and_tmp_symlink_bait_are_removed_without_touching_the_target(box):
    dirs, data = box
    ws = ws_of(data)
    ws.mkdir(mode=0o700)
    outside = data / "luar"
    outside.mkdir()
    put(outside, "penanda.txt", "utuh")
    os.symlink(outside, ws / ".project.tmp")
    assert init(dirs)["status"] == "ok"
    assert dump(outside) == {"penanda.txt": b"utuh"} and (ws / "project").is_dir()
    (ws / "project").rename(ws / "pindah")
    put(ws, ".project.tmp/setengah.txt", "sisa")
    assert init(dirs)["status"] == "ok" and (ws / "project").is_dir() and not (ws / ".project.tmp").exists()


@pytest.mark.parametrize("setup,code", [
    (lambda base: shutil.rmtree(base), "baseline_tidak_ada"),
    (lambda base: (base / "AndroidManifest.xml").unlink(), "baseline_tidak_ada"),
    (lambda base: ((base / "AndroidManifest.xml").unlink(), os.symlink("/etc/passwd", base / "AndroidManifest.xml")), "baseline_tidak_ada"),
    (lambda base: (shutil.move(str(base), str(base) + ".asli"), os.symlink(str(base) + ".asli", base)), "baseline_tidak_ada"),
], ids=["tanpa-apktool", "tanpa-manifest", "manifest-symlink", "apktool-symlink"])
def test_init_needs_a_real_baseline(box, setup, code):
    dirs, data = box
    setup(data / "work/1/apktool")
    r = init(dirs)
    assert r["status"] == "refused" and r["code"] == code
    assert not (ws_of(data) / "project").exists() and not (ws_of(data) / ".project.tmp").exists()


def test_init_over_the_copy_limit_is_refused_and_leaves_nothing(box):
    dirs, data = box
    put(data / "work/1/apktool", "assets/besar.bin", b"x" * 5000)
    r = init(dirs, quota=4000)                                   # 3/4 kuota = 3000 byte < isi baseline
    assert r["status"] == "refused" and r["code"] == "too_large"
    assert not (ws_of(data) / "project").exists() and not (ws_of(data) / ".project.tmp").exists()


def test_init_that_would_leave_the_workspace_over_90_percent_is_refused_and_a_success_never_does(box):
    dirs, data = box
    ws = ws_of(data)
    ws.mkdir(mode=0o700)
    put(ws, "sampah.bin", b"y" * 400_000)
    used_before = E.tree_bytes(ws)
    quota = int(used_before / 0.9) + 20_000                      # sisa ruang kurang dari baseline (beberapa blok)
    r = init(dirs, quota=quota)
    assert r["status"] == "refused" and r["code"] == "kuota" and not (ws / "project").exists() and not (ws / ".project.tmp").exists()
    ok = init(dirs, quota=quota + 4 * 1024 * 1024)
    assert ok["status"] == "ok" and E.tree_bytes(ws) <= (quota + 4 * 1024 * 1024) * 9 // 10, "init sukses tidak membuat perintah shell pertama ditolak kuota"


def test_init_refuses_when_free_disk_space_is_too_small_and_leaves_no_tmp(box):
    """A-15: statvfs kecil -> refused kuota SEBELUM menyalin."""
    dirs, data = box

    class Small:
        f_bavail, f_frsize = 10, 4096

    class Big:
        f_bavail, f_frsize = 10**9, 4096
    r = init(dirs, statvfs=lambda p: Small)
    assert r["status"] == "refused" and r["code"] == "kuota" and "ruang disk" in r["message"]
    assert not (ws_of(data) / "project").exists() and not (ws_of(data) / ".project.tmp").exists()
    assert init(dirs, statvfs=lambda p: Big)["status"] == "ok"


def test_force_quota_accounts_for_the_old_project_being_replaced(box):
    dirs, data = box
    assert init(dirs)["status"] == "ok"
    ws = ws_of(data)
    quota = int(E.tree_bytes(ws) / 0.9) + 30_000                 # cukup untuk SATU project, tidak untuk dua
    r = init(dirs, force=True, quota=quota)
    assert r["status"] == "ok" and r["reason"] == "reset"


def test_init_is_cancellable_and_times_out_with_cleanup(box, monkeypatch):
    dirs, data = box
    for i in range(30):
        put(data / "work/1/apktool", f"smali/p{i}/F.smali", "x" * 10)
    clock = [0.0]

    def fast() -> float:                                              # jam treediff melompat: on_tick dipanggil di setiap entri
        clock[0] += 3.0
        return clock[0]
    monkeypatch.setattr(T, "_clock", fast)
    calls = []
    r = init(dirs, cancel=lambda: calls.append(1) or len(calls) > 3)
    assert r["status"] == "cancelled" and calls, r
    assert not (ws_of(data) / "project").exists() and not (ws_of(data) / ".project.tmp").exists()
    real = W._ticker
    seq = iter(range(0, 100_000, 7))
    monkeypatch.setattr(W, "_ticker", lambda c, h, t, clock=None: real(c, h, t, clock=lambda: float(next(seq))))
    r = init(dirs, timeout=10)
    assert r["status"] == "timeout", r
    assert not (ws_of(data) / "project").exists() and not (ws_of(data) / ".project.tmp").exists()
    monkeypatch.undo()
    assert init(dirs)["status"] == "ok"


def test_ticker_raises_cancel_and_timeout_and_beats():
    now = [100.0]
    beats = []
    tick = W._ticker(lambda: False, lambda: beats.append(1), 10, clock=lambda: now[0])
    tick()
    now[0] = 103.0
    tick()
    assert len(beats) == 1
    now[0] = 106.0
    tick()
    assert len(beats) == 2, "detak jantung tiap <= 5 dtk"
    now[0] = 111.0
    with pytest.raises(T.TreeLimitError) as ei:
        tick()
    assert ei.value.code == "timeout"
    with pytest.raises(T.TreeLimitError) as ei:
        W._ticker(lambda: True, lambda: None, 10, clock=lambda: 0.0)()
    assert ei.value.code == "cancelled"
    assert W._from_limit_error(T.TreeLimitError("cancelled"))["status"] == "cancelled"
    assert W._from_limit_error(T.TreeLimitError("timeout", "x"))["status"] == "timeout"
    assert W._from_limit_error(T.TreeLimitError("too_deep", "x"))["status"] == "refused"


def test_diff_before_init_and_with_a_bad_project_is_refused_with_a_code(box):
    dirs, data = box
    r = diff(dirs)
    assert r["status"] == "refused" and r["code"] == "belum_init"
    ws_of(data).mkdir(mode=0o700)
    assert diff(dirs)["code"] == "belum_init"
    (ws_of(data) / "project").write_text("bukan direktori")
    assert diff(dirs)["code"] == "project_tidak_valid"
    (ws_of(data) / "project").unlink()
    outside = data / "luar"
    outside.mkdir()
    os.symlink(outside, ws_of(data) / "project")
    assert diff(dirs)["code"] == "project_tidak_valid", "symlink tidak diikuti"
    (ws_of(data) / "project").unlink()
    (ws_of(data) / "project").mkdir()
    shutil.rmtree(data / "work/1/apktool")
    assert diff(dirs)["code"] == "baseline_tidak_ada"


def test_diff_of_a_fresh_init_is_empty_stable_and_equals_treediff(box):
    dirs, data = box
    init(dirs)
    a, b = diff(dirs), diff(dirs)
    assert a["status"] == "ok" and a["counts"] == {"added": 0, "modified": 0, "removed": 0} and a["top"] == [] and a["entries_total"] == 0
    assert a["diff_sha256"] == b["diff_sha256"] == T.compute_diff(data / "work/1/apktool", ws_of(data) / "project").diff_sha256
    assert a["base_entries"] == len(BASE_FILES) and SP.parse_diff_result(a)["status"] == "ok"


def test_diff_sees_exactly_one_modified_file_and_the_hash_follows_content(box):
    dirs, data = box
    init(dirs)
    empty = diff(dirs)["diff_sha256"]
    sx = ws_of(data) / "project/res/values/strings.xml"
    sx.write_text(sx.read_text().replace("Contoh", "PENANDA-123"))
    r = diff(dirs)
    assert r["counts"] == {"added": 0, "modified": 1, "removed": 0} and r["kinds"]["res"] == 1
    assert [(t["op"], t["path"]) for t in r["top"]] == [("M", "res/values/strings.xml")] and r["lines"]["plus"] == 1 and r["lines"]["minus"] == 1
    assert r["diff_sha256"] != empty
    sx.write_text(sx.read_text().replace("PENANDA-123", "PENANDA-124"))
    assert diff(dirs)["diff_sha256"] != r["diff_sha256"], "satu byte beda mengubah hash"
    sx.write_text(sx.read_text().replace("PENANDA-124", "Contoh"))
    assert diff(dirs)["diff_sha256"] == empty, "kembali ke isi semula = hash semula"


def test_diff_ignores_build_dist_symlink_and_fifo_in_project_without_hanging(box):
    dirs, data = box
    init(dirs)
    proj = ws_of(data) / "project"
    empty = diff(dirs)["diff_sha256"]
    put(proj, "build/apk/classes.dex", "DEX-SELUNDUPAN")
    put(proj, "dist/x.apk", "x")
    os.symlink("/etc/passwd", proj / "pw")
    os.mkfifo(proj / "fifo")
    with within(10):
        r = diff(dirs)
    assert r["diff_sha256"] == empty and r["skipped"]["root_ignored"] == 2 and r["skipped"]["symlink"] == 1 and r["skipped"]["special"] == 1


def test_diff_equals_the_hash_of_a_snapshot_made_by_copy_tree_safe(box):
    """Runner menghitung ulang atas SNAPSHOT: hash harus sama dengan yang dilihat pemilik di bench (pohon hidup)."""
    dirs, data = box
    init(dirs)
    proj = ws_of(data) / "project"
    put(proj, "res/values/strings.xml", "<resources>ubah</resources>")
    put(proj, "assets/baru.sh", "#!/bin/sh\n", 0o755)
    os.symlink("/etc/passwd", proj / "pw")
    os.makedirs(proj / "build/apk")
    live = diff(dirs)["diff_sha256"]
    snap = data / "snap"
    T.copy_tree_safe(proj, snap)
    assert T.compute_diff(data / "work/1/apktool", snap).diff_sha256 == live


def test_diff_is_cancellable_beats_and_times_out(box, monkeypatch):
    dirs, data = box
    init(dirs)
    clock = [0.0]

    def fast() -> float:                                              # jam treediff melompat: on_tick dipanggil di setiap entri
        clock[0] += 3.0
        return clock[0]
    monkeypatch.setattr(T, "_clock", fast)
    beats = []
    assert diff(dirs, cancel=lambda: True)["status"] == "cancelled"
    assert diff(dirs, heartbeat=lambda: beats.append(1))["status"] == "ok" and beats
    real = W._ticker
    seq = iter(range(0, 100_000, 7))
    monkeypatch.setattr(W, "_ticker", lambda c, h, t, clock=None: real(c, h, t, clock=lambda: float(next(seq))))
    assert diff(dirs, timeout=10)["status"] == "timeout"


def test_op_paths_come_from_an_int_only():
    dirs = P.Dirs(Path("/data"))
    assert P.project_dir(dirs, 7) == Path("/data/bench/7/project") and P.base_tree(dirs, 7) == Path("/data/work/7/apktool")
    for bad in ("7", "../7", True, 0, -1, 10**9, 7.0, None):
        with pytest.raises(ValueError):
            P.project_dir(dirs, bad)
        with pytest.raises(ValueError):
            P.base_tree(dirs, bad)
        with pytest.raises(ValueError):
            W.op_init(dirs, QUOTA, bad, False, timeout=5)
        with pytest.raises(ValueError):
            W.op_diff(dirs, bad, timeout=5)


# ================================================================================ 3. daemon (validasi di sisi penerima)
@pytest.fixture
def daemon(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("BENCH_SPOOL", str(tmp_path / "sp"))
    loader = importlib.machinery.SourceFileLoader("bench_daemon_ops_under_test", str(SERVICES / "bench/bench-daemon"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    (tmp_path / "data/bench").mkdir(parents=True)
    mkbase(tmp_path / "data")
    mod.SPOOL.ensure_dirs()
    return mod, tmp_path / "data"


def job(op="init", **kw):
    j = {"job_id": "s1-aaaaaaaaaaaa", "op": op, "analysis_id": 1, "timeout": 30}
    if op == "init":
        j["force"] = False
    j.update(kw)
    return j


def test_daemon_runs_init_then_diff_and_ignores_every_path_like_field(daemon, tmp_path):
    d, data = daemon
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    r = d.run_job("s1-aaaaaaaaaaaa", job("init", path=str(decoy), project=str(decoy), src="/etc", command="rm -rf /", sha256="../x", workspace=str(decoy)))
    assert r["status"] == "ok" and r["created"] is True and (data / "bench/1/project/AndroidManifest.xml").is_file() and os.listdir(decoy) == []
    r = d.run_job("s1-aaaaaaaaaaaa", job("diff", path=str(decoy), base="/etc"))
    assert r["status"] == "ok" and r["counts"] == {"added": 0, "modified": 0, "removed": 0}
    assert SP.parse_diff_result(r)["status"] == "ok" and SP.parse_init_result({"status": "ok"})["status"] == "ok"


@pytest.mark.parametrize("aid", ["1", True, False, 0, -3, 10**9, 2**31, 2**40, 1.0, None, [1], {"a": 1}], ids=lambda v: repr(v))
@pytest.mark.parametrize("op", ["init", "diff"])
def test_daemon_refuses_a_bad_analysis_id_for_new_ops_and_touches_nothing(daemon, op, aid):
    d, data = daemon
    r = d.run_job("s1-aaaaaaaaaaaa", job(op, analysis_id=aid))
    assert r["status"] == "refused" and "analysis_id" in r["message"]
    assert os.listdir(data / "bench") == []


@pytest.mark.parametrize("force", ["true", "True", 1, 0, None, "", [True], {"force": True}], ids=lambda v: repr(v))
def test_daemon_refuses_a_force_that_is_not_a_real_bool(daemon, force):
    d, data = daemon
    r = d.run_job("s1-aaaaaaaaaaaa", job("init", force=force))
    assert r["status"] == "refused" and "force" in r["message"] and os.listdir(data / "bench") == []


def test_daemon_refuses_init_without_a_force_field_and_accepts_diff_without_one(daemon):
    d, data = daemon
    j = job("init")
    del j["force"]
    assert d.run_job("s1-aaaaaaaaaaaa", j)["status"] == "refused"
    d.run_job("s1-aaaaaaaaaaaa", job("init"))
    assert d.run_job("s1-aaaaaaaaaaaa", job("diff", force="apa-saja"))["status"] == "ok"


@pytest.mark.parametrize("timeout", [0, -1, "30", True, None, 1.5], ids=lambda v: repr(v))
def test_daemon_refuses_a_bad_timeout_for_new_ops(daemon, timeout):
    d, _ = daemon
    assert d.run_job("s1-aaaaaaaaaaaa", job("diff", timeout=timeout))["status"] == "refused"


def test_daemon_clamps_the_timeout_and_refuses_unknown_ops_and_keeps_run_unchanged(daemon):
    d, _ = daemon
    assert d.validate_op(job("diff", timeout=10**9))[2] == SP.OP_MAX_TIMEOUT
    for op in ("bogus", "INIT", "Run", "", None, 5, ["init"], "init ", "init\n"):
        r = d.run_job("s1-aaaaaaaaaaaa", {**job(), "op": op})
        assert r["status"] == "refused" and "operasi tidak dikenal" in r["message"], op
    r = d.run_job("s1-aaaaaaaaaaaa", {"op": "run", "analysis_id": "1", "command": "id", "timeout": 5})
    assert r["status"] == "refused" and "analysis_id" in r["message"], "validasi op run lama tidak berubah"
    assert d.validate_run({"analysis_id": 2**31 - 1, "command": "id", "timeout": 5})[0] == 2**31 - 1, "op run lama tetap 1 <= aid < 2**31"


def test_daemon_spool_roundtrip_with_shellspool_client(daemon):
    """Klien (web) -> spool -> daemon (satu iterasi seperti main) -> hasil dinormalkan: init lalu diff."""
    d, data = daemon
    sp = d.SPOOL
    sp.write_heartbeat("idle")
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            c = sp.claim_next()
            if c:
                sp.finish(c[0], d.run_job(*c))
            else:
                time.sleep(0.02)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    try:
        r = SP.run_op(sp, SP.build_init_request(1), SP.parse_init_result, poll=0.02)
        assert r["status"] == "ok" and r["created"] is True
        r = SP.run_op(sp, SP.build_diff_request(1), SP.parse_diff_result, poll=0.02)
        assert r["status"] == "ok" and len(r["diff_sha256"]) == 64
        r = SP.run_op(sp, SP.build_init_request(1, True), SP.parse_init_result, poll=0.02)
        assert r["reason"] == "reset"
    finally:
        stop.set()
        t.join(2)


# ================================================================================ 4. uid 10001 / berkas milik uid lain / ro / noexec
_SETPRIV, _UNSHARE = shutil.which("setpriv"), shutil.which("unshare")
_REAL_PY = os.path.realpath(os.path.join(sys.base_prefix, "bin", f"python{sys.version_info.major}.{sys.version_info.minor}"))
_LIB = os.path.join(os.path.dirname(os.path.dirname(_REAL_PY)), "lib")
_ENV = ["env", "-i", "PATH=/usr/bin:/bin", f"LD_LIBRARY_PATH={_LIB}", "PYTHONDONTWRITEBYTECODE=1", f"PYTHONPATH={SERVICES}:{SERVICES / 'bench'}"]
_AS_10001 = [_SETPRIV, "--reuid=10001", "--regid=10001", "--clear-groups", *_ENV, _REAL_PY] if _SETPRIV else []

_SCRIPT = textwrap.dedent('''
    import json, sys
    from pathlib import Path
    from bench import policy, workspace
    mode, data, force = sys.argv[1], Path(sys.argv[2]), sys.argv[3] == "1"
    dirs = policy.Dirs(data)
    if mode == "init":
        out = workspace.op_init(dirs, 1 << 30, 1, force, timeout=60)
    else:
        out = workspace.op_diff(dirs, 1, timeout=60)
    print(json.dumps(out))
''')


def _can_drop() -> bool:
    if os.geteuid() != 0 or not _SETPRIV:
        return False
    try:
        r = subprocess.run([*_AS_10001, "-c", "import os, sys, rvcore.treediff, bench.workspace; sys.exit(0 if os.getuid() == 10001 else 1)"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


_CAN_DROP = _can_drop()
need_uid = pytest.mark.skipif(not _CAN_DROP, reason="butuh root + setpriv + interpreter yang bisa dijalankan uid 10001 (izin diabaikan bagi root)")


@pytest.fixture
def shared():
    """Pohon data yang bisa dilintasi uid 10001 (tmp_path pytest berizin 0700): dibuat/dihapus root. work/ milik root (seperti volume `work` yang ditulis runner)."""
    d = Path(tempfile.mkdtemp(prefix="rv-benchops-"))
    d.chmod(0o755)
    (d / "run.py").write_text(_SCRIPT)
    (d / "run.py").chmod(0o644)
    data = d / "data"
    data.mkdir(mode=0o755)
    mkbase(data)
    for p in (data / "work").rglob("*"):
        p.chmod(0o755 if p.is_dir() else 0o644)
    (data / "work").chmod(0o755)
    bench = data / "bench"
    bench.mkdir(mode=0o755)
    os.chown(bench, 10001, 10001)
    yield d, data
    shutil.rmtree(d, ignore_errors=True)


def as_user(shared_dir: Path, mode: str, data: Path, force: bool = False, wrap: list[str] | None = None, timeout: int = 60) -> dict:
    r = subprocess.run([*(wrap or []), *_AS_10001, str(shared_dir / "run.py"), mode, str(data), "1" if force else "0"], capture_output=True, text=True, timeout=timeout)
    assert r.returncode == 0, (r.stdout, r.stderr)
    return json.loads(r.stdout.strip().splitlines()[-1])


@need_uid
def test_uid10001_init_copies_a_root_owned_baseline_into_its_own_workspace(shared):
    d, data = shared
    out = as_user(d, "init", data)
    assert out["status"] == "ok" and out["created"] is True
    proj = data / "bench/1/project"
    owners = {(p.stat().st_uid, stat.S_IMODE(p.stat().st_mode)) for p in proj.rglob("*") if p.is_file()}
    assert owners == {(10001, 0o644)} and proj.stat().st_uid == 10001 and stat.S_IMODE(proj.stat().st_mode) == 0o755
    assert (data / "bench/1/.last-used").exists() and dump(proj) == dump(data / "work/1/apktool")
    dd = as_user(d, "diff", data)
    assert dd["status"] == "ok" and dd["counts"] == {"added": 0, "modified": 0, "removed": 0}
    assert dd["diff_sha256"] == T.compute_diff(data / "work/1/apktool", proj).diff_sha256, "uid 10001 dan root menghitung hash yang sama"


@need_uid
def test_uid10001_fails_closed_on_a_mode600_root_owned_baseline_file_and_leaves_nothing(shared):
    d, data = shared
    os.chmod(data / "work/1/apktool/res/values/strings.xml", 0o600)
    out = as_user(d, "init", data)
    assert out["status"] == "refused" and out["code"] == "unreadable" and "res/values/strings.xml" in out["message"] and str(d) not in out["message"]
    assert not (data / "bench/1/project").exists() and not (data / "bench/1/.project.tmp").exists()


@need_uid
def test_uid10001_cannot_create_a_workspace_when_bench_is_owned_by_root(shared):
    d, data = shared
    os.chown(data / "bench", 0, 0)
    out = as_user(d, "init", data)
    assert out["status"] == "failed" and "PermissionError" in out["message"] and str(d) not in out["message"]
    assert os.listdir(data / "bench") == []
    assert as_user(d, "diff", data)["code"] == "belum_init"


@need_uid
def test_uid10001_is_locked_out_of_a_workspace_owned_by_another_uid_and_reports_failed_not_a_crash(shared):
    d, data = shared
    ws = data / "bench/1"
    ws.mkdir(mode=0o700)
    os.chown(ws, 10002, 10002)
    put(ws, "project/x.txt", "milik uid lain")
    assert as_user(d, "init", data)["status"] == "failed"
    assert as_user(d, "init", data, force=True)["status"] == "failed"
    assert as_user(d, "diff", data)["status"] == "failed"
    assert (ws / "project/x.txt").read_text() == "milik uid lain"


@need_uid
def test_uid10001_force_cannot_delete_a_root_owned_project_and_keeps_it(shared):
    """project lama milik root di folder tak bisa ditulis: hapus gagal -> `failed`, isi lama utuh, tidak ada sisa .project.tmp."""
    d, data = shared
    ws = data / "bench/1"
    ws.mkdir(mode=0o700)
    os.chown(ws, 10001, 10001)
    put(ws, "project/x.txt", "milik root", 0o600)
    put(ws, "project/sub/y.txt", "milik root", 0o600)
    put(ws, "project/tertutup/z.txt", "milik root", 0o600)
    for p in (ws / "project", ws / "project/sub"):
        p.chmod(0o755)
    (ws / "project/tertutup").chmod(0o000)                            # tak bisa dibuka dan tak bisa di-chmod uid 10001 (bukan pemiliknya): tidak boleh rekursi tak berujung
    with within(30):
        out = as_user(d, "init", data, force=True)
    assert out["status"] == "failed" and str(d) not in out["message"]
    (ws / "project/tertutup").chmod(0o755)
    assert (ws / "project/x.txt").read_text() == "milik root" and not (ws / ".project.tmp").exists()


@need_uid
def test_uid10001_force_resets_its_own_project_even_with_mode000_dirs_and_readonly_files(shared):
    d, data = shared
    assert as_user(d, "init", data)["created"] is True
    proj = data / "bench/1/project"
    put(proj, "kunci/rahasia.txt", "x", 0o444)                       # dibuat root: ubah pemilik agar milik uid 10001
    for p in (proj / "kunci", proj / "kunci/rahasia.txt"):
        os.chown(p, 10001, 10001)
    (proj / "kunci").chmod(0o000)
    out = as_user(d, "init", data, force=True)
    assert out["status"] == "ok" and out["reason"] == "reset"
    assert dump(proj) == dump(data / "work/1/apktool")


@need_uid
@pytest.mark.skipif(not _UNSHARE, reason="butuh unshare")
def test_uid10001_with_work_bind_readonly_and_bench_on_noexec_tmpfs(shared):
    """Meniru bench: `work` dipasang ro (EROFS bila ditulis), `bench` volume tersendiri (di sini tmpfs `noexec`, milik 10001). Pohon salinan tetap 0644/0755."""
    d, data = shared
    put(data / "work/1/apktool", "assets/run.sh", "#!/bin/sh\n", 0o755)
    ro_mnt, benchmnt = d / "work_ro", data / "bench"
    ro_mnt.mkdir()
    script = (f"set -e; mount --bind {data / 'work'} {ro_mnt}; mount -o remount,bind,ro {ro_mnt}; "
              f"mount -t tmpfs -o noexec,nosuid,size=300m,uid=10001,gid=10001,mode=0755 tmpfs {benchmnt}; "
              f"if (echo x > {ro_mnt}/1/apktool/probe) 2>/dev/null; then echo RW; exit 9; fi; "
              f"mkdir -p {d / 'data2'}; ln -sfn {benchmnt} {d / 'data2/bench'}; ln -sfn {ro_mnt} {d / 'data2/work'}; "
              f"exec {' '.join(_AS_10001)} {d / 'run.py'} init {d / 'data2'} 0")
    r = subprocess.run([_UNSHARE, "-m", "sh", "-c", script], capture_output=True, text=True, timeout=90)
    if "RW" in r.stdout or r.returncode == 9:
        pytest.fail("bind ro ternyata bisa ditulis")
    if r.returncode != 0 and ("mount" in r.stderr or "unshare" in r.stderr):
        pytest.skip(f"unshare/mount tidak diizinkan: {r.stderr.strip()[:120]}")
    assert r.returncode == 0, (r.stdout, r.stderr)
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["status"] == "ok" and out["created"] is True and out["files"] == len(BASE_FILES) + 1, out


# ================================================================================ 5. daemon NYATA sebagai proses
def _libpython_mounts() -> str | None:
    """Shell yang membuat libpython interpreter ini terjangkau uid 10001 TANPA LD_LIBRARY_PATH, atau "" bila sudah terjangkau, atau None bila tak bisa.

    executor.run_confined menjalankan penolong dengan env bersih (tanpa LD_LIBRARY_PATH). Interpreter sandbox punya RPATH ke /root/.pyenv (tak bisa dilintasi uid
    10001); di image bench python ada di /usr/local. Di namespace mount sendiri, /root ditutup tmpfs lalu direktori lib asli di-bind ke jalur RPATH."""
    if not _CAN_DROP:
        return None
    probe = subprocess.run([_SETPRIV, "--reuid=10001", "--regid=10001", "--clear-groups", "env", "-i", _REAL_PY, "-c", "pass"], capture_output=True, timeout=30)
    if probe.returncode == 0:
        return ""
    if not _UNSHARE:
        return None
    ldd = subprocess.run(["ldd", _REAL_PY], capture_output=True, text=True).stdout
    for line in ldd.splitlines():
        if "libpython" in line and "=>" in line:
            shown = os.path.dirname(line.split("=>")[1].split()[0])
            real = os.path.dirname(os.path.realpath(os.path.join(shown, os.path.basename(line.split("=>")[1].split()[0]))))
            top = "/" + shown.strip("/").split("/")[0]
            return f"mount -t tmpfs -o mode=0755 tmpfs {top} && mkdir -p {shown} && mount --bind {real} {shown} && "
    return None


def _start_real_daemon(base: Path):
    data, spool = base / "data", base / "spool"
    spool.mkdir(mode=0o777)
    os.chmod(spool, 0o777)
    scratch = base / "tmp"                                            # /tmp kontainer = tmpfs milik 10001; /tmp sandbox bisa tak dapat ditulis uid lain
    scratch.mkdir(mode=0o700)
    os.chown(scratch, 10001, 10001)
    fix = _libpython_mounts()
    if fix is None:
        pytest.skip("interpreter tidak bisa dijalankan uid 10001 dengan env bersih (tanpa unshare)")
    env = ["env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1", "PYTHONUNBUFFERED=1",
           f"PYTHONPATH={SERVICES}:{SERVICES / 'bench'}", f"DATA_DIR={data}", f"BENCH_SPOOL={spool}", "BENCH_IDLE_EXIT=0", "BENCH_CMD_MAX_TIMEOUT=30",
           "BENCH_NPROC=100000", f"TMPDIR={scratch}", f"HOME={scratch}"]
    inner = [_SETPRIV, "--reuid=10001", "--regid=10001", "--clear-groups", *env, _REAL_PY, str(SERVICES / "bench/bench-daemon")]
    if fix:
        cmd = [_UNSHARE, "-m", "sh", "-c", fix + "exec " + " ".join(inner)]
    else:
        cmd = inner
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    sp = SP.make_spool(spool)
    for _ in range(100):
        if sp.heartbeat_age() is not None:
            return proc, sp
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    proc.kill()
    out = proc.communicate()[0]
    if "mount" in out or "unshare" in out:
        pytest.skip(f"unshare/mount tidak diizinkan: {out.strip()[:120]}")
    pytest.fail("bench-daemon tidak hidup: " + out)


def _stop(proc) -> str:
    proc.send_signal(signal.SIGTERM)
    try:
        out, _ = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    return out


@need_uid
def test_real_daemon_process_runs_init_diff_and_a_confined_shell_that_writes_ws_project(shared):
    """Proses `bench-daemon` SUNGGUHAN sebagai uid 10001: init (baseline milik root) -> perintah shell terkurung Landlock mengubah $WS/project -> diff tepat 1 M + 1 A."""
    d, data = shared
    proc, sp = _start_real_daemon(d)
    try:
        r = SP.run_op(sp, SP.build_init_request(1), SP.parse_init_result, poll=0.05)
        assert r["status"] == "ok" and r["created"] is True, r
        assert SP.run_op(sp, SP.build_diff_request(1), SP.parse_diff_result, poll=0.05)["counts"] == {"added": 0, "modified": 0, "removed": 0}
        r = SP.run_op(sp, SP.build_init_request(1), SP.parse_init_result, poll=0.05)
        assert r["created"] is False and r["reason"] == "exists"
        if LL.abi_version() < 1:
            pytest.skip("Landlock tidak tersedia: bagian shell terkurung dilewati (init/diff nyata sudah terbukti di atas)")
        marker = "PENANDA-" + os.urandom(4).hex()
        cmd = (f"sed -i 's/Contoh/{marker}/' $WS/project/res/values/strings.xml && echo baru > $WS/project/assets/baru.txt "
               "&& (echo x > $WORK/apktool/hack.txt) 2>/dev/null; echo selesai")
        res = SP.run_command(sp, 1, cmd, timeout=20, poll=0.05)
        assert res["status"] == "ok" and "selesai" in res["stdout"], (res.get("message"), proc.poll())
        assert not (data / "work/1/apktool/hack.txt").exists(), "perintah terkurung tidak boleh menulis baseline"
        dd = SP.run_op(sp, SP.build_diff_request(1), SP.parse_diff_result, poll=0.05)
        assert dd["status"] == "ok" and dd["counts"] == {"added": 1, "modified": 1, "removed": 0}, dd
        assert sorted((t["op"], t["path"]) for t in dd["top"]) == [("A", "assets/baru.txt"), ("M", "res/values/strings.xml")]
        assert marker in (data / "bench/1/project/res/values/strings.xml").read_text()
        ra = SP.run_op(sp, SP.build_init_request(1), SP.parse_init_result, poll=0.05)
        assert ra["created"] is False, "init tanpa force tidak menimpa pekerjaan shell"
        assert marker in (data / "bench/1/project/res/values/strings.xml").read_text()
        rf = SP.run_op(sp, SP.build_init_request(1, True), SP.parse_init_result, poll=0.05)
        assert rf["reason"] == "reset" and marker not in (data / "bench/1/project/res/values/strings.xml").read_text()
        assert SP.run_op(sp, SP.build_diff_request(1), SP.parse_diff_result, poll=0.05)["counts"]["modified"] == 0
    finally:
        log = _stop(proc)
    assert "Traceback" not in log, log


@need_uid
def test_real_daemon_refuses_hostile_raw_requests_dropped_into_the_spool(shared):
    """Permintaan MENTAH (tanpa lewat klien yang memvalidasi): id string/bool, force string, bidang jalur. Daemon menolak di sisi penerima dan tetap hidup."""
    d, data = shared
    proc, sp = _start_real_daemon(d)
    try:
        for i, extra in enumerate(({"analysis_id": "1"}, {"analysis_id": True}, {"analysis_id": 10**9}, {"force": "true"}, {"force": 1}, {"op": "hapus"},
                                   {"op": "init", "force": False, "analysis_id": "../../etc"})):
            jid = f"s1-{i:012x}"
            sp.submit({**{"job_id": jid, "op": "init", "analysis_id": 1, "force": False, "timeout": 30, "path": "/etc"}, **extra})
            for _ in range(200):
                got = sp.results / f"{jid}.json"
                if got.exists():
                    break
                time.sleep(0.05)
            res = json.loads((sp.results / f"{jid}.json").read_text())
            assert res["status"] == "refused", (extra, res)
        assert not (data / "bench/1").exists() or not (data / "bench/1/project").exists()
        assert SP.run_op(sp, SP.build_init_request(1), SP.parse_init_result, poll=0.05)["created"] is True, "daemon masih hidup dan melayani"
    finally:
        log = _stop(proc)
    assert "Traceback" not in log, log


# ================================================================================ 6. statis
def test_bench_image_ships_the_whole_package_and_never_mentions_builds():
    df = (SERVICES / "bench/Dockerfile").read_text()
    assert "COPY bench/bench ./bench" in df and "COPY rvcore ./rvcore" in df, "workspace.py dan treediff.py ikut karena seluruh paket disalin"
    assert "/data/builds" not in df
    assert (SERVICES / "bench/bench/workspace.py").is_file()


def test_compose_bench_service_has_no_builds_volume_and_keeps_work_readonly():
    text = (ROOT / "docker-compose.yml").read_text()
    block = text[text.index("\n  bench:\n"):text.index("\n  egress:")] if "\n  egress:" in text else text[text.index("\n  bench:\n"):]
    vols = [ln.strip() for ln in block.splitlines() if ln.strip().startswith("- ") and ":/data/" in ln]
    assert any(v.startswith("- work:/data/work:ro") for v in vols), vols
    assert not any("builds" in v or "signwork" in v or "signspool" in v for v in vols), vols


def test_selftest_checks_init_diff_and_project_writability():
    st = (SERVICES / "bench/bench-selftest").read_text()
    for needle in ("init menyalin baseline ke $WS/project", "init kedua TIDAK menimpa pekerjaan", "diff pohon yang baru di-init kosong", "boleh MENULIS di $WS/project",
                   "TIDAK boleh menulis baseline lewat $WORK", "volume bench TIDAK memuat builds"):
        assert needle in st, needle


def test_no_ai_tool_can_build_an_init_request():
    """`force` hanya sah dari pemilik/kode (CLI): kode tool AI tidak boleh membangun permintaan init/diff."""
    offenders = []
    for p in (SERVICES / "web/app").rglob("*.py"):
        txt = p.read_text(encoding="utf-8")
        if p.parts[-2] == "ai" and any(n in txt for n in ("build_init_request", "OP_INIT", "build_diff_request", "run_op", "op_init")):
            offenders.append(str(p.relative_to(ROOT)))
    assert offenders == []
