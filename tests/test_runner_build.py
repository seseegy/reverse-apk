"""Tahap runner `build` (Tahap 2b): `services/runner/buildstage.py` + cabang `build` di `runner-daemon`.

Lapisan:
  1. apktool PALSU yang merekam argv/cwd/env/isi `src` dan bisa disuruh gagal/tidur/membanjiri/menghasilkan keluaran aneh -> urutan langkah, `workspace_changed`
     (hash dihitung ulang atas SNAPSHOT, dasar ikut diikat), disk, timeout/pembatalan/penghentian, batas keluaran, scrub jalur absolut+relatif (NB-3), `build.log`, pembersihan;
  2. cabang `build` di runner-daemon (dimuat lewat SourceFileLoader): dispatch SEBELUM pemeriksaan APK, validasi, allowlist;
  3. daemon NYATA sebagai proses uid 10001 dengan `bench` sebagai bind READ-ONLY (unshare -m), berkas milik root/uid lain (pelajaran 3);
  4. apktool NYATA (BUILD_TEST_APKTOOL_JAR, BUILD_TEST_AAPT2, BUILD_TEST_JAVA_HOME) lewat wrapper produksi; dilewati bersih bila env tidak diset (CI tidak punya alatnya).
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import buildstage
import pytest
from conftest import ROOT, UNSHARE, as_user, need_mount, open_to_10001, within_call
from rvcore import buildproto, treediff
from rvcore.buildproto import BuildRequest
from rvcore.paths import Layout
from rvcore.spool import Spool

DAEMON = ROOT / "services" / "runner" / "runner-daemon"
AID, BID = 5, 7
G = "cd" * 32                                           # sha256 APK asal (jejak FR-9.23)

BASE_FILES = {
    "AndroidManifest.xml": "<manifest package='x'/>\n",
    "apktool.yml": "version: 3.0.3\n",
    "res/values/strings.xml": '<resources><string name="app_name">Asli</string></resources>\n',
    "res/values-v21/styles.xml": "<resources/>\n",
    "res/layout/main.xml": "<LinearLayout/>\n",
    "smali/com/x/A.smali": ".class public Lcom/x/A;\n",
}
EDIT = {"res/values/strings.xml": '<resources><string name="app_name">Dimodifikasi</string></resources>\n', "assets/extra.txt": "tambahan\n"}


def mktree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    root.mkdir(parents=True, exist_ok=True)
    return root


# ======================================================================================== apktool palsu
FAKE_APKTOOL = r'''#!@PY@
import hashlib, json, os, signal, subprocess, sys, time
REC = @REC@
args = sys.argv[1:]
src, out = args[4], args[6]
files = {}
for dp, dn, fn in os.walk(src):
    for f in fn:
        p = os.path.join(dp, f)
        try:
            files[os.path.relpath(p, src)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
        except OSError:
            files[os.path.relpath(p, src)] = None
rec = {"argv": args, "cwd": os.getcwd(), "env": dict(os.environ), "src_top": sorted(os.listdir(src)), "files": files,
       "trace": open(os.path.join(src, "assets", "reverse-apk-modified.txt")).read() if os.path.exists(os.path.join(src, "assets", "reverse-apk-modified.txt")) else None,
       "pgid_is_leader": os.getpgid(0) == os.getpid()}
with open(os.path.join(REC, "calls.jsonl"), "a") as fh:
    fh.write(json.dumps(rec) + "\n")
try:
    beh = json.load(open(os.path.join(REC, "behavior.json")))
except OSError:
    beh = {}
mode = beh.get("mode", "ok")
if beh.get("mutate_live"):
    path, text = beh["mutate_live"]
    open(path, "w").write(text)
if mode == "sleep":
    gc = subprocess.Popen(["sleep", "300"])
    open(os.path.join(REC, "gc.pid"), "w").write(str(gc.pid))
    open(os.path.join(REC, "started"), "w").write("1")
    if beh.get("ignore_term"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(300)
if mode == "slow":
    open(os.path.join(REC, "started"), "w").write("1")
    time.sleep(beh.get("seconds", 0.6))
if mode == "flood_build":
    os.makedirs(os.path.join(src, "build", "apk"), exist_ok=True)
    with open(os.path.join(src, "build", "apk", "big.bin"), "wb") as fh:
        fh.write(b"x" * beh.get("bytes", 5 * 1024 * 1024))
    open(os.path.join(REC, "started"), "w").write("1")
    time.sleep(120)
if mode == "flood_out":
    with open(out, "wb") as fh:
        fh.write(b"x" * beh.get("bytes", 5 * 1024 * 1024))
    open(os.path.join(REC, "started"), "w").write("1")
    time.sleep(120)
if mode == "many_files":
    os.makedirs(os.path.join(src, "build", "apk"), exist_ok=True)
    for i in range(beh.get("count", 50)):
        open(os.path.join(src, "build", "apk", "f%d" % i), "w").write("x")
    open(os.path.join(REC, "started"), "w").write("1")
    time.sleep(120)
if mode == "log":
    for i in range(beh.get("lines", 4000)):
        print("I: baris %06d %s" % (i, beh.get("padline", "y" * 60)))
    print("I: BARIS-TERAKHIR")
def sub(t):
    return t.replace("{SRC}", src).replace("{BUILD}", os.path.dirname(out)).replace("{HOME}", os.environ["HOME"])


if mode == "stack":
    print("Exception in thread main brut.androlib.exceptions.AndrolibException: boom di " + src + "/res/values/strings.xml")
    for i in range(30):
        print("\tat brut.androlib.Foo.bar(Foo.java:%d)" % i)
    print("\t... 12 more")
    print(sub("W: lihat work/5/apktool/res/x.xml dan {HOME}/.local dan smali/com/x/work/Foo.smali dan /data/work/5 dan /tmp/lain"))
    sys.exit(beh.get("rc", 1))
if mode == "fail":
    if beh.get("partial"):
        open(out, "wb").write(b"separuh")
    print(sub(beh.get("text", "Gagal tiruan")))
    sys.exit(beh.get("rc", 1))
if mode == "noout":
    sys.exit(0)
if mode == "empty":
    open(out, "wb").close()
    sys.exit(0)
if mode == "symlink":
    os.symlink("/etc/hostname", out)
    sys.exit(0)
if mode == "fifo":
    os.mkfifo(out)
    sys.exit(0)
if mode == "dir":
    os.mkdir(out)
    sys.exit(0)
payload = b"PK-apk-palsu:" + json.dumps(sorted(files.items())).encode()
open(out, "wb").write(payload + b"\0" * beh.get("pad", 0))
print("I: Building apk file...")
sys.exit(0)
'''


# aapt2 PALSU (Tahap 5, badging): keluaran bentuk `aapt2 dump badging`, perilaku diatur lewat REC/aapt.json (mode ok|nopackage|fail|sleep|flood).
BADGING_TEXT = ("package: name='com.contoh.app' versionCode='7' versionName='1.2.3' platformBuildVersionName='14' platformBuildVersionCode='34' compileSdkVersion='34'\n"
                "sdkVersion:'21'\ntargetSdkVersion:'34'\nuses-permission: name='android.permission.INTERNET'\nlaunchable-activity: name='com.contoh.Main'\n")
FAKE_AAPT2 = r'''#!@PY@
import json, os, sys, time
REC = @REC@
try:
    beh = json.load(open(os.path.join(REC, "aapt.json")))
except OSError:
    beh = {}
with open(os.path.join(REC, "aapt_calls.jsonl"), "a") as fh:
    fh.write(json.dumps({"argv": sys.argv[1:], "cwd": os.getcwd(), "env": dict(os.environ), "apk_exists": os.path.isfile(sys.argv[-1])}) + "\n")
mode = beh.get("mode", "ok")
if mode == "fail":
    sys.stderr.write("aapt2: error: gagal membuka\n")
    sys.exit(1)
if mode == "sleep":
    time.sleep(300)
text = beh.get("text", @TEXT@)
if mode == "nopackage":
    text = "sdkVersion:'21'\n"
sys.stdout.write(text)
sys.stdout.flush()
if mode == "flood":
    line = ("uses-permission: name='" + "x" * 200 + "'\n").encode()
    out = sys.stdout.buffer
    for _ in range(40000):
        out.write(line)
    out.flush()
'''


def load_daemon(monkeypatch, data: Path, **env):
    monkeypatch.setenv("DATA_DIR", str(data))
    monkeypatch.setenv("TOOL_HOME_ROOT", str(data.parent / "toolhome"))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    name = f"runner_daemon_under_test_{len(sys.modules)}"
    loader = importlib.machinery.SourceFileLoader(name, str(DAEMON))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class Clock:
    """Jam palsu yang bisa dimajukan; dipakai bersama `treediff._clock` agar tenggat langkah salin/hash teruji tanpa menunggu."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def rig(tmp_path, monkeypatch):
    data = tmp_path / "data"
    rec, bindir = tmp_path / "rec", tmp_path / "bin"
    for p in (rec, bindir):
        p.mkdir()
    (bindir / "apktool").write_text(FAKE_APKTOOL.replace("@PY@", sys.executable).replace("@REC@", repr(str(rec))))
    (bindir / "apktool").chmod(0o755)
    (bindir / "aapt2").write_text(FAKE_AAPT2.replace("@PY@", sys.executable).replace("@REC@", repr(str(rec))).replace("@TEXT@", repr(BADGING_TEXT)))
    (bindir / "aapt2").chmod(0o755)
    layout = Layout(data)
    base = mktree(layout.base_tree(AID), BASE_FILES)
    project = mktree(layout.project_dir(AID), {**BASE_FILES, **EDIT})
    build_dir = layout.build_dir(AID, BID)
    build_dir.mkdir(parents=True)
    daemon = load_daemon(monkeypatch, data)
    spool = Spool(data / "spool")
    spool.ensure_dirs()
    env = buildstage.Env(layout=layout, spool=spool, stop=threading.Event(), home_root=tmp_path / "toolhome", kill_group=daemon.kill_group, sweep_group=daemon.sweep_group,
                         pump_output=daemon.pump_output, max_output_bytes=3 * 1024 ** 3, max_output_files=600000, say=lambda m: None,
                         path_env=f"{bindir}:/usr/bin:/bin", tick=0.05, heartbeat_every=0.05, output_check_every=0.05, aapt2=str(bindir / "aapt2"))
    r = SimpleNamespace(tmp=tmp_path, data=data, rec=rec, bin=bindir, layout=layout, base=base, project=project, build_dir=build_dir, daemon=daemon, spool=spool, env=env)
    r.diff = lambda: treediff.compute_diff(base, project).diff_sha256
    r.behave = lambda **kw: (rec / "behavior.json").write_text(json.dumps(kw))
    r.aapt = lambda **kw: (rec / "aapt.json").write_text(json.dumps(kw))
    r.aapt_calls = lambda: [json.loads(ln) for ln in (rec / "aapt_calls.jsonl").read_text().splitlines()] if (rec / "aapt_calls.jsonl").exists() else []
    r.req = lambda **over: BuildRequest(over.pop("aid", AID), over.pop("bid", BID), over.pop("diff", None) or r.diff(), over.pop("sha", G), over.pop("timeout", 60))
    r.job_id = "a5-build-abcdef12"
    r.run = lambda **over: buildstage.run(env, r.job_id, r.req(**over))
    r.calls = lambda: [json.loads(ln) for ln in (rec / "calls.jsonl").read_text().splitlines()] if (rec / "calls.jsonl").exists() else []
    r.names = lambda: sorted(p.name for p in build_dir.iterdir())
    r.homes = lambda: sorted(p.name for p in (tmp_path / "toolhome").iterdir()) if (tmp_path / "toolhome").exists() else []
    return r


# ======================================================================================== allowlist argv
def test_apktool_argv_is_the_exact_allowlist_with_b_first():
    argv = buildstage.apktool_argv("/x/src", "/x/unsigned.apk")
    assert argv == ["apktool", "b", "-f", "-j", "2", "/x/src", "-o", "/x/unsigned.apk"] and argv[1] == "b"
    for forbidden in ("--copy-original", "--debuggable", "--net-sec-conf", "-p", "-l", "--aapt", "-a"):
        assert forbidden not in argv


def test_daemon_has_no_generic_build_command_for_the_build_stage(rig):
    d = rig.daemon
    with pytest.raises(ValueError):
        d.build_command("build", Path("/x.apk"), Path("/o"), False)
    assert d.build_command("apktool", Path("/x.apk"), Path("/o"), False)[0][:3] == ["apktool", "d", "-f"]       # tahap lama tak berubah
    assert d.tool_version("build") == d.tool_version("apktool")
    assert "build" in d.TOOL_STAGES


# ======================================================================================== alur sukses
def test_successful_build_runs_the_allowlisted_argv_on_a_snapshot_and_cleans_up(rig):
    res = rig.run()
    assert res["status"] == "ok" and "error_code" not in res and res["output_size"] > 0 and res["elapsed"] >= 0
    unsigned = rig.build_dir / "unsigned.apk"
    data = unsigned.read_bytes()
    assert res["output_sha256"] == hashlib.sha256(data).hexdigest() and res["output_size"] == len(data)
    (call,) = rig.calls()
    src = str(rig.build_dir / "src")
    assert call["argv"] == ["b", "-f", "-j", "2", src, "-o", str(unsigned)]
    assert call["pgid_is_leader"] is True, "apktool dijalankan di grup proses sendiri (start_new_session)"
    assert call["cwd"] == str(rig.tmp / "toolhome" / rig.job_id) and call["env"]["HOME"] == call["cwd"]
    assert set(call["env"]) <= {"PATH", "HOME", "LANG", "PYTHONDONTWRITEBYTECODE", "LC_CTYPE"}, "environment minimal seperti tahap lain"
    # snapshot = pohon yang disetujui (+ berkas jejak), bukan pohon hidup
    want = {rel: hashlib.sha256(text.encode()).hexdigest() for rel, text in {**BASE_FILES, **EDIT}.items()}
    got = {rel: h for rel, h in call["files"].items() if rel != "assets/reverse-apk-modified.txt"}
    assert got == want and "assets/reverse-apk-modified.txt" in call["files"]
    # pembersihan: src/ dan HOME hilang; unsigned.apk (untuk signer) dan build.log tinggal
    assert rig.names() == ["build.log", "unsigned.apk"] and rig.homes() == []
    assert res["files"] == len(want) and res["bytes"] == sum(len(t) for t in {**BASE_FILES, **EDIT}.values())
    assert res["peak_mem_mib"] is None or res["peak_mem_mib"] >= 0
    assert buildproto.parse_build_result(res)["ok"] is True


def test_result_passes_the_worker_side_normalizer_and_is_small(rig):
    res = rig.run()
    assert len(json.dumps(res).encode()) < buildproto.RESULT_MAX_BYTES
    parsed = buildproto.parse_build_result(res)
    assert parsed["ok"] and parsed["output_sha256"] == res["output_sha256"]


def test_trace_file_is_added_after_the_hash_check_with_five_fixed_lines(rig):
    res = rig.run()
    assert res["status"] == "ok"
    (call,) = rig.calls()
    lines = call["trace"].splitlines()
    assert len(lines) == 5 and lines[0].startswith("APK ini HASIL MODIFIKASI")
    assert lines[1] == f"asal_sha256={G}" and lines[2] == f"diff_sha256={rig.diff()}" and lines[3] == f"build={BID}" and lines[4].startswith("waktu_utc=")
    assert "reverse-apk-modified.txt" not in " ".join(p.name for p in rig.project.rglob("*")), "pohon proyek (milik AI) tidak disentuh"


def test_trace_overwrites_a_same_named_file_or_directory_planted_by_the_ai(rig):
    (rig.project / "assets").mkdir(exist_ok=True)
    (rig.project / "assets" / "reverse-apk-modified.txt").write_text("PALSU: tidak dimodifikasi\n")
    res = rig.run()
    assert res["status"] == "ok" and rig.calls()[0]["trace"].startswith("APK ini HASIL MODIFIKASI")
    (rig.rec / "calls.jsonl").unlink()
    (rig.project / "assets" / "reverse-apk-modified.txt").unlink()
    (rig.project / "assets" / "reverse-apk-modified.txt").mkdir()
    (rig.project / "assets" / "reverse-apk-modified.txt" / "x").write_text("x")
    res = rig.run()
    assert res["status"] == "ok" and rig.calls()[0]["trace"].startswith("APK ini HASIL MODIFIKASI")


def test_assets_that_is_a_regular_file_in_the_project_gives_snapshot_failed_and_apktool_never_runs(rig):
    shutil.rmtree(rig.project / "assets")
    (rig.project / "assets").write_text("saya berkas, bukan direktori")
    res = rig.run()
    assert (res["status"], res["error_code"]) == ("failed", "snapshot_failed") and rig.calls() == []
    assert rig.names() == ["build.log"] and rig.homes() == []


def test_project_with_symlink_fifo_and_apktool_output_dirs_hashes_like_the_bench_and_hides_the_dex_cache(rig):
    """D1 + A-16: `build/` dan `dist/` di akar (cache dex apktool), symlink, FIFO tidak masuk snapshot; hash sama dengan yang dihitung bench atas pohon hidup."""
    (rig.project / "build" / "apk").mkdir(parents=True)
    (rig.project / "build" / "apk" / "classes.dex").write_bytes(b"PLANTED-DEX")
    (rig.project / "dist").mkdir()
    (rig.project / "dist" / "lama.apk").write_bytes(b"x")
    os.symlink("/etc/passwd", rig.project / "res" / "pw")
    os.mkfifo(rig.project / "res" / "pipa")
    (rig.project / "res" / "hanya-symlink").mkdir()
    os.symlink("/etc/hostname", rig.project / "res" / "hanya-symlink" / "s")
    res = rig.run()
    assert res["status"] == "ok", res
    (call,) = rig.calls()
    assert "build" not in call["src_top"] and "dist" not in call["src_top"], "cache dex tidak boleh ikut ke snapshot yang dibangun"
    assert not any(k.startswith(("build/", "dist/")) or k in ("res/pw", "res/pipa") or "hanya-symlink" in k for k in call["files"]) and call["argv"][1] == "-f"


def test_the_live_tree_may_change_during_the_build_the_snapshot_is_what_gets_built(rig):
    """AI menulis ke ruang kerja SELAMA apktool berjalan: tidak memengaruhi apa yang dibangun (snapshot) dan tidak membuat build gagal."""
    live = rig.project / "res" / "values" / "strings.xml"
    rig.behave(mutate_live=[str(live), "SESUDAH snapshot\n"])
    res = rig.run()
    assert res["status"] == "ok" and live.read_text() == "SESUDAH snapshot\n"
    assert rig.calls()[0]["files"]["res/values/strings.xml"] == hashlib.sha256(EDIT["res/values/strings.xml"].encode()).hexdigest()


# ======================================================================================== workspace_changed (FR-9.40)
def test_workspace_changed_when_the_project_changed_after_approval_and_apktool_never_runs(rig):
    approved = rig.diff()
    (rig.project / "res" / "values" / "strings.xml").write_text("diubah SETELAH disetujui\n")
    res = rig.run(diff=approved)
    assert (res["status"], res["error_code"]) == ("failed", "workspace_changed") and "ajukan build baru" in res["error_text"]
    assert rig.calls() == [] and rig.names() == ["build.log"] and rig.homes() == []
    assert "hash diff tidak sama" in (rig.build_dir / "build.log").read_text()


def test_workspace_changed_when_only_the_base_tree_changed_f01(rig):
    """F-01: runner memasang `work` rw dan memproses APK hostile; dasar yang diubah antara request dan snapshot tidak boleh lolos dengan hash sama."""
    approved = rig.diff()
    (rig.base / "res" / "layout" / "main.xml").write_text("<LinearLayout android:id='dibelokkan'/>\n")
    res = rig.run(diff=approved)
    assert res["error_code"] == "workspace_changed" and rig.calls() == []


@pytest.mark.parametrize("mutate", [
    lambda p: (p / "smali/com/x/A.smali").write_text("baru\n"),                     # berkas diubah
    lambda p: (p / "smali/com/x/B.smali").write_text("baru\n"),                     # berkas ditambah
    lambda p: (p / "res/layout/main.xml").unlink(),                                  # berkas dihapus
    lambda p: (p / "res/kosong").mkdir(),                                            # direktori kosong ditambah
    lambda p: os.chmod(p / "res/layout/main.xml", 0o755),                            # bit x
])
def test_any_change_to_the_project_after_approval_is_caught(rig, mutate):
    approved = rig.diff()
    mutate(rig.project)
    assert rig.run(diff=approved)["error_code"] == "workspace_changed" and rig.calls() == []


def test_the_hash_is_recomputed_over_the_snapshot_not_the_live_tree(rig, monkeypatch):
    """Snapshot yang berbeda dari pohon hidup (disalin saat AI sedang menulis) harus gagal walau pohon hidup SAMA dengan yang disetujui."""
    real_copy = buildstage.treediff.copy_tree_safe

    def tampered(src, dst, limits, *, on_tick=None):
        stats = real_copy(src, dst, limits, on_tick=on_tick)
        (Path(dst) / "smali" / "com" / "x" / "A.smali").write_text("disusupi di snapshot\n")
        return stats

    monkeypatch.setattr(buildstage.treediff, "copy_tree_safe", tampered)
    res = rig.run()
    assert res["error_code"] == "workspace_changed" and rig.calls() == []
    # pohon hidup tidak berubah: bila yang dihitung pohon hidup, build ini akan lolos
    assert rig.diff() == rig.req().diff_sha256


def test_matching_hash_is_required_to_the_last_hex_digit(rig):
    h = rig.diff()
    for forged in (h[:-1] + ("0" if h[-1] != "0" else "1"), "0" * 64, h.upper()):
        assert rig.run(diff=forged)["error_code"] == "workspace_changed"
    assert rig.calls() == []


# ======================================================================================== prasyarat
def test_no_workspace_when_the_project_is_missing_or_a_symlink(rig, tmp_path):
    h = rig.diff()
    shutil.rmtree(rig.project)
    assert rig.run(diff=h)["error_code"] == "no_workspace"
    outside = mktree(tmp_path / "luar", BASE_FILES)
    rig.project.symlink_to(outside)
    assert rig.run(diff=h)["error_code"] == "no_workspace" and rig.calls() == []


def test_no_workspace_when_bench_aid_is_a_symlink(rig, tmp_path):
    h = rig.diff()
    real = rig.layout.bench / str(AID)
    moved = tmp_path / "dipindah"
    real.rename(moved)
    real.symlink_to(moved)
    assert rig.run(diff=h)["error_code"] == "no_workspace" and rig.calls() == []


def test_baseline_missing_when_the_base_tree_has_no_manifest_or_is_a_symlink(rig, tmp_path):
    h = rig.diff()
    (rig.base / "AndroidManifest.xml").unlink()
    assert rig.run(diff=h)["error_code"] == "baseline_missing"
    (rig.base / "AndroidManifest.xml").symlink_to("/etc/hostname")
    assert rig.run(diff=h)["error_code"] == "baseline_missing"
    (rig.base / "AndroidManifest.xml").unlink()
    (rig.base / "AndroidManifest.xml").write_text("<manifest/>")
    shutil.move(rig.base, tmp_path / "pindah")
    rig.base.symlink_to(tmp_path / "pindah")
    assert rig.run(diff=h)["error_code"] == "baseline_missing" and rig.calls() == []


def test_internal_error_when_the_build_folder_is_missing_or_a_symlink(rig, tmp_path):
    h = rig.diff()
    victim = mktree(tmp_path / "korban", {"penting": "x"})
    shutil.rmtree(rig.build_dir)
    assert rig.run(diff=h)["error_code"] == "internal"
    rig.build_dir.symlink_to(victim)
    res = rig.run(diff=h)
    assert res["error_code"] == "internal" and rig.calls() == [] and [p.name for p in victim.iterdir()] == ["penting"], "sasaran symlink tidak disentuh"


def test_aid_and_bid_come_from_integers_never_from_request_paths(rig):
    other = rig.layout.build_dir(6, 1)
    other.mkdir(parents=True)
    d = rig.daemon
    job = {"job_id": rig.job_id, "stage": "build", "analysis_id": AID, "build_id": BID, "diff_sha256": rig.diff(), "sha256": G, "timeout": 60,
           "path": str(other), "src": "/etc", "out": "/tmp/x", "output": "../../6/1"}
    monkey = d.build_env
    d.build_env = lambda: rig.env
    try:
        res = d.run_build_job(rig.job_id, job)
    finally:
        d.build_env = monkey
    assert res["status"] == "ok" and not list(other.iterdir()) and (rig.build_dir / "unsigned.apk").exists()


# ======================================================================================== disk
def test_no_space_is_checked_before_copying_or_building(rig, monkeypatch):
    size = sum(len(t) for t in {**BASE_FILES, **EDIT}.values())
    need = 2 * size + buildstage.RESERVE
    monkeypatch.setattr(buildstage.os, "statvfs", lambda _p: SimpleNamespace(f_bavail=need - 1, f_frsize=1))
    res = rig.run()
    assert (res["error_code"], res["status"]) == ("no_space", "failed") and "MiB" in res["error_text"] and rig.calls() == []
    assert rig.names() == ["build.log"], "tidak ada src/ yang sempat disalin"
    monkeypatch.setattr(buildstage.os, "statvfs", lambda _p: SimpleNamespace(f_bavail=need, f_frsize=1))
    assert rig.run()["status"] == "ok"


def test_tree_too_large_is_refused_before_copying(rig, monkeypatch):
    monkeypatch.setattr(buildstage, "Limits", lambda: treediff.Limits(max_total_bytes=10))
    res = rig.run()
    assert res["error_code"] == "tree_too_large" and rig.calls() == [] and rig.names() == ["build.log"]


@pytest.mark.parametrize("limits,code", [
    (treediff.Limits(max_entries=3), "tree_too_large"), (treediff.Limits(max_file_bytes=5), "tree_too_large"), (treediff.Limits(max_depth=1), "tree_too_large"),
])
def test_tree_limits_during_snapshot_become_tree_too_large(rig, monkeypatch, limits, code):
    monkeypatch.setattr(buildstage, "Limits", lambda: limits)
    monkeypatch.setattr(buildstage, "_check_disk", lambda *a, **k: None)
    res = rig.run()
    assert res["error_code"] == code and rig.calls() == [] and rig.names() == ["build.log"]


def test_unreadable_project_file_fails_closed(rig):
    if os.geteuid() == 0:
        pytest.skip("root mengabaikan izin; dibuktikan sebagai uid 10001 di tes proses nyata")
    diff = rig.diff()                                    # dihitung SEBELUM berkas dikunci (compute_diff juga gagal tertutup pada berkas tak terbaca)
    os.chmod(rig.project / "res" / "layout" / "main.xml", 0o000)
    res = rig.run(diff=diff)
    assert res["error_code"] == "tree_unreadable" and "res/layout/main.xml" in res["error_text"] and str(rig.tmp) not in res["error_text"]


# ======================================================================================== tenggat, pembatalan, penghentian
def test_deadline_covers_the_snapshot_step_not_only_apktool(rig, monkeypatch):
    clock = Clock()
    rig.env.clock = clock
    real_copy = buildstage.treediff.copy_tree_safe

    def slow_copy(src, dst, limits, *, on_tick=None):
        clock.t += 61                                   # menyalin "memakan" lebih dari batas 60 dtk
        return real_copy(src, dst, limits, on_tick=lambda: on_tick())

    monkeypatch.setattr(buildstage.treediff, "copy_tree_safe", slow_copy)
    monkeypatch.setattr(treediff, "_clock", clock)
    monkeypatch.setattr(buildstage, "_check_disk", lambda *a, **k: None)
    (rig.project / "res" / "besar.bin").write_bytes(os.urandom(70_000))
    monkeypatch.setattr(treediff, "TICK_ENTRIES", 1)
    said = []
    rig.env.say = said.append
    res = rig.run()
    assert (res["status"], res["error_code"]) == ("timeout", "timeout") and rig.calls() == [] and rig.names() == ["build.log"]
    assert not any("mulai:" in m for m in said), "apktool TIDAK PERNAH diluncurkan (bukan sekadar terbunuh sebelum sempat mencatat)"


def test_deadline_covers_the_recompute_step(rig, monkeypatch):
    approved = rig.diff()
    clock = Clock()
    rig.env.clock = clock
    real = buildstage.treediff.compute_diff

    def slow(base, work, limits=treediff.Limits(), *, on_tick=None, text_stats=True):
        clock.t += 61
        on_tick()
        return real(base, work, limits, on_tick=on_tick, text_stats=text_stats)

    monkeypatch.setattr(buildstage.treediff, "compute_diff", slow)
    said = []
    rig.env.say = said.append
    res = rig.run(diff=approved)
    assert res["status"] == "timeout" and rig.calls() == [] and not any("mulai:" in m for m in said)


def test_timeout_kills_the_whole_process_group_and_cleans_up(rig):
    rig.behave(mode="sleep")
    res = rig.run(timeout=1)
    assert (res["status"], res["error_code"]) == ("timeout", "timeout") and "batas waktu" in res["error_text"]
    pid = int((rig.rec / "gc.pid").read_text())
    time.sleep(0.2)
    assert not alive(pid), "cucu apktool ikut mati (kill group)"
    assert rig.names() == ["build.log"] and rig.homes() == []


def test_term_ignoring_apktool_is_sigkilled_after_the_grace(rig, monkeypatch):
    monkeypatch.setattr(rig.daemon, "TERM_GRACE", 0.3)
    rig.behave(mode="sleep", ignore_term=True)
    started = time.monotonic()
    res = rig.run(timeout=1)
    assert res["status"] == "timeout" and time.monotonic() - started < 20
    assert not alive(int((rig.rec / "gc.pid").read_text()))


def test_cancel_before_start_never_runs_apktool(rig):
    rig.spool.request_cancel(rig.job_id)
    res = rig.run()
    assert (res["status"], res["error_code"]) == ("cancelled", "cancelled") and rig.calls() == [] and rig.names() == ["build.log"]


def test_cancel_during_apktool_kills_the_group(rig):
    rig.behave(mode="sleep")
    threading.Timer(0.0, lambda: None).start()

    def cancel_when_started():
        end = time.monotonic() + 20
        while time.monotonic() < end and not (rig.rec / "started").exists():
            time.sleep(0.02)
        rig.spool.request_cancel(rig.job_id)

    t = threading.Thread(target=cancel_when_started, daemon=True)
    t.start()
    res = rig.run(timeout=60)
    t.join(5)
    assert (res["status"], res["error_code"]) == ("cancelled", "cancelled") and not alive(int((rig.rec / "gc.pid").read_text()))
    assert rig.names() == ["build.log"]


def test_stop_event_aborts_the_build_with_aborted(rig):
    rig.behave(mode="sleep")
    t = threading.Thread(target=lambda: ((time.sleep(0.3) if not (rig.rec / "started").exists() else None), rig.env.stop.set()), daemon=True)
    t.start()
    res = rig.run(timeout=60)
    assert (res["status"], res["error_code"]) == ("aborted", "aborted") and not alive(int((rig.rec / "gc.pid").read_text()))
    assert buildproto.parse_build_result(res)["error_code"] == "aborted"


def test_stop_before_apktool_is_aborted_not_cancelled(rig):
    """Runner dihentikan (SIGTERM) saat masih menyalin/menghitung: hasil `aborted`, bukan `cancelled` (pembatalan oleh pengguna)."""
    rig.env.stop.set()
    res = rig.run()
    assert (res["status"], res["error_code"]) == ("aborted", "aborted") and rig.calls() == [] and rig.names() == ["build.log"]


def test_heartbeat_is_written_at_least_every_five_seconds_while_apktool_runs(rig):
    beats = []
    real = rig.spool.write_heartbeat
    rig.spool.write_heartbeat = lambda state, job=None: (beats.append((state, job, time.monotonic())), real(state, job))[1]
    rig.env.heartbeat_every = 0.05
    rig.behave(mode="slow", seconds=0.6)
    assert rig.run()["status"] == "ok"
    assert len(beats) >= 5 and all(b[0] == "busy" and b[1] == rig.job_id for b in beats)
    gaps = [b2[2] - b1[2] for b1, b2 in zip(beats, beats[1:])]
    assert max(gaps) < 0.5


def test_default_heartbeat_interval_is_within_the_workers_staleness_budget():
    """A-07: worker menandai runner basi pada 45 dtk; detak build <= 5 dtk."""
    e = buildstage.Env.__dataclass_fields__
    assert e["heartbeat_every"].default <= 5.0 and e["tick"].default <= 0.5


# ======================================================================================== batas keluaran
def test_output_limit_counts_only_the_output_not_the_snapshot(rig):
    """Pohon sah yang lebih besar dari batas keluaran TIDAK gagal output_limit (snapshot sudah dibatasi treediff); tulisan apktool yang membanjir gagal."""
    rig.env.max_output_bytes = 1024 * 1024
    (rig.project / "assets" / "besar.bin").write_bytes(b"\0" * (3 * 1024 * 1024))
    rig.behave(mode="slow", seconds=0.4)
    res = rig.run()
    assert res["status"] == "ok", "snapshot 3 MiB > batas keluaran 1 MiB tetap lolos"


def test_output_limit_kills_a_flooding_apktool(rig):
    rig.env.max_output_bytes = 1024 * 1024
    rig.behave(mode="flood_build", bytes=5 * 1024 * 1024)
    started = time.monotonic()
    res = rig.run(timeout=60)
    assert (res["status"], res["error_code"]) == ("failed", "output_limit") and time.monotonic() - started < 30
    assert rig.names() == ["build.log"] and rig.homes() == []


def test_output_limit_by_file_count(rig):
    rig.env.max_output_files = 10
    rig.behave(mode="many_files", count=50)
    assert rig.run(timeout=60)["error_code"] == "output_limit"


def test_output_limit_counts_a_growing_unsigned_apk(rig):
    rig.env.max_output_bytes = 1024 * 1024
    rig.behave(mode="flood_out", bytes=4 * 1024 * 1024)
    res = rig.run(timeout=60)
    assert (res["status"], res["error_code"]) == ("failed", "output_limit") and not os.path.lexists(rig.build_dir / "unsigned.apk")


# ======================================================================================== hasil apktool
@pytest.mark.parametrize("mode", ["noout", "empty", "symlink", "fifo", "dir"])
def test_missing_empty_or_unsafe_output_is_no_output_and_never_hangs(rig, mode):
    rig.behave(mode=mode)
    res, exc = within_call(15, rig.run)
    assert exc is None and (res["status"], res["error_code"]) == ("failed", "no_output") and "output_sha256" not in res or res.get("output_sha256") is None
    assert not os.path.lexists(rig.build_dir / "unsigned.apk") and rig.names() == ["build.log"]


def test_a_stale_unsigned_apk_from_an_earlier_attempt_is_never_reported(rig):
    (rig.build_dir / "unsigned.apk").write_bytes(b"LAMA")
    (rig.build_dir / "src").mkdir()
    (rig.build_dir / "src" / "sisa").write_text("x")
    rig.behave(mode="noout")
    res = rig.run()
    assert res["error_code"] == "no_output" and rig.names() == ["build.log"]


def test_build_failure_gives_a_scrubbed_single_line_reason_and_removes_the_partial_apk(rig):
    rig.behave(mode="stack", rc=1)
    res = rig.run()
    assert (res["status"], res["error_code"]) == ("failed", "build_failed")
    text = res["error_text"]
    assert "\n" not in text and "/data" not in text and "\tat" not in text and len(text) <= 300
    assert "AndrolibException" in text and "<proyek>/res/values/strings.xml" in text, "jalur proyek relatif dipertahankan, akar disamarkan"
    log = (rig.build_dir / "build.log").read_text()
    assert "\tat brut" not in log and "... 12 more" not in log, "stack trace JVM dibuang seperti log jadx"
    assert "/data" not in log and str(rig.tmp) not in log and "work/5/apktool" not in log and "/tmp/lain" not in log
    assert "<home>/.local" in log and "<proyek>/res/values/strings.xml" in log
    assert "smali/com/x/work/Foo.smali" in log, "jalur proyek yang kebetulan memuat kata 'work' tidak ikut disamarkan"
    assert not os.path.lexists(rig.build_dir / "unsigned.apk") and rig.homes() == []
    assert buildproto.parse_build_result(res)["error_code"] == "build_failed"


def test_partial_output_on_failure_is_removed(rig):
    rig.behave(mode="fail", partial=True, text="Exception: gagal tiruan")
    res = rig.run()
    assert res["error_code"] == "build_failed" and res["error_text"] == "Exception: gagal tiruan" and rig.names() == ["build.log"]


def test_nonzero_exit_without_an_error_line_still_reports_the_code(rig):
    rig.behave(mode="fail", text="baris biasa saja", rc=3)
    assert "kode 3" in rig.run()["error_text"]


def test_scrub_covers_absolute_and_relative_paths_in_result_and_log_tail(rig):
    rig.behave(mode="fail", text="E: error di {SRC}/res/x.xml dan {BUILD}/unsigned.apk dan work/5/apktool/res/y.xml dan /opt/aapt-exec/aapt2 dan bench/5/project/z")
    res = rig.run()
    log = (rig.build_dir / "build.log").read_text()
    for blob in (res["error_text"], res["apktool_log_tail"], log):
        assert not any(frag in blob for frag in (str(rig.tmp), "/opt", "work/5", "bench/5")), blob
    assert "<proyek>/res/x.xml" in log and "<build>/unsigned.apk" in log and "<proyek>/res/x.xml" in res["error_text"]


def test_build_log_is_capped_at_64_kib_with_head_marker_and_tail(rig):
    rig.behave(mode="log", lines=4000)
    res = rig.run()
    assert res["status"] == "ok"
    data = (rig.build_dir / "build.log").read_bytes()
    assert len(data) <= 64 * 1024 and b"[dipotong]" in data
    text = data.decode()
    assert "baris 000000" in text and "BARIS-TERAKHIR" in text and "baris 002000" not in text
    assert len(res["apktool_log_tail"]) <= buildproto.LOG_TAIL_MAX and "BARIS-TERAKHIR" in res["apktool_log_tail"]
    assert len(json.dumps(res).encode()) < buildproto.RESULT_MAX_BYTES


def test_build_log_stays_within_64_kib_even_when_scrubbing_makes_the_text_longer(rig):
    """`db/1` (4 karakter) menjadi `<path>` (6): log yang disaring bisa lebih panjang dari log mentah, tetapi build.log TETAP <= 64 KiB dan akhir log (paling berguna) utuh."""
    rig.behave(mode="log", lines=1900, padline="db/1 " * 12)
    assert rig.run()["status"] == "ok"
    data = (rig.build_dir / "build.log").read_bytes()
    assert len(data) <= 64 * 1024 and data.rstrip().endswith(b"I: Building apk file...") and b"I: BARIS-TERAKHIR" in data
    assert b"db/1" not in data and b"<path>" in data and b"[dipotong]" in data and data.startswith(b"I: baris 000000"), "kepala dan penanda dipertahankan, ekor yang dipangkas dari awal"


def test_small_log_is_written_whole(rig):
    rig.run()
    assert (rig.build_dir / "build.log").read_text() == "I: Building apk file...\n"


def test_build_log_replaces_a_planted_symlink_without_following_it(rig, tmp_path):
    victim = tmp_path / "korban.txt"
    victim.write_text("jangan ditimpa")
    (rig.build_dir / "build.log").symlink_to(victim)
    rig.run()
    assert victim.read_text() == "jangan ditimpa" and not (rig.build_dir / "build.log").is_symlink()


def test_build_log_is_removed_before_being_rewritten_even_if_planted_as_a_directory(rig):
    (rig.build_dir / "build.log").mkdir()
    (rig.build_dir / "build.log" / "x").write_text("x")
    rig.run()
    assert (rig.build_dir / "build.log").is_file()


def test_unexpected_exception_in_a_step_becomes_internal_and_still_cleans_up(rig, monkeypatch):
    def boom(*a, **k):
        raise PermissionError(13, "ditolak")

    monkeypatch.setattr(buildstage, "_run_apktool", boom)
    res = rig.run()
    assert (res["status"], res["error_code"]) == ("failed", "internal") and rig.names() == ["build.log"] and rig.homes() == []


def test_enospc_during_the_build_maps_to_no_space(rig, monkeypatch):
    import errno

    monkeypatch.setattr(buildstage, "_run_apktool", lambda *a, **k: (_ for _ in ()).throw(OSError(errno.ENOSPC, "penuh")))
    assert rig.run()["error_code"] == "no_space"


def test_missing_apktool_binary_is_internal_not_a_crash(rig, monkeypatch):
    rig.env.path_env = "/nonexistent"
    res = rig.run()
    assert (res["status"], res["error_code"]) == ("failed", "internal") and rig.homes() == []


# ======================================================================================== cabang build di runner-daemon
def test_run_job_dispatches_build_before_any_apk_check(rig, monkeypatch):
    """Build tidak membaca uploads/: tanpa berkas APK dan tanpa work/<id> yang bisa ditulis pun tetap berjalan (cabang SEBELUM pemeriksaan APK)."""
    d = rig.daemon
    monkeypatch.setattr(d, "build_env", lambda: rig.env)
    assert not (rig.data / "uploads").exists()
    job = buildproto.build_build_request(AID, BID, rig.diff(), G, 60)
    res = d.run_job(job["job_id"], job)
    assert res["status"] == "ok" and (rig.build_dir / "unsigned.apk").exists()


def test_run_job_old_stages_still_validate_exactly_as_before(rig):
    d = rig.daemon
    res = d.run_job("a5-apktool-abcdef12", {"stage": "apktool", "analysis_id": 5, "sha256": "a" * 64, "timeout": 60})
    assert res["error_code"] == "tool_error" and "APK tidak ditemukan" in res["message"]
    res = d.run_job("a5-jadx-abcdef12", {"stage": "jadx", "analysis_id": 0, "sha256": "a" * 64, "timeout": 60})
    assert res["error_code"] == "bad_request"
    res = d.run_job("x", {"stage": "nonsense"})
    assert res["error_code"] == "bad_request"


@pytest.mark.parametrize("mut", [{"analysis_id": "5"}, {"build_id": 0}, {"diff_sha256": "x"}, {"sha256": None}, {"timeout": "9"}, {"analysis_id": 10 ** 9}])
def test_run_job_rejects_a_malformed_build_request_with_bad_request(rig, mut):
    job = {"job_id": rig.job_id, "stage": "build", "analysis_id": AID, "build_id": BID, "diff_sha256": rig.diff(), "sha256": G, "timeout": 60, **mut}
    res = rig.daemon.run_job(rig.job_id, job)
    assert res["status"] == "failed" and res["error_code"] == "bad_request" and rig.calls() == []
    assert buildproto.parse_build_result(res)["error_code"] == "bad_request"


def test_main_loop_failure_result_for_build_maps_to_internal(rig):
    """Jalur pengecualian `main` memakai error_code tool_error: pembaca worker memetakannya ke `internal` (A-11), bukan bad_result."""
    res = {"status": "failed", "error_code": "tool_error", "message": "galat internal runner: ValueError"}
    assert buildproto.parse_build_result(res)["error_code"] == "internal"
    orphan = {"status": "aborted", "error_code": "runner_restart", "message": "Runner dimulai ulang saat job berjalan."}
    assert buildproto.parse_build_result(orphan)["error_code"] == "aborted"


def test_build_loop_and_run_tool_loop_behave_the_same_for_timeout_and_cancel(rig, monkeypatch):
    """F-11: `_run_tool` tidak diubah dan loop pengawas build berdiri sendiri; keduanya harus memberi hasil yang sama pada kasus timeout/pembatalan yang sama
    (grup proses dibunuh, kode sama)."""
    d = rig.daemon
    old_bin = rig.tmp / "bin-old"
    old_bin.mkdir()
    (old_bin / "apktool").write_text(f"#!/bin/sh\nsleep 300 &\necho $! > {rig.rec}/gc_old.pid\ntouch {rig.rec}/started_old\nwait\n")
    (old_bin / "apktool").chmod(0o755)
    monkeypatch.setattr(d, "TOOL_HOME_ROOT", rig.tmp / "toolhome2")
    monkeypatch.setenv("PATH", f"{old_bin}:{os.environ['PATH']}")
    work = rig.layout.work_dir(99)                      # _run_tool menghapus work/<id>/apktool: JANGAN pakai pohon dasar milik tes ini
    work.mkdir(parents=True)
    rig.behave(mode="sleep")

    def run_old(timeout):
        (rig.rec / "gc_old.pid").unlink(missing_ok=True)
        return d._run_tool("a5-apktool-abcdef12", "apktool", False, timeout, Path("/dev/null"), work, time.monotonic())

    old = run_old(1)
    assert (old["status"], old["error_code"]) == ("timeout", "timeout")
    assert not alive(int((rig.rec / "gc_old.pid").read_text()))
    new = rig.run(timeout=1)
    assert (new["status"], new["error_code"]) == (old["status"], old["error_code"]) and not alive(int((rig.rec / "gc.pid").read_text()))
    # pembatalan: sinyal batal lebih dulu ada -> kedua loop menghentikan dan melapor 'cancelled'
    rig.spool.request_cancel("a5-apktool-abcdef12")
    old = run_old(30)
    rig.spool.request_cancel(rig.job_id)
    rig.behave(mode="sleep")
    new = rig.run(timeout=30)
    assert old["status"] == "cancelled" and new["status"] == "cancelled"


def alive(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


# ======================================================================================== DAEMON NYATA sebagai proses uid 10001 (unshare -m: bench bind READ-ONLY, tmpfs noexec/exec)
SH_APKTOOL = """#!/bin/sh
# apktool palsu (sh murni: environment alat runner dibersihkan, tanpa LD_LIBRARY_PATH untuk python pyenv). Merekam argv, uid, hasil percobaan menulis ke bench (ro), isi src.
REC=@REC@
echo "$@" > "$REC/argv.txt"
id -u > "$REC/uid.txt"
src="$5"; out="$7"
ls "$src" > "$REC/src_top.txt"
if (echo x > "@BENCH@/probe") 2>/dev/null; then echo RW > "$REC/bench_write.txt"; else echo EROFS > "$REC/bench_write.txt"; fi
cat "$src/assets/reverse-apk-modified.txt" > "$REC/trace.txt" 2>/dev/null
printf 'PK-fake-apk\n' > "$out"
echo "I: Building apk file..."
"""


def scratch_base() -> Path:
    """Folder sementara BUKAN di /tmp: namespace uji memasang tmpfs noexec di /tmp (seperti kontainer), jadi /tmp asli tersembunyi di dalamnya. Dicoba: $RV_TEST_SCRATCH,
    induk repositori, lalu folder di dalam repositori (dihapus di akhir); tidak ada yang bisa ditulis -> tes dilewati."""
    for cand in (os.environ.get("RV_TEST_SCRATCH"), str(ROOT.parent), str(ROOT / ".tmp-test")):
        if not cand:
            continue
        try:
            Path(cand).mkdir(parents=True, exist_ok=True)
            return Path(tempfile.mkdtemp(prefix="rv-runner-", dir=cand))
        except OSError:
            continue
    pytest.skip("tidak ada folder sementara di luar /tmp yang bisa ditulis")


@pytest.fixture
def procs(tmp_path_factory):
    base = open_to_10001(scratch_base())
    data = open_to_10001(base / "data")
    bench_src = open_to_10001(base / "bench-asli")                  # milik root; di-bind READ-ONLY ke data/bench
    for sub in ("uploads", "work", "bench", "builds", "spool"):
        open_to_10001(data / sub)
    layout = Layout(data)
    # pohon milik ROOT (bukan pemilik runner): mode 644/755 seperti hasil copy_tree_safe bench; bench bind ro
    mktree(layout.base_tree(AID), BASE_FILES)
    project_real = bench_src / str(AID) / "project"
    mktree(project_real, {**BASE_FILES, **EDIT})
    for dirpath, dirs, files in os.walk(base):
        for n in dirs:
            os.chmod(Path(dirpath) / n, 0o755)
        for n in files:
            os.chmod(Path(dirpath) / n, 0o644)
    bdir = data / "builds" / str(AID) / str(BID)
    bdir.mkdir(parents=True)
    for q in (data / "builds" / str(AID), bdir):
        os.chown(q, 10001, 10001)
    os.chown(data / "builds", 10001, 10001)
    toolhome, execdir, rec, tbin = (open_to_10001(base / n) for n in ("toolhome", "execdir", "rec", "bin"))
    os.chmod(rec, 0o777)
    spool_root = data / "spool"
    Spool(spool_root).ensure_dirs()
    for dp, dn, fn in os.walk(spool_root):
        os.chown(dp, 10001, 10001)
    diff = treediff.compute_diff(layout.base_tree(AID), project_real).diff_sha256
    ns = SimpleNamespace(base=base, data=data, bench_src=bench_src, bench_ro=data / "bench", layout=layout, bdir=bdir, toolhome=toolhome, execdir=execdir,
                         rec=rec, bin=tbin, spool=Spool(spool_root), diff=diff, project_real=project_real)
    yield ns
    subprocess.run(["umount", "-l", str(ns.bench_ro)], capture_output=True)
    shutil.rmtree(base, ignore_errors=True)


def run_real_daemon(p, *, job: dict, path_env: str, timeout: float = 180.0, fresh_env: dict | None = None) -> tuple[dict, str]:
    """Jalankan `runner-daemon` sebagai proses uid 10001 di `unshare -m` (bench = bind read-only, /tmp = tmpfs noexec seperti kontainer, execdir = tmpfs exec milik 10001),
    kirim satu job build lewat spool, tunggu hasil, hentikan daemon dengan SIGTERM. Mengembalikan (hasil, log)."""
    env = {"DATA_DIR": str(p.data), "TOOL_HOME_ROOT": "/tmp/home", "RUNNER_RECYCLE": "0", "PATH": path_env, "PYTHONUNBUFFERED": "1", **(fresh_env or {})}
    inner = " ".join(map(__import__("shlex").quote, as_user(env, str(DAEMON))))
    script = (f"set -e; mount --bind {p.bench_src} {p.bench_ro}; mount -o remount,bind,ro {p.bench_ro}; "
              f"mount -t tmpfs -o noexec,nosuid,size=256m,mode=1777 tmpfs /tmp; "
              f"mount -t tmpfs -o exec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0755 tmpfs {p.execdir}; "
              f"exec {inner}")
    proc = subprocess.Popen([UNSHARE, "-m", "sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    result = None
    try:
        end = time.monotonic() + 60
        while time.monotonic() < end and not (p.data / "spool" / "runner.hb").exists() and proc.poll() is None:
            time.sleep(0.1)
        if proc.poll() is not None:
            out = proc.stdout.read()
            if "mount" in out or "unshare" in out or "Operation not permitted" in out:
                pytest.skip(f"unshare/mount tidak diizinkan: {out.strip()[:150]}")
            pytest.fail(f"daemon berhenti sebelum siap: {out}")
        p.spool.submit(job)
        end = time.monotonic() + timeout
        res_path = p.spool.results / f"{job['job_id']}.json"
        while time.monotonic() < end and not res_path.exists():
            time.sleep(0.2)
        assert res_path.exists(), "tidak ada hasil dari daemon"
        result = json.loads(res_path.read_text())
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            log = proc.communicate(timeout=60)[0]
        except subprocess.TimeoutExpired:
            proc.kill()
            log = proc.communicate()[0]
    return result, log


def write_fake(p, text: str) -> None:
    (p.bin / "apktool").write_text(text.replace("@REC@", str(p.rec)).replace("@BENCH@", str(p.bench_ro)))
    os.chmod(p.bin / "apktool", 0o755)


@need_mount
def test_real_daemon_process_uid10001_builds_from_a_readonly_bench_bind_and_writes_builds(procs):
    write_fake(procs, SH_APKTOOL)
    job = buildproto.build_build_request(AID, BID, procs.diff, G, 60)
    res, log = run_real_daemon(procs, job=job, path_env=f"{procs.bin}:/usr/bin:/bin")
    assert res["status"] == "ok", (res, log)
    parsed = buildproto.parse_build_result(res)
    assert parsed["ok"] and parsed["output_size"] == len(b"PK-fake-apk\n")
    assert (procs.rec / "uid.txt").read_text().strip() == "10001"
    assert (procs.rec / "bench_write.txt").read_text().strip() == "EROFS", "bench dipasang READ-ONLY bagi runner"
    assert (procs.rec / "argv.txt").read_text().split()[:5] == ["b", "-f", "-j", "2", str(procs.bdir / "src")]
    assert (procs.rec / "trace.txt").read_text().startswith("APK ini HASIL MODIFIKASI")
    st = os.stat(procs.bdir / "unsigned.apk")
    assert st.st_uid == 10001 and stat.S_IMODE(st.st_mode) & 0o400
    assert sorted(q.name for q in procs.bdir.iterdir()) == ["build.log", "unsigned.apk"], "src/ dihapus"
    assert not (procs.bench_src / str(AID) / "probe").exists() and sorted(q.name for q in (procs.bench_src / str(AID)).iterdir()) == ["project"]
    assert "Traceback" not in log and "[job]" not in log


@need_mount
def test_real_daemon_process_workspace_changed_when_the_ro_project_differs_from_the_approved_hash(procs):
    write_fake(procs, SH_APKTOOL)
    job = buildproto.build_build_request(AID, BID, "0" * 64, G, 60)
    res, _log = run_real_daemon(procs, job=job, path_env=f"{procs.bin}:/usr/bin:/bin")
    assert (res["status"], res["error_code"]) == ("failed", "workspace_changed") and not (procs.rec / "argv.txt").exists()
    assert sorted(q.name for q in procs.bdir.iterdir()) == ["build.log"]


@need_mount
def test_real_daemon_process_unreadable_project_file_owned_by_root_mode600_fails_closed(procs):
    write_fake(procs, SH_APKTOOL)
    os.chmod(procs.project_real / "res" / "layout" / "main.xml", 0o600)          # milik root, bukan pemilik runner (uid 10001)
    job = buildproto.build_build_request(AID, BID, procs.diff, G, 60)
    res, _log = run_real_daemon(procs, job=job, path_env=f"{procs.bin}:/usr/bin:/bin")
    assert res["error_code"] == "tree_unreadable" and "res/layout/main.xml" in res["error_text"] and str(procs.base) not in res["error_text"]
    assert not (procs.rec / "argv.txt").exists()


@need_mount
def test_real_daemon_process_survives_a_bad_build_request_and_answers_it(procs):
    write_fake(procs, SH_APKTOOL)
    job = {"job_id": "a5-build-abcdef12", "stage": "build", "analysis_id": "../etc", "build_id": 7, "diff_sha256": procs.diff, "sha256": G, "timeout": 60, "path": "/etc"}
    res, log = run_real_daemon(procs, job=job, path_env=f"{procs.bin}:/usr/bin:/bin")
    assert res["error_code"] == "bad_request" and "Traceback" not in log


# ======================================================================================== apktool NYATA (lewat wrapper produksi)
REAL_ENV = ("BUILD_TEST_APKTOOL_JAR", "BUILD_TEST_AAPT2", "BUILD_TEST_JAVA_HOME")
APKTOOL_PIN = "dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423"
AAPT2_PIN = "df312db814c018019b2b79a993b041b738d7b76f4a8f28da25bc874a026368cc"
real_only = pytest.mark.skipif(not all(os.environ.get(v) for v in REAL_ENV), reason="apktool nyata tidak ada (set BUILD_TEST_APKTOOL_JAR, BUILD_TEST_AAPT2, BUILD_TEST_JAVA_HOME)")


def _sha(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def real_shim(bindir: Path, execdir: Path, tmp: Path) -> str:
    """`apktool` di PATH yang menjalankan WRAPPER PRODUKSI (services/runner/apktool-wrapper, `b` argumen pertama) dengan jalur alat sandbox. Mengembalikan PATH."""
    jar, aapt2 = os.environ["BUILD_TEST_APKTOOL_JAR"], os.environ["BUILD_TEST_AAPT2"]
    jdk = Path(os.path.realpath(os.environ["BUILD_TEST_JAVA_HOME"]))      # jalur nyata: JDK mise ada di bawah /root (tak terlintasi uid 10001) lewat symlink
    if _sha(jar) != APKTOOL_PIN or _sha(aapt2) != AAPT2_PIN:
        pytest.skip("hash jar apktool / aapt2 bukan pin Dockerfile")
    pin = tmp / "aapt2.sha256"
    pin.write_text(AAPT2_PIN + "\n")
    shim = bindir / "apktool"
    shim.write_text(f"#!/bin/sh\nexport APKTOOL_JAR={jar} AAPT2_PATH={aapt2} AAPT2_EXEC_DIR={execdir} AAPT2_PIN_FILE={pin}\nexec {ROOT}/services/runner/apktool-wrapper \"$@\"\n")
    shim.chmod(0o755)
    if not (bindir / "java").exists():
        (bindir / "java").symlink_to(jdk / "bin" / "java")            # PATH hanya berisi bindir + /usr/bin:/bin (pencarian PATH ke JDK di bawah /root tidak andal bagi uid 10001)
    return f"{bindir}:/usr/bin:/bin"


def sample_base(root: Path) -> Path:
    spec = importlib.util.spec_from_file_location("sample_apk_build", ROOT / "scripts" / "sample-apk" / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    root.mkdir(parents=True, exist_ok=True)
    mod.write_project(root)
    return root


def apktool_cli(rig, *args: str) -> None:
    r = subprocess.run(["apktool", *args], capture_output=True, text=True, timeout=600, env={"PATH": rig.env.path_env, "HOME": str(rig.tmp / "clihome"), "LANG": "C.UTF-8"})
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.fixture
def real(rig, tmp_path):
    """Baseline = hasil `apktool d` dari APK sampel (seperti analisis produksi), bukan proyek tulisan tangan; project = salinan baseline + satu string diubah."""
    execdir = tmp_path / "aapt-exec"
    execdir.mkdir()
    rig.env.path_env = real_shim(rig.bin, execdir, tmp_path)
    src = sample_base(tmp_path / "sample-src")
    (tmp_path / "clihome").mkdir()
    apktool_cli(rig, "b", "-f", str(src), "-o", str(tmp_path / "sample.apk"))
    shutil.rmtree(rig.base)
    shutil.rmtree(rig.project)
    apktool_cli(rig, "d", "-f", "-o", str(rig.base), str(tmp_path / "sample.apk"))
    shutil.copytree(rig.base, rig.project)
    sx = rig.project / "res" / "values" / "strings.xml"
    assert "VulnSample" in sx.read_text()
    sx.write_text(sx.read_text().replace("VulnSample", "TandaUnikModifikasi"))
    (rig.project / "assets").mkdir(exist_ok=True)
    (rig.project / "assets" / "extra.txt").write_text("tambahan\n")
    return rig


def decode(rig, apk: Path, out: Path) -> Path:
    apktool_cli(rig, "d", "-f", "-o", str(out), str(apk))
    return out


@real_only
def test_real_apktool_builds_the_snapshot_and_the_change_is_in_the_decoded_apk(real):
    res = real.run(timeout=600)
    assert res["status"] == "ok", res
    apk = real.build_dir / "unsigned.apk"
    assert zipfile_ok(apk) and res["output_sha256"] == hashlib.sha256(apk.read_bytes()).hexdigest()
    names = zipfile.ZipFile(apk).namelist()
    assert "assets/reverse-apk-modified.txt" in names and "assets/extra.txt" in names and "AndroidManifest.xml" in names
    out = decode(real, apk, real.tmp / "dec")
    strings = (out / "res" / "values" / "strings.xml").read_text()
    assert "TandaUnikModifikasi" in strings and "VulnSample" not in strings, "string baru ada, string lama tidak"
    assert (out / "assets" / "extra.txt").read_text() == "tambahan\n"
    trace = (out / "assets" / "reverse-apk-modified.txt").read_text().splitlines()
    assert trace[1] == f"asal_sha256={G}" and trace[2] == f"diff_sha256={real.diff()}"
    # berkas lain TIDAK berubah dibanding baseline (derau yang dikenal: apktool.yml, original/AndroidManifest.xml)
    changed = [rel for rel in BASE_RELS(real.base) if (out / rel).exists() and (real.base / rel).read_bytes() != (out / rel).read_bytes()]
    assert set(changed) <= {"apktool.yml", "res/values/strings.xml", "original/AndroidManifest.xml"}, changed
    assert real.names() == ["build.log", "unsigned.apk"] and real.homes() == []


def BASE_RELS(root: Path):
    return sorted(str(q.relative_to(root)) for q in root.rglob("*") if q.is_file())


def zipfile_ok(path: Path) -> bool:
    return zipfile.is_zipfile(path) and zipfile.ZipFile(path).testzip() is None



@real_only
def test_real_apktool_never_runs_when_the_workspace_changed_after_approval(real):
    approved = real.diff()
    (real.project / "res" / "values" / "strings.xml").write_text("<resources/>\n")
    res = real.run(diff=approved, timeout=600)
    assert res["error_code"] == "workspace_changed" and real.names() == ["build.log"]


@real_only
def test_real_apktool_does_not_reuse_a_planted_dex_cache_from_the_project_d1(real):
    """D1: `apktool b` tanpa -f memakai ulang build/apk/classes.dex yang sudah ada. build/ di akar tidak ikut snapshot dan runner selalu memakai -f."""
    (real.project / "build" / "apk").mkdir(parents=True)
    (real.project / "build" / "apk" / "classes.dex").write_bytes(b"PLANTED-DEX")
    res = real.run(timeout=600)
    assert res["status"] == "ok", res
    dex = zipfile.ZipFile(real.build_dir / "unsigned.apk").read("classes.dex")
    assert dex != b"PLANTED-DEX" and dex.startswith(b"dex\n"), "classes.dex hasil kompilasi smali, bukan cache yang ditanam"


@real_only
def test_real_apktool_failure_is_reported_with_a_scrubbed_reason_and_log(real):
    (real.project / "AndroidManifest.xml").write_text("<manifest><bukan-xml-valid")
    real.env.output_check_every = 60
    approved = treediff.compute_diff(real.base, real.project).diff_sha256
    res = real.run(diff=approved, timeout=600)
    assert (res["status"], res["error_code"]) == ("failed", "build_failed"), res
    assert not any(frag in json.dumps(res) for frag in (str(real.tmp), "/tmp/", "/projects/"))
    log = (real.build_dir / "build.log").read_text()
    assert log and str(real.tmp) not in log and not os.path.lexists(real.build_dir / "unsigned.apk")


@real_only
@need_mount
def test_real_daemon_process_uid10001_with_real_apktool_aapt2_on_exec_tmpfs_and_ro_bench(procs):
    """Gabungan paling dekat dengan kontainer yang bisa ditiru di sandbox: proses uid 10001, bench bind READ-ONLY, HOME di tmpfs NOEXEC, aapt2 disalin wrapper ke tmpfs
    EXEC milik 10001 (bukan /tmp), apktool NYATA 3.0.3, pohon milik root mode 644/755."""
    shutil.rmtree(procs.layout.base_tree(AID))
    sample_base(procs.layout.base_tree(AID))
    shutil.rmtree(procs.bench_src / str(AID))
    shutil.copytree(procs.layout.base_tree(AID), procs.bench_src / str(AID) / "project")
    sx = procs.bench_src / str(AID) / "project" / "res" / "values" / "strings.xml"
    sx.write_text(sx.read_text().replace("VulnSample", "TandaUnikDaemonNyata"))
    for dirpath, dirs, files in os.walk(procs.base):
        for n in dirs:
            os.chmod(Path(dirpath) / n, 0o755)
        for n in files:
            os.chmod(Path(dirpath) / n, 0o644)
    diff = treediff.compute_diff(procs.layout.base_tree(AID), procs.bench_src / str(AID) / "project").diff_sha256
    path_env = real_shim(procs.bin, procs.execdir, procs.base)
    job = buildproto.build_build_request(AID, BID, diff, G, 600)
    res, log = run_real_daemon(procs, job=job, path_env=path_env, timeout=420)
    assert res["status"] == "ok", (res, log, (procs.bdir / "build.log").read_text() if (procs.bdir / "build.log").exists() else "")
    apk = procs.bdir / "unsigned.apk"
    assert os.stat(apk).st_uid == 10001 and zipfile_ok(apk)
    assert res["output_sha256"] == hashlib.sha256(apk.read_bytes()).hexdigest()
    assert "Traceback" not in log


# ======================================================================================== runner-selftest bagian 7 (mount tahap build) dijalankan sungguhan
SELFTEST_SRC = (ROOT / "services" / "runner" / "runner-selftest").read_text(encoding="utf-8")
PRELUDE = "import os, sys\nfailed = False\ndef report(ok, name, detail=''):\n    print(('OK ' if ok else 'GAGAL ') + name + ' | ' + detail)\n"


def run_selftest_mounts(p, *, ro: bool, extra_dirs=(), builds_owner=10001) -> list[str]:
    section = SELFTEST_SRC.split("# 7. Mount tahap build", 1)[1].split("shutil.rmtree(work", 1)[0]
    (p.base / "mounts.py").write_text(PRELUDE + section)
    os.chmod(p.base / "mounts.py", 0o644)
    for name in extra_dirs:
        (p.data / name).mkdir(exist_ok=True)
    os.chown(p.data / "builds", builds_owner, builds_owner)
    inner = " ".join(map(__import__("shlex").quote, as_user({"DATA_DIR": str(p.data)}, str(p.base / "mounts.py"))))
    mounts = f"mount --bind {p.bench_src} {p.bench_ro}; mount -o remount,bind,ro {p.bench_ro}; " if ro else ""
    r = subprocess.run([UNSHARE, "-m", "sh", "-c", f"set -e; {mounts}exec {inner}"], capture_output=True, text=True, timeout=60)
    if r.returncode != 0 and ("mount" in r.stderr or "unshare" in r.stderr):
        pytest.skip(f"unshare/mount tidak diizinkan: {r.stderr.strip()[:120]}")
    return r.stdout.splitlines()


@need_mount
def test_runner_selftest_mount_checks_pass_for_the_intended_layout(procs):
    lines = run_selftest_mounts(procs, ro=True)
    assert len(lines) == 3 and all(ln.startswith("OK ") for ln in lines), lines


@need_mount
def test_runner_selftest_mount_checks_fail_for_a_writable_bench_forbidden_volumes_and_unwritable_builds(procs):
    bad = run_selftest_mounts(procs, ro=False)
    assert bad[0].startswith("GAGAL bench dipasang READ-ONLY"), bad
    bad = run_selftest_mounts(procs, ro=True, extra_dirs=("signspool", "signwork", "benchspool"))
    assert bad[2].startswith("GAGAL /data runner tanpa") and "signspool" in bad[2] and "signwork" in bad[2]
    bad = run_selftest_mounts(procs, ro=True, builds_owner=0)
    assert bad[1].startswith("GAGAL builds dapat ditulis") and "mkdir + chown 10001" in bad[1]


def test_runner_selftest_mount_section_is_static_correct():
    assert "# 7. Mount tahap build" in SELFTEST_SRC and SELFTEST_SRC.index("# 7. Mount tahap build") > SELFTEST_SRC.index("# 6c.")
    assert 'FORBIDDEN_VOLUMES = ("benchspool", "signspool", "signwork", "files", "db")' in SELFTEST_SRC
    assert SELFTEST_SRC.rstrip().endswith("sys.exit(1 if failed else 0)")


# ======================================================================================== badging (Tahap 5; FR-9.24 / FR-9.41)
REAL_BADGING = """package: name='com.contoh.app' versionCode='7' versionName='1.2.3' platformBuildVersionName='14' platformBuildVersionCode='34' compileSdkVersion='34' compileSdkVersionCodename='14'
sdkVersion:'21'
targetSdkVersion:'34'
uses-permission: name='android.permission.INTERNET'
application-label:'Contoh'
"""


def test_parse_badging_text_reads_package_versions_and_sdk_levels():
    got = buildstage.parse_badging_text(REAL_BADGING)
    assert got == {"package": "com.contoh.app", "version_code": 7, "version_name": "1.2.3", "min_sdk": 21, "target_sdk": 34}


def test_parse_badging_text_prefers_min_sdk_version_and_tolerates_preview_codenames_and_missing_lines():
    text = "package: name='a.b' versionCode='1'\nsdkVersion:'21'\nminSdkVersion:'24'\ntargetSdkVersion:'VanillaIceCream'\n"
    got = buildstage.parse_badging_text(text)
    assert got["min_sdk"] == 24 and got["target_sdk"] is None and got["version_name"] == ""
    assert buildstage.parse_badging_text("sdkVersion:'21'\n") is None
    assert buildstage.parse_badging_text("package: versionCode='1'\n") is None, "tanpa name"
    assert buildstage.parse_badging_text("") is None


def test_parse_badging_text_bounds_field_lengths_and_numbers():
    text = "package: name='" + "p" * 5000 + "' versionCode='99999999999999999999' versionName='" + "v" * 5000 + "'\n"
    got = buildstage.parse_badging_text(text)
    assert len(got["package"]) == buildstage.BADGING_FIELD_MAX and len(got["version_name"]) == buildstage.BADGING_FIELD_MAX and got["version_code"] is None


def test_successful_build_reports_badging_from_aapt2_on_the_unsigned_apk(rig):
    res = rig.run()
    assert res["status"] == "ok"
    assert res["badging"] == {"package": "com.contoh.app", "version_code": 7, "version_name": "1.2.3", "min_sdk": 21, "target_sdk": 34}
    (call,) = rig.aapt_calls()
    unsigned = str(rig.build_dir / "unsigned.apk")
    assert call["argv"] == ["dump", "badging", unsigned] and call["apk_exists"] is True
    assert call["cwd"] == str(rig.tmp / "toolhome" / rig.job_id) and call["env"]["HOME"] == call["cwd"]
    assert set(call["env"]) <= {"PATH", "HOME", "LANG", "LC_CTYPE"}, "environment minimal"
    parsed = buildproto.parse_build_result(res)
    assert parsed["ok"] and parsed["badging"]["package"] == "com.contoh.app" and rig.names() == ["build.log", "unsigned.apk"]


def test_aapt2_is_not_run_when_the_build_failed(rig):
    rig.behave(mode="fail")
    res = rig.run()
    assert res["status"] == "failed" and rig.aapt_calls() == []


@pytest.mark.parametrize("mode", ["fail", "nopackage"])
def test_unreadable_badging_is_null_and_does_not_fail_the_runner_stage(rig, mode):
    rig.aapt(mode=mode)
    res = rig.run()
    assert res["status"] == "ok" and res["badging"] is None, "worker yang memutuskan (FR-9.24); runner hanya melapor"
    assert buildproto.parse_build_result(res)["badging"] is None


def test_missing_aapt2_binary_gives_null_badging(rig):
    rig.env.aapt2 = str(rig.tmp / "tidak-ada" / "aapt2")
    res = rig.run()
    assert res["status"] == "ok" and res["badging"] is None


def test_hanging_aapt2_is_killed_at_the_badging_timeout(rig, monkeypatch):
    monkeypatch.setattr(buildstage, "BADGING_TIMEOUT", 0.6)
    rig.aapt(mode="sleep")
    t0 = time.monotonic()
    res = rig.run()
    assert res["status"] == "ok" and res["badging"] is None and time.monotonic() - t0 < 20


def test_flooding_aapt2_output_is_capped_and_still_parsed_from_the_head(rig, monkeypatch):
    monkeypatch.setattr(buildstage, "BADGING_MAX_BYTES", 64 * 1024)
    rig.aapt(mode="flood")
    res = rig.run()
    assert res["status"] == "ok" and res["badging"]["package"] == "com.contoh.app"
    assert len(json.dumps(res).encode()) < buildproto.RESULT_MAX_BYTES


def test_default_aapt2_is_the_pinned_rootfs_copy_not_the_runner_writable_tmpfs():
    env_default = buildstage.Env.__dataclass_fields__["aapt2"].default_factory()
    assert env_default == os.environ.get("AAPT2_PATH", "/opt/apktool/aapt2") and "/opt/aapt-exec" not in env_default
