"""signer-selftest bagian kunci pemilik, `--leak-scan`, `--watch` dan ringkasan (Tahap 2a, FEAT-004).

Semua tanpa Docker/root: /proc dan cgroup PALSU di folder sementara, keytool PALSU (skrip Python di PATH) untuk `check_keystore`. Satu tes dengan keytool
NYATA dilewati bersih bila SIGNER_TEST_JAVA_HOME tidak diset (CI tidak punya JDK 21 khusus). Sandi uji dibuat panjang (>= 16) karena pola yang lebih pendek
memang ditolak pemindai (positif palsu).
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from rvcore.signkeys import KeyStatus

ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "Rahasia-Sandi-Uji-0123456789-XYZ"
APK_ARGV = ["java", "-Xmx256m", "-jar", "/opt/build-tools/apksigner.jar", "sign", "--ks", "/run/secrets/signing_keystore",
            "--ks-pass", "file:/run/secrets/signing_keystore_pass", "--out", "/data/builds/1/2/.sign-signed.tmp", "/data/builds/1/2/.sign-aligned.tmp"]


def _selftest():
    path = str(ROOT / "services/signer/signer-selftest")
    loader = importlib.machinery.SourceFileLoader("signer_selftest_watch", path)
    spec = importlib.util.spec_from_loader("signer_selftest_watch", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture
def st():
    return _selftest()


# ================================================================================ /proc dan cgroup palsu
def add_proc(proc: Path, pid: int, argv: list[str], environ: dict[str, str] | None = None) -> None:
    d = proc / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
    (d / "environ").write_bytes(b"\0".join(f"{k}={v}".encode() for k, v in (environ or {"PATH": "/usr/bin"}).items()) + b"\0")


@pytest.fixture
def rig(tmp_path):
    proc, cg, tmp = tmp_path / "proc", tmp_path / "cgroup", tmp_path / "tmp"
    for d in (proc, cg, tmp):
        d.mkdir()
    add_proc(proc, 1, ["python3", "/usr/local/bin/signer-daemon"])
    return type("Rig", (), {"proc": proc, "cg": cg, "tmp": tmp, "stop": tmp_path / "stop", "pattern": PASSWORD.encode(), "path": tmp_path})()


def watch(st, rig, seconds=0.2, **kwargs):
    base = dict(pattern=rig.pattern, proc_root=str(rig.proc), cgroup_root=str(rig.cg), tmp_root=str(rig.tmp), stop_file=str(rig.stop), interval=0.01)
    base.update(kwargs)
    return st.watch(seconds, **base)


def test_watch_sees_apksigner_argv_without_password_and_reports_ok(st, rig):
    add_proc(rig.proc, 50, APK_ARGV)
    add_proc(rig.proc, 51, ["zipalign", "-P", "16", "-f", "4", "a", "b"])
    add_proc(rig.proc, 52, ["keytool", "-exportcert", "-storepass:file", "/run/secrets/signing_keystore_pass"])
    r = watch(st, rig)
    assert r["samples"] >= 1 and r["argv_apksigner"] >= 1 and r["argv_zipalign"] >= 1 and r["argv_keytool"] >= 1 and r["bocor"] == 0
    state, why = st.watch_verdict(r)
    assert state == "OK" and PASSWORD not in why


def test_watch_without_any_apksigner_sample_is_not_proven_rather_than_ok(st, rig):
    r = watch(st, rig)
    assert r["argv_apksigner"] == 0 and r["bocor"] == 0
    state, _ = st.watch_verdict(r)
    assert state == "tidak terbukti" and state != "OK"


@pytest.mark.parametrize("where", ["cmdline", "environ", "hsperfdata"])
def test_watch_detects_the_password_in_argv_environ_and_hsperfdata(st, rig, where):
    if where == "cmdline":
        add_proc(rig.proc, 60, APK_ARGV + ["--ks-pass", f"pass:{PASSWORD}"])
    elif where == "environ":
        add_proc(rig.proc, 60, APK_ARGV, {"PATH": "/usr/bin", "KS_PASS": PASSWORD})
    else:
        add_proc(rig.proc, 60, APK_ARGV)
        perf = rig.tmp / "hsperfdata_signer"
        perf.mkdir()
        (perf / "60").write_bytes(b"\x00\x01sun.rt.javaCommand=apksigner.jar sign pass:" + PASSWORD.encode() + b"\x00")
    r = watch(st, rig)
    assert r["bocor"] >= 1
    state, why = st.watch_verdict(r)
    assert state == "GAGAL" and PASSWORD not in why


def test_watch_hsperfdata_without_password_is_clean(st, rig):
    add_proc(rig.proc, 60, APK_ARGV)
    perf = rig.tmp / "hsperfdata_signer"
    perf.mkdir()
    (perf / "60").write_bytes(b"sun.rt.javaCommand=apksigner.jar sign --ks-pass file:/run/secrets/x")
    assert watch(st, rig)["bocor"] == 0


def test_watch_reads_memory_stat_and_oom_kill_delta_from_the_cgroup(st, rig):
    (rig.cg / "memory.stat").write_text(f"anon {100 * st.MIB}\nfile 5\nshmem {10 * st.MIB}\n")
    (rig.cg / "memory.events").write_text("low 0\nhigh 0\nmax 0\noom 0\noom_kill 3\n")
    (rig.cg / "memory.peak").write_text(f"{300 * st.MIB}\n")
    calls = []

    def sleeper(_):
        calls.append(1)
        if len(calls) == 1:                                    # sampel kedua: anon naik, satu OOM-kill baru
            (rig.cg / "memory.stat").write_text(f"anon {350 * st.MIB}\nshmem {20 * st.MIB}\n")
            (rig.cg / "memory.events").write_text("oom_kill 4\n")
        else:
            (rig.cg / "memory.stat").write_text(f"anon {50 * st.MIB}\nshmem 0\n")

    r = watch(st, rig, seconds=0.1, sleep=sleeper)
    assert r["anon_peak_mib"] == 370 and r["oom_kill"] == 1 and r["memory_peak"] == "300 MiB"


def test_watch_without_cgroup_files_reports_dash_and_unavailable(st, rig):
    r = watch(st, rig)
    assert (r["anon_peak_mib"], r["oom_kill"], r["memory_peak"]) == ("-", "-", "tidak tersedia")


def test_watch_stops_on_stop_file_quickly(st, rig):
    threading.Timer(0.3, lambda: rig.stop.write_text("")).start()
    started = time.monotonic()
    r = watch(st, rig, seconds=60)
    assert time.monotonic() - started < 2 and r["samples"] >= 1


def test_watch_stops_on_stdin_eof_quickly(st, rig):
    rfd, wfd = os.pipe()
    stream = os.fdopen(rfd, "rb")
    threading.Timer(0.3, lambda: os.close(wfd)).start()
    started = time.monotonic()
    try:
        r = watch(st, rig, seconds=60, stdin=stream)
    finally:
        stream.close()
    assert time.monotonic() - started < 2 and r["samples"] >= 1


def test_watch_keeps_running_while_stdin_is_open_and_stops_at_the_time_limit(st, rig):
    rfd, wfd = os.pipe()
    stream = os.fdopen(rfd, "rb")
    try:
        started = time.monotonic()
        r = watch(st, rig, seconds=0.3, stdin=stream)
        assert 0.25 <= time.monotonic() - started < 2 and r["samples"] >= 3
    finally:
        stream.close()
        os.close(wfd)


def test_watch_without_a_usable_stdin_ignores_it(st, rig):
    class NoFileno:
        def fileno(self):
            raise OSError("tidak ada fd")

    assert watch(st, rig, seconds=0.1, stdin=NoFileno())["samples"] >= 1


# ================================================================================ keluaran kunci=nilai
@pytest.fixture
def pwfile(tmp_path, monkeypatch, st):
    path = tmp_path / "signing_keystore_pass"
    path.write_text(PASSWORD + "\n")
    monkeypatch.setattr(st, "PASS_PATH", str(path))
    return path


def test_run_watch_prints_fixed_key_value_lines_without_json(st, rig, pwfile, capsys):
    add_proc(rig.proc, 50, APK_ARGV)
    rc = st.run_watch(0.1, pw_path=str(pwfile), proc_root=str(rig.proc), cgroup_root=str(rig.cg), tmp_root=str(rig.tmp), stop_file=str(rig.stop), interval=0.01)
    cap = capsys.readouterr()
    assert rc == 0
    keys = [ln.split("=", 1)[0] for ln in cap.out.splitlines()]
    assert keys == ["samples", "argv_apksigner", "argv_zipalign", "argv_keytool", "bocor", "anon_peak_mib", "oom_kill", "memory_peak"]
    assert all("=" in ln for ln in cap.out.splitlines()) and "{" not in cap.out and PASSWORD not in cap.out + cap.err
    assert dict(ln.split("=", 1) for ln in cap.out.splitlines())["bocor"] == "0"


def test_main_watch_uses_module_roots_and_argument_validation(st, rig, pwfile, monkeypatch, capsys):
    for name, value in (("PROC_ROOT", rig.proc), ("CGROUP_ROOT", rig.cg), ("TMP_ROOT", rig.tmp), ("STOP_FILE", rig.stop)):
        monkeypatch.setattr(st, name, str(value))
    rig.stop.write_text("")                                       # berhenti setelah sampel pertama
    assert st.main(["--watch", "30"]) == 0
    assert capsys.readouterr().out.startswith("samples=1\n")
    assert st.main(["--watch", "abc"]) == 64
    assert st.main(["--watch", "0"]) == 64
    assert st.main(["--watch", "5", "--leak-scan"]) == 64


def test_watch_and_leak_scan_refuse_missing_or_short_password(st, rig, tmp_path, capsys):
    assert st.run_leak_scan(str(rig.proc), str(tmp_path / "tidak-ada")) == 2
    short = tmp_path / "pendek"
    short.write_text("abc\n")
    assert st.run_leak_scan(str(rig.proc), str(short)) == 2
    assert st.run_watch(0.1, pw_path=str(short), proc_root=str(rig.proc)) == 2
    cap = capsys.readouterr()
    assert cap.out == "" and "abc" not in cap.err                 # tanpa kunci=nilai palsu, isi sandi tak dicetak


def test_leak_scan_clean_and_leaking_exit_codes(st, rig, pwfile, capsys):
    add_proc(rig.proc, 50, APK_ARGV)
    assert st.run_leak_scan(str(rig.proc), str(pwfile)) == 0
    out = capsys.readouterr().out
    assert out.splitlines() == ["diperiksa=4", "bocor=0"]
    add_proc(rig.proc, 51, ["x"], {"PATH": "/usr/bin", "LEAK": PASSWORD})
    add_proc(rig.proc, 52, ["tool", f"--pass={PASSWORD}"])
    assert st.run_leak_scan(str(rig.proc), str(pwfile)) == 1
    cap = capsys.readouterr()
    assert cap.out.splitlines() == ["diperiksa=8", "bocor=2"] and PASSWORD not in cap.out + cap.err
    assert "51/environ" in cap.err and "52/cmdline" in cap.err


def test_leak_scan_skips_unreadable_processes_without_counting_them(st, rig, pwfile, capsys):
    (rig.proc / "70").mkdir()                                     # tanpa environ/cmdline
    (rig.proc / "bukan-pid").mkdir()
    assert st.run_leak_scan(str(rig.proc), str(pwfile)) == 0
    assert capsys.readouterr().out.splitlines() == ["diperiksa=2", "bocor=0"]


# ================================================================================ check_keystore (keytool PALSU)
FAKE_KEYTOOL = """#!{py}
import hashlib, json, os, sys
cfg = json.load(open(os.environ["FAKE_KT_CFG"]))
args = sys.argv[1:]
with open(cfg["log"], "a") as f:
    f.write(json.dumps(args) + "\\n")
der = bytes.fromhex(cfg["der_hex"])
if "-exportcert" in args:
    if cfg["mode"] == "fail_export":
        sys.exit(1)
    sys.stdout.buffer.write(der)
    sys.exit(0)
if "-list" in args:
    if cfg["mode"] == "fail_list":
        print("keytool error: password was incorrect", file=sys.stderr)
        sys.exit(1)
    fp = hashlib.sha256(der if cfg["mode"] != "bad_fp" else b"lain").hexdigest().upper()
    fp = ":".join(fp[i:i + 2] for i in range(0, 64, 2))
    entry = "trustedCertEntry" if cfg["mode"] == "trusted" else "PrivateKeyEntry"
    print(f'''Alias name: reverse-apk
Entry type: {{entry}}
Certificate fingerprints:
\\t SHA1: 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33
\\t SHA256: {{fp}}''')
    sys.exit(0)
sys.exit(2)
"""


@pytest.fixture
def ks(tmp_path, monkeypatch, st):
    secrets = tmp_path / "run-secrets"
    secrets.mkdir()
    (secrets / "signing_keystore").write_bytes(b"P12-PALSU" * 20)
    (secrets / "signing_keystore_pass").write_text(PASSWORD + "\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    cfg = tmp_path / "kt.json"
    log = tmp_path / "kt.log"
    der = b"\x30\x82\x03\x00" + os.urandom(300)

    def configure(mode="ok"):
        cfg.write_text(json.dumps({"mode": mode, "der_hex": der.hex(), "log": str(log)}))

    kt = bindir / "keytool"
    kt.write_text(FAKE_KEYTOOL.format(py=sys.executable))
    kt.chmod(0o755)
    configure()
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_KT_CFG", str(cfg))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    st.failed = False
    st.counts.update(ok=0, gagal=0, skip=0)
    st.printed.clear()
    return type("Ks", (), {"dir": secrets, "configure": staticmethod(configure), "log": log, "der_sha": hashlib.sha256(der).hexdigest()})()


def output_of(capsys) -> str:
    return capsys.readouterr().out


def test_check_keystore_ok_with_two_way_fingerprint_and_no_password_in_output(st, ks, capsys):
    st.check_keystore(str(ks.dir))
    out = output_of(capsys)
    assert st.counts == {"ok": 5, "gagal": 0, "skip": 0} and not st.failed
    assert "PrivateKeyEntry" in out and ks.der_sha[:12] in out and ks.der_sha[:13] not in out.replace("…", "")
    assert "keluaran selftest tidak memuat kata sandi" in out and PASSWORD not in out
    calls = [json.loads(ln) for ln in ks.log.read_text().splitlines()]
    assert {a for c in calls for a in c if a.startswith("-storepass")} == {"-storepass:file"}
    assert all(PASSWORD not in " ".join(c) for c in calls)


def test_check_keystore_without_keystore_is_skipped_not_failed(st, tmp_path, ks, capsys):
    empty = tmp_path / "kosong"
    empty.mkdir()
    for target in (empty, tmp_path / "tidak-ada"):
        st.check_keystore(str(target))
    out = output_of(capsys)
    assert st.counts == {"ok": 0, "gagal": 0, "skip": 2} and not st.failed
    assert out.count("[ -- ] DILEWATI — tidak ada /run/secrets. Bila secrets/signing_keystore.p12 sudah ada di host, jalankan lewat 'make'") == 2
    assert "memuat docker-compose.keystore.yml" in out and "'make keystore' lalu 'make up'" in out


def test_check_keystore_fails_for_trusted_cert_entry(st, ks, capsys):
    ks.configure("trusted")
    st.check_keystore(str(ks.dir))
    out = output_of(capsys)
    assert st.failed and "[GAGAL] kunci pemilik: alias reverse-apk bertipe PrivateKeyEntry — tipe entri: trustedCertEntry" in out
    assert PASSWORD not in out


def test_check_keystore_fails_when_the_two_fingerprint_methods_disagree(st, ks, capsys):
    ks.configure("bad_fp")
    st.check_keystore(str(ks.dir))
    out = output_of(capsys)
    assert st.failed and "[GAGAL] kunci pemilik: sidik jari" in out


@pytest.mark.parametrize("mode,needle", [("fail_list", "keytool -list -v"), ("fail_export", "sidik jari")])
def test_check_keystore_fails_when_keytool_fails(st, ks, capsys, mode, needle):
    ks.configure(mode)
    st.check_keystore(str(ks.dir))
    out = output_of(capsys)
    assert st.failed and "[GAGAL]" in out and needle in out and PASSWORD not in out


def test_check_keystore_fails_when_the_password_file_is_missing(st, ks, capsys):
    (ks.dir / "signing_keystore_pass").unlink()
    st.check_keystore(str(ks.dir))
    out = output_of(capsys)
    assert st.failed and "[GAGAL] kunci pemilik: signing_keystore_pass" in out and "missing" in out
    assert not ks.log.exists(), "keytool tidak boleh dijalankan bila berkas kunci tidak lengkap"


def test_check_keystore_fails_for_a_symlinked_key_file(st, ks, capsys, tmp_path):
    real = tmp_path / "asli"
    real.write_bytes(b"x" * 300)
    (ks.dir / "signing_keystore").unlink()
    (ks.dir / "signing_keystore").symlink_to(real)
    st.check_keystore(str(ks.dir))
    out = output_of(capsys)
    assert st.failed and "symlink" in out


def test_check_keystore_unreadable_file_uses_the_describe_unreadable_text(st, ks, capsys, monkeypatch):
    unreadable = KeyStatus("unreadable", "mode 600 milik uid 1000. Di host jalankan: make keystore-access")
    real = st.inspect_key_file
    monkeypatch.setattr(st, "inspect_key_file", lambda path, *, kind, **kw: unreadable if kind == "pass" else real(path, kind=kind, **kw))
    st.check_keystore(str(ks.dir))
    assert st.failed and "make keystore-access" in output_of(capsys)


def test_check_keystore_detects_a_password_that_leaks_into_the_output(st, ks, capsys):
    st.printed.append(f"baris asing memuat {PASSWORD}")        # simulasi cek lain yang membocorkan sandi
    st.check_keystore(str(ks.dir))
    out = output_of(capsys)
    assert st.failed and "[GAGAL] keluaran selftest tidak memuat kata sandi" in out and PASSWORD not in out


def test_check_keystore_short_password_skips_the_leak_comparison(st, ks, capsys):
    (ks.dir / "signing_keystore_pass").write_text("pendek\n")
    st.check_keystore(str(ks.dir))
    out = output_of(capsys)
    assert st.counts["skip"] == 1 and "terlalu pendek" in out and "pendek\n" not in out.replace("terlalu pendek", "")


# ================================================================================ ringkasan dan jalur biasa
def test_main_toolchain_only_prints_summary_and_skips_keystore_when_absent(st, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert not os.path.exists("/run/secrets/signing_keystore"), "tes ini mengandaikan mesin uji tanpa keystore di /run/secrets"
    assert st.main(["--toolchain-only"]) == 1                      # alat hilang (PATH kosong) -> GAGAL; DILEWATI tidak ikut menggagalkan
    lines = capsys.readouterr().out.splitlines()
    assert lines[-1] == f"ringkasan: {st.counts['ok']} OK, {st.counts['gagal']} GAGAL, {st.counts['skip']} DILEWATI"
    assert st.counts["gagal"] >= 1 and st.counts["skip"] == 1
    assert any(ln.startswith("[ -- ] DILEWATI — tidak ada /run/secrets.") for ln in lines)


def test_summary_counts_skip_without_failing_the_exit_code(st, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(st, "check_tools", lambda: st.report(True, "alat", "ok"))
    monkeypatch.setattr(st, "check_toolchain", lambda: st.report(True, "rantai", "ok"))
    monkeypatch.setattr(st, "check_keystore", lambda *a: st.skip("tidak ada kunci"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert st.main(["--toolchain-only"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[-1] == "ringkasan: 2 OK, 0 GAGAL, 1 DILEWATI" and "[ -- ] DILEWATI — tidak ada kunci" in out


def test_summary_exit_code_is_1_only_when_something_failed(st, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(st, "check_tools", lambda: st.report(False, "alat", "hilang"))
    monkeypatch.setattr(st, "check_toolchain", lambda: None)
    monkeypatch.setattr(st, "check_keystore", lambda *a: None)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert st.main(["--toolchain-only"]) == 1
    assert capsys.readouterr().out.splitlines()[-1] == "ringkasan: 0 OK, 1 GAGAL, 0 DILEWATI"


def test_watch_and_leak_scan_are_not_part_of_the_plain_selftest_recipe():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    recipe = makefile.split("\nsigner-selftest:", 1)[1].split("\n\n", 1)[0]
    assert "--watch" not in recipe and "--leak-scan" not in recipe
    verify = (ROOT / "scripts/signer-verify.sh").read_text(encoding="utf-8")
    assert "signer-selftest --watch" in verify and "signer-selftest --leak-scan" in verify


def test_prune_is_exactly_the_documented_tuple(st):
    assert st.PRUNE == ("/proc", "/sys", "/dev", "/tmp", "/run/secrets", "/data")


# ================================================================================ NYATA (JDK 21 + keytool asli)
needs_real_jdk = pytest.mark.skipif(not os.environ.get("SIGNER_TEST_JAVA_HOME"), reason="JDK nyata tidak ada (set SIGNER_TEST_JAVA_HOME)")


@needs_real_jdk
def test_real_check_keystore_with_a_real_pkcs12_owner_key_and_a_trusted_cert(st, tmp_path, monkeypatch, capsys):
    jh = Path(os.environ["SIGNER_TEST_JAVA_HOME"])
    kt = str(jh / "bin" / "keytool")
    home = tmp_path / "home"
    home.mkdir()
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8"}
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    pw = os.urandom(32).hex()
    (secrets / "signing_keystore_pass").write_text(pw + "\n")
    subprocess.run([kt, "-genkeypair", "-keystore", str(secrets / "signing_keystore"), "-storetype", "PKCS12", "-alias", "reverse-apk", "-keyalg", "RSA",
                    "-keysize", "2048", "-validity", "30", "-dname", "CN=selftest-nyata", "-storepass:file", str(secrets / "signing_keystore_pass")],
                   check=True, capture_output=True, env=env, timeout=180)
    monkeypatch.setenv("PATH", f"{jh / 'bin'}{os.pathsep}/usr/bin:/bin")
    monkeypatch.setenv("HOME", str(home))
    st.check_keystore(str(secrets))
    out = capsys.readouterr().out
    assert st.counts == {"ok": 5, "gagal": 0, "skip": 0}, out
    assert "PrivateKeyEntry" in out and pw not in out
    der = subprocess.run([kt, "-exportcert", "-alias", "reverse-apk", "-keystore", str(secrets / "signing_keystore"), "-storetype", "PKCS12",
                          "-storepass:file", str(secrets / "signing_keystore_pass")], check=True, capture_output=True, env=env, timeout=60).stdout
    assert hashlib.sha256(der).hexdigest()[:12] in out
    # Entri sertifikat tepercaya (tanpa kunci privat) HARUS gagal di cek tipe entri.
    cert = tmp_path / "cert.der"
    cert.write_bytes(der)
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / "signing_keystore_pass").write_text(pw + "\n")
    subprocess.run([kt, "-importcert", "-noprompt", "-keystore", str(trusted / "signing_keystore"), "-storetype", "PKCS12", "-alias", "reverse-apk",
                    "-file", str(cert), "-storepass:file", str(trusted / "signing_keystore_pass")], check=True, capture_output=True, env=env, timeout=180)
    st.counts.update(ok=0, gagal=0, skip=0)
    st.failed = False
    st.printed.clear()
    st.check_keystore(str(trusted))
    out = capsys.readouterr().out
    assert st.failed and "trustedCertEntry" in out and pw not in out


# ================================================================================ --check-apk (Tahap 2b, FEAT G)
# Alat PALSU (skrip sh di PATH); yang diuji adalah logika selftest: validasi argumen, pembukaan berkas lewat rantai-dirfd (tanpa symlink/FIFO), keluaran kunci=nilai yang
# stabil, deteksi berkas yang ditukar saat alat berjalan, dan jalannya sebagai uid 10001 pada pohon berizin ketat. Alat NYATA (apksigner/zipalign) hanya di VPS/e2e.
CHECK_KEYS = ["signers", "v2", "v3", "cert", "zipalign", "sha", "size"]
CERT_A = hashlib.sha256(b"cert-a").hexdigest()
CERT_B = hashlib.sha256(b"cert-b").hexdigest()

FAKE_APKSIGNER = """#!/bin/sh
echo "apksigner $*" >> "$FAKE_LOG"
cat "$FAKE_VERIFY_OUT"
[ -n "$FAKE_SLEEP" ] && sleep "$FAKE_SLEEP"
exit "${FAKE_VERIFY_RC:-0}"
"""
FAKE_ZIPALIGN = """#!/bin/sh
echo "zipalign $*" >> "$FAKE_LOG"
for a; do last=$a; done
[ -n "$FAKE_SWAP" ] && mv "$FAKE_SWAP" "$last"
exit "${FAKE_ZIPALIGN_RC:-0}"
"""


def verify_out(digests=(CERT_A,), v1=False, v2=True, v3=True, signers=None) -> str:
    lines = ["Verifies", f"Verified using v1 scheme (JAR signing): {str(v1).lower()}", f"Verified using v2 scheme (APK Signature Scheme v2): {str(v2).lower()}",
             f"Verified using v3 scheme (APK Signature Scheme v3): {str(v3).lower()}", f"Number of signers: {len(digests) if signers is None else signers}"]
    for i, dig in enumerate(digests, 1):
        lines += [f"Signer #{i} certificate DN: CN=reverse-apk", f"Signer #{i} certificate SHA-256 digest: {dig.upper()}", f"Signer #{i} public key SHA-256 digest: {CERT_B}"]
    return "\n".join(lines) + "\n"


class CheckRig:
    def __init__(self, tmp_path, monkeypatch, st):
        self.st = st
        self.root = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        for name, body in (("apksigner", FAKE_APKSIGNER), ("zipalign", FAKE_ZIPALIGN)):
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        self.builds = tmp_path / "data" / "builds"
        self.dir = self.builds / "5" / "9"
        self.dir.mkdir(parents=True)
        self.name = "app-modified-9.apk"
        self.data = b"PK\x03\x04" + b"isi-apk-uji" * 50
        (self.dir / self.name).write_bytes(self.data)
        self.log = tmp_path / "tools.log"
        self.out = tmp_path / "verify.out"
        self.out.write_text(verify_out())
        for k, v in (("PATH", f"{self.bin}{os.pathsep}{os.environ['PATH']}"), ("FAKE_LOG", str(self.log)), ("FAKE_VERIFY_OUT", str(self.out))):
            monkeypatch.setenv(k, v)
        for k in ("FAKE_VERIFY_RC", "FAKE_ZIPALIGN_RC", "FAKE_SWAP", "FAKE_SLEEP"):
            monkeypatch.delenv(k, raising=False)
        self.mp = monkeypatch

    def run(self, aid="5", bid="9", name=None, capsys=None):
        rc = self.st.run_check_apk([aid, bid, self.name if name is None else name], builds_root=str(self.builds))
        out = capsys.readouterr() if capsys else None
        return rc, out

    def tools_called(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []


@pytest.fixture
def ck(tmp_path, monkeypatch, st):
    return CheckRig(tmp_path, monkeypatch, st)


def kvs(text: str) -> dict[str, str]:
    return dict(ln.split("=", 1) for ln in text.splitlines() if "=" in ln)


def test_check_apk_happy_path_prints_exactly_the_documented_keys_in_order(ck, capsys):
    rc, cap = ck.run(capsys=capsys)
    assert rc == 0, cap.out + cap.err
    lines = cap.out.strip().splitlines()
    assert [ln.split("=", 1)[0] for ln in lines] == CHECK_KEYS
    got = kvs(cap.out)
    assert got == {"signers": "1", "v2": "1", "v3": "1", "cert": CERT_A, "zipalign": "ok", "sha": hashlib.sha256(ck.data).hexdigest(), "size": str(len(ck.data))}
    assert cap.err == ""


def test_check_apk_runs_the_same_tool_commands_as_the_daemon(ck, capsys):
    ck.run(capsys=capsys)
    path = str(ck.dir / ck.name)
    assert ck.tools_called() == [f"zipalign -c -P 16 4 {path}", f"apksigner verify --verbose --print-certs {path}"]


def test_check_apk_reports_multiple_signers_without_judging_them(ck, capsys):
    ck.out.write_text(verify_out(digests=(CERT_B, CERT_A)))
    rc, cap = ck.run(capsys=capsys)
    got = kvs(cap.out)
    assert rc == 0 and got["signers"] == "2" and got["cert"] == ",".join(sorted([CERT_A, CERT_B]))


def test_check_apk_reports_missing_schemes_as_zero(ck, capsys):
    ck.out.write_text(verify_out(v2=False, v3=False, v1=True))
    rc, cap = ck.run(capsys=capsys)
    got = kvs(cap.out)
    assert rc == 0 and got["v2"] == "0" and got["v3"] == "0"


@pytest.mark.parametrize("bad", ["", "0", "-1", "+1", " 1", "1 ", "1.0", "01x", "1000000000", "99999999999999999999", "\u0661", "true", "١٢"])
def test_check_apk_rejects_non_integer_or_out_of_range_ids(ck, capsys, bad):
    for aid, bid in ((bad, "9"), ("5", bad)):
        rc, cap = ck.run(aid=aid, bid=bid, capsys=capsys)
        assert rc == 64, (aid, bid)
        assert cap.out == "" and cap.err.startswith("GALAT:")
    assert ck.tools_called() == []


@pytest.mark.parametrize("bad", ["", "../x.apk", ".tersembunyi.apk", "-rf", "a/b.apk", "a b.apk", "a" * 121, "é.apk", "x.apk\n", "x\x00.apk", "..", "."])
def test_check_apk_rejects_names_that_fail_the_output_name_regex(ck, capsys, bad):
    rc, cap = ck.run(name=bad, capsys=capsys)
    assert rc == 64
    assert cap.out == ""
    assert ck.tools_called() == []


def test_check_apk_name_regex_is_the_same_as_the_stores(st):
    from rvcore import store
    assert st.OUTPUT_NAME_RE.pattern == store._OUTPUT_NAME_RE.pattern


@pytest.mark.parametrize("args", [[], ["5"], ["5", "9"], ["5", "9", "a.apk", "extra"]])
def test_check_apk_needs_exactly_three_arguments(st, capsys, args):
    rc = st.main(["--check-apk", *args])
    assert rc == 64
    assert capsys.readouterr().out == ""


def test_check_apk_cannot_be_combined_with_the_other_modes(st, capsys):
    assert st.main(["--check-apk", "5", "9", "a.apk", "--watch"]) == 64
    assert st.main(["--leak-scan", "--check-apk", "5", "9", "a.apk"]) == 64


def test_check_apk_is_dispatched_by_main_and_skips_the_container_checks(ck, capsys, st):
    ck.mp.setattr(st, "DATA_DIR", str(ck.root / "data"))
    rc = st.main(["--check-apk", "5", "9", ck.name])
    assert rc == 0
    assert "ringkasan" not in capsys.readouterr().out


def test_check_apk_missing_file_is_a_stable_failure_without_running_tools(ck, capsys):
    rc, cap = ck.run(name="tidak-ada.apk", capsys=capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada"
    assert ck.tools_called() == []


def test_check_apk_missing_folder_is_a_stable_failure(ck, capsys):
    rc, cap = ck.run(aid="6", capsys=capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada"


def test_check_apk_never_follows_a_symlinked_name(ck, capsys):
    (ck.dir / "asli.apk").write_bytes(ck.data)
    (ck.dir / "tautan.apk").symlink_to("asli.apk")
    rc, cap = ck.run(name="tautan.apk", capsys=capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada"
    assert ck.tools_called() == []


def test_check_apk_never_follows_a_symlinked_build_folder(ck, capsys):
    other = ck.root / "lain"
    other.mkdir()
    (other / ck.name).write_bytes(ck.data)
    (ck.builds / "5" / "8").symlink_to(other)
    rc, cap = ck.run(bid="8", capsys=capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada"
    assert ck.tools_called() == []


def test_check_apk_never_follows_a_symlinked_analysis_folder(ck, capsys):
    other = ck.root / "lain2"
    (other / "9").mkdir(parents=True)
    (other / "9" / ck.name).write_bytes(ck.data)
    (ck.builds / "7").symlink_to(other)
    rc, cap = ck.run(aid="7", capsys=capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada"


def test_check_apk_fifo_does_not_hang_and_is_refused(ck, capsys):
    os.mkfifo(ck.dir / "fifo.apk")
    from conftest import within_call
    (rc, cap), exc = within_call(10, ck.run, name="fifo.apk", capsys=capsys)
    assert exc is None and rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada"


@pytest.mark.parametrize("kind", ["dir", "empty"])
def test_check_apk_refuses_directories_and_empty_files(ck, capsys, kind):
    if kind == "dir":
        (ck.dir / "folder.apk").mkdir()
    else:
        (ck.dir / "folder.apk").write_bytes(b"")
    rc, cap = ck.run(name="folder.apk", capsys=capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada"
    assert ck.tools_called() == []


def test_check_apk_failed_signature_check_is_exit_3_with_the_keys_still_printed(ck, capsys):
    ck.mp.setenv("FAKE_VERIFY_RC", "1")
    ck.out.write_text("DOES NOT VERIFY\n")
    rc, cap = ck.run(capsys=capsys)
    got = kvs(cap.out)
    assert rc == 3 and got["kode"] == "verify_gagal"
    assert got["v2"] == "0" and got["v3"] == "0" and got["signers"] == "-" and got["cert"] == "-"
    assert got["zipalign"] == "ok" and got["sha"] == hashlib.sha256(ck.data).hexdigest()


def test_check_apk_failed_alignment_check_is_exit_3(ck, capsys):
    ck.mp.setenv("FAKE_ZIPALIGN_RC", "1")
    rc, cap = ck.run(capsys=capsys)
    got = kvs(cap.out)
    assert rc == 3 and got["zipalign"] == "gagal" and got["kode"] == "zipalign_gagal"


def test_check_apk_unparseable_tool_output_is_not_a_pass(ck, capsys):
    ck.out.write_text("keluaran tak dikenal\n")
    rc, cap = ck.run(capsys=capsys)
    got = kvs(cap.out)
    assert got["v2"] == "0" and got["v3"] == "0" and got["signers"] == "-" and got["cert"] == "-"


def test_check_apk_detects_a_file_swapped_while_the_tools_ran(ck, capsys):
    (ck.dir / "pengganti.tmp").write_bytes(b"PK\x03\x04" + b"palsu" * 10)
    ck.mp.setenv("FAKE_SWAP", str(ck.dir / "pengganti.tmp"))
    rc, cap = ck.run(capsys=capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "berubah"


def test_check_apk_tool_timeout_is_a_stable_failure(ck, capsys):
    ck.mp.setattr(ck.st, "CHECK_TIMEOUT", 1)
    ck.mp.setenv("FAKE_SLEEP", "30")
    started = time.monotonic()
    rc, cap = ck.run(capsys=capsys)
    assert time.monotonic() - started < 20
    assert rc == 3 and kvs(cap.out)["kode"] == "alat_waktu_habis"


def test_check_apk_output_has_no_control_characters_and_no_secrets(ck, capsys):
    ck.out.write_text(verify_out() + "\x1b[31mmerah\x1b[0m\n")
    rc, cap = ck.run(capsys=capsys)
    assert all(ch.isprintable() or ch == "\n" for ch in cap.out)
    assert PASSWORD not in cap.out


def test_check_apk_hashes_in_chunks_without_loading_the_whole_file(ck, capsys):
    big = ck.dir / "besar-modified-9.apk"
    with open(big, "wb") as fh:
        fh.truncate(5 * 1024 * 1024)
        fh.seek(0)
        fh.write(b"PK\x03\x04")
    rc, cap = ck.run(name="besar-modified-9.apk", capsys=capsys)
    assert rc == 0
    assert kvs(cap.out)["size"] == str(5 * 1024 * 1024)
    assert kvs(cap.out)["sha"] == hashlib.sha256(big.read_bytes()).hexdigest()


def test_check_apk_unexpected_errors_become_kode_internal_without_a_traceback(ck, capsys):
    def boom(argv):
        raise RuntimeError("meledak")
    ck.mp.setattr(ck.st, "_run_tool", boom)
    rc, cap = ck.run(capsys=capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "internal" and "meledak" not in cap.out
    assert "Traceback" not in cap.out + cap.err


@pytest.mark.skipif(not __import__("conftest").CAN_DROP, reason="butuh root + setpriv (uid 10001)")
def test_check_apk_as_uid_10001_on_strict_modes_and_a_file_owned_by_another_uid(tmp_path):
    from conftest import ROOT as R, open_to_10001, as_user
    import tempfile, shutil as sh
    shared = open_to_10001(Path(tempfile.mkdtemp(prefix="rv-chk-")))
    try:
        os.chown(shared, 10001, 10001)
        bin_ = shared / "bin"
        bin_.mkdir()
        for name, body in (("apksigner", FAKE_APKSIGNER), ("zipalign", FAKE_ZIPALIGN)):
            (bin_ / name).write_text(body)
            (bin_ / name).chmod(0o755)
        (shared / "verify.out").write_text(verify_out())
        d = shared / "builds" / "5" / "9"
        d.mkdir(parents=True)
        for p in (shared / "builds", shared / "builds" / "5", d):
            os.chown(p, 10001, 10001)
            os.chmod(p, 0o700)
        mine, theirs = d / "app-modified-9.apk", d / "milik-lain.apk"
        mine.write_bytes(b"PK\x03\x04" + b"x" * 100)
        theirs.write_bytes(b"PK\x03\x04" + b"y" * 100)
        os.chown(mine, 10001, 10001)
        os.chmod(mine, 0o600)
        os.chmod(theirs, 0o600)                                   # milik root, mode 600: uid 10001 tidak boleh membukanya
        driver = ("import importlib.machinery as m, importlib.util as u, sys\n"
                  f"l = m.SourceFileLoader('st', {str(R / 'services/signer/signer-selftest')!r}); s = u.spec_from_loader('st', l); mod = u.module_from_spec(s); l.exec_module(mod)\n"
                  f"sys.exit(mod.run_check_apk([sys.argv[1], sys.argv[2], sys.argv[3]], builds_root={str(shared / 'builds')!r}))\n")
        env = {"PYTHONPATH": str(R / "services"), "PATH": f"{bin_}:/usr/bin:/bin", "FAKE_LOG": str(shared / "t.log"), "FAKE_VERIFY_OUT": str(shared / "verify.out"),
               "HOME": "/tmp"}
        ok = subprocess.run(as_user(env, "-c", driver, "5", "9", "app-modified-9.apk"), capture_output=True, text=True, timeout=60, cwd=str(shared))
        assert ok.returncode == 0, (ok.stdout, ok.stderr)
        assert kvs(ok.stdout)["signers"] == "1"
        bad = subprocess.run(as_user(env, "-c", driver, "5", "9", "milik-lain.apk"), capture_output=True, text=True, timeout=60, cwd=str(shared))
        assert bad.returncode == 3 and kvs(bad.stdout)["kode"] == "tidak_terbaca", (bad.stdout, bad.stderr)
        assert "Traceback" not in bad.stderr
    finally:
        sh.rmtree(shared, ignore_errors=True)
