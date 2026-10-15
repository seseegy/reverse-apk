"""scripts/signer-verify.sh (`make signer-verify`) dengan `docker` PALSU (Tahap 2a, FEAT-004).

Skrip dijalankan SUNGGUHAN (bash) pada pohon repo mini (salinan signer-verify.sh + keystore.sh, secrets/ dan testdata/ buatan tes). `docker` palsu di PATH
mencatat setiap panggilan (JSON per baris) dan membalas per subperintah dengan keluaran `kunci=nilai` / `HASIL ...` seperti signcheck.py, sehingga yang
diuji adalah LOGIKA skrip: urutan langkah, keputusan OK/GAGAL/DILEWATI, tabel, kode keluar, trap, kebocoran sandi. Yang TIDAK terbukti di sini: Docker/Compose
nyata, volume, healthcheck, `exec -T` meneruskan EOF stdin (V12): lihat verification.md.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_SRC = ROOT / "scripts/signer-verify.sh"
KS_SRC = ROOT / "scripts/keystore.sh"
AID = 2147483000
OWNER = hashlib.sha256(b"sertifikat pemilik").hexdigest()
OTHER = hashlib.sha256(b"sertifikat lain").hexdigest()
SHA = hashlib.sha256(b"signed.apk").hexdigest()
PW = "Pw-Uji-Signer-Verify-0123456789-abcdef"

LABELS = {
    1: "1 versi Compose", 2: "2 keystore ada", 3: "3 izin kunci host", 4: "4 bangun image", 5: "5 signer hidup & sehat", 6: "6 status daemon via spool",
    7: "7 sidik jari daemon = keystore.sh info", 8: "8 APK uji", 9: "9 taruh masukan", 10: "10 kirim job & tunggu", 11: "11 hasil koheren",
    12: "12 verifikasi independen", 13: "13 negatif: tanpa berkas", 14: "14 negatif: ZIP palsu", 15: "15 negatif: symlink",
    16: "16 negatif: request mentah traversal", 17: "17 APK besar (BIG_MB)", 18: "18 kebocoran sandi", 19: "19 memori", 20: "20 pembersihan",
}

FAKE_DOCKER = r'''#!@PY@
import glob, json, os, select, sys, time
cfg = json.load(open(@CFG@))
args = sys.argv[1:]
state = cfg["state"]
os.makedirs(state, exist_ok=True)


def log(entry):
    entry["argv"] = args
    entry["tmp_exists"] = bool(glob.glob(os.path.join(os.environ.get("TMPDIR", "/tmp"), "signer-verify.*")))
    with open(cfg["log"], "a") as f:
        f.write(json.dumps(entry) + "\n")


def counter(key):
    path = os.path.join(state, key.replace("/", "_").replace(":", "_") + ".n")
    n = int(open(path).read()) if os.path.exists(path) else 0
    open(path, "w").write(str(n + 1))
    return n


def reply(rc, out):
    if out:
        sys.stdout.write(out if out.endswith("\n") else out + "\n")
    sys.stdout.flush()
    sys.exit(rc)


def answer(key, entry):
    if isinstance(entry, dict) and "seq" in entry:
        seq = entry["seq"]
        entry = seq[min(counter("seq-" + key), len(seq) - 1)]
    if isinstance(entry, dict) and "sleep" in entry:
        open(entry["marker"], "w").write("mulai")
        time.sleep(entry["sleep"])
        entry = [0, ""]
    reply(entry[0], entry[1])


if args[:1] == ["inspect"]:
    log({"kind": "inspect"})
    what = args[2] if len(args) > 2 else ""
    reply(0, cfg["health_log"] if "Log" in " ".join(args) else cfg["health"])
if args[:1] != ["compose"]:
    log({"kind": "lain"})
    reply(97, "fake-docker: perintah tak dikenal")
rest = args[1:]
while rest and rest[0] == "--profile":
    rest = rest[2:]
cmd, rest = rest[0], rest[1:]
if cmd == "version":
    log({"kind": "version"})
    reply(*cfg["version"])
if cmd == "build":
    log({"kind": "build"})
    reply(*cfg["build"])
if cmd == "up":
    log({"kind": "up"})
    reply(*cfg["up"])
if cmd == "ps":
    log({"kind": "ps"})
    reply(0, cfg["cid"])
if cmd == "logs":
    log({"kind": "logs"})
    reply(0, cfg["logs"])
if cmd == "run":
    flags_diag = False
    while rest and rest[0].startswith("-"):
        if rest[0] == "-e":
            flags_diag = flags_diag or rest[1] == "SIGNCHECK_DIAG=1"
            rest = rest[2:]
        else:
            rest = rest[1:]
    service, rest = rest[0], rest[1:]
    if service == "signer":
        log({"kind": "verify-signer", "script": rest[2] if len(rest) > 2 else ""})
        reply(*cfg["signer_verify"])
    assert service == "worker", service
    sub = rest[2]
    sargs = rest[3:]
    key = sub if sub in ("status", "df") else (sub if sub == "clean" and len(sargs) == 1 else sub + ":" + sargs[1])
    stdin_bytes = None
    if sub in ("put", "put-big"):
        stdin_bytes = len(sys.stdin.buffer.read())
    log({"kind": "sc", "sub": sub, "key": key, "sargs": sargs, "diag": flags_diag, "stdin_bytes": stdin_bytes})
    entry = cfg["sc"].get(key)
    if entry is None:
        reply(99, "GALAT: fake-docker tidak punya jawaban untuk " + key)
    answer(key, entry)
if cmd == "exec":
    while rest and rest[0].startswith("-"):
        rest = rest[1:]
    service, rest = rest[0], rest[1:]
    stop = cfg["stopfile"]
    if rest[:2] == ["touch", "/tmp/selftest-watch.stop"]:
        log({"kind": "touch-stop"})
        open(stop, "w").write("")
        reply(0, "")
    if rest[:3] == ["rm", "-f", "/tmp/selftest-watch.stop"]:
        log({"kind": "rm-stop"})
        if os.path.exists(stop):
            os.unlink(stop)
        reply(0, "")
    if rest[:2] == ["signer-selftest", "--leak-scan"]:
        log({"kind": "leak-scan"})
        reply(*cfg["leak"])
    if rest[:2] == ["signer-selftest", "--watch"]:
        idx = counter("watch")
        log({"kind": "watch", "index": idx})
        open(os.path.join(state, "watch%d.started" % idx), "w").write("mulai")
        reason = "batas"
        end = time.monotonic() + 30
        while time.monotonic() < end:
            if os.path.exists(stop):
                reason = "stop"
                break
            ready, _, _ = select.select([0], [], [], 0.05)
            if ready and os.read(0, 4096) == b"":
                reason = "eof"
                break
        open(os.path.join(state, "watch%d.exit" % idx), "w").write(reason)
        watches = cfg["watches"]
        text = watches[idx] if idx < len(watches) else ""
        reply(0, text)
    log({"kind": "exec-lain"})
    reply(97, "fake-docker: exec tak dikenal")
log({"kind": "lain"})
reply(97, "fake-docker: tak dikenal")
'''

FAKE_KEYTOOL = """#!/bin/sh
cat <<'EOF'
Keystore type: PKCS12
Alias name: reverse-apk
Entry type: PrivateKeyEntry
Owner: CN=reverse-apk uji
Valid from: Mon Jan 05 10:00:00 UTC 2026 until: Thu Dec 28 10:00:00 UTC 2056
Certificate fingerprints:
	 SHA1: 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33
	 SHA256: {fp}
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 3072-bit RSA key
EOF
"""


def colon(hexstr: str) -> str:
    return ":".join(hexstr[i:i + 2].upper() for i in range(0, 64, 2))


def hasil(ok=True, code="-", cert=OWNER, sha=SHA, size=4321, v1=0, v2=1, v3=1, signers=1, elapsed="1.5") -> str:
    return (f"HASIL ok={1 if ok else 0} code={code} cert={cert if ok else '-'} sha={sha if ok else '-'} size={size if ok else 0} "
            f"v1={v1 if ok else '-'} v2={v2 if ok else 0} v3={v3 if ok else 0} signers={signers if ok else '-'} elapsed={elapsed}")


def watch_text(samples=500, apksigner=12, zipalign=3, keytool=4, bocor=0, anon=210, oom=0, peak="300 MiB") -> str:
    return (f"samples={samples}\nargv_apksigner={apksigner}\nargv_zipalign={zipalign}\nargv_keytool={keytool}\nbocor={bocor}\n"
            f"anon_peak_mib={anon}\noom_kill={oom}\nmemory_peak={peak}")


def verify_text(digests=(OWNER,), rcv=0, rca=0, sha=SHA, size=4321) -> str:
    lines = ["Verifies", "Verified using v1 scheme (JAR signing): false", "Verified using v2 scheme (APK Signature Scheme v2): true",
             "Verified using v3 scheme (APK Signature Scheme v3): true", "Number of signers: %d" % len(digests)]
    for i, dig in enumerate(digests, 1):
        lines += [f"Signer #{i} certificate DN: CN=reverse-apk uji", f"Signer #{i} certificate SHA-256 digest: {dig}",
                  f"Signer #{i} certificate SHA-1 digest: {'ab' * 20}", f"Signer #{i} public key SHA-256 digest: {OTHER}"]
    return "\n".join(lines + [f"rc_verify={rcv}", f"rc_align={rca}", f"sha={sha}", f"size={size}"])


def make_apk(path: Path, *, extra: dict[str, bytes] | None = None) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"manifest" * 30)
        zf.writestr("classes.dex", b"dex\n035\x00" * 20)
        for name, data in (extra or {}).items():
            zf.writestr(zipfile.ZipInfo(name), data, compress_type=zipfile.ZIP_STORED)
    return path.read_bytes()


def default_sc(apk_sha: str, apk_size: int) -> dict:
    return {
        "status": [0, f"hidup=1\numur_hb=1.2\nkeystore=ok\ncert_sha256={OWNER}\ndetail="],
        "clean": [0, "dibersihkan=1"], "clean:5": [0, "dibersihkan=1"], "clean:6": [0, "dibersihkan=1"], "clean:7": [0, "dibersihkan=1"],
        "df": [0, "bebas_mib=99999"],
        "put:1": [0, f"ditulis={apk_size}\nsha256={apk_sha}"],
        "sign:1": [0, hasil()],
        "sign:3": [0, hasil(ok=False, code="input_missing")],
        "put-garbage:2": [0, "ditulis=10"], "sign:2": [0, hasil(ok=False, code="align_failed")],
        "put-symlink:4": [0, "dibuat=symlink"], "sign:4": [0, hasil(ok=False, code="input_unsafe")],
        "bad-request:1": [0, hasil(ok=False, code="bad_request")],
        "put-big:5": [0, "ditulis=1\nentri=4"], "put-big:6": [0, "ditulis=1\nentri=60003"], "put-big:7": [0, "ditulis=1\nentri=60006"],
        "sign:5": [0, hasil()], "sign:6": [0, hasil()], "sign:7": [0, hasil()],
        "ls:1": [0, ""],
        "ls:2": {"seq": [[0, "unsigned.apk"], [0, ""]]},
        "ls:3": [0, ""], "ls:4": [0, ""],
        "ls:5": [0, ""], "ls:6": [0, ""], "ls:7": [0, ""],
    }


class Rig:
    def __init__(self, tmp_path: Path):
        self.root = tmp_path
        self.repo = tmp_path / "repo"
        self.bin = tmp_path / "bin"
        self.tmpdir = tmp_path / "tmp"
        self.state = tmp_path / "state"
        self.calls_log = tmp_path / "calls.jsonl"
        self.stopfile = tmp_path / "stopfile"
        for d in (self.repo / "scripts", self.bin, self.tmpdir):
            d.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SCRIPT_SRC, self.repo / "scripts/signer-verify.sh")
        shutil.copy2(KS_SRC, self.repo / "scripts/keystore.sh")
        (self.repo / "scripts/sample-apk").mkdir()
        (self.repo / "scripts/sample-apk/build.py").write_text(f"open({str(tmp_path / 'build-dipanggil')!r}, 'w').write('x')\n")
        secrets = self.repo / "secrets"
        secrets.mkdir()
        secrets.chmod(0o700)
        (secrets / "signing_keystore.p12").write_bytes(b"P12-PALSU" * 40)
        (secrets / "signing_keystore_pass").write_text(PW + "\n")
        for f in secrets.iterdir():
            f.chmod(0o644)
        self.apk = self.repo / "testdata/vulnsample.apk"
        data = make_apk(self.apk)
        kt = self.bin / "keytool"
        kt.write_text(FAKE_KEYTOOL.format(fp=colon(OWNER)))
        kt.chmod(0o755)
        self.cfg = {
            "log": str(self.calls_log), "state": str(self.state), "stopfile": str(self.stopfile), "version": [0, "v2.40.0"], "build": [0, ""], "up": [0, ""],
            "cid": "cid123", "health": "healthy", "health_log": "Health check gagal: keystore invalid: sandi salah\n", "logs": "signer siap (uid=10001)\n",
            "signer_verify": [0, verify_text()], "leak": [0, "diperiksa=40\nbocor=0"],
            "watches": [watch_text() for _ in range(4)],
            "sc": default_sc(hashlib.sha256(data).hexdigest(), len(data)),
        }
        self.write_docker()

    def write_docker(self):
        cfgp = self.root / "cfg.json"
        cfgp.write_text(json.dumps(self.cfg))
        docker = self.bin / "docker"
        docker.write_text(FAKE_DOCKER.replace("@PY@", sys.executable).replace("@CFG@", repr(str(cfgp))))
        docker.chmod(0o755)

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if k not in ("COMPOSE", "COMPOSE_FILE", "COMPOSE_PROFILES", "DOCKER_CMD", "BIG_MB", "HEALTH_WAIT", "KEYTOOL_CMD",
                                                                "SECRETS_DIR", "KEYSTORE_STAMP", "SIGNCHECK_DIAG", "KS_CONTAINER_UID", "TMPDIR")}
        env.update({"PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "TMPDIR": str(self.tmpdir), "KEYTOOL_CMD": str(self.bin / "keytool"),
                    "HEALTH_WAIT": "4", "LC_ALL": "C.UTF-8"})
        env.update(extra)
        return env

    def run(self, *args, timeout=120, **env):
        return subprocess.run(["bash", str(self.repo / "scripts/signer-verify.sh"), *args], capture_output=True, text=True, timeout=timeout, env=self.env(**env),
                              cwd=self.root)

    def calls(self) -> list[dict]:
        return [json.loads(ln) for ln in self.calls_log.read_text().splitlines()] if self.calls_log.exists() else []

    def sc_calls(self, key=None):
        return [c for c in self.calls() if c["kind"] == "sc" and (key is None or c["key"] == key)]

    def set_sc(self, key, entry):
        self.cfg["sc"][key] = entry
        self.write_docker()

    def replace_apk(self, **kw):
        data = make_apk(self.apk, **kw)
        self.set_sc("put:1", [0, f"ditulis={len(data)}\nsha256={hashlib.sha256(data).hexdigest()}"])

    def update(self, **kw):
        self.cfg.update(kw)
        self.write_docker()


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path)


def table(out: str) -> dict[str, tuple[str, str]]:
    rows = {}
    for line in out.splitlines():
        parts = [p.strip() for p in line.split(" | ", 2)]
        if len(parts) == 3 and parts[1] in ("OK", "GAGAL", "DILEWATI", "INFO"):
            rows[parts[0]] = (parts[1], parts[2])
    return rows


def st(rows, n):
    return rows[LABELS[n]][0]


def note(rows, n):
    return rows[LABELS[n]][1]


def statuses(rows) -> dict[int, str]:
    return {n: st(rows, n) for n in LABELS if LABELS[n] in rows}


# ================================================================================ jalur sukses
def test_success_path_prints_one_table_and_exits_0(rig):
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "LANGKAH" in r.stdout and "STATUS" in r.stdout and "KETERANGAN" in r.stdout
    assert r.stdout.count("LANGKAH") == 1, "SATU tabel"
    got = statuses(rows)
    assert got == {1: "INFO", 2: "OK", 3: "OK", 4: "OK", 5: "OK", 6: "OK", 7: "OK", 8: "OK", 9: "OK", 10: "OK", 11: "OK", 12: "OK", 13: "OK", 14: "OK", 15: "OK",
                   16: "OK", 17: "DILEWATI", 18: "OK", 19: "DILEWATI", 20: "OK"}, r.stdout
    assert re.search(r"✓ semua OK \(\d+ langkah, 2 dilewati\)", r.stdout) and "GAGAL" not in r.stdout.replace("STATUS", "")
    assert PW not in r.stdout + r.stderr


def test_success_path_call_order_arguments_and_cleanup(rig):
    rig.run()
    kinds = [c["kind"] for c in rig.calls()]
    assert kinds[:5] == ["version", "build", "up", "ps", "inspect"]
    sc = [c for c in rig.calls() if c["kind"] == "sc"]
    keys = [c["key"] for c in sc]
    assert keys[:3] == ["status", "clean", "put:1"] and keys[-1] in ("ls:4", "ls:3", "ls:2", "ls:1") and "sign:1" in keys
    sign = next(c for c in sc if c["key"] == "sign:1")
    assert sign["sargs"] == [str(AID), "1", "--timeout", "300", "--expect-ok", "--owner-sha256", OWNER] and not sign["diag"]
    put = next(c for c in sc if c["key"] == "put:1")
    assert put["stdin_bytes"] == rig.apk.stat().st_size, "APK uji dikirim lewat stdin"
    for key in ("put-garbage:2", "put-symlink:4", "bad-request:1"):
        assert next(c for c in sc if c["key"] == key)["diag"] is True, "subperintah diagnostik harus diberi SIGNCHECK_DIAG=1"
    assert not any(c["diag"] for c in sc if c["sub"] in ("status", "put", "sign", "ls", "df", "clean"))
    assert next(c for c in sc if c["key"] == "sign:3")["sargs"] == [str(AID), "3", "--timeout", "60", "--expect-error", "input_missing"]
    assert sc[-6]["key"] == "clean" or any(c["key"] == "clean" for c in sc[-8:]), "pembersihan sentinel di akhir"
    assert not (rig.root / "build-dipanggil").exists()


def test_every_signcheck_call_uses_only_sentinel_ids(rig):
    rig.run()
    for c in rig.sc_calls():
        if c["sargs"]:
            assert c["sargs"][0] == str(AID) and (len(c["sargs"]) == 1 or c["sargs"][1] in list("1234567")), c


def test_watcher_runs_during_job_and_is_stopped_with_stop_file_then_eof(rig):
    r = rig.run()
    calls = rig.calls()
    kinds = [c["kind"] for c in calls]
    assert kinds.count("watch") == 1 and kinds.count("touch-stop") >= 1
    watch_i, sign_i = kinds.index("watch"), next(i for i, c in enumerate(calls) if c["kind"] == "sc" and c["key"] == "sign:1")
    stop_i = kinds.index("touch-stop")
    # Urutan log antara proses latar (pemotret) dan job bergantung jadwal proses: yang dijamin skrip adalah pemotret DILUNCURKAN sebelum job, dan berhenti sesudahnya.
    assert watch_i < stop_i and sign_i < stop_i, "pemotret dihentikan sesudah job dan langkah 16"
    assert any(c["kind"] == "sc" and c["key"] == "bad-request:1" for c in calls[:stop_i]), "W1 mencakup langkah 10-16"
    assert (rig.state / "watch0.exit").read_text() in ("stop", "eof")
    assert "argv apksigner teramati 12 kali" in note(table(r.stdout), 18)


def test_no_temp_folder_is_left_behind(rig):
    rig.run()
    assert list(rig.tmpdir.glob("signer-verify.*")) == []


# ================================================================================ gerbang host: nol panggilan Docker
def test_keystore_missing_fails_hard_with_zero_docker_calls(rig):
    shutil.rmtree(rig.repo / "secrets")
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 2) == "GAGAL" and "make keystore" in note(rows, 2)
    assert all(st(rows, n) == "DILEWATI" for n in range(4, 21)) and rig.calls() == []
    assert re.search(r"✗ 1 GAGAL — tempel tabel ini ke chat", r.stdout)


def test_only_one_key_file_counts_as_missing_keystore(rig):
    (rig.repo / "secrets/signing_keystore_pass").unlink()
    r = rig.run()
    assert r.returncode == 1 and st(table(r.stdout), 2) == "GAGAL" and rig.calls() == []


def test_mode_600_keystore_gives_diagnosis_and_zero_docker_calls(rig):
    for f in (rig.repo / "secrets").iterdir():
        f.chmod(0o600)
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 3) == "GAGAL" and "make keystore-access" in note(rows, 3)
    assert st(rows, 2) == "OK" and all(st(rows, n) == "DILEWATI" for n in range(4, 21)) and rig.calls() == []
    assert st(rows, 1) == "DILEWATI"


def test_open_secrets_folder_is_a_hard_failure_with_zero_docker_calls(rig):
    (rig.repo / "secrets").chmod(0o755)
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 3) == "GAGAL" and "chmod 700 secrets" in note(rows, 3) and rig.calls() == []


def test_second_instance_stops_on_the_lock_without_touching_anything(rig):
    import fcntl

    lock = rig.repo / "secrets/.signer-verify.lock"
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        r = rig.run()
    finally:
        os.close(fd)
    assert r.returncode == 1 and "signer-verify lain sedang berjalan" in r.stderr + r.stdout and rig.calls() == []
    assert "LANGKAH" not in r.stdout, "proses kedua tidak mencetak tabel dan tidak membersihkan data proses pertama"


def test_lock_file_is_private_and_status_check_ignores_it(rig):
    rig.run()
    lock = rig.repo / "secrets/.signer-verify.lock"
    assert lock.exists() and stat.S_IMODE(lock.stat().st_mode) == 0o600 and lock.stat().st_size == 0
    ks = subprocess.run(["bash", str(rig.repo / "scripts/keystore.sh"), "status"], capture_output=True, text=True, cwd=rig.root,
                        env=rig.env(SECRETS_DIR=str(rig.repo / "secrets")), timeout=60)
    assert ks.returncode == 0 and "✓" in ks.stdout


def test_without_flock_the_run_continues_with_an_info_row(rig, tmp_path):
    safe = tmp_path / "safebin"
    safe.mkdir()
    for name in ("bash", "env", "sed", "grep", "tr", "cut", "head", "tail", "od", "wc", "stat", "mktemp", "rm", "mkdir", "mkfifo", "awk", "sort", "sha256sum",
                 "dirname", "cat", "sleep", "date", "id", "ls", "chmod", "touch", "readlink", "uname", "basename", "true", "false", "printf", "tee", "paste", "xargs",
                 "stat", "mv", "cp", "ln", "sh", "dash", "expr", "test", "find"):
        found = shutil.which(name)
        if found and not (safe / name).exists():
            (safe / name).symlink_to(found)
    assert not (safe / "flock").exists()
    for name in ("docker", "keytool"):
        (safe / name).symlink_to(rig.bin / name)
    r = rig.run(PATH=str(safe))
    rows = table(r.stdout)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "flock tidak ada" in rows["kunci antar-proses"][1] and rows["kunci antar-proses"][0] == "INFO"


def test_usage_errors_exit_64(rig):
    assert rig.run("--aneh").returncode == 64
    for bad in ("abc", "0", "1101", "-5", "10.5"):
        r = rig.run(BIG_MB=bad)
        assert r.returncode == 64 and "BIG_MB" in r.stderr, bad
    assert rig.calls() == []


# ================================================================================ langkah 1-7: kegagalan
def test_compose_version_failure_is_fatal(rig):
    rig.update(version=[127, "docker: command not found"])
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 1) == "GAGAL" and all(st(rows, n) == "DILEWATI" for n in range(4, 21))
    assert [c["kind"] for c in rig.calls()] == ["version"]


def test_build_failure_stops_before_anything_runs(rig):
    rig.update(build=[1, "ERROR: pull access denied"])
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 4) == "GAGAL" and "pull access denied" in note(rows, 4) and st(rows, 5) == "DILEWATI"
    assert not [c for c in rig.calls() if c["kind"] in ("up", "sc", "watch")]


def test_unhealthy_signer_shows_the_health_reason_and_stops(rig):
    rig.update(health="unhealthy")
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 5) == "GAGAL" and "keystore invalid: sandi salah" in note(rows, 5) and st(rows, 6) == "DILEWATI"
    assert not [c for c in rig.calls() if c["kind"] == "sc"]


def test_signer_stuck_in_starting_times_out(rig):
    rig.update(health="starting")
    r = rig.run(HEALTH_WAIT="2")
    assert r.returncode == 1 and st(table(r.stdout), 5) == "GAGAL" and "belum sehat setelah 2 dtk" in note(table(r.stdout), 5)


def test_status_with_multiline_detail_is_shown_untruncated(rig):
    rig.set_sc("status", [0, "hidup=1\numur_hb=1.0\nkeystore=unreadable\ncert_sha256=-\ndetail=mode 600 milik uid 1000 dan TIDAK bisa dibaca\ndetail=jalankan: make keystore-access"])
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 6) == "GAGAL"
    assert "mode 600 milik uid 1000 dan TIDAK bisa dibaca" in note(rows, 6) and "jalankan: make keystore-access" in note(rows, 6)
    assert st(rows, 7) == "DILEWATI"


def test_daemon_fingerprint_different_from_keystore_info_fails(rig):
    rig.set_sc("status", [0, f"hidup=1\numur_hb=1.0\nkeystore=ok\ncert_sha256={OTHER}\ndetail="])
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 7) == "GAGAL" and "BEDA" in note(rows, 7)


def test_keystore_info_failure_skips_the_signing_steps_but_not_the_negatives(rig):
    (rig.bin / "keytool").write_text("#!/bin/sh\necho 'keytool: gagal' >&2\nexit 1\n")
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 7) == "GAGAL"
    assert st(rows, 10) == "DILEWATI" and st(rows, 11) == "DILEWATI" and st(rows, 12) == "DILEWATI" and st(rows, 13) == "OK"


# ================================================================================ langkah 8: APK uji
def test_missing_test_apk_fails_with_instruction_and_never_calls_build_py(rig):
    rig.apk.unlink()
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 8) == "GAGAL" and "python3 scripts/sample-apk/build.py" in note(rows, 8)
    assert not (rig.root / "build-dipanggil").exists()
    assert st(rows, 9) == "DILEWATI" and st(rows, 10) == "DILEWATI" and st(rows, 13) == "OK"


def test_test_apk_that_is_not_a_zip_fails(rig):
    rig.apk.write_bytes(b"ini bukan apk")
    rows = table(rig.run().stdout)
    assert st(rows, 8) == "GAGAL" and "bukan ZIP" in note(rows, 8)


def test_test_apk_with_v2_signing_block_fails(rig):
    rig.replace_apk(extra={"assets/x": b"..APK Sig Block 42.."})
    rows = table(rig.run().stdout)
    assert st(rows, 8) == "GAGAL" and "v2/v3" in note(rows, 8)


def test_test_apk_with_v1_only_signature_is_info_and_the_run_continues(rig):
    rig.replace_apk(extra={"META-INF/CERT.RSA": b"\x30\x00"})
    r = rig.run()
    rows = table(r.stdout)
    assert st(rows, 8) == "INFO" and "signer akan menimpa" in note(rows, 8) and st(rows, 10) == "OK" and r.returncode == 0


# ================================================================================ langkah 9-16
def test_input_hash_mismatch_fails(rig):
    rig.set_sc("put:1", [0, f"ditulis=5\nsha256={OTHER}"])
    rows = table(rig.run().stdout)
    assert st(rows, 9) == "GAGAL" and "sha256 beda" in note(rows, 9) and st(rows, 10) == "DILEWATI"


def test_put_error_shows_the_galat_line(rig):
    rig.set_sc("put:1", [2, "GALAT: tidak bisa membuat folder build: Permission denied"])
    rows = table(rig.run().stdout)
    assert st(rows, 9) == "GAGAL" and "Permission denied" in note(rows, 9)


def test_expect_ok_failure_with_alasan_is_a_failure_with_the_reason_in_the_table(rig):
    rig.set_sc("sign:1", [3, hasil(ok=False, code="verify_failed") + "\nALASAN: diharapkan sukses tetapi job gagal (verify_failed): Verifikasi gagal."])
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 10) == "GAGAL" and "verify_failed" in note(rows, 10)
    assert st(rows, 11) == "DILEWATI" and st(rows, 12) == "DILEWATI", "tanpa hasil sukses tidak ada yang diverifikasi"
    assert st(rows, 13) == "OK", "negatif tetap jalan"


def test_sign_galat_exit_2_is_a_failure(rig):
    rig.set_sc("sign:1", [2, "GALAT: Signer tidak aktif, jadi tidak ada yang ditandatangani."])
    rows = table(rig.run().stdout)
    assert st(rows, 10) == "GAGAL" and "Signer tidak aktif" in note(rows, 10)


@pytest.mark.parametrize("bad", [hasil(signers=2), hasil(v2=0), hasil(v3=0), hasil(sha="zz"), hasil(cert="zz"), hasil(size=0)])
def test_incoherent_hasil_fails_step_11(rig, bad):
    rig.set_sc("sign:1", [0, bad])
    rows = table(rig.run().stdout)
    assert st(rows, 11) == "GAGAL" and "tidak koheren" in note(rows, 11)


def test_v1_value_does_not_matter_for_step_11(rig):
    rig.set_sc("sign:1", [0, hasil(v1="-")])
    assert st(table(rig.run().stdout), 11) == "OK"


@pytest.mark.parametrize("verify,needle", [
    (verify_text(digests=(OTHER,)), "bukan-pemilik=1"),
    (verify_text(digests=(OWNER, OTHER)), "bukan-pemilik=1"),
    (verify_text(rcv=1), "apksigner verify=1"),
    (verify_text(rca=1), "zipalign=1"),
    (verify_text(sha=OTHER), "sha="),
    (verify_text(size=1), "ukuran=1"),
    ("rc_verify=0\nrc_align=0\nsha=%s\nsize=4321" % SHA, "digest=0"),
])
def test_independent_verification_fails_on_any_mismatch(rig, verify, needle):
    rig.update(signer_verify=[0, verify])
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 12) == "GAGAL" and needle in note(rows, 12), note(rows, 12)


def test_public_key_digest_lines_are_not_mistaken_for_certificate_digests(rig):
    rig.update(signer_verify=[0, verify_text()])         # fixture memuat 'public key SHA-256 digest' berbeda dari pemilik
    assert st(table(rig.run().stdout), 12) == "OK"


def test_independent_verification_script_runs_in_the_signer_container_on_the_signed_file(rig):
    rig.run()
    call = next(c for c in rig.calls() if c["kind"] == "verify-signer")
    argv = " ".join(call["argv"])
    assert "run --rm --no-deps -T signer sh -c" in argv and f"/data/builds/{AID}/1/signed.apk" in argv
    assert "apksigner verify --verbose --print-certs" in call["script"] and "zipalign -c -P 16 4" in call["script"] and "sha256sum" in call["script"]


@pytest.mark.parametrize("key,label,ok_note", [("sign:3", 13, "input_missing"), ("sign:2", 14, "align_failed"), ("sign:4", 15, "input_unsafe"), ("bad-request:1", 16, "bad_request")])
def test_negative_steps_fail_when_the_expected_error_is_not_returned(rig, key, label, ok_note):
    rig.set_sc(key, [3, hasil(ok=False, code="internal") + f"\nALASAN: diharapkan kode {ok_note} tetapi kode hasil internal"])
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, label) == "GAGAL" and ok_note in note(rows, label)


def test_negative_a_fails_if_signed_apk_appears(rig):
    rig.set_sc("ls:3", [0, "signed.apk\nunsigned.apk"])
    rows = table(rig.run().stdout)
    assert st(rows, 13) == "GAGAL" and "signed.apk tercipta" in note(rows, 13)


def test_negative_b_fails_on_leftover_artifacts(rig):
    rig.set_sc("ls:2", {"seq": [[0, "unsigned.apk\n.sign-aligned.tmp"], [0, ""]]})
    rows = table(rig.run().stdout)
    assert st(rows, 14) == "GAGAL" and ".sign-aligned.tmp" in note(rows, 14)


def test_watcher_is_stopped_even_when_a_middle_step_fails(rig):
    rig.set_sc("sign:3", [3, hasil(ok=False, code="x") + "\nALASAN: salah"])
    rig.run()
    kinds = [c["kind"] for c in rig.calls()]
    assert "touch-stop" in kinds and (rig.state / "watch0.exit").exists()


# ================================================================================ langkah 18: kebocoran sandi
def test_leak_watch_with_secret_is_a_failure(rig):
    rig.update(watches=[watch_text(bocor=2)] + [watch_text()] * 3)
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 18) == "GAGAL" and "2 sampel" in note(rows, 18)
    assert PW not in r.stdout + r.stderr


def test_leak_scan_with_secret_is_a_failure(rig):
    rig.update(leak=[1, "diperiksa=40\nbocor=1"])
    rows = table(rig.run().stdout)
    assert st(rows, 18) == "GAGAL" and "--leak-scan" in note(rows, 18)


def test_password_in_signer_log_is_a_failure_and_is_never_printed(rig):
    rig.update(logs=f"2026 ... login dengan {PW} ...\n")
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 18) == "GAGAL" and "log signer" in note(rows, 18)
    assert PW not in r.stdout + r.stderr


def test_password_in_saved_hasil_or_galat_output_is_a_failure(rig):
    rig.set_sc("status", [0, f"hidup=1\numur_hb=1.0\nkeystore=ok\ncert_sha256={OWNER}\ndetail=bocor {PW}"])
    r = rig.run()
    assert st(table(r.stdout), 18) == "GAGAL" and PW not in r.stdout + r.stderr


@pytest.mark.parametrize("watches", [[""] * 4, ["pesan galat bukan kunci=nilai"] * 4, [watch_text(apksigner=0)] + [watch_text()] * 3])
def test_empty_or_unproven_watch_is_skipped_not_ok(rig, watches):
    rig.update(watches=watches)
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 0 and st(rows, 18) == "DILEWATI" and "tidak terbukti" in note(rows, 18)


def test_password_file_with_trailing_blank_lines_gives_no_false_failure(rig):
    (rig.repo / "secrets/signing_keystore_pass").write_text(PW + "\n\n\n")
    r = rig.run()
    rows = table(r.stdout)
    assert r.returncode == 0 and st(rows, 18) == "OK", note(rows, 18)


def test_password_file_with_crlf_and_blank_lines_gives_no_false_failure(rig):
    (rig.repo / "secrets/signing_keystore_pass").write_bytes(PW.encode() + b"\r\n\r\n")
    assert st(table(rig.run().stdout), 18) == "OK"


def test_password_file_with_crlf_still_detects_a_leak_in_the_log(rig):
    (rig.repo / "secrets/signing_keystore_pass").write_bytes(PW.encode() + b"\r\n\r\n")
    rig.update(logs=f"... {PW} ...\n")
    rows = table(rig.run().stdout)
    assert st(rows, 18) == "GAGAL" and "log signer" in note(rows, 18)


def test_short_password_file_skips_the_check(rig):
    (rig.repo / "secrets/signing_keystore_pass").write_text("pendek\n\n")
    r = rig.run()
    rows = table(r.stdout)
    assert st(rows, 18) == "DILEWATI" and "berkas sandi tak lazim" in note(rows, 18) and r.returncode == 0


def test_script_text_follows_the_addendum_rules():
    text = SCRIPT_SRC.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n") and "set -uo pipefail" in text and os.access(SCRIPT_SRC, os.X_OK)
    assert "pw=\"$(tr -d '\\r\\n' <secrets/signing_keystore_pass" in text and '[ "${#pw}" -lt 16 ]' in text and 'grep -F -q -e "$pw"' in text
    assert "sed -n 's/^detail=//p'" in text
    assert "flock -n 9" in text and "secrets/.signer-verify.lock" in text
    assert not re.search(r"\bjq\b|python3? -c|json\.load", text), "bash tidak boleh mem-parse JSON"
    assert "build.py" in text and "python3 scripts/sample-apk/build.py" in text and not re.search(r"^\s*python3? scripts/sample-apk/build\.py", text, re.M)
    uses_kv = [ln for ln in text.splitlines() if re.search(r"\bkv [a-z_0-9]+ ", ln) and not ln.lstrip().startswith("#")]
    assert uses_kv and all(("HL" in ln or "HASIL" in ln or "elapsed" in ln) for ln in uses_kv), uses_kv


# ================================================================================ langkah 17 dan 19 (BIG_MB)
def test_big_run_runs_three_cases_with_watchers_and_memory_verdict_ok(rig):
    rig.update(watches=[watch_text(), watch_text(anon=150), watch_text(anon=380), watch_text(anon=399)])
    r = rig.run(BIG_MB="64")
    rows = table(r.stdout)
    assert r.returncode == 0, r.stdout
    labels = [k for k in rows if k.startswith("17")]
    assert len(labels) == 3 and all(rows[k][0] == "OK" for k in labels), labels
    assert any("1 entri" in k for k in labels) and sum("60000 entri" in k for k in labels) == 2 and any("META-INF" in k for k in labels)
    assert st(rows, 19) == "OK" and "W2:anon=150" in note(rows, 19) and "W4:anon=399" in note(rows, 19)
    pb = {c["key"]: c for c in rig.sc_calls() if c["sub"] == "put-big"}
    assert pb["put-big:5"]["sargs"] == [str(AID), "5", "--size-mb", "64", "--entries", "1"]
    assert pb["put-big:6"]["sargs"] == [str(AID), "6", "--size-mb", "64", "--entries", "60000"]
    assert pb["put-big:7"]["sargs"] == [str(AID), "7", "--size-mb", "64", "--entries", "60000", "--jar-meta"]
    assert all(c["diag"] and c["stdin_bytes"] == rig.apk.stat().st_size for c in pb.values())
    seq = [c["key"] for c in rig.sc_calls() if c["key"] in ("put-big:5", "sign:5", "clean:5", "put-big:6", "sign:6", "clean:6", "put-big:7", "sign:7", "clean:7")]
    assert seq == ["put-big:5", "sign:5", "clean:5", "put-big:6", "sign:6", "clean:6", "put-big:7", "sign:7", "clean:7"]
    assert [c["index"] for c in rig.calls() if c["kind"] == "watch"] == [0, 1, 2, 3]
    assert next(c for c in rig.sc_calls("sign:5"))["sargs"][2:4] == ["--timeout", "900"]


@pytest.mark.parametrize("w2,w3,w4,expect", [
    (watch_text(anon=450), watch_text(), watch_text(), "W2 anon_peak_mib=450"),
    (watch_text(), watch_text(anon=400), watch_text(), "W3 anon_peak_mib=400"),
    (watch_text(), watch_text(), watch_text(oom=1), "W4 oom_kill=1"),
])
def test_memory_criteria_fail_on_anon_400_or_oom_kill(rig, w2, w3, w4, expect):
    rig.update(watches=[watch_text(), w2, w3, w4])
    r = rig.run(BIG_MB="10")
    rows = table(r.stdout)
    assert r.returncode == 1 and st(rows, 19) == "GAGAL" and expect in note(rows, 19)


def test_memory_gejala_hint_when_1_entry_passes_but_many_entries_fail(rig):
    rig.update(watches=[watch_text(), watch_text(), watch_text(anon=450), watch_text()])
    assert "MaxDirectMemorySize" in note(table(rig.run(BIG_MB="10").stdout), 19)


def test_memory_unmeasured_is_skipped_not_ok(rig):
    rig.update(watches=[watch_text(), watch_text(anon="-", oom="-"), watch_text(anon="-", oom="-"), watch_text(anon="-", oom="-")])
    r = rig.run(BIG_MB="10")
    rows = table(r.stdout)
    assert r.returncode == 0 and st(rows, 19) == "DILEWATI" and "tidak terukur" in note(rows, 19)


def test_memory_step_info_row_for_job_one_and_skip_without_big_mb(rig):
    rows = table(rig.run().stdout)
    assert rows["19 memori (job 1)"][0] == "INFO" and "anon_peak_mib=210" in rows["19 memori (job 1)"][1]
    assert st(rows, 19) == "DILEWATI" and "tidak diminta" in note(rows, 19) and st(rows, 17) == "DILEWATI" and "BIG_MB" in note(rows, 17)


def test_big_run_is_skipped_with_numbers_when_disk_is_too_small(rig):
    rig.set_sc("df", [0, "bebas_mib=1139"])
    r = rig.run(BIG_MB="50")
    rows = table(r.stdout)
    assert r.returncode == 0 and st(rows, 17) == "DILEWATI" and "butuh 1140 MiB, bebas 1139 MiB" in note(rows, 17)
    assert st(rows, 19) == "DILEWATI" and not rig.sc_calls("put-big:5")
    rig.set_sc("df", [0, "bebas_mib=1140"])
    assert any(k.startswith("17a") for k in table(rig.run(BIG_MB="50").stdout)), "tepat di batas: uji besar berjalan"


def test_big_disk_formula_for_1000_mib_is_3040(rig):
    rig.set_sc("df", [0, "bebas_mib=3039"])
    assert "butuh 3040 MiB" in note(table(rig.run(BIG_MB="1000").stdout), 17)


def test_big_case_failure_is_reported_and_other_cases_continue(rig):
    rig.set_sc("sign:6", [3, hasil(ok=False, code="timeout") + "\nALASAN: diharapkan sukses tetapi job gagal (timeout): lewat batas"])
    r = rig.run(BIG_MB="10")
    rows = table(r.stdout)
    bad = [k for k, v in rows.items() if k.startswith("17b")]
    assert r.returncode == 1 and bad and rows[bad[0]][0] == "GAGAL" and "timeout" in rows[bad[0]][1]
    assert any(k.startswith("17c") and v[0] == "OK" for k, v in rows.items())
    assert [c["index"] for c in rig.calls() if c["kind"] == "watch"] == [0, 1, 2, 3]


# ================================================================================ trap: INT dan pemotret
def run_in_background(rig, **env):
    return subprocess.Popen(["bash", str(rig.repo / "scripts/signer-verify.sh")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=rig.env(**env),
                            cwd=rig.root, start_new_session=True)


def wait_for(path: Path, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end and not path.exists():
        time.sleep(0.05)
    assert path.exists(), f"{path.name} tidak muncul"


def test_sigint_trap_touches_the_stop_file_before_removing_the_temp_folder(rig):
    marker = rig.root / "sign-mulai"
    rig.set_sc("sign:1", {"sleep": 60, "marker": str(marker)})
    proc = run_in_background(rig)
    try:
        wait_for(marker)
        os.killpg(proc.pid, signal.SIGINT)
        out, err = proc.communicate(timeout=60)
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
    calls = rig.calls()
    assert proc.returncode == 1
    touch = next(c for c in calls if c["kind"] == "touch-stop")
    assert touch["tmp_exists"] is True, "berkas stop harus ditulis SEBELUM folder sementara dihapus"
    assert (rig.state / "watch0.exit").read_text() in ("stop", "eof")
    assert list(rig.tmpdir.glob("signer-verify.*")) == [], "folder sementara tidak boleh tersisa"
    rows = table(out)
    assert rows["dihentikan"][0] == "GAGAL" and "tempel tabel ini ke chat" in out
    assert any(c["kind"] == "sc" and c["key"] == "clean" for c in calls[calls.index(touch):]), "sisa sentinel dibersihkan lewat trap"


def test_sigterm_also_cleans_up(rig):
    marker = rig.root / "sign-mulai"
    rig.set_sc("sign:1", {"sleep": 60, "marker": str(marker)})
    proc = run_in_background(rig)
    try:
        wait_for(marker)
        os.killpg(proc.pid, signal.SIGTERM)
        proc.communicate(timeout=60)
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
    assert any(c["kind"] == "touch-stop" for c in rig.calls()) and list(rig.tmpdir.glob("signer-verify.*")) == [] and proc.returncode == 1


def test_killed_script_gives_the_watcher_eof_because_the_child_does_not_inherit_the_write_end(rig):
    marker = rig.root / "sign-mulai"
    rig.set_sc("sign:1", {"sleep": 60, "marker": str(marker)})
    proc = run_in_background(rig)
    try:
        wait_for(marker)
        wait_for(rig.state / "watch0.started")
        os.kill(proc.pid, signal.SIGKILL)                  # tanpa trap: hanya kernel yang menutup fd 7
        wait_for(rig.state / "watch0.exit", 20)
        assert (rig.state / "watch0.exit").read_text() == "eof", "EOF stdin harus menghentikan pemotret (7>&- pada anak)"
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        for d in rig.tmpdir.glob("signer-verify.*"):
            shutil.rmtree(d, ignore_errors=True)


# ================================================================================ Makefile
def test_make_signer_verify_runs_the_script_with_the_make_compose(rig, tmp_path):
    shutil.copy2(ROOT / "Makefile", rig.repo / "Makefile")
    r = subprocess.run(["make", "-s", "signer-verify", "COMPOSE=docker compose"], capture_output=True, text=True, cwd=rig.repo, env=rig.env(), timeout=120)
    assert r.returncode == 0 and "✓ semua OK" in r.stdout, r.stdout + r.stderr
    assert "compose" in {a for c in rig.calls() for a in c["argv"]}
