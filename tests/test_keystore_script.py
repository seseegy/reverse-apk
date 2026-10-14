"""Keystore penanda tangan (`scripts/keystore.sh`, dipanggil `make init` / `make keystore` / `make keystore-info`).

Dua lapis:
- TANPA JDK (selalu jalan, termasuk CI): skrip dijalankan sungguhan dengan keytool PALSU (perekam argv/environ) lewat `KEYTOOL_CMD`, dan dengan docker PALSU
  (`DOCKER_CMD`) untuk memeriksa argumen `docker run`. Yang diperiksa: berkas/mode, idempoten, tidak menimpa, gagal-tertutup, sandi tidak bocor.
- DENGAN JDK (dilewati bersih bila keytool tidak ada; tes tidak bergantung pada JDK CI): keytool asli membuat keystore sungguhan dan hasilnya diperiksa.

BELUM terbukti di sini: `docker run ... keytool` pada Docker nyata (izin tulis user host, mode berkas, image `reverse-apk-signer`); itu dibuktikan di server pemilik.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_SRC = ROOT / "scripts/keystore.sh"
KS, PW = "signing_keystore.p12", "signing_keystore_pass"

REAL_KEYTOOL = os.environ.get("KEYTOOL_FOR_TESTS") or shutil.which("keytool")
needs_jdk = pytest.mark.skipif(
    REAL_KEYTOOL is None,
    reason="keytool (JDK) tidak ada di mesin ini; tes yang membutuhkan keytool asli dilewati — CI ubuntu-latest punya JDK, tetapi tes tidak bergantung padanya",
)


# ================================================================================ alat bantu
FAKE_KEYTOOL = """#!{py}
import hashlib, json, os, sys, time
cfg = json.load(open({cfg!r}))
args = sys.argv[1:]
with open(cfg["log"], "a") as f:
    f.write(json.dumps({{"argv": args, "environ": dict(os.environ)}}) + "\\n")
def val(flag):
    return args[args.index(flag) + 1] if flag in args else None
mode = cfg["mode"]
if "-genkeypair" in args:
    time.sleep(cfg.get("delay", 0))
    if mode == "fail":
        print("keytool error: simulasi gagal", file=sys.stderr)
        sys.exit(1)
    pw = open(val("-storepass:file"), "rb").read()
    if cfg.get("race_pass"):  # proses lain menciptakan berkas sandi final di tengah pembuatan
        with open(cfg["race_pass"], "w") as f:
            f.write("PEMENANG")
    os.umask(0o022)  # keytool/JDK menulis p12 dengan mode 644
    alias = "salah" if mode == "bad_list" else val("-alias")
    body = "FAKEP12\\n%s\\n%s\\n%s\\n%s\\n" % (hashlib.sha256(pw).hexdigest(), val("-dname"), alias, os.urandom(16).hex())
    with open(val("-keystore"), "w") as f:
        f.write(body)
    if mode == "fail_after_write":
        print("keytool error: gagal setelah menulis", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)
if "-list" in args:
    lines = open(val("-keystore")).read().split("\\n")
    if hashlib.sha256(open(val("-storepass:file"), "rb").read()).hexdigest() != lines[1]:
        print("keytool error: java.io.IOException: keystore password was incorrect", file=sys.stderr)
        sys.exit(1)
    fp = hashlib.sha256("\\n".join(lines).encode()).hexdigest().upper()
    fp = ":".join(fp[i:i + 2] for i in range(0, 64, 2))
    print(f'''Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 1 entry

Alias name: {{lines[3]}}
Creation date: Jan 5, 2026
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
Owner: {{lines[2]}}
Issuer: {{lines[2]}}
Valid from: Mon Jan 05 10:00:00 UTC 2026 until: Thu Dec 28 10:00:00 UTC 2056
Certificate fingerprints:
\\t SHA1: 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33
\\t SHA256: {{fp}}
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 3072-bit RSA key
Version: 3''')
    sys.exit(0)
sys.exit(2)
"""

FAKE_DOCKER = """#!{py}
import json, os, subprocess, sys
cfg = json.load(open({cfg!r}))
args = sys.argv[1:]
with open(cfg["log"], "a") as f:
    f.write(json.dumps(args) + "\\n")
built = cfg["log"] + ".built"
if args[:2] == ["image", "inspect"]:
    sys.exit(0 if (cfg["has_image"] or os.path.exists(built)) else 1)
if args[:1] == ["compose"]:
    open(built, "w").close()
    sys.exit(0)
if args[:1] != ["run"]:
    print("fake-docker: perintah tak dikenal", args, file=sys.stderr)
    sys.exit(97)
VALUE = {{"--user", "-v", "--tmpfs", "-e", "--entrypoint", "--network", "--security-opt", "--cap-drop", "--pids-limit", "--memory", "--workdir", "--pull"}}
BOOL = {{"--rm", "--read-only"}}
i, mounts, opts = 1, {{}}, {{}}
while i < len(args) and args[i].startswith("-"):
    if args[i] in BOOL:
        opts[args[i]] = True; i += 1
    elif args[i] in VALUE:
        if args[i] == "-v":
            src, dst, *flags = args[i + 1].split(":")
            mounts[dst] = src
        opts[args[i]] = args[i + 1]; i += 2
    else:  # bendera tak dikenal: jangan diam-diam diabaikan
        print("fake-docker: bendera tak dikenal", args[i], file=sys.stderr)
        sys.exit(97)
image, rest = args[i], args[i + 1:]
if opts.get("--entrypoint") != "keytool":
    sys.exit(97)
out = []
for a in rest:
    for dst, src in mounts.items():
        if a == dst or a.startswith(dst + "/"):
            a = src + a[len(dst):]
    out.append(a)
sys.exit(subprocess.call([cfg["keytool"]] + out))
"""


def _write_exec(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


def fake_keytool(tmp: Path, mode: str = "ok", delay: float = 0.0, race_pass: Path | None = None) -> tuple[Path, Path]:
    d = tmp / "fakekt"
    d.mkdir(exist_ok=True)
    log = d / "log.jsonl"
    cfg = d / "cfg.json"
    cfg.write_text(json.dumps({"mode": mode, "delay": delay, "log": str(log), "race_pass": str(race_pass) if race_pass else None}), encoding="utf-8")
    return _write_exec(d / "keytool", FAKE_KEYTOOL.format(py=sys.executable, cfg=str(cfg))), log


def fake_docker(tmp: Path, keytool: Path, has_image: bool = True) -> tuple[Path, Path]:
    d = tmp / "fakedocker"
    d.mkdir(exist_ok=True)
    log = d / "log.jsonl"
    cfg = d / "cfg.json"
    cfg.write_text(json.dumps({"log": str(log), "has_image": has_image, "keytool": str(keytool)}), encoding="utf-8")
    return _write_exec(d / "docker", FAKE_DOCKER.format(py=sys.executable, cfg=str(cfg))), log


def services(compose_text: str) -> dict[str, str]:
    """Blok tiap layanan di bawah `services:` (sama seperti helper di test_runner_aapt2)."""
    body = compose_text.split("\nservices:\n", 1)[1]
    body = re.split(r"\n(?=[A-Za-z])", body, maxsplit=1)[0]
    parts = re.split(r"(?m)^  ([\w-]+):[ \t]*$", body)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}


def read_log(log: Path) -> list:
    return [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []


@pytest.fixture
def repo(tmp_path):
    """Salinan skrip di pohon repo mini (skrip `cd` ke induk folder `scripts/`, jadi .env/ secrets uji tidak menyentuh repo asli)."""
    (tmp_path / "repo/scripts").mkdir(parents=True)
    shutil.copy2(SCRIPT_SRC, tmp_path / "repo/scripts/keystore.sh")
    return tmp_path / "repo"


def run_ks(repo: Path, *args: str, secrets: Path | None = None, **env_extra: str) -> subprocess.CompletedProcess:
    # Lingkungan nyata (shim JDK seperti mise butuh HOME/XDG asli) tanpa variabel milik skrip yang bisa bocor dari mesin pengembang.
    env = {k: v for k, v in os.environ.items() if k not in ("KEYTOOL_CMD", "SECRETS_DIR", "DOCKER_CMD", "COMPOSE", "SIGNER_IMAGE")}
    env.update({"LC_ALL": "C.UTF-8", "SECRETS_DIR": str(secrets or repo.parent / "secrets")})
    env.update(env_extra)
    return subprocess.run(["bash", str(repo / "scripts/keystore.sh"), *args], capture_output=True, text=True, env=env, timeout=120, cwd=repo.parent)


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def mode_of(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


@pytest.fixture
def made(repo, tmp_path):
    """Keystore (palsu) sudah dibuat: (repo, secrets, hasil, log keytool)."""
    kt, log = fake_keytool(tmp_path)
    secrets = tmp_path / "secrets"
    r = run_ks(repo, "create", KEYTOOL_CMD=str(kt))
    assert r.returncode == 0, r.stderr
    return repo, secrets, r, log


# ================================================================================ 1-4: pembuatan, argumen, sandi, idempoten
def test_create_makes_both_files_with_strict_modes(made):
    repo, secrets, r, _ = made
    assert (secrets / KS).is_file() and (secrets / PW).is_file()
    assert mode_of(secrets / KS) == 0o600 and mode_of(secrets / PW) == 0o600  # keytool palsu menulis 644: chmod harus memperbaikinya
    assert mode_of(secrets) == 0o700
    assert sorted(p.name for p in secrets.iterdir()) == sorted([KS, PW])
    assert not list(secrets.glob(".keystore-work.*"))
    assert "CADANGKAN" in r.stdout and KS in r.stdout and PW in r.stdout


def test_password_file_is_64_hex_without_newline(made):
    _, secrets, _, _ = made
    assert re.fullmatch(rb"[0-9a-f]{64}", (secrets / PW).read_bytes())


def test_keytool_arguments(made):
    _, _, _, log = made
    gen = next(c["argv"] for c in read_log(log) if "-genkeypair" in c["argv"])
    flat = " ".join(gen)
    for must in ("-storetype PKCS12", "-alias reverse-apk", "-keyalg RSA", "-keysize 3072", "-sigalg SHA256withRSA", "-validity 10950"):
        assert must in flat, must
    for flag in ("-storepass:file", "-keypass:file", "-noprompt"):
        assert flag in gen
    assert re.fullmatch(r"CN=reverse-apk [0-9a-f]{8}", gen[gen.index("-dname") + 1])
    assert "-J-Duser.language=en" in gen  # keluaran Inggris tetap agar parsing stabil


def test_dn_is_random_between_installs(tmp_path):
    dns = []
    for n in range(2):
        base = tmp_path / f"i{n}"
        (base / "repo/scripts").mkdir(parents=True)
        shutil.copy2(SCRIPT_SRC, base / "repo/scripts/keystore.sh")
        kt, log = fake_keytool(base)
        assert run_ks(base / "repo", "create", KEYTOOL_CMD=str(kt)).returncode == 0
        gen = next(c["argv"] for c in read_log(log) if "-genkeypair" in c["argv"])
        dns.append(gen[gen.index("-dname") + 1])
    assert dns[0] != dns[1]


def test_password_never_appears_in_argv_environ_or_output(made, tmp_path):
    repo, secrets, r, log = made
    password = (secrets / PW).read_text()
    kt, _ = fake_keytool(tmp_path)  # sama; `info` juga memanggil keytool palsu yang sama
    info = run_ks(repo, "info", KEYTOOL_CMD=str(kt))
    assert info.returncode == 0, info.stderr
    for call in read_log(log):
        assert password not in json.dumps(call["argv"]), "sandi bocor ke argumen keytool"
        assert password not in json.dumps(call["environ"]), "sandi bocor ke environ keytool"
        for a in call["argv"]:
            assert not re.fullmatch(r"-(storepass|keypass)", a), "-storepass/-keypass harus dengan :file"
    for out in (r.stdout, r.stderr, info.stdout, info.stderr):
        assert password not in out
    assert any("-list" in c["argv"] for c in read_log(log))


def test_script_text_never_traces_or_exports_password():
    code = "\n".join(ln for ln in SCRIPT_SRC.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r"\bset\s+-\w*x", code) and "xtrace" not in code
    assert not re.search(r"echo[^\n]*\$\{?pw\b", code) and not re.search(r"export\s+pw\b", code)
    assert not re.search(r"-(storepass|keypass)(?!:file)\b", code)


def test_second_run_changes_nothing(made, tmp_path):
    repo, secrets, _, log = made
    before = {p.name: (sha(p), p.stat().st_mtime_ns) for p in (secrets / KS, secrets / PW)}
    calls = len(read_log(log))
    kt, _ = fake_keytool(tmp_path)
    r = run_ks(repo, "create", KEYTOOL_CMD=str(kt))
    assert r.returncode == 0 and "sudah ada" in r.stdout
    assert {p.name: (sha(p), p.stat().st_mtime_ns) for p in (secrets / KS, secrets / PW)} == before
    assert len(read_log(log)) == calls, "keytool tidak boleh dipanggil lagi"


# ================================================================================ 5-8: tidak destruktif, gagal-tertutup
@pytest.mark.parametrize("present,absent", [(KS, PW), (PW, KS)])
def test_only_one_file_fails_without_touching_anything(repo, tmp_path, present, absent):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / present).write_text("JANGAN DISENTUH")
    (secrets / present).chmod(0o640)
    kt, log = fake_keytool(tmp_path)
    r = run_ks(repo, "create", KEYTOOL_CMD=str(kt))
    assert r.returncode == 2
    assert present in r.stderr and "Tidak ada yang diubah" in r.stderr
    assert (secrets / present).read_text() == "JANGAN DISENTUH" and mode_of(secrets / present) == 0o640
    assert not (secrets / absent).exists() and not list(secrets.glob(".keystore-work.*"))
    assert read_log(log) == [], "keytool tidak boleh dipanggil"


@pytest.mark.parametrize("kind", ["dir", "symlink", "dangling"])
def test_not_a_regular_file_is_refused(repo, tmp_path, kind):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    target = secrets / KS
    if kind == "dir":
        target.mkdir()
    elif kind == "symlink":
        (tmp_path / "lain").write_text("x")
        target.symlink_to(tmp_path / "lain")
    else:
        target.symlink_to(tmp_path / "tidak-ada")
    kt, log = fake_keytool(tmp_path)
    r = run_ks(repo, "create", KEYTOOL_CMD=str(kt))
    assert r.returncode == 2 and "BUKAN berkas biasa" in r.stderr
    assert not (secrets / PW).exists() and read_log(log) == []
    if kind == "symlink":
        assert (tmp_path / "lain").read_text() == "x"


@pytest.mark.parametrize("mode", ["fail", "fail_after_write", "bad_list"])
def test_keytool_failure_leaves_no_files(repo, tmp_path, mode):
    kt, _ = fake_keytool(tmp_path, mode=mode)
    r = run_ks(repo, "create", KEYTOOL_CMD=str(kt))
    assert r.returncode != 0
    secrets = tmp_path / "secrets"
    assert sorted(p.name for p in secrets.iterdir()) == [], "tidak boleh ada berkas final maupun sisa direktori kerja"


def test_failed_run_can_be_repeated_successfully(repo, tmp_path):
    bad, _ = fake_keytool(tmp_path, mode="fail")
    assert run_ks(repo, "create", KEYTOOL_CMD=str(bad)).returncode != 0
    good, _ = fake_keytool(tmp_path)
    assert run_ks(repo, "create", KEYTOOL_CMD=str(good)).returncode == 0
    assert (tmp_path / "secrets" / KS).is_file()


def test_interrupted_run_cleans_work_dir(repo, tmp_path):
    import signal
    import time

    kt, _ = fake_keytool(tmp_path, delay=30)
    env = {"PATH": os.environ["PATH"], "SECRETS_DIR": str(tmp_path / "secrets"), "KEYTOOL_CMD": str(kt)}
    p = subprocess.Popen(["bash", str(repo / "scripts/keystore.sh"), "create"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        for _ in range(100):
            if list((tmp_path / "secrets").glob(".keystore-work.*")):
                break
            time.sleep(0.05)
        assert list((tmp_path / "secrets").glob(".keystore-work.*")), "direktori kerja harus ada selama pembuatan"
        os.killpg(p.pid, signal.SIGTERM)
        p.wait(timeout=30)
    finally:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
    assert sorted(x.name for x in (tmp_path / "secrets").iterdir()) == []


def test_race_existing_password_created_midway_is_not_overwritten(repo, tmp_path):
    secrets = tmp_path / "secrets"
    kt, _ = fake_keytool(tmp_path, race_pass=secrets / PW)
    r = run_ks(repo, "create", KEYTOOL_CMD=str(kt))
    assert r.returncode == 2
    assert (secrets / PW).read_text() == "PEMENANG"
    assert not (secrets / KS).exists() and not list(secrets.glob(".keystore-work.*"))


def _ln_shim(tmp: Path, victim: str) -> str:
    """PATH dengan `ln` pembungkus: tepat sebelum `ln` menerbitkan `victim`, proses 'lain' menciptakan berkas itu (jendela balapan setelah pengecekan ulang)."""
    d = tmp / "lnshim"
    d.mkdir(exist_ok=True)
    _write_exec(d / "ln", f'#!/bin/bash\nfor a in "$@"; do case "$a" in */{victim}) printf PEMENANG > "$a";; esac; done\nexec {shutil.which("ln")} "$@"\n')
    return f"{d}:{os.environ['PATH']}"


@pytest.mark.parametrize("victim,other", [(PW, KS), (KS, PW)])
def test_race_during_publication_never_overwrites_winner(repo, tmp_path, victim, other):
    kt, _ = fake_keytool(tmp_path)
    secrets = tmp_path / "secrets"
    r = run_ks(repo, "create", KEYTOOL_CMD=str(kt), PATH=_ln_shim(tmp_path, victim))
    assert r.returncode == 2 and "Tidak ada yang ditimpa" in r.stderr
    assert (secrets / victim).read_text() == "PEMENANG", "berkas pemenang balapan tidak boleh ditimpa"
    assert not (secrets / other).exists(), "sandi/p12 milik proses yang kalah tidak boleh tertinggal"
    assert not list(secrets.glob(".keystore-work.*"))


def test_parallel_creates_yield_exactly_one_consistent_pair(repo, tmp_path):
    kt, _ = fake_keytool(tmp_path, delay=0.6)
    env = {"PATH": os.environ["PATH"], "SECRETS_DIR": str(tmp_path / "secrets"), "KEYTOOL_CMD": str(kt)}
    procs = [subprocess.Popen(["bash", str(repo / "scripts/keystore.sh"), "create"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
    res = [(p.wait(timeout=60), p.stdout.read(), p.stderr.read()) for p in procs]
    codes = sorted(c for c, _, _ in res)
    assert codes[0] == 0 and codes[1] in (0, 2), res
    assert sum("keystore dibuat" in o for _, o, _ in res) == 1, "tepat satu proses yang membuat"
    secrets = tmp_path / "secrets"
    lines = (secrets / KS).read_text().split("\n")
    assert lines[1] == hashlib.sha256((secrets / PW).read_bytes()).hexdigest(), "sandi harus cocok dengan p12 pemenang"
    assert sorted(p.name for p in secrets.iterdir()) == sorted([KS, PW])


# ================================================================================ 9: mode Docker (docker palsu)
def _docker_env(tmp_path, repo, has_image=True, write_dotenv=True):
    kt, ktlog = fake_keytool(tmp_path)
    dk, dklog = fake_docker(tmp_path, kt, has_image=has_image)
    if write_dotenv:
        (repo / ".env").write_text("X=1\n")
    return dict(DOCKER_CMD=str(dk), COMPOSE=f"{dk} compose"), dklog, ktlog


def _opts(run: list) -> list:
    """Hanya opsi docker (sebelum nama image); argumen keytool sesudahnya ikut `-v` dari `-list -v`."""
    return run[: run.index("reverse-apk-signer")]


def _run_calls(dklog):
    return [c for c in read_log(dklog) if c[:1] == ["run"]]


def test_docker_mode_run_arguments_are_confined(repo, tmp_path):
    env, dklog, _ = _docker_env(tmp_path, repo)
    r = run_ks(repo, "create", **env)
    assert r.returncode == 0, r.stderr
    calls = read_log(dklog)
    assert calls[0][:2] == ["image", "inspect"]
    runs = _run_calls(dklog)
    assert runs, "docker run harus dipanggil"
    secrets = tmp_path / "secrets"
    for run in runs:
        flat = " ".join(run)
        for must in ("--rm", "--pull never", "--network none", "--read-only", "--tmpfs /tmp:rw,size=64m,nosuid", "--cap-drop ALL",
                     "--security-opt no-new-privileges:true", "-e HOME=/tmp", "--entrypoint keytool", "reverse-apk-signer"):
            assert must in flat, must
        assert not re.search(r"(?<!no)exec", run[run.index("--tmpfs") + 1]), "tmpfs /tmp tidak boleh exec"
        assert run[run.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}", "harus user host (id -u:id -g), bukan uid tetap"
        for bad in ("--privileged", "-p", "--publish", "host", "docker.sock", "--cap-add", "--volumes-from"):
            assert bad not in run
        opts = _opts(run)
        rw = [opts[i + 1] for i, a in enumerate(opts) if a == "-v" and not opts[i + 1].endswith(":ro")]
        assert len(rw) == 1, f"tepat satu mount rw, ditemukan {rw}"
        src, dst = rw[0].split(":")
        assert dst == "/out" and Path(src).parent == secrets.resolve() and Path(src).name.startswith(".keystore-work.")
        assert Path(src) != secrets.resolve()
        assert (secrets / PW).read_text() not in flat
    assert (secrets / KS).is_file() and mode_of(secrets / KS) == 0o600


def test_docker_mode_does_not_see_other_secrets(repo, tmp_path):
    env, dklog, _ = _docker_env(tmp_path, repo)
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "admin_password_hash").write_text("RAHASIA-ADMIN")
    assert run_ks(repo, "create", **env).returncode == 0
    assert all("admin_password_hash" not in " ".join(c) for c in read_log(dklog))
    assert (secrets / "admin_password_hash").read_text() == "RAHASIA-ADMIN"


def test_docker_mode_builds_image_when_missing(repo, tmp_path):
    env, dklog, _ = _docker_env(tmp_path, repo, has_image=False)
    r = run_ks(repo, "create", **env)
    assert r.returncode == 0, r.stderr
    calls = read_log(dklog)
    assert any(c[:1] == ["compose"] and c[1:] == ["--profile", "build", "build", "signer"] for c in calls)
    assert calls.index(next(c for c in calls if c[:1] == ["compose"])) < calls.index(_run_calls(dklog)[0])


def test_docker_mode_missing_image_without_dotenv_fails_clearly(repo, tmp_path):
    env, dklog, _ = _docker_env(tmp_path, repo, has_image=False, write_dotenv=False)
    r = run_ks(repo, "create", **env)
    assert r.returncode == 1 and "make init" in r.stderr
    assert _run_calls(dklog) == [] and sorted(p.name for p in (tmp_path / "secrets").iterdir()) == []


def test_docker_mode_info_mounts_read_only_only(made, tmp_path):
    repo, secrets, _, _ = made
    env, dklog, _ = _docker_env(tmp_path, repo)
    r = run_ks(repo, "info", **env)
    assert r.returncode == 0, r.stderr
    run = _run_calls(dklog)[0]
    opts = _opts(run)
    mounts = [opts[i + 1] for i, a in enumerate(opts) if a == "-v"]
    assert len(mounts) == 2 and all(m.endswith(":ro") for m in mounts)
    assert (secrets / PW).read_text() not in " ".join(run) + r.stdout + r.stderr


# ================================================================================ 10-11: info & status
def test_info_prints_fingerprint_dn_validity_algorithm(made, tmp_path):
    repo, secrets, _, _ = made
    kt, _ = fake_keytool(tmp_path)
    r = run_ks(repo, "info", KEYTOOL_CMD=str(kt))
    assert r.returncode == 0, r.stderr
    out = r.stdout
    for must in ("reverse-apk", "3072-bit RSA", "SHA256withRSA", "PKCS12", "2056", "(mode 600)"):
        assert must in out, must
    colon = re.search(r"SHA-256 \(keytool\)\s*:\s*((?:[0-9A-F]{2}:){31}[0-9A-F]{2})", out)
    plain = re.search(r"SHA-256 \(heks kecil\):\s*([0-9a-f]{64})", out)
    assert colon and plain and colon.group(1).replace(":", "").lower() == plain.group(1)
    assert "⚠" not in out


def test_info_warns_on_loose_mode(made, tmp_path):
    repo, secrets, _, _ = made
    (secrets / KS).chmod(0o644)
    kt, _ = fake_keytool(tmp_path)
    r = run_ks(repo, "info", KEYTOOL_CMD=str(kt))
    assert r.returncode == 0 and "⚠" in r.stderr and "chmod 600" in r.stderr


def test_info_without_keystore_and_with_single_file(repo, tmp_path):
    kt, _ = fake_keytool(tmp_path)
    r = run_ks(repo, "info", KEYTOOL_CMD=str(kt))
    assert r.returncode == 1 and "belum ada" in r.stderr
    secrets = tmp_path / "secrets"
    secrets.mkdir(exist_ok=True)
    (secrets / PW).write_text("x")
    r = run_ks(repo, "info", KEYTOOL_CMD=str(kt))
    assert r.returncode == 2


def test_status_states(repo, tmp_path):
    secrets = tmp_path / "secrets"
    r = run_ks(repo, "status")  # tidak ada keystore: peringatan, tetapi kode 0 (stack tetap boleh naik)
    assert r.returncode == 0 and "belum dibuat" in r.stderr
    kt, _ = fake_keytool(tmp_path)
    assert run_ks(repo, "create", KEYTOOL_CMD=str(kt)).returncode == 0
    r = run_ks(repo, "status")
    assert r.returncode == 0 and r.stdout.startswith("✓") and "600/600" in r.stdout
    (secrets / PW).chmod(0o644)
    r = run_ks(repo, "status")
    assert r.returncode == 0 and "600/644" in r.stderr and r.stdout == ""
    (secrets / ".keystore-work.sisa").mkdir()
    assert "sisa direktori kerja" in run_ks(repo, "status").stderr
    (secrets / KS).unlink()
    r = run_ks(repo, "status")
    assert r.returncode == 2 and PW in r.stderr


def test_usage_error():
    r = subprocess.run(["bash", str(SCRIPT_SRC), "bukan-perintah"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 64 and "Pemakaian" in r.stderr


# ================================================================================ 12: statis repo
def test_gitignore_ignores_secrets():
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert re.search(r"^secrets/$", text, re.M)
    if shutil.which("git") and (ROOT / ".git").exists():
        for name in (KS, PW):
            r = subprocess.run(["git", "check-ignore", "-q", f"secrets/{name}"], cwd=ROOT)
            assert r.returncode == 0, f"secrets/{name} harus di-gitignore"
        tracked = subprocess.run(["git", "ls-files", "secrets"], cwd=ROOT, capture_output=True, text=True).stdout
        assert tracked.strip() == "", "tidak boleh ada berkas di secrets/ yang dilacak git"


def test_script_is_executable_bash_with_strict_mode():
    text = SCRIPT_SRC.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n") and "\nset -euo pipefail\n" in text
    assert os.access(SCRIPT_SRC, os.X_OK), "scripts/keystore.sh harus executable"
    assert subprocess.run(["bash", "-n", str(SCRIPT_SRC)]).returncode == 0
    if shutil.which("git") and (ROOT / ".git").exists():
        mode = subprocess.run(["git", "ls-files", "-s", "scripts/keystore.sh"], cwd=ROOT, capture_output=True, text=True).stdout.split()
        assert not mode or mode[0] == "100755"


def test_script_text_has_no_dangerous_docker_options():
    text = SCRIPT_SRC.read_text(encoding="utf-8")
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    for bad in ("--privileged", "docker.sock", "--network host", "--cap-add"):
        assert bad not in code, bad
    for entry in re.findall(r"--tmpfs[\s\"',]+(\S+)", code):
        assert not re.search(r"(?<!no)exec", entry), entry
    assert '-v "$2:/out"' in code, "satu-satunya mount rw adalah direktori kerja"
    assert '"$SECRETS_DIR:' not in code, "seluruh secrets/ tidak boleh di-mount"


def test_init_calls_keystore_after_secrets_dir_and_before_done():
    init = (ROOT / "scripts/init.sh").read_text(encoding="utf-8")
    assert "./scripts/keystore.sh create" in init
    assert init.index("mkdir -p secrets") < init.index("./scripts/keystore.sh create") < init.index('echo "Selesai')
    assert "set -euo pipefail" in init, "kegagalan keystore harus menghentikan init"
    assert re.search(r"cadangkan secrets/signing_keystore\.p12 DAN secrets/signing_keystore_pass", init)
    assert subprocess.run(["bash", "-n", str(ROOT / "scripts/init.sh")]).returncode == 0


def test_makefile_has_keystore_targets_and_help_lists_them():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    phony = next(ln for ln in makefile.splitlines() if ln.startswith(".PHONY:"))
    for target, sub in (("keystore", "create"), ("keystore-info", "info")):
        assert re.search(rf"\b{target}\b", phony), f"{target} harus ada di .PHONY"
        m = re.search(rf"^{target}:.*## .+\n((?:\t.*\n)+)", makefile, re.M)
        assert m, f"{target} harus punya deskripsi `## ` dan resep"
        assert f"./scripts/keystore.sh {sub}" in m.group(1)
    doctor = re.search(r"^doctor:.*\n((?:\t.*\n)+)", makefile, re.M).group(1)
    assert "./scripts/keystore.sh status" in doctor and "|| true" in next(ln for ln in doctor.splitlines() if "keystore.sh status" in ln)
    assert re.search(r"^init:.*keystore", makefile, re.M)
    if shutil.which("make"):
        out = subprocess.run(["make", "-s", "help"], cwd=ROOT, capture_output=True, text=True, timeout=30).stdout
        assert re.search(r"\bkeystore\b", out) and "keystore-info" in out


# ================================================================================ 13: compose belum merujuk keystore
def test_compose_does_not_reference_keystore_yet():
    """PENJAGA SADAR: pada Tahap 1 keystore BELUM dihubungkan ke layanan mana pun (menambah `secrets:`/volume ke `signer` merusak jaminan
    'signer tanpa secrets' dan cek 'tanpa /run/secrets' di signer-selftest). Tahap 2 (signer-daemon) MENGUBAH tes ini secara sadar."""
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    code = "\n".join(re.sub(r"\s+#.*$", "", ln) for ln in compose.splitlines() if not ln.strip().startswith("#"))
    for name, block in services(code).items():
        assert not re.search(r"signing_|keystore", block, re.I), f"layanan {name} tidak boleh merujuk keystore pada Tahap 1"
    assert not re.search(r"signing_keystore", code), "docker-compose.yml tidak boleh menyebut berkas keystore"
    top = code.split("\nsecrets:\n", 1)[1]
    assert re.findall(r"(?m)^  (\w+):", top) == ["admin_password_hash"]


def test_compose_is_still_valid_yaml():
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    try:
        import yaml  # PyYAML tidak ada di requirements; dipakai bila tersedia
    except ImportError:
        yaml = None
    if yaml:
        doc = yaml.safe_load(text)
        assert "signer" in doc["services"] and list(doc["secrets"]) == ["admin_password_hash"]
    else:  # pemeriksaan struktur sederhana
        assert "\t" not in text, "YAML tidak boleh berisi tab"
        svc = services(text)
        assert "signer" in svc and "web" in svc and "\nsecrets:\n  admin_password_hash:\n" in text


# ================================================================================ 14-18: keytool ASLI
@pytest.fixture(scope="module")
def real(tmp_path_factory):
    """Satu keystore asli (dibuat skrip + keytool asli) dipakai bersama oleh semua tes ber-JDK."""
    if REAL_KEYTOOL is None:
        pytest.skip("keytool tidak ada")
    probe = subprocess.run([REAL_KEYTOOL, "-version"], capture_output=True, text=True, timeout=60)
    if probe.returncode != 0:
        pytest.skip(f"keytool ada tetapi tidak bisa dijalankan: {probe.stderr.strip()[:100]}")
    base = tmp_path_factory.mktemp("real")
    (base / "repo/scripts").mkdir(parents=True)
    shutil.copy2(SCRIPT_SRC, base / "repo/scripts/keystore.sh")
    r = run_ks(base / "repo", "create", KEYTOOL_CMD=REAL_KEYTOOL)
    assert r.returncode == 0, r.stdout + r.stderr
    return base / "repo", base / "secrets", r


def _list_v(secrets: Path, pw_file: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([REAL_KEYTOOL, "-J-Duser.language=en", "-J-Duser.country=US", "-J-Duser.timezone=UTC", "-list", "-v", "-keystore", str(secrets / KS),
                           "-storepass:file", str(pw_file or secrets / PW)], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)


@needs_jdk
def test_real_pkcs12_is_valid(real):
    _, secrets, _ = real
    r = _list_v(secrets)
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert "Keystore type: PKCS12" in out and "Alias name: reverse-apk" in out
    assert out.count("PrivateKeyEntry") == 1
    assert "Subject Public Key Algorithm: 3072-bit RSA key" in out and "Signature algorithm name: SHA256withRSA" in out


@needs_jdk
def test_real_wrong_password_is_rejected(real, tmp_path):
    _, secrets, _ = real
    wrong = tmp_path / "salah"
    wrong.write_text("0" * 64)
    assert _list_v(secrets, wrong).returncode != 0


@needs_jdk
def test_real_validity_is_at_least_30_years(real):
    _, secrets, _ = real
    m = re.search(r"Valid from: (.+?) until: (.+)", _list_v(secrets).stdout)
    assert m
    fmt = "%a %b %d %H:%M:%S %Z %Y"
    start, end = (datetime.strptime(x.strip(), fmt) for x in m.groups())
    assert (end - start).days >= 10950 - 1
    assert end.year > 2033


@needs_jdk
def test_real_dn_and_fingerprint_match_independent_computation(real):
    repo, secrets, _ = real
    out = _list_v(secrets).stdout
    assert re.search(r"^Owner: CN=reverse-apk [0-9a-f]{8}$", out, re.M)
    pem = subprocess.run([REAL_KEYTOOL, "-exportcert", "-rfc", "-alias", "reverse-apk", "-keystore", str(secrets / KS), "-storepass:file", str(secrets / PW)],
                         capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    assert pem.returncode == 0, pem.stderr
    expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.stdout.strip())).hexdigest()
    info = run_ks(repo, "info", KEYTOOL_CMD=REAL_KEYTOOL)
    assert info.returncode == 0, info.stderr
    assert re.search(r"SHA-256 \(heks kecil\):\s*" + expected, info.stdout)
    assert "CN=reverse-apk" in info.stdout and "3072-bit RSA" in info.stdout


@needs_jdk
def test_real_files_have_strict_modes_and_password_format(real):
    _, secrets, _ = real
    assert mode_of(secrets / KS) == 0o600, "keytool menulis 644: skrip harus chmod 600"
    assert mode_of(secrets / PW) == 0o600 and mode_of(secrets) == 0o700
    assert re.fullmatch(rb"[0-9a-f]{64}", (secrets / PW).read_bytes())


@needs_jdk
def test_real_second_create_keeps_hashes_and_single_file_fails(real, tmp_path):
    repo, secrets, _ = real
    before = (sha(secrets / KS), sha(secrets / PW))
    r = run_ks(repo, "create", secrets=secrets, KEYTOOL_CMD=REAL_KEYTOOL)
    assert r.returncode == 0 and "sudah ada" in r.stdout
    assert (sha(secrets / KS), sha(secrets / PW)) == before
    # satu berkas saja pada salinan: gagal tanpa menimpa
    copy = tmp_path / "copy"
    copy.mkdir()
    shutil.copy2(secrets / KS, copy / KS)
    h = sha(copy / KS)
    r = run_ks(repo, "create", secrets=copy, KEYTOOL_CMD=REAL_KEYTOOL)
    assert r.returncode == 2 and sha(copy / KS) == h and not (copy / PW).exists()
