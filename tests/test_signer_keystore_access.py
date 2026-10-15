"""Akses kunci untuk kontainer signer (uid 10001) — Tahap 2a, FEAT-003: `scripts/keystore.sh present|check|access|status|create`, berkas tambahan
`docker-compose.keystore.yml` dan gerbang Makefile.

Keputusan SADAR (menggantikan 'mode 600' Tahap 1): kontainer signer berjalan sebagai uid 10001, bukan pemilik berkas, dan Compose mengabaikan uid/gid/mode untuk
secret bersumber `file:`; maka kedua berkas keystore dibuat mode 644 DI DALAM `secrets/` yang tetap 700. Kerahasiaan bertumpu pada folder.

Semua tes berjalan TANPA root dan TANPA Docker (CI): "kontainer" ditiru dengan `KS_CONTAINER_UID` (uid yang diprediksi `check`) berbeda dari pemilik berkas uji, atau dengan
shim `stat`. Pembuktian dengan uid 10001 NYATA (`setpriv`, berkas milik uid lain di folder 700) dilakukan di sandbox root dan dilaporkan terpisah (verification.md);
tes yang butuh root (chown ke uid lain) di sini dilewati bila bukan root dan TIDAK dihitung sebagai "dijaga CI".
"""

from __future__ import annotations

import hashlib
import os
import pwd
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from rvcore import signkeys
from test_keystore_script import REAL_KEYTOOL, fake_keytool, needs_jdk, read_log, run_ks

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_SRC = ROOT / "scripts/keystore.sh"
MAKEFILE = ROOT / "Makefile"
KS, PW = "signing_keystore.p12", "signing_keystore_pass"
ME = os.getuid()
OTHER = str(ME + 1)  # uid 'kontainer' yang BUKAN pemilik berkas uji
try:
    OWNER = pwd.getpwuid(ME).pw_name  # nama pemilik berkas uji = nama yang dicetak `stat -c %U` oleh keystore.sh
except KeyError:
    OWNER = "UNKNOWN"
is_root = pytest.mark.skipif(ME != 0, reason="butuh root (chown ke uid lain); dibuktikan di sandbox root, BUKAN dijaga CI non-root")


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "repo/scripts").mkdir(parents=True)
    shutil.copy2(SCRIPT_SRC, tmp_path / "repo/scripts/keystore.sh")
    return tmp_path / "repo"


def plant(tmp_path: Path, ks: int | None = 0o644, pw: int | None = 0o644, folder: int = 0o700) -> Path:
    """secrets/ palsu (isi bebas) dengan mode yang diminta; None = berkas tidak dibuat."""
    d = tmp_path / "secrets"
    d.mkdir(exist_ok=True)
    for name, mode, body in ((KS, ks, b"FAKEP12\n"), (PW, pw, b"0" * 64)):
        if mode is not None:
            (d / name).write_bytes(body)
            (d / name).chmod(mode)
    d.chmod(folder)
    return d


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def unreadable_msg(name: str, mod: str, owner: str = OWNER, uid: int = ME, container: str = OTHER) -> str:
    return (f"✗ secrets/{name}: mode {mod} milik {owner} (uid {uid}). Kontainer signer berjalan sebagai uid {container} "
            "dan TIDAK bisa membacanya → jalankan: make keystore-access")


FOLDER_MSG = "✗ secrets/ mode {d} sedangkan berkas keystore {f}: user lain di server ini bisa membaca kunci → jalankan: chmod 700 secrets   (atau make keystore-access)"


# ================================================================================ present
def test_present_true_only_when_both_regular_files_exist_and_is_silent(repo, tmp_path):
    env = {"DOCKER_CMD": "/tidak/ada/docker", "KEYTOOL_CMD": ""}
    assert not (tmp_path / "secrets").exists()
    r = run_ks(repo, "present", **env)
    assert r.returncode == 1 and r.stdout == "" and r.stderr == ""
    assert not (tmp_path / "secrets").exists(), "present tidak boleh membuat secrets/"
    d = plant(tmp_path, ks=0o600, pw=None)
    assert run_ks(repo, "present", **env).returncode == 1, "satu berkas saja bukan 'ada'"
    (d / PW).write_text("x")
    r = run_ks(repo, "present", **env)
    assert r.returncode == 0 and r.stdout == "" and r.stderr == ""
    assert sorted(p.name for p in d.iterdir()) == sorted([KS, PW]), "present tidak mengubah apa pun"


@pytest.mark.parametrize("kind", ["symlink", "dangling", "dir", "fifo"])
def test_present_refuses_symlink_directory_and_fifo(repo, tmp_path, kind):
    d = plant(tmp_path, ks=None, pw=0o644)
    target = d / KS
    if kind == "symlink":
        (tmp_path / "lain").write_text("x")
        target.symlink_to(tmp_path / "lain")
    elif kind == "dangling":
        target.symlink_to(tmp_path / "tidak-ada")
    elif kind == "dir":
        target.mkdir()
    else:
        os.mkfifo(target)
    r = run_ks(repo, "present")
    assert r.returncode == 1 and r.stdout == "" and r.stderr == ""


# ================================================================================ check: kode keluar dan pesan persis
def test_check_unreadable_by_container_uid_is_code_10_with_the_exact_message(repo, tmp_path):
    plant(tmp_path, ks=0o600, pw=0o644)
    r = run_ks(repo, "check", KS_CONTAINER_UID=OTHER)
    assert r.returncode == 10, r.stderr
    assert unreadable_msg(KS, "600") in r.stderr
    assert "signing_keystore_pass" not in r.stderr, "berkas 644 terbaca; hanya yang 600 dilaporkan"
    assert r.stdout == ""
    plant(tmp_path, ks=0o600, pw=0o600)
    r = run_ks(repo, "check", KS_CONTAINER_UID=OTHER)
    assert r.returncode == 10 and unreadable_msg(KS, "600") in r.stderr and unreadable_msg(PW, "600") in r.stderr


def test_check_world_readable_is_ok_and_prints_a_single_check_line(repo, tmp_path):
    plant(tmp_path)
    r = run_ks(repo, "check", KS_CONTAINER_UID=OTHER)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("✓") and r.stdout.count("\n") == 1 and r.stderr == ""
    assert f"uid {OTHER}" in r.stdout and "700" in r.stdout and "644/644" in r.stdout


def test_check_open_folder_is_code_11_even_when_files_are_644(repo, tmp_path):
    plant(tmp_path, folder=0o755)
    r = run_ks(repo, "check", KS_CONTAINER_UID=OTHER)
    assert r.returncode == 11, r.stderr
    assert FOLDER_MSG.format(d="755", f="644") in r.stderr


@pytest.mark.parametrize("folder", [0o755, 0o750, 0o710, 0o705])
def test_check_folder_wins_over_unreadable_file(repo, tmp_path, folder):
    """Prioritas: FOLDER dulu (11), baru berkas (10) — meski berkas 600 juga tak terbaca uid kontainer."""
    plant(tmp_path, ks=0o600, pw=0o600, folder=folder)
    r = run_ks(repo, "check", KS_CONTAINER_UID=OTHER)
    assert r.returncode == 11, r.stderr
    assert f"secrets/ mode {folder:o}" in r.stderr and "chmod 700 secrets" in r.stderr and "make keystore-access" in r.stderr
    assert "TIDAK bisa membacanya" not in r.stderr


def test_check_container_uid_equal_to_owner_reads_even_mode_600(repo, tmp_path):
    plant(tmp_path, ks=0o600, pw=0o600)
    r = run_ks(repo, "check", KS_CONTAINER_UID=str(ME))
    assert r.returncode == 0 and r.stdout.startswith("✓"), r.stderr


def test_check_default_container_uid_is_10001(repo, tmp_path):
    plant(tmp_path, ks=0o600, pw=0o644)
    r = run_ks(repo, "check")
    if ME == 10001:
        assert r.returncode == 0
    else:
        assert r.returncode == 10 and "uid 10001" in r.stderr and "make keystore-access" in r.stderr


STAT_SHIM = """#!/bin/bash
# stat palsu: hanya untuk format '%u %g %a %U' mengembalikan FAKE_STAT_<nama berkas>; selebihnya stat asli.
if [ "${1:-}" = "-c" ] && [ "${2:-}" = "%u %g %a %U" ]; then
  case "$3" in
    */signing_keystore.p12) echo "$FAKE_STAT_P12"; exit 0 ;;
    */signing_keystore_pass) echo "$FAKE_STAT_PASS"; exit 0 ;;
  esac
fi
exec REAL_STAT "$@"
"""


def _stat_shim(tmp_path: Path) -> str:
    d = tmp_path / "statshim"
    d.mkdir(exist_ok=True)
    (d / "stat").write_text(STAT_SHIM.replace("REAL_STAT", shutil.which("stat")), encoding="utf-8")
    (d / "stat").chmod(0o755)
    return f"{d}:{os.environ['PATH']}"


@pytest.mark.parametrize("uid,gid,perm,container,expected", [
    (1000, 10001, "640", "10001", 0),   # gid berkas == uid kontainer dan g+r  -> terbaca
    (1000, 10001, "600", "10001", 10),  # gid cocok tetapi TANPA g+r            -> tak terbaca
    (1000, 2000, "640", "10001", 10),   # g+r tetapi gid BUKAN uid kontainer    -> tak terbaca
    (1000, 2000, "604", "10001", 0),    # o+r                                   -> terbaca
    (10001, 2000, "600", "10001", 0),   # pemilik == uid kontainer              -> terbaca
])
def test_check_prediction_rule_uid_or_other_read_or_group_match(repo, tmp_path, uid, gid, perm, container, expected):
    """Tiga kasus I3-12 (+ dua penunjang) dengan shim `stat`, jadi dijaga CI non-root: terbaca = uid==U atau o+r atau (gid==U dan g+r)."""
    plant(tmp_path, ks=0o644, pw=0o644)  # mode nyata tidak dipakai untuk berkas; folder 700 nyata
    line = f"{uid} {gid} {perm} pemilik"
    r = run_ks(repo, "check", KS_CONTAINER_UID=container, PATH=_stat_shim(tmp_path), FAKE_STAT_P12=line, FAKE_STAT_PASS=line)
    assert r.returncode == expected, r.stderr
    if expected == 10:
        assert f"mode {perm} milik pemilik (uid {uid}). Kontainer signer berjalan sebagai uid {container} dan TIDAK bisa membacanya" in r.stderr


@is_root
def test_check_group_rule_with_real_chown_as_root(repo, tmp_path):
    d = plant(tmp_path, ks=0o640, pw=0o640)
    for name in (KS, PW):
        os.chown(d / name, 1000, 20001)
    assert run_ks(repo, "check", KS_CONTAINER_UID="20001").returncode == 0
    assert run_ks(repo, "check", KS_CONTAINER_UID="20002").returncode == 10
    os.chmod(d / KS, 0o600)
    assert run_ks(repo, "check", KS_CONTAINER_UID="20001").returncode == 10


def test_check_missing_inconsistent_and_bad_uid(repo, tmp_path):
    r = run_ks(repo, "check")
    assert r.returncode == 2 and "belum ada" in r.stderr
    d = plant(tmp_path, ks=0o644, pw=None)
    r = run_ks(repo, "check")
    assert r.returncode == 2 and KS in r.stderr
    (d / PW).write_text("x")
    (d / KS).unlink()
    (tmp_path / "lain").write_text("x")
    (d / KS).symlink_to(tmp_path / "lain")
    assert run_ks(repo, "check").returncode == 2
    assert run_ks(repo, "check", KS_CONTAINER_UID="abc").returncode == 64


def test_check_never_reads_file_contents_or_changes_anything(repo, tmp_path):
    d = plant(tmp_path, ks=0o600, pw=0o600, folder=0o755)
    before = {p.name: (mode(p), sha(p), p.stat().st_mtime_ns) for p in d.iterdir()}
    assert run_ks(repo, "check", KS_CONTAINER_UID=OTHER).returncode == 11
    assert mode(d) == 0o755
    assert {p.name: (mode(p), sha(p), p.stat().st_mtime_ns) for p in d.iterdir()} == before


# ================================================================================ access
def test_access_fixes_600_to_644_without_changing_content_and_shows_a_table(repo, tmp_path):
    d = plant(tmp_path, ks=0o600, pw=0o600, folder=0o755)
    hashes = (sha(d / KS), sha(d / PW))
    r = run_ks(repo, "access")
    assert r.returncode == 0, r.stderr
    assert (mode(d), mode(d / KS), mode(d / PW)) == (0o700, 0o644, 0o644)
    assert (sha(d / KS), sha(d / PW)) == hashes, "isi berkas tidak boleh berubah"
    assert "755 → 700" in r.stdout and r.stdout.count("600 → 644") == 2
    assert "Kompromi" in r.stdout and "secrets/" in r.stdout
    assert run_ks(repo, "check", KS_CONTAINER_UID=OTHER).returncode == 0
    again = run_ks(repo, "access")
    assert again.returncode == 0 and again.stdout.count("sudah benar") == 3


def test_access_auto_prints_one_line_only_when_something_changed(repo, tmp_path):
    d = plant(tmp_path, ks=0o600, pw=0o644)
    r = run_ks(repo, "access", "--auto")
    assert r.returncode == 0 and r.stderr == ""
    assert len(r.stdout.splitlines()) == 1 and "600→644" in r.stdout and KS in r.stdout
    assert (mode(d / KS), mode(d / PW)) == (0o644, 0o644)
    again = run_ks(repo, "access", "--auto")
    assert again.returncode == 0 and again.stdout == "" and again.stderr == ""


def test_access_auto_is_silent_and_creates_nothing_without_a_keystore(repo, tmp_path):
    r = run_ks(repo, "access", "--auto")
    assert r.returncode == 0 and r.stdout == "" and r.stderr == ""
    assert not (tmp_path / "secrets").exists()
    r = run_ks(repo, "access")
    assert r.returncode == 1 and "make keystore" in r.stderr and not (tmp_path / "secrets").exists()


@pytest.mark.parametrize("kind", ["symlink", "dangling", "dir", "partial", "partial_pass"])
def test_access_auto_never_fails_hard(repo, tmp_path, kind):
    """--auto dipanggil `make up` || true, tetapi kodenya sendiri WAJIB 0 (peringatan saja): symlink, direktori, satu berkas."""
    d = plant(tmp_path, ks=None, pw=0o600)
    if kind == "symlink":
        (tmp_path / "lain").write_text("x")
        (tmp_path / "lain").chmod(0o600)
        (d / KS).symlink_to(tmp_path / "lain")
    elif kind == "dangling":
        (d / KS).symlink_to(tmp_path / "tidak-ada")
    elif kind == "dir":
        (d / KS).mkdir()
    elif kind == "partial":
        (d / KS).write_text("x")
        (d / KS).chmod(0o600)
        (d / PW).unlink()
    r = run_ks(repo, "access", "--auto")
    assert r.returncode == 0, r.stderr
    assert r.stdout == "", "tidak ada ✓ palsu bila tidak ada yang diperbaiki"
    assert r.stderr == "" or r.stderr.startswith("⚠")
    if kind in ("symlink", "dir", "dangling"):
        assert "BUKAN berkas biasa" in r.stderr
        assert mode(d / PW) == 0o600, "tidak ada yang diubah bila ada anomali"
    if kind == "symlink":
        assert mode(tmp_path / "lain") == 0o600, "symlink tidak boleh diikuti chmod"
    non_auto = run_ks(repo, "access")
    assert non_auto.returncode == 2, non_auto.stderr


@is_root
def test_access_auto_does_not_fail_when_not_the_owner_and_leaves_files_alone(repo, tmp_path):
    d = plant(tmp_path, ks=0o600, pw=0o600, folder=0o755)
    for name in (KS, PW):
        os.chown(d / name, 1234, 1234)
    os.chown(d, 1234, 1234)
    # root yang menjalankan skrip BUKAN pemilik berkas (-O salah): tidak boleh diubah.
    r = run_ks(repo, "access", "--auto")
    assert r.returncode == 0 and "bukan milik user ini" in r.stderr
    assert (mode(d), mode(d / KS), mode(d / PW)) == (0o755, 0o600, 0o600)
    assert run_ks(repo, "access").returncode == 1


def test_access_touches_only_the_two_keystore_files_and_the_folder(repo, tmp_path):
    d = plant(tmp_path, ks=0o600, pw=0o600, folder=0o755)
    other = d / "admin_password_hash"
    other.write_text("hash")
    other.chmod(0o640)
    lock = d / ".signer-verify.lock"
    lock.write_text("")
    lock.chmod(0o600)
    assert run_ks(repo, "access", "--auto").returncode == 0
    assert mode(other) == 0o640 and mode(lock) == 0o600


def test_access_rejects_unknown_option(repo, tmp_path):
    plant(tmp_path)
    assert run_ks(repo, "access").returncode == 0, "subperintah access harus dikenal"
    assert run_ks(repo, "access", "--bukan-opsi").returncode == 64


# ================================================================================ status & create & info
def test_status_uses_the_new_rule_and_ignores_the_verify_lock_file(repo, tmp_path):
    d = plant(tmp_path)
    (d / ".signer-verify.lock").write_text("")
    r = run_ks(repo, "status", KS_CONTAINER_UID=OTHER)
    assert r.returncode == 0 and r.stderr == ""
    assert r.stdout.strip() == "✓ keystore penanda tangan ada (mode 644/644, folder 700); pastikan sudah dicadangkan"
    (d / KS).chmod(0o600)
    r = run_ks(repo, "status", KS_CONTAINER_UID=OTHER)
    assert r.returncode == 0 and r.stdout == "" and unreadable_msg(KS, "600").replace("✗", "⚠") in r.stderr
    (d / KS).chmod(0o644)
    d.chmod(0o755)
    r = run_ks(repo, "status", KS_CONTAINER_UID=OTHER)
    d.chmod(0o700)
    assert r.returncode == 0 and r.stdout == "" and FOLDER_MSG.format(d="755", f="644").replace("✗", "⚠") in r.stderr


def test_status_without_keystore_is_zero_and_a_single_file_is_two(repo, tmp_path):
    r = run_ks(repo, "status")
    assert r.returncode == 0 and "belum dibuat" in r.stderr
    plant(tmp_path, ks=0o644, pw=None)
    assert run_ks(repo, "status").returncode == 2


def test_create_gives_644_files_in_a_700_folder_and_publishes_with_those_modes(repo, tmp_path):
    kt, _ = fake_keytool(tmp_path)
    r = run_ks(repo, "create", KEYTOOL_CMD=str(kt), KS_CONTAINER_UID=OTHER)
    assert r.returncode == 0, r.stderr
    d = tmp_path / "secrets"
    assert (mode(d), mode(d / KS), mode(d / PW)) == (0o700, 0o644, 0o644)
    assert "⚠" not in r.stderr, "keadaan benar (644/700) tidak boleh menimbulkan peringatan"
    assert run_ks(repo, "check", KS_CONTAINER_UID=OTHER).returncode == 0
    assert not list(d.glob(".keystore-work.*"))


def test_create_on_existing_600_keystore_repairs_access_without_calling_keytool(repo, tmp_path):
    kt, log = fake_keytool(tmp_path)
    assert run_ks(repo, "create", KEYTOOL_CMD=str(kt)).returncode == 0
    d = tmp_path / "secrets"
    for name in (KS, PW):
        (d / name).chmod(0o600)  # mis. dipulihkan dari cadangan dengan umask 077
    hashes = (sha(d / KS), sha(d / PW))
    calls = len(read_log(log))
    r = run_ks(repo, "create", KEYTOOL_CMD=str(kt))
    assert r.returncode == 0 and "sudah ada" in r.stdout and "600→644" in r.stdout
    assert (mode(d / KS), mode(d / PW)) == (0o644, 0o644) and (sha(d / KS), sha(d / PW)) == hashes
    assert len(read_log(log)) == calls, "keytool tidak boleh dipanggil"


def test_create_refuses_a_directory_left_by_docker_and_mentions_rmdir(repo, tmp_path):
    d = plant(tmp_path, ks=None, pw=None)
    (d / KS).mkdir()
    kt, log = fake_keytool(tmp_path)
    r = run_ks(repo, "create", KEYTOOL_CMD=str(kt))
    assert r.returncode == 2 and "BUKAN berkas biasa" in r.stderr and "rmdir" in r.stderr
    assert read_log(log) == []


@needs_jdk
def test_real_keytool_create_then_600_repair_keeps_the_same_key(tmp_path):
    (tmp_path / "repo/scripts").mkdir(parents=True)
    shutil.copy2(SCRIPT_SRC, tmp_path / "repo/scripts/keystore.sh")
    repo = tmp_path / "repo"
    assert run_ks(repo, "create", KEYTOOL_CMD=REAL_KEYTOOL).returncode == 0
    d = tmp_path / "secrets"
    assert (mode(d), mode(d / KS), mode(d / PW)) == (0o700, 0o644, 0o644)
    for name in (KS, PW):
        (d / name).chmod(0o600)
    hashes = (sha(d / KS), sha(d / PW))
    assert run_ks(repo, "check", KS_CONTAINER_UID=OTHER).returncode == 10
    assert run_ks(repo, "access").returncode == 0
    assert (sha(d / KS), sha(d / PW)) == hashes
    assert run_ks(repo, "check", KS_CONTAINER_UID=OTHER).returncode == 0
    info = run_ks(repo, "info", KEYTOOL_CMD=REAL_KEYTOOL)
    assert info.returncode == 0 and "⚠" not in info.stderr and "(mode 644)" in info.stdout


def test_ks_alias_in_the_script_equals_the_alias_the_daemon_uses():
    m = re.search(r"(?m)^readonly KS_ALIAS=(\S+)$", SCRIPT_SRC.read_text(encoding="utf-8"))
    assert m and m.group(1) == signkeys.ALIAS == "reverse-apk"


def test_script_documents_the_644_compromise_and_no_longer_says_unconnected():
    text = SCRIPT_SRC.read_text(encoding="utf-8")
    head = text.split("set -euo pipefail", 1)[0]
    assert "644" in head and "KOMPROMI" in head and "docker-compose.keystore.yml" in head
    assert "BELUM dihubungkan" not in text
    assert "mode berkas keystore/sandi bukan 600" not in text and "Perbaiki: chmod 600" not in text


def test_usage_lists_new_subcommands():
    r = subprocess.run(["bash", str(SCRIPT_SRC), "bukan-perintah"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 64 and all(w in r.stderr for w in ("present", "access", "check"))


# ================================================================================ berkas tambahan compose
_EXTRA_FILE = ROOT / "docker-compose.keystore.yml"
EXTRA = _EXTRA_FILE.read_text(encoding="utf-8") if _EXTRA_FILE.exists() else ""  # hilang -> tes gagal dengan assert yang jelas, bukan galat pengumpulan
BASE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")


def _code(text: str) -> str:
    return "\n".join(re.sub(r"\s+#.*$", "", ln) for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#"))


def override_violations(text: str) -> list[str]:
    """Pemeriksa TEKS (tanpa PyYAML; dasar: regex dari design-review I3-1): berkas tambahan hanya boleh `services.signer.{secrets,labels}` + `secrets`."""
    code = _code(text)
    bad: list[str] = []
    top = re.findall(r"(?m)^([A-Za-z][\w-]*):", code)
    if top != ["services", "secrets"]:
        bad.append(f"kunci tingkat-atas {top}")
    svc_body = code.split("\nsecrets:\n", 1)[0].split("services:\n", 1)[-1]
    names = re.findall(r"(?m)^  ([\w-]+):\s*$", svc_body)
    if names != ["signer"]:
        bad.append(f"layanan {names}")
    keys = sorted(re.findall(r"(?m)^    ([\w.-]+):", svc_body))
    if keys != ["labels", "secrets"]:
        bad.append(f"kunci di signer {keys}")
    labels = re.findall(r"(?m)^      ([\w.-]+):", svc_body)
    if labels != ["reverse-apk.keystore-stamp"]:
        bad.append(f"label {labels}")
    if not re.search(r'(?m)^      reverse-apk\.keystore-stamp: "\$\{KEYSTORE_STAMP:-\}"$', svc_body):
        bad.append("label stempel hilang")
    if not re.search(r"(?m)^    secrets: \[signing_keystore, signing_keystore_pass\]$", svc_body):
        bad.append("daftar secret signer bukan persis dua")
    secrets_body = code.split("\nsecrets:\n", 1)[1] if "\nsecrets:\n" in code else ""
    if re.findall(r"(?m)^  (\w+):", secrets_body) != ["signing_keystore", "signing_keystore_pass"]:
        bad.append("secret tingkat-atas bukan persis dua")
    files = re.findall(r"file:\s*(\S+?)\s*\}", secrets_body)
    if files != ["./secrets/signing_keystore.p12", "./secrets/signing_keystore_pass"]:
        bad.append(f"berkas sumber {files}")
    if "tmpfs" in code:
        bad.append("tmpfs")
    return bad


def test_override_file_has_exactly_the_agreed_shape():
    assert override_violations(EXTRA) == []
    code = _code(EXTRA)
    assert code == "\n".join([
        "services:",
        "  signer:",
        "    secrets: [signing_keystore, signing_keystore_pass]",
        "    labels:",
        '      reverse-apk.keystore-stamp: "${KEYSTORE_STAMP:-}"',
        "secrets:",
        "  signing_keystore:      { file: ./secrets/signing_keystore.p12 }",
        "  signing_keystore_pass: { file: ./secrets/signing_keystore_pass }",
    ])
    assert "\t" not in EXTRA
    assert EXTRA.lstrip().startswith("#"), "komentar header Indonesia: hanya dimuat Makefile bila kedua berkas ada"
    assert "Hanya dimuat" in EXTRA and "JANGAN dimuat" in EXTRA


MUTATIONS = {
    "read_only: false": lambda t: t.replace("  signer:\n", "  signer:\n    read_only: false\n"),
    "cap_add": lambda t: t.replace("  signer:\n", "  signer:\n    cap_add: [NET_ADMIN]\n"),
    "network_mode: bridge": lambda t: t.replace("  signer:\n", "  signer:\n    network_mode: bridge\n"),
    "volumes ./secrets": lambda t: t.replace("  signer:\n", '  signer:\n    volumes: ["./secrets:/leak"]\n'),
    "user 0:0": lambda t: t.replace("  signer:\n", '  signer:\n    user: "0:0"\n'),
    "tmpfs exec": lambda t: t.replace("  signer:\n", "  signer:\n    tmpfs:\n      - /tmp:rw,exec\n"),
    "environment": lambda t: t.replace("  signer:\n", "  signer:\n    environment:\n      X: 1\n"),
    "secret ketiga": lambda t: t.replace("secrets: [signing_keystore, signing_keystore_pass]", "secrets: [signing_keystore, signing_keystore_pass, admin_password_hash]"),
    "layanan lain": lambda t: t.replace("\nsecrets:\n", "\n  web:\n    secrets: [signing_keystore]\nsecrets:\n", 1),
    "label stempel hilang": lambda t: t.replace('      reverse-apk.keystore-stamp: "${KEYSTORE_STAMP:-}"', '      lain: "x"'),
    "kunci tingkat-atas": lambda t: t + "volumes:\n  x: {}\n",
    "sumber diganti": lambda t: t.replace("./secrets/signing_keystore.p12", "./secrets/admin_password_hash"),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_override_mutations_that_loosen_the_signer_are_caught(name):
    mutated = MUTATIONS[name](EXTRA)
    assert mutated != EXTRA, name
    assert override_violations(mutated), f"mutasi '{name}' pada berkas tambahan lolos"


HARDENING = ("network_mode", "read_only", "user", "cap_drop", "security_opt", "mem_limit", "cpus", "pids_limit", "tmpfs", "volumes", "environment",
             "restart", "stop_grace_period", "init", "profiles", "healthcheck", "build")


def deep_merge(base, over):
    """Gabungan ala Compose: pemetaan digabung rekursif, daftar ditambahkan (tanpa duplikat), skalar ditimpa."""
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = deep_merge(base[k], v) if k in base else v
        return out
    if isinstance(base, list) and isinstance(over, list):
        return base + [x for x in over if x not in base]
    return over


def test_deep_merge_keeps_every_hardening_key_of_the_signer_identical_to_base():
    yaml = pytest.importorskip("yaml")  # CI tidak punya PyYAML; ada di venv pengembangan
    base = yaml.safe_load(BASE)
    over = yaml.safe_load(EXTRA)
    merged = deep_merge(base, over)
    b, m = base["services"]["signer"], merged["services"]["signer"]
    for key in HARDENING:
        assert key in b, f"{key} tidak ada di base"
        assert m[key] == b[key], f"{key} berubah setelah digabung dengan berkas tambahan"
    assert m["volumes"] == ["builds:/data/builds", "signspool:/data/signspool"] and len(m["volumes"]) == 2
    assert m["tmpfs"] == ["/tmp:rw,size=256m,nosuid"]
    assert m["secrets"] == ["signing_keystore", "signing_keystore_pass"] and "secrets" not in b
    assert list(m["labels"]) == ["reverse-apk.keystore-stamp"]
    assert sorted(merged["secrets"]) == ["admin_password_hash", "signing_keystore", "signing_keystore_pass"]
    for name, svc in merged["services"].items():
        if name != "signer":
            assert svc == base["services"][name], f"layanan {name} berubah setelah digabung"
    assert sorted(merged["services"]) == sorted(base["services"])


@pytest.mark.parametrize("name", ["read_only: false", "cap_add", "network_mode: bridge", "volumes ./secrets", "user 0:0", "tmpfs exec", "environment"])
def test_deep_merge_detects_loosening_mutations_on_the_override(name):
    yaml = pytest.importorskip("yaml")
    base = yaml.safe_load(BASE)
    merged = deep_merge(base, yaml.safe_load(MUTATIONS[name](EXTRA)))
    b, m = base["services"]["signer"], merged["services"]["signer"]
    changed = [k for k in HARDENING if m.get(k) != b.get(k)] + [k for k in m if k not in b and k not in ("secrets", "labels")]
    assert changed, f"mutasi '{name}' tidak terlihat oleh perbandingan deep-merge"


# ================================================================================ Makefile: gerbang keystore
MAKE = shutil.which("make")
needs_make = pytest.mark.skipif(MAKE is None, reason="make tidak terpasang")
PRINT_VARS = '_t: ; @printf "%s|%s|%s" "$$COMPOSE_FILE" "$$COMPOSE_PROFILES" "$$KEYSTORE_STAMP"'


def _tree(tmp_path: Path, with_keystore: bool, **kw) -> Path:
    t = tmp_path / "tree"
    (t / "scripts").mkdir(parents=True)
    shutil.copy2(MAKEFILE, t / "Makefile")
    shutil.copy2(SCRIPT_SRC, t / "scripts/keystore.sh")
    (t / "secrets").mkdir()
    (t / "secrets").chmod(0o700)
    (t / "secrets/admin_password_hash").write_text("hash")
    if with_keystore:
        for n in (KS, PW):
            (t / "secrets" / n).write_text(n)
            (t / "secrets" / n).chmod(0o644)
    return t


def _make(tree: Path, *args: str, **env_extra: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k not in ("COMPOSE_FILE", "COMPOSE_PROFILES", "KEYSTORE_STAMP", "COMPOSE", "MAKEFLAGS", "MFLAGS", "MAKELEVEL")}
    env.update(env_extra)
    return subprocess.run([MAKE, "-s", "--no-print-directory", *args], cwd=tree, capture_output=True, text=True, env=env, timeout=60)


def _print_vars(tree: Path, **env_extra: str) -> str:
    r = _make(tree, "--eval=.PHONY: _t", f"--eval={PRINT_VARS}", "_t", **env_extra)
    assert r.returncode == 0, r.stderr
    return r.stdout


@needs_make
def test_makefile_gate_exports_compose_file_profile_and_stamp_only_with_both_files(tmp_path):
    tree = _tree(tmp_path, with_keystore=True)
    st = [(tree / "secrets" / n).stat() for n in (KS, PW)]
    stamp = "".join(f"{s.st_ino}-{s.st_size}-{int(s.st_mtime)}:" for s in st)
    assert _print_vars(tree) == f"docker-compose.yml:docker-compose.keystore.yml|build|{stamp}"
    assert stamp.count(":") == 2 and re.fullmatch(r"(\d+-\d+-\d+:){2}", stamp)


@needs_make
@pytest.mark.parametrize("kind", ["none", "only_p12", "only_pass", "symlink", "dir"])
def test_makefile_gate_is_empty_without_a_complete_keystore(tmp_path, kind):
    """Tanpa keystore perilaku Makefile identik dengan sebelumnya: tiga variabel kosong (CI tidak punya secrets/ sama sekali)."""
    tree = _tree(tmp_path, with_keystore=False)
    s = tree / "secrets"
    if kind == "only_p12":
        (s / KS).write_text("x")
    elif kind == "only_pass":
        (s / PW).write_text("x")
    elif kind == "symlink":
        (tree / "lain").write_text("x")
        (s / KS).symlink_to(tree / "lain")
        (s / PW).write_text("x")
    elif kind == "dir":
        (s / KS).mkdir()
        (s / PW).write_text("x")
    assert _print_vars(tree) == "||"


@needs_make
def test_makefile_gate_is_empty_when_the_secrets_folder_does_not_exist_at_all(tmp_path):
    tree = _tree(tmp_path, with_keystore=False)
    shutil.rmtree(tree / "secrets")
    assert _print_vars(tree) == "||"
    assert not (tree / "secrets").exists(), "evaluasi Makefile tidak boleh membuat secrets/"


@needs_make
def test_make_dry_run_up_and_restart_repair_access_before_compose(tmp_path):
    tree = _tree(tmp_path, with_keystore=True)
    for target, compose_line in (("up", "docker compose up -d --build"), ("restart", "docker compose up -d")):
        out = _make(tree, "-n", target).stdout.splitlines()
        access = next(n for n, ln in enumerate(out) if "./scripts/keystore.sh access --auto || true" in ln)
        assert access < out.index(compose_line), (target, out)
    assert "--profile" not in _make(tree, "-n", "up").stdout
    assert _make(tree, "-n", "down").stdout.strip() == "COMPOSE_PROFILES=build docker compose down"
    # tanpa keystore: perintah compose sama; `access --auto` tetap dipanggil (senyap, tidak mengubah apa pun)
    tree2 = _tree(tmp_path / "t2", with_keystore=False)
    out2 = _make(tree2, "-n", "up").stdout.splitlines()
    assert "docker compose up -d --build" in out2 and any("access --auto || true" in ln for ln in out2)


@needs_make
def test_make_up_runs_access_auto_for_real_and_fixes_a_600_keystore(tmp_path):
    """Bukan hanya -n: `up` dengan COMPOSE palsu (echo) benar-benar memperbaiki berkas 600 -> 644 sebelum perintah compose."""
    tree = _tree(tmp_path, with_keystore=True)
    for n in (KS, PW):
        (tree / "secrets" / n).chmod(0o600)
    r = _make(tree, "up", COMPOSE="echo COMPOSE-PALSU")
    assert r.returncode == 0, r.stderr
    assert "COMPOSE-PALSU up -d --build" in r.stdout and "600→644" in r.stdout
    assert r.stdout.index("600→644") < r.stdout.index("COMPOSE-PALSU")
    assert (mode(tree / "secrets" / KS), mode(tree / "secrets" / PW)) == (0o644, 0o644)


@needs_make
def test_make_up_never_fails_because_of_access_repair(tmp_path):
    tree = _tree(tmp_path, with_keystore=False)  # tanpa keystore: access --auto senyap
    r = _make(tree, "up", COMPOSE="echo COMPOSE-PALSU")
    assert r.returncode == 0 and r.stdout.strip() == "COMPOSE-PALSU up -d --build"
    (tree / "secrets" / KS).mkdir()  # anomali: direktori -> peringatan, tetap lanjut
    (tree / "secrets" / PW).write_text("x")
    r = _make(tree, "up", COMPOSE="echo COMPOSE-PALSU")
    assert r.returncode == 0 and "COMPOSE-PALSU up -d --build" in r.stdout and "BUKAN berkas biasa" in r.stderr


@needs_make
def test_make_help_lists_keystore_access(tmp_path):
    out = subprocess.run([MAKE, "-s", "help"], cwd=ROOT, capture_output=True, text=True, timeout=30).stdout
    assert re.search(r"keystore-access\s+\S", out)


def test_init_and_keystore_recipes_do_not_depend_on_the_keystore_gate():
    """P6/I3-11: Makefile dibaca SEBELUM resep jalan, jadi `make init up` dalam satu panggilan melihat keadaan lama; resep init/keystore tidak boleh bergantung pada variabel gerbang."""
    makefile = MAKEFILE.read_text(encoding="utf-8")
    for target in ("init", "keystore", "keystore-info", "keystore-access"):
        m = re.search(rf"^{target}:.*\n((?:\t.*\n)+)", makefile, re.M)
        assert m and not re.search(r"KEYSTORE_PRESENT|KEYSTORE_STAMP|COMPOSE_FILE|COMPOSE_PROFILES", m.group(1)), target
    assert makefile.count("export COMPOSE_FILE") == 1 and makefile.count("export COMPOSE_PROFILES") == 1 and makefile.count("export KEYSTORE_STAMP") == 1
    gate = makefile.split("ifeq ($(KEYSTORE_PRESENT),1)\n", 1)[1].split("\nendif", 1)[0]
    assert all(f"export {v}" in gate for v in ("COMPOSE_FILE", "COMPOSE_PROFILES", "KEYSTORE_STAMP"))
