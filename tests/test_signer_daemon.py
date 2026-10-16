"""Tes signer-daemon (Tahap 2a): fungsi murni -> alat PALSU (merekam argv/environ/stdin) -> alat NYATA (skip bersih bila env tidak diset).

Skrip tanpa ekstensi dimuat lewat SourceFileLoader (seperti signer-selftest). Env DATA_DIR / SIGNER_SECRETS_DIR disetel SEBELUM exec_module
karena konstanta dibaca saat impor. Tes yang berpotensi menggantung (FIFO) berjalan di utas dengan join(5).

Kelompok NYATA (nama berawalan test_real_) butuh Build-Tools 37, JDK 21 dan sebuah unsigned.apk nyata:
  SIGNER_TEST_BUILD_TOOLS=<.../build-tools/android-37.0> SIGNER_TEST_JAVA_HOME=<jdk21> SIGNER_TEST_APK=<unsigned.apk>
Tanpa ketiganya (CI) kelompok itu DILEWATI.
"""

from __future__ import annotations

import errno
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "services" / "signer" / "signer-daemon"
SERVICES = ROOT / "services"
PASSWORD = "0123456789abcdef" * 4                     # 64 heks tanpa newline, seperti make keystore
DER = b"0" + b"x" * 299                               # 'sertifikat' tiruan: diawali 0x30, 300 byte
OWNER = hashlib.sha256(DER).hexdigest()
OTHER = "ab" * 32

from rvcore import signspool                              # noqa: E402 - conftest sudah menaruh services di sys.path
from rvcore.signkeys import KeyStatus                     # noqa: E402

_loaded = 0


def load_daemon(monkeypatch, tmp_path, **env):
    global _loaded
    _loaded += 1
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SIGNER_SECRETS_DIR", str(tmp_path / "run-secrets"))
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    name = f"signer_daemon_under_test_{_loaded}"
    loader = importlib.machinery.SourceFileLoader(name, str(SCRIPT))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    monkeypatch.setattr(mod, "TOOL_HOME_ROOT", tmp_path / "home")
    monkeypatch.setattr(mod, "TICK", 0.05)
    monkeypatch.setattr(mod, "TERM_GRACE", 0.5)
    monkeypatch.setattr(mod, "FINISH_RETRY_DELAY", 0.0)
    return mod


@pytest.fixture
def d(monkeypatch, tmp_path):
    return load_daemon(monkeypatch, tmp_path)


def within(seconds, fn, *args):
    """Jalankan fn di utas; gagal bila menggantung (FIFO). Mengembalikan (hasil, pengecualian)."""
    box: dict = {}

    def target():
        try:
            box["value"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001
            box["exc"] = exc

    th = threading.Thread(target=target, daemon=True)
    th.start()
    th.join(seconds)
    assert not th.is_alive(), "menggantung"
    return box.get("value"), box.get("exc")


def alive(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


# ================================================================================ fixture keluaran apksigner (Build-Tools 37.0.0)
CERT_DIGEST = "17e063a1aff5c6bbb173d365efd2ab8b7c26ed10485326a5b210e405193aa8ed"
PUBKEY_DIGEST = "f1246801a2238b3740191e69d5904a4fbfc9ba10d9e4ce68d64b8c2366c409fb"


def verify_text(v1="false", v2="true", v3="true", signers=1, lines=None):
    """Keluaran nyata `apksigner verify --verbose --print-certs` (Build-Tools 37.0.0) dengan skema yang bisa diatur."""
    head = (f"Verifies\nVerified using v1 scheme (JAR signing): {v1}\nVerified using v2 scheme (APK Signature Scheme v2): {v2}\n"
            f"Verified using v3 scheme (APK Signature Scheme v3): {v3}\nVerified using v3.1 scheme (APK Signature Scheme v3.1): false\n"
            "Verified using v3.2 scheme (APK Signature Scheme v3.2): false\nVerified using v4 scheme (APK Signature Scheme v4): false\n"
            f"Verified for SourceStamp: false\nNumber of signers: {signers}\n")
    body = lines if lines is not None else (
        f"V3.0 Signer: certificate DN: CN=test\nV3.0 Signer: certificate SHA-256 digest: {CERT_DIGEST}\n"
        "V3.0 Signer: certificate SHA-1 digest: 2d79c0f50ef503e02777d6122ba3e81742fae4fc\n"
        "V3.0 Signer: certificate MD5 digest: 069c056f49c3a3cdd633518feaa42b4e\nV3.0 Signer: key algorithm: RSA\n"
        f"V3.0 Signer: key size (bits): 3072\nV3.0 Signer: public key SHA-256 digest: {PUBKEY_DIGEST}\n"
        "V3.0 Signer: public key SHA-1 digest: a1390c5892427805ce460b92c784d3b9acfd27be\n")
    return head + body


# ================================================================================ murni: berkas, konstanta, env
def test_script_is_executable_python_with_shebang():
    assert SCRIPT.read_bytes().startswith(b"#!/usr/bin/env python3\n")
    assert SCRIPT.stat().st_mode & 0o111 == 0o111


def test_constants_follow_the_plan(d):
    assert (d.RESERVE, d.SIG_SLACK, d.HEARTBEAT_EVERY, d.HEALTH_MAX_AGE, d.KEY_RECHECK) == (1024 * 1024 * 1024, 16 * 1024 * 1024, 5.0, 20.0, 10.0)
    assert (d.KEYTOOL_TIMEOUT, d.MAX_TOOL_OUTPUT) == (30.0, 8 * 1024 * 1024)
    assert d.LAYOUT.root == Path(os.environ["DATA_DIR"]) and d.SPOOL.root == d.LAYOUT.signspool
    assert d.SPOOL.heartbeat_file.name == "signer.hb" and isinstance(d.SPOOL, signspool.SignSpool)


def test_defaults_without_env(monkeypatch, tmp_path):
    for var in ("SIGN_TIMEOUT", "SIGN_MAX_MB"):
        monkeypatch.delenv(var, raising=False)
    mod = load_daemon(monkeypatch, tmp_path)
    assert (mod.SIGN_TIMEOUT, mod.SIGN_MAX_MB) == (900, 1280)
    assert 'os.environ.get("SIGNER_SECRETS_DIR", "/run/secrets")' in SCRIPT.read_text(encoding="utf-8")


@pytest.mark.parametrize("raw,timeout,max_mb", [
    ("abc", 900, 1280), ("", 900, 1280), ("1.5", 900, 1280), ("-", 900, 1280),
    ("5", 30, 5), ("99999", 3600, 4096), ("0", 30, 1), ("-7", 30, 1), ("1200", 1200, 1200), (" 60 ", 60, 60),
])
def test_sign_env_invalid_values_fall_back_and_valid_values_are_clamped(monkeypatch, tmp_path, raw, timeout, max_mb):
    mod = load_daemon(monkeypatch, tmp_path, SIGN_TIMEOUT=raw, SIGN_MAX_MB=raw)
    assert (mod.SIGN_TIMEOUT, mod.SIGN_MAX_MB) == (timeout, max_mb)


def test_env_minimal_has_only_path_home_lang(d, monkeypatch):
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-Xmx1g")
    monkeypatch.setenv("SECRET_THING", "rahasia")
    env = d.env_minimal("/tmp/home/x")
    assert env == {"PATH": d.TOOL_PATH, "HOME": "/tmp/home/x", "LANG": "C.UTF-8"}


# ================================================================================ murni: perintah
def test_command_builders_are_exact(d):
    secrets = d.SECRETS_DIR
    assert d.build_zipalign_cmd("/b/unsigned.apk", "/b/.sign-aligned.tmp") == ["zipalign", "-P", "16", "-f", "4", "/b/unsigned.apk", "/b/.sign-aligned.tmp"]
    assert d.build_zipalign_check_cmd("/b/.sign-aligned.tmp") == ["zipalign", "-c", "-P", "16", "4", "/b/.sign-aligned.tmp"]
    assert d.build_sign_cmd("/b/.sign-aligned.tmp", "/b/.sign-signed.tmp") == [
        "apksigner", "sign", "--ks", f"{secrets}/signing_keystore", "--ks-type", "PKCS12", "--ks-key-alias", "reverse-apk",
        "--ks-pass", f"file:{secrets}/signing_keystore_pass", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
        "--v4-signing-enabled", "false", "--out", "/b/.sign-signed.tmp", "/b/.sign-aligned.tmp"]
    assert d.build_verify_cmd("/b/.sign-signed.tmp") == ["apksigner", "verify", "--verbose", "--print-certs", "/b/.sign-signed.tmp"]


def test_sign_command_has_no_password_flags_and_only_a_password_file_path(d):
    argv = d.build_sign_cmd("/in", "/out")
    joined = " ".join(argv)
    for forbidden in ("--key-pass", "pass:", "env:", "stdin", "--min-sdk-version", "--v1-signing-enabled"):
        assert forbidden not in joined.replace("file:", ""), forbidden
    assert [a for a in argv if a.startswith("file:")] == [f"file:{d.SECRETS_DIR}/signing_keystore_pass"]
    assert argv[argv.index("--ks-pass") + 1].startswith("file:")


def test_redact_argv_hides_secret_paths(d):
    shown = " ".join(d.redact_argv(d.build_sign_cmd(d.LAYOUT.build_dir(1, 2) / "a", d.LAYOUT.build_dir(1, 2) / "b")))
    assert "<ks>" in shown and "file:<pw>" in shown and str(d.SECRETS_DIR) not in shown and str(d.LAYOUT.root) not in shown


# ================================================================================ murni: parse_verify / evaluate_verify
def test_parse_verify_certificate_digest_not_public_key_digest(d):
    v = d.parse_verify(0, verify_text())
    assert v.digests == (CERT_DIGEST,) and PUBKEY_DIGEST not in v.digests
    assert (v.v1, v.v2, v.v3, v.signer_count, v.rc) == (False, True, True, 1, 0)


def test_parse_verify_only_public_key_digest_gives_no_certificate_digest(d):
    text = verify_text(lines=f"V3.0 Signer: public key SHA-256 digest: {PUBKEY_DIGEST}\n")
    assert d.parse_verify(0, text).digests == ()
    assert d.evaluate_verify(d.parse_verify(0, text), PUBKEY_DIGEST)[1] == "verify_failed"


def test_parse_verify_v1_true_and_v31_v32_v4_are_not_mistaken_for_v3(d):
    v = d.parse_verify(0, verify_text(v1="true", v3="false"))
    assert (v.v1, v.v2, v.v3) == (True, True, False)          # baris 'v3.1 scheme' (false) tidak menimpa v3
    only31 = verify_text(v3="false").replace("v3.1 scheme (APK Signature Scheme v3.1): false", "v3.1 scheme (APK Signature Scheme v3.1): true")
    assert d.parse_verify(0, only31).v3 is False


def test_parse_verify_v3_0_only_signer_lines_and_signer_hash_prefix(d):
    lines = f"Signer #1 certificate DN: CN=a\nSigner #1 certificate SHA-256 digest: {CERT_DIGEST.upper()}\n"
    v = d.parse_verify(0, verify_text(v1="true", lines=lines))
    assert v.digests == (CERT_DIGEST,)                         # dinormalkan ke huruf kecil


def test_parse_verify_two_signers(d):
    lines = (f"Signer #1 certificate SHA-256 digest: {CERT_DIGEST}\nSigner #2 certificate SHA-256 digest: {OTHER}\n")
    v = d.parse_verify(0, verify_text(signers=2, lines=lines))
    assert v.signer_count == 2 and set(v.digests) == {CERT_DIGEST, OTHER}


@pytest.mark.parametrize("text", ["", "   \n", "omong kosong\nbukan keluaran apksigner\n", "DOES NOT VERIFY\nERROR: APK Signature Scheme v3 signer #1: boom\n"])
def test_parse_verify_unknown_output_is_not_ok(d, text):
    v = d.parse_verify(1, text)
    assert (v.v1, v.v2, v.v3, v.signer_count, v.digests) == (False, False, False, None, ())
    assert d.evaluate_verify(v, OWNER)[:2] == (False, "verify_failed")


def test_parse_verify_ignores_unanchored_lines(d):
    sneaky = f"  something: certificate SHA-256 digest: {OTHER}\nSource Stamp Signer: certificate SHA-256 digest: {OTHER}\n"
    assert d.parse_verify(0, verify_text(lines=sneaky)).digests == ()
    assert d.parse_verify(0, "xx Verified using v2 scheme (a): true\nVerified using v3 scheme (b): true").v2 is False


def test_evaluate_verify_cases(d):
    ok = d.parse_verify(0, verify_text(lines=f"V3.0 Signer: certificate SHA-256 digest: {OWNER}\n"))
    assert d.evaluate_verify(ok, OWNER) == (True, None, "")
    assert d.evaluate_verify(ok, OWNER.upper())[0] is True
    # v1 informatif: false atau true sama-sama lulus
    assert d.evaluate_verify(d.parse_verify(0, verify_text(v1="true", lines=f"V3.0 Signer: certificate SHA-256 digest: {OWNER}\n")), OWNER)[0] is True

    other = d.parse_verify(0, verify_text(lines=f"V3.0 Signer: certificate SHA-256 digest: {OTHER}\n"))
    good, code, text = d.evaluate_verify(other, OWNER)
    assert (good, code) == (False, "cert_mismatch") and OTHER[:12] in text and OWNER[:12] in text and OTHER not in text

    mixed = d.parse_verify(0, verify_text(signers=2, lines=f"Signer #1 certificate SHA-256 digest: {OWNER}\nSigner #2 certificate SHA-256 digest: {OTHER}\n"))
    assert d.evaluate_verify(mixed, OWNER)[:2] == (False, "cert_mismatch")

    twice = d.parse_verify(0, verify_text(signers=2, lines=f"Signer #1 certificate SHA-256 digest: {OWNER}\nSigner #2 certificate SHA-256 digest: {OWNER}\n"))
    assert d.evaluate_verify(twice, OWNER)[:2] == (False, "verify_failed")

    for kwargs in ({"v2": "false"}, {"v3": "false"}, {"v2": "false", "v3": "false"}):
        assert d.evaluate_verify(d.parse_verify(0, verify_text(lines=f"V3.0 Signer: certificate SHA-256 digest: {OWNER}\n", **kwargs)), OWNER)[1] == "verify_failed"
    assert d.evaluate_verify(d.parse_verify(1, verify_text(lines=f"V3.0 Signer: certificate SHA-256 digest: {OWNER}\n")), OWNER)[1] == "verify_failed"
    assert d.evaluate_verify(d.parse_verify(0, verify_text(lines="")), OWNER)[1] == "verify_failed"


# ================================================================================ murni: scrub / map_tool_error / check_disk
def test_scrub_removes_control_chars_paths_and_extras(d):
    text = f"gagal\x00 di {d.SECRETS_DIR}/signing_keystore_pass\r\nlalu {d.LAYOUT.root}/builds/1/2/unsigned.apk \x1b[31mmerah\x07 kata-sandi-ku"
    out = d.scrub(text, extra=("kata-sandi-ku", ""))
    assert "\x00" not in out and "\x1b" not in out and "\n" not in out and "\x07" not in out
    assert str(d.SECRETS_DIR) not in out and str(d.LAYOUT.root) not in out and "kata-sandi-ku" not in out
    assert "<rahasia>" in out and "<build>" in out


def test_scrub_truncates_and_has_no_alias_rule(d):
    assert len(d.scrub("x" * 1000)) == 300
    assert d.scrub("alias reverse-apk dipakai") == "alias reverse-apk dipakai"


@pytest.mark.parametrize("code,rc,text,want_code,want_text", [
    ("sign_failed", 2, 'Failed to load signer "signer #1"\njava.io.IOException: keystore password was incorrect\n\tat a.b(C.java:1)', "keystore_invalid", None),
    ("sign_failed", 2, 'Failed to load signer "signer #1": x.p12 entry "nope" does not contain a key', "keystore_invalid", None),
    ("sign_failed", 1, "java.io.IOException: No space left on device", "no_space", None),
    ("sign_failed", 1, "Exception in thread main java.lang.OutOfMemoryError: Direct buffer memory\n\tat x", "sign_failed", "memori langsung JVM habis; lihat docs/deploy.md (batas -XX:MaxDirectMemorySize)"),
    ("sign_failed", 1, "java.lang.OutOfMemoryError: Java heap space", "sign_failed", "memori heap JVM habis (-Xmx256m); lihat docs/deploy.md"),
    ("verify_failed", 137, "", "verify_failed", "alat dimatikan (kemungkinan kehabisan memori 512m; lihat docs/deploy.md)"),
    ("sign_failed", -9, "", "sign_failed", "alat dimatikan (kemungkinan kehabisan memori 512m; lihat docs/deploy.md)"),
    ("sign_failed", 1, "com.android.apksig.MinSdkVersionException: x", "sign_failed", "APK tidak valid (AndroidManifest.xml tidak terbaca)"),
    ("sign_failed", 1, "ERROR: malformed binary resource: AndroidManifest.xml", "sign_failed", "APK tidak valid (AndroidManifest.xml tidak terbaca)"),
    ("align_failed", 1, "Unable to open '/data/builds/1/2/unsigned.apk' as zip archive: Success", "align_failed", "bukan berkas ZIP/APK yang valid"),
])
def test_map_tool_error_table(d, code, rc, text, want_code, want_text):
    got_code, got_text = d.map_tool_error(code, rc, text)
    assert got_code == want_code
    if want_text:
        assert got_text == want_text
    else:
        assert got_text == signspool.ERROR_TEXT[want_code]


def test_map_tool_error_never_forwards_stack_traces(d):
    trace = "Exception in thread \"main\" java.lang.IllegalStateException: boom\n\tat a.b.C.d(C.java:1)\n\tat e.f.G.h(G.java:2)\n\t... 9 more\n"
    code, text = d.map_tool_error("sign_failed", 1, trace)
    assert (code, "\n" in text, "\tat" in text, "more" in text) == ("sign_failed", False, False, False) and "boom" in text
    assert d.map_tool_error("sign_failed", 1, "")[1] == signspool.ERROR_TEXT["sign_failed"]
    secret_line = f"ERROR: failed reading {d.SECRETS_DIR}/signing_keystore_pass"
    assert str(d.SECRETS_DIR) not in d.map_tool_error("sign_failed", 1, secret_line)[1]


def test_check_disk_exact_boundary(d):
    size = 100 * 1024 * 1024
    need = 2 * size + d.SIG_SLACK + d.RESERVE
    assert d.check_disk(need - 1, size) == (False, need)
    assert d.check_disk(need, size) == (True, need)
    assert d.check_disk(need + 1, size)[0] is True
    # rumus lama 3*size+RESERVE TIDAK dipakai: ruang antara kedua rumus harus lulus
    assert d.check_disk(3 * size + d.RESERVE - 1, size)[0] is True


# ================================================================================ murni: berkas aman (FS tmp nyata)
@pytest.fixture
def builds(d):
    bdir = d.LAYOUT.build_dir(7, 3)
    bdir.mkdir(parents=True)
    return bdir


def test_open_build_dir_chain_and_rejections(d, builds, tmp_path):
    fd = d.open_build_dir(7, 3)
    assert os.fstat(fd).st_ino == builds.stat().st_ino
    os.close(fd)
    for bad in (("7", 3), (7, "3"), (7.0, 3), (True, 3), (0, 3), (-1, 3)):
        with pytest.raises(ValueError):
            d.open_build_dir(*bad)
    with pytest.raises(d.JobError) as err:
        d.open_build_dir(7, 99)
    assert err.value.code == "input_missing"
    with pytest.raises(d.JobError) as err:
        d.open_build_dir(8, 1)
    assert err.value.code == "input_missing"


def test_open_build_dir_rejects_symlink_components(d, builds, tmp_path):
    outside = tmp_path / "outside"
    (outside / "3").mkdir(parents=True)
    d.LAYOUT.builds_dir(9).symlink_to(outside)                 # builds/9 -> luar (komponen perantara)
    with pytest.raises(d.JobError) as err:
        d.open_build_dir(9, 3)
    assert err.value.code == "input_unsafe"
    (d.LAYOUT.builds_dir(7) / "4").symlink_to(builds)           # builds/7/4 -> builds/7/3 (komponen akhir)
    with pytest.raises(d.JobError) as err:
        d.open_build_dir(7, 4)
    assert err.value.code == "input_unsafe"


def test_open_input_normal_and_error_codes(d, builds):
    bfd = d.open_build_dir(7, 3)
    try:
        with pytest.raises(d.JobError) as err:
            d.open_input(bfd, "unsigned.apk", 1024)
        assert err.value.code == "input_missing"

        (builds / "unsigned.apk").write_bytes(b"x" * 100)
        fd, size = d.open_input(bfd, "unsigned.apk", 1024)
        os.close(fd)
        assert size == 100

        with pytest.raises(d.JobError) as err:
            d.open_input(bfd, "unsigned.apk", 99)
        assert err.value.code == "input_too_large" and "MiB" in err.value.text

        (builds / "unsigned.apk").write_bytes(b"")
        with pytest.raises(d.JobError) as err:
            d.open_input(bfd, "unsigned.apk", 1024)
        assert err.value.code == "input_unsafe" and "0 byte" in err.value.text
    finally:
        os.close(bfd)


def test_open_input_too_large_message_has_size_and_limit_in_mib(d, builds):
    big = builds / "unsigned.apk"
    with open(big, "wb") as fh:
        fh.truncate(3 * 1024 * 1024)
    bfd = d.open_build_dir(7, 3)
    try:
        with pytest.raises(d.JobError) as err:
            d.open_input(bfd, "unsigned.apk", 2 * 1024 * 1024)
    finally:
        os.close(bfd)
    assert err.value.code == "input_too_large" and "3.0 MiB" in err.value.text and "2 MiB" in err.value.text


def test_open_input_rejects_symlink_hardlink_and_directory(d, builds, tmp_path):
    target = tmp_path / "target.apk"
    target.write_bytes(b"data")
    bfd = d.open_build_dir(7, 3)
    try:
        (builds / "unsigned.apk").symlink_to(target)
        with pytest.raises(d.JobError) as err:
            d.open_input(bfd, "unsigned.apk", 1024)
        assert err.value.code == "input_unsafe"
        (builds / "unsigned.apk").unlink()

        os.link(target, builds / "unsigned.apk")                # nlink == 2
        with pytest.raises(d.JobError) as err:
            d.open_input(bfd, "unsigned.apk", 1024)
        assert err.value.code == "input_unsafe" and "tautan keras" in err.value.text
        (builds / "unsigned.apk").unlink()

        (builds / "unsigned.apk").mkdir()
        with pytest.raises(d.JobError) as err:
            d.open_input(bfd, "unsigned.apk", 1024)
        assert err.value.code == "input_unsafe"
    finally:
        os.close(bfd)


def test_open_input_fifo_does_not_hang(d, builds):
    fifo = builds / "unsigned.apk"
    os.mkfifo(fifo)
    bfd = d.open_build_dir(7, 3)
    unblock = None
    try:
        _, exc = within(5, d.open_input, bfd, "unsigned.apk", 1024)
    finally:
        try:
            unblock = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)      # bila sempat menggantung, lepaskan utasnya
        except OSError:
            pass
        if unblock is not None:
            os.close(unblock)
        os.close(bfd)
    assert isinstance(exc, d.JobError) and exc.code == "input_unsafe"


def test_sweep_leftovers_removes_only_job_outputs_and_is_idempotent(d, builds, tmp_path):
    for name in ("signed.apk", ".sign-aligned.tmp", ".sign-signed.tmp", ".sign-x", "a.apk.idsig", "unsigned.apk", "notes.txt", "x.sign-y", "signedx.apk"):
        (builds / name).write_bytes(b"1")
    outside = tmp_path / "victim"
    outside.write_bytes(b"jangan dihapus")
    (builds / ".sign-link").symlink_to(outside)                    # symlink dihapus, bukan targetnya
    bfd = d.open_build_dir(7, 3)
    try:
        assert d.sweep_leftovers(bfd) == []
        assert sorted(p.name for p in builds.iterdir()) == ["notes.txt", "signedx.apk", "unsigned.apk", "x.sign-y"]
        assert outside.read_bytes() == b"jangan dihapus"
        assert d.sweep_leftovers(bfd) == []                         # idempoten
    finally:
        os.close(bfd)


def test_sweep_leftovers_reports_what_it_cannot_remove(d, builds):
    (builds / ".sign-dir").mkdir()
    (builds / ".sign-file").write_bytes(b"1")
    bfd = d.open_build_dir(7, 3)
    try:
        assert d.sweep_leftovers(bfd) == [".sign-dir"]
        assert not (builds / ".sign-file").exists()
    finally:
        os.close(bfd)


def test_unlink_through_dir_fd_does_not_follow_a_swapped_parent_symlink(d, builds, tmp_path):
    (builds / "signed.apk").write_bytes(b"asli")
    bfd = d.open_build_dir(7, 3)
    decoy = tmp_path / "decoy" / "3"
    decoy.mkdir(parents=True)
    (decoy / "signed.apk").write_bytes(b"umpan")
    moved = d.LAYOUT.builds_dir(7).rename(tmp_path / "moved-7")
    d.LAYOUT.builds_dir(7).symlink_to(tmp_path / "decoy")          # builds/7 sekarang symlink ke umpan
    try:
        assert d.sweep_leftovers(bfd) == []
    finally:
        os.close(bfd)
    assert (decoy / "signed.apk").read_bytes() == b"umpan"           # umpan tidak tersentuh
    assert not (moved / "3" / "signed.apk").exists()                 # folder asli yang dipegang fd yang dibersihkan


def test_cleanup_job_files_keeps_signed_apk_removes_temp_and_home(d, builds, tmp_path):
    home = tmp_path / "home" / "job1"
    (home / "sub").mkdir(parents=True)
    (home / "sub" / "f").write_bytes(b"1")
    for name in ("signed.apk", ".sign-signed.tmp", "q.idsig", "unsigned.apk"):
        (builds / name).write_bytes(b"1")
    bfd = d.open_build_dir(7, 3)
    try:
        assert d.cleanup_job_files(bfd, home) is True
        assert sorted(p.name for p in builds.iterdir()) == ["signed.apk", "unsigned.apk"]
        assert not home.exists()
        assert d.cleanup_job_files(bfd, home) is True                # idempoten
        assert d.cleanup_job_files(None, None) is True
        (builds / ".sign-dir").mkdir()
        assert d.cleanup_job_files(bfd, None) is False
    finally:
        os.close(bfd)


def test_sha256_fd_hashes_and_ticks_every_chunk_window(d, tmp_path, monkeypatch):
    path = tmp_path / "f"
    path.write_bytes(os.urandom(5 * 1024 * 1024 + 17))
    monkeypatch.setattr(d, "HASH_CHECK_EVERY", 2 * 1024 * 1024)
    ticks = []
    fd = os.open(path, os.O_RDONLY)
    try:
        sha, size = d.sha256_fd(fd, lambda: ticks.append(1))
    finally:
        os.close(fd)
    assert sha == hashlib.sha256(path.read_bytes()).hexdigest() and size == path.stat().st_size and len(ticks) == 2


# ================================================================================ detak jantung
def test_on_tick_writes_at_most_every_five_seconds(d, monkeypatch):
    now = [100.0]
    writes = []
    monkeypatch.setattr(d, "CLOCK", lambda: now[0])
    monkeypatch.setattr(d.SPOOL, "write_signer_heartbeat", lambda state, job, ks: writes.append((state, job, now[0])))
    d.on_tick()
    assert len(writes) == 1                                           # pertama kali: menulis
    for delta in (0.5, 1.0, 2.5, 4.9):
        now[0] = 100.0 + delta
        d.on_tick()
    assert len(writes) == 1
    now[0] = 105.0
    d.on_tick()
    assert len(writes) == 2
    now[0] = 105.5
    d.HB.update(state="busy", job="g1-1-abcdef12")                    # pergantian keadaan menulis segera
    d.on_tick()
    assert len(writes) == 3 and writes[-1][:2] == ("busy", "g1-1-abcdef12")
    d.on_tick()
    assert len(writes) == 3
    d.KEY_STATE["last"] = d.KeyInfo("ok", "", OWNER)                  # perubahan status kunci menulis segera
    now[0] = 106.0
    d.on_tick()
    assert len(writes) == 4


def test_heartbeat_oserror_warns_once_then_reports_recovery(d, monkeypatch, capsys):
    def boom(*_a):
        raise OSError(errno.ENOSPC, "disk penuh")

    monkeypatch.setattr(d.SPOOL, "write_signer_heartbeat", boom)
    for _ in range(4):
        d.write_hb("idle")
    out = capsys.readouterr().out
    assert out.count("WARN write_signer_heartbeat gagal") == 1 and "ENOSPC" in out
    monkeypatch.setattr(d.SPOOL, "write_signer_heartbeat", lambda *a: None)
    d.write_hb("idle")
    d.write_hb("idle")
    out = capsys.readouterr().out
    assert out.count("INFO write_signer_heartbeat pulih") == 1


def test_housekeeping_oserror_warns_once_and_removes_stale_files(d, tmp_path, monkeypatch, capsys):
    d.SPOOL.ensure_dirs()
    old, fresh = d.SPOOL.results / "old.json", d.SPOOL.results / "fresh.json"
    flag = d.SPOOL.cancel / "g1-1-abcdef12"
    for p in (old, fresh, flag):
        p.write_text("{}")
    past = time.time() - 2 * 3600
    os.utime(old, (past, past))
    os.utime(flag, (past, past))
    d.housekeeping()
    assert not old.exists() and not flag.exists() and fresh.exists()

    def boom(*_a, **_k):
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr(d.os, "scandir", boom)
    capsys.readouterr()
    for _ in range(3):
        d.housekeeping()
    out = capsys.readouterr().out
    assert out.count("WARN housekeeping gagal") == 1


# ================================================================================ alat PALSU
FAKE_TOOL = r'''#!@PY@
import json, os, shutil, signal, subprocess, sys, time
REC = @REC@
name = os.path.basename(sys.argv[0])
args = sys.argv[1:]
phase = args[0] if name == "apksigner" and args else ("check" if args and args[0] == "-c" else "")
key = name + (":" + phase if phase else "")
with open(os.path.join(REC, "calls.jsonl"), "a") as fh:
    fh.write(json.dumps({"tool": name, "key": key, "argv": args, "env": dict(os.environ), "stdin": sys.stdin.read(), "cwd": os.getcwd()}) + "\n")
try:
    beh = json.load(open(os.path.join(REC, "behavior.json")))
except OSError:
    beh = {}
b = beh.get(key, {})
mode = b.get("mode", "ok")
out = args[args.index("--out") + 1] if "--out" in args else None


def partial():
    target = out or args[-1]
    if key == "zipalign":
        target = args[-1]
    with open(target, "wb") as fh:
        fh.write(b"separuh")
    open(target + ".idsig", "wb").write(b"x")


if mode == "sleep":
    gc = subprocess.Popen(["sleep", "300"])
    open(os.path.join(REC, "gc.pid"), "w").write(str(gc.pid))
    if b.get("ignore_term"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(300)
if mode == "flood":
    chunk = b"x" * 65536
    while True:
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
if mode == "kill9":
    os.kill(os.getpid(), signal.SIGKILL)
if mode in ("fail", "enospc"):
    if b.get("partial"):
        partial()
    print(b.get("text", "java.io.IOException: No space left on device" if mode == "enospc" else "Failed: gagal tiruan"))
    sys.exit(b.get("rc", 1))

if key == "keytool":
    if beh.get("keytool_noise"):
        sys.stderr.write("Picked up JAVA_TOOL_OPTIONS: -Xmx64m\n")
    sys.stdout.buffer.write(b"0" + b"x" * 299)
    sys.exit(0)
if key == "zipalign":
    shutil.copyfile(args[-2], args[-1])
    sys.exit(0)
if key == "zipalign:check":
    sys.exit(0)
if key == "apksigner:sign":
    shutil.copyfile(args[-1], out)
    if b.get("noout"):
        os.unlink(out)
    sys.exit(0)
if key == "apksigner:verify":
    digests = b.get("digests", [beh.get("owner")])
    lines = "".join("V3.0 Signer: certificate SHA-256 digest: %s\n" % x for x in digests)
    print("Verifies\nVerified using v1 scheme (JAR signing): %s\nVerified using v2 scheme (APK Signature Scheme v2): %s\n"
          "Verified using v3 scheme (APK Signature Scheme v3): %s\nNumber of signers: %d\n%s" % (
              "true" if b.get("v1") else "false", "false" if b.get("v2") is False else "true", "false" if b.get("v3") is False else "true",
              b.get("signers", 1), lines))
    sys.stdout.flush()
    if mode == "swap_fifo":
        os.unlink(args[-1])
        os.mkfifo(args[-1])
    sys.exit(b.get("rc", 0))
sys.exit(0)
'''


@pytest.fixture
def rig(d, tmp_path, monkeypatch):
    """Daemon + alat palsu + kunci tiruan + folder build 1/2 berisi unsigned.apk."""
    rec = tmp_path / "rec"
    bindir = tmp_path / "bin"
    secrets = tmp_path / "run-secrets"
    for p in (rec, bindir, secrets):
        p.mkdir()
    text = FAKE_TOOL.replace("@PY@", sys.executable).replace("@REC@", repr(str(rec)))
    for tool in ("zipalign", "apksigner", "keytool"):
        (bindir / tool).write_text(text)
        (bindir / tool).chmod(0o755)
    (secrets / "signing_keystore").write_bytes(b"p12-tiruan")
    (secrets / "signing_keystore_pass").write_text(PASSWORD)             # tanpa newline
    for p in (secrets / "signing_keystore", secrets / "signing_keystore_pass"):
        p.chmod(0o644)
    bdir = d.LAYOUT.build_dir(1, 2)
    bdir.mkdir(parents=True)
    (bdir / "unsigned.apk").write_bytes(b"APK-TIRUAN" * 100)
    monkeypatch.setattr(d, "TOOL_PATH", f"{bindir}:/usr/bin:/bin")
    monkeypatch.setattr(d, "KEYTOOL_TIMEOUT", 10.0)
    r = SimpleNamespace(d=d, rec=rec, bin=bindir, secrets=secrets, bdir=bdir, home=tmp_path / "home")
    r.behave = lambda **kw: (rec / "behavior.json").write_text(json.dumps({"owner": OWNER, **kw}))
    r.behave()

    def calls():
        path = rec / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    r.calls = calls
    r.run = lambda aid=1, bid=2, timeout=60: run_one(d, aid, bid, timeout)
    return r


def sreq(layout, aid, bid, timeout=60, expect=None):
    """Request sign dengan `expect_sha256` = hash `unsigned.apk` yang SEKARANG ada (seperti yang dilaporkan runner); tak ada/bukan berkas biasa -> hash nol."""
    f = layout.build_dir(aid, bid) / "unsigned.apk"
    got = hashlib.sha256(f.read_bytes()).hexdigest() if f.is_file() and not f.is_symlink() else "0" * 64
    return signspool.build_sign_request(aid, bid, timeout, expect or got)


def run_one(d, aid=1, bid=2, timeout=60):
    job = sreq(d.LAYOUT, aid, bid, timeout)
    d.SPOOL.submit(job)
    claimed = d.SPOOL.claim_next()
    assert claimed is not None and claimed[0] == job["job_id"]
    return job["job_id"], d.run_job(*claimed)


def stored_result(d, job_id):
    return json.loads((d.SPOOL.results / f"{job_id}.json").read_text())


def tool_calls(r):
    return [(c["tool"], c["argv"][0] if c["argv"] else "") for c in r.calls() if c["tool"] != "keytool"]


def test_fake_success_flow_order_commands_and_published_file(rig):
    d = rig.d
    job_id, res = rig.run()
    assert res["ok"] is True, res
    assert [c for c in tool_calls(rig)] == [("zipalign", "-P"), ("zipalign", "-c"), ("apksigner", "sign"), ("apksigner", "verify")]
    bdir = rig.bdir
    assert sorted(p.name for p in bdir.iterdir()) == ["signed.apk", "unsigned.apk"]            # .sign-* sudah bersih
    data = (bdir / "signed.apk").read_bytes()
    assert (res["output_size"], res["output_sha256"], res["cert_sha256"]) == (len(data), hashlib.sha256(data).hexdigest(), OWNER)
    assert res["verify"] == {"v1": False, "v2": True, "v3": True} and res["signer_count"] == 1 and res["error_code"] is None
    parsed = signspool.parse_result(stored_result(d, job_id))
    assert parsed["ok"] is True and parsed["output_sha256"] == res["output_sha256"]
    assert not (rig.home / job_id).exists()
    assert (rig.bdir / "unsigned.apk").read_bytes() == b"APK-TIRUAN" * 100

    # R3/R10: SEMUA alat bekerja di ruang kerja privat signwork/<job>/, TIDAK di folder build milik runner.
    wdir = d.LAYOUT.signwork / job_id
    sign = next(c for c in rig.calls() if c["key"] == "apksigner:sign")["argv"]
    assert sign[sign.index("--ks-pass") + 1] == f"file:{rig.secrets}/signing_keystore_pass"
    assert sign[sign.index("--out") + 1] == str(wdir / "signed.apk") and sign[-1] == str(wdir / "aligned.apk")
    zipalign = next(c for c in rig.calls() if c["key"] == "zipalign")["argv"]
    assert zipalign == ["-P", "16", "-f", "4", str(wdir / "in.apk"), str(wdir / "aligned.apk")]
    verify = next(c for c in rig.calls() if c["key"] == "apksigner:verify")["argv"]
    assert verify[-1] == str(wdir / "signed.apk")
    assert not any(str(bdir) in a for c in rig.calls() for a in c["argv"]), "tidak ada alat yang menyentuh jalur folder build"
    assert not wdir.exists() and list(d.LAYOUT.signwork.iterdir()) == [], "ruang kerja privat dibersihkan"
    assert res["input_sha256"] == hashlib.sha256(b"APK-TIRUAN" * 100).hexdigest()


def test_fake_password_is_nowhere_but_the_secret_file(rig, capfd):
    job_id, res = rig.run()
    assert res["ok"] is True
    calls = rig.calls()
    assert {c["tool"] for c in calls} == {"keytool", "zipalign", "apksigner"}
    for c in calls:
        assert PASSWORD not in json.dumps(c["argv"]) and PASSWORD not in json.dumps(c["env"]) and c["stdin"] == ""
        assert not any(a in ("--key-pass", "--min-sdk-version", "--v1-signing-enabled") for a in c["argv"])
        assert not any(a.startswith(("pass:", "env:", "stdin")) for a in c["argv"])
        assert set(c["env"]) >= {"PATH", "HOME", "LANG"} and set(c["env"]) <= {"PATH", "HOME", "LANG", "LC_CTYPE"}
        assert c["env"]["HOME"] == c["cwd"]
    keytool = next(c for c in calls if c["tool"] == "keytool")
    assert "-storepass:file" in keytool["argv"] and f"{rig.secrets}/signing_keystore_pass" in keytool["argv"]
    log = capfd.readouterr().out
    assert PASSWORD not in log and str(rig.secrets) not in log
    assert PASSWORD not in (rig.d.SPOOL.results / f"{job_id}.json").read_text()
    rig.d.write_hb("idle")
    assert PASSWORD not in rig.d.SPOOL.heartbeat_file.read_text()


def test_fake_job_log_is_one_line_without_secret_paths(rig, capfd):
    rig.behave(**{"apksigner:sign": {"mode": "fail", "text": f"Failed to read {rig.secrets}/signing_keystore_pass"}})
    _, res = rig.run()
    assert res["error_code"] == "sign_failed" and str(rig.secrets) not in res["error_text"]
    lines = [ln for ln in capfd.readouterr().out.splitlines() if "aid=1 bid=2" in ln]
    assert len(lines) == 1 and "sign_failed" in lines[0] and "<ks>" in lines[0] and "file:<pw>" in lines[0]
    assert str(rig.secrets) not in lines[0] and PASSWORD not in lines[0]


@pytest.mark.parametrize("behavior,code", [
    ({"zipalign": {"mode": "fail", "partial": True, "text": "Unable to open 'x' as zip archive: Success"}}, "align_failed"),
    ({"zipalign:check": {"mode": "fail", "text": "Verification FAILED"}}, "align_failed"),
    ({"apksigner:sign": {"mode": "fail", "partial": True}}, "sign_failed"),
    ({"apksigner:sign": {"mode": "fail", "partial": True, "text": "java.io.IOException: keystore password was incorrect"}}, "keystore_invalid"),
    ({"apksigner:sign": {"mode": "enospc", "partial": True}}, "no_space"),
    ({"apksigner:sign": {"mode": "kill9"}}, "sign_failed"),
    ({"apksigner:verify": {"mode": "fail", "rc": 1, "text": "DOES NOT VERIFY\nERROR: boom"}}, "verify_failed"),
    ({"apksigner:verify": {"digests": [OTHER]}}, "cert_mismatch"),
    ({"apksigner:verify": {"v3": False}}, "verify_failed"),
    ({"apksigner:verify": {"signers": 2}}, "verify_failed"),
    ({"apksigner:verify": {"digests": []}}, "verify_failed"),
])
def test_fake_every_failure_path_leaves_no_temp_files_and_no_signed_apk(rig, behavior, code):
    rig.behave(**behavior)
    job_id, res = rig.run()
    assert (res["ok"], res["error_code"]) == (False, code), res
    assert sorted(p.name for p in rig.bdir.iterdir()) == ["unsigned.apk"]
    assert not (rig.home / job_id).exists() and list(rig.d.LAYOUT.signwork.iterdir()) == []
    stored = signspool.parse_result(stored_result(rig.d, job_id))
    assert stored["ok"] is False and stored["error_code"] == code and stored["error_text"]


def test_fake_sign_failure_still_removes_aligned_copy(rig):
    rig.behave(**{"apksigner:sign": {"mode": "fail", "partial": True}})
    rig.run()
    assert not any(p.name.startswith(".sign-") for p in rig.bdir.iterdir()) and list(rig.d.LAYOUT.signwork.iterdir()) == []


def test_fake_cert_mismatch_text_has_both_prefixes_and_no_signed_apk(rig):
    rig.behave(**{"apksigner:verify": {"digests": [OTHER]}})
    _, res = rig.run()
    assert OTHER[:12] in res["error_text"] and OWNER[:12] in res["error_text"] and not (rig.bdir / "signed.apk").exists()


def test_fake_leftovers_from_an_earlier_job_are_cleared_first(rig):
    for name in ("signed.apk", ".sign-aligned.tmp", ".sign-signed.tmp", "z.idsig"):
        (rig.bdir / name).write_bytes(b"lama")
    rig.behave(**{"zipalign": {"mode": "fail"}})
    _, res = rig.run()
    assert res["error_code"] == "align_failed"
    assert sorted(p.name for p in rig.bdir.iterdir()) == ["unsigned.apk"]      # signed.apk lama TIDAK tersisa saat gagal


def test_fake_stale_signed_apk_is_replaced_not_kept(rig):
    (rig.bdir / "signed.apk").write_bytes(b"lama")
    _, res = rig.run()
    assert res["ok"] and (rig.bdir / "signed.apk").read_bytes() != b"lama"


def test_fake_undeletable_leftover_gives_input_unsafe(rig):
    (rig.bdir / ".sign-dir").mkdir()
    _, res = rig.run()
    assert res["error_code"] == "input_unsafe" and tool_calls(rig) == []


# ---- disk
def test_fake_check_disk_runs_after_sweep_so_leftovers_do_not_cause_a_false_no_space(rig, monkeypatch):
    d = rig.d
    size = (rig.bdir / "unsigned.apk").stat().st_size
    need = 2 * size + d.SIG_SLACK + d.RESERVE
    real_statvfs = os.statvfs

    def fake_statvfs(target):
        # ruang "cukup" HANYA bila sisa .sign-* sudah terhapus (sisa itu 'memakai' ruang)
        names = os.listdir(target)
        blocks = need if not any(n.startswith(".sign-") or n == "signed.apk" for n in names) else need - 1
        st = real_statvfs(target)
        return SimpleNamespace(f_bavail=blocks, f_frsize=1, f_bsize=st.f_bsize)

    monkeypatch.setattr(d.os, "statvfs", fake_statvfs)
    (rig.bdir / ".sign-aligned.tmp").write_bytes(b"x")
    (rig.bdir / ".sign-signed.tmp").write_bytes(b"x")
    _, res = rig.run()
    assert res["ok"] is True, res


@pytest.mark.parametrize("delta,ok", [(-1, False), (0, True)])
def test_fake_disk_boundary_in_run_job(rig, monkeypatch, delta, ok):
    d = rig.d
    size = (rig.bdir / "unsigned.apk").stat().st_size
    need = 2 * size + d.SIG_SLACK + d.RESERVE
    monkeypatch.setattr(d.os, "statvfs", lambda _t: SimpleNamespace(f_bavail=need + delta, f_frsize=1))
    _, res = rig.run()
    assert res["ok"] is ok
    if not ok:
        assert res["error_code"] == "no_space" and "MiB" in res["error_text"] and tool_calls(rig) == []


def test_fake_input_size_limit(rig, monkeypatch):
    monkeypatch.setattr(rig.d, "SIGN_MAX_MB", 1)
    with open(rig.bdir / "unsigned.apk", "wb") as fh:
        fh.truncate(2 * 1024 * 1024)
    _, res = rig.run()
    assert res["error_code"] == "input_too_large" and "2.0 MiB" in res["error_text"] and tool_calls(rig) == []


# ---- masukan tak aman lewat run_job
def test_fake_unsigned_apk_fifo_gives_input_unsafe_without_hanging(rig):
    (rig.bdir / "unsigned.apk").unlink()
    fifo = rig.bdir / "unsigned.apk"
    os.mkfifo(fifo)
    try:
        started = time.monotonic()
        (job_id, res), exc = within(8, rig.run)
        assert exc is None and time.monotonic() - started < 5
    finally:
        try:
            os.close(os.open(fifo, os.O_RDWR | os.O_NONBLOCK))
        except OSError:
            pass
    assert res["error_code"] == "input_unsafe" and tool_calls(rig) == []
    fifo.unlink()
    (rig.bdir / "unsigned.apk").write_bytes(b"APK-TIRUAN" * 10)
    assert rig.run()[1]["ok"] is True                                  # job berikut tetap jalan


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "empty", "dir", "missing"])
def test_fake_unsafe_inputs(rig, tmp_path, kind):
    target = tmp_path / "t.apk"
    target.write_bytes(b"xyz")
    apk = rig.bdir / "unsigned.apk"
    apk.unlink()
    {"symlink": lambda: apk.symlink_to(target), "hardlink": lambda: os.link(target, apk), "empty": lambda: apk.write_bytes(b""),
     "dir": lambda: apk.mkdir(), "missing": lambda: None}[kind]()
    _, res = rig.run()
    assert res["error_code"] == ("input_missing" if kind == "missing" else "input_unsafe") and tool_calls(rig) == []


def test_fake_builds_aid_symlink_is_refused_and_nothing_is_deleted(rig, tmp_path):
    d = rig.d
    outside = tmp_path / "outside"
    (outside / "5").mkdir(parents=True)
    (outside / "5" / "signed.apk").write_bytes(b"jangan hapus")
    (outside / "5" / "unsigned.apk").write_bytes(b"APK")
    d.LAYOUT.builds_dir(4).symlink_to(outside)
    _, res = rig.run(4, 5)
    assert res["error_code"] == "input_unsafe" and (outside / "5" / "signed.apk").read_bytes() == b"jangan hapus"
    assert tool_calls(rig) == []


def test_fake_publish_hash_rejects_a_tmp_swapped_for_a_fifo(rig):
    rig.behave(**{"apksigner:verify": {"mode": "swap_fifo"}})
    (job_id, res), exc = within(10, rig.run)
    assert exc is None and res["error_code"] == "input_unsafe"
    assert not (rig.bdir / "signed.apk").exists()
    assert sorted(p.name for p in rig.bdir.iterdir()) == ["unsigned.apk"]


# ---- bad_request / kunci
def test_fake_bad_requests_are_answered_without_running_tools(rig):
    d = rig.d
    for job_id, request in (
        ("g1-2-abcdef12", {"job_id": "g1-2-abcdef12", "op": "sign", "analysis_id": "1", "build_id": 2, "timeout": 60}),
        ("g1-2-abcdef13", {"job_id": "g1-2-abcdef13", "op": "verify", "analysis_id": 1, "build_id": 2, "timeout": 60}),
        ("g1-2-abcdef14", {"job_id": "g1-2-abcdef14", "op": "sign", "analysis_id": 1, "build_id": 3, "timeout": 60}),
        ("g1-2-abcdef15", {"job_id": "g1-2-abcdef15", "op": "sign", "analysis_id": True, "build_id": 2, "timeout": 60}),
    ):
        res = d.run_job(job_id, request)
        assert (res["ok"], res["error_code"]) == (False, "bad_request"), request
    assert rig.calls() == []                                                     # ditolak sebelum alat apa pun dijalankan


def test_fake_unlink_after_directory_swap_never_follows_the_new_symlink(rig, tmp_path, monkeypatch):
    """Semua operasi (sweep, penerbitan `.sign-signed.tmp`, rename ke signed.apk, baca ulang, unlink) memakai dir_fd folder build yang SUDAH dibuka: folder diganti
    symlink di tengah job (antara salin dan sign) tidak boleh membuat signer menghapus/menimpa berkas di tujuan symlink (mutasi M35: operasi berbasis jalur string)."""
    d = rig.d
    victim = tmp_path / "korban"
    victim.mkdir()
    canaries = {name: victim / name for name in (".sign-signed.tmp", "signed.apk", ".sign-aligned.tmp")}
    for c in canaries.values():
        c.write_text("jangan dihapus")
    original = d.build_sign_cmd

    def swap(src, dst):
        rig.bdir.rename(rig.bdir.parent / "asli")
        rig.bdir.symlink_to(victim)
        return original(src, dst)

    monkeypatch.setattr(d, "build_sign_cmd", swap)
    _, res = rig.run()
    assert all(c.read_text() == "jangan dihapus" for c in canaries.values()), res
    assert sorted(p.name for p in victim.iterdir()) == sorted(canaries), "tidak ada yang ditulis ke tujuan symlink"
    # hasil terbit ke inode folder ASLI yang dibuka signer (lewat dir_fd); folder baru (symlink) tak berisi artefak => worker menangkapnya sebagai artifact_changed
    assert res["ok"] is True and (rig.bdir.parent / "asli" / "signed.apk").is_file()
    assert sorted(p.name for p in (rig.bdir.parent / "asli").iterdir()) == ["signed.apk", "unsigned.apk"]


def test_fake_request_path_fields_are_ignored(rig, tmp_path):
    job = sreq(rig.d.LAYOUT, 1, 2, 60)
    job.update(path="/etc/passwd", input="/etc/shadow", out="/tmp/x")
    rig.d.SPOOL.submit(job)
    job_id, request = rig.d.SPOOL.claim_next()
    res = rig.d.run_job(job_id, request)
    assert res["ok"] is True and not (tmp_path / "x").exists()
    # Jalur alat HANYA dari id bilangan bulat (Layout.build_dir), bukan dari bidang request (mutasi M11).
    first = next(c for c in rig.calls() if c["tool"] == "zipalign")
    assert str(rig.d.LAYOUT.signwork / job_id / "in.apk") in first["argv"] and not any("/etc/" in a or "/tmp/x" in a for c in rig.calls() for a in c["argv"])


@pytest.mark.parametrize("make_bad,code", [
    ("missing", "keystore_missing"), ("nopass", "keystore_missing"), ("badpass", "keystore_invalid"), ("emptyp12", "keystore_invalid"),
    ("keytool_fails", "keystore_invalid"),
])
def test_fake_key_problems_become_keystore_errors(rig, make_bad, code):
    s = rig.secrets
    if make_bad == "missing":
        (s / "signing_keystore").unlink()
    elif make_bad == "nopass":
        (s / "signing_keystore_pass").unlink()
    elif make_bad == "badpass":
        (s / "signing_keystore_pass").write_bytes(b"ab\x00cd")
    elif make_bad == "emptyp12":
        (s / "signing_keystore").write_bytes(b"")
    else:
        rig.behave(keytool={"mode": "fail", "rc": 1, "text": "keytool error: java.io.IOException: keystore password was incorrect"})
    _, res = rig.run()
    assert res["error_code"] == code and res["error_text"] and tool_calls(rig) == []
    assert PASSWORD not in res["error_text"]


def test_fake_unreadable_key_reports_diagnosis(rig, monkeypatch):
    d = rig.d
    real = d.inspect_key_file

    def fake_inspect(path, *, kind, **kw):
        if kind == "p12":
            return real(path, kind=kind, open_fn=lambda *_a, **_k: (_ for _ in ()).throw(PermissionError(errno.EACCES, "x")),
                        stat_fn=lambda _p: SimpleNamespace(st_mode=0o100600, st_uid=1000, st_gid=1000), euid=10001)
        return real(path, kind=kind)

    monkeypatch.setattr(d, "inspect_key_file", fake_inspect)
    _, res = rig.run()
    assert res["error_code"] == "keystore_unreadable"
    for needle in ("uid 10001", "mode 600", "uid 1000", "make keystore-access"):
        assert needle in res["error_text"]


# ---- timeout / batal / aborted / batas keluaran
def test_fake_timeout_kills_the_whole_group(rig, monkeypatch):
    monkeypatch.setattr(rig.d, "SIGN_TIMEOUT", 1)
    rig.behave(**{"apksigner:sign": {"mode": "sleep"}})
    started = time.monotonic()
    _, res = rig.run(timeout=3600)
    assert res["error_code"] == "timeout" and "1 detik" in res["error_text"] and time.monotonic() - started < 15
    pid = int((rig.rec / "gc.pid").read_text())
    time.sleep(0.3)
    assert not alive(pid), "anak cucu harus ikut mati"
    assert sorted(p.name for p in rig.bdir.iterdir()) == ["unsigned.apk"]


def test_fake_term_ignoring_tool_is_sigkilled_after_grace(rig, monkeypatch):
    monkeypatch.setattr(rig.d, "SIGN_TIMEOUT", 1)
    rig.behave(**{"zipalign": {"mode": "sleep", "ignore_term": True}})
    started = time.monotonic()
    _, res = rig.run()
    assert res["error_code"] == "timeout" and time.monotonic() - started < 15
    assert not alive(int((rig.rec / "gc.pid").read_text()))


def test_fake_cancel_stops_the_job(rig):
    d = rig.d
    rig.behave(**{"apksigner:sign": {"mode": "sleep"}})
    job = sreq(d.LAYOUT, 1, 2, 60)
    d.SPOOL.submit(job)
    job_id, request = d.SPOOL.claim_next()
    d.SPOOL.request_cancel(job_id)
    started = time.monotonic()
    res = d.run_job(job_id, request)
    assert res["error_code"] == "cancelled" and time.monotonic() - started < 10
    assert sorted(p.name for p in rig.bdir.iterdir()) == ["unsigned.apk"] and not alive(int((rig.rec / "gc.pid").read_text()))


def test_fake_sigterm_during_a_job_gives_aborted(rig):
    d = rig.d
    rig.behave(**{"apksigner:sign": {"mode": "sleep"}})
    timer = threading.Timer(0.6, d.STOP.set)
    timer.start()
    try:
        _, res = rig.run()
    finally:
        timer.cancel()
    assert res["error_code"] == "aborted" and sorted(p.name for p in rig.bdir.iterdir()) == ["unsigned.apk"]
    assert not alive(int((rig.rec / "gc.pid").read_text()))


def test_fake_output_limit_kills_flooding_tool(rig, monkeypatch):
    monkeypatch.setattr(rig.d, "MAX_TOOL_OUTPUT", 256 * 1024)
    rig.behave(**{"zipalign": {"mode": "flood"}})
    started = time.monotonic()
    _, res = rig.run()
    assert res["error_code"] == "output_limit" and time.monotonic() - started < 15


def test_fake_missing_tool_is_an_internal_error(rig, monkeypatch):
    assert rig.d.key_status().state == "ok"                           # keytool dijalankan dan di-cache dulu
    monkeypatch.setattr(rig.d, "TOOL_PATH", str(rig.secrets))        # lalu tak ada zipalign di PATH
    _, res = rig.run()
    assert res["error_code"] == "internal" and "zipalign" in res["error_text"]


def test_fake_unexpected_exception_becomes_internal(rig, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("meledak " + PASSWORD)

    monkeypatch.setattr(rig.d, "check_disk", boom)
    job_id, res = rig.run()
    assert res["error_code"] == "internal" and res["error_text"] == "galat internal signer: RuntimeError"
    assert PASSWORD not in (rig.d.SPOOL.results / f"{job_id}.json").read_text()
    assert sorted(p.name for p in rig.bdir.iterdir()) == ["unsigned.apk"]


def test_fake_enospc_from_the_filesystem_maps_to_no_space(rig, monkeypatch):
    def boom(*_a, **_k):
        raise OSError(errno.ENOSPC, "No space left on device")

    real_replace = os.replace
    # hanya os.replace milik penerbitan (memakai src_dir_fd) yang gagal; atomic_write_json di Spool tetap normal
    monkeypatch.setattr(rig.d.os, "replace", lambda *a, **k: boom() if "src_dir_fd" in k else real_replace(*a, **k))
    _, res = rig.run()
    assert res["error_code"] == "no_space"
    assert sorted(p.name for p in rig.bdir.iterdir()) == ["unsigned.apk"]


# ---- urutan akhir job: cleanup SEBELUM finish
def test_fake_cleanup_runs_before_finish_and_enospc_once_still_delivers(rig, monkeypatch):
    d = rig.d
    rig.behave(**{"apksigner:verify": {"digests": [OTHER]}})              # gagal dengan .sign-signed.tmp masih ada
    events = []
    seen_at_finish = []
    real_finish, real_cleanup = d.SPOOL.finish, d.cleanup_job_files

    def finish(job_id, result):
        events.append("finish")
        seen_at_finish.append(sorted(n for n in os.listdir(rig.bdir) if n.startswith(".sign-")))
        if events.count("finish") == 1:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_finish(job_id, result)

    def cleanup(bfd, home=None):
        events.append("cleanup")
        return real_cleanup(bfd, home)

    monkeypatch.setattr(d.SPOOL, "finish", finish)
    monkeypatch.setattr(d, "cleanup_job_files", cleanup)
    job_id, res = rig.run()
    assert events.index("cleanup") < events.index("finish")
    assert seen_at_finish[0] == [] and seen_at_finish[1] == []              # .sign-* SUDAH terhapus pada percobaan pertama
    assert events.count("finish") == 2
    delivered = signspool.parse_result(stored_result(d, job_id))
    assert delivered["ok"] is False and delivered["error_code"] == "cert_mismatch"


def test_fake_finish_that_always_fails_does_not_hang_and_leaves_request_running(rig, monkeypatch, capfd):
    d = rig.d
    calls = []

    def finish(job_id, result):
        calls.append(result)
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr(d.SPOOL, "finish", finish)
    job = sreq(d.LAYOUT, 1, 2, 60)
    d.SPOOL.submit(job)
    job_id, request = d.SPOOL.claim_next()
    res = d.run_job(job_id, request)
    assert res["ok"] is True and len(calls) == d.FINISH_ATTEMPTS + 1        # 3 percobaan + hasil minimal
    assert calls[-1]["ok"] is False and calls[-1]["error_code"] == "internal"
    assert "ERROR hasil tidak bisa ditulis" in capfd.readouterr().out
    assert (d.SPOOL.running / f"{job_id}.json").exists()                     # dijawab 'aborted' saat start berikut
    assert d.SPOOL.running_job_ids() == [job_id]


def test_fake_finish_failing_with_enospc_writes_no_space_minimal_result(rig, monkeypatch):
    d = rig.d
    real_finish = d.SPOOL.finish
    calls = []

    def finish(job_id, result):
        calls.append(result)
        if len(calls) <= d.FINISH_ATTEMPTS:
            raise OSError(errno.ENOSPC, "penuh")
        return real_finish(job_id, result)

    monkeypatch.setattr(d.SPOOL, "finish", finish)
    job_id, _ = rig.run()
    stored = stored_result(d, job_id)
    assert stored["ok"] is False and stored["error_code"] == "no_space"


# ---- pemulihan yatim
def test_fake_orphan_recovery_answers_aborted_and_removes_outputs(rig):
    d = rig.d
    job = sreq(d.LAYOUT, 1, 2, 60)
    d.SPOOL.ensure_dirs()
    (d.SPOOL.running / f"{job['job_id']}.json").write_text(json.dumps(job))
    for name in ("signed.apk", ".sign-aligned.tmp", ".sign-signed.tmp", "sisa.idsig"):
        (rig.bdir / name).write_bytes(b"sisa")
    d.abort_orphans()
    stored = signspool.parse_result(stored_result(d, job["job_id"]))
    assert stored["ok"] is False and stored["error_code"] == "aborted" and "dimulai ulang" in stored["error_text"]
    assert sorted(p.name for p in rig.bdir.iterdir()) == ["unsigned.apk"]
    assert d.SPOOL.running_job_ids() == []


def test_fake_orphan_recovery_does_not_follow_symlinks(rig, tmp_path):
    d = rig.d
    outside = tmp_path / "outside"
    (outside / "5").mkdir(parents=True)
    (outside / "5" / "signed.apk").write_bytes(b"jangan hapus")
    d.LAYOUT.builds_dir(4).symlink_to(outside)
    job = sreq(d.LAYOUT, 4, 5, 60)
    d.SPOOL.ensure_dirs()
    (d.SPOOL.running / f"{job['job_id']}.json").write_text(json.dumps(job))
    d.abort_orphans()
    assert (outside / "5" / "signed.apk").read_bytes() == b"jangan hapus"
    assert stored_result(d, job["job_id"])["error_code"] == "aborted"


# ---- --health
def write_hb(d, *, age=0.0, ks="ok", detail=""):
    d.SPOOL.ensure_dirs()
    d.SPOOL.heartbeat_file.write_text(json.dumps({"ts": time.time() - age, "pid": 1, "state": "idle", "job": None,
                                                  "keystore": {"state": ks, "detail": detail, "cert_sha256": OWNER if ks == "ok" else None}}))


def test_health_fresh_and_ok_exits_0(d, capsys):
    write_hb(d)
    assert d.health() == 0 and capsys.readouterr().out == ""


def test_health_via_main_flag(d, monkeypatch, capsys):
    write_hb(d, age=1)
    monkeypatch.setattr(sys, "argv", ["signer-daemon", "--health"])
    assert d.main() == 0
    write_hb(d, age=60)
    assert d.main() == 1 and capsys.readouterr().out.count("\n") == 1


@pytest.mark.parametrize("age", [21.0, 300.0])
def test_health_stale_heartbeat_exits_1_with_one_line(d, capsys, age):
    write_hb(d, age=age)
    assert d.health() == 1
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and "usang" in out


def test_health_missing_heartbeat(d, capsys):
    d.SPOOL.ensure_dirs()
    assert d.health() == 1 and "usang" in capsys.readouterr().out


@pytest.mark.parametrize("state", ["missing", "unreadable", "invalid", "stale"])
def test_health_keystore_not_ok_exits_1_with_reason(d, capsys, state):
    write_hb(d, ks=state, detail=f"alasan {state}\nbaris kedua")
    assert d.health() == 1
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and state in out and "alasan" in out


def test_health_heartbeat_fifo_does_not_hang(d, capsys):
    d.SPOOL.ensure_dirs()
    os.mkfifo(d.SPOOL.heartbeat_file)
    code, exc = within(5, d.health)
    assert exc is None and code == 1


# ---- key_status
def keytool_calls(rig):
    return [c for c in rig.calls() if c["tool"] == "keytool"]


def test_fake_key_status_ok_uses_stderr_separately_and_key_home(rig):
    rig.behave(keytool_noise=True)
    info = rig.d.key_status()
    assert (info.state, info.cert_sha256) == ("ok", OWNER)                  # stderr 'Picked up…' tidak merusak DER
    call = keytool_calls(rig)[0]
    key_home = str(rig.home / "_key")
    assert call["env"]["HOME"] == key_home and call["cwd"] == key_home
    assert "-J-Xmx128m" in call["argv"] and f"-J-Duser.home={key_home}" in call["argv"]


def test_fake_key_status_cache_is_signature_based(rig):
    d = rig.d
    assert d.key_status().state == "ok" and d.key_status().state == "ok"
    assert len(keytool_calls(rig)) == 1                                     # dari cache
    os.chmod(rig.secrets / "signing_keystore", 0o640)                       # ctime berubah -> cache tidak dipakai
    assert d.key_status().state == "ok"
    assert len(keytool_calls(rig)) == 2
    (rig.secrets / "signing_keystore_pass").write_text(PASSWORD)            # mtime/ctime berubah
    d.key_status()
    assert len(keytool_calls(rig)) == 3


def test_fake_key_status_definitive_invalid_is_cached_and_recovers_on_change(rig):
    d = rig.d
    rig.behave(keytool={"mode": "fail", "rc": 1, "text": "keytool error: keystore password was incorrect"})
    first = d.key_status()
    assert first.state == "invalid" and "keytool gagal" in first.detail and d.key_status() == first
    assert len(keytool_calls(rig)) == 1
    rig.behave()
    os.utime(rig.secrets / "signing_keystore", (1, 1))
    assert d.key_status().state == "ok"


def test_fake_key_status_stale_is_never_served_from_cache(rig, monkeypatch):
    d = rig.d
    assert d.key_status().state == "ok" and d.KEY_STATE["cache"] is not None
    real = d.inspect_key_file
    monkeypatch.setattr(d, "inspect_key_file", lambda path, **kw: KeyStatus("stale", "make restart") if kw["kind"] == "p12" else real(path, **kw))
    stale = d.key_status()
    assert (stale.state, stale.cert_sha256) == ("stale", None) and "make restart" in stale.detail
    monkeypatch.setattr(d, "inspect_key_file", real)
    assert d.key_status().state == "ok"
    assert len(keytool_calls(rig)) == 1


def test_fake_key_status_p12_fifo_does_not_hang(rig):
    p12 = rig.secrets / "signing_keystore"
    p12.unlink()
    os.mkfifo(p12)
    info, exc = within(5, rig.d.key_status)
    assert exc is None and info.state == "invalid" and keytool_calls(rig) == []


def test_fake_key_status_keytool_sleep_times_out_is_not_cached_and_heartbeat_continues(rig, monkeypatch):
    d = rig.d
    monkeypatch.setattr(d, "KEYTOOL_TIMEOUT", 1.0)
    monkeypatch.setattr(d, "HEARTBEAT_EVERY", 0.2)
    rig.behave(keytool={"mode": "sleep"})
    stamps = []
    real_write = d.SPOOL.write_signer_heartbeat

    def spy(state, job, ks):
        stamps.append(time.monotonic())
        return real_write(state, job, ks)

    monkeypatch.setattr(d.SPOOL, "write_signer_heartbeat", spy)
    started = time.monotonic()
    info = d.key_status()
    elapsed = time.monotonic() - started
    assert info.state == "invalid" and "keytool tidak menjawab dalam 1 dtk" in info.detail and elapsed < 10
    assert d.KEY_STATE["cache"] is None                                     # hasil sementara tidak di-cache
    assert len(stamps) >= 2 and d.SPOOL.heartbeat_file.exists()             # signer.hb tetap diperbarui selama keytool
    time.sleep(0.2)
    assert not alive(int((rig.rec / "gc.pid").read_text()))
    rig.behave()                                                            # keytool sehat lagi -> langsung pulih (tak ada cache invalid)
    assert d.key_status().state == "ok"


def test_default_keytool_timeout_message_says_30_seconds(rig, monkeypatch):
    d = rig.d
    monkeypatch.setattr(d, "KEYTOOL_TIMEOUT", 30.0)
    monkeypatch.setattr(d, "run_tool", lambda argv, **kw: d.ToolResult(None, b"", "", "timeout"))
    info = d.key_status()
    assert info.detail == "keytool tidak menjawab dalam 30 dtk (keystore di filesystem yang macet atau kehabisan memori?)"


def test_fake_key_status_stop_during_keytool_returns_previous_without_touching_cache(rig, monkeypatch):
    d = rig.d
    previous = d.KeyInfo("ok", "", OTHER)
    d.KEY_STATE["last"] = previous
    d.KEY_STATE["cache"] = None
    rig.behave(keytool={"mode": "sleep"})
    timer = threading.Timer(0.5, d.STOP.set)
    timer.start()
    try:
        info, exc = within(10, d.key_status)
    finally:
        timer.cancel()
    assert exc is None and info == previous and d.KEY_STATE["cache"] is None
    assert not alive(int((rig.rec / "gc.pid").read_text()))


# ---- run_tool langsung
def test_run_tool_separate_stderr_and_bounded_output(d, tmp_path):
    script = tmp_path / "t.sh"
    script.write_text("#!/bin/sh\necho oke\necho galat >&2\n")
    script.chmod(0o755)
    res = d.run_tool([str(script)], deadline=time.monotonic() + 10, home=tmp_path / "h", on_tick=lambda: None, stderr="separate")
    assert (res.rc, res.out_bytes, res.err_text, res.status) == (0, b"oke\n", "galat\n", "done")
    merged = d.run_tool([str(script)], deadline=time.monotonic() + 10, home=tmp_path / "h", on_tick=lambda: None)
    assert merged.status == "done" and set(merged.text().split()) == {"oke", "galat"} and merged.err_text == ""


def test_run_tool_keeps_head_and_tail_only(d, tmp_path):
    script = tmp_path / "t.sh"
    script.write_text("#!/bin/sh\nawk 'BEGIN{for(i=0;i<20000;i++) print \"baris\" i}'\n")
    script.chmod(0o755)
    res = d.run_tool([str(script)], deadline=time.monotonic() + 20, home=tmp_path / "h", on_tick=lambda: None)
    text = res.text()
    assert res.status == "done" and text.startswith("baris0\n") and text.rstrip().endswith("baris19999") and "[...dipotong...]" in text
    assert len(res.out_bytes) < 8 * 1024 + 56 * 1024 + 100


def test_run_tool_calls_on_tick_while_waiting(d, tmp_path):
    script = tmp_path / "t.sh"
    script.write_text("#!/bin/sh\nsleep 0.5\n")
    script.chmod(0o755)
    ticks = []
    res = d.run_tool([str(script)], deadline=time.monotonic() + 10, home=tmp_path / "h", on_tick=lambda: ticks.append(1))
    assert res.status == "done" and len(ticks) >= 3


def test_run_tool_puts_the_tool_in_its_own_session_and_process_group(d, tmp_path):
    """kill_group/sweep_group memakai killpg(proc.pid): alat HARUS pemimpin sesi/grup sendiri, bukan satu grup dengan daemon (mutasi M31b)."""
    script = tmp_path / "t.py"
    script.write_text("import os\nprint(os.getpid(), os.getpgid(0), os.getsid(0))\n")
    res = d.run_tool([sys.executable, str(script)], deadline=time.monotonic() + 20, home=tmp_path / "h", on_tick=lambda: None)
    pid, pgid, sid = (int(x) for x in res.text().split())
    assert res.status == "done" and pid == pgid == sid
    assert pgid != os.getpgid(0) and sid != os.getsid(0)


def test_run_tool_sweeps_grandchildren_left_behind_by_a_finished_tool(d, tmp_path):
    script = tmp_path / "t.sh"
    pidfile = tmp_path / "gc.pid"
    script.write_text(f"#!/bin/sh\nsleep 300 &\necho $! > {pidfile}\nexit 0\n")      # anak cucu mewarisi pipa keluaran dan hidup terus
    script.chmod(0o755)
    started = time.monotonic()
    res = d.run_tool([str(script)], deadline=time.monotonic() + 20, home=tmp_path / "h", on_tick=lambda: None)
    assert (res.rc, res.status) == (0, "done") and time.monotonic() - started < 4
    time.sleep(0.2)
    assert not alive(int(pidfile.read_text()))


def test_run_tool_spawn_failure_is_a_status_not_an_exception(d, tmp_path):
    res = d.run_tool(["/tidak/ada/alat"], deadline=time.monotonic() + 5, home=tmp_path / "h", on_tick=lambda: None)
    assert (res.rc, res.status) == (None, "spawn_failed") and "tidak dapat dijalankan" in res.err_text


# ================================================================================ daemon sebagai proses (SIGTERM, siklus utama)
def test_fake_daemon_process_signs_then_aborts_on_sigterm(rig, tmp_path):
    d = rig.d
    boot = f"""
import importlib.machinery, importlib.util, sys
from pathlib import Path
sys.path.insert(0, {str(SERVICES)!r})
loader = importlib.machinery.SourceFileLoader('signer_daemon_main', {str(SCRIPT)!r})
spec = importlib.util.spec_from_loader('signer_daemon_main', loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)
m.TOOL_HOME_ROOT = Path({str(rig.home)!r}); m.TOOL_PATH = {d.TOOL_PATH!r}; m.TICK = 0.1; m.KEY_RECHECK = 1.0; m.TERM_GRACE = 0.5
sys.exit(m.main())
"""
    env = {"PATH": "/usr/bin:/bin", "DATA_DIR": str(d.LAYOUT.root), "SIGNER_SECRETS_DIR": str(rig.secrets), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.Popen([sys.executable, "-c", boot], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (signspool.signer_status(d.SPOOL)["hidup"] and signspool.signer_status(d.SPOOL)["keystore"]["state"] == "ok"):
            time.sleep(0.1)
        assert signspool.signer_status(d.SPOOL)["keystore"]["state"] == "ok", "daemon tidak siap"

        job = sreq(d.LAYOUT, 1, 2, 60)
        d.SPOOL.submit(job)
        end = time.monotonic() + 30
        while time.monotonic() < end and signspool.read_result(d.SPOOL, job["job_id"]) is None:
            time.sleep(0.1)
        first = signspool.read_result(d.SPOOL, job["job_id"])
        assert first is not None and first["ok"] is True and (rig.bdir / "signed.apk").exists()

        rig.behave(**{"apksigner:sign": {"mode": "sleep"}})
        job2 = sreq(d.LAYOUT, 1, 2, 60)
        d.SPOOL.submit(job2)
        end = time.monotonic() + 30
        while time.monotonic() < end and signspool.signer_status(d.SPOOL)["job"] != job2["job_id"]:
            time.sleep(0.1)
        time.sleep(1.0)                                            # pastikan apksigner palsu sudah tidur
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=30) == 0
        second = signspool.read_result(d.SPOOL, job2["job_id"])
        assert second is not None and second["error_code"] == "aborted"
        assert sorted(p.name for p in rig.bdir.iterdir()) == ["unsigned.apk"]
        assert not alive(int((rig.rec / "gc.pid").read_text()))
    finally:
        if proc.poll() is None:
            proc.kill()
        log = proc.stdout.read()
        proc.stdout.close()
    assert PASSWORD not in log and "signer siap" in log and "berhenti" in log


# ================================================================================ NYATA (Build-Tools 37 + JDK 21 + APK nyata)
REAL_VARS = ("SIGNER_TEST_BUILD_TOOLS", "SIGNER_TEST_JAVA_HOME", "SIGNER_TEST_APK")
real_only = pytest.mark.skipif(not all(os.environ.get(v) for v in REAL_VARS),
                               reason="alat nyata tidak ada (set SIGNER_TEST_BUILD_TOOLS, SIGNER_TEST_JAVA_HOME, SIGNER_TEST_APK)")
WRAPPER = ('#!/bin/sh\nexec java -Xmx256m -XX:MaxDirectMemorySize=64m --enable-native-access=ALL-UNNAMED -Duser.home="$HOME" '
           '-Djava.io.tmpdir=/tmp -jar {bt}/lib/apksigner.jar "$@"\n')


def keytool_run(real_tools, *args, check=True):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(real_tools.root), "LANG": "C.UTF-8"}
    return subprocess.run([str(real_tools.keytool), *args], capture_output=True, timeout=180, env=env, check=check)


def make_keystore(real_tools, name):
    folder = real_tools.root / name
    folder.mkdir()
    pw = os.urandom(32).hex()
    (folder / "pass").write_text(pw)
    keytool_run(real_tools, "-genkeypair", "-keystore", str(folder / "ks.p12"), "-storetype", "PKCS12", "-alias", "reverse-apk", "-keyalg", "RSA",
                "-keysize", "3072", "-sigalg", "SHA256withRSA", "-validity", "3650", "-dname", "CN=pemilik-tiruan", "-storepass:file", str(folder / "pass"))
    der = keytool_run(real_tools, "-exportcert", "-alias", "reverse-apk", "-keystore", str(folder / "ks.p12"), "-storetype", "PKCS12",
                      "-storepass:file", str(folder / "pass")).stdout
    return SimpleNamespace(p12=folder / "ks.p12", pw=folder / "pass", sha=hashlib.sha256(der).hexdigest(), der=der, folder=folder)


@pytest.fixture(scope="module")
def real_tools(tmp_path_factory):
    if not all(os.environ.get(v) for v in REAL_VARS):
        pytest.skip("alat nyata tidak ada")
    bt, jh, apk = Path(os.environ["SIGNER_TEST_BUILD_TOOLS"]), Path(os.environ["SIGNER_TEST_JAVA_HOME"]), Path(os.environ["SIGNER_TEST_APK"])
    root = tmp_path_factory.mktemp("realtools")
    bindir = root / "bin"
    bindir.mkdir()
    (bindir / "apksigner").write_text(WRAPPER.format(bt=bt))
    (bindir / "apksigner").chmod(0o755)
    (bindir / "zipalign").symlink_to(bt / "zipalign")
    (bindir / "java").symlink_to(jh / "bin" / "java")
    (bindir / "keytool").symlink_to(jh / "bin" / "keytool")
    tools = SimpleNamespace(root=root, bin=bindir, bt=bt, apk=apk, keytool=jh / "bin" / "keytool")
    tools.owner = make_keystore(tools, "owner")
    return tools


@pytest.fixture
def real(real_tools, d, tmp_path, monkeypatch):
    secrets = tmp_path / "run-secrets"
    secrets.mkdir()
    shutil.copy(real_tools.owner.p12, secrets / "signing_keystore")
    shutil.copy(real_tools.owner.pw, secrets / "signing_keystore_pass")
    bdir = d.LAYOUT.build_dir(1, 2)
    bdir.mkdir(parents=True)
    shutil.copy(real_tools.apk, bdir / "unsigned.apk")
    monkeypatch.setattr(d, "TOOL_PATH", str(real_tools.bin))
    monkeypatch.setattr(d, "KEYTOOL_TIMEOUT", 60.0)
    monkeypatch.setattr(d, "TICK", 0.25)
    return SimpleNamespace(d=d, tools=real_tools, secrets=secrets, bdir=bdir, run=lambda timeout=300: run_one(d, 1, 2, timeout))


def independent_verify(real_tools, path):
    jar = real_tools.bt / "lib" / "apksigner.jar"
    java = real_tools.bin / "java"
    out = subprocess.run([str(java), "-jar", str(jar), "verify", "--verbose", "--print-certs", str(path)], capture_output=True, text=True, timeout=120,
                         env={"PATH": "/usr/bin:/bin", "HOME": str(real_tools.root)})
    return out.returncode, out.stdout


@real_only
def test_real_sign_and_verify_with_the_owner_keystore(real):
    d = real.d
    job_id, res = real.run()
    assert res["ok"] is True, res
    signed = real.bdir / "signed.apk"
    data = signed.read_bytes()
    assert (res["output_size"], res["output_sha256"], res["cert_sha256"]) == (len(data), hashlib.sha256(data).hexdigest(), real.tools.owner.sha)
    assert res["verify"]["v2"] is True and res["verify"]["v3"] is True and res["signer_count"] == 1
    assert sorted(p.name for p in real.bdir.iterdir()) == ["signed.apk", "unsigned.apk"]
    rc, out = independent_verify(real.tools, signed)                      # verifikasi independen di luar daemon
    parsed = d.parse_verify(rc, out)
    assert rc == 0 and set(parsed.digests) == {real.tools.owner.sha}
    assert zipfile.ZipFile(signed).testzip() is None
    zip_check = subprocess.run([str(real.tools.bin / "zipalign"), "-c", "-P", "16", "4", str(signed)], capture_output=True, timeout=60)
    assert zip_check.returncode == 0
    delivered = signspool.parse_result(stored_result(d, job_id))
    assert delivered["ok"] is True and delivered["output_sha256"] == res["output_sha256"]
    assert PASSWORD not in (d.SPOOL.results / f"{job_id}.json").read_text()


@real_only
def test_real_different_owner_gives_cert_mismatch_and_no_signed_apk(real, monkeypatch):
    d = real.d
    other = make_keystore(real.tools, "other")                              # sertifikat lain yang BUKAN milik pemilik
    monkeypatch.setattr(d, "key_status", lambda: d.KeyInfo("ok", "", other.sha))
    _, res = real.run()
    assert (res["ok"], res["error_code"]) == (False, "cert_mismatch"), res
    assert other.sha[:12] in res["error_text"] and real.tools.owner.sha[:12] in res["error_text"]
    assert sorted(p.name for p in real.bdir.iterdir()) == ["unsigned.apk"]


@real_only
def test_real_bogus_zip_gives_align_failed(real):
    (real.bdir / "unsigned.apk").write_bytes(b"ini bukan zip\n" * 50)
    _, res = real.run()
    assert (res["error_code"], res["error_text"]) == ("align_failed", "bukan berkas ZIP/APK yang valid")
    assert sorted(p.name for p in real.bdir.iterdir()) == ["unsigned.apk"]


@real_only
def test_real_wrong_password_in_keytool_gives_keystore_invalid(real):
    (real.secrets / "signing_keystore_pass").write_text("salah-" + PASSWORD)
    _, res = real.run()
    assert res["error_code"] == "keystore_invalid"
    assert sorted(p.name for p in real.bdir.iterdir()) == ["unsigned.apk"]


@real_only
def test_real_wrong_password_in_apksigner_gives_keystore_invalid(real, monkeypatch):
    d = real.d
    (real.secrets / "signing_keystore_pass").write_text("salah-" + PASSWORD)
    monkeypatch.setattr(d, "key_status", lambda: d.KeyInfo("ok", "", real.tools.owner.sha))      # lewati keytool: uji pemetaan apksigner
    _, res = real.run()
    assert (res["error_code"], res["error_text"]) == ("keystore_invalid", signspool.ERROR_TEXT["keystore_invalid"])
    assert "salah-" not in json.dumps(res) and sorted(p.name for p in real.bdir.iterdir()) == ["unsigned.apk"]


@real_only
def test_real_trusted_cert_entry_instead_of_key_gives_keystore_invalid(real):
    tools = real.tools
    cert = real.secrets.parent / "cert.der"
    cert.write_bytes(tools.owner.der)
    trusted = real.secrets / "signing_keystore"
    trusted.unlink()
    keytool_run(tools, "-importcert", "-noprompt", "-alias", "reverse-apk", "-file", str(cert), "-keystore", str(trusted), "-storetype", "PKCS12",
                "-storepass:file", str(real.secrets / "signing_keystore_pass"))
    _, res = real.run()                                                   # keytool -exportcert lolos; apksigner: 'does not contain a key'
    assert res["error_code"] == "keystore_invalid", res
    assert sorted(p.name for p in real.bdir.iterdir()) == ["unsigned.apk"]


def patch_min_sdk_and_add_jar_meta(src: Path, dst: Path) -> None:
    """minSdkVersion 24 -> 21 di AndroidManifest biner (v1 aktif) dan tambah META-INF/MANIFEST.MF|CERT.SF|CERT.RSA ke masukan."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "AndroidManifest.xml":
                buf = bytearray(data)
                pos, resmap = 8, ()
                while pos + 8 <= len(buf):
                    kind, header, size = struct.unpack_from("<HHI", buf, pos)
                    if kind == 0x0180:
                        resmap = struct.unpack_from(f"<{(size - header) // 4}I", buf, pos + header)
                    pos += size
                name_idx = resmap.index(0x0101020C)                         # android:minSdkVersion
                pattern = struct.pack("<iHBBI", -1, 8, 0, 0x10, 24)
                at = buf.find(pattern)
                while at >= 0:
                    if struct.unpack_from("<I", buf, at - 4)[0] == name_idx:
                        struct.pack_into("<I", buf, at + 8, 21)
                    at = buf.find(pattern, at + 1)
                data = bytes(buf)
            zout.writestr(item, data, compress_type=item.compress_type)
        zout.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n")
        zout.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\r\n\r\n")
        zout.writestr("META-INF/CERT.RSA", b"\x30\x00")


@real_only
def test_real_v1_active_input_with_jar_meta_still_passes_and_reports_v1(real, tmp_path):
    patched = tmp_path / "v1.apk"
    patch_min_sdk_and_add_jar_meta(real.tools.apk, patched)
    shutil.copy(patched, real.bdir / "unsigned.apk")
    _, res = real.run()
    assert res["ok"] is True, res
    assert res["verify"] == {"v1": True, "v2": True, "v3": True} and res["signer_count"] == 1 and res["cert_sha256"] == real.tools.owner.sha
    rc, out = independent_verify(real.tools, real.bdir / "signed.apk")
    assert rc == 0 and "Verified using v1 scheme (JAR signing): true" in out
    names = zipfile.ZipFile(real.bdir / "signed.apk").namelist()
    assert "META-INF/MANIFEST.MF" in names


@real_only
def test_real_second_run_replaces_the_previous_signed_apk(real):
    _, first = real.run()
    _, second = real.run()
    assert first["ok"] and second["ok"] and sorted(p.name for p in real.bdir.iterdir()) == ["signed.apk", "unsigned.apk"]
    assert (real.bdir / "signed.apk").stat().st_size == second["output_size"]


@real_only
def test_real_tool_environment_is_minimal(real, monkeypatch):
    d = real.d
    seen = []
    original = d.env_minimal

    def spy(home):
        env = original(home)
        seen.append(env)
        return env

    monkeypatch.setattr(d, "env_minimal", spy)
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-Dsecret=ya")
    _, res = real.run()
    assert res["ok"] is True and seen and all(set(e) == {"PATH", "HOME", "LANG"} for e in seen)
    assert stat.S_IMODE(os.stat(d.TOOL_HOME_ROOT / "_key").st_mode) == 0o700
