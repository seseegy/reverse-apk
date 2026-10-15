"""Pustaka kunci signer (`rvcore/signkeys.py`): pembacaan aman berkas kunci dan masukan tak tepercaya, serta penilaian keadaan keystore pemilik.

Semua tes berjalan TANPA root dan tanpa JDK: EACCES nyata tidak bisa ditiru di sandbox root, jadi diinjeksikan lewat `open_fn`/`stat_fn`/`euid`
(itulah yang dijaga CI). Tes yang berpotensi menggantung (FIFO, symlink ke /dev/zero) berjalan di utas dengan `join(5)`.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import threading
from types import SimpleNamespace

import pytest

from rvcore import signkeys as K

P12 = "/run/secrets/signing_keystore"


def run_bounded(fn, *args, **kwargs):
    """Jalankan di utas; gagal bila menggantung > 5 dtk (FIFO tanpa penulis memblokir open() biasa selamanya)."""
    box: dict = {}

    def target():
        box["r"] = fn(*args, **kwargs)

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "menggantung"
    return box["r"]


def release_fifo(path):
    """Buka ujung tulis supaya utas yang (mungkin) terblokir di open() terbebas."""
    try:
        fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
        os.close(fd)
    except OSError:
        pass


def eacces(path, flags, *a, **kw):
    raise PermissionError(errno.EACCES, "Permission denied")


def test_alias_and_flags():
    assert K.ALIAS == "reverse-apk"
    for flag in (os.O_NOFOLLOW, os.O_CLOEXEC, os.O_NONBLOCK):
        assert K.OPEN_FLAGS & flag
    assert K.OPEN_FLAGS & os.O_ACCMODE == os.O_RDONLY
    assert K.MAX_P12_BYTES == 1024 * 1024 and K.MAX_PASS_BYTES == 256


# ----------------------------------------------------------------------------------------------------- inspect_key_file
def test_unreadable_message_names_uids_mode_and_the_fix():
    """Inti risiko #1 yang dijaga CI tanpa root: berkas 600 milik uid 1000 dibaca proses uid 10001."""
    st = SimpleNamespace(st_mode=0o100600, st_uid=1000, st_gid=1000)
    res = K.inspect_key_file(P12, kind="p12", open_fn=eacces, stat_fn=lambda p: st, euid=10001)
    assert res.state == "unreadable"
    for needle in ("uid 10001", "mode 600", "uid 1000", "make keystore-access"):
        assert needle in res.detail, needle
    assert len(res.detail) <= 300


def test_unreadable_without_stat_still_gives_the_fix():
    def no_stat(p):
        raise FileNotFoundError

    res = K.inspect_key_file(P12, kind="p12", open_fn=eacces, stat_fn=no_stat, euid=10001)
    assert res.state == "unreadable" and "uid 10001" in res.detail and "make keystore-access" in res.detail


def test_eperm_is_unreadable_too():
    def eperm(path, flags, *a, **kw):
        raise PermissionError(errno.EPERM, "Operation not permitted")

    assert K.inspect_key_file(P12, kind="p12", open_fn=eperm, stat_fn=lambda p: SimpleNamespace(st_mode=0o100600, st_uid=0, st_gid=0),
                              euid=10001).state == "unreadable"


def test_describe_unreadable_formats_mode_in_octal():
    text = K.describe_unreadable("/x", 10001, SimpleNamespace(st_mode=0o100640, st_uid=7, st_gid=8))
    assert "mode 640" in text and "uid 7" in text and "uid 10001" in text


def test_readable_644_is_ok(tmp_path):
    f = tmp_path / "signing_keystore"
    f.write_bytes(b"x" * 3000)
    f.chmod(0o644)
    fake = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_size=3000, st_nlink=1)
    assert K.inspect_key_file(f, kind="p12", fstat_fn=lambda fd: fake, euid=10001) == K.KeyStatus("ok", "")
    assert K.inspect_key_file(f, kind="p12").state == "ok"


def test_missing_gives_the_exact_hint(tmp_path):
    res = K.inspect_key_file(tmp_path / "nope", kind="p12")
    assert res.state == "missing"
    assert res.detail == ("/run/secrets tidak berisi kunci. Jika secrets/signing_keystore.p12 sudah ada di host, jalankan lewat 'make up' "
                          "(memuat docker-compose.keystore.yml); jika belum, 'make keystore' lalu 'make up'.")


def test_unlinked_file_is_stale_and_says_restart(tmp_path):
    f = tmp_path / "ks"
    f.write_bytes(b"x" * 500)
    gone = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_size=500, st_nlink=0)
    res = K.inspect_key_file(f, kind="p12", fstat_fn=lambda fd: gone)
    assert res.state == "stale" and "make restart" in res.detail


def test_real_unlink_between_open_and_fstat_is_stale(tmp_path):
    """Berkas yang diganti di host (rename menimpa) tetap terbuka di kontainer dengan nlink 0."""
    f = tmp_path / "ks"
    f.write_bytes(b"x" * 500)
    seen = {}

    def open_then_unlink(path, flags, *a, **kw):
        fd = os.open(path, flags, *a, **kw)
        os.unlink(path)
        seen["fd"] = fd
        return fd

    assert K.inspect_key_file(f, kind="p12", open_fn=open_then_unlink).state == "stale"


@pytest.mark.parametrize("size", [0, K.MAX_P12_BYTES + 1])
def test_p12_size_out_of_range_is_invalid(tmp_path, size):
    f = tmp_path / "ks"
    with open(f, "wb") as fh:
        fh.truncate(size)
    assert K.inspect_key_file(f, kind="p12").state == "invalid"


def test_p12_exactly_at_limit_is_ok(tmp_path):
    f = tmp_path / "ks"
    with open(f, "wb") as fh:
        fh.truncate(K.MAX_P12_BYTES)
    assert K.inspect_key_file(f, kind="p12").state == "ok"


@pytest.mark.parametrize("content", [b"", b"\n", b"x" * 257, b"ab\x00cd\n", b"ab\x07cd", b"ab\ncd\n", b"x" * 400])
def test_bad_passwords_are_invalid(tmp_path, content):
    f = tmp_path / "pw"
    f.write_bytes(content)
    assert K.inspect_key_file(f, kind="pass").state == "invalid"
    assert K.read_password_line(f) is False


@pytest.mark.parametrize("content", [b"a", b"secret-value\n", b"secret-value\r\n", b"x" * 256, b"x" * 256 + b"\n", b"pw\n\n", b"p w ok"])
def test_good_passwords_are_ok(tmp_path, content):
    f = tmp_path / "pw"
    f.write_bytes(content)
    assert K.inspect_key_file(f, kind="pass").state == "ok"
    assert K.read_password_line(f) is True


def test_password_value_is_never_in_the_status(tmp_path):
    f = tmp_path / "pw"
    f.write_bytes(b"s3cret-PASSWORD-value\x00")
    res = K.inspect_key_file(f, kind="pass")
    assert res.state == "invalid" and "s3cret" not in res.detail


def test_directory_and_symlink_are_invalid(tmp_path):
    d = tmp_path / "dir"
    d.mkdir()
    assert K.inspect_key_file(d, kind="p12").state == "invalid"
    real = tmp_path / "real"
    real.write_bytes(b"x" * 500)
    link = tmp_path / "link"
    link.symlink_to(real)
    assert K.inspect_key_file(link, kind="p12").state == "invalid"


def test_inspect_never_raises(tmp_path):
    def boom(*a, **kw):
        raise RuntimeError("boom")

    assert K.inspect_key_file(tmp_path / "x", kind="p12", open_fn=boom).state == "unreadable"
    f = tmp_path / "f"
    f.write_bytes(b"x" * 500)
    assert K.inspect_key_file(f, kind="p12", fstat_fn=boom).state == "unreadable"


def test_fifo_does_not_hang_and_is_not_ok(tmp_path):
    fifo = tmp_path / "ks"
    os.mkfifo(fifo)
    try:
        for kind in ("p12", "pass"):
            res = run_bounded(K.inspect_key_file, fifo, kind=kind)
            assert res.state != "ok"
        assert run_bounded(K.read_password_line, fifo) is False
    finally:
        release_fifo(fifo)


def test_symlink_to_dev_zero_does_not_hang_and_is_not_ok(tmp_path):
    link = tmp_path / "ks"
    link.symlink_to("/dev/zero")
    assert run_bounded(K.inspect_key_file, link, kind="p12").state != "ok"
    assert run_bounded(K.inspect_key_file, "/dev/zero", kind="p12").state != "ok"
    assert run_bounded(K.read_small, link, 1024) is None


# ------------------------------------------------------------------------------------------------------------ read_small
def test_read_small_reads_regular_files_up_to_the_limit(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"abcd")
    assert K.read_small(f, 4) == b"abcd"
    assert K.read_small(f, 3) is None
    empty = tmp_path / "e"
    empty.write_bytes(b"")
    assert K.read_small(empty, 4) == b""
    assert K.read_small(tmp_path / "missing", 4) is None


def test_read_small_rejects_directory_symlink_and_fifo(tmp_path):
    (tmp_path / "d").mkdir()
    real = tmp_path / "real"
    real.write_bytes(b"hi")
    (tmp_path / "l").symlink_to(real)
    fifo = tmp_path / "p"
    os.mkfifo(fifo)
    try:
        assert K.read_small(tmp_path / "d", 100) is None
        assert K.read_small(tmp_path / "l", 100) is None
        assert run_bounded(K.read_small, fifo, 100) is None
    finally:
        release_fifo(fifo)


def test_read_small_never_reads_more_than_limit_plus_one(monkeypatch):
    """/proc melaporkan ukuran 0 tetapi isinya besar: pembacaan harus tetap berbatas."""
    asked = []
    real_read = os.read

    def spy(fd, n):
        asked.append(n)
        return real_read(fd, n)

    monkeypatch.setattr(os, "read", spy)
    assert K.read_small("/proc/self/maps", 10) is None
    assert asked and sum(asked) <= 11 + 10 and max(asked) <= 11


def test_read_small_closes_the_fd_and_opens_with_the_shared_flags(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"x")
    opened = []

    def spy_open(path, flags, *a, **kw):
        opened.append(flags)
        fd = os.open(path, flags, *a, **kw)
        opened.append(fd)
        return fd

    assert K.read_small(f, 10, open_fn=spy_open) == b"x"
    assert opened[0] == K.OPEN_FLAGS
    with pytest.raises(OSError):
        os.fstat(opened[1])


def test_read_small_uses_dir_fd(tmp_path):
    (tmp_path / "f").write_bytes(b"dd")
    dfd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert K.read_small("f", 10, dir_fd=dfd) == b"dd"
    finally:
        os.close(dfd)


# ------------------------------------------------------------------------------------------------------ owner_fingerprint
DER = b"\x30\x82\x01\x00" + b"A" * 400


def make_run(rc=0, out=DER, calls=None, exc=None):
    def run(argv, *, deadline, home, stderr):
        if calls is not None:
            calls.append({"argv": argv, "deadline": deadline, "home": home, "stderr": stderr})
        if exc is not None:
            raise exc
        return K.ToolResult(rc, out, "Picked up JAVA_TOOL_OPTIONS: -Xmx64m")
    return run


def test_owner_fingerprint_hashes_the_der_and_builds_the_exact_command():
    calls: list = []
    state, value = K.owner_fingerprint("/s/ks", "/s/pw", make_run(calls=calls), home="/tmp/home/_key")
    assert (state, value) == ("ok", hashlib.sha256(DER).hexdigest())
    c = calls[0]
    assert c["argv"] == ["keytool", "-exportcert", "-alias", "reverse-apk", "-keystore", "/s/ks", "-storetype", "PKCS12",
                         "-storepass:file", "/s/pw", "-J-Xmx128m", "-J-Duser.home=/tmp/home/_key"]
    assert c["home"] == "/tmp/home/_key" and c["stderr"] == "separate" and c["deadline"] > 0


@pytest.mark.parametrize("out", [b"-----BEGIN CERTIFICATE-----\n" + b"A" * 300, b"\x31" + b"A" * 300, b"\x30" + b"A" * 50,
                                 b"\x30" + b"A" * 5000, b""])
def test_non_der_output_is_invalid(out):
    state, detail = K.owner_fingerprint("/s/ks", "/s/pw", make_run(out=out))
    assert state == "invalid" and "DER" in detail


def test_nonzero_exit_is_invalid_without_leaking_tool_output():
    state, detail = K.owner_fingerprint("/s/ks", "/s/pw", make_run(rc=1, out=b"keytool error: password was incorrect"))
    assert state == "invalid" and "kode 1" in detail and "password" not in detail


@pytest.mark.parametrize("exc", [TimeoutError(), InterruptedError(), OSError(errno.EIO, "io")])
def test_interrupted_or_timed_out_keytool_is_transient_not_invalid(exc):
    assert K.owner_fingerprint("/s/ks", "/s/pw", make_run(exc=exc))[0] == "transient"
    assert K.owner_fingerprint("/s/ks", "/s/pw", make_run(rc=None))[0] == "transient"
