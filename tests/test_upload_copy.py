"""`bundle.open_upload` (Tahap 3, sub-area A): pembukaan upload TOCTOU-aman, dua lintasan, salinan memfd.

`uploads/` ditulis WEB dan hanya `:ro` di runner/worker; `:ro` tidak mencegah penulisan DI TEMPAT pada inode yang sama, jadi hash dari fd saja
tidak cukup. Semua tes non-root. Semua GAGAL di kode lama: `open_upload` belum ada.
"""

from __future__ import annotations

import ast
import hashlib
import os
import stat
import threading
from pathlib import Path

import pytest

from rvcore import bundle as B
from rvcore.bundle import BundleError

from test_bundle import xapk

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="memfd_create hanya Linux")


@pytest.fixture
def up(tmp_path):
    d = tmp_path / "uploads"
    d.mkdir()
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    yield d, fd
    os.close(fd)


def put(d: Path, data: bytes) -> str:
    sha = hashlib.sha256(data).hexdigest()
    (d / f"{sha}.apk").write_bytes(data)
    return sha


def fds() -> int:
    return len(os.listdir("/proc/self/fd"))


def test_upload_dibaca_penuh_dan_zip_bisa_dipakai(up):
    d, dfd = up
    data = xapk()
    sha = put(d, data)
    with B.open_upload(dfd, sha, 64 * B.MIB) as cp:
        assert cp.size == len(data) and cp.sha256 == sha
        assert "manifest.json" in cp.zip.namelist()
        assert cp.zip.read("icon.png") == b"\x89PNG"


def test_upload_ditulis_di_tempat_setelah_memfd_tak_berpengaruh(up):
    d, dfd = up
    data = xapk()
    sha = put(d, data)
    with B.open_upload(dfd, sha, 64 * B.MIB) as cp:
        with open(d / f"{sha}.apk", "r+b") as fh:                              # web menimpa di tempat (inode sama)
            fh.write(b"\xff" * 200)
        assert cp.zip.read("icon.png") == b"\x89PNG"
        assert cp.zip.testzip() is None


def test_upload_hash_beda_bundle_changed(up):
    d, dfd = up
    data = xapk()
    sha = put(d, data)
    (d / f"{sha}.apk").write_bytes(data[:50] + bytes([data[50] ^ 0xFF]) + data[51:])
    with pytest.raises(BundleError) as ei:
        B.open_upload(dfd, sha, 64 * B.MIB)
    assert ei.value.code == "bundle_changed"


def test_upload_tidak_ada_bundle_changed(up):
    d, dfd = up
    with pytest.raises(BundleError) as ei:
        B.open_upload(dfd, "a" * 64, 64 * B.MIB)
    assert ei.value.code == "bundle_changed"


def test_upload_sha_tidak_valid_ditolak(up):
    d, dfd = up
    for bad in ("../x", "A" * 64, "abc", "", "a/b"):
        with pytest.raises(BundleError) as ei:
            B.open_upload(dfd, bad, 64 * B.MIB)
        assert ei.value.code == "bundle_invalid"


def test_upload_symlink_fifo_nlink2_bukan_reguler_ditolak(up, tmp_path):
    d, dfd = up
    data = xapk()
    sha = hashlib.sha256(data).hexdigest()
    real = tmp_path / "real.bin"
    real.write_bytes(data)
    name = d / f"{sha}.apk"
    os.symlink(real, name)                                                      # symlink
    with pytest.raises(BundleError) as ei:
        B.open_upload(dfd, sha, 64 * B.MIB)
    assert ei.value.code == "bundle_invalid"
    name.unlink()
    os.mkfifo(name)                                                             # FIFO: tidak boleh menggantung
    with pytest.raises(BundleError) as ei:
        B.open_upload(dfd, sha, 64 * B.MIB)
    assert ei.value.code == "bundle_invalid"
    name.unlink()
    name.mkdir()                                                                # direktori
    with pytest.raises(BundleError) as ei:
        B.open_upload(dfd, sha, 64 * B.MIB)
    assert ei.value.code == "bundle_invalid"
    name.rmdir()
    name.write_bytes(data)
    os.link(name, tmp_path / "keras.bin")                                       # nlink == 2
    with pytest.raises(BundleError) as ei:
        B.open_upload(dfd, sha, 64 * B.MIB)
    assert ei.value.code == "bundle_invalid"


def test_upload_kosong_ditolak(up):
    d, dfd = up
    sha = hashlib.sha256(b"").hexdigest()
    (d / f"{sha}.apk").write_bytes(b"")
    with pytest.raises(BundleError) as ei:
        B.open_upload(dfd, sha, 64 * B.MIB)
    assert ei.value.code == "bundle_invalid"


def test_upload_bukan_zip_bundle_invalid(up):
    d, dfd = up
    sha = put(d, b"bukan zip sama sekali" * 10)
    with pytest.raises(BundleError) as ei:
        B.open_upload(dfd, sha, 64 * B.MIB)
    assert ei.value.code == "bundle_invalid"


def test_upload_melebihi_cap_bundle_too_large(up):
    d, dfd = up
    data = xapk()
    sha = put(d, data)
    with pytest.raises(BundleError) as ei:
        B.open_upload(dfd, sha, len(data) - 1)
    assert ei.value.code == "bundle_too_large"
    B.open_upload(dfd, sha, len(data)).close()                                  # tepat di batas diterima


def test_upload_cap_dihitung_dari_byte_nyata_saat_berkas_tumbuh(up, monkeypatch):
    d, dfd = up
    data = xapk()
    sha = put(d, data)
    real_fstat = os.fstat

    def small(fd):                                                              # fstat berbohong kecil; byte nyata melampaui cap
        r = real_fstat(fd)
        return os.stat_result((r.st_mode, r.st_ino, r.st_dev, r.st_nlink, r.st_uid, r.st_gid, 10, r.st_atime, r.st_mtime, r.st_ctime))

    monkeypatch.setattr(B.os, "fstat", small)
    with pytest.raises(BundleError) as ei:
        B.open_upload(dfd, sha, 100)
    assert ei.value.code == "bundle_too_large"


def test_memfd_tak_tersedia_gagal_tertutup(up, monkeypatch):
    d, dfd = up
    sha = put(d, xapk())
    monkeypatch.delattr(B.os, "memfd_create", raising=False)
    with pytest.raises(BundleError) as ei:
        B.open_upload(dfd, sha, 64 * B.MIB)
    assert ei.value.code == "memfd_unavailable"
    assert sorted(p.name for p in d.iterdir()) == [f"{sha}.apk"]                # tanpa cadangan berkas biasa


def test_memfd_create_oserror_gagal_tertutup(up, monkeypatch):
    d, dfd = up
    sha = put(d, xapk())

    def boom(*a, **k):
        raise OSError(12, "ENOMEM")

    monkeypatch.setattr(B.os, "memfd_create", boom)
    with pytest.raises(BundleError) as ei:
        B.open_upload(dfd, sha, 64 * B.MIB)
    assert ei.value.code == "memfd_unavailable"


def test_upload_dibuka_sekali_lewat_dirfd_nofollow(up, monkeypatch):
    d, dfd = up
    sha = put(d, xapk())
    calls = []
    real = os.open

    def spy(path, flags, mode=0o777, *, dir_fd=None):
        calls.append((path, flags, dir_fd))
        return real(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(B.os, "open", spy)
    B.open_upload(dfd, sha, 64 * B.MIB).close()
    assert len(calls) == 1
    path, flags, dir_fd = calls[0]
    assert path == f"{sha}.apk" and dir_fd == dfd
    for f in (os.O_NOFOLLOW, os.O_NONBLOCK, os.O_CLOEXEC):
        assert flags & f
    assert flags & os.O_ACCMODE == os.O_RDONLY


def test_open_upload_ast_satu_os_open_dengan_dir_fd():
    tree = ast.parse((ROOT / "services/rvcore/bundle.py").read_text())
    fns = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    opens = [c for n in ("open_upload", "begin_upload") if n in fns for c in ast.walk(fns[n])
             if isinstance(c, ast.Call) and getattr(c.func, "attr", "") == "open" and getattr(c.func.value, "id", "") == "os"]
    assert len(opens) == 1 and any(k.arg == "dir_fd" for k in opens[0].keywords)


def test_satu_zipfile_dipakai_untuk_semua_split(up, monkeypatch):
    import zipfile
    d, dfd = up
    sha = put(d, xapk())
    made = []
    real = zipfile.ZipFile.__init__

    def counting(self, *a, **k):
        made.append(1)
        return real(self, *a, **k)

    monkeypatch.setattr(zipfile.ZipFile, "__init__", counting)
    with B.open_upload(dfd, sha, 64 * B.MIB) as cp:
        before = len(made)
        for n in cp.zip.namelist():
            cp.zip.read(n)
    assert before == 1 and len(made) == 1


def test_tidak_ada_kebocoran_fd(up):
    d, dfd = up
    sha = put(d, xapk())
    base = fds()
    for _ in range(5):
        B.open_upload(dfd, sha, 64 * B.MIB).close()
    for bad in ("a" * 64,):
        with pytest.raises(BundleError):
            B.open_upload(dfd, bad, 64 * B.MIB)
    (d / f"{sha}.apk").write_bytes(b"PK\x03\x04xx")
    with pytest.raises(BundleError):
        B.open_upload(dfd, sha, 64 * B.MIB)
    assert fds() == base


def test_upload_ditukar_setelah_lintasan1_ditolak_lintasan2(up):
    """Balapan nyata: lintasan 1 lolos, lalu utas lain menimpa berkas di tempat sebelum lintasan 2 -> bundle_changed."""
    d, dfd = up
    data = xapk()
    sha = put(d, data)
    h = B.begin_upload(dfd, sha, 64 * B.MIB)
    try:
        assert h.size == len(data)
        evil = bytearray(data)
        evil[10] ^= 0xFF

        def attacker():
            with open(d / f"{sha}.apk", "r+b") as fh:
                fh.write(bytes(evil))

        t = threading.Thread(target=attacker)
        t.start()
        t.join()
        with pytest.raises(BundleError) as ei:
            h.copy()
        assert ei.value.code == "bundle_changed"
    finally:
        h.close()


def test_begin_upload_lintasan1_membaca_central_directory_lalu_copy_memfd(up):
    d, dfd = up
    data = xapk()
    sha = put(d, data)
    with B.begin_upload(dfd, sha, 64 * B.MIB) as h:
        with h.zipfile() as z1:
            infos = z1.infolist()
        cp = h.copy()
        with cp:
            assert [i.filename for i in cp.zip.infolist()] == [i.filename for i in infos]
            assert B.plan_split_set(cp.zip.infolist(), cp.zip.read("manifest.json")).plan_sha256 == \
                B.plan_split_set(infos, cp.zip.read("manifest.json")).plan_sha256


def test_memfd_bukan_berkas_di_filesystem(up):
    d, dfd = up
    sha = put(d, xapk())
    with B.open_upload(dfd, sha, 64 * B.MIB) as cp:
        for fd in os.listdir("/proc/self/fd"):
            try:
                target = os.readlink(f"/proc/self/fd/{fd}")
            except OSError:
                continue
            if target.startswith("/memfd:"):
                assert stat.S_ISREG(os.fstat(int(fd)).st_mode)
                break
        else:
            pytest.fail("tidak ada memfd terbuka")
        assert cp.size > 0


def test_on_tick_dipanggil_per_potongan_dan_bisa_membatalkan(up):
    d, dfd = up
    data = xapk() + b""
    sha = put(d, data)
    ticks = []
    B.open_upload(dfd, sha, 64 * B.MIB, on_tick=lambda: ticks.append(1)).close()
    assert len(ticks) >= 2                                                       # minimal satu per lintasan

    def stop():
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        B.open_upload(dfd, sha, 64 * B.MIB, on_tick=stop)
