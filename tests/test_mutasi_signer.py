"""Tes tambahan hasil UJI MUTASI fase 4 (Tahap 3): signer-daemon dan `signer-selftest --check-bundle`.

Mutan yang sebelumnya SELAMAT adalah pagar berlapis: dua lapisan menolak masukan buruk dengan KODE yang sama, sehingga tes lama (yang hanya membandingkan kode)
tidak tahu lapisan mana yang bekerja. Tes ini mengunci lapisan itu lewat pesan galat, urutan (gagal-cepat), dan isi ruang kerja saat alat dipanggil.
Lulus di kode asli, tidak bergantung root/uid.
"""

from __future__ import annotations

import io
import os
import zipfile

import pytest
from rvcore import signspool

from test_signer_daemon import load_daemon
import test_signer_selftest_bundle as _sb
from test_signer_selftest_bundle import apk, zbytes

rg, st = _sb.rg, _sb.st                                                            # fixture dipakai ulang lewat penugasan

MIB = 1024 * 1024


@pytest.fixture
def d(monkeypatch, tmp_path):
    return load_daemon(monkeypatch, tmp_path)


@pytest.fixture
def dirfd(tmp_path):
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    yield fd
    os.close(fd)


# ======================================================================================== signer-daemon
def test_entry_names_bukan_berkas_biasa_ditolak_dengan_pesan_itu(d, tmp_path, dirfd):
    os.mkdir(tmp_path / "x")                                                       # dibuka OPEN_FLAGS lalu fstat: bukan S_ISREG
    with pytest.raises(d.JobError, match="bukan berkas biasa") as ei:
        d._entry_names(dirfd, "x", "split-001.apk", "input_unsafe")
    assert ei.value.code == "input_unsafe"


def test_open_input_fifo_ditolak_sebagai_bukan_berkas_biasa_bukan_kosong(d, tmp_path, dirfd):
    os.mkfifo(tmp_path / "unsigned.apk")                                           # nlink 1 dan ukuran 0: hanya S_ISREG yang menolak dengan pesan ini
    with pytest.raises(d.JobError, match="bukan berkas biasa") as ei:
        d.open_input(dirfd, "unsigned.apk", 10 * MIB)
    assert ei.value.code == "input_unsafe"


def test_process_menolak_lebih_dari_max_splits_walau_validasi_request_dilewati(d, monkeypatch):
    monkeypatch.setattr(d, "validate_request", lambda request, job_id: (1, 2, 60, "a" * 64, ["b" * 64] * (signspool.MAX_SPLITS + 1)))
    job = d._Job("g1-2-deadbeef")
    with pytest.raises(d.JobError, match="melebihi") as ei:                         # pagar kedua (defense-in-depth) sebelum kunci/folder disentuh
        d._process(job, {}, 0.0)
    assert ei.value.code == "bad_request" and job.bfd is None


def test_copy_input_menolak_in_apk_yang_sudah_ada_o_excl(d, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / d.W_IN).write_bytes(b"ditanam-penyerang")                               # berkas biasa yang sudah ada: O_TRUNC akan menimpanya, O_EXCL menolak
    src = tmp_path / "src.apk"
    src.write_bytes(b"isi-apk" * 10)
    wfd = os.open(work, os.O_RDONLY | os.O_DIRECTORY)
    sfd = os.open(src, os.O_RDONLY)
    try:
        with pytest.raises(FileExistsError):
            d.copy_input(sfd, wfd, MIB, lambda: None)
    finally:
        os.close(sfd)
        os.close(wfd)
    assert (work / d.W_IN).read_bytes() == b"ditanam-penyerang"


# ======================================================================================== signer-selftest --check-bundle
def _package(rg_, data: bytes):
    (rg_.dir / rg_.name).write_bytes(data)
    return rg_


def _flag_encrypted(data: bytes) -> bytes:
    buf = bytearray(data)
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = buf.find(sig)
        while pos >= 0:
            buf[pos + off] |= 0x1
            pos = buf.find(sig, pos + 4)
    return bytes(buf)


def test_check_bundle_entri_terenkripsi_ditolak_sebelum_ekstraksi(rg, capsys):
    _package(rg, _flag_encrypted(zbytes({"x.apk": apk("base"), "config.a.apk": apk("a")})))
    rc, cap = rg.run(capsys)
    assert rc == 3 and "kode=bukan_paket" in cap.out
    assert "terenkripsi" in cap.out and rg.tools() == []                              # bukan 'entri APK rusak' dari ekstraksi; tak ada alat dijalankan


def test_check_bundle_kompresi_tak_umum_ditolak(rg, capsys):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("x.apk", apk("base"), compress_type=zipfile.ZIP_BZIP2)
    _package(rg, buf.getvalue())
    rc, cap = rg.run(capsys)
    assert rc == 3 and "kode=bukan_paket" in cap.out and rg.tools() == []


class _Rd:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def read(self, n):
        return self.chunks.pop(0) if self.chunks else b""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeZip:
    def __init__(self, chunks):
        self.chunks = chunks

    def open(self, info):
        return _Rd(self.chunks)


def test_extract_apk_byte_nyata_melebihi_ukuran_terdeklarasi_ditolak(st, tmp_path):
    info = zipfile.ZipInfo("x.apk")
    info.file_size = 10
    sub = tmp_path / "sub"
    sub.mkdir()
    sfd = os.open(sub, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(st.CheckFail, match="melebihi") as ei:
            st._extract_apk(_FakeZip([b"x" * 6, b"y" * 6]), info, sfd, "e001.apk")
    finally:
        os.close(sfd)
    assert ei.value.kode == "bukan_paket"


def test_check_bundle_jumlah_entri_ditolak_dari_eocd_sebelum_zipfile_dibuka(rg, capsys, monkeypatch):
    rg.package()
    monkeypatch.setattr(rg.st, "ZIP_MAX_ENTRIES", 2)                               # paket uji berisi 6 entri

    def boom(*a, **k):
        raise AssertionError("ZipFile tidak boleh dibuka sebelum pagar EOCD")

    monkeypatch.setattr(rg.st.zipfile, "ZipFile", boom)
    rc, cap = rg.run(capsys)
    assert rc == 3 and "kode=bukan_paket" in cap.out and "kode=internal" not in cap.out


def test_check_bundle_apk_diekstrak_dibuang_sebelum_apk_berikutnya_puncak_disk_satu_apk(rg, capsys, monkeypatch):
    rg.package()
    seen: list[list[str]] = []
    real = rg.st._run_tool

    def spy(argv, *a, **k):
        seen.append(sorted(os.listdir(os.path.dirname(argv[-1]))))
        return real(argv, *a, **k)

    monkeypatch.setattr(rg.st, "_run_tool", spy)
    rc, cap = rg.run(capsys)
    assert rc == 0, cap.out
    assert seen == [["e001.apk"], ["e001.apk"], ["e002.apk"], ["e002.apk"], ["e003.apk"], ["e003.apk"]], "tiap APK dibuang sebelum yang berikut diekstrak"
