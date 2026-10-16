"""Tes tambahan hasil UJI MUTASI fase 4 (Tahap 3): ingest/unpack (bundle.py, splitzip.py), runner (buildstage.py), dan buildproto.

Tiap tes membunuh mutan yang sebelumnya SELAMAT dari tes area (lihat .agents/run/mutation-results.md). Semuanya lulus di kode asli, tidak bergantung root/uid,
dan memeriksa perilaku yang dijanjikan desain, bukan detail impl: pesan galat spesifik (pagar berlapis menghasilkan KODE yang sama sehingga hanya pesan yang
membedakan lapisan mana yang menolak), urutan pemeriksaan (gagal-cepat sebelum membaca/membuka), dan kebocoran fd.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import struct
import sys
import threading
import warnings
import zipfile
import zlib

import pytest
from rvcore import bundle as B
from rvcore import buildproto
from rvcore import splitzip as S
from rvcore.bundle import BundleError, plan_split_set

import buildstage
from test_bundle import apk_bytes, xapk, xapk_manifest, zip_bytes
from test_bundle_plan import refused, split_set, zf_of
import test_runner_build_bundle as _rb
import test_splitzip as _sz
import test_upload_copy as _uc
from test_runner_build_bundle import xapk_bytes
from test_splitzip import apk, outer
from test_upload_copy import fds, put

# fixture dipakai ulang lewat penugasan (pola yang sama dengan test_runner_build_bundle.rig): pytest menemukannya sebagai nama tingkat modul
bun, rig, dfd, up = _rb.bun, _rb.rig, _sz.dfd, _uc.up

MIB = 1024 * 1024
_SKIP_MEMFD = pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="memfd_create hanya Linux")


# ======================================================================================== bundle.plan_split_set
def test_plan_split_set_nama_ganda_persis_ditolak_duplicate_entry():
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", json.dumps(xapk_manifest(splits=())))
            zf.writestr("com.example.app.apk", apk_bytes())
            zf.writestr("icon.png", b"1")
            zf.writestr("icon.png", b"2")
    assert refused(buf.getvalue()).code == "duplicate_entry"                      # bukan 'bundle_unsafe_entry' milik pemeriksa huruf-besar-kecil


def test_plan_split_set_batas_jumlah_entri_zip_max_entries(monkeypatch):
    data = xapk()
    n = len(zf_of(data).namelist())
    monkeypatch.setattr(B, "ZIP_MAX_ENTRIES", n - 1)
    assert refused(data).code == "bundle_too_large"
    monkeypatch.setattr(B, "ZIP_MAX_ENTRIES", n)
    split_set(data)                                                               # tepat di batas diterima


def test_plan_sha256_memperhitungkan_nama_crc_dan_ukuran_terdeklarasi():
    with zf_of(xapk()) as zf:
        infos, raw = zf.infolist(), zf.read("manifest.json")
        want = plan_split_set(infos, raw).plan_sha256
        for field, delta in (("file_size", 1), ("CRC", 1)):
            mod = [copy.copy(i) for i in infos]
            setattr(mod[1], field, getattr(mod[1], field) + delta)
            assert plan_split_set(mod, raw).plan_sha256 != want, field


def test_dropped_dikenali_tanpa_peduli_huruf_besar_kecil():
    data = zip_bytes({"toc.pb": b"x", "splits/base-master.apk": apk_bytes(), "Standalones/Standalone-A.apk": apk_bytes("s"),
                      "INSTANT/i.apk": apk_bytes("i"), "System/s.apk": apk_bytes("y")})
    ss = split_set(data)
    assert ss.dropped == ("Standalones/Standalone-A.apk", "INSTANT/i.apk", "System/s.apk") and ss.apk_order == ()


def test_alias_kandidat_mulai_dari_master_2_bukan_1():
    data = zip_bytes({"toc.pb": b"x", "splits/base-master.apk": apk_bytes(), "splits/base-master_1.apk": apk_bytes("1"), "splits/base-master_2.apk": apk_bytes("2")})
    assert split_set(data).alias_candidates == ("splits/base-master_2.apk",)


def test_manifest_json_valid_tetapi_melebihi_batas_ditolak_dengan_pesan_terlalu_besar():
    raw = json.dumps(xapk_manifest()).encode() + b" " * B.MAX_MANIFEST_BYTES              # JSON SAH, hanya kebesaran: bukan 'JSON rusak'
    with zf_of(xapk()) as zf:
        with pytest.raises(BundleError, match="terlalu besar") as ei:
            plan_split_set(zf.infolist(), raw)
    assert ei.value.code == "bad_bundle"


def _xapk_dengan_manifest(raw: bytes) -> bytes:
    return zip_bytes({"manifest.json": raw, "com.example.app.apk": apk_bytes(), "icon.png": b"\x89PNG"})


def test_plan_from_zip_membaca_satu_byte_lebih_agar_batas_terdeteksi():
    pas = json.dumps(xapk_manifest(splits=())).encode()
    pas = pas + b" " * (B.MAX_MANIFEST_BYTES - len(pas))
    with zf_of(_xapk_dengan_manifest(pas)) as zf:
        assert B.plan_from_zip(zf).format == "xapk"                                # tepat MAX_MANIFEST_BYTES diterima
    with zf_of(_xapk_dengan_manifest(pas + b" ")) as zf:
        with pytest.raises(BundleError, match="terlalu besar") as ei:               # MAX+1: terdeteksi hanya bila dibaca MAX+1 byte
            B.plan_from_zip(zf)
    assert ei.value.code == "bad_bundle"


def test_apk_biasa_di_dalam_paket_ditolak_walau_ada_apk_bersarang():
    data = zip_bytes({"AndroidManifest.xml": b"axml", "toc.pb": b"x", "splits/base-master.apk": apk_bytes()})
    err = refused(data)
    assert err.code == "bundle_invalid" and "APK biasa" in err.message


def test_paket_tanpa_entri_apk_ditolak_bundle_invalid():
    err = refused(zip_bytes({"manifest.json": json.dumps(xapk_manifest(splits=())).encode(), "icon.png": b"1"}))
    assert err.code == "bundle_invalid" and "tidak ada entri .apk" in err.message          # bukan 'bundle_no_base' dari _xapk_base


# ======================================================================================== bundle.begin_upload / copy
def _bounded(fn, fifo_path, seconds=5):
    """Jalankan `fn` di utas; menggantung (FIFO tanpa O_NONBLOCK) -> dilepas lalu GAGAL cepat, bukan membekukan seluruh tes."""
    box: dict = {}

    def target():
        try:
            box["r"] = fn()
        except BaseException as exc:  # noqa: BLE001
            box["e"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        os.close(os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK))
        t.join(2)
        pytest.fail("menggantung pada FIFO: pembukaan harus O_NONBLOCK")
    if "e" in box:
        raise box["e"]
    return box.get("r")


@_SKIP_MEMFD
def test_begin_upload_fifo_tidak_menggantung(up):
    d, dfd_ = up
    sha = "cd" * 32
    os.mkfifo(d / f"{sha}.apk")
    with pytest.raises(BundleError):
        _bounded(lambda: B.begin_upload(dfd_, sha, 64 * MIB), d / f"{sha}.apk")


@_SKIP_MEMFD
def test_begin_upload_fifo_ditolak_sebagai_bukan_berkas_biasa_bukan_kosong(up):
    d, dfd_ = up
    sha = "ab" * 32
    os.mkfifo(d / f"{sha}.apk")                                                   # nlink 1 dan ukuran 0: HANYA S_ISREG yang menolaknya dengan pesan ini
    with pytest.raises(BundleError, match="bukan berkas biasa") as ei:
        B.begin_upload(dfd_, sha, 64 * MIB)
    assert ei.value.code == "bundle_invalid"


@_SKIP_MEMFD
def test_begin_upload_hash_lintasan1_langsung_dibandingkan(up):
    d, dfd_ = up
    data = xapk()
    sha = put(d, data)
    evil = bytearray(data)
    evil[10] ^= 0xFF
    (d / f"{sha}.apk").write_bytes(bytes(evil))
    with pytest.raises(BundleError, match="tidak sama dengan hash") as ei:          # gagal-cepat di lintasan 1, sebelum salinan memfd
        B.begin_upload(dfd_, sha, 64 * MIB)
    assert ei.value.code == "bundle_changed"


@_SKIP_MEMFD
def test_begin_upload_cap_ukuran_ditolak_sebelum_satu_byte_pun_dibaca(up, monkeypatch):
    d, dfd_ = up
    data = xapk()
    sha = put(d, data)

    def boom(*a, **k):
        raise AssertionError("tidak boleh membaca isi upload yang sudah melebihi cap")

    with monkeypatch.context() as mp:
        mp.setattr(os, "read", boom)
        with pytest.raises(BundleError) as ei:
            B.begin_upload(dfd_, sha, len(data) - 1)
    assert ei.value.code == "bundle_too_large"


@_SKIP_MEMFD
def test_begin_upload_kosong_ditolak_dengan_pesan_kosong(up):
    d, dfd_ = up
    sha = hashlib.sha256(b"").hexdigest()                                           # hash cocok: hanya pemeriksaan ukuran yang menolak
    (d / f"{sha}.apk").write_bytes(b"")
    with pytest.raises(BundleError, match="kosong") as ei:
        B.begin_upload(dfd_, sha, 64 * MIB)
    assert ei.value.code == "bundle_invalid"


@_SKIP_MEMFD
def test_copy_gagal_tidak_membocorkan_memfd(up):
    d, dfd_ = up
    data = xapk()
    sha = put(d, data)
    h = B.begin_upload(dfd_, sha, 64 * MIB)
    try:
        evil = bytearray(data)
        evil[10] ^= 0xFF
        (d / f"{sha}.apk").write_bytes(bytes(evil))
        before = fds()
        with pytest.raises(BundleError) as ei:
            h.copy()
        assert ei.value.code == "bundle_changed" and fds() == before, "memfd yang sudah dibuat harus ditutup saat hash lintasan 2 beda"
    finally:
        h.close()


# ======================================================================================== splitzip.checked_entry_names
def _fd_of(tmp_path, data: bytes) -> int:
    p = tmp_path / "z.zip"
    p.write_bytes(data)
    return os.open(p, os.O_RDONLY)


def _patch_eocd(data: bytes, total: int | None = None, cd_size: int | None = None) -> bytes:
    at = data.rfind(b"PK\x05\x06")
    buf = bytearray(data)
    if total is not None:
        buf[at + 8:at + 12] = struct.pack("<HH", total, total)
    if cd_size is not None:
        buf[at + 12:at + 16] = struct.pack("<I", cd_size)
    return bytes(buf)


def _no_zipfile(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("ZipFile tidak boleh dibuka sebelum EOCD lolos pagar")

    monkeypatch.setattr(S.zipfile, "ZipFile", boom)


def test_checked_entry_names_total_eocd_melebihi_batas_ditolak_sebelum_zipfile_dibuka(tmp_path, monkeypatch):
    fd = _fd_of(tmp_path, apk({f"f{i}": b"x" for i in range(5)}))
    try:
        _no_zipfile(monkeypatch)
        with pytest.raises(S.ZipTooBig, match="jumlah entri 5"):
            S.checked_entry_names(fd, 3)
    finally:
        os.close(fd)


def test_checked_entry_names_ukuran_central_directory_ditolak_sebelum_zipfile_dibuka(tmp_path, monkeypatch):
    data = apk({f"{'n' * 600}{i}": b"x" for i in range(5)})                        # CD ~3,2 KiB > 5 x 512
    fd = _fd_of(tmp_path, data)
    try:
        assert len(S.checked_entry_names(fd, 7)) == 5                               # 7 x 512 cukup: diterima
        _no_zipfile(monkeypatch)
        with pytest.raises(S.ZipTooBig, match="central directory"):
            S.checked_entry_names(fd, 5)
    finally:
        os.close(fd)


def test_checked_entry_names_cd_size_lebih_besar_dari_berkas_ditolak(tmp_path):
    fd = _fd_of(tmp_path, _patch_eocd(apk({"a": b"x"}), cd_size=10 ** 6))
    try:
        with pytest.raises(S.ZipTooBig, match="central directory"):
            S.checked_entry_names(fd, 10 ** 6)                                       # batas entri longgar: hanya 'cd_size > ukuran berkas' yang menolak
    finally:
        os.close(fd)


def test_checked_entry_names_zip64_ditolak_bukan_sebagai_terlalu_besar(tmp_path):
    fd = _fd_of(tmp_path, _patch_eocd(apk({"a": b"x"}), total=0xFFFF))
    try:
        with pytest.raises(zipfile.BadZipFile, match="ZIP64") as ei:
            S.checked_entry_names(fd, 1_000_000)
        assert not isinstance(ei.value, S.ZipTooBig)
    finally:
        os.close(fd)


def test_checked_entry_names_jumlah_nama_nyata_diperiksa_walau_eocd_berbohong(tmp_path):
    fd = _fd_of(tmp_path, _patch_eocd(apk({f"f{i}": b"x" for i in range(5)}), total=1))        # EOCD mengaku 1, CD berisi 5
    try:
        with pytest.raises(S.ZipTooBig, match="jumlah entri 5"):
            S.checked_entry_names(fd, 3)
    finally:
        os.close(fd)


@pytest.mark.parametrize("data", [b"x" * 100, b"PK\x05\x06" + b"\0" * 10, b""])
def test_checked_entry_names_tanpa_eocd_utuh_ditolak_dengan_pesan_rekaman_akhir(tmp_path, data):
    fd = _fd_of(tmp_path, data)
    try:
        with pytest.raises(zipfile.BadZipFile, match="rekaman akhir"):
            S.checked_entry_names(fd, 100)
    finally:
        os.close(fd)


# ======================================================================================== splitzip: pesan lapisan penolak
def _encrypted(data: bytes) -> bytes:
    buf = bytearray(data)
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        buf[buf.find(sig) + off] |= 0x1
    return bytes(buf)


def test_strip_entri_terenkripsi_ditolak_oleh_pemeriksa_metode_bukan_oleh_zipfile(dfd, tmp_path):
    with zipfile.ZipFile(io.BytesIO(_encrypted(apk({"AndroidManifest.xml": b"m"})))) as zf:
        with pytest.raises(BundleError, match="terenkripsi") as ei:
            S.strip_signatures(zf, dfd, "split-001.apk", S.ZipBudget())
    assert ei.value.code == "split_invalid" and not list(tmp_path.iterdir())


def test_extract_member_at_anggota_terenkripsi_ditolak_dengan_pesan_terenkripsi(dfd, tmp_path):
    with zipfile.ZipFile(io.BytesIO(_encrypted(apk({"a.apk": apk({"a": b"1"})})))) as zf:
        with pytest.raises(BundleError, match="terenkripsi"):
            S.extract_member_at(zf, "a.apk", dfd, "o.raw", MIB)
    assert not list(tmp_path.iterdir())


def test_strip_rasio_kompresi_tinggi_di_bawah_ambang_8_mib_diterima(dfd, tmp_path):
    data = apk({"AndroidManifest.xml": b"m", "nol.bin": b"\0" * MIB})                # rasio ~1000:1 tetapi 1 MiB < BOMB_ENTRY_MIN
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        S.strip_signatures(zf, dfd, "split-001.apk", S.ZipBudget())
    assert zipfile.ZipFile(tmp_path / "split-001.apk").read("nol.bin") == b"\0" * MIB


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
    """ZipFile palsu yang berbohong tentang ukuran: pagar byte-nyata harus berdiri sendiri, tidak mengandalkan zipfile."""

    def __init__(self, info, chunks):
        self._info, self._chunks = info, chunks

    def infolist(self):
        return [self._info]

    def open(self, info):
        return _Rd(self._chunks)


def _lying_info(name="a.apk", declared=10):
    info = zipfile.ZipInfo(name)
    info.file_size = declared
    info.compress_size = declared
    return info


def test_copy_entry_byte_nyata_melebihi_ukuran_terdeklarasi_ditolak():
    sink: list[bytes] = []
    with pytest.raises(BundleError, match="melebihi ukuran terdeklarasi"):
        S._copy_entry(_FakeZip(_lying_info(), [b"x" * 6, b"y" * 6]), _lying_info(), sink.append, None)


def test_copy_entry_isi_lebih_pendek_dari_terdeklarasi_ditolak():
    with pytest.raises(BundleError, match="lebih pendek"):
        S._copy_entry(_FakeZip(_lying_info(), [b"x" * 4]), _lying_info(), lambda c: None, None)


def test_extract_member_at_byte_nyata_melebihi_batas_walau_deklarasi_kecil(dfd, tmp_path):
    info = _lying_info(declared=10)
    info.compress_type = zipfile.ZIP_STORED
    fake = _FakeZip(info, [b"PK\x03\x04" + b"x" * MIB, b"y" * MIB])                  # deklarasi 10 B, nyata 2 MiB
    with pytest.raises(BundleError, match="setelah diekstrak") as ei:
        S.extract_member_at(fake, "a.apk", dfd, "o.raw", MIB)
    assert ei.value.code == "bundle_too_large" and not list(tmp_path.iterdir())


def test_extract_member_at_deklarasi_melebihi_batas_ditolak_sebelum_membaca(dfd, tmp_path):
    inner = apk({"a": os.urandom(4000)}, {"a": zipfile.ZIP_STORED})
    with outer({"a.apk": inner}) as zf:
        with pytest.raises(BundleError) as ei:
            S.extract_member_at(zf, "a.apk", dfd, "o.raw", len(inner) - 1)
    assert ei.value.code == "bundle_too_large" and "setelah diekstrak" not in ei.value.message, "ditolak oleh pra-cek ukuran terdeklarasi, bukan saat streaming"
    assert not list(tmp_path.iterdir())


def test_extract_member_at_anggota_folder_ditolak_dengan_pesan_folder(dfd, tmp_path):
    with zipfile.ZipFile(io.BytesIO(zip_bytes({"dir/": b"", "x": b"1"}))) as zf:
        with pytest.raises(BundleError, match="folder") as ei:
            S.extract_member_at(zf, "dir/", dfd, "o.raw", MIB)
    assert ei.value.code == "split_invalid" and not list(tmp_path.iterdir())


def test_extract_member_at_memakai_batas_per_entri_anggaran(dfd, tmp_path):
    inner = apk({"a": os.urandom(4000)}, {"a": zipfile.ZIP_STORED})
    with outer({"a.apk": inner}) as zf:
        with pytest.raises(BundleError, match="terlalu besar") as ei:
            S.extract_member_at(zf, "a.apk", dfd, "o.raw", 10 * MIB, budget=S.ZipBudget(max_entry=100))
    assert ei.value.code == "bundle_too_large" and not list(tmp_path.iterdir())


def _crc_suffix(prefix: bytes, target: int) -> bytes:
    """4 byte `b` sehingga crc32(prefix + b) == target. CRC32 afin atas GF(2): selesaikan sistem linear 32x32 dengan eliminasi Gauss memakai zlib itu sendiri."""
    base = zlib.crc32(prefix + b"\0\0\0\0")
    cols = [zlib.crc32(prefix + (1 << i).to_bytes(4, "little")) ^ base for i in range(32)]
    basis: dict[int, tuple[int, int]] = {}
    for i, col in enumerate(cols):
        v, mask = col, 1 << i
        while v:
            p = v.bit_length() - 1
            if p not in basis:
                basis[p] = (v, mask)
                break
            v ^= basis[p][0]
            mask ^= basis[p][1]
    v, mask = target ^ base, 0
    while v:
        p = v.bit_length() - 1
        v ^= basis[p][0]
        mask ^= basis[p][1]
    out = mask.to_bytes(4, "little")
    assert zlib.crc32(prefix + out) == target
    return out


def test_content_digest_membedakan_dua_isi_ber_crc32_dan_ukuran_sama():
    target = 0xDEADBEEF
    a = b"isi-APK-pertama-" + _crc_suffix(b"isi-APK-pertama-", target)
    b = b"ISI-lain-sekali!" + _crc_suffix(b"ISI-lain-sekali!", target)
    assert a != b and zlib.crc32(a) == zlib.crc32(b) and len(a) == len(b)
    za = apk({"classes.dex": a}, {"classes.dex": zipfile.ZIP_STORED})
    zb = apk({"classes.dex": b}, {"classes.dex": zipfile.ZIP_STORED})
    with zipfile.ZipFile(io.BytesIO(za)) as x, zipfile.ZipFile(io.BytesIO(zb)) as y:
        assert x.getinfo("classes.dex").CRC == y.getinfo("classes.dex").CRC and x.getinfo("classes.dex").file_size == y.getinfo("classes.dex").file_size
        assert S.content_digest(x) != S.content_digest(y), "alias ditentukan dari SHA-256 isi, bukan CRC32 (tabrakan CRC32 mudah dibuat)"


# ======================================================================================== buildproto
def test_hasil_split_ukuran_batas_atas_2_pangkat_50():
    base = {"status": "ok", "output_size": 10, "output_sha256": "aa" * 32, "source_kind": "xapk", "plan_sha256": "bb" * 32, "aliases": [], "warnings": []}
    ok = buildproto.parse_build_result({**base, "splits": [{"index": 1, "sha256": "cc" * 32, "size": 2 ** 50}]})
    assert ok["ok"] is True
    big = buildproto.parse_build_result({**base, "splits": [{"index": 1, "sha256": "cc" * 32, "size": 2 ** 50 + 1}]})
    assert big["ok"] is False and big["error_code"] == "bad_result"


# ======================================================================================== runner (buildstage)
def test_bundle_finish_kode_di_luar_daftar_dipetakan_ke_bundle_invalid():
    assert buildstage._bundle_finish(BundleError("bundle_unsafe_entry", "x")).result["error_code"] == "bundle_invalid"
    assert buildstage._bundle_finish(BundleError("split_missing", "x")).result["error_code"] == "split_missing"


def test_bundle_src_dihapus_sebelum_split_dibuat(bun, monkeypatch):
    seen: list[bool] = []
    real = buildstage._make_splits

    def spy(env, bfd, handle, plan, ticker):
        seen.append((bun.build_dir / "src").exists())
        return real(env, bfd, handle, plan, ticker)

    monkeypatch.setattr(buildstage, "_make_splits", spy)
    assert bun.brun(xapk_bytes(), "xapk")["status"] == "ok"
    assert seen == [False], "pohon src/ (bisa ratusan MiB) harus sudah dibuang sebelum split diekstrak (puncak disk)"


def test_bundle_batas_byte_split_runner_ditegakkan(bun):
    bun.env.max_split_bytes = 50                                                   # nested() jauh lebih besar dari 50 byte
    res = bun.brun(xapk_bytes(), "xapk")
    assert (res["status"], res["error_code"]) == ("failed", "bundle_too_large")
    assert bun.ls() == ["build.log"]


def test_bundle_berkas_antara_raw_dibuang_setelah_tiap_split(bun, monkeypatch):
    seen: list[list[str]] = []
    real = buildstage.splitzip.strip_signatures

    def spy(zf, dirfd, name, budget, on_tick=None, mode=0o644):
        seen.append(sorted(n for n in os.listdir(dirfd) if n.startswith((".split-", ".alias-"))))
        return real(zf, dirfd, name, budget, on_tick, mode)

    monkeypatch.setattr(buildstage.splitzip, "strip_signatures", spy)
    assert bun.brun(xapk_bytes(splits=("config.a.apk", "config.b.apk", "config.c.apk")), "xapk")["status"] == "ok"
    assert seen == [[".split-001.raw"], [".split-002.raw"], [".split-003.raw"]], "hanya satu .split-NNN.raw ada pada satu waktu"


def test_bundle_ticker_dicek_langsung_sebelum_tiap_split(bun, monkeypatch):
    direct: list[str] = []
    real_call = buildstage._Ticker.__call__

    def spy(self):
        caller = sys._getframe(1).f_code.co_name
        if caller == "_make_splits":
            direct.append(caller)
        return real_call(self)

    monkeypatch.setattr(buildstage._Ticker, "__call__", spy)
    assert bun.brun(xapk_bytes(splits=("config.a.apk", "config.b.apk", "config.c.apk")), "xapk")["status"] == "ok"
    assert len(direct) == 3, "pembatalan/tenggat dicek SEBELUM tiap split diekstrak, tidak hanya per potongan 1 MiB di dalamnya"


def test_bundle_batas_salinan_upload_runner_ditegakkan(bun):
    bun.env.upload_cap_bytes = 100                                                 # xapk_bytes() jauh lebih besar dari 100 byte
    res = bun.brun(xapk_bytes(), "xapk")
    assert (res["status"], res["error_code"]) == ("failed", "bundle_too_large")
    assert bun.ls() == ["build.log"]
