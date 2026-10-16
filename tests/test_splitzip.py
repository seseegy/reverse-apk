"""`rvcore.splitzip` (Tahap 3, sub-area A): pembuangan tanda tangan lama lewat re-zip, ekstraksi anggota ke dir_fd, ringkasan isi.

Tidak bergantung root/uid (CI non-root). Semua tes GAGAL di kode lama: modul belum ada.
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from rvcore import splitzip as S
from rvcore.bundle import BundleError

MIB = 1024 * 1024
SIG_NAMES = ["META-INF/MANIFEST.MF", "META-INF/CERT.SF", "META-INF/CERT.RSA", "META-INF/CERT.DSA", "META-INF/CERT.EC", "META-INF/SIG-X"]


def apk(entries: dict[str, bytes], methods: dict[str, int] | None = None, dates: dict[str, tuple] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zi = zipfile.ZipInfo(name, (dates or {}).get(name, (2021, 5, 6, 7, 8, 10)))
            zi.compress_type = (methods or {}).get(name, zipfile.ZIP_DEFLATED)
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16 if name == "link" else 0o100600 << 16
            zf.writestr(zi, data)
    return buf.getvalue()


def zf_of(data: bytes) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(data))


@pytest.fixture
def dfd(tmp_path):
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    yield fd
    os.close(fd)


def strip(data: bytes, dfd: int, name: str = "split-001.apk", budget=None):
    with zf_of(data) as zf:
        return S.strip_signatures(zf, dfd, name, budget or S.ZipBudget())


def result_zip(tmp_path: Path, name: str = "split-001.apk") -> zipfile.ZipFile:
    return zipfile.ZipFile(tmp_path / name)


# ---------------------------------------------------------------------------------------------- predikat
@pytest.mark.parametrize("name", SIG_NAMES)
def test_strip_tiap_ekstensi_tanda_tangan_satu_per_satu(name, dfd, tmp_path):
    strip(apk({"AndroidManifest.xml": b"m", name: b"sig"}), dfd)
    assert result_zip(tmp_path).namelist() == ["AndroidManifest.xml"]


@pytest.mark.parametrize("name", ["meta-inf/x.rsa", "Meta-Inf/X.Rsa", "META-INF/x.sf", "meta-inf/manifest.mf", "META-INF/sig-a"])
def test_strip_meta_inf_huruf_kecil_dan_campuran(name, dfd, tmp_path):
    assert S.is_signature_entry(name)
    strip(apk({"AndroidManifest.xml": b"m", name: b"sig"}), dfd)
    assert result_zip(tmp_path).namelist() == ["AndroidManifest.xml"]


def test_predikat_tanda_tangan_semua_ekstensi_case_insensitive():
    for ext in ("SF", "RSA", "DSA", "EC", "sf", "rsa", "dsa", "ec", "Rsa"):
        assert S.is_signature_entry(f"META-INF/ABC.{ext}")


def test_predikat_tidak_menyentuh_services_version_kotlin_module_dan_subfolder():
    for name in ("META-INF/services/x.RSA", "META-INF/com/x.SF", "META-INF/androidx.core.version", "META-INF/app.kotlin_module", "META-INF/", "META-INF/sub/MANIFEST.MF",
                 "res/META-INF/A.RSA", "assets/CERT.RSA", "META-INF", "META-INF/x.rsa.bak", "META-INF/x.idsig", "AndroidManifest.xml"):
        assert not S.is_signature_entry(name), name


def test_strip_membuang_blok_v2_v3(dfd, tmp_path):
    data = apk({"AndroidManifest.xml": b"m", "classes.dex": b"d" * 100})
    cd = data.rfind(b"PK\x01\x02")
    first_cd_offset = struct.unpack("<I", data[data.rfind(b"PK\x05\x06") + 16:data.rfind(b"PK\x05\x06") + 20])[0]
    block = b"BLOCKBYTES" * 10 + struct.pack("<Q", 0) + b"APK Sig Block 42"
    eocd = bytearray(data[data.rfind(b"PK\x05\x06"):])
    eocd[16:20] = struct.pack("<I", first_cd_offset + len(block))
    body = data[:first_cd_offset] + block + data[first_cd_offset:data.rfind(b"PK\x05\x06")]
    # offset header lokal tidak berubah (blok disisipkan SESUDAH entri); cukup sesuaikan EOCD
    signed = body + bytes(eocd)
    assert b"APK Sig Block 42" in signed and cd > 0
    strip(signed, dfd)
    out = (tmp_path / "split-001.apk").read_bytes()
    assert b"APK Sig Block 42" not in out and b"BLOCKBYTES" not in out


def test_strip_mempertahankan_urutan_compress_type_date_time(dfd, tmp_path):
    entries = {"b.txt": b"b" * 50, "a.bin": b"a" * 50, "lib/arm64-v8a/x.so": b"\x7fELF" * 100, "META-INF/CERT.RSA": b"s", "res/z.xml": b"z" * 80}
    methods = {"a.bin": zipfile.ZIP_STORED, "lib/arm64-v8a/x.so": zipfile.ZIP_STORED}
    dates = {"b.txt": (2019, 2, 3, 4, 5, 6), "a.bin": (2022, 12, 31, 23, 59, 58)}
    strip(apk(entries, methods, dates), dfd)
    with result_zip(tmp_path) as zf:
        got = [(i.filename, i.compress_type, i.date_time) for i in zf.infolist()]
    want = [(n, methods.get(n, zipfile.ZIP_DEFLATED), dates.get(n, (2021, 5, 6, 7, 8, 10))) for n in entries if n != "META-INF/CERT.RSA"]
    assert got == want


def test_strip_tidak_meneruskan_external_attr_symlink(dfd, tmp_path):
    strip(apk({"AndroidManifest.xml": b"m", "link": b"/etc/passwd", "d/": b""}), dfd)
    with result_zip(tmp_path) as zf:
        modes = {i.filename: i.external_attr >> 16 for i in zf.infolist()}
    assert modes["link"] == 0o100644 and modes["AndroidManifest.xml"] == 0o100644
    assert modes["d/"] == 0o040755


def test_strip_hasil_dapat_dibaca_dan_crc_sama(dfd, tmp_path):
    entries = {"AndroidManifest.xml": b"manifest" * 10, "classes.dex": os.urandom(5000), "resources.arsc": b"r" * 300}
    src = apk(entries, {"resources.arsc": zipfile.ZIP_STORED})
    sha, size = strip(src, dfd)
    out = (tmp_path / "split-001.apk").read_bytes()
    assert (hashlib.sha256(out).hexdigest(), len(out)) == (sha, size)
    with zf_of(src) as a, result_zip(tmp_path) as b:
        assert b.testzip() is None
        assert [(i.filename, i.CRC, i.file_size) for i in a.infolist()] == [(i.filename, i.CRC, i.file_size) for i in b.infolist()]
        assert all(a.read(n) == b.read(n) for n in entries)


@pytest.mark.parametrize("method", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_strip_tolak_kompresi_bzip2_lzma(method, dfd, tmp_path):
    with pytest.raises(BundleError) as ei:
        strip(apk({"AndroidManifest.xml": b"m", "x.bin": b"x" * 100}, {"x.bin": method}), dfd)
    assert ei.value.code == "split_invalid"
    assert not list(tmp_path.iterdir())


def test_strip_tolak_terenkripsi(dfd, tmp_path):
    data = bytearray(apk({"AndroidManifest.xml": b"m"}))
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):                                   # set flag bit 0 di header lokal dan central
        pos = data.find(sig)
        off = 6 if sig == b"PK\x03\x04" else 8
        data[pos + off] |= 0x1
    with pytest.raises(BundleError) as ei:
        strip(bytes(data), dfd)
    assert ei.value.code == "split_invalid"
    assert not list(tmp_path.iterdir())


def test_strip_tolak_nama_ganda(dfd, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"1")
        with pytest.warns(UserWarning):
            zf.writestr("a.txt", b"2")
    with pytest.raises(BundleError) as ei:
        strip(buf.getvalue(), dfd)
    assert ei.value.code == "split_invalid"


def test_strip_nama_ganda_setelah_lipat_huruf(dfd, tmp_path):
    with pytest.raises(BundleError) as ei:
        strip(apk({"META-INF/A.RSA": b"1", "meta-inf/a.rsa": b"2", "AndroidManifest.xml": b"m"}), dfd)
    assert ei.value.code == "split_invalid"
    assert not list(tmp_path.iterdir())


def test_strip_tolak_entri_melebihi_batas(dfd, tmp_path, monkeypatch):
    monkeypatch.setattr(S, "ZIP_MAX_ENTRIES", 3)
    with pytest.raises(BundleError) as ei:
        strip(apk({f"f{i}": b"x" for i in range(4)}), dfd)
    assert ei.value.code == "bundle_too_large"
    strip(apk({f"f{i}": b"x" for i in range(3)}), dfd)                          # tepat di batas diterima


def test_strip_tolak_entri_terlalu_besar_per_entri(dfd, tmp_path):
    with pytest.raises(BundleError) as ei:
        strip(apk({"big.bin": b"0" * 4096}), dfd, budget=S.ZipBudget(max_entry=1000))
    assert ei.value.code == "bundle_too_large"


def test_strip_tolak_rasio_bomb_deklarasi_bohong(dfd, tmp_path):
    # Header berbohong: file_size dideklarasikan jauh lebih kecil dari isi sebenarnya -> zipfile memotong, CRC tidak cocok -> split_invalid.
    real = b"A" * (3 * MIB)
    data = bytearray(apk({"AndroidManifest.xml": b"m", "bomb.bin": real}))
    pos = data.rfind(b"PK\x01\x02")
    while pos >= 0 and data[pos + 46:pos + 46 + 8] != b"bomb.bin":
        pos = data.rfind(b"PK\x01\x02", 0, pos)
    assert pos >= 0
    data[pos + 24:pos + 28] = struct.pack("<I", 10)                             # file_size palsu di central directory
    with pytest.raises(BundleError) as ei:
        strip(bytes(data), dfd)
    assert ei.value.code == "split_invalid"
    assert not list(tmp_path.iterdir())


def test_strip_tolak_rasio_kompresi_deklarasi_besar(dfd, tmp_path, monkeypatch):
    monkeypatch.setattr(S, "BOMB_ENTRY_MIN", 1000)
    with pytest.raises(BundleError) as ei:
        strip(apk({"AndroidManifest.xml": b"m", "z.bin": b"\0" * 50_000}), dfd, budget=S.ZipBudget(max_ratio=10))
    assert ei.value.code == "bundle_too_large"


def test_strip_anggaran_total_antar_split(dfd, tmp_path):
    budget = S.ZipBudget(total=2500)
    strip(apk({"a.bin": os.urandom(1000), "AndroidManifest.xml": b"m"}), dfd, "split-001.apk", budget)
    strip(apk({"a.bin": os.urandom(1000)}), dfd, "split-002.apk", budget)
    with pytest.raises(BundleError) as ei:
        strip(apk({"a.bin": os.urandom(1000)}), dfd, "split-003.apk", budget)
    assert ei.value.code == "bundle_too_large"
    assert not (tmp_path / "split-003.apk").exists()


def test_strip_tujuan_ditanam_symlink_eexist(dfd, tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(b"jangan disentuh")
    os.symlink(victim, tmp_path / "split-001.apk.part")
    with pytest.raises(FileExistsError):
        strip(apk({"AndroidManifest.xml": b"m"}), dfd)
    assert victim.read_bytes() == b"jangan disentuh"


def test_strip_tujuan_symlink_digantikan_bukan_diikuti(dfd, tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(b"jangan disentuh")
    os.symlink(victim, tmp_path / "split-001.apk")                              # nama akhir berupa symlink: rename menggantikannya, tidak menulis lewatnya
    strip(apk({"AndroidManifest.xml": b"m"}), dfd)
    assert victim.read_bytes() == b"jangan disentuh"
    assert not (tmp_path / "split-001.apk").is_symlink() and zipfile.is_zipfile(tmp_path / "split-001.apk")


def test_strip_zipinfo_sumber_tidak_dipakai_ulang(dfd, tmp_path):
    # Regresi "Bad magic number": memakai ulang ZipInfo sumber (header_offset lama) merusak berkas hasil.
    entries = {f"f{i}.bin": os.urandom(300) for i in range(6)}
    entries["META-INF/CERT.RSA"] = b"x" * 700
    strip(apk(entries), dfd)
    with result_zip(tmp_path) as zf:
        assert zf.testzip() is None and len(zf.namelist()) == 6


def test_strip_bukan_zip_atau_rusak(dfd, tmp_path):
    with pytest.raises(zipfile.BadZipFile):
        zf_of(b"bukan zip")                                                     # pembukaan ZipFile adalah tanggung jawab pemanggil
    data = bytearray(apk({"a.bin": os.urandom(2000)}))
    data[40] ^= 0xFF                                                            # rusak di isi -> CRC tak cocok
    with pytest.raises(BundleError) as ei:
        strip(bytes(data), dfd)
    assert ei.value.code == "split_invalid"
    assert not list(tmp_path.iterdir())


def test_strip_part_dihapus_saat_galat(dfd, tmp_path):
    with pytest.raises(BundleError):
        strip(apk({"a.bin": b"x" * 100}, {"a.bin": zipfile.ZIP_LZMA}), dfd)
    assert not list(tmp_path.iterdir())


def test_strip_on_tick_dipanggil_dan_dapat_membatalkan(dfd, tmp_path):
    ticks = []

    def tick():
        ticks.append(1)
        if len(ticks) >= 2:
            raise KeyboardInterrupt

    with zf_of(apk({"a.bin": os.urandom(3 * MIB + 5)}, {"a.bin": zipfile.ZIP_STORED})) as zf:
        with pytest.raises(KeyboardInterrupt):
            S.strip_signatures(zf, dfd, "split-001.apk", S.ZipBudget(), tick)
    assert ticks and not list(tmp_path.iterdir())


# ---------------------------------------------------------------------------------------------- content_digest
def test_content_digest_sama_meski_meta_inf_beda():
    a = apk({"AndroidManifest.xml": b"m", "classes.dex": b"d", "META-INF/A.RSA": b"1", "META-INF/MANIFEST.MF": b"x"})
    b = apk({"AndroidManifest.xml": b"m", "classes.dex": b"d", "META-INF/B.SF": b"2"})
    with zf_of(a) as za, zf_of(b) as zb:
        assert S.content_digest(za) == S.content_digest(zb)


def test_content_digest_beda_satu_byte_bukan_alias():
    with zf_of(apk({"a": b"1234"})) as za, zf_of(apk({"a": b"1235"})) as zb:
        assert S.content_digest(za) != S.content_digest(zb)


def test_content_digest_crc32_tabrakan_bukan_alias():
    # Isi beda tetapi CRC32 dipalsukan sama di header: digest berbasis isi, jadi tidak pernah dianggap alias (CRC palsu -> galat atau beda).
    x = apk({"a": b"isi-pertama"}, {"a": zipfile.ZIP_STORED})
    y = bytearray(apk({"a": b"isi-kedua!!"}, {"a": zipfile.ZIP_STORED}))
    crc_x, crc_y = zlib.crc32(b"isi-pertama"), zlib.crc32(b"isi-kedua!!")
    for sig, off in ((b"PK\x03\x04", 14), (b"PK\x01\x02", 16)):
        pos = y.find(sig)
        assert struct.unpack("<I", y[pos + off:pos + off + 4])[0] == crc_y
        y[pos + off:pos + off + 4] = struct.pack("<I", crc_x)
    with zf_of(x) as za, zf_of(bytes(y)) as zb:
        want = S.content_digest(za)
        try:
            got = S.content_digest(zb)
        except BundleError as exc:
            assert exc.code == "split_invalid"
        else:
            assert got != want


def test_content_digest_urutan_dan_tanpa_entri_ttd():
    with zf_of(apk({"a": b"1", "b": b"2"})) as za, zf_of(apk({"b": b"2", "a": b"1", "META-INF/X.EC": b"z"})) as zb:
        assert S.content_digest(za) == S.content_digest(zb)
    with zf_of(apk({"a": b"1"})) as za, zf_of(apk({"b": b"1"})) as zb:          # nama ikut dihitung
        assert S.content_digest(za) != S.content_digest(zb)


def test_content_digest_nama_ganda_dan_bomb_ditolak():
    with zf_of(apk({"a": b"1", "A": b"2"})) as z:
        with pytest.raises(BundleError) as ei:
            S.content_digest(z)
    assert ei.value.code == "split_invalid"
    with zf_of(apk({"a": os.urandom(5000)})) as z:
        with pytest.raises(BundleError) as ei:
            S.content_digest(z, S.ZipBudget(max_entry=100))
    assert ei.value.code == "bundle_too_large"


# ---------------------------------------------------------------------------------------------- extract_member_at
def outer(members: dict[str, bytes], **kw) -> zipfile.ZipFile:
    return zf_of(apk(members, **kw))


def test_extract_member_at_menulis_lewat_dirfd_dan_hash_dari_fd_sama(dfd, tmp_path):
    inner = apk({"AndroidManifest.xml": b"m"})
    with outer({"splits/a.apk": inner, "x": b"y"}) as zf:
        sha, size = S.extract_member_at(zf, "splits/a.apk", dfd, ".split-001.raw", 10 * MIB)
    assert (tmp_path / ".split-001.raw").read_bytes() == inner
    assert (sha, size) == (hashlib.sha256(inner).hexdigest(), len(inner))
    assert not (tmp_path / ".split-001.raw.part").exists()
    assert stat.S_IMODE((tmp_path / ".split-001.raw").stat().st_mode) == 0o600


def test_extract_member_at_batas_byte_nyata(dfd, tmp_path):
    inner = apk({"a": os.urandom(4000)}, {"a": zipfile.ZIP_STORED})
    with outer({"a.apk": inner}) as zf:
        with pytest.raises(BundleError) as ei:
            S.extract_member_at(zf, "a.apk", dfd, "o.raw", len(inner) - 1)
        assert ei.value.code == "bundle_too_large"
        S.extract_member_at(zf, "a.apk", dfd, "o.raw", len(inner))               # tepat di batas
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".part")]


def test_extract_member_at_batas_dihitung_dari_byte_nyata_bukan_deklarasi(dfd, tmp_path, monkeypatch):
    inner = apk({"a": b"x" * 100})
    with outer({"a.apk": inner}) as zf:
        info = zf.getinfo("a.apk")
        real_len = info.file_size
        monkeypatch.setattr(info, "file_size", 5)                                # deklarasi menyesatkan lolos pra-cek ...
        with pytest.raises((BundleError, zipfile.BadZipFile)):
            S.extract_member_at(zf, "a.apk", dfd, "o.raw", 10)
        assert real_len > 10
    assert not list(tmp_path.iterdir())


def test_extract_member_at_o_excl_nofollow_lewat_dirfd(dfd, tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(b"asli")
    os.symlink(victim, tmp_path / "o.raw.part")
    with outer({"a.apk": apk({"a": b"1"})}) as zf:
        with pytest.raises(FileExistsError):
            S.extract_member_at(zf, "a.apk", dfd, "o.raw", MIB)
    assert victim.read_bytes() == b"asli"


def test_extract_member_at_bukan_zip_ditolak(dfd, tmp_path):
    with outer({"a.apk": b"ini bukan zip"}) as zf:
        with pytest.raises(BundleError) as ei:
            S.extract_member_at(zf, "a.apk", dfd, "o.raw", MIB)
    assert ei.value.code == "split_invalid"
    assert not list(tmp_path.iterdir())


def test_extract_member_at_hilang_ganda_terenkripsi_dan_kompresi_tak_umum(dfd, tmp_path):
    with outer({"a.apk": apk({"a": b"1"})}) as zf:
        with pytest.raises(BundleError) as ei:
            S.extract_member_at(zf, "tidak-ada.apk", dfd, "o.raw", MIB)
        assert ei.value.code == "bundle_invalid"
    with outer({"a.apk": apk({"a": b"1"})}, methods={"a.apk": zipfile.ZIP_LZMA}) as zf:
        with pytest.raises(BundleError) as ei:
            S.extract_member_at(zf, "a.apk", dfd, "o.raw", MIB)
        assert ei.value.code == "split_invalid"
    assert not list(tmp_path.iterdir())


def test_extract_member_at_part_dihapus_saat_galat(dfd, tmp_path):
    inner = apk({"a": os.urandom(2000)}, {"a": zipfile.ZIP_STORED})
    data = bytearray(apk({"a.apk": inner}, {"a.apk": zipfile.ZIP_STORED}))
    data[60 + 100] ^= 0xFF                                                      # rusak di tengah isi -> CRC luar tidak cocok
    with zf_of(bytes(data)) as zf:
        with pytest.raises((BundleError, zipfile.BadZipFile)):
            S.extract_member_at(zf, "a.apk", dfd, "o.raw", MIB)
    assert not list(tmp_path.iterdir())


def test_extract_member_at_anggaran_total(dfd, tmp_path):
    inner = apk({"a": os.urandom(2000)}, {"a": zipfile.ZIP_STORED})
    with outer({"a.apk": inner}) as zf:
        with pytest.raises(BundleError) as ei:
            S.extract_member_at(zf, "a.apk", dfd, "o.raw", MIB, budget=S.ZipBudget(total=len(inner) - 1))
    assert ei.value.code == "bundle_too_large"
    assert not list(tmp_path.iterdir())


def test_modul_splitzip_hanya_lewat_dir_fd_tanpa_shell():
    import ast
    src = (Path(__file__).resolve().parent.parent / "services/rvcore/splitzip.py").read_text()
    tree = ast.parse(src)
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        f = call.func
        name = getattr(f, "attr", getattr(f, "id", ""))
        assert name not in {"system", "popen", "Popen", "run", "extractall", "extract"}
        if name in {"open", "rename", "unlink"} and getattr(getattr(f, "value", None), "id", "") == "os":
            assert any(k.arg in {"dir_fd", "src_dir_fd"} for k in call.keywords), ast.dump(call)[:120]
