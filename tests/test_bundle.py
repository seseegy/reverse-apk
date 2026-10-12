"""Paket multi-APK (XAPK/APKS), PRD 09 PR A. Tiga lapis diuji TERPISAH supaya mutasi pada satu lapis tidak tertutup lapis lain:
  1. rvcore.bundle   : mengenali paket dan memilih base (dipakai web DAN runner)
  2. rvcore.bundle   : mengekstrak base dengan aman (hanya runner yang melakukannya)
  3. web             : validate_apk, rute /api/uploads, halaman

Susunan berkas sintetis di sini meniru berkas NYATA yang diukur: XAPK v2 (manifest.json + split_apks[id=base] + split config.*),
APKS bundletool mode universal (universal.apk + toc.pb) dan mode default (splits/base-master.apk, base-master_2.apk, puluhan split).
Verifikasi pada berkas asli (XAPK YouSee Musik, APKS NexLoad) dilakukan manual dan dicatat di docs/prd/09.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import struct
import warnings
import zipfile
from contextlib import closing
from pathlib import Path

import pytest

from app import apkcheck, context, routes_apk
from app.apkcheck import ApkRejected, Limits, validate_apk
from rvcore import bundle as B
from rvcore.bundle import BundleError, plan_bundle, prepared_apk

from conftest import BROWSER

LIMITS = Limits(max_entries=100_000, max_total_uncompressed=3 << 30, max_entry_uncompressed=512 << 20, max_ratio=100)


# ---------------------------------------------------------------------------------------------- pembangun berkas
def zip_bytes(entries: dict[str, bytes], deflate: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED if deflate else zipfile.ZIP_STORED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def apk_bytes(tag: str = "x") -> bytes:
    """APK minimal yang lolos validate_apk (manifest + dex di akar). `tag` membuat isinya unik (sha256 berbeda)."""
    return zip_bytes({"AndroidManifest.xml": b"<manifest/>" + tag.encode(), "classes.dex": b"dex\n035\x00" + tag.encode(), "res/a.xml": b"<a/>"})


def xapk_manifest(base: str = "com.example.app.apk", splits: tuple[str, ...] = ("config.arm64_v8a.apk", "config.en.apk")) -> dict:
    """Bentuk manifest.json XAPK v2 nyata (bidang yang tidak dipakai kode ikut disertakan agar tidak ada asumsi tersembunyi)."""
    return {"xapk_version": 2, "package_name": "com.example.app", "name": "Contoh", "version_code": "1", "version_name": "1.0", "min_sdk_version": "26",
            "target_sdk_version": "36", "permissions": ["android.permission.INTERNET"], "split_configs": ["config.arm64_v8a", "config.en"],
            "total_size": 1, "icon": "icon.png",
            "split_apks": [{"file": base, "id": "base"}] + [{"file": s, "id": s[:-4]} for s in splits]}


def xapk(tag: str = "x", manifest: dict | None = None, base: str = "com.example.app.apk", splits: tuple[str, ...] = ("config.arm64_v8a.apk", "config.en.apk")) -> bytes:
    m = manifest if manifest is not None else xapk_manifest(base, splits)
    entries = {base: apk_bytes(tag), "manifest.json": json.dumps(m).encode(), "icon.png": b"\x89PNG"}
    entries.update({s: apk_bytes(tag + s) for s in splits})
    return zip_bytes(entries)


def apks_default(tag: str = "x") -> bytes:
    return zip_bytes({"toc.pb": b"\x0a\x00", "splits/base-master.apk": apk_bytes(tag), "splits/base-master_2.apk": apk_bytes(tag), "splits/base-en.apk": apk_bytes(tag + "en"),
                      "splits/base-arm64_v8a.apk": apk_bytes(tag + "abi")})


def apks_universal(tag: str = "x") -> bytes:
    return zip_bytes({"toc.pb": b"\x0a\x00", "universal.apk": apk_bytes(tag)})


def patch_central(data: bytes, name: str, offset: int, fmt: str, fn) -> bytes:
    """Ubah satu bidang di central directory entri `name` (offset dari awal header 'PK\\x01\\x02')."""
    buf = bytearray(data)
    pos = 0
    while True:
        pos = buf.find(b"PK\x01\x02", pos)
        if pos < 0:
            raise AssertionError(f"entri {name} tidak ditemukan")
        n, m, k = struct.unpack_from("<HHH", buf, pos + 28)
        if bytes(buf[pos + 46:pos + 46 + n]).decode() == name:
            (old,) = struct.unpack_from(fmt, buf, pos + offset)
            struct.pack_into(fmt, buf, pos + offset, fn(old))
            return bytes(buf)
        pos += 46 + n + m + k


def write(tmp: Path, name: str, data: bytes) -> Path:
    p = tmp / name
    p.write_bytes(data)
    return p


def plan_of(data: bytes):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return plan_bundle(zf)


def rejected(data: bytes) -> BundleError:
    with pytest.raises(BundleError) as ei:
        plan_of(data)
    return ei.value


# ================================================================================ lapis 1: memilih base
def test_xapk_base_comes_from_manifest_id_not_from_position():
    base = "zz.last.apk"                                   # urutan abjad terakhir: bukan "yang pertama"
    p = plan_of(xapk(base=base, splits=("a.apk", "b.apk")))
    assert (p.format, p.base) == ("xapk", base) and set(p.apks) == {base, "a.apk", "b.apk"}


def test_xapk_options_record_format_base_and_splits():
    o = plan_of(xapk()).to_options()
    assert o["format"] == "xapk" and o["base"] == "com.example.app.apk" and o["apk_count"] == 3
    assert o["splits"] == ["config.arm64_v8a.apk", "config.en.apk"] and o["splits_more"] == 0 and o["alternates"] == 0


def test_options_cap_listed_splits_and_clean_names():
    many = tuple(f"s{i}.apk" for i in range(60))
    o = plan_of(xapk(splits=many)).to_options()
    assert len(o["splits"]) == B.MAX_LISTED and o["splits_more"] == 60 - B.MAX_LISTED and o["apk_count"] == 61
    assert B._clean("a\nb\x1b[0m" + "x" * 500) == "a?b?[0m" + "x" * (120 - 7)


def test_xapk_without_base_marker_falls_back_to_package_name_apk():
    m = xapk_manifest(); m["split_apks"] = [{"file": "config.en.apk", "id": "config.en"}]
    assert plan_of(xapk(manifest=m)).base == "com.example.app.apk"


def test_xapk_without_marker_or_package_apk_uses_the_only_root_apk():
    m = {"split_apks": []}
    assert plan_of(zip_bytes({"manifest.json": json.dumps(m).encode(), "solo.apk": apk_bytes()})).base == "solo.apk"


def test_xapk_ambiguous_base_is_refused_not_guessed():
    m = {"package_name": "tidak.ada", "split_apks": []}
    e = rejected(zip_bytes({"manifest.json": json.dumps(m).encode(), "a.apk": apk_bytes("a"), "b.apk": apk_bytes("b")}))
    assert e.code == "bundle_no_base"


def test_xapk_two_base_markers_is_refused():
    m = xapk_manifest(); m["split_apks"].append({"file": "config.en.apk", "id": "base"})
    assert rejected(xapk(manifest=m)).code == "bundle_no_base"


@pytest.mark.parametrize("evil", ["../../etc/passwd.apk", "/abs/base.apk", "tidak-ada.apk", "com.example.app.apk/", "..\\x.apk", "x\x00.apk"])
def test_xapk_manifest_names_must_equal_a_real_entry(evil):
    """Nama dari manifest.json hanya dibandingkan dengan entri yang ADA; tidak pernah menjadi path."""
    m = xapk_manifest(); m["split_apks"][0]["file"] = evil
    m["package_name"] = "tidak.ada"
    e = rejected(zip_bytes({"manifest.json": json.dumps(m).encode(), "a.apk": apk_bytes("a"), "b.apk": apk_bytes("b")}))
    assert e.code == "bundle_no_base"


def test_xapk_manifest_that_names_a_non_apk_entry_is_refused():
    m = xapk_manifest(); m["split_apks"][0]["file"] = "icon.png"
    assert rejected(xapk(manifest=m)).code == "bundle_no_base"


@pytest.mark.parametrize("raw,code", [(b"bukan json", "bad_bundle"), (b"[1,2]", "bad_bundle"), (b'"teks"', "bad_bundle"), (b"\xff\xfe\x00", "bad_bundle")])
def test_xapk_bad_manifest_json_is_refused(raw, code):
    assert rejected(zip_bytes({"manifest.json": raw, "a.apk": apk_bytes()})).code == code


def test_xapk_manifest_with_utf8_bom_is_read():
    raw = b"\xef\xbb\xbf" + json.dumps(xapk_manifest()).encode()
    base = "com.example.app.apk"
    assert plan_of(zip_bytes({"manifest.json": raw, base: apk_bytes(), "config.en.apk": apk_bytes("e"), "config.arm64_v8a.apk": apk_bytes("a")})).base == base


def test_xapk_oversized_manifest_is_refused_without_reading_it():
    big = b"{" + b" " * (B.MAX_MANIFEST_BYTES + 10) + b"}"
    assert rejected(zip_bytes({"manifest.json": big, "a.apk": apk_bytes()}, deflate=True)).code == "bad_bundle"


def test_xapk_oversized_manifest_is_never_even_opened(monkeypatch):
    """Batas ukuran terdeklarasi harus menolak SEBELUM membaca; batas saat membaca hanya lapis cadangan (zipfile tidak pernah mengembalikan lebih
    dari ukuran terdeklarasi, jadi lapis kedua tidak bisa diuji sendiri)."""
    big = b"{" + b" " * (B.MAX_MANIFEST_BYTES + 10) + b"}"
    data = zip_bytes({"manifest.json": big, "a.apk": apk_bytes()}, deflate=True)      # dibangun SEBELUM patch: writestr juga memanggil ZipFile.open
    opened = []
    real = zipfile.ZipFile.open
    monkeypatch.setattr(zipfile.ZipFile, "open", lambda self, name, *a, **k: (opened.append(getattr(name, "filename", name)), real(self, name, *a, **k))[1])
    assert rejected(data).code == "bad_bundle"
    assert opened == []


def test_apks_universal_is_the_base():
    p = plan_of(apks_universal())
    assert (p.format, p.base, p.alternates) == ("apks", "universal.apk", 0)


def test_apks_default_picks_lowest_numbered_master_and_counts_alternates():
    p = plan_of(apks_default())
    assert (p.format, p.base, p.alternates) == ("apks", "splits/base-master.apk", 1) and p.to_options()["alternates"] == 1


def test_apks_master_order_is_numeric_not_alphabetic():
    d = zip_bytes({"toc.pb": b"x", "splits/base-master_10.apk": apk_bytes("a"), "splits/base-master_2.apk": apk_bytes("b")})
    assert plan_of(d).base == "splits/base-master_2.apk"


def test_apks_only_master_2_still_works():
    assert plan_of(zip_bytes({"toc.pb": b"x", "splits/base-master_2.apk": apk_bytes()})).base == "splits/base-master_2.apk"


def test_apks_single_standalone_is_the_base_but_two_are_refused():
    one = zip_bytes({"toc.pb": b"x", "standalones/standalone-arm64.apk": apk_bytes()})
    assert plan_of(one).base == "standalones/standalone-arm64.apk"
    two = zip_bytes({"toc.pb": b"x", "standalones/a.apk": apk_bytes("a"), "standalones/b.apk": apk_bytes("b")})
    assert rejected(two).code == "bundle_no_base"


def test_apks_without_any_base_candidate_is_refused():
    assert rejected(zip_bytes({"toc.pb": b"x", "splits/base-en.apk": apk_bytes()})).code == "bundle_no_base"


def test_apkm_is_refused_with_an_honest_message():
    e = rejected(zip_bytes({"info.json": b"{}", "base.apk": apk_bytes()}))
    assert e.code == "unsupported_bundle" and "APKM" in e.message and "belum" in e.message


def test_unknown_multi_apk_layout_is_refused():
    assert rejected(zip_bytes({"x.apk": apk_bytes("1"), "y.apk": apk_bytes("2")})).code == "unsupported_bundle"


def test_zip_without_manifest_or_apk_keeps_the_original_error():
    e = rejected(zip_bytes({"readme.txt": b"hi"}))
    assert e.code == "no_manifest" and "AndroidManifest.xml" in e.message


def test_duplicate_entry_names_are_refused_in_the_planner_itself():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        d = zip_bytes({"toc.pb": b"x", "universal.apk": apk_bytes("1")})
        buf = io.BytesIO(d)
        with zipfile.ZipFile(buf, "a") as zf:
            zf.writestr("universal.apk", apk_bytes("2"))
    assert rejected(buf.getvalue()).code == "duplicate_entry"


def test_encrypted_base_is_refused():
    d = patch_central(apks_universal(), "universal.apk", 8, "<H", lambda v: v | 1)
    assert rejected(d).code == "bad_bundle"


def test_picking_is_by_content_names_not_extension_case():
    d = zip_bytes({"toc.pb": b"x", "UNIVERSAL.APK": apk_bytes()})
    assert rejected(d).code == "bundle_no_base"            # nama huruf besar bukan 'universal.apk': tidak ditebak


# ================================================================================ lapis 2: mengekstrak base
def test_plain_apk_is_used_as_is_and_nothing_is_created(tmp_path):
    src = write(tmp_path, "a.apk", apk_bytes())
    work = tmp_path / "w"; work.mkdir()
    with prepared_apk(src, work, 1 << 30) as real:
        assert real == src and list(work.iterdir()) == []
    assert list(work.iterdir()) == []


@pytest.mark.parametrize("make,base", [(xapk, "com.example.app.apk"), (apks_universal, "universal.apk"), (apks_default, "splits/base-master.apk")],
                         ids=["xapk", "apks-universal", "apks-default"])
def test_bundle_yields_the_exact_base_bytes_and_cleans_up(tmp_path, make, base):
    data = make("isi")
    src = write(tmp_path, "p.apk", data)
    work = tmp_path / "w"; work.mkdir()
    expected = zipfile.ZipFile(io.BytesIO(data)).read(base)
    with prepared_apk(src, work, 1 << 30) as real:
        assert real == work / "base.apk" and real.read_bytes() == expected
        assert oct(real.stat().st_mode & 0o777) == "0o600"
        assert zipfile.ZipFile(real).testzip() is None
    assert list(work.iterdir()) == []


def test_bundle_base_is_removed_even_when_the_tool_step_raises(tmp_path):
    src = write(tmp_path, "p.apk", xapk())
    work = tmp_path / "w"; work.mkdir()
    with pytest.raises(RuntimeError):
        with prepared_apk(src, work, 1 << 30):
            raise RuntimeError("tool gagal")
    assert list(work.iterdir()) == []


def test_extraction_refuses_a_base_over_the_byte_cap_and_leaves_nothing(tmp_path):
    src = write(tmp_path, "p.apk", xapk())
    work = tmp_path / "w"; work.mkdir()
    with pytest.raises(BundleError) as ei:
        with prepared_apk(src, work, 10):
            pass
    assert ei.value.code == "base_too_large" and list(work.iterdir()) == []


def test_extraction_cap_counts_bytes_actually_written_not_the_declared_size(tmp_path, monkeypatch):
    """Header yang berbohong 'kecil' tidak boleh melewati batas: yang dihitung adalah byte yang sungguh ditulis."""
    src = write(tmp_path, "p.apk", xapk())
    work = tmp_path / "w"; work.mkdir()
    real_open = zipfile.ZipFile.infolist

    def liar(self):
        infos = real_open(self)
        for i in infos:
            if i.filename == "com.example.app.apk":
                i.file_size = 1                                  # klaim 1 byte; isi sebenarnya jauh lebih besar dari batas
        return infos

    monkeypatch.setattr(zipfile.ZipFile, "infolist", liar)
    with pytest.raises(BundleError) as ei:
        B.extract_member(src, "com.example.app.apk", work / "base.apk", max_bytes=20)
    assert ei.value.code in ("base_too_large", "bad_bundle") and list(work.iterdir()) == []


def test_lying_uncompressed_size_in_the_archive_fails_the_crc_check(tmp_path):
    d = patch_central(apks_universal(), "universal.apk", 24, "<I", lambda v: v - 5)
    src = write(tmp_path, "p.apk", d)
    work = tmp_path / "w"; work.mkdir()
    with pytest.raises(BundleError) as ei:
        with prepared_apk(src, work, 1 << 30):
            pass
    assert ei.value.code == "bad_bundle" and list(work.iterdir()) == []


def test_base_that_is_not_a_zip_is_refused(tmp_path):
    d = zip_bytes({"toc.pb": b"x", "universal.apk": b"ini bukan zip sama sekali"})
    src = write(tmp_path, "p.apk", d)
    work = tmp_path / "w"; work.mkdir()
    with pytest.raises(BundleError) as ei:
        with prepared_apk(src, work, 1 << 30):
            pass
    assert ei.value.code == "bad_bundle" and list(work.iterdir()) == []


def test_missing_or_duplicate_member_is_refused_at_extraction_time_too(tmp_path):
    """Runner memutuskan ulang dari isi berkas; ia tidak percaya pada nama yang dikirim siapa pun."""
    src = write(tmp_path, "p.apk", apks_universal())
    work = tmp_path / "w"; work.mkdir()
    with pytest.raises(BundleError) as ei:
        B.extract_member(src, "tidak-ada.apk", work / "base.apk", 1 << 30)
    assert ei.value.code == "bundle_no_base"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        buf = io.BytesIO(apks_universal())
        with zipfile.ZipFile(buf, "a") as zf:
            zf.writestr("universal.apk", apk_bytes("dua"))
    dup = write(tmp_path, "d.apk", buf.getvalue())
    with pytest.raises(BundleError):
        B.extract_member(dup, "universal.apk", work / "base.apk", 1 << 30)
    assert list(work.iterdir()) == []


def test_extraction_never_writes_through_a_symlink_at_the_destination(tmp_path):
    victim = tmp_path / "korban.txt"; victim.write_text("JANGAN DIUBAH")
    work = tmp_path / "w"; work.mkdir()
    os.symlink(victim, work / "base.apk")
    os.symlink(victim, work / "base.apk.part")
    src = write(tmp_path, "p.apk", apks_universal())
    with prepared_apk(src, work, 1 << 30) as real:
        assert real.read_bytes()[:2] == b"PK" and not real.is_symlink()
    assert victim.read_text() == "JANGAN DIUBAH" and list(work.iterdir()) == []


def test_extraction_survives_a_symlink_planted_between_cleanup_and_open(tmp_path, monkeypatch):
    """O_EXCL + O_NOFOLLOW adalah lapis TERAKHIR: `unlink` sudah membuang sisa lama, tetapi pihak lain bisa menanam symlink sesudahnya (balapan).
    Disimulasikan dengan menanam tautan tepat sebelum os.open; ekstraksi harus gagal, bukan menulis lewat tautan itu."""
    victim = tmp_path / "korban.txt"; victim.write_text("JANGAN DIUBAH")
    work = tmp_path / "w"; work.mkdir()
    src = write(tmp_path, "p.apk", apks_universal())
    real_open = os.open

    def planting_open(path, flags, *a, **k):
        if str(path).endswith("base.apk.part") and not os.path.lexists(path):
            os.symlink(victim, path)
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(B.os, "open", planting_open)
    with pytest.raises(BundleError) as ei:
        B.extract_member(src, "universal.apk", work / "base.apk", 1 << 30)
    assert ei.value.code == "bad_bundle" and victim.read_text() == "JANGAN DIUBAH"


def test_extraction_refuses_an_encrypted_member_even_if_the_planner_was_bypassed(tmp_path):
    src = write(tmp_path, "p.apk", patch_central(apks_universal(), "universal.apk", 8, "<H", lambda v: v | 1))
    work = tmp_path / "w"; work.mkdir()
    with pytest.raises(BundleError) as ei:
        B.extract_member(src, "universal.apk", work / "base.apk", 1 << 30)
    assert ei.value.code == "bad_bundle" and list(work.iterdir()) == []


def test_extraction_reports_progress_and_never_exceeds_the_cap(tmp_path):
    src = write(tmp_path, "p.apk", apks_universal())
    work = tmp_path / "w"; work.mkdir()
    calls = []
    n = B.extract_member(src, "universal.apk", work / "base.apk", 1 << 30, progress=lambda: calls.append(1))
    assert n == (work / "base.apk").stat().st_size and calls


def test_prepared_apk_on_a_broken_archive_is_a_bundle_error(tmp_path):
    src = write(tmp_path, "rusak.apk", b"PK\x03\x04 rusak")
    with pytest.raises(BundleError) as ei:
        with prepared_apk(src, tmp_path, 1 << 30):
            pass
    assert ei.value.code == "bad_zip"


# ================================================================================ lapis 3: web
def test_validate_accepts_xapk_and_apks_and_reports_the_plan(tmp_path):
    for make, fmt in ((xapk, "xapk"), (apks_universal, "apks"), (apks_default, "apks")):
        info = validate_apk(write(tmp_path, f"{fmt}.bin", make()), LIMITS)
        assert info.bundle is not None and info.bundle.format == fmt and info.dex_files == 0


def test_validate_plain_apk_is_unchanged(tmp_path):
    info = validate_apk(write(tmp_path, "a.apk", apk_bytes()), LIMITS)
    assert info.bundle is None and info.dex_files == 1


def test_validate_still_rejects_what_it_rejected_before(tmp_path):
    cases = [(zip_bytes({"AndroidManifest.xml": b"<m/>"}), "no_dex"), (zip_bytes({"a.txt": b"x"}), "no_manifest"), (b"MZ\x90\x00 bukan zip", "not_zip"),
             (b"", "empty")]
    for i, (data, code) in enumerate(cases):
        with pytest.raises(ApkRejected) as ei:
            validate_apk(write(tmp_path, f"c{i}.apk", data), LIMITS)
        assert ei.value.code == code, (i, ei.value.code)


@pytest.mark.parametrize("data,code", [
    (zip_bytes({"info.json": b"{}", "base.apk": apk_bytes()}), "unsupported_bundle"),
    (zip_bytes({"manifest.json": b"{}", "a.apk": apk_bytes("1"), "b.apk": apk_bytes("2")}), "bundle_no_base"),
    (zip_bytes({"toc.pb": b"x", "universal.apk": b"bukan zip"}), "bad_bundle"),
], ids=["apkm", "xapk-ambigu", "base-bukan-zip"])
def test_validate_rejects_bad_bundles_with_the_planner_code(tmp_path, data, code):
    with pytest.raises(ApkRejected) as ei:
        validate_apk(write(tmp_path, "b.apk", data), LIMITS)
    assert ei.value.code == code and ei.value.message


def test_validate_checks_bundles_against_the_same_zip_limits(tmp_path):
    with pytest.raises(ApkRejected) as ei:
        validate_apk(write(tmp_path, "b.apk", apks_universal()), Limits(1, 1 << 30, 1 << 30, 100))
    assert ei.value.code == "too_many_entries"
    with pytest.raises(ApkRejected) as ei:
        validate_apk(write(tmp_path, "c.apk", apks_universal()), Limits(100, 1 << 30, 10, 100))
    assert ei.value.code == "entry_too_large"


def test_validate_does_not_decompress_anything_but_four_bytes_of_the_base(tmp_path, monkeypatch):
    """Web membaca daftar isi saja; ekstraksi hanya di runner. Jika kode ini mulai mengekstrak, tes ini gagal."""
    called = []
    monkeypatch.setattr(B, "extract_member", lambda *a, **k: called.append(1))
    monkeypatch.setattr(apkcheck.zipfile.ZipFile, "extract", lambda *a, **k: called.append(1))
    monkeypatch.setattr(apkcheck.zipfile.ZipFile, "extractall", lambda *a, **k: called.append(1))
    validate_apk(write(tmp_path, "p.apk", xapk()), LIMITS)
    assert not called


# ---------------------------------------------------------------------------------------------- HTTP
@pytest.fixture
def uploaded(monkeypatch):
    """Antrean dimatikan (Redis tak terjangkau di tes). Baris & berkas yang dibuat dibersihkan: DB uji dipakai bersama tes lain."""
    monkeypatch.setattr(routes_apk, "enqueue_analysis", lambda *a, **k: None)
    made: list[str] = []
    yield made
    for sha in made:
        with closing(context.db()) as conn:
            conn.execute("DELETE FROM apk WHERE sha256 = ?", (sha,))
            conn.commit()
        context.layout.upload_path(sha).unlink(missing_ok=True)
        # audit_log sengaja dibiarkan: tidak ada tes lain yang menghitungnya


def post(client, seeded, data: bytes, name: str, **extra):
    h = {"X-CSRF-Token": seeded.csrf, "X-Upload-Name": name, "X-Authorized": "1", "Content-Type": "application/octet-stream", **extra}
    return client.post("/api/uploads", content=data, headers=h)


def options_of(analysis_id: int) -> dict:
    with closing(context.db()) as conn:
        return json.loads(conn.execute("SELECT options FROM analysis WHERE id = ?", (analysis_id,)).fetchone()[0])


@pytest.mark.parametrize("name,make", [("paket.xapk", xapk), ("paket.apks", apks_default), ("PAKET.XAPK", xapk), ("universal.apks", apks_universal)],
                         ids=["xapk", "apks-default", "xapk-huruf-besar", "apks-universal"])
def test_upload_accepts_bundles_stores_them_and_records_the_plan(client, seeded, uploaded, name, make):
    data = make("http-" + name)
    r = post(client, seeded, data, name)
    sha = hashlib.sha256(data).hexdigest(); uploaded.append(sha)
    assert r.status_code == 201, r.text
    body = r.json()
    assert context.layout.upload_path(sha).read_bytes() == data                     # disimpan UTUH sebagai bundel; yang diekstrak nanti base-nya
    b = options_of(body["analysis_id"])["bundle"]
    assert b["format"] in ("xapk", "apks") and b["base"] and b["apk_count"] >= 1
    assert options_of(body["analysis_id"])["deobf"] is False


def test_upload_of_the_same_bundle_twice_is_a_duplicate(client, seeded, uploaded):
    data = xapk("dup"); uploaded.append(hashlib.sha256(data).hexdigest())
    assert post(client, seeded, data, "a.xapk").status_code == 201
    r = post(client, seeded, data, "a.xapk")
    assert r.status_code == 200 and r.json()["duplicate"] is True


def test_upload_plain_apk_still_works_and_has_no_bundle_option(client, seeded, uploaded):
    data = apk_bytes("biasa"); uploaded.append(hashlib.sha256(data).hexdigest())
    r = post(client, seeded, data, "biasa.apk")
    assert r.status_code == 201 and "bundle" not in options_of(r.json()["analysis_id"])


def test_a_bundle_renamed_to_dot_apk_is_still_recognised_by_content(client, seeded, uploaded):
    data = xapk("rename"); uploaded.append(hashlib.sha256(data).hexdigest())
    r = post(client, seeded, data, "bukan-apk-biasa.apk")
    assert r.status_code == 201 and options_of(r.json()["analysis_id"])["bundle"]["format"] == "xapk"


@pytest.mark.parametrize("name", ["x.txt", "x.zip", "x.apkm", "x.aab", "x.apk.exe", "x"])
def test_upload_rejects_other_extensions_with_the_new_message(client, seeded, uploaded, name):
    r = post(client, seeded, apk_bytes("ext"), name)
    assert r.status_code == 422 and r.json()["code"] == "bad_extension" and ".xapk" in r.json()["error"] and ".apks" in r.json()["error"]


def test_upload_rejects_bundles_without_a_usable_base_and_stores_nothing(client, seeded, uploaded):
    data = zip_bytes({"manifest.json": b"{}", "a.apk": apk_bytes("1"), "b.apk": apk_bytes("2")})
    r = post(client, seeded, data, "ambigu.xapk")
    assert r.status_code == 422 and r.json()["code"] == "bundle_no_base"
    assert not context.layout.upload_path(hashlib.sha256(data).hexdigest()).exists()
    assert list(context.layout.uploads_tmp.glob("*.part")) == []


def test_upload_rejects_apkm_clearly(client, seeded, uploaded):
    r = post(client, seeded, zip_bytes({"info.json": b"{}", "base.apk": apk_bytes("m")}), "x.xapk")
    assert r.status_code == 422 and r.json()["code"] == "unsupported_bundle" and "APKM" in r.json()["error"]


def test_upload_requires_login_and_csrf(anon, client, seeded, uploaded):
    data = xapk("auth")
    assert anon.post("/api/uploads", content=data, headers={"X-Upload-Name": "a.xapk", "X-Authorized": "1"}).status_code == 401
    r = client.post("/api/uploads", content=data, headers={"X-CSRF-Token": "salah", "X-Upload-Name": "a.xapk", "X-Authorized": "1"})
    assert r.status_code == 403 and not context.layout.upload_path(hashlib.sha256(data).hexdigest()).exists()


def test_analysis_page_tells_the_truth_about_what_was_analysed(client, seeded, uploaded):
    data = apks_default("halaman"); uploaded.append(hashlib.sha256(data).hexdigest())
    aid = post(client, seeded, data, "p.apks").json()["analysis_id"]
    t = client.get(f"/analyses/{aid}", headers=BROWSER).text
    assert "Hanya base yang dianalisis" in t and "splits/base-master.apk" in t and "library native" in t and "1 kandidat base lain" in t


def test_analysis_page_of_a_plain_apk_has_no_bundle_row(client, seeded):
    t = client.get(f"/analyses/{seeded.aid}", headers=BROWSER).text
    assert "Hanya base yang dianalisis" not in t


def test_upload_page_offers_the_new_formats_and_is_honest_about_limits(client):
    t = client.get("/upload", headers=BROWSER).text
    assert ".xapk,.apks" in t and "belum didukung" not in t and "hanya APK base" in t.replace("<strong>", "").replace("</strong>", "")
    js = Path(__file__).resolve().parent.parent / "services/web/app/static/js/app.js"
    assert r"/\.(apk|xapk|apks)$/i" in js.read_text(encoding="utf-8") and "belum)" not in js.read_text(encoding="utf-8")


def test_runner_uses_the_prepared_apk_for_every_stage():
    """Penjaga struktural untuk runner-daemon (skrip tanpa tes): path APK yang diberikan ke tool HARUS hasil prepared_apk, bukan upload_path.
    Jika ada yang mengembalikan `LAYOUT.upload_path` ke `build_command`, jadx/analyzer akan menerima paket mentah."""
    src = (Path(__file__).resolve().parent.parent / "services/runner/runner-daemon").read_text(encoding="utf-8")
    assert "with prepared_apk(apk, work, MAX_BASE_APK_BYTES, beat) as real_apk:" in src and "_run_tool(job_id, stage, deobf, timeout, real_apk, work, started)" in src
    body = src.split("def _run_tool(", 1)[1].split("\n\n\n", 1)[0]
    assert "upload_path" not in body and "build_command(stage, apk, out, deobf)" in body


def test_upload_dropzone_is_not_overridden_by_the_chat_drop_overlay():
    """Regresi (terukur di main): aturan zona lepas chat memakai kelas `.dropzone` yang sama dengan halaman Unggah (position:absolute; inset:0),
    sehingga dropzone Unggah menutupi seluruh halaman dan klik 'Pilih berkas' dicegat teks lain. Overlay chat sekarang `.chat-dropzone`."""
    root = Path(__file__).resolve().parent.parent / "services/web/app"
    css = (root / "static/css/app.css").read_text(encoding="utf-8")
    import re
    for m in re.finditer(r"(?m)^\.dropzone\s*\{([^}]*)\}", css):
        assert "absolute" not in m.group(1) and "inset" not in m.group(1), "`.dropzone` (halaman Unggah) tidak boleh dibuat overlay"
    assert re.search(r"(?m)^\.chat-dropzone\s*\{[^}]*position:\s*absolute", css)
    assert 'class="chat-dropzone"' in (root / "templates/chat.html").read_text(encoding="utf-8")
    assert 'class="dropzone"' in (root / "templates/upload.html").read_text(encoding="utf-8")
