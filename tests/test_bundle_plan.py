"""Rencana set split (Tahap 3, sub-area A): `plan_split_set` dan pengetatan `plan_bundle` pada upload baru.

Murni atas central directory + manifest.json kecil: tidak ada APK bersarang yang dibuka, nama tidak pernah menjadi path.
Semua tes ini GAGAL di kode lama (fungsi/konstanta belum ada, atau ingest lama menerima masukan itu).
"""

from __future__ import annotations

import io
import json
import re
import stat
import zipfile
from pathlib import Path

import pytest

from rvcore import bundle as B
from rvcore.bundle import BundleError, SplitSet, plan_bundle, plan_split_set

from test_bundle import apk_bytes, apks_default, apks_universal, xapk, xapk_manifest, zip_bytes

ROOT = Path(__file__).resolve().parent.parent


def zf_of(data: bytes) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(data))


def split_set(data: bytes) -> SplitSet:
    with zf_of(data) as zf:
        raw = zf.read("manifest.json") if "manifest.json" in zf.namelist() else None
        return plan_split_set(zf.infolist(), raw)


def refused(data: bytes, fn=split_set) -> BundleError:
    with pytest.raises(BundleError) as ei:
        fn(data)
    return ei.value


def zip_with_attr(entries: dict[str, tuple[bytes, int]]) -> bytes:
    """entries: nama -> (isi, mode Unix penuh termasuk tipe berkas)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, (data, mode) in entries.items():
            zi = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            zi.create_system = 3
            zi.external_attr = mode << 16
            zf.writestr(zi, data)
    return buf.getvalue()


def plan_of(data: bytes):
    with zf_of(data) as zf:
        return plan_bundle(zf)


# ---------------------------------------------------------------------------------------------- rencana set
def test_plan_split_set_urutan_central_directory_stabil():
    ss = split_set(xapk(splits=("config.zz.apk", "config.aa.apk", "feat.apk")))
    assert ss.format == "xapk" and ss.base == "com.example.app.apk"
    assert ss.apk_order == ("config.zz.apk", "config.aa.apk", "feat.apk")      # urutan arsip, bukan alfabet
    assert ss.alias_candidates == () and ss.dropped == ()
    assert set(ss.extras) == {"manifest.json", "icon.png"}


def test_plan_split_set_plan_sha256_berubah_bila_crc_beda():
    a = split_set(xapk(tag="a"))
    b = split_set(xapk(tag="b"))
    assert re.fullmatch(r"[0-9a-f]{64}", a.plan_sha256)
    assert a.plan_sha256 != b.plan_sha256
    assert a.plan_sha256 == split_set(xapk(tag="a")).plan_sha256


def test_plan_menolak_lebih_200_apk():
    entries = {"manifest.json": json.dumps({"split_apks": [{"file": "b.apk", "id": "base"}]}).encode(), "b.apk": b"PK\x03\x04"}
    entries.update({f"s{i}.apk": b"PK\x03\x04" for i in range(200)})          # 201 APK
    err = refused(zip_bytes(entries))
    assert err.code == "bundle_too_many_apks"
    with zf_of(zip_bytes(entries)) as zf:                                    # ingest (plan_bundle) menegakkan batas yang sama
        with pytest.raises(BundleError) as ei:
            plan_bundle(zf)
    assert ei.value.code == "bundle_too_many_apks"


def test_plan_200_apk_tepat_diterima():
    entries = {"manifest.json": json.dumps({"split_apks": [{"file": "b.apk", "id": "base"}]}).encode(), "b.apk": b"PK\x03\x04"}
    entries.update({f"s{i}.apk": b"PK\x03\x04" for i in range(199)})          # tepat 200
    assert len(split_set(zip_bytes(entries)).apk_order) == 199
    assert B.MAX_BUNDLE_APKS == 200


@pytest.mark.parametrize("mode", [stat.S_IFLNK | 0o777, stat.S_IFCHR | 0o600, stat.S_IFBLK | 0o600, stat.S_IFIFO | 0o600, stat.S_IFSOCK | 0o600])
def test_plan_menolak_symlink_perangkat_fifo(mode):
    data = zip_with_attr({"manifest.json": (json.dumps(xapk_manifest(splits=())).encode(), stat.S_IFREG | 0o644),
                          "com.example.app.apk": (apk_bytes(), stat.S_IFREG | 0o644), "evil": (b"/etc/passwd", mode)})
    assert refused(data).code == "bundle_unsafe_entry"
    assert refused(data, plan_of).code == "bundle_unsafe_entry"


def test_plan_berkas_biasa_dan_mode_nol_diterima():
    data = zip_with_attr({"manifest.json": (json.dumps(xapk_manifest(splits=())).encode(), 0),
                          "com.example.app.apk": (apk_bytes(), stat.S_IFREG | 0o644), "dir/": (b"", stat.S_IFDIR | 0o755)})
    assert split_set(data).base == "com.example.app.apk"


@pytest.mark.parametrize("bad", ["a\x01b.bin", "a\x7fb.bin", "a\\b.bin", "a//b.bin", "./a.bin", "a/./b.bin", "a/../b.bin", "/abs.bin", "x" * 256 + ".bin"])
def test_plan_menolak_nama_kontrol_backslash_komponen_kosong_terlalu_panjang(bad):
    data = zip_bytes({"manifest.json": json.dumps(xapk_manifest(splits=())).encode(), "com.example.app.apk": apk_bytes(), bad: b"x"})
    assert refused(data).code == "bundle_unsafe_entry"
    assert refused(data, plan_of).code == "bundle_unsafe_entry"


def test_plan_nama_255_byte_diterima():
    ok = "x" * 251 + ".bin"
    data = zip_bytes({"manifest.json": json.dumps(xapk_manifest(splits=())).encode(), "com.example.app.apk": apk_bytes(), ok: b"x"})
    assert ok in split_set(data).extras


def test_plan_alias_candidates_regex_dan_maks_8():
    names = {"toc.pb": b"x", "splits/base-master.apk": apk_bytes()}
    names.update({f"splits/base-master_{n}.apk": apk_bytes() for n in range(2, 14)})        # 12 kandidat
    names.update({"splits/base-master_1.apk": apk_bytes(), "splits/base-master_x.apk": apk_bytes(), "splits/xbase-master_5.apk": apk_bytes()})
    ss = split_set(zip_bytes(names))
    assert ss.base == "splits/base-master.apk"
    assert ss.alias_candidates == tuple(f"splits/base-master_{n}.apk" for n in range(2, 10))
    assert "alias_terlalu_banyak" in ss.warnings
    assert all(c in ss.apk_order for c in ss.alias_candidates)          # kandidat tetap ada di apk_order
    assert "splits/base-master_1.apk" not in ss.alias_candidates and "splits/base-master_x.apk" not in ss.alias_candidates
    assert split_set(apks_default()).alias_candidates == ("splits/base-master_2.apk",)


def test_plan_split_set_tidak_membuka_apk_bersarang(monkeypatch):
    data = xapk()
    reads: list[str] = []
    real_open = zipfile.ZipFile.open

    def spy(self, name, *a, **k):
        reads.append(getattr(name, "filename", name))
        return real_open(self, name, *a, **k)

    monkeypatch.setattr(zipfile.ZipFile, "open", spy)
    with zf_of(data) as zf:
        infos = zf.infolist()
        plan_split_set(infos, zf.read("manifest.json"))
    assert [r for r in reads if str(r).endswith(".apk")] == []


@pytest.mark.parametrize("bad", ["a*.apk", "a?.apk", "a[1].apk", "a]b.apk", "obb/x*.obb", "obb/y?.obb"])
def test_plan_nama_glob_ditolak_bundle_unsafe_entry(bad):
    data = zip_bytes({"toc.pb": b"x", "universal.apk": apk_bytes(), bad: b"PK\x03\x04"})
    assert refused(data).code == "bundle_unsafe_entry"
    plan_of(data)                                                       # ingest (analisis) tetap menerima: pengetatan hanya di jalur build


def test_plan_nama_glob_pada_berkas_lain_tidak_ditolak():
    data = zip_bytes({"toc.pb": b"x", "universal.apk": apk_bytes(), "notes*.txt": b"x"})
    assert "notes*.txt" in split_set(data).extras


def test_plan_split_apks_hilang_split_missing():
    m = xapk_manifest(splits=("config.en.apk",))
    data = zip_bytes({"manifest.json": json.dumps(m).encode(), "com.example.app.apk": apk_bytes()})     # config.en.apk tidak ada
    assert refused(data).code == "split_missing"


def test_plan_bundle_ingest_tetap_menerima_split_apks_hilang():
    m = xapk_manifest(splits=("config.en.apk",))
    data = zip_bytes({"manifest.json": json.dumps(m).encode(), "com.example.app.apk": apk_bytes()})
    assert plan_of(data).base == "com.example.app.apk"


def test_plan_sai_ditolak_pesan_menyebut_sai():
    for marker in ("meta.sai_v1.json", "meta.sai_v2.json"):
        err = refused(zip_bytes({marker: b"{}", "a.apk": apk_bytes()}), plan_of)
        assert err.code == "unsupported_bundle" and "SAI" in err.message


def test_plan_apkm_tetap_ditolak():
    err = refused(zip_bytes({"info.json": b"{}", "base.apk": apk_bytes()}), plan_of)
    assert err.code == "unsupported_bundle" and "APKM" in err.message
    assert "SAI" not in err.message


def test_dropped_standalones_instant_system_tidak_di_apk_order():
    data = zip_bytes({"toc.pb": b"x", "splits/base-master.apk": apk_bytes(), "splits/base-en.apk": apk_bytes("en"),
                      "standalones/standalone-xhdpi.apk": apk_bytes("s"), "instant/i.apk": apk_bytes("i"), "system/s.apk": apk_bytes("y")})
    ss = split_set(data)
    assert ss.dropped == ("standalones/standalone-xhdpi.apk", "instant/i.apk", "system/s.apk")
    assert ss.apk_order == ("splits/base-en.apk",)
    assert not set(ss.dropped) & set(ss.extras)


def test_dropped_tidak_mencakup_base_standalone():
    data = zip_bytes({"toc.pb": b"x", "standalones/standalone-a.apk": apk_bytes("a"), "splits/base-en.apk": apk_bytes("en")})
    ss = split_set(data)
    assert ss.base == "standalones/standalone-a.apk"
    assert ss.dropped == () and ss.apk_order == ("splits/base-en.apk",)


def test_asset_slices_dan_apk_akar_adalah_split_biasa():
    data = zip_bytes({"toc.pb": b"x", "splits/base-master.apk": apk_bytes(), "asset-slices/pack.apk": apk_bytes("p"), "extra.apk": apk_bytes("e")})
    ss = split_set(data)
    assert ss.apk_order == ("asset-slices/pack.apk", "extra.apk") and ss.dropped == ()


def test_plan_duplikat_casefold_ditolak():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps(xapk_manifest(splits=())))
        zf.writestr("com.example.app.apk", apk_bytes())
        zf.writestr("Obb/Main.obb", b"1")
        zf.writestr("obb/main.obb", b"2")
    assert refused(buf.getvalue()).code == "bundle_unsafe_entry"


def test_plan_apks_universal_tanpa_split_n0():
    ss = split_set(apks_universal())
    assert ss.format == "apks" and ss.base == "universal.apk" and ss.apk_order == () and ss.extras == ("toc.pb",)


def test_plan_apk_biasa_bukan_paket():
    assert refused(apk_bytes()).code == "bundle_invalid"


def test_plan_xapk_tanpa_manifest_bytes_ditolak():
    with zf_of(xapk()) as zf:
        with pytest.raises(BundleError) as ei:
            plan_split_set(zf.infolist(), None)
    assert ei.value.code == "bundle_invalid"


def test_plan_manifest_terlalu_besar_ditolak():
    with zf_of(xapk()) as zf:
        with pytest.raises(BundleError):
            plan_split_set(zf.infolist(), b" " * (B.MAX_MANIFEST_BYTES + 1))


def test_konstanta_zip_max_runner_worker_sama_dengan_settings_web():
    from app.config import Settings, load_settings
    s = load_settings()
    assert B.ZIP_MAX_ENTRIES == s.zip_max_entries == 100_000
    assert B.ZIP_MAX_TOTAL_BYTES == s.zip_max_total_uncompressed == 3072 * B.MIB
    assert B.ZIP_MAX_ENTRY_BYTES == s.zip_max_entry_uncompressed == 512 * B.MIB
    assert B.ZIP_MAX_RATIO == s.zip_max_ratio == 100
    assert (B.UPLOAD_COPY_MAX_RUNNER_MB, B.UPLOAD_COPY_MAX_WORKER_MB, B.MAX_ALIAS_CANDIDATES) == (512, 256, 8)
    assert Settings is not None


def test_konstanta_dibaca_dari_env_bernama_sama():
    # Proses terpisah: me-reload modul di proses uji mengganti kelas BundleError dan merusak tes lain.
    import os
    import subprocess
    import sys
    env = {**os.environ, "ZIP_MAX_ENTRIES": "77", "ZIP_MAX_RATIO": "7", "ZIP_MAX_ENTRY_MB": "bukan-angka", "PYTHONPATH": str(ROOT / "services")}
    out = subprocess.run([sys.executable, "-c", "from rvcore import bundle as b; print(b.ZIP_MAX_ENTRIES, b.ZIP_MAX_RATIO, b.ZIP_MAX_ENTRY_BYTES)"],
                         env=env, capture_output=True, text=True, check=True).stdout.split()
    assert out == ["77", "7", str(512 * B.MIB)]


def test_modul_bundle_tidak_membuka_apk_bersarang_di_plan_split_set():
    import ast
    tree = ast.parse((ROOT / "services/rvcore/bundle.py").read_text())
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "plan_split_set")
    called = {getattr(c.func, "attr", getattr(c.func, "id", "")) for c in ast.walk(fn) if isinstance(c, ast.Call)}
    assert not called & {"open", "ZipFile", "read", "extract", "extractall"}
