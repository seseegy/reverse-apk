"""Perakit paket akhir (`rvcore.bundleout`, Tahap 3 sub-area D): format asal terjaga, extras utuh, manifest.json bedah, hash saat disalin, tmp aman, verifikasi.

Tidak ada alat nyata: "APK bertanda tangan" adalah byte buatan; yang dibuktikan adalah rakitan, bukan kriptografi (itu tugas signer).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from pathlib import Path

import pytest

from rvcore import bundleout as O
from rvcore.bundle import plan_from_zip
from rvcore.bundleout import AssembleError, SignedFile

from test_bundle import zip_bytes

SPLITS = ("config.arm64_v8a.apk", "config.id.apk")
OBB = "Android/obb/com.example.app/main.1.com.example.app.obb"
BASE = "com.example.app.apk"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def xapk(total_size=None, extra_manifest=None, order_manifest_first=True, splits=SPLITS) -> tuple[bytes, dict]:
    apks = {BASE: b"PK-asli-base" * 20, **{s: b"PK-asli-" + s.encode() * 5 for s in splits}}
    total = sum(len(v) for v in apks.values()) if total_size is None else total_size
    manifest = {"package_name": "com.example.app", "total_size": total, "split_apks": [{"file": BASE, "id": "base"}] + [{"file": s, "id": s[:-4]} for s in splits]}
    manifest.update(extra_manifest or {})
    entries = {"manifest.json": json.dumps(manifest).encode(), "icon.png": b"\x89PNG-ikon", OBB: os.urandom(3000), **apks}
    if not order_manifest_first:
        entries = {**{k: v for k, v in entries.items() if k != "manifest.json"}, "manifest.json": entries["manifest.json"]}
    return zip_bytes(entries, deflate=True), apks


class R:
    pass


@pytest.fixture
def rig(tmp_path):
    r = R()
    r.bdir = tmp_path / "b"
    r.bdir.mkdir()
    r.fd = os.open(r.bdir, os.O_RDONLY | os.O_DIRECTORY)
    r.ticks = 0

    def tick():
        r.ticks += 1

    r.check = tick

    def prepare(data: bytes, aliases=None, n_signed=None):
        r.zf = zipfile.ZipFile(io.BytesIO(data))
        r.plan = plan_from_zip(r.zf)
        r.aliases = aliases or []
        names = O.final_split_names(r.plan, r.aliases)
        r.signed = {"signed.apk": b"SIGNED-BASE" * 30}
        for i, n in enumerate(names, 1):
            r.signed[f"signed-{i:03d}.apk"] = f"SIGNED-{n}".encode() * 7
        for name, body in r.signed.items():
            (r.bdir / name).write_bytes(body)
        r.base = SignedFile("signed.apk", sha(r.signed["signed.apk"]), len(r.signed["signed.apk"]))
        r.splits = [SignedFile(f"signed-{i:03d}.apk", sha(r.signed[f"signed-{i:03d}.apk"]), len(r.signed[f"signed-{i:03d}.apk"])) for i in range(1, len(names) + 1)]
        return r

    def run(tmp=".bundle-aa.tmp"):
        return O.assemble(r.fd, tmp, r.zf, r.plan, r.aliases, r.base, r.splits, r.check)

    r.prepare, r.run = prepare, run
    r.out = lambda tmp=".bundle-aa.tmp": zipfile.ZipFile(r.bdir / tmp)
    yield r
    os.close(r.fd)


def test_rakit_xapk_nama_dan_urutan_dari_upload(rig):
    data, _ = xapk(order_manifest_first=False)
    rig.prepare(data)
    res = rig.run()
    names_in = zipfile.ZipFile(io.BytesIO(data)).namelist()
    with rig.out() as z:
        assert z.namelist() == names_in, "urutan dan nama persis upload"
        assert z.read(BASE) == rig.signed["signed.apk"]
        assert z.read(SPLITS[0]) == rig.signed["signed-001.apk"] and z.read(SPLITS[1]) == rig.signed["signed-002.apk"]
    assert res.entries == len(names_in)
    body = (rig.bdir / ".bundle-aa.tmp").read_bytes()
    assert res.sha256 == sha(body) and res.size == len(body)
    assert oct((rig.bdir / ".bundle-aa.tmp").stat().st_mode & 0o777) == "0o644"


def test_extras_isi_crc_ukuran_sama(rig):
    data, _ = xapk()
    rig.prepare(data)
    rig.run()
    src = zipfile.ZipFile(io.BytesIO(data))
    with rig.out() as z:
        for n in ("icon.png", OBB):
            assert z.read(n) == src.read(n)
            assert z.getinfo(n).CRC == src.getinfo(n).CRC and z.getinfo(n).file_size == src.getinfo(n).file_size
            assert z.getinfo(n).compress_type == src.getinfo(n).compress_type


def test_compress_type_asli_dipertahankan(rig):
    entries = {"manifest.json": json.dumps({"split_apks": [{"file": BASE, "id": "base"}]}).encode(), BASE: b"PK" * 10, "a.bin": b"x" * 2000, "b.bin": b"y" * 2000}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", entries["manifest.json"], zipfile.ZIP_DEFLATED)
        z.writestr(BASE, entries[BASE], zipfile.ZIP_STORED)
        z.writestr("a.bin", entries["a.bin"], zipfile.ZIP_STORED)
        z.writestr("b.bin", entries["b.bin"], zipfile.ZIP_DEFLATED)
    rig.prepare(buf.getvalue())
    rig.run()
    with rig.out() as z:
        assert [z.getinfo(n).compress_type for n in ("a.bin", "b.bin", BASE)] == [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED]


def test_direktori_entri_disalin(rig):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", json.dumps({"split_apks": [{"file": BASE, "id": "base"}]}))
        z.writestr(BASE, b"PK")
        z.writestr("Android/", b"")
        z.writestr("Android/obb/", b"")
    rig.prepare(buf.getvalue())
    rig.run()
    with rig.out() as z:
        assert z.namelist() == ["manifest.json", BASE, "Android/", "Android/obb/"] and z.getinfo("Android/").is_dir()


def test_rakit_apks_alias_menulis_byte_base_dua_nama(rig):
    data = zip_bytes({"toc.pb": b"\x0a\x00", "splits/base-master.apk": b"PK-master", "splits/base-master_2.apk": b"PK-master2", "splits/base-id.apk": b"PK-id",
                      "standalones/standalone.apk": b"PK-stand"}, deflate=True)
    rig.prepare(data, aliases=[1])
    # apk_order = [base-master_2? ...] posisi alias dicari lewat nama
    order = rig.plan.apk_order
    rig.prepare(data, aliases=[order.index("splits/base-master_2.apk")])
    rig.run()
    with rig.out() as z:
        assert "standalones/standalone.apk" not in z.namelist(), "dropped tidak ditulis"
        assert z.read("splits/base-master.apk") == z.read("splits/base-master_2.apk") == rig.signed["signed.apk"]
        assert z.read("splits/base-id.apk") == rig.signed["signed-001.apk"] and z.read("toc.pb") == b"\x0a\x00"
        assert z.namelist() == ["toc.pb", "splits/base-master.apk", "splits/base-master_2.apk", "splits/base-id.apk"]


def test_xapk_tanpa_split_n0_dirakit(rig):
    data, _ = xapk(splits=())
    rig.prepare(data)
    rig.run()
    with rig.out() as z:
        assert z.read(BASE) == rig.signed["signed.apk"] and OBB in z.namelist()


# ------------------------------------------------------------------ hash saat disalin
def test_hash_berkas_ttd_dihitung_saat_disalin_mismatch_artifact_changed(rig):
    data, _ = xapk()
    rig.prepare(data)
    (rig.bdir / "signed-002.apk").write_bytes(b"X" * len(rig.signed["signed-002.apk"]))      # ukuran sama, isi beda
    with pytest.raises(AssembleError) as ei:
        rig.run()
    assert ei.value.code == "artifact_changed" and not (rig.bdir / ".bundle-aa.tmp").exists()


def test_ukuran_beda_symlink_fifo_hardlink_dan_hilang_artifact_changed(rig, tmp_path):
    data, _ = xapk()
    rig.prepare(data)
    p = rig.bdir / "signed-001.apk"
    body = p.read_bytes()
    for plant in ("ukuran", "symlink", "fifo", "hardlink", "hilang"):
        p.unlink(missing_ok=True)
        if plant == "ukuran":
            p.write_bytes(body + b"+")
        elif plant == "symlink":
            real = tmp_path / "asli"
            real.write_bytes(body)
            p.symlink_to(real)
        elif plant == "fifo":
            os.mkfifo(p)
        elif plant == "hardlink":
            p.write_bytes(body)
            os.link(p, tmp_path / "tautan")
        with pytest.raises(AssembleError) as ei:
            rig.run()
        assert ei.value.code == "artifact_changed", plant
        assert not (rig.bdir / ".bundle-aa.tmp").exists()
        if plant == "hardlink":
            (tmp_path / "tautan").unlink()


def test_jumlah_split_beda_dari_rencana_bundle_changed(rig):
    data, _ = xapk()
    rig.prepare(data)
    rig.splits = rig.splits[:1]
    with pytest.raises(AssembleError) as ei:
        rig.run()
    assert ei.value.code == "bundle_changed"


def test_tmp_o_excl_nofollow_gagal_tertutup(rig, tmp_path):
    data, _ = xapk()
    rig.prepare(data)
    victim = tmp_path / "korban"
    victim.write_text("asli")
    os.symlink(victim, rig.bdir / ".bundle-aa.tmp")
    with pytest.raises(AssembleError) as ei:
        rig.run()
    assert ei.value.code == "assemble_failed" and victim.read_text() == "asli"
    assert (rig.bdir / ".bundle-aa.tmp").is_symlink(), "tmp milik orang lain tidak dihapus"


def test_pembatalan_di_tengah_perakitan_membersihkan_tmp(rig):
    class Stop(Exception):
        pass

    data, _ = xapk()
    rig.prepare(data)
    n = {"i": 0}

    def check():
        n["i"] += 1
        if n["i"] == 3:
            raise Stop()

    rig.check = check
    with pytest.raises(Stop):
        rig.run()
    assert not (rig.bdir / ".bundle-aa.tmp").exists()


def test_perakitan_gagal_tak_meninggalkan_tmp(rig, monkeypatch):
    data, _ = xapk()
    rig.prepare(data)
    monkeypatch.setattr(O, "_verify", lambda *a, **k: (_ for _ in ()).throw(AssembleError("assemble_failed", "x")))
    with pytest.raises(AssembleError):
        rig.run()
    assert sorted(os.listdir(rig.bdir)) == ["signed-001.apk", "signed-002.apk", "signed.apk"]


def test_verifikasi_ulang_menangkap_isi_paket_yang_diubah(rig, monkeypatch):
    data, _ = xapk()
    rig.prepare(data)
    real = O._write_signed

    def bad(zout, src, bfd, item, check):
        real(zout, src, bfd, item, check)

    monkeypatch.setattr(O, "_copy_member", lambda zout, zin, src, check: zout.writestr(O._zinfo(src), b"BEDA" if src.filename == "icon.png" else zin.read(src)))
    with pytest.raises(AssembleError) as ei:
        rig.run()
    assert ei.value.code == "assemble_failed" and not (rig.bdir / ".bundle-aa.tmp").exists()


def test_tidak_ada_penerbitan_oleh_modul():
    import ast
    tree = ast.parse(Path(O.__file__).read_text())
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not attrs & {"rename", "replace", "mkdir", "makedirs", "rmtree"}, "modul hanya menulis tmp; pemanggil yang menerbitkan"


# ------------------------------------------------------------------ manifest.json
def test_manifest_total_size_diganti_bedah_bila_jumlah_cocok(rig):
    data, apks = xapk()
    rig.prepare(data)
    res = rig.run()
    new_total = len(rig.signed["signed.apk"]) + len(rig.signed["signed-001.apk"]) + len(rig.signed["signed-002.apk"])
    old_total = sum(len(v) for v in apks.values())
    src = zipfile.ZipFile(io.BytesIO(data)).read("manifest.json")
    with rig.out() as z:
        got = z.read("manifest.json")
    assert got == src.replace(str(old_total).encode(), str(new_total).encode(), 1)
    assert f"manifest_total_size=diperbarui({old_total}->{new_total})" in res.notes


@pytest.mark.parametrize("raw,reason", [
    (b"bukan json", "json_rusak"),
    (b'{"a":1}', "tanpa_kunci"),
    (b'{"x":{"total_size":5}}', "bukan_akar"),
    (b'{"total_size":5,"y":{"total_size":5}}', "ganda"),
    (b'{"total_size":"5"}', "bukan_int"),
    (b'{"total_size":5.0}', "bukan_int"),
    (b'{"total_size":1e3}', "bukan_int"),
    (b'{"total_size":true}', "bukan_int"),
    (b'{"total_size":999999,"split_apks":[{"file":"a.apk"}]}', "nilai_beda"),
    (b'{"total_size":10,"split_apks":[{"file":"hilang.apk"}]}', "verifikasi_gagal"),
    (b'{"total_size":10,"split_apks":[{"file":"a.apk"}]}\xff', "json_rusak"),
])
def test_manifest_total_size_tak_cocok_tak_disentuh(raw, reason):
    out, note = O.patch_manifest(raw, {"a.apk": 10}, {"a.apk": 99}, ["a.apk"])
    assert out == raw and note == f"tidak_diperbarui({reason})"


def test_manifest_tanpa_split_apks_memakai_semua_apk_akar_dan_hanya_digit_berubah():
    raw = b'{ "a": 1,\n  "total_size" :  30 ,\n "z": [1,2] }\n'
    out, note = O.patch_manifest(raw, {"a.apk": 10, "b.apk": 20, "sub/c.apk": 500}, {"a.apk": 11, "b.apk": 22}, ["a.apk", "b.apk"])
    assert out == raw.replace(b"30", b"33") and note == "diperbarui(30->33)"


def test_manifest_teks_total_size_dalam_string_tidak_mengganggu_dan_regex_tak_unik_ditolak(monkeypatch):
    raw = b'{"total_size": 10, "ket": "\\"total_size\\": 7,"}'
    out, note = O.patch_manifest(raw, {"a.apk": 10}, {"a.apk": 9}, ["a.apk"])
    assert out == raw.replace(b"10", b"9", 1) and note == "diperbarui(10->9)", "kemunculan di dalam string (dengan escape) tidak cocok jangkar"
    import re
    monkeypatch.setattr(O, "_TOTAL_RE", re.compile(rb"\d+"))
    out, note = O.patch_manifest(raw, {"a.apk": 10}, {"a.apk": 9}, ["a.apk"])
    assert out == raw and note == "tidak_diperbarui(regex_tak_unik)"


def test_manifest_lebih_1mib_tak_disentuh():
    raw = b'{"total_size":1,"x":"' + b"a" * (1 << 20) + b'"}'
    assert O.patch_manifest(raw, {"a.apk": 1}, {"a.apk": 2}, ["a.apk"])[1] == "tidak_diperbarui(json_rusak)"


def test_manifest_byte_sama_selain_total_size_dan_catatan_di_rakitan(rig):
    data, _ = xapk(total_size=12345)
    rig.prepare(data)
    res = rig.run()
    with rig.out() as z:
        assert z.read("manifest.json") == zipfile.ZipFile(io.BytesIO(data)).read("manifest.json")
    assert "manifest_total_size=tidak_diperbarui(nilai_beda)" in res.notes


def test_manifest_memuat_hash_apk_peringatan(rig):
    data, _ = xapk(extra_manifest={"checksum": "ab" * 32})
    rig.prepare(data)
    assert "manifest_memuat_hash_tak_diperbarui" in rig.run().notes


def test_apks_tidak_menyentuh_manifest_json_dan_tanpa_catatan(rig):
    data = zip_bytes({"toc.pb": b"x", "manifest.json": b'{"total_size": 5}', "splits/base-master.apk": b"PK"})
    rig.prepare(data)
    res = rig.run()
    with rig.out() as z:
        assert z.read("manifest.json") == b'{"total_size": 5}'
    assert res.notes == ()
