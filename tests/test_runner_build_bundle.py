"""Tahap runner `build` untuk paket XAPK/APKS (Tahap 3, sub-area B): `buildstage.run` dengan `source_kind` xapk/apks.

Memakai apktool PALSU dan rig dari `test_runner_build.py`. Yang dibuktikan: urutan langkah bernomor (design 3.3), split ditulis ke `split-NNN.apk` tanpa tanda tangan
lama dengan hash dari fd yang sama, keputusan alias, `bundle_changed` (dua lintasan), peringatan versi, pembersihan pada setiap jalur gagal, dan bahwa jalur APK
tunggal tidak menyentuh `uploads/`.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import io
import json
import os
import zipfile
from pathlib import Path
from types import SimpleNamespace

import buildstage
import pytest
from rvcore import buildproto, bundle, splitzip
from rvcore.buildproto import BuildRequest
from test_bundle import zip_bytes
import test_runner_build
from test_runner_build import AID, BASE_FILES, BID, EDIT, Clock

rig = test_runner_build.rig          # fixture dipakai ulang (pytest menemukannya sebagai nama tingkat modul)
MIB = 1024 * 1024
LIST_SPLITS = ("config.arm64_v8a.apk", "config.id.apk")


def nested(tag: str, stale: bool = True, extra: dict[str, bytes] | None = None) -> bytes:
    """APK bersarang: berisi sisa tanda tangan v1 palsu (tanpa kunci) dan satu berkas META-INF yang HARUS selamat."""
    files = {"AndroidManifest.xml": b"axml-" + tag.encode(), "classes.dex": b"dex-" + tag.encode(), "res/a.xml": b"<a/>" + tag.encode(),
             "META-INF/services/demo": b"layanan"}
    if stale:
        files.update({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "META-INF/BNDLTOOL.SF": b"sf" + tag.encode(), "META-INF/BNDLTOOL.RSA": b"rsa" + tag.encode()})
    files.update(extra or {})
    return zip_bytes(files, deflate=True)


def xapk_bytes(tag: str = "x", splits: tuple[str, ...] = LIST_SPLITS, extra: dict[str, bytes] | None = None, base: str = "com.example.app.apk") -> bytes:
    manifest = {"package_name": "com.example.app", "total_size": 1, "split_apks": [{"file": base, "id": "base"}] + [{"file": s, "id": s[:-4]} for s in splits]}
    entries = {base: nested(tag), "manifest.json": json.dumps(manifest).encode(), "icon.png": b"\x89PNG"}
    entries.update({s: nested(tag + s) for s in splits})
    entries.update(extra or {})
    return zip_bytes(entries)


def apks_bytes(tag: str = "x", master2: str | None = "alias", extra: dict[str, bytes] | None = None) -> bytes:
    """master2: 'alias' (isi sama, tanda tangan beda: meniru bundletool), 'lain' (isi beda), atau None (tanpa base-master_2)."""
    entries = {"toc.pb": b"\x0a\x00", "splits/base-master.apk": nested(tag + "M"), "splits/base-id.apk": nested(tag + "id")}
    if master2 == "alias":
        same = {n: zipfile.ZipFile(io.BytesIO(nested(tag + "M"))).read(n) for n in ("AndroidManifest.xml", "classes.dex", "res/a.xml", "META-INF/services/demo")}
        entries["splits/base-master_2.apk"] = zip_bytes({**same, "META-INF/BNDLTOOL.SF": b"sf-lain", "META-INF/BNDLTOOL.RSA": b"rsa-lain", "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"}, deflate=True)
    elif master2 == "lain":
        entries["splits/base-master_2.apk"] = nested(tag + "BEDA")
    entries.update(extra or {})
    return zip_bytes(entries)


@pytest.fixture
def bun(rig):
    rig.layout.uploads.mkdir(parents=True, exist_ok=True)

    def put(data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        (rig.layout.uploads / f"{sha}.apk").write_bytes(data)
        return sha

    def run(data: bytes | None, kind: str = "xapk", sha: str | None = None, **over):
        if data is not None:
            sha = put(data)
        return rig.run(sha=sha or "ab" * 32, **over) if kind is None else _run(rig, kind, sha, **over)

    def _run(rg, kind, sha, **over):
        req = BuildRequest(over.pop("aid", AID), over.pop("bid", BID), over.pop("diff", None) or rg.diff(), sha, over.pop("timeout", 60), kind)
        return buildstage.run(rg.env, rg.job_id, req)

    rig.put, rig.brun = put, run
    rig.ls = lambda: sorted(os.listdir(rig.build_dir))
    return rig


def split_names(data: bytes) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return [n for n in zf.namelist() if n.endswith(".apk")]


# ======================================================================================== alur sukses
def test_bundle_xapk_hasil_unsigned_dan_split_dengan_hash(bun):
    data = xapk_bytes()
    res = bun.brun(data, "xapk")
    assert res["status"] == "ok" and res["source_kind"] == "xapk" and res["warnings"] == []
    assert [s["index"] for s in res["splits"]] == [1, 2] and res["aliases"] == []
    for s in res["splits"]:
        body = (bun.build_dir / f"split-{s['index']:03d}.apk").read_bytes()
        assert s["sha256"] == hashlib.sha256(body).hexdigest() and s["size"] == len(body), "hash + ukuran dari berkas yang sama"
        names = zipfile.ZipFile(io.BytesIO(body)).namelist()
        assert "META-INF/services/demo" in names and not [n for n in names if splitzip.is_signature_entry(n)], "tidak ada sisa tanda tangan; non-tanda-tangan selamat"
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        plan = bundle.plan_split_set(zf.infolist(), zf.read("manifest.json"))
    assert res["plan_sha256"] == plan.plan_sha256
    assert bun.ls() == ["build.log", "split-001.apk", "split-002.apk", "unsigned.apk"] and bun.homes() == []
    assert buildproto.parse_build_result(res)["ok"] is True and len(bun.calls()) == 1


def test_bundle_split_mengikuti_urutan_central_directory(bun):
    res = bun.brun(xapk_bytes(splits=("config.zz.apk", "config.aa.apk")), "xapk")
    first = zipfile.ZipFile(bun.build_dir / "split-001.apk").read("AndroidManifest.xml")
    assert res["status"] == "ok" and first == b"axml-x" + b"config.zz.apk"


def test_bundle_xapk_tanpa_split_n0_tetap_ok(bun):
    res = bun.brun(xapk_bytes(splits=()), "xapk")
    assert res["status"] == "ok" and res["splits"] == [] and bun.ls() == ["build.log", "unsigned.apk"]


def test_bundle_apks_alias_tidak_diekstrak(bun):
    res = bun.brun(apks_bytes(), "apks")
    # apk_order = [base-id, base-master_2]; alias = posisi 1; split final hanya base-id
    assert res["status"] == "ok" and res["aliases"] == [1] and [s["index"] for s in res["splits"]] == [1]
    assert bun.ls() == ["build.log", "split-001.apk", "unsigned.apk"], "alias tidak diekstrak sebagai split dan tak ada sisa .alias-*"


def test_bundle_apks_master_n_non_alias_bundle_invalid(bun):
    res = bun.brun(apks_bytes(master2="lain"), "apks")
    assert (res["status"], res["error_code"]) == ("failed", "bundle_invalid") and bun.ls() == ["build.log"]


def test_bundle_apks_standalone_dibuang_dengan_peringatan(bun):
    data = apks_bytes(master2=None, extra={"standalones/standalone-xhdpi.apk": nested("S")})
    res = bun.brun(data, "apks")
    assert res["status"] == "ok" and "entri_dibuang_n=1" in res["warnings"] and [s["index"] for s in res["splits"]] == [1]
    assert bun.ls() == ["build.log", "split-001.apk", "unsigned.apk"]


# ======================================================================================== kegagalan dan pembersihan
def test_bundle_split_missing_gagal_sebelum_apktool(bun):
    data = zip_bytes({"manifest.json": json.dumps({"split_apks": [{"file": "b.apk", "id": "base"}, {"file": "hilang.apk", "id": "x"}]}).encode(), "b.apk": nested("b")})
    res = bun.brun(data, "xapk")
    assert (res["status"], res["error_code"]) == ("failed", "split_missing") and bun.calls() == [] and bun.ls() == ["build.log"]


@pytest.mark.parametrize("blob", [b"PK\x03\x04" + b"\x00" * 64, b"bukan zip sama sekali"])
def test_bundle_split_rusak_split_invalid_bersih(bun, blob):
    data = xapk_bytes(extra={"config.id.apk": blob})
    res = bun.brun(data, "xapk")
    assert (res["status"], res["error_code"]) == ("failed", "split_invalid") and bun.ls() == ["build.log"], "split-*, .split-*, unsigned.apk dibuang"


def test_bundle_zip_bomb_dalam_bundle_too_large(bun):
    bomb = zip_bytes({"AndroidManifest.xml": b"a", "res/raw/nol.bin": b"\x00" * (12 * MIB)}, deflate=True)
    res = bun.brun(xapk_bytes(extra={"config.id.apk": bomb}), "xapk")
    assert (res["status"], res["error_code"]) == ("failed", "bundle_too_large") and bun.ls() == ["build.log"]


def test_bundle_anggaran_total_dekompresi_dibagi_semua_split(bun, monkeypatch):
    monkeypatch.setattr(splitzip, "ZIP_MAX_TOTAL_BYTES", 100)
    res = bun.brun(xapk_bytes(), "xapk")
    assert (res["status"], res["error_code"]) == ("failed", "bundle_too_large") and bun.ls() == ["build.log"]


@pytest.mark.parametrize("kind,make", [("apks", xapk_bytes), ("xapk", apks_bytes)])
def test_bundle_format_request_tak_cocok_bad_request(bun, kind, make):
    res = bun.brun(make(), kind)
    assert (res["status"], res["error_code"]) == ("failed", "bad_request") and bun.calls() == [] and bun.ls() == ["build.log"]


def test_bundle_nama_keluaran_ditanam_symlink_gagal_tertutup(bun, tmp_path):
    victim = tmp_path / "korban.txt"
    victim.write_text("asli")
    os.symlink(victim, bun.build_dir / ".split-001.raw.part")
    res = bun.brun(xapk_bytes(), "xapk")
    assert res["status"] == "failed" and res["error_code"] == "internal" and victim.read_text() == "asli"
    assert bun.ls() == ["build.log"], "symlink tertanam dibuang sebagai tautan (bukan targetnya)"
    os.symlink(victim, bun.build_dir / "split-001.apk.part")
    res = bun.brun(xapk_bytes(), "xapk")
    assert res["status"] == "failed" and res["error_code"] == "internal" and victim.read_text() == "asli" and bun.ls() == ["build.log"]


def test_bundle_symlink_di_split_akhir_tidak_diikuti(bun, tmp_path):
    victim = tmp_path / "korban.txt"
    victim.write_text("asli")
    os.symlink(victim, bun.build_dir / "split-001.apk")
    res = bun.brun(xapk_bytes(), "xapk")
    assert res["status"] == "ok" and victim.read_text() == "asli"
    assert not (bun.build_dir / "split-001.apk").is_symlink() and (bun.build_dir / "split-001.apk").stat().st_size == res["splits"][0]["size"]


def _spy_strip(monkeypatch, bun, action):
    real = splitzip.strip_signatures
    count = {"n": 0}

    def wrapped(*a, **k):
        count["n"] += 1
        action(count["n"])
        return real(*a, **k)

    monkeypatch.setattr(buildstage.splitzip, "strip_signatures", wrapped)
    return count


def test_bundle_pembatalan_di_tengah_split_membersihkan(bun, monkeypatch):
    _spy_strip(monkeypatch, bun, lambda n: bun.spool.request_cancel(bun.job_id) if n == 2 else None)
    res = bun.brun(xapk_bytes(), "xapk")
    assert (res["status"], res["error_code"]) == ("cancelled", "cancelled")
    assert bun.ls() == ["build.log"], "split-001 yang sudah jadi, unsigned.apk, dan sisa .split-* dibuang"


def test_bundle_tenggat_jam_palsu_di_tengah_ekstraksi_timeout(bun, monkeypatch):
    clock = Clock()
    bun.env.clock = clock
    _spy_strip(monkeypatch, bun, lambda n: setattr(clock, "t", clock.t + 61) if n == 1 else None)
    res = bun.brun(xapk_bytes(), "xapk")
    assert (res["status"], res["error_code"]) == ("timeout", "timeout") and bun.ls() == ["build.log"]


def test_bundle_detak_tiap_5_dtk_saat_rezip(bun, monkeypatch):
    beats = []
    real = bun.spool.write_heartbeat
    bun.spool.write_heartbeat = lambda state, job=None: (beats.append(state), real(state, job))[1]
    bun.env.heartbeat_every = 0.0
    seen = {}
    _spy_strip(monkeypatch, bun, lambda n: seen.setdefault(n, len(beats)))
    assert bun.brun(xapk_bytes(), "xapk")["status"] == "ok"
    assert len(beats) > seen[1], "detak ditulis lagi selama/sesudah re-zip (on_tick tersambung)"


def test_bundle_hitung_disk_menyertakan_split(bun, monkeypatch):
    data = xapk_bytes()
    sha = bun.put(data)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        sizes = [zf.getinfo(n).file_size for n in LIST_SPLITS]
    size = sum(len(t) for t in {**BASE_FILES, **EDIT}.values())
    need = 2 * size + buildstage.RESERVE + sum(sizes) + max(sizes)
    monkeypatch.setattr(buildstage.os, "statvfs", lambda _p: SimpleNamespace(f_bavail=need - 1, f_frsize=1))
    res = bun.brun(None, "xapk", sha=sha)
    assert res["error_code"] == "no_space" and bun.calls() == [] and bun.ls() == ["build.log"]
    monkeypatch.setattr(buildstage.os, "statvfs", lambda _p: SimpleNamespace(f_bavail=need, f_frsize=1))
    assert bun.brun(None, "xapk", sha=sha)["status"] == "ok"


def test_bundle_gagal_membuang_unsigned_dan_split(bun):
    bun.behave(mode="fail", text="gagal tiruan")
    res = bun.brun(xapk_bytes(), "xapk")
    assert res["error_code"] == "build_failed" and bun.ls() == ["build.log"]


def test_bundle_memfd_tak_tersedia_tanpa_cadangan(bun, monkeypatch):
    def boom(*a, **k):
        raise OSError(12, "ENOMEM")

    monkeypatch.setattr(os, "memfd_create", boom)
    res = bun.brun(xapk_bytes(), "xapk")
    assert (res["status"], res["error_code"]) == ("failed", "memfd_unavailable") and bun.ls() == ["build.log"]


def test_bundle_memfd_ditutup_dan_tak_ada_sisa_nama_perantara(bun):
    before = len(os.listdir("/proc/self/fd"))
    assert bun.brun(xapk_bytes(), "xapk")["status"] == "ok"
    assert len(os.listdir("/proc/self/fd")) <= before, "fd upload dan memfd tertutup"
    assert not [n for n in bun.ls() if n.startswith(".")]


# ======================================================================================== upload berubah (dua lintasan)
def test_bundle_upload_ditukar_sebelum_mulai_bundle_changed(bun):
    sha = bun.put(xapk_bytes())
    (bun.layout.uploads / f"{sha}.apk").write_bytes(xapk_bytes("lain"))
    res = bun.brun(None, "xapk", sha=sha)
    assert (res["status"], res["error_code"]) == ("failed", "bundle_changed") and bun.calls() == [] and bun.ls() == ["build.log"]


def test_bundle_upload_hilang_bundle_changed(bun):
    res = bun.brun(None, "xapk", sha="ab" * 32)
    assert res["error_code"] == "bundle_changed" and bun.calls() == []


@pytest.mark.parametrize("plant", ["symlink", "hardlink", "fifo"])
def test_bundle_upload_bukan_berkas_biasa_ditolak(bun, tmp_path, plant):
    data = xapk_bytes()
    sha = hashlib.sha256(data).hexdigest()
    real = tmp_path / "asli.bin"
    real.write_bytes(data)
    target = bun.layout.uploads / f"{sha}.apk"
    if plant == "symlink":
        os.symlink(real, target)
    elif plant == "hardlink":
        target.write_bytes(data)
        os.link(target, tmp_path / "tautan.bin")
    else:
        os.mkfifo(target)
    res = bun.brun(None, "xapk", sha=sha)
    assert res["status"] == "failed" and res["error_code"] in ("bundle_invalid", "bundle_changed") and bun.calls() == []


def test_bundle_lintasan2_setelah_apktool(bun):
    """Upload ditulis-di-tempat OLEH apktool palsu (antara lintasan 1 dan 2): hanya lintasan 2 yang menangkapnya."""
    data = xapk_bytes()
    sha = bun.put(data)
    bun.behave(mutate_live=[str(bun.layout.uploads / f"{sha}.apk"), "ditulis di tempat"])
    res = bun.brun(None, "xapk", sha=sha)
    assert (res["status"], res["error_code"]) == ("failed", "bundle_changed") and len(bun.calls()) == 1, "apktool sudah jalan sekali"
    assert bun.ls() == ["build.log"]


def test_bundle_upload_ditulis_di_tempat_antara_lintasan_bundle_changed(bun, monkeypatch):
    sha = bun.put(xapk_bytes())
    real = bundle.UploadHandle.copy

    def tamper(self):
        (bun.layout.uploads / f"{sha}.apk").write_bytes(b"x" * 100)
        return real(self)

    monkeypatch.setattr(bundle.UploadHandle, "copy", tamper)
    res = bun.brun(None, "xapk", sha=sha)
    assert res["error_code"] == "bundle_changed" and bun.ls() == ["build.log"]


def test_bundle_plan_sha_beda_antara_langkah3_dan_8_bundle_changed(bun, monkeypatch):
    real = bundle.plan_from_zip
    calls = []

    def flip(zf):
        calls.append(1)
        plan = real(zf)
        return plan if len(calls) == 1 else dataclasses.replace(plan, plan_sha256="0" * 64)

    monkeypatch.setattr(buildstage.bundle, "plan_from_zip", flip)
    res = bun.brun(xapk_bytes(), "xapk")
    assert res["error_code"] == "bundle_changed" and len(calls) == 2 and bun.ls() == ["build.log"]


def test_bundle_apk_tunggal_tidak_membuka_uploads(bun, monkeypatch):
    def forbid(*a, **k):
        raise AssertionError("uploads tidak boleh dibuka untuk source_kind=apk")

    monkeypatch.setattr(buildstage.bundle, "begin_upload", forbid)
    monkeypatch.setattr(buildstage.bundle, "open_upload", forbid)
    res = bun.brun(None, "apk", sha="cd" * 32)
    parsed = buildproto.parse_build_result(res)
    assert res["status"] == "ok" and "splits" not in res and parsed["source_kind"] == "apk" and parsed["splits"] == []
    assert bun.ls() == ["build.log", "unsigned.apk"]


# ======================================================================================== urutan langkah (F12)
def test_urutan_upload_ditukar_mengalahkan_diff_changed(bun):
    sha = bun.put(xapk_bytes())
    (bun.layout.uploads / f"{sha}.apk").write_bytes(b"lain")
    (bun.project / "res" / "values" / "strings.xml").write_text("diubah setelah persetujuan")
    res = bun.brun(None, "xapk", sha=sha, diff="ef" * 32)
    assert res["error_code"] == "bundle_changed"


def _missing():
    return zip_bytes({"manifest.json": json.dumps({"split_apks": [{"file": "b.apk", "id": "base"}, {"file": "hilang.apk", "id": "x"}]}).encode(), "b.apk": nested("b")})


def test_urutan_split_missing_mengalahkan_workspace_changed(bun):
    res = bun.brun(_missing(), "xapk", diff="ef" * 32)
    assert res["error_code"] == "split_missing"


def test_urutan_split_missing_mengalahkan_no_space(bun, monkeypatch):
    monkeypatch.setattr(buildstage.os, "statvfs", lambda _p: SimpleNamespace(f_bavail=0, f_frsize=1))
    assert bun.brun(_missing(), "xapk")["error_code"] == "split_missing"


def test_urutan_no_space_mendahului_workspace_changed(bun, monkeypatch):
    monkeypatch.setattr(buildstage.os, "statvfs", lambda _p: SimpleNamespace(f_bavail=0, f_frsize=1))
    assert bun.brun(xapk_bytes(), "xapk", diff="ef" * 32)["error_code"] == "no_space"


def test_urutan_apktool_tidak_dipanggil_bila_rencana_cacat(bun):
    for data in (_missing(), zip_bytes({"a.apk": nested("a")}), b"bukan zip"):
        res = bun.brun(data, "xapk")
        assert res["status"] == "failed" and bun.calls() == []


# ======================================================================================== peringatan versi (atas pohon teks)
def tree(root: Path, yml: str | None, manifest: str | None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    if yml is not None:
        (root / "apktool.yml").write_text(yml)
    if manifest is not None:
        (root / "AndroidManifest.xml").write_text(manifest)
    return root


def yml(code: str = "1", rename: str = "null") -> str:
    return f"version: 3.0.3\napkFileName: a.apk\nrenameManifestPackage: {rename}\nversionInfo:\n  versionCode: '{code}'\n  versionName: 1.0\nunknownFiles:\n  x: y\n"


def man(pkg: str = "com.x", code: str = "1", extra: str = "") -> str:
    return f'<?xml version="1.0"?>\n<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="{code}" package="{pkg}"{extra}>\n<application/></manifest>\n'


def warn(tmp_path, a, b) -> list[str]:
    return buildstage._version_warnings(tree(tmp_path / "a", *a), tree(tmp_path / "b", *b))


def test_peringatan_tidak_ada_bila_sama(tmp_path):
    assert warn(tmp_path, (yml(), man()), (yml(), man())) == []


def test_peringatan_package_dan_version_code_berubah(tmp_path):
    assert warn(tmp_path, (yml(), man()), (yml(), man(pkg="com.lain"))) == ["package_berubah"]
    assert warn(tmp_path, (yml(), man()), (yml("2"), man())) == ["version_code_berubah"]
    assert warn(tmp_path, (yml(), man()), (yml("2"), man("com.lain", "2"))) == ["package_berubah", "version_code_berubah"]


def test_peringatan_platform_build_version_code_bukan_version_code(tmp_path):
    base = (None, man(extra=' platformBuildVersionCode="33"'))
    new = (None, man(extra=' platformBuildVersionCode="34"'))
    assert warn(tmp_path, base, new) == []
    assert warn(tmp_path, base, (None, man(code="9", extra=' platformBuildVersionCode="33"'))) == ["version_code_berubah"]


def test_peringatan_perubahan_hanya_di_apktool_yml_terdeteksi(tmp_path):
    assert warn(tmp_path, (yml("1"), man(code="1")), (yml("7"), man(code="1"))) == ["version_code_berubah"], "apktool.yml MENANG atas manifest"


def test_peringatan_perubahan_hanya_di_manifest_terdeteksi(tmp_path):
    assert warn(tmp_path, (None, man(code="1")), (None, man(code="5"))) == ["version_code_berubah"]
    assert warn(tmp_path, (yml("1"), man(code="1")), (yml("1"), man(code="5"))) == [], "yml dipakai bila ada: manifest tak dibandingkan untuk versionCode"


def test_peringatan_rename_manifest_package(tmp_path):
    assert warn(tmp_path, (yml(), man()), (yml(rename="com.baru"), man())) == ["package_berubah"]
    assert warn(tmp_path, (yml(rename="com.a"), man()), (yml(rename="com.a"), man(pkg="com.lain"))) == []


def test_peringatan_manifest_lebih_256kib_perbandingan_gagal(tmp_path):
    big = man(extra=" " * (257 * 1024))
    assert warn(tmp_path, (yml(), man()), (yml("2"), big)) == ["perbandingan_versi_gagal"]


def test_peringatan_tag_manifest_tak_ada_perbandingan_gagal(tmp_path):
    assert warn(tmp_path, (yml(), man()), (yml(), "<bukan-manifest/>")) == ["perbandingan_versi_gagal"]
    assert warn(tmp_path, (yml(), man()), (yml(), None)) == ["perbandingan_versi_gagal"]


def test_peringatan_manifest_tanda_kutip_tunggal(tmp_path):
    assert warn(tmp_path, (yml(), "<manifest package='com.x'/>"), (yml(), "<manifest package='com.y'/>")) == ["package_berubah"]


def test_peringatan_tanpa_parser_xml():
    tree_ = ast.parse(Path(buildstage.__file__).read_text())
    mods = {n.module for n in ast.walk(tree_) if isinstance(n, ast.ImportFrom) and n.module} | {a.name for n in ast.walk(tree_) if isinstance(n, ast.Import) for a in n.names}
    assert not [m for m in mods if m.startswith(("xml", "lxml", "defusedxml"))]


def test_peringatan_versi_dihitung_sebelum_src_dihapus(bun, monkeypatch):
    seen = {}
    real = buildstage._version_warnings

    def spy(base, src):
        seen["src_ada"] = Path(src).is_dir()
        return real(base, src)

    monkeypatch.setattr(buildstage, "_version_warnings", spy)
    assert bun.brun(xapk_bytes(), "xapk")["status"] == "ok" and seen["src_ada"] is True


def test_peringatan_masuk_hasil_paket(bun):
    (bun.base / "apktool.yml").write_text(yml("1"))
    (bun.project / "apktool.yml").write_text(yml("1"))
    (bun.project / "apktool.yml").write_text(yml("3"))
    res = bun.brun(xapk_bytes(), "xapk")
    assert res["status"] == "ok" and res["warnings"] == ["version_code_berubah"]


# ======================================================================================== kebersihan kode
def test_buildstage_tanpa_shell_dan_nama_split_dari_sistem():
    text = Path(buildstage.__file__).read_text()
    assert "shell=True" not in text and "os.system" not in text
    assert "split-%03d" in text or "split-{" in text, "nama split dibuat sistem, bukan dari nama entri arsip"


def test_daemon_meneruskan_batas_salinan_dan_ekstraksi(bun):
    env = bun.daemon.build_env()
    assert env.upload_cap_bytes == bundle.UPLOAD_COPY_MAX_RUNNER_MB * MIB and env.max_split_bytes == bun.daemon.MAX_BASE_APK_BYTES


def test_buildstage_sinkron_dengan_buildproto_kode_galat():
    for code in ("bundle_changed", "bundle_invalid", "split_missing", "split_invalid", "bundle_too_large", "memfd_unavailable"):
        assert code in buildproto.BUILD_ERROR_CODES
