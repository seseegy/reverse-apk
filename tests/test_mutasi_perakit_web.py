"""Tes tambahan hasil UJI MUTASI fase 4 (Tahap 3): perakit paket (`bundleout`), worker (`worker/builds.py`), skrip install-multiple, dan `artifact-info` (web).

Mutan yang sebelumnya SELAMAT adalah pagar berlapis (lapisan kedua "tidak bergantung pada parse_result" dan sejenisnya) atau pemeriksaan yang hanya terlihat lewat
pesan galat/urutan. Tes ini memanggil lapisan itu langsung atau menyuntikkan kegagalan di antara dua langkah. Lulus di kode asli, tidak bergantung root/uid.
"""

from __future__ import annotations

import dataclasses
import io
import json
import os
import re
import threading
import zipfile
from contextlib import closing

import pytest
from rvcore import bundle as bundle_mod
from rvcore import bundleout as O
from rvcore import installscript
from rvcore.bundleout import AssembleError, SignedFile

import test_buildctl_bundle as tb
import test_bundleout as _bo
import test_installscript as _ti
import test_worker_bundle as _wb
from build_rig import OWNER, sha
from test_buildctl_bundle import _done_bundle
from test_bundle import zip_bytes
from test_bundleout import BASE, xapk
from test_installscript import script
from test_worker_bundle import failed_with, no_leftovers, xapk_build

# fixture dipakai ulang lewat penugasan (pola yang sama dengan test_runner_build_bundle.rig): pytest menemukannya sebagai nama tingkat modul
brig, sh, B, rig, ctl, env, ctl_mod = _bo.rig, _ti.sh, _wb.B, _wb.rig, tb.ctl, tb.env, tb.ctl_mod


# ======================================================================================== bundleout (perakit)
def _bounded(fn, fifo_path, seconds=5):
    """Jalankan `fn` di utas; menggantung pada FIFO (O_NONBLOCK hilang) -> dilepas lalu GAGAL cepat. Mengembalikan pengecualian yang dilempar `fn` (atau None)."""
    box: dict = {}

    def target():
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001
            box["e"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        os.close(os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK))
        t.join(2)
        pytest.fail("menggantung pada FIFO: pembukaan harus O_NONBLOCK")
    return box.get("e")


def test_isi_berkas_ttd_beda_tertangkap_saat_disalin_dengan_pesan_isi(brig):
    data, _ = xapk()
    brig.prepare(data)
    (brig.bdir / "signed-002.apk").write_bytes(b"X" * len(brig.signed["signed-002.apk"]))        # ukuran sama, isi beda
    with pytest.raises(AssembleError, match="Isi berkas bertanda tangan") as ei:                # bukan lapisan verifikasi ulang paket
        brig.run()
    assert ei.value.code == "artifact_changed"


def test_ukuran_beda_tertangkap_oleh_pembukaan_dengan_pesan_ukuran(brig):
    data, _ = xapk()
    brig.prepare(data)
    p = brig.bdir / "signed-001.apk"
    p.write_bytes(p.read_bytes() + b"+")
    with pytest.raises(AssembleError, match="ukuran beda") as ei:
        brig.run()
    assert ei.value.code == "artifact_changed"


def test_fifo_sebagai_berkas_ttd_berukuran_nol_tetap_ditolak(brig):
    data, _ = xapk()
    brig.prepare(data)
    p = brig.bdir / "signed-001.apk"
    p.unlink()
    os.mkfifo(p)                                                                                    # nlink 1; dengan size laporan 0 dan hash string kosong hanya S_ISREG yang menolak
    brig.splits[0] = SignedFile("signed-001.apk", sha(b""), 0)
    exc = _bounded(brig.run, p)
    assert isinstance(exc, AssembleError) and exc.code == "artifact_changed" and "bukan berkas biasa" in exc.message
    assert not (brig.bdir / ".bundle-aa.tmp").exists()


def test_fifo_berkas_ttd_tidak_menggantung_perakit(brig):
    data, _ = xapk()
    brig.prepare(data)
    p = brig.bdir / "signed-001.apk"
    p.unlink()
    os.mkfifo(p)
    exc = _bounded(brig.run, p)
    assert isinstance(exc, AssembleError) and exc.code == "artifact_changed"


def test_hash_file_at_hardlink_dan_fifo_ditolak_berkas_biasa_diterima(tmp_path):
    d = tmp_path / "b"
    d.mkdir()
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        (d / "skrip.sh").write_bytes(b"isi")
        assert O.hash_file_at(fd, "skrip.sh") == (sha(b"isi"), 3)
        os.link(d / "skrip.sh", tmp_path / "tautan")
        with pytest.raises(AssembleError, match="satu tautan") as ei:
            O.hash_file_at(fd, "skrip.sh")
        assert ei.value.code == "artifact_changed"
        os.mkfifo(d / "fifo")
        with pytest.raises(AssembleError, match="bukan berkas biasa") as ei:                          # ditolak oleh S_ISREG, bukan oleh galat baca EAGAIN di bawahnya
            O.hash_file_at(fd, "fifo")
        assert ei.value.code == "artifact_changed"
    finally:
        os.close(fd)


def test_tmp_paket_yang_sudah_ada_berkas_biasa_tidak_ditimpa_o_excl(brig):
    data, _ = xapk()
    brig.prepare(data)
    (brig.bdir / ".bundle-aa.tmp").write_bytes(b"milik-orang-lain")
    with pytest.raises(AssembleError) as ei:
        brig.run()
    assert ei.value.code == "assemble_failed" and (brig.bdir / ".bundle-aa.tmp").read_bytes() == b"milik-orang-lain"


def test_write_new_file_tidak_menimpa_berkas_yang_sudah_ada(brig):
    (brig.bdir / ".install-aa.tmp").write_bytes(b"lama")
    with pytest.raises(AssembleError) as ei:
        O.write_new_file(brig.fd, ".install-aa.tmp", b"baru")
    assert ei.value.code == "assemble_failed" and (brig.bdir / ".install-aa.tmp").read_bytes() == b"lama"
    O.write_new_file(brig.fd, ".install-bb.tmp", b"baru")
    assert (brig.bdir / ".install-bb.tmp").read_bytes() == b"baru"


def _assembled_out(brig):
    data, _ = xapk()
    brig.prepare(data)
    brig.run()
    keep = list(brig.zf.infolist())
    target = {brig.plan.base: brig.base, **dict(zip(O.final_split_names(brig.plan, []), brig.splits))}
    return keep, target


def test_verify_menolak_urutan_atau_nama_entri_yang_beda_dari_rencana(brig):
    keep, target = _assembled_out(brig)
    with open(brig.bdir / ".bundle-aa.tmp", "rb") as out:
        with pytest.raises(AssembleError, match="Daftar entri") as ei:
            O._verify(out, list(reversed(keep)), brig.zf, target, None, brig.check)
    assert ei.value.code == "assemble_failed"


def test_verify_menolak_apk_bertanda_tangan_yang_hash_nya_beda_dari_laporan_signer(brig):
    keep, target = _assembled_out(brig)
    target[BASE] = SignedFile(BASE, "0" * 64, target[BASE].size)
    with brig.out() as written:
        patched = written.read("manifest.json")                                                   # manifest hasil patch dianggap sah; hanya hash APK yang berbeda
    with open(brig.bdir / ".bundle-aa.tmp", "rb") as out:
        with pytest.raises(AssembleError, match="paket hasil tidak sama dengan laporan signer") as ei:
            O._verify(out, keep, brig.zf, target, patched, brig.check)
    assert ei.value.code == "artifact_changed"


def test_verify_menolak_manifest_json_yang_beda_dari_yang_ditulis(brig):
    keep, target = _assembled_out(brig)
    with open(brig.bdir / ".bundle-aa.tmp", "rb") as out:
        with pytest.raises(AssembleError, match="manifest.json di paket hasil") as ei:
            O._verify(out, keep, brig.zf, target, b"{}", brig.check)
    assert ei.value.code == "assemble_failed"


def test_tanggal_entri_dan_direktori_deflated_dipertahankan_sebagaimana_aturan(brig):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("manifest.json", (2011, 2, 3, 4, 5, 6)), json.dumps({"split_apks": [{"file": BASE, "id": "base"}]}))
        z.writestr(zipfile.ZipInfo(BASE, (2012, 3, 4, 5, 6, 8)), b"PK")
        zi = zipfile.ZipInfo("Android/", (2013, 4, 5, 6, 7, 8))
        zi.compress_type = zipfile.ZIP_DEFLATED                                                       # direktori dideflate oleh pembuat asal
        z.writestr(zi, b"")
    brig.prepare(buf.getvalue())
    brig.run()
    with brig.out() as z:
        assert z.getinfo("manifest.json").date_time == (2011, 2, 3, 4, 5, 6) and z.getinfo(BASE).date_time == (2012, 3, 4, 5, 6, 8)
        assert z.getinfo("Android/").date_time == (2013, 4, 5, 6, 7, 8) and z.getinfo("Android/").compress_type == zipfile.ZIP_STORED


class _Rd:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def read(self, n):
        return self.chunks.pop(0) if self.chunks else b""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeIn:
    def __init__(self, chunks):
        self.chunks = chunks

    def open(self, info):
        return _Rd(self.chunks)


def _copy(chunks, declared=10):
    info = zipfile.ZipInfo("icon.png")
    info.file_size = declared
    with zipfile.ZipFile(io.BytesIO(), "w") as zout:
        O._copy_member(zout, _FakeIn(chunks), info, lambda: None)


def test_copy_member_isi_melebihi_atau_kurang_dari_terdeklarasi_ditolak():
    _copy([b"x" * 10])                                                                                # pas: diterima
    with pytest.raises(AssembleError, match="melebihi ukuran terdeklarasi"):
        _copy([b"x" * 6, b"y" * 6])
    with pytest.raises(AssembleError, match="lebih pendek"):
        _copy([b"x" * 4])


def test_patch_manifest_verifikasi_hasil_patch_menolak_patch_yang_mendarat_di_tempat_salah(monkeypatch):
    raw = b'{"total_size": 10, "n": 7}'
    monkeypatch.setattr(O, "_TOTAL_RE", re.compile(rb'"n": (\d+)'))                                    # cocok tepat satu kali, tetapi BUKAN pada total_size
    out, note = O.patch_manifest(raw, {"a.apk": 10}, {"a.apk": 9}, ["a.apk"])
    assert out == raw and note == "tidak_diperbarui(verifikasi_gagal)"


# ======================================================================================== worker (_check_sign_result, _plan_matches, urutan terbit)
def _good_res(n=2):
    rows = [{"index": i, "input_sha256": sha(b"in%d" % i), "output_sha256": sha(b"out%d" % i), "output_size": 10, "cert_sha256": OWNER, "v2": True, "v3": True, "signer_count": 1}
            for i in range(1, n + 1)]
    return {"ok": True, "cert_sha256": OWNER, "verify": {"v2": True, "v3": True}, "signer_count": 1, "output_size": 5, "output_sha256": sha(b"base-out"),
            "input_sha256": sha(b"base-in"), "splits": rows}


def _sent(n=2):
    return [{"index": i, "sha256": sha(b"in%d" % i), "size": 3} for i in range(1, n + 1)]


def test_check_sign_result_baseline_lolos(B):
    assert B._check_sign_result(_good_res(), OWNER, sha(b"base-in"), _sent()) is None


@pytest.mark.parametrize("name,mutate,code", [
    ("index_geser", lambda r: r["splits"][1].update(index=5), "sign_bad_result"),
    ("index_bukan_int", lambda r: r["splits"][0].update(index=True), "sign_bad_result"),
    ("baris_bukan_dict", lambda r: r["splits"].__setitem__(0, None), "sign_bad_result"),
    ("v2_false", lambda r: r["splits"][0].update(v2=False), "sign_bad_result"),
    ("v3_false", lambda r: r["splits"][1].update(v3=False), "sign_bad_result"),
    ("v2_truthy_bukan_true", lambda r: r["splits"][0].update(v2=1), "sign_bad_result"),
    ("signer_dua", lambda r: r["splits"][0].update(signer_count=2), "sign_bad_result"),
    ("signer_bukan_int", lambda r: r["splits"][0].update(signer_count=True), "sign_bad_result"),
    ("ukuran_nol", lambda r: r["splits"][0].update(output_size=0), "sign_bad_result"),
    ("ukuran_bukan_int", lambda r: r["splits"][0].update(output_size="10"), "sign_bad_result"),
    ("hash_keluaran_bukan_hex", lambda r: r["splits"][1].update(output_sha256="xyz"), "sign_bad_result"),
    ("hash_keluaran_hilang", lambda r: r["splits"][1].pop("output_sha256"), "sign_bad_result"),
    ("input_sha_beda", lambda r: r["splits"][0].update(input_sha256="1" * 64), "artifact_changed"),
    ("cert_beda", lambda r: r["splits"][1].update(cert_sha256="2" * 64), "sign_cert_mismatch"),
    ("jumlah_kurang", lambda r: r.update(splits=r["splits"][:1]), "sign_bad_result"),
    ("bidang_splits_hilang", lambda r: r.pop("splits"), "sign_bad_result"),
])
def test_check_sign_result_menolak_tiap_cacat_per_split_langsung(B, name, mutate, code):
    res = _good_res()
    mutate(res)
    got = B._check_sign_result(res, OWNER, sha(b"base-in"), _sent())
    assert got is not None and got[0] == code, name


def test_plan_matches_tiap_syarat_berdiri_sendiri(B):
    data, _ = xapk()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        plan = bundle_mod.plan_from_zip(zf)
    n = len(plan.apk_order)
    good = {"aliases": [], "plan_sha256": plan.plan_sha256, "splits": [{}] * n}
    assert B._plan_matches(plan, "xapk", good) is True
    assert B._plan_matches(plan, "apks", good) is False, "format rencana harus sama dengan format build"
    assert B._plan_matches(plan, "xapk", {**good, "splits": [{}] * (n + 1)}) is False
    assert B._plan_matches(plan, "xapk", {**good, "splits": []}) is False
    assert B._plan_matches(plan, "xapk", {**good, "plan_sha256": "0" * 64}) is False
    assert B._plan_matches(plan, "xapk", {**good, "aliases": [0]}) is False


def test_rencana_dihitung_ulang_saat_merakit_dan_harus_sama_dengan_laporan_runner(rig, B, monkeypatch):
    aid, bid, *_ = xapk_build(rig)
    calls = {"n": 0}
    real = bundle_mod.plan_from_zip

    def second_differs(zf):
        calls["n"] += 1
        plan = real(zf)
        return plan if calls["n"] <= 2 else dataclasses.replace(plan, plan_sha256="0" * 64)      # runner palsu (1) dan precheck (2) lolos; pembacaan di perakit (3) berbeda

    monkeypatch.setattr(bundle_mod, "plan_from_zip", second_differs)
    rig.start()
    rig.run(bid)
    failed_with(rig, bid, "bundle_changed")
    assert calls["n"] == 3 and len(rig.signer.jobs) == 1, "signer sudah berjalan; perakit menolak sebelum menerbitkan apa pun"
    no_leftovers(rig, aid, bid)


def test_skrip_di_luar_allowlist_tidak_pernah_diterbitkan(rig, B, monkeypatch):
    aid, bid, *_ = xapk_build(rig)
    monkeypatch.setattr(installscript, "render", lambda *a, **k: "#!/bin/sh\nrm -rf /\n")
    rig.start()
    rig.run(bid)
    failed_with(rig, bid, "assemble_failed")
    assert rig.listing(aid, bid) == ["build.log"]


def test_paket_ditukar_inode_setelah_rename_artifact_changed(rig, B, monkeypatch):
    aid, bid, *_ = xapk_build(rig)
    real = B._rename_over

    def swap_after(bfd, src, dst):
        real(bfd, src, dst)
        if dst.endswith(".xapk"):                                                                     # pihak lain menukar paket yang baru terbit dengan berkas baru (inode lain)
            os.unlink(dst, dir_fd=bfd)
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=bfd)
            os.write(fd, b"pengganti")
            os.close(fd)

    monkeypatch.setattr(B, "_rename_over", swap_after)
    rig.start()
    rig.run(bid)
    failed_with(rig, bid, "artifact_changed")
    no_leftovers(rig, aid, bid)


# ======================================================================================== skrip install-multiple (perilaku)
def test_skrip_membersihkan_direktori_sementara_saat_keluar_normal_dan_gagal(sh, tmp_path):
    tmpdir = tmp_path / "tmpdir"
    tmpdir.mkdir()
    text = script()
    p, _ = sh(text, env={"TMPDIR": str(tmpdir)})
    assert p.returncode == 0, p.stderr
    assert os.listdir(tmpdir) == [], "trap EXIT harus menghapus mktemp -d walau skrip selesai normal"
    p, _ = sh(text, abis="", env={"TMPDIR": str(tmpdir)})                                              # daftar ABI kosong -> exit 1 di tengah
    assert p.returncode == 1 and os.listdir(tmpdir) == [], "trap EXIT juga berlaku saat keluar dengan galat"


# ======================================================================================== artifact-info (web)
def test_artifact_info_catatan_skrip_tidak_ada_di_stage_log_dilaporkan(ctl, env):
    from app import context
    _aid, bid, _meta = _done_bundle("mut-nolog")
    with closing(context.db()) as conn:
        conn.execute("UPDATE build SET stage_log = ? WHERE id = ?", ("signing_mulai=1.0\nsplit_n=2", bid))
        conn.commit()
    r = ctl("artifact-info", str(bid))
    assert r.code == 3 and r["kode"] == "skrip_tidak_ada" and "Catatan build tidak memuat" in r["alasan"], r.text


def test_artifact_info_split_tanpa_android_manifest_dilaporkan(ctl, env, monkeypatch):
    orig = tb._signed_apk
    monkeypatch.setattr(tb, "_signed_apk", lambda tag, extra=None: zip_bytes({"classes.dex": b"dex"}) if tag.endswith("1") else orig(tag, extra))
    _aid, bid, _meta = _done_bundle("mut-nomanifest")
    r = ctl("artifact-info", str(bid))
    assert r.code == 3 and r["kode"] == "split_bermasalah" and "verifikasi=tanpa_manifest" in r["split.2"], r.text


def test_artifact_info_batas_jumlah_apk_ditegakkan(ctl, env, monkeypatch):
    import app.builds as wb
    monkeypatch.setattr(wb, "BUNDLE_MAX_APKS", 2)
    _aid, bid, _meta = _done_bundle("mut-maxapk")                                                      # paket berisi 3 APK
    r = ctl("artifact-info", str(bid))
    assert r.code == 3 and r["kode"] == "split_bermasalah" and "(> 2)" in r["alasan"] and r["split_n"] == "2", r.text


def test_artifact_info_batas_total_byte_split_ditegakkan(ctl, env, monkeypatch):
    import app.builds as wb
    monkeypatch.setattr(wb, "BUNDLE_MAX_BYTES", 1)
    _aid, bid, _meta = _done_bundle("mut-maxbytes")
    r = ctl("artifact-info", str(bid))
    assert r.code == 3 and r["kode"] == "split_bermasalah" and "verifikasi=terlalu_besar" in r["split.1"], r.text


def test_artifact_info_skrip_terlalu_besar_tidak_dibaca(ctl, env, monkeypatch):
    import app.builds as wb
    monkeypatch.setattr(wb, "SCRIPT_MAX_BYTES", 10)
    _aid, bid, _meta = _done_bundle("mut-bigscript")
    r = ctl("artifact-info", str(bid))
    assert r.code == 3 and r["kode"] == "skrip_tidak_ada" and "terlalu besar" in r["alasan"], r.text


def test_atribut_unix_entri_hasil_dinormalkan_bukan_diteruskan_dari_upload(brig):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", json.dumps({"split_apks": [{"file": BASE, "id": "base"}]}))
        z.writestr(BASE, b"PK")
        for name, mode in (("bin/jalan.sh", 0o104755), ("rahasia.txt", 0o100000), ("tanpa-mode.txt", 0)):                    # setuid, tanpa izin, mode Unix nol
            zi = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            zi.external_attr = mode << 16
            z.writestr(zi, b"isi")
    brig.prepare(buf.getvalue())
    brig.run()
    with brig.out() as z:
        for name in ("bin/jalan.sh", "rahasia.txt", "tanpa-mode.txt", "manifest.json", BASE):
            assert z.getinfo(name).external_attr >> 16 == 0o100644, name
