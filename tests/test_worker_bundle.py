"""Worker `run_build` untuk paket XAPK/APKS (Tahap 3, sub-area D): runner + signer PALSU (protokol nyata, tests/build_rig.py), DB sementara, upload nyata di tmp.

Dibuktikan: format asal terjaga (XAPK->XAPK, APKS->APKS) dengan nama/urutan entri dari UPLOAD; sertifikat/hash/v2/v3 diperiksa per split; set tidak setengah-jadi pada
kegagalan atau pembatalan (paket DAN skrip hilang); skrip pasang bersaudara; sisa dibersihkan; retensi BUILD_KEEP membersihkan set multi-berkas; margin job RQ.
Tidak dibuktikan: apksigner/zipalign nyata (signer palsu), RQ nyata, kontainer.
"""

from __future__ import annotations

import ast
import io
import os
import re
import zipfile

import build_rig as br
import pytest
from build_rig import OWNER, OTHER, Rig, bm, sha
from conftest import ROOT
from rvcore import buildproto, bundle, installscript, signspool, store
from test_bundle import apks_default, apks_universal
from test_bundleout import BASE, OBB, SPLITS, xapk as xapk_total

SERVICES = ROOT / "services"


@pytest.fixture
def rig(tmp_path):
    r = Rig(tmp_path)
    yield r
    r.stop()


@pytest.fixture
def B(monkeypatch):
    mod = bm()
    monkeypatch.setattr(mod, "POLL_INTERVAL", 0.02)
    return mod


def xapk_build(rig, **kw):
    data, apks = xapk_total(**kw)
    aid = rig.bundle_analysis(data, "xapk", filename="contoh.xapk")
    return aid, rig.build(aid, source_kind="xapk"), data, apks


def package_of(rig, aid, bid) -> zipfile.ZipFile:
    return zipfile.ZipFile(rig.bdir(aid, bid) / rig.row(bid)["output_name"])


# ====================================================================================== jalur sukses
def test_bundle_xapk_end_to_end_shim(rig, B):
    aid, bid, data, apks = xapk_build(rig)
    rig.start()
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["error_code"], row["verify_ok"], row["output_format"], row["source_kind"], row["cert_sha256"]) == ("done", None, 1, "xapk", "xapk", OWNER)
    pkg, script = f"com.contoh.app-modified-{bid}.xapk", f"com.contoh.app-modified-{bid}-install.sh"
    assert row["output_name"] == pkg and rig.listing(aid, bid) == sorted(["build.log", pkg, script]), "src/, unsigned.apk, split-*, signed* hilang"
    body = (rig.bdir(aid, bid) / pkg).read_bytes()
    assert (row["output_sha256"], row["output_size"]) == (sha(body), len(body))
    z = zipfile.ZipFile(io.BytesIO(body))
    src = zipfile.ZipFile(io.BytesIO(data))
    assert z.namelist() == src.namelist(), "nama dan urutan entri dari upload"
    assert z.read(BASE).endswith(b"+SIGNED") and z.read(SPLITS[0]).endswith(b"+SIGNED") and z.read(OBB) == src.read(OBB) and z.read("icon.png") == src.read("icon.png")
    text = (rig.bdir(aid, bid) / script).read_text()
    assert installscript.lint(text) == [] and f"BUNDLE='{pkg}'" in text and f"add '{SPLITS[0]}' 'arm64_v8a'" in text and "obb '" in text
    log = row["stage_log"]
    assert "split_n=2" in log and re.search(rf"(?m)^install_script={re.escape(script)} sha256={sha(text.encode())}$", log) and "manifest_total_size=diperbarui(" in log
    assert "tanda_tangan: " in log and "/data" not in log
    # permintaan: runner membawa source_kind; signer membawa hash split milik runner dan tenggat diskalakan 10 dtk per split
    assert rig.runner.jobs[0]["source_kind"] == "xapk"
    result_splits = rig.signer.jobs[0]["splits"]
    assert len(result_splits) == 2 and all(re.fullmatch(r"[0-9a-f]{64}", h) for h in result_splits)
    assert rig.signer.jobs[0]["timeout"] == 30 + 10 * 2


def test_bundle_apks_end_to_end_shim_alias_dan_dropped(rig, B):
    data = apks_default()
    aid = rig.bundle_analysis(data, "apks", filename="contoh.apks")
    bid = rig.build(aid, source_kind="apks")
    rig.start()
    rig.run(bid)
    row = rig.row(bid)
    assert (row["status"], row["output_format"], row["output_name"]) == ("done", "apks", f"com.contoh.app-modified-{bid}.apks")
    z = package_of(rig, aid, bid)
    assert z.namelist() == zipfile.ZipFile(io.BytesIO(data)).namelist()
    assert z.read("splits/base-master.apk") == z.read("splits/base-master_2.apk") and z.read("splits/base-master.apk").endswith(b"+SIGNED")
    assert z.read("toc.pb") == b"\x0a\x00"
    script = (rig.bdir(aid, bid) / f"com.contoh.app-modified-{bid}-install.sh").read_text()
    adds = [ln for ln in script.splitlines() if ln.startswith("add ")]
    assert adds[0] == "add 'splits/base-master.apk' ''" and not any("master_2" in a for a in adds) and len(adds) == 3
    assert "obb " not in "\n".join(ln for ln in script.splitlines() if ln.startswith("obb"))


def test_bundle_xapk_tanpa_split_n0_lewat_jalur_paket(rig, B):
    aid, bid, data, _ = xapk_build(rig, splits=())
    rig.start()
    rig.run(bid)
    row = rig.row(bid)
    assert row["status"] == "done" and row["output_name"].endswith(".xapk") and package_of(rig, aid, bid).read(BASE).endswith(b"+SIGNED")
    assert rig.signer.jobs[0].get("splits") in (None, [])


def test_bundle_apks_universal_tanpa_split(rig, B):
    data = apks_universal()
    aid = rig.bundle_analysis(data, "apks", filename="u.apks")
    bid = rig.build(aid, source_kind="apks")
    rig.start()
    rig.run(bid)
    row = rig.row(bid)
    assert row["status"] == "done" and package_of(rig, aid, bid).read("universal.apk").endswith(b"+SIGNED") and package_of(rig, aid, bid).read("toc.pb") == b"\x0a\x00"


def test_apk_tunggal_jalur_publish_lama_tak_berubah(rig, B):
    aid = rig.analysis()
    rig.start()
    bid = rig.build(aid)
    rig.run(bid)
    row = rig.row(bid)
    assert row["output_format"] == "apk" and row["output_name"].endswith(".apk") and rig.listing(aid, bid) == sorted(["build.log", row["output_name"]])
    assert "source_kind" not in rig.runner.jobs[0] and "splits" not in rig.signer.jobs[0]


def test_nama_entri_dari_upload_bukan_hasil_runner(rig, B):
    aid, bid, data, _ = xapk_build(rig)

    def runner(r, job_id, job):
        res = br.FakeRunner.default(r, job_id, job)
        for sp in res["splits"]:
            sp["name"] = "../../etc/passwd"
        res["splits"][0]["nama"] = "x"
        return res

    rig.start(runner=runner)
    rig.run(bid)
    assert rig.row(bid)["status"] == "done"
    assert package_of(rig, aid, bid).namelist() == zipfile.ZipFile(io.BytesIO(data)).namelist()


# ====================================================================================== kegagalan runner/rencana
def failed_with(rig, bid, code):
    row = rig.row(bid)
    assert (row["status"], row["error_code"]) == ("failed", code), (row["status"], row["error_code"], row["error_text"])
    return row


def no_leftovers(rig, aid, bid):
    left = rig.listing(aid, bid)
    assert not [n for n in left if n.startswith((".bundle-", ".install-", ".split-", ".alias-", "split-", "signed", "unsigned", "src")) or n.endswith((".xapk", ".apks", ".sh"))], left


def test_plan_sha_beda_bundle_changed_dan_signer_tidak_dipanggil(rig, B):
    aid, bid, *_ = xapk_build(rig)

    def runner(r, job_id, job):
        res = br.FakeRunner.default(r, job_id, job)
        res["plan_sha256"] = "0" * 64
        return res

    rig.start(runner=runner)
    rig.run(bid)
    failed_with(rig, bid, "bundle_changed")
    assert rig.signer.jobs == [] and rig.listing(aid, bid) == ["build.log"]


def test_jumlah_split_hasil_beda_bundle_changed(rig, B):
    aid, bid, *_ = xapk_build(rig)

    def runner(r, job_id, job):
        res = br.FakeRunner.default(r, job_id, job)
        res["splits"] = res["splits"][:1]
        return res

    rig.start(runner=runner)
    rig.run(bid)
    failed_with(rig, bid, "bundle_changed")


def test_alias_di_luar_kandidat_bundle_changed(rig, B):
    aid, bid, *_ = xapk_build(rig)

    def runner(r, job_id, job):
        res = br.FakeRunner.default(r, job_id, job)
        res["aliases"] = [0]
        res["splits"] = res["splits"][:1]
        return res

    rig.start(runner=runner)
    rig.run(bid)
    failed_with(rig, bid, "bundle_changed")


def test_runner_melaporkan_format_lain_bundle_changed(rig, B):
    aid, bid, *_ = xapk_build(rig)

    def runner(r, job_id, job):
        res = br.FakeRunner.default(r, job_id, job)
        res["source_kind"] = "apks"
        return res

    rig.start(runner=runner)
    rig.run(bid)
    failed_with(rig, bid, "bundle_changed")


def test_upload_ditukar_bundle_changed_signer_tidak_dipanggil(rig, B):
    aid, bid, data, _ = xapk_build(rig)

    def runner(r, job_id, job):
        res = br.FakeRunner.default(r, job_id, job)
        (r.layout.upload_path(job["sha256"])).write_bytes(b"lain sama sekali")
        return res

    rig.start(runner=runner)
    rig.run(bid)
    failed_with(rig, bid, "bundle_changed")
    assert rig.signer.jobs == [] and rig.listing(aid, bid) == ["build.log"]


def test_upload_ditukar_setelah_ditandatangani_bundle_changed(rig, B):
    aid, bid, data, _ = xapk_build(rig)

    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        s.layout.upload_path(rig.row(job["build_id"]) and rig.analysis_sha(aid)).write_bytes(b"lain")
        return res

    rig.analysis_sha = lambda a: store.get_analysis(rig.conn(), a)["sha256"]
    rig.start(signer=signer)
    rig.run(bid)
    failed_with(rig, bid, "bundle_changed")
    no_leftovers(rig, aid, bid)


def test_upload_hilang_bundle_changed(rig, B):
    aid, bid, *_ = xapk_build(rig)
    sha_ = store.get_analysis(rig.conn(), aid)["sha256"]

    def runner(r, job_id, job):
        res = br.FakeRunner.default(r, job_id, job)
        r.layout.upload_path(sha_).unlink()
        return res

    rig.start(runner=runner)
    rig.run(bid)
    failed_with(rig, bid, "bundle_changed")


def test_worker_memfd_cap_256mib(rig, B, monkeypatch):
    assert bundle.UPLOAD_COPY_MAX_WORKER_MB == 256
    aid, bid, *_ = xapk_build(rig)
    monkeypatch.setattr(bundle, "UPLOAD_COPY_MAX_WORKER_MB", 0)
    rig.start()
    rig.run(bid)
    failed_with(rig, bid, "bundle_too_large")


def test_kode_galat_runner_paket_diterima_store(rig, B):
    for code in ("split_missing", "split_invalid", "bundle_invalid", "bundle_too_large", "memfd_unavailable"):
        aid, bid, *_ = xapk_build(rig)
        if rig.runner is None:
            rig.start()
        rig.runner.behave = lambda r, j, job, c=code: {"status": "failed", "error_code": c, "error_text": ""}
        rig.run(bid)
        row = failed_with(rig, bid, code)
        assert row["error_text"] == buildproto.ERROR_TEXT[code]


# ====================================================================================== hasil signer per split
def sign_with(mutate):
    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        mutate(res, s, job)
        return res
    return signer


@pytest.mark.parametrize("name,mutate,code", [
    ("cert_beda_satu_split", lambda res, s, job: res["splits"][1].update(cert_sha256=OTHER), "sign_cert_mismatch"),
    ("input_sha_split_beda", lambda res, s, job: res["splits"][0].update(input_sha256="1" * 64), "artifact_changed"),
    ("v2_false", lambda res, s, job: res["splits"][0].update(v2=False), "sign_bad_result"),
    ("v3_false", lambda res, s, job: res["splits"][1].update(v3=False), "sign_bad_result"),
    ("dua_penanda_tangan", lambda res, s, job: res["splits"][0].update(signer_count=2), "sign_bad_result"),
    ("hasil_split_kurang", lambda res, s, job: res.update(splits=res["splits"][:1]), "sign_bad_result"),
    ("index_loncat", lambda res, s, job: res["splits"][1].update(index=5), "sign_bad_result"),
    ("tanpa_bidang_splits_gaya_2b", lambda res, s, job: res.pop("splits"), "sign_bad_result"),
])
def test_hasil_signer_per_split_diperiksa(rig, B, name, mutate, code):
    aid, bid, *_ = xapk_build(rig)
    rig.start(signer=sign_with(mutate))
    rig.run(bid)
    failed_with(rig, bid, code)
    no_leftovers(rig, aid, bid)


def test_signer_menolak_stale_signature_seluruh_set_gagal(rig, B):
    aid, bid, *_ = xapk_build(rig)
    rig.start(signer=lambda s, j, job: br.failure_result("stale_signature"))
    rig.run(bid)
    row = failed_with(rig, bid, "sign_stale_signature")
    assert row["error_text"] == signspool.ERROR_TEXT["stale_signature"]
    no_leftovers(rig, aid, bid)


@pytest.mark.parametrize("code", ["input_missing", "input_unsafe", "cert_mismatch", "verify_failed"])
def test_kode_gagal_signer_batch_diteruskan(rig, B, code):
    aid, bid, *_ = xapk_build(rig)
    rig.start(signer=lambda s, j, job: br.failure_result(code))
    rig.run(bid)
    failed_with(rig, bid, f"sign_{code}")


# ====================================================================================== split diubah SESUDAH ditandatangani / hilang / hash tak cocok
@pytest.mark.parametrize("plant", ["isi_diubah_ukuran_sama", "ukuran_beda", "hilang", "symlink", "fifo", "hardlink"])
def test_split_bertanda_tangan_diubah_sesudah_signer_artifact_changed(rig, B, tmp_path, plant):
    aid, bid, *_ = xapk_build(rig)

    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        p = s.layout.build_dir(job["analysis_id"], job["build_id"]) / "signed-002.apk"
        body = p.read_bytes()
        p.unlink()
        if plant == "isi_diubah_ukuran_sama":
            p.write_bytes(b"X" * len(body))
        elif plant == "ukuran_beda":
            p.write_bytes(body + b"!")
        elif plant == "symlink":
            real = tmp_path / "asli"
            real.write_bytes(body)
            p.symlink_to(real)
        elif plant == "fifo":
            os.mkfifo(p)
        elif plant == "hardlink":
            p.write_bytes(body)
            os.link(p, tmp_path / "tautan")
        return res

    rig.start(signer=signer)
    rig.run(bid)
    failed_with(rig, bid, "artifact_changed")
    no_leftovers(rig, aid, bid)


def test_base_bertanda_tangan_diubah_artifact_changed(rig, B):
    aid, bid, *_ = xapk_build(rig)

    def signer(s, job_id, job):
        res = br.FakeSigner.default(s, job_id, job)
        (s.layout.build_dir(job["analysis_id"], job["build_id"]) / "signed.apk").write_bytes(b"palsu")
        return res

    rig.start(signer=signer)
    rig.run(bid)
    failed_with(rig, bid, "artifact_changed")
    no_leftovers(rig, aid, bid)


def test_tmp_paket_ditanam_symlink_gagal_tertutup(rig, B, tmp_path, monkeypatch):
    aid, bid, *_ = xapk_build(rig)
    victim = tmp_path / "korban"
    victim.write_text("asli")
    monkeypatch.setattr(bm().uuid, "uuid4", lambda: type("U", (), {"hex": "a" * 32})())

    def runner(r, job_id, job):
        res = br.FakeRunner.default(r, job_id, job)
        os.symlink(victim, r.layout.build_dir(job["analysis_id"], job["build_id"]) / ".bundle-aaaaaaaaaaaa.tmp")
        return res

    rig.start(runner=runner)
    rig.run(bid)
    failed_with(rig, bid, "assemble_failed")
    assert victim.read_text() == "asli"
    no_leftovers(rig, aid, bid)


# ====================================================================================== pembatalan dan kegagalan di antara dua rename
def test_batal_saat_menandatangani_paket_tidak_terbit(rig, B):
    aid, bid, *_ = xapk_build(rig)

    def signer(s, job_id, job):
        store.request_cancel_build(rig.conn(), job["build_id"])
        return br.FakeSigner.default(s, job_id, job)

    rig.start(signer=signer)
    rig.run(bid)
    assert rig.row(bid)["status"] == "cancelled"
    no_leftovers(rig, aid, bid)


def test_publish_batal_di_antara_dua_rename_keduanya_hilang(rig, B, monkeypatch):
    aid, bid, *_ = xapk_build(rig)
    real = B._rename_over
    calls = []

    def spy(bfd, src, dst):
        real(bfd, src, dst)
        calls.append(dst)
        if len(calls) == 1:
            store.request_cancel_build(rig.conn(), bid)
            B.time.sleep(0.6)                                   # perakit membatasi pemeriksaan DB 2x/dtk

    monkeypatch.setattr(B, "_rename_over", spy)
    rig.start()
    rig.run(bid)
    assert rig.row(bid)["status"] == "cancelled" and len(calls) == 1
    assert rig.listing(aid, bid) == ["build.log"], "skrip yang sudah terbit dihapus; paket tidak pernah terbit"


def test_publish_gagal_di_antara_dua_rename_keduanya_hilang(rig, B, monkeypatch):
    aid, bid, *_ = xapk_build(rig)
    real = B._rename_over
    n = {"i": 0}

    def spy(bfd, src, dst):
        n["i"] += 1
        if n["i"] == 2:
            raise B._changed()
        real(bfd, src, dst)

    monkeypatch.setattr(B, "_rename_over", spy)
    rig.start()
    rig.run(bid)
    failed_with(rig, bid, "artifact_changed")
    assert rig.listing(aid, bid) == ["build.log"]


def test_publish_rename_tujuan_direktori_rmtree_lalu_rename(rig, B):
    aid, bid, *_ = xapk_build(rig)
    pkg, script = f"com.contoh.app-modified-{bid}.xapk", f"com.contoh.app-modified-{bid}-install.sh"

    def runner(r, job_id, job):
        res = br.FakeRunner.default(r, job_id, job)
        d = r.layout.build_dir(job["analysis_id"], job["build_id"])
        for name in (pkg, script):
            (d / name / "dalam").mkdir(parents=True)
            (d / name / "dalam" / "x").write_text("x")
        return res

    rig.start(runner=runner)
    rig.run(bid)
    assert rig.row(bid)["status"] == "done"
    assert (rig.bdir(aid, bid) / pkg).is_file() and (rig.bdir(aid, bid) / script).is_file()


def test_publish_tujuan_symlink_tidak_diikuti(rig, B, tmp_path):
    aid, bid, *_ = xapk_build(rig)
    victim = tmp_path / "korban"
    victim.write_text("asli")
    pkg = f"com.contoh.app-modified-{bid}.xapk"

    def runner(r, job_id, job):
        res = br.FakeRunner.default(r, job_id, job)
        os.symlink(victim, r.layout.build_dir(job["analysis_id"], job["build_id"]) / pkg)
        return res

    rig.start(runner=runner)
    rig.run(bid)
    assert victim.read_text() == "asli"
    if rig.row(bid)["status"] == "done":
        assert not (rig.bdir(aid, bid) / pkg).is_symlink()


def test_perakitan_melewati_tenggat_assemble_timeout(rig, B, monkeypatch):
    aid, bid, *_ = xapk_build(rig)
    monkeypatch.setattr(B, "ASSEMBLE_TIMEOUT", -1)
    rig.start()
    rig.run(bid)
    failed_with(rig, bid, "assemble_timeout")
    no_leftovers(rig, aid, bid)


def test_disk_kurang_no_space_sebelum_merakit(rig, B, monkeypatch):
    aid, bid, *_ = xapk_build(rig)
    monkeypatch.setattr(B, "ASSEMBLE_RESERVE", 1 << 62)
    rig.start()
    rig.run(bid)
    failed_with(rig, bid, "no_space")
    no_leftovers(rig, aid, bid)


def test_urutan_penerbitan_skrip_tmp_paket_tmp_lalu_rename_lalu_finish(rig, B, monkeypatch):
    aid, bid, *_ = xapk_build(rig)
    order = []
    ow, oa, orn, of = B.bundleout.write_new_file, B.bundleout.assemble, B._rename_over, store.finish_build
    monkeypatch.setattr(B.bundleout, "write_new_file", lambda *a, **k: (order.append("skrip_tmp"), ow(*a, **k))[1])
    monkeypatch.setattr(B.bundleout, "assemble", lambda *a, **k: (order.append("paket_tmp"), oa(*a, **k))[1])
    monkeypatch.setattr(B, "_rename_over", lambda b, s, d: (order.append("rename:" + ("skrip" if d.endswith(".sh") else "paket")), orn(b, s, d))[1])
    monkeypatch.setattr(store, "finish_build", lambda *a, **k: (order.append("finish"), of(*a, **k))[1])
    rig.start()
    rig.run(bid)
    assert order == ["skrip_tmp", "paket_tmp", "rename:skrip", "rename:paket", "finish"]


def test_finish_kalah_balapan_pembatalan_menghapus_paket_dan_skrip(rig, B, monkeypatch):
    aid, bid, *_ = xapk_build(rig)
    real = store.finish_build

    def lose(*a, **k):
        raise store.BuildStateError("kalah")

    monkeypatch.setattr(store, "finish_build", lose)
    rig.start()
    rig.run(bid)
    assert rig.listing(aid, bid) == ["build.log"], "paket dan skrip yang sudah dinamai ikut dihapus"
    monkeypatch.setattr(store, "finish_build", real)


# ====================================================================================== pemulihan dan sisa
def test_scrub_membuang_split_signed_bundle_install_tmp(rig, B):
    aid = rig.analysis()
    bid = rig.build(aid)
    d = rig.layout.build_dir(aid, bid)
    d.mkdir(parents=True)
    keep = ["build.log", f"x-modified-{bid}.xapk", f"x-modified-{bid}-install.sh"]
    junk = ["split-001.apk", "split-199.apk.part", "signed-001.apk", "signed-199.apk", ".split-001.raw", ".split-001.raw.part", ".alias-000.raw", ".bundle-abc.tmp",
            ".install-abc.tmp", "unsigned.apk", "signed.apk", ".sign-signed.tmp"]
    for n in keep + junk:
        (d / n).write_text("x")
    (d / "src").mkdir()
    B._scrub_build_dir(rig.layout, aid, bid)
    assert sorted(os.listdir(d)) == sorted(keep)


def test_scrub_dengan_also_daftar_nama_terbit(rig, B):
    aid = rig.analysis()
    bid = rig.build(aid)
    d = rig.layout.build_dir(aid, bid)
    d.mkdir(parents=True)
    for n in ("build.log", "a.xapk", "a-install.sh"):
        (d / n).write_text("x")
    B._scrub_build_dir(rig.layout, aid, bid, also=("a.xapk", "a-install.sh"))
    assert os.listdir(d) == ["build.log"]


# ====================================================================================== penamaan dan margin
@pytest.mark.parametrize("fmt,ext", [("apk", "apk"), ("xapk", "xapk"), ("apks", "apks"), ("zip", "apk"), ("", "apk")])
def test_artifact_name_ekstensi_mengikuti_format(B, fmt, ext):
    assert B.artifact_name("com.x.y", "f.xapk", 7, fmt) == f"com.x.y-modified-7.{ext}"
    assert B.artifact_name("com.x.y", "f.xapk", 7) == "com.x.y-modified-7.apk"


def test_install_script_name_turunan_sistem_dan_panjang_aman(B):
    assert B.install_script_name("com.x.y", "f.apk", 7) == "com.x.y-modified-7-install.sh"
    n = B.install_script_name("a" * 200, "f.apk", 999_999_999)
    assert store._OUTPUT_NAME_RE.fullmatch(n) and n.endswith("-install.sh")
    assert B.install_script_name("../../etc", "x", 1) == "etc-modified-1-install.sh"


def test_job_margin_paket_3800_apk_600(B):
    assert (B.job_margin("apk"), B.job_margin("xapk"), B.job_margin("apks"), B.job_margin("zip")) == (600, 3800, 3800, 600)
    cfg = B.BuildConfig(layout=None, timeout_build=1800, timeout_sign=900, pickup_timeout=1)
    assert cfg.job_timeout == 3300 and cfg.job_timeout_for("xapk") == 1800 + 900 + 3800


def test_job_timeout_margin_paritas_web_worker(B):
    import app.builds as W
    assert (W.JOB_TIMEOUT_MARGIN, W.BUNDLE_JOB_MARGIN) == (B.JOB_TIMEOUT_MARGIN, B.BUNDLE_JOB_MARGIN) and W.BUNDLE_KINDS == B.BUNDLE_KINDS
    for kind in ("apk", "xapk", "apks", "lain"):
        assert W.job_margin(kind) == B.job_margin(kind)
    assert B.BUNDLE_JOB_MARGIN >= 600 + signspool.SIGN_PER_FILE_S * signspool.MAX_SPLITS + B.ASSEMBLE_TIMEOUT - 10


def test_requeue_memakai_margin_menurut_format(rig, B, monkeypatch):
    import fakeredis
    from rq import Queue
    monkeypatch.setenv("DATA_DIR", str(rig.layout.root))
    aid, bid, *_ = xapk_build(rig)
    aid2 = rig.analysis()
    bid2 = rig.build(aid2)
    conn = fakeredis.FakeRedis()
    assert sorted(B.requeue_orphans(conn)) == sorted([bid, bid2])
    q = Queue("jobs", connection=conn)
    timeouts = {int(j.args[0]): j.timeout for j in (q.fetch_job(i) for i in q.job_ids)}
    assert timeouts[bid2] == 1800 + 900 + 600 and timeouts[bid] == 1800 + 900 + 3800


def test_semua_kode_galat_baru_diterima_store_dan_teks_lengkap(B):
    for code in ("bundle_changed", "assemble_failed", "assemble_timeout", "no_space", "artifact_changed"):
        assert re.fullmatch(r"[a-z][a-z0-9_]{0,39}", code) and B.SIGN_TEXT[code].endswith(".")
    assert re.fullmatch(r"[a-z][a-z0-9_]{0,39}", "sign_stale_signature")


def test_builds_tidak_menerbitkan_dengan_replace_dan_semua_rename_dirfd():
    tree = ast.parse((SERVICES / "worker" / "builds.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
            if node.func.attr in ("replace", "rename"):
                assert node.func.attr == "rename" and {k.arg for k in node.keywords} >= {"src_dir_fd", "dst_dir_fd"}
    assert "os.replace" not in (SERVICES / "worker" / "builds.py").read_text()


# ====================================================================================== retensi BUILD_KEEP untuk set multi-berkas
def finished_bundle(rig, aid, *, extra_junk=False) -> int:
    bid = rig.final_build(aid, "done", make_dir=False)
    d = rig.layout.build_dir(aid, bid)
    d.mkdir(parents=True)
    for n in ("build.log", f"x-modified-{bid}.xapk", f"x-modified-{bid}-install.sh"):
        (d / n).write_text(str(bid))
    if extra_junk:
        for n in ("signed-001.apk", "split-001.apk", ".split-001.raw"):
            (d / n).write_text("sisa")
        (d / "src").mkdir()
    return bid


def test_prune_11_build_xapk_sisakan_10_dan_set_analisis_lain_utuh(rig, B):
    a1, a2 = rig.analysis(), rig.analysis()
    first = [finished_bundle(rig, a1, extra_junk=(i == 0)) for i in range(11)]
    other = [finished_bundle(rig, a2) for _ in range(3)]
    removed = B.prune_analysis(rig.conn(), rig.layout, a1, 10)
    assert removed == [first[0]]
    assert not rig.bdir(a1, first[0]).exists() and not rig.exists(first[0]), "direktori set (paket, skrip, sisa) hilang seluruhnya"
    for bid in first[1:]:
        assert sorted(rig.listing(a1, bid)) == sorted(["build.log", f"x-modified-{bid}.xapk", f"x-modified-{bid}-install.sh"])
    for bid in other:
        assert len(rig.listing(a2, bid)) == 3 and rig.exists(bid), "set analisis lain tidak disentuh"


def test_prune_set_multi_berkas_direktori_utuh_dihapus_symlink_dalam_tak_diikuti(rig, B, tmp_path):
    a1 = rig.analysis()
    victim = br.victim(tmp_path)
    ids = [finished_bundle(rig, a1) for _ in range(3)]
    os.symlink(victim / "5", rig.bdir(a1, ids[0]) / "signed-001.apk")
    removed = B.prune_analysis(rig.conn(), rig.layout, a1, 2)
    assert removed == [ids[0]] and not rig.bdir(a1, ids[0]).exists() and br.victim_intact(victim)


def test_tak_ada_artefak_di_luar_folder_build(rig, B):
    aid, bid, *_ = xapk_build(rig)
    rig.start()
    before = set(p for p in rig.layout.root.rglob("*") if p.is_file())
    rig.run(bid)
    new = set(p for p in rig.layout.root.rglob("*") if p.is_file()) - before
    assert rig.row(bid)["status"] == "done"
    allowed = rig.layout.build_dir(aid, bid)
    assert new and all(allowed in p.parents or p.suffix == ".db" or "db" in p.name or p.parent.name in ("signspool", "spool") for p in new), new
