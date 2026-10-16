"""Tes tambahan hasil UJI MUTASI fase 4 (Tahap 3): pemeriksaan `scripts/verify-build.sh` langkah 12b/12c/12d/12f yang hanya terlihat bila SATU syarat dilanggar sendirian.

Tes lama melanggar beberapa syarat sekaligus (mis. sertifikat `OTHER` beda dari DB DAN dari keystore pemilik), sehingga menghapus salah satu pemeriksaan tidak
terdeteksi. `docker` palsu milik `test_verify_build_script` diberi tambahan kenop skenario kecil (penggantian teks yang dijaga: tepat satu kecocokan) tanpa mengubah
berkas tes lama. Tidak bergantung root.
"""

from __future__ import annotations

import pytest

import test_verify_build_script as V
from test_verify_build_script import OTHER, run_ok, status_of

PATCHES = [
    ('cert=OWNER, verify_ok=1, flipped=False)',
     'cert=(sc["bundle_db_cert"] if ext != "apk" and sc.get("bundle_db_cert") else OWNER), verify_ok=1, flipped=False)'),
    ('kv(source_kind=b["kind"], output_format', 'kv(source_kind=sc.get("source_kind", b["kind"]), output_format'),
    ('name=(NAME % b["id"]).replace(".apk", "." + ext),',
     'name=((sc["bundle_name"] if ext != "apk" and sc.get("bundle_name") else NAME) % b["id"]).replace(".apk", "." + ext),'),
    ('            names = list(S["apk_names"])\n            ov = dict(sc.get("bundle_selftest", {}))',
     '            names = [("lain-" + nm if sc.get("rename_entry") and i == 0 else nm) for i, nm in enumerate(S["apk_names"])]\n            ov = dict(sc.get("bundle_selftest", {}))'),
    ('        for n in sorted(map(int, slot.get("splits", {}))):\n            out.append("SPLIT', '        for n in sorted(map(int, slot.get("splits", {})))[:sc.get("split_lines", 99)]:\n            out.append("SPLIT'),
]


@pytest.fixture
def vrig(tmp_path, monkeypatch):
    body = V.FAKE_DOCKER
    for old, new in PATCHES:
        assert body.count(old) == 1, old
        body = body.replace(old, new)
    monkeypatch.setattr(V, "FAKE_DOCKER", body)
    return V.Rig(tmp_path)


def note(rows, step):
    return rows[step][1]


def test_12c_sertifikat_sama_dengan_keystore_tetapi_beda_dari_db_gagal(vrig):
    vrig.scn(bundle_db_cert=OTHER)
    res, rows = run_ok(vrig)
    assert status_of(rows, "12c XAPK verifikasi") == "GAGAL" and "sertifikat build di DB" in note(rows, "12c XAPK verifikasi")
    assert "keystore pemilik" not in note(rows, "12c XAPK verifikasi")


def test_12c_sertifikat_sama_dengan_db_tetapi_beda_dari_keystore_gagal(vrig):
    vrig.scn(bundle_db_cert=OTHER, bundle_selftest={"cert": OTHER})
    res, rows = run_ok(vrig)
    assert status_of(rows, "12c XAPK verifikasi") == "GAGAL" and "keystore pemilik" in note(rows, "12c XAPK verifikasi")
    assert "sertifikat build di DB" not in note(rows, "12c XAPK verifikasi")


def test_12d_skrip_berubah_setelah_terbit_gagal_walau_artifact_info_keluar_nol(vrig):
    vrig.scn(bundle_info={"skrip_cocok": 0})
    res, rows = run_ok(vrig)
    assert status_of(rows, "12d XAPK isi") == "GAGAL" and "skrip_cocok=0" in note(rows, "12d XAPK isi")


def test_12f_kontrol_positif_ditolak_signer_dilaporkan_sebagai_set_bersih_harus_ditandatangani(vrig):
    vrig.scn(sign_cert="lain")
    res, rows = run_ok(vrig)
    assert status_of(rows, "12f negatif set") == "GAGAL"
    assert "kontrol positif (set bersih harus ditandatangani)" in note(rows, "12f negatif set")


def test_12f_kontrol_positif_harus_melaporkan_tepat_dua_baris_split(vrig):
    vrig.scn(split_lines=1)
    res, rows = run_ok(vrig)
    assert status_of(rows, "12f negatif set") == "GAGAL" and "baris SPLIT 1 (harus 2)" in note(rows, "12f negatif set")


def test_12b_source_kind_di_status_harus_sama_dengan_format_sampel(vrig):
    vrig.scn(source_kind="apk")
    res, rows = run_ok(vrig)
    assert status_of(rows, "12b XAPK build") == "GAGAL" and "source_kind=apk" in note(rows, "12b XAPK build")


def test_12b_nama_keluaran_harus_cocok_pola_modified_id_format(vrig):
    vrig.scn(bundle_name="app-gantian-%d.apk")
    res, rows = run_ok(vrig)
    assert status_of(rows, "12b XAPK build") == "GAGAL" and "tidak cocok pola" in note(rows, "12b XAPK build")


def test_12c_nama_entri_apk_harus_sama_dengan_sampel_walau_jumlah_sama(vrig):
    vrig.scn(rename_entry=True)
    res, rows = run_ok(vrig)
    assert status_of(rows, "12c XAPK verifikasi") == "GAGAL" and "nama entri APK beda dari sampel" in note(rows, "12c XAPK verifikasi")
