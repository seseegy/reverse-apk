"""Konsistensi dokumen Tahap 3 (XAPK/APKS, sub-area F): docs/deploy.md, PRD 09/01, README, audit.md, .env.example dan skrip `scripts/verify-build.sh`.

Yang dijaga: setiap langkah baru `verify-build` (12a-12f) punya baris gejala di deploy.md DENGAN nama persis seperti di skrip; variabel opsional skrip terdokumentasi; batas jujur
(anti-tamper/packer/Play Integrity/hash .so) dan pengingat cadangan keystore ada; klaim 'diuji' tidak berlebihan (BELUM DIUJI tetap ada); env baru tercantum di .env.example.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(p: str) -> str:
    return (ROOT / p).read_text(encoding="utf-8")


def script_step_names() -> list[str]:
    return re.findall(r'^N12[A-F]="([^"\n]+)"$', read("scripts/verify-build.sh"), re.M)


def deploy_tahap3() -> str:
    deploy = read("docs/deploy.md")
    assert "### Build XAPK/APKS Tahap 3" in deploy, "bagian Tahap 3 belum ada di docs/deploy.md"
    return deploy.split("### Build XAPK/APKS Tahap 3", 1)[1].split("\n## ", 1)[0]


def test_skrip_punya_enam_langkah_paket_dengan_nama_berurutan():
    assert script_step_names() == ["12a prasyarat paket", "12b XAPK build", "12c XAPK verifikasi", "12d XAPK isi", "12e APKS build+verifikasi", "12f negatif set"]


def test_deploy_punya_baris_gejala_untuk_setiap_langkah_baru_dengan_nama_persis():
    section = deploy_tahap3()
    rows = {ln.split("|")[1].strip(): ln for ln in section.splitlines() if ln.startswith("| 12")}
    for name in script_step_names():
        assert name in rows, f"deploy.md tidak punya baris untuk langkah '{name}'"
        cells = [c.strip() for c in rows[name].split("|")[1:-1]]
        assert len(cells) == 3 and all(cells), rows[name]            # Langkah | Arti | Gejala bila GAGAL -- semuanya terisi


def test_gejala_menyebut_kode_dan_tindakan_yang_bisa_dilakukan():
    section = deploy_tahap3()
    for needle in ("make up", "memfd_unavailable", "--check-bundle", "input_unsafe", "input_missing", "stale_signature", "sisa_ttd", "cert_berbeda", "skrip_cocok", "skrip_lint",
                   "split_invalid", "verify_ok", "output_format", "PYTHON3"):
        assert needle in section, needle


def test_deploy_menyatakan_batas_jujur_dan_belum_diuji():
    section = deploy_tahap3()
    for needle in ("anti-tamper", "packer", "Play Integrity", "hash `.so`", "100%", "BELUM DIUJI", "adb install-multiple", "Android 12", "tanpa tautan unduh"):
        assert needle in section, needle
    assert "tidak ada tombol" in section or "tidak ada tautan" in section.lower() or "tanpa tautan unduh" in section


def test_deploy_mengingatkan_cadangan_keystore_di_luar_vps_dan_akibatnya():
    section = deploy_tahap3()
    assert "secrets/signing_keystore.p12" in section and "signing_keystore_pass" in section
    assert re.search(r"di luar VPS|luar VPS", section)
    assert "tanda tangan" in section and ("uninstall" in section or "hapus" in section)       # akibat kehilangan kunci


def test_deploy_mencatat_konfigurasi_yang_berubah_dan_batas_resource():
    section = deploy_tahap3()
    for needle in ("SIGN_MAX_TOTAL_MB", "ZIP_MAX_ENTRIES", "ZIP_MAX_UNCOMPRESSED_MB", "ZIP_MAX_ENTRY_MB", "ZIP_MAX_RATIO", "web", "runner", "worker", "memfd", "ASSEMBLE_TIMEOUT",
                   "BUILD_KEEP", "MAX_UPLOAD_MB", "scripts/make-test-bundles.py"):
        assert needle in section, needle


def test_variabel_opsional_skrip_terdokumentasi_di_deploy():
    head = "\n".join(read("scripts/verify-build.sh").splitlines()[:16])
    deploy = read("docs/deploy.md")
    for var in re.findall(r"^#\s+([A-Z][A-Z0-9_]+)=", head, re.M):
        assert var in deploy, var
    assert "PYTHON3" in deploy


def test_env_baru_tahap3_ada_di_env_example_dan_compose():
    env, compose = read(".env.example"), read("docker-compose.yml")
    assert "SIGN_MAX_TOTAL_MB" in env and "SIGN_MAX_TOTAL_MB" in compose
    # PYTHON3/VB_* hanyalah variabel skrip host (bukan compose): tidak boleh bocor ke compose atau .env.example sebagai pengaturan layanan
    for var in ("PYTHON3", "VB_STRICT_DIFF", "BIG_MB"):
        assert var not in compose, var


def test_prd09_status_tahap3_menyatakan_fr_9_3_ditegakkan_format_asli_dan_batas():
    prd = read("docs/prd/09-bundles-and-workbench.md")
    assert "## Status Tahap 3" in prd
    note = prd.split("## Status Tahap 3", 1)[1].split("\n## ", 1)[0]
    for needle in ("XAPK", "APKS", "FR-9.3", "ditegakkan", "FR-9.17", "format asal", "adb install-multiple", "teks", "aplikasi tidak memanggil adb", "anti-tamper", "Play Integrity",
                   "BELUM DIUJI", "make verify-build", "tanpa tautan unduh", "ASUMSI"):
        assert needle in note, needle
    row = next(ln for ln in prd.splitlines() if ln.startswith("| FR-9.3 |"))
    assert "ditegakkan" in row


def test_prd01_fr_1_2_menyebut_build_paket():
    row = next(ln for ln in read("docs/prd/01-ingestion-storage.md").splitlines() if ln.startswith("| FR-1.2 |"))
    assert "Tahap 3" in row and "200" in row


def test_readme_menyatakan_tahap3_dan_batas_jujur_dan_fixture():
    readme = read("README.md")
    assert "Tahap 3" in readme and "XAPK" in readme and "APKS" in readme
    for needle in ("anti-tamper", "Play Integrity", "BELUM DIUJI", "scripts/make-test-bundles.py", "adb install-multiple", "signing_keystore.p12"):
        assert needle in readme, needle


def test_audit_punya_entri_tahap3_dengan_risiko_dan_yang_belum_terbukti():
    audit = read("audit.md")
    assert "### 10.19 " in audit
    entry = audit.split("### 10.19 ", 1)[1]
    for needle in ("Tahap 3", "META-INF", "stale_signature", "Belum terbukti", "memfd", "ASUMSI", "adb", "make verify-build", "anti-tamper", "kunci"):
        assert needle in entry, needle


def test_tidak_ada_klaim_100_persen_tanpa_penyangkal():
    for p in ("README.md", "docs/deploy.md", "docs/prd/09-bundles-and-workbench.md"):
        for ln in read(p).splitlines():
            if re.search(r"(berfungsi|jalan|dijamin)[^.\n]{0,40}100\s?%", ln, re.I):
                assert re.search(r"tidak|bukan|jangan|tak ", ln, re.I), f"{p}: {ln.strip()[:120]}"
