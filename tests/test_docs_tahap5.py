"""Konsistensi dokumen dan teks kode Tahap 5 (tab Build di web): PRD 05/06/09, README, docs/deploy.md, audit.md 10.21, `builds.NO_DOWNLOAD_NOTICE`, prompt AI, compose.

Yang dijaga: klaim yang belum teruji tetap ditandai BELUM DIUJI; FR-9.24/9.41 tercatat terpenuhi dan 9.34 menyebut tombol web; sisa kalimat lama ("menyusul di Tahap 5", "baru Tahap 5",
"CLI-only") tidak lagi dipakai sebagai keadaan saat ini; runbook deploy hanya memakai perintah yang benar-benar ada di CLI/pembantu.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(p: str) -> str:
    return (ROOT / p).read_text(encoding="utf-8")


def prd_section() -> str:
    prd = read("docs/prd/09-bundles-and-workbench.md")
    assert "## Status Tahap 5" in prd
    return prd.split("## Status Tahap 5", 1)[1]


def deploy_section() -> str:
    deploy = read("docs/deploy.md")
    assert "### Build web Tahap 5" in deploy
    return deploy.split("### Build web Tahap 5", 1)[1].split("\n## ", 1)[0]


def test_prd_records_the_stage5_decisions_and_the_honest_gaps():
    sec = prd_section()
    for needle in ("routes_build.py", "approve_build(via='ui')", "aapt2 dump badging", "/opt/apktool/aapt2", "/opt/aapt-exec", "badging_unreadable", "target_sdk_di_bawah_23",
                   "salin", "409", "build_download", "OUTPUT_NAME_RE", "FR-9.24, FR-9.41, FR-9.34 terpenuhi", "BELUM DIUJI", "isi berkas tidak bisa dibuka", "FR-9.42",
                   "verify-build", "app.webcheck", "requeue"):
        assert needle in sec, needle


def test_prd_requirement_rows_match_the_new_state():
    prd = read("docs/prd/09-bundles-and-workbench.md")
    row = lambda fr: next(ln for ln in prd.splitlines() if ln.startswith(f"| {fr} |"))  # noqa: E731
    assert "TERPENUHI di Tahap 5" in row("FR-9.24") and "TERPENUHI di Tahap 5" in row("FR-9.41")
    assert "tab Build" in row("FR-9.34") and "CLI" in row("FR-9.34")
    assert "ada di Tahap 5" in row("FR-9.25")
    assert "Persetujuan CLI-only sampai Tahap 5; sejak Tahap 5 juga lewat tombol web" in prd


def test_readme_describes_the_build_tab_and_its_limits():
    readme = read("README.md")
    para = next(p for p in readme.split("\n>\n") if "Tab Build di web (Tahap 5)" in p)
    for needle in ("layar persetujuan", "pernyataan wewenang", "menyalin berkas", "409", "audit", "target SDK < 23", "tidak dijanjikan", "BELUM DIUJI", "webcheck", "tanda tangan berbeda"):
        assert needle.lower() in para.lower(), needle
    assert "masih HANYA lewat CLI" not in readme and "ditunda ke Tahap 5" not in readme


def test_deploy_runbook_uses_only_commands_that_exist_and_lists_the_symptoms():
    sec = deploy_section()
    buildctl = read("services/web/app/buildctl.py")
    for sub in re.findall(r"app\.buildctl (\w[\w-]*)", sec):
        assert f'add_parser("{sub}"' in buildctl, sub
    webcheck = read("services/web/app/webcheck.py")
    for sub in set(re.findall(r"app\.webcheck (\w+)", sec)):
        assert f'"{sub}"' in webcheck, sub
    for needle in ("badging_unreadable", "409", "507", "503", "diff_berubah", "BELUM DIUJI", "make runner-selftest", "make verify-build", "Play Integrity", "dicopot",
                   "--no-statement", "pernyataan_wajib", "BELUM ADA langkah otomatis"):
        assert needle in sec, needle


def test_audit_has_the_new_section_with_surface_risks_and_gaps():
    audit = read("audit.md")
    assert "### 10.21 Tahap 5" in audit
    sec = audit.split("### 10.21 Tahap 5", 1)[1]
    for needle in ("Permukaan baru", "Risiko dan mitigasi", "Risiko sisa", "Belum terbukti", "salin-lalu-hash-lalu-bandingkan", "CSRF", "XSS", "via=ui", "/opt/apktool/aapt2"):
        assert needle in sec, needle


def test_prd05_and_prd06_mention_the_web_approval_and_the_tab():
    p5 = read("docs/prd/05-chat-agent.md")
    assert "tab Build" in p5 and "via=ui" in p5 and "diminta oleh AI" in p5
    p6 = read("docs/prd/06-web-ui.md")
    assert "*Build* (Tahap 5)" in p6 and "FR-6.13" in p6 and "BELUM DIUJI" in p6


def test_no_code_text_still_says_the_web_button_or_download_is_coming():
    from_code = {p: read(p) for p in ("services/web/app/builds.py", "services/web/app/ai/agent.py", "services/web/app/buildctl.py", "docker-compose.yml", "services/worker/builds.py")}
    for path, text in from_code.items():
        assert "menyusul di Tahap 5" not in text and "baru Tahap 5" not in text, path
    assert "baru Tahap 5" not in from_code["services/web/app/builds.py"]
    assert "menyusul" not in from_code["services/web/app/ai/agent.py"].split("BUILD_PROMPT_BLOCK")[1].split("SHELL_RULE_D")[0]
    assert "nanti menyajikannya" not in from_code["docker-compose.yml"]


def test_no_download_notice_points_to_the_build_tab_and_the_hash_check():
    import sys
    sys.path.insert(0, str(ROOT / "services"))
    sys.path.insert(0, str(ROOT / "services" / "web"))
    from app import builds
    assert "tab Build" in builds.NO_DOWNLOAD_NOTICE and "di-hash ulang" in builds.NO_DOWNLOAD_NOTICE and "Tahap 5" not in builds.NO_DOWNLOAD_NOTICE
