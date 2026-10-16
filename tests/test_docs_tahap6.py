"""Konsistensi dokumen Tahap 6: bagian 'Status Tahap 6' di PRD 05/09, deploy.md, README, audit.md 10.22; variabel baru terdokumentasi; kejujuran 'BELUM DIUJI'/'ASUMSI' tidak hilang."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NEW_VARS = ("AI_SHELL_MAX_SECONDS_PER_TURN", "AI_SHELL_MAX_TURN_OUTPUT_CHARS", "AI_BUILD_MAX_PER_SESSION")


def read(p: str) -> str:
    return (ROOT / p).read_text(encoding="utf-8")


def test_sections_exist_in_every_document():
    assert "## Status Tahap 6" in read("docs/prd/09-bundles-and-workbench.md") and "## Status Tahap 6" in read("docs/prd/05-chat-agent.md")
    assert "### Limit AI, berhenti rapi, dan batas 1 GB (Tahap 6)" in read("docs/deploy.md") and "### 10.22 Tahap 6" in read("audit.md")
    assert "Tahap 6" in read("README.md")


def test_new_variables_are_documented_everywhere_they_matter():
    for name in NEW_VARS:
        for path in (".env.example", "docs/prd/09-bundles-and-workbench.md"):
            assert name in read(path), (name, path)
    assert "AI_BUILD_MAX_PER_SESSION" in read("README.md") and "AI_SHELL_MAX_SECONDS_PER_TURN" in read("README.md")


def test_prd_size_table_lists_before_after_and_status_and_is_honest_about_measurement():
    sec = read("docs/prd/09-bundles-and-workbench.md").split("## Status Tahap 6", 1)[1]
    assert "| Pengaturan | Sebelum | Sesudah | Alasan | Status |" in sec
    for name in ("MAX_UPLOAD_MB", "ZIP_MAX_ENTRY_MB", "ZIP_MAX_UNCOMPRESSED_MB", "MAX_OUTPUT_MB", "BENCH_WORKSPACE_MAX_MB", "BENCH_FILE_MAX_MB", "SIGN_MAX_MB",
                 "TIMEOUT_APKTOOL", "JOB_TIMEOUT", "MIN_FREE_GB", "mem_limit", "UPLOAD_COPY_MAX_WORKER_MB"):
        assert name in sec, name
    assert "TIDAK ADA pengukuran" in sec and "ASUMSI" in sec and "DIKUNCI TES" in sec and "BELUM DIUJI" in sec
    assert "256 MiB" in sec and "bundle_too_large" in sec


def test_old_sentence_about_the_200_mb_default_is_gone_from_deploy_and_env_example():
    assert "bawaan 200)" not in read("docs/deploy.md") and "#MAX_UPLOAD_MB=200" not in read(".env.example")


def test_stop_values_in_prd_05_match_the_code():
    from_code = re.search(r"STOPPED_VALUES = \(([^)]*)\)", read("services/web/app/ai/agent.py")).group(1)
    names = re.findall(r'"(\w+)"', from_code)
    assert "shell_budget" in names and "build_limit" in names
    assert " | ".join(names) in read("docs/prd/05-chat-agent.md")
