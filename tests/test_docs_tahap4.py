"""Konsistensi dokumen Tahap 4 (tool AI build): docs/deploy.md, PRD 05/09, README, audit.md, .env.example dan `scripts/verify-build.sh`.

Yang dijaga: tiap langkah 14a-14n punya baris gejala di deploy.md DENGAN nama persis seperti di skrip; persetujuan ditulis masih CLI-only sampai Tahap 5; cek live dengan model nyata
(`make ai-check`) ditulis opsional/manual; BELUM DIUJI tetap ada; tidak ada env baru (jadi `.env.example` tidak perlu entri baru).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(p: str) -> str:
    return (ROOT / p).read_text(encoding="utf-8")


def script_names() -> list[str]:
    return re.findall(r'^N14[A-N]="([^"\n]+)"$', read("scripts/verify-build.sh"), re.M)


def deploy_section() -> str:
    deploy = read("docs/deploy.md")
    assert "### Tool build AI (Tahap 4)" in deploy
    return deploy.split("### Tool build AI (Tahap 4)", 1)[1].split("\n## ", 1)[0]


def test_the_script_has_fourteen_tool_steps_in_order():
    names = script_names()
    assert len(names) == 14 and [n[:3] for n in names] == [f"14{c}" for c in "abcdefghijklmn"]


def test_deploy_has_a_symptom_row_for_every_step_with_the_exact_script_name():
    rows = {ln.split("|")[1].strip(): ln for ln in deploy_section().splitlines() if ln.startswith("| 14")}
    for name in script_names():
        assert name in rows, name
        cells = [c.strip() for c in rows[name].split("|")[1:-1]]
        assert len(cells) == 3 and all(cells), rows[name]


def test_deploy_says_approval_is_cli_only_until_stage_5_and_the_ai_cannot_approve():
    sec = deploy_section()
    assert "buildctl approve" in sec and "Tahap 5" in sec and "CLI" in sec
    assert re.search(r"tidak punya tool untuk menyetujui", sec)


def test_deploy_marks_the_live_check_optional_manual_and_says_what_ai_check_covers():
    sec = deploy_section()
    assert "make ai-check" in sec and "opsional" in sec.lower() and "MANUAL" in sec
    assert "tidak menyentuh tool build" in sec and "kunci API" in sec


def test_deploy_documents_the_helper_commands_and_the_unproven_parts():
    sec = deploy_section()
    for needle in ("app.aitoolcheck", "audit-approvals", "--shell 0", "AI_SHELL_ENABLED=1", "BELUM DIUJI", "anti-tamper", "packer", "Play Integrity", "hash `.so`",
                   "git pull --ff-only && make up"):
        assert needle in sec, needle


def test_prd_readme_and_audit_mention_the_tools_and_cli_only_approval():
    for path in ("docs/prd/05-chat-agent.md", "docs/prd/09-bundles-and-workbench.md", "README.md", "audit.md"):
        text = read(path)
        for tool in ("bench_diff", "request_build", "get_build_status"):
            assert tool in text, (path, tool)
        assert "Tahap 5" in text and ("CLI" in text), path
    assert "### 10.20 Tahap 4" in read("audit.md") and "## Status Tahap 4" in read("docs/prd/09-bundles-and-workbench.md")


def test_no_new_env_means_env_example_is_untouched_by_this_stage():
    env = read(".env.example")
    assert "AI_SHELL_ENABLED" in env and "AI_BUILD" not in env and "AITOOL" not in env


def test_the_dropped_diff_preview_is_stated_explicitly_in_every_owner_document():
    for p in ("docs/deploy.md", "docs/prd/09-bundles-and-workbench.md", "audit.md", "README.md"):
        text = read(p)
        assert "pratinjau" in text.lower() and "dilepas" in text.lower(), p
    assert "bench_diff" in read("docs/prd/05-chat-agent.md") and "dilepas" in read("docs/prd/05-chat-agent.md").lower()


def test_owner_runbook_states_slot_hold_and_that_approval_commands_come_from_buildctl_not_chat():
    deploy = deploy_section()
    assert "menahan slot" in deploy
    assert "salin" in deploy.lower() and "bukan dari chat" in deploy.lower()

