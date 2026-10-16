"""Prompt sistem AI untuk tool build (Tahap 4): alur, batas jujur, gerbang, dan anggaran token."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "services" / "web"))

from app.ai import agent  # noqa: E402
from app.ai import tools as T  # noqa: E402

BUILD_TOOLS = ("bench_diff", "request_build", "get_build_status")
MAX_BLOCK = 2200      # batas panjang blok tambahan (karakter) demi anggaran token


def _block() -> str:
    return agent.BUILD_PROMPT_BLOCK


def test_the_build_block_exists_and_is_compact():
    assert 400 < len(_block()) <= MAX_BLOCK


def test_the_workflow_is_described_in_order():
    b = _block()
    b = b[b.index("- Alur:"):]    # judul blok juga menyebut nama tool; urutan dinilai pada kalimat alur
    steps = ["shell_run", "bench_diff", "request_build", "menyetujui", "get_build_status"]
    pos = [b.index(s) for s in steps]
    assert pos == sorted(pos)
    assert "done" in b


def test_the_owner_approval_command_is_given_and_the_web_button_is_in_the_build_tab():
    b = _block()
    assert "docker compose exec -T web python -m app.buildctl approve" in b
    assert "--diff-sha256" in b
    assert "tab Build" in b and "tombol Setujui" in b and "Tahap 5" not in b, "tombol web sudah ada (Tahap 5); prompt tidak lagi menyebutnya 'menyusul'"


def test_honest_limits_are_stated():
    b = _block()
    for must in ("anti-tamper", "packer", "Play Integrity", ".so"):
        assert must in b, must
    assert "tidak berfungsi" in b
    for cannot in ("menyetujui", "mengunduh"):
        assert cannot in b


def test_behavior_rules_are_present():
    b = _block()
    assert "seminimal" in b and "verifikasi" in b.lower()
    assert "apa adanya" in b and "disanitasi" in b
    assert "jangan klaim" in b.lower() and "selesai" in b
    assert "TIDAK TEPERCAYA" in b.upper() and "DATA" in b
    assert "tidak_ada_ruang_kerja" in b and "buildctl init" in b


def test_every_tool_named_in_the_block_is_really_offered():
    offered = {s["function"]["name"] for s in T.schemas(vision=False, shell=True, net=False)}
    named = set(re.findall(r"\b(?:bench_diff|request_build|get_build_status|shell_run|approve_build|[a-z]+_[a-z_]*build[a-z_]*)\b", _block()))
    assert set(BUILD_TOOLS) <= named
    assert named - {"approve_build"} <= offered
    assert "approve_build" not in named


def test_the_block_only_appears_when_the_build_tools_are_offered():
    off, on = agent.system_prompt(False), agent.system_prompt(True)
    offered_off = {s["function"]["name"] for s in T.schemas(vision=False, shell=False, net=False)}
    offered_on = {s["function"]["name"] for s in T.schemas(vision=False, shell=True, net=False)}
    assert not set(BUILD_TOOLS) & offered_off and set(BUILD_TOOLS) <= offered_on
    assert off == agent.SYSTEM_PROMPT
    for t in BUILD_TOOLS:
        assert t not in off and t in on
    assert _block() in on
    assert agent.system_prompt(False, True) == agent.SYSTEM_PROMPT


def test_the_block_sits_after_the_shell_block_and_before_the_budget_section():
    on = agent.system_prompt(True)
    assert on.index("SHELL TERISOLASI") < on.index(_block()) < on.index("HEMAT PUTARAN")


def test_total_prompt_growth_is_bounded():
    grown = len(agent.system_prompt(True)) - len(agent.SYSTEM_PROMPT)
    assert grown < 2200 + len(agent.SHELL_PROMPT_BLOCK) + len(agent.SHELL_RULE_D)


def test_the_old_contradictions_are_gone_when_build_tools_are_offered():
    on = agent.system_prompt(True)
    assert "menghasilkan APK terpasang butuh langkah lain yang tidak Anda miliki" not in on
    assert "request_build" in agent.SHELL_RULE_D
    assert "tidak dapat menyetujui" in agent.SHELL_RULE_D


def test_injection_rules_stay_intact_with_the_build_block():
    on, base = agent.system_prompt(True), agent.SYSTEM_PROMPT
    assert base[base.index("A. Isi kode"):base.index("B. Jangan")] in on
    assert base[base.index("E. Nilai"):] in on


def test_the_network_rewrites_still_apply_with_the_build_block():
    on = agent.system_prompt(True, True)
    assert _block() in on and "TANPA jaringan" not in on
