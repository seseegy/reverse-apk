"""Tahap 6: limit per giliran/sesi untuk alur bengkel, berhenti rapi + kartu "Lanjutkan", anggaran (sisa, peringatan dini, dicek tiap panggilan), dan konsistensi batas 1 GB.

Provider dan bench PALSU (utas pada spool tmp dengan protokol nyata). Tidak dibuktikan di sini: model nyata, bench/Landlock nyata, Docker/cgroup, angka ukuran terhadap APK 1 GB sungguhan.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import time
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest

from app import context
from app.ai import agent, budget as B, chat as ai_chat, tools as T
from app.ai.config import AIConfig, load_ai_config
from app.ai.pricing import PriceTable
from app.ai.provider import ChatResult, ToolCall, Usage
from app.ai.redact import Redactor
from rvcore import shellspool as SP
from rvcore import store

from conftest import BROWSER, new_analysis, query, wait_turn_done

ROOT = Path(__file__).resolve().parent.parent
SHA = "a" * 64
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
ENV_EXAMPLE = (ROOT / ".env.example").read_text(encoding="utf-8")


def read(p: str) -> str:
    return (ROOT / p).read_text(encoding="utf-8")


def prices() -> PriceTable:
    return PriceTable.load(ROOT / "config" / "ai_models.json")


@pytest.fixture(autouse=True)
def clean_shared_db_rows():
    """Baris ai_call/chat_session milik tes ini dibersihkan: tes anggaran lain menghitung total harian persis."""
    before_calls = {r[0] for r in query("SELECT id FROM ai_call")}
    before_sessions = {r[0] for r in query("SELECT id FROM chat_session")}
    yield
    for i in {r[0] for r in query("SELECT id FROM ai_call")} - before_calls:
        query("DELETE FROM ai_call WHERE id = ?", i)
    for i in {r[0] for r in query("SELECT id FROM chat_session")} - before_sessions:
        query("DELETE FROM chat_session WHERE id = ?", i)


@pytest.fixture
def sp(tmp_path):
    s = SP.make_spool(tmp_path / "benchspool")
    s.ensure_dirs()
    s.write_heartbeat("idle")
    return s


def bench_responder(sp, result, stop, seen=None):
    def run():
        while not stop.is_set():
            c = sp.claim_next()
            if c:
                if seen is not None:
                    seen.append(c[1])
                sp.finish(c[0], result)
            else:
                time.sleep(0.01)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


@pytest.fixture
def bench(sp):
    stop = threading.Event()
    seen: list = []
    bench_responder(sp, {"status": "ok", "exit_code": 0, "stdout": "x" * 100, "stderr": "", "duration_ms": 5}, stop, seen)
    yield seen
    stop.set()


def make_ctx(sp, aid=1, **over):
    cfg = replace(load_ai_config(), shell_enabled=True, shell_spool_dir=str(sp.root), **over)
    c = T.ToolContext(aid, ROOT, cfg, context.db, Redactor(True), cancel=threading.Event())
    c.bench_sha256 = SHA
    return c


def run(ctx, name, **args):
    out, ok = T.run_tool(ctx, name, json.dumps(args))
    return ok, out


def chat_session(aid):
    with closing(context.db()) as conn:
        return store.create_chat_session(conn, aid, "uji tahap 6")


class Client:
    """Klien LLM palsu: `script` = daftar giliran; tiap elemen = daftar (nama, args) untuk diminta, atau str untuk menjawab. Giliran terakhir diulang."""

    def __init__(self, script, final="Ringkasan jujur."):
        self.script, self.final, self.n = script, final, 0
        self.tools_offered, self.last_messages = [], []

    def chat(self, messages, *, model, tools, stream, on_delta, cancel, temperature, on_tool):
        self.n += 1
        self.tools_offered.append(tools)
        self.last_messages = [dict(m) for m in messages]
        if tools is None:
            return ChatResult(content=self.final, finish_reason="stop", usage=Usage(10, 5), model=model)
        step = self.script[min(self.n, len(self.script)) - 1]
        if isinstance(step, str):
            return ChatResult(content=step, finish_reason="stop", usage=Usage(10, 5), model=model)
        return ChatResult(tool_calls=[ToolCall(f"c{self.n}-{i}", nm, json.dumps(a)) for i, (nm, a) in enumerate(step)], finish_reason="tool_calls", usage=Usage(10, 5), model=model)


def turn(sp, client, aid, **over):
    ctx = make_ctx(sp, aid, **{k: v for k, v in over.items() if k not in ("session_id",)})
    sid = over.get("session_id") or chat_session(aid)
    ctx.session_id = sid
    events = []
    res = agent.run_turn(client=client, cfg=ctx.cfg, prices=prices(), ctx=ctx, history=[], user_text="uji", model="test-model", session_id=sid, emit=lambda e, d: events.append((e, d)))
    return res, events, ctx, sid


# ================================================================================ A. konfigurasi
def test_new_limits_have_sane_defaults_and_zero_means_unlimited(monkeypatch):
    for n in ("AI_SHELL_MAX_SECONDS_PER_TURN", "AI_SHELL_MAX_TURN_OUTPUT_CHARS", "AI_BUILD_MAX_PER_SESSION"):
        monkeypatch.delenv(n, raising=False)
    cfg = load_ai_config()
    assert (cfg.shell_max_seconds_per_turn, cfg.shell_max_turn_output_chars, cfg.build_max_per_session) == (900, 400_000, 5)
    for n in ("AI_SHELL_MAX_SECONDS_PER_TURN", "AI_SHELL_MAX_TURN_OUTPUT_CHARS", "AI_BUILD_MAX_PER_SESSION"):
        monkeypatch.setenv(n, "0")
    cfg = load_ai_config()
    assert (cfg.shell_max_seconds_per_turn, cfg.shell_max_turn_output_chars, cfg.build_max_per_session) == (0, 0, 0)


@pytest.mark.parametrize("name,bad", [("AI_SHELL_MAX_SECONDS_PER_TURN", "-1"), ("AI_SHELL_MAX_SECONDS_PER_TURN", "999999"), ("AI_SHELL_MAX_TURN_OUTPUT_CHARS", "-5"),
                                      ("AI_BUILD_MAX_PER_SESSION", "1001"), ("AI_BUILD_MAX_PER_SESSION", "-1"), ("AI_BUILD_MAX_PER_SESSION", "banyak")])
def test_new_limits_are_clamped_and_validated(monkeypatch, name, bad):
    from app.ai.config import ConfigError
    monkeypatch.setenv(name, bad)
    with pytest.raises(ConfigError):
        load_ai_config()


def test_new_variables_are_forwarded_by_compose_documented_and_defaults_agree():
    web = re.search(r"(?ms)^  web:.*?^  worker:", COMPOSE).group(0)
    cfg_src = read("services/web/app/ai/config.py")
    for name, default in (("AI_SHELL_MAX_SECONDS_PER_TURN", "900"), ("AI_SHELL_MAX_TURN_OUTPUT_CHARS", "400000"), ("AI_BUILD_MAX_PER_SESSION", "5")):
        assert f"{name}: ${{{name}:-{default}}}" in web, name
        assert f'"{name}"' in cfg_src and f"#{name}={default}" in ENV_EXAMPLE, name


def test_shell_time_limit_returns_a_clear_tool_error_records_it_and_flags_the_stop(sp, bench):
    ctx = make_ctx(sp, shell_max_seconds_per_turn=10)
    ctx.shell_seconds = 10.5
    ok, out = run(ctx, "shell_run", command="id")
    assert not ok and "batas total waktu shell 10 detik" in out and "Lanjut" not in out.split("galat")[0]
    assert ctx.limit_hit == "shell_budget" and ctx.shell_calls == 0 and bench == []


def test_shell_time_limit_shrinks_the_last_commands_timeout(sp):
    ctx = make_ctx(sp, shell_max_seconds_per_turn=10)
    ctx.shell_seconds = 8.2
    assert T._shell_turn_guard(ctx, 60) == 2
    ctx.shell_seconds = 9.99
    assert T._shell_turn_guard(ctx, 60) == 1
    assert T._shell_turn_guard(make_ctx(sp, shell_max_seconds_per_turn=0), 60) == 60


def test_shell_time_is_accumulated_across_calls(sp, bench):
    ctx = make_ctx(sp, shell_max_seconds_per_turn=1000)
    assert run(ctx, "shell_run", command="echo 1")[0] and ctx.shell_seconds > 0
    first = ctx.shell_seconds
    assert run(ctx, "shell_run", command="echo 2")[0] and ctx.shell_seconds > first


def test_shell_total_output_limit_blocks_the_next_call_and_flags_the_stop(sp, bench):
    ctx = make_ctx(sp, shell_max_turn_output_chars=150)
    assert run(ctx, "shell_run", command="a")[0] and ctx.shell_out_chars == 100
    assert run(ctx, "shell_run", command="b")[0] and ctx.shell_out_chars == 200
    ok, out = run(ctx, "shell_run", command="c")
    assert not ok and "batas total keluaran shell 150 karakter" in out and ctx.limit_hit == "shell_budget" and len(bench) == 2


def test_call_count_limit_also_flags_the_stop(sp, bench):
    ctx = make_ctx(sp, shell_max_calls_per_turn=1)
    assert run(ctx, "shell_run", command="a")[0]
    ok, out = run(ctx, "shell_run", command="b")
    assert not ok and "batas 1 perintah" in out and ctx.limit_hit == "shell_budget"


def test_zero_disables_every_new_shell_limit(sp, bench):
    ctx = make_ctx(sp, shell_max_seconds_per_turn=0, shell_max_turn_output_chars=0)
    ctx.shell_seconds, ctx.shell_out_chars = 10**6, 10**9
    assert run(ctx, "shell_run", command="a")[0] and ctx.limit_hit is None


# ---------------------------------------------------------------- batas build per sesi
def test_session_build_count_uses_real_create_build_audit_and_does_not_mix_sessions():
    """Penghitung membaca audit_log `build_requested`; tes ini memakai store.create_build SUNGGUHAN supaya perubahan format audit tertangkap."""
    from web_rig import ctx_analysis
    _, aid = ctx_analysis("t6-count")             # (apk_id, analysis_id): id keduanya hanya kebetulan sama pada DB bersih
    sid = 910_007                                    # id sesi yang tidak dipakai tes lain di DB bersama
    with closing(context.db()) as conn:
        before = [T.session_build_count(conn, n) for n in (sid, sid * 10, sid * 100 + 7)]
        store.create_build(conn, aid, requested_by=f"ai:{sid}", source_kind="apk", diff_sha256="b" * 64, diff_summary={"v": 1})
        after = [T.session_build_count(conn, n) for n in (sid, sid * 10, sid * 100 + 7)]
    assert after[0] == before[0] + 1 and after[1:] == before[1:], "sesi lain (awalan angka sama) tidak ikut terhitung"


def test_session_build_limit_blocks_with_a_clear_error_and_flags_build_limit(tmp_path):
    from web_rig import WebRig
    rig = WebRig(tmp_path)
    try:
        aid = rig.analysis_with()
        with closing(rig.conn()) as conn:
            store.audit(conn, "build_requested", {"build_id": 1, "analysis_id": aid, "requested_by": "ai:7"})
        cfg = replace(load_ai_config(), shell_enabled=True, shell_spool_dir=str(rig.layout.root / "benchspool"), build_max_per_session=1)
        ctx = T.ToolContext(aid, ROOT, cfg, rig.conn, Redactor(True), session_id=7)
        ok, out = run(ctx, "request_build")
        assert not ok and "[batas_sesi]" in out and "AI_BUILD_MAX_PER_SESSION" in out and ctx.limit_hit == "build_limit"
        with closing(rig.conn()) as conn:
            assert conn.execute("SELECT COUNT(*) FROM build WHERE analysis_id = ?", (aid,)).fetchone()[0] == 0
        other = T.ToolContext(aid, ROOT, cfg, rig.conn, Redactor(True), session_id=8)       # sesi lain tidak terkena
        ok2, out2 = run(other, "request_build")
        assert ok2 and other.limit_hit is None
        unlimited = T.ToolContext(aid, ROOT, replace(cfg, build_max_per_session=0), rig.conn, Redactor(True), session_id=7)
        assert "[batas_sesi]" not in run(unlimited, "request_build")[1]
    finally:
        rig.stop()


# ================================================================================ B. berhenti rapi
def test_stop_values_are_covered_everywhere():
    vals = set(agent.STOPPED_VALUES) - {"done"}
    assert set(agent.STOP_NOTES) == vals
    assert agent.CONTINUABLE | agent.NEEDS_OWNER <= vals and not agent.CONTINUABLE & agent.NEEDS_OWNER
    assert {"shell_budget", "build_limit"} <= vals
    js = read("services/web/app/static/js/app.js")
    block = js.split("var STOP_NOTES = {", 1)[1].split("};", 1)[0]
    assert set(re.findall(r"(\w+):\s*\"", block)) == vals


def test_budget_and_build_limit_cards_never_offer_continue_but_per_turn_limits_do():
    for v in agent.NEEDS_OWNER:
        info = agent.stop_info(v)
        assert info["note"] and info["can_continue"] is False and "Tombol lanjut tidak ditampilkan" in info["note"]
    for v in agent.CONTINUABLE:
        assert agent.stop_info(v)["can_continue"] is True and "Lanjutkan" in agent.stop_info(v)["note"]
    assert agent.stop_info("done") == {"stopped": "done", "note": "", "can_continue": False}


def test_agent_stops_cleanly_when_the_shell_call_limit_is_hit(sp, bench):
    client = Client([[("shell_run", {"command": "a"}), ("shell_run", {"command": "b"}), ("shell_run", {"command": "c"})], [("shell_run", {"command": "d"})]])
    res, events, ctx, _ = turn(sp, client, new_analysis("t6-calls"), shell_max_calls_per_turn=2)
    assert res.stopped == "shell_budget" and res.content == "Ringkasan jujur."
    assert [c["ok"] for c in res.tool_calls] == [True, True, False] and "batas 2 perintah" in res.tool_calls[2]["summary"]
    assert client.tools_offered[-1] is None and client.n == 2, "putaran penutup tanpa tool; tidak ada putaran ketiga"
    wrap = client.last_messages[-1]
    assert wrap["role"] == "user" and "JANGAN memanggil tool lagi" in wrap["content"] and "Lanjutkan" in wrap["content"]


def test_agent_stops_cleanly_on_shell_time_and_output_limits(sp, bench):
    for over, needle in (({"shell_max_seconds_per_turn": 1}, "batas total waktu"), ({"shell_max_turn_output_chars": 50}, "batas total keluaran")):
        client = Client([[("shell_run", {"command": "a"})], [("shell_run", {"command": "b"})], [("shell_run", {"command": "c"})]])
        aid = new_analysis("t6-" + needle.split()[-1])
        ctx = make_ctx(sp, aid, **over)
        ctx.shell_seconds = 5.0 if "shell_max_seconds_per_turn" in over else 0.0
        ctx.session_id = chat_session(aid)
        res = agent.run_turn(client=client, cfg=ctx.cfg, prices=prices(), ctx=ctx, history=[], user_text="uji", model="test-model", session_id=ctx.session_id)
        assert res.stopped == "shell_budget", over
        failed = [c for c in res.tool_calls if not c["ok"]]
        assert failed and needle in failed[0]["summary"], failed


def test_agent_stops_cleanly_when_the_build_limit_is_hit(tmp_path):
    from web_rig import WebRig
    rig = WebRig(tmp_path)
    try:
        aid = rig.analysis_with()
        with closing(rig.conn()) as conn:
            store.audit(conn, "build_requested", {"build_id": 1, "analysis_id": aid, "requested_by": "ai:7"})
            sid = store.create_chat_session(conn, aid, "uji")
        with closing(rig.conn()) as conn:
            store.audit(conn, "build_requested", {"build_id": 2, "analysis_id": aid, "requested_by": f"ai:{sid}"})
        cfg = replace(load_ai_config(), shell_enabled=True, shell_spool_dir=str(rig.layout.root / "benchspool"), build_max_per_session=1)
        ctx = T.ToolContext(aid, ROOT, cfg, rig.conn, Redactor(True), session_id=sid)
        client = Client([[("request_build", {})], [("request_build", {})]])
        res = agent.run_turn(client=client, cfg=cfg, prices=prices(), ctx=ctx, history=[], user_text="uji", model="test-model", session_id=sid)
        assert res.stopped == "build_limit" and not res.tool_calls[0]["ok"] and "batas_sesi" in res.tool_calls[0]["summary"]
        assert client.tools_offered[-1] is None and "Jangan menawarkan build lagi" in client.last_messages[-1]["content"]
        assert agent.stop_info(res.stopped)["can_continue"] is False
    finally:
        rig.stop()


def test_max_steps_and_tool_budget_still_stop_with_their_own_reason():
    aid = new_analysis("t6-steps")
    for over, want in (({"max_steps": 1}, "max_steps"), ({"max_turn_tool_chars": 1}, "tool_budget")):
        cfg = replace(load_ai_config(), **over)
        ctx = T.ToolContext(aid, ROOT, cfg, context.db, Redactor(True))
        client = Client([[("get_overview", {})], [("get_overview", {})], [("get_overview", {})]])
        sid = chat_session(aid)
        res = agent.run_turn(client=client, cfg=cfg, prices=prices(), ctx=ctx, history=[], user_text="uji", model="test-model", session_id=sid)
        assert res.stopped == want and res.content == "Ringkasan jujur." and client.tools_offered[-1] is None, over


def test_an_empty_closing_answer_gets_an_honest_server_written_summary():
    aid = new_analysis("t6-empty")
    cfg = replace(load_ai_config(), shell_enabled=True, shell_max_calls_per_turn=1)
    ctx = T.ToolContext(aid, ROOT, cfg, context.db, Redactor(True))
    client = Client([[("shell_run", {"command": "a"}), ("shell_run", {"command": "b"})]], final="")
    res = agent.run_turn(client=client, cfg=cfg, prices=prices(), ctx=ctx, history=[], user_text="uji", model="test-model", session_id=chat_session(aid))
    assert res.stopped == "shell_budget" and "Batas shell" in res.content and "shell_run" in res.content


def test_a_truncated_closing_answer_stays_an_error():
    class Cut(Client):
        def chat(self, messages, **kw):
            if kw["tools"] is None:
                return ChatResult(content="sebagian", finish_reason="incomplete", usage=Usage(1, 1), model="test-model")
            return super().chat(messages, **kw)
    aid = new_analysis("t6-cut")
    cfg = replace(load_ai_config(), max_steps=1)
    res = agent.run_turn(client=Cut([[("get_overview", {})]]), cfg=cfg, prices=prices(), ctx=T.ToolContext(aid, ROOT, cfg, context.db, Redactor(True)), history=[],
                         user_text="uji", model="test-model", session_id=chat_session(aid))
    assert res.stopped == "error"


# ---------------------------------------------------------------- prompt
def test_limit_block_is_present_only_with_the_shell_and_explains_summary_and_continue():
    off, on = agent.system_prompt(False), agent.system_prompt(True)
    assert off == agent.SYSTEM_PROMPT and agent.LIMIT_PROMPT_BLOCK not in off
    blk = agent.LIMIT_PROMPT_BLOCK
    assert blk in on and on.index(agent.BUILD_PROMPT_BLOCK) < on.index(blk) < on.index("HEMAT PUTARAN")
    assert "ringkasan jujur" in blk and "Lanjutkan" in blk and "menaikkan batas atau memulai sesi baru" in blk
    assert len(blk) < 1000 and "jaringan" not in blk and "approve" not in blk
    assert "app.buildctl approve" not in blk


# ================================================================================ chat: penanda, rute, halaman
SEQ = [0]


def seed_stopped_session(stopped: str, with_marker: bool = True):
    SEQ[0] += 1
    aid = new_analysis(f"t6-seed-{SEQ[0]}-{stopped}")
    with closing(context.db()) as conn:
        sid = store.create_chat_session(conn, aid, "uji")
        store.add_chat_message(conn, sid, "user", "halo")
        mid = store.add_chat_message(conn, sid, "assistant", "ringkasan")
        if with_marker:
            ai_chat.mark_stop(conn, analysis_id=aid, session_id=sid, message_id=mid, stopped=stopped, model="m")
    return aid, sid, mid


def test_marker_is_zero_cost_scoped_to_the_last_message_and_only_for_limits():
    aid, sid, mid = seed_stopped_session("shell_budget")
    with closing(context.db()) as conn:
        msgs = store.get_chat_messages(conn, sid)
        assert ai_chat.stop_card_for(conn, sid, msgs)["stopped"] == "shell_budget"
        assert store.ai_spent(conn, session_id=sid) == 0.0 and conn.execute("SELECT cost_credits FROM chat_session WHERE id = ?", (sid,)).fetchone()[0] == 0
        store.add_chat_message(conn, sid, "user", "lanjut")
        assert ai_chat.stop_card_for(conn, sid, store.get_chat_messages(conn, sid)) is None, "kartu hilang begitu pengguna melanjutkan"
    for v in ("error", "cancelled", "done"):
        aid2, sid2, _ = seed_stopped_session(v)
        with closing(context.db()) as conn:
            assert ai_chat.stop_card_for(conn, sid2, store.get_chat_messages(conn, sid2)) is None, v


def test_reload_renders_the_card_with_continue_only_for_per_turn_limits(client, seeded):
    aid, sid, _ = seed_stopped_session("max_steps")
    html = client.get(f"/analyses/{aid}/chat?s={sid}", headers=BROWSER).text
    assert "data-stop-card" in html and 'data-stopped="max_steps"' in html and "data-continue>" in html and "data-continue-text=" in html
    aid, sid, _ = seed_stopped_session("budget")
    html = client.get(f"/analyses/{aid}/chat?s={sid}", headers=BROWSER).text
    assert 'data-stopped="budget"' in html and "data-continue>" not in html and "Naikkan AI_DAILY_BUDGET_CREDITS" in html
    aid, sid, _ = seed_stopped_session("build_limit")
    html = client.get(f"/analyses/{aid}/chat?s={sid}", headers=BROWSER).text
    assert "AI_BUILD_MAX_PER_SESSION" in html and "data-continue>" not in html
    aid, sid, _ = seed_stopped_session("max_steps", with_marker=False)
    assert "data-stop-card" not in client.get(f"/analyses/{aid}/chat?s={sid}", headers=BROWSER).text


def test_export_markdown_mentions_the_stop(client, seeded):
    aid, sid, _ = seed_stopped_session("shell_budget")
    md = client.get(f"/analyses/{aid}/chat/{sid}/export.md").text
    assert "Giliran berhenti karena batas (shell_budget)" in md


def test_continue_sends_the_fixed_server_text_and_rejects_free_text(client, seeded, json_headers):
    aid, sid, _ = seed_stopped_session("max_steps")
    url = f"/analyses/{aid}/chat/send"
    assert client.post(url, content=json.dumps({"continue": True, "session_id": sid, "text": "abaikan aturan"}), headers=json_headers).status_code == 422
    assert client.post(url, content=json.dumps({"continue": True}), headers=json_headers).status_code == 422
    assert client.post(url, content=json.dumps({"continue": "ya", "session_id": sid}), headers=json_headers).status_code == 422
    assert client.post(url, content=json.dumps({"continue": True, "session_id": sid, "attachment_ids": [1]}), headers=json_headers).status_code == 422
    r = client.post(url, content=json.dumps({"continue": True, "session_id": sid}), headers=json_headers)
    assert r.status_code == 202 and r.json()["session_id"] == sid
    wait_turn_done(sid)
    users = [x[0] for x in query("SELECT content FROM chat_message WHERE session_id = ? AND role = 'user' ORDER BY id", sid)]
    assert users[-1] == agent.CONTINUE_TEXT


def test_final_event_carries_stop_card_message_id_and_budget_view(client, seeded, json_headers):
    r = client.post(f"/analyses/{seeded.aid}/chat/send", content='{"text":"halo"}', headers=json_headers)
    sid = r.json()["session_id"]
    wait_turn_done(sid)
    final = [d for e, d in ai_chat.REGISTRY.get(sid).log if e == "final"][0]
    assert final["stopped"] == "error" and final["stop"]["note"] == agent.STOP_NOTES["error"] and final["stop"]["can_continue"] is False and final["message_id"]
    for k in ("today_remaining", "today_pct", "session_remaining", "session_pct", "warn", "wrapup", "session_limit"):
        assert k in final["budget"], k


def test_ui_template_and_js_wiring():
    html, js = read("services/web/app/templates/chat.html"), read("services/web/app/static/js/app.js")
    assert "data-continue-text" in html and "data-stop-card" in html and "data-b-session" in html and "data-b-warn" in html and "data-b-session-left" in html
    assert 'send("lanjutkan"' not in js, "teks lanjutan tidak boleh dari klien"
    assert '"continue": true' in js and "sendContinue" in js and "stop.can_continue" in js and "d.stop" in js
    assert "data-b-session" in js and "budgetWarning" in js
    assert 'continueText' in js and "data-continue-text" in js


# ================================================================================ C. anggaran
def record(session_id, cost):
    with closing(context.db()) as conn:
        store.record_ai_call(conn, purpose="chat", model="test-model", cost_credits=cost, session_id=session_id)


def cfg_with(**over) -> AIConfig:
    return replace(load_ai_config(), **over)


def test_snapshot_remaining_percent_and_early_warning():
    sid = chat_session(new_analysis("t6-snap"))
    cfg = cfg_with(session_budget=1.0, daily_budget=100.0)
    with closing(context.db()) as conn:
        s = B.snapshot(conn, cfg, sid)
        assert s["warn"] == "" and s["wrapup"] is False and s["session_remaining"] == 1.0 and s["session_pct"] == 0.0
    record(sid, 0.8)
    with closing(context.db()) as conn:
        s = B.snapshot(conn, cfg, sid)
        assert s["warn"] == "session" and s["wrapup"] is False and abs(s["session_remaining"] - 0.2) < 1e-9 and s["session_pct"] == 80.0
    record(sid, 0.12)
    with closing(context.db()) as conn:
        assert B.snapshot(conn, cfg, sid)["wrapup"] is True
    record(sid, 0.5)
    with closing(context.db()) as conn:
        s = B.snapshot(conn, cfg, sid)
        assert s["session_exhausted"] is True and s["warn"] == "" and s["session_remaining"] == 0.0 and s["session_pct"] == 100.0


def test_snapshot_unlimited_budget_has_no_warning_and_no_remaining():
    sid = chat_session(new_analysis("t6-unl"))
    record(sid, 50.0)
    with closing(context.db()) as conn:
        s = B.snapshot(conn, cfg_with(session_budget=0, daily_budget=0), sid)
    assert s["warn"] == "" and s["wrapup"] is False and s["session_remaining"] is None and s["today_remaining"] is None and s["session_pct"] == 0.0


def test_check_returns_the_snapshot_and_still_raises_when_exhausted():
    sid = chat_session(new_analysis("t6-chk"))
    cfg = cfg_with(session_budget=1.0)
    with closing(context.db()) as conn:
        assert B.check(conn, cfg, sid)["session"] == 0.0
    record(sid, 1.0)
    with closing(context.db()) as conn, pytest.raises(Exception) as ei:
        B.check(conn, cfg, sid)
    assert getattr(ei.value, "kind", "") == "budget"


def test_budget_is_checked_before_every_provider_call_in_a_long_shell_loop(sp, bench):
    """Loop panjang berbasis shell: tiap putaran = satu panggilan provider yang didahului pemeriksaan anggaran. Habis di tengah loop = berhenti, tanpa panggilan ekstra."""
    cost = prices().cost("test-model", 10, 5)
    assert cost > 0
    budget_credits = cost * 3 - cost / 2                 # habis sesudah panggilan ke-3 (3 x biaya > anggaran), dan sebelum ke-3 masih di bawah ambang penutup
    client = Client([[("shell_run", {"command": "a"})]])
    aid = new_analysis("t6-loop")
    res, events, ctx, sid = turn(sp, client, aid, session_budget=budget_credits, daily_budget=0, max_steps=50)
    assert res.stopped == "budget"
    assert client.n <= 4, f"{client.n} panggilan provider: anggaran harus dicek sebelum tiap panggilan"
    with closing(context.db()) as conn:
        calls = conn.execute("SELECT COUNT(*), COALESCE(SUM(cost_credits),0) FROM ai_call WHERE session_id = ? AND purpose = 'chat'", (sid,)).fetchone()
    assert calls[0] == client.n and calls[1] <= budget_credits + cost + 1e-9, "pemakaian melampaui batas paling banyak SATU panggilan"


def test_nearly_exhausted_budget_closes_with_a_summary_while_credit_remains(sp, bench):
    aid = new_analysis("t6-wrap")
    sid = chat_session(aid)
    cost = prices().cost("test-model", 10, 5)
    cfg_budget = 1.0
    record(sid, cfg_budget * 0.95 - cost)                # setelah 1 panggilan: tepat 95% (>= ambang 90%), belum habis
    client = Client([[("get_overview", {})], [("get_overview", {})]])
    res, _, _, _ = turn(sp, client, aid, session_budget=cfg_budget, daily_budget=0, session_id=sid)
    assert res.stopped == "budget" and res.content == "Ringkasan jujur." and client.n == 2
    assert client.tools_offered[-1] is None and "Anggaran kredit hampir habis" in client.last_messages[-1]["content"] and "Jangan menawarkan untuk melanjutkan" in client.last_messages[-1]["content"]
    assert agent.stop_info("budget")["can_continue"] is False


def test_step_one_is_never_pre_empted_by_the_wrapup_threshold(sp, bench):
    aid = new_analysis("t6-step1")
    sid = chat_session(aid)
    record(sid, 0.95)
    client = Client(["Jawaban langsung."])
    res, _, _, _ = turn(sp, client, aid, session_budget=1.0, daily_budget=0, session_id=sid)
    assert res.stopped == "done" and res.content == "Jawaban langsung." and client.tools_offered[0] is not None


def test_exhausted_budget_at_the_start_stops_without_calling_the_provider(sp, bench):
    aid = new_analysis("t6-hard")
    sid = chat_session(aid)
    record(sid, 2.0)
    client = Client(["tidak boleh dipanggil"])
    res, _, _, _ = turn(sp, client, aid, session_budget=1.0, daily_budget=0, session_id=sid)
    assert res.stopped == "budget" and client.n == 0 and "habis" in (res.error or "")


def test_build_tool_turns_are_charged_to_the_session_budget_like_any_other_call(sp, bench):
    """FR-9.35: tiap putaran model (termasuk yang memanggil tool build) tercatat di ai_call dengan session_id dan menambah biaya sesi."""
    aid = new_analysis("t6-charge")
    client = Client([[("bench_diff", {})], "selesai"])
    res, _, ctx, sid = turn(sp, client, aid)
    assert [c["name"] for c in res.tool_calls] == ["bench_diff"]
    with closing(context.db()) as conn:
        n, spent = conn.execute("SELECT COUNT(*), COALESCE(SUM(cost_credits),0) FROM ai_call WHERE session_id = ? AND purpose = 'chat'", (sid,)).fetchone()
        assert n == 2 and spent > 0 and abs(spent - store.ai_spent(conn, session_id=sid)) < 1e-12
        assert abs(conn.execute("SELECT cost_credits FROM chat_session WHERE id = ?", (sid,)).fetchone()[0] - spent) < 1e-12


# ================================================================================ D. batas 1 GB: konsistensi
def compose_default(service: str, name: str) -> str:
    body = COMPOSE.split("\nservices:\n", 1)[1].split("\nnetworks:\n", 1)[0]
    parts = re.split(r"(?m)^  ([\w-]+):[ \t]*$", body)
    blocks = {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}
    m = re.search(rf"(?m)^      {name}: \$\{{{name}:-([^}}]*)\}}$", blocks[service])
    assert m, f"{service} tidak meneruskan {name} dengan bawaan"
    return m.group(1)


def test_upload_limit_is_one_gigabyte_and_caddy_and_web_read_the_same_variable():
    assert compose_default("web", "MAX_UPLOAD_MB") == compose_default("caddy", "MAX_UPLOAD_MB") == "1024"
    from app.config import load_settings
    assert load_settings().max_upload_bytes == 1024 * 1024 * 1024
    assert "max_size {$MAX_UPLOAD_MB}MiB" in read("deploy/Caddyfile")
    assert "#MAX_UPLOAD_MB=1024" in ENV_EXAMPLE


@pytest.mark.parametrize("name", ["ZIP_MAX_ENTRIES", "ZIP_MAX_UNCOMPRESSED_MB", "ZIP_MAX_ENTRY_MB", "ZIP_MAX_RATIO"])
def test_zip_limits_are_forwarded_to_web_runner_and_worker_with_identical_defaults(name):
    from rvcore import bundle
    values = {compose_default(s, name) for s in ("web", "runner", "worker")}
    assert len(values) == 1, (name, values)
    code = {"ZIP_MAX_ENTRIES": bundle.ZIP_MAX_ENTRIES, "ZIP_MAX_UNCOMPRESSED_MB": bundle.ZIP_MAX_TOTAL_BYTES // bundle.MIB,
            "ZIP_MAX_ENTRY_MB": bundle.ZIP_MAX_ENTRY_BYTES // bundle.MIB, "ZIP_MAX_RATIO": bundle.ZIP_MAX_RATIO}[name]
    assert int(values.pop()) == code and f"#{name}={code}" in ENV_EXAMPLE


def test_size_defaults_in_code_compose_and_env_example_agree():
    import importlib.machinery
    import importlib.util
    from app.config import load_settings

    def load(path, name):
        loader = importlib.machinery.SourceFileLoader(name, str(ROOT / path))
        spec = importlib.util.spec_from_loader(name, loader)
        mod = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(ROOT / "services/rvcore"))
        loader.exec_module(mod)
        return mod

    src = {p: read(p) for p in ("services/runner/runner-daemon", "services/bench/bench-daemon", "services/signer/signer-daemon", "services/worker/pipeline.py", "services/worker/worker.py")}
    assert 'os.environ.get("MAX_OUTPUT_MB", "6144")' in src["services/runner/runner-daemon"] and compose_default("runner", "MAX_OUTPUT_MB") == "6144"
    assert 'os.environ.get("MAX_BASE_APK_MB", "1024")' in src["services/runner/runner-daemon"] and compose_default("runner", "MAX_BASE_APK_MB") == "1024"
    assert '"BENCH_WORKSPACE_MAX_MB", 4096,' in src["services/bench/bench-daemon"] and compose_default("bench", "BENCH_WORKSPACE_MAX_MB") == "4096"
    assert '"BENCH_FILE_MAX_MB", 1024,' in src["services/bench/bench-daemon"] and compose_default("bench", "BENCH_FILE_MAX_MB") == "1024"
    assert '_int_env("SIGN_MAX_MB", 1280,' in src["services/signer/signer-daemon"] and compose_default("signer", "SIGN_MAX_MB") == "1280"
    for var, code in (("TIMEOUT_APKTOOL", "600"), ("TIMEOUT_JADX", "2400"), ("TIMEOUT_ANALYZE", "600")):
        assert f'_env_int("{var}", {code})' in src["services/worker/pipeline.py"] and compose_default("worker", var) == code and f"#{var}={code}" in ENV_EXAMPLE
    assert '"JOB_TIMEOUT", "4500") or 4500' in src["services/worker/worker.py"]
    assert load_settings().job_timeout == 4500 and compose_default("web", "JOB_TIMEOUT") == compose_default("worker", "JOB_TIMEOUT") == "4500" and "#JOB_TIMEOUT=4500" in ENV_EXAMPLE
    for var, code in (("MAX_OUTPUT_MB", "6144"), ("BENCH_WORKSPACE_MAX_MB", "4096"), ("BENCH_FILE_MAX_MB", "1024"), ("SIGN_MAX_MB", "1280")):
        assert f"#{var}={code}" in ENV_EXAMPLE, var
    sys.path.insert(0, str(ROOT / "services/bench"))
    from bench import executor
    assert executor.Limits().workspace_bytes == 4096 * 1024 ** 2 and executor.Limits().file_bytes == 1024 ** 3


def test_the_size_chain_is_ordered_so_a_one_gigabyte_apk_is_not_rejected_by_accident():
    from rvcore import bundle, treediff
    mib = 1024 ** 2
    upload, entry, base = 1024, bundle.ZIP_MAX_ENTRY_BYTES // mib, 1024
    sign, out = int(compose_default("signer", "SIGN_MAX_MB")), int(compose_default("runner", "MAX_OUTPUT_MB"))
    ws, bfile = int(compose_default("bench", "BENCH_WORKSPACE_MAX_MB")), int(compose_default("bench", "BENCH_FILE_MAX_MB"))
    lim = treediff.Limits()
    assert entry >= upload and base >= upload, "satu entri/APK dasar di dalam paket bisa sebesar unggahan"
    assert sign > upload, "unsigned.apk hasil rebuild boleh sedikit lebih besar dari unggahan"
    assert ws * 3 // 4 * mib >= lim.max_total_bytes, "baseline apktool terbesar yang boleh dibangun harus muat di kuota salin ruang kerja (3/4)"
    assert bfile * mib >= lim.max_file_bytes, "berkas terbesar yang boleh ada di pohon proyek harus boleh ditulis AI di ruang kerja"
    assert out * mib >= 2 * lim.max_total_bytes, "keluaran dekompilasi (apktool + jadx) boleh dua kali pohon proyek"
    stages = sum(int(compose_default("worker", v)) for v in ("TIMEOUT_APKTOOL", "TIMEOUT_JADX", "TIMEOUT_ANALYZE"))
    assert int(compose_default("worker", "JOB_TIMEOUT")) > stages, "JOB_TIMEOUT harus melampaui jumlah tenggat tahap"
    assert int(compose_default("signer", "SIGN_MAX_TOTAL_MB")) >= sign


def test_memory_limits_were_not_raised_for_one_gigabyte_and_the_bundle_copy_cap_respects_the_worker_memory():
    """Tahap 6 TIDAK menaikkan mem_limit (VPS 8 GB total). Salinan memfd upload paket dihitung ke memori kontainer worker: batasnya harus tetap jauh di bawah mem_limit."""
    from rvcore import bundle
    body = COMPOSE.split("\nservices:\n", 1)[1].split("\nnetworks:\n", 1)[0]
    parts = re.split(r"(?m)^  ([\w-]+):[ \t]*$", body)
    limits = {}
    for i in range(1, len(parts), 2):
        m = re.search(r"(?m)^    mem_limit: (\d+)([mg])$", parts[i + 1])
        if m:
            limits[parts[i]] = int(m.group(1)) * (1024 if m.group(2) == "g" else 1)
    assert {k: limits[k] for k in ("web", "worker", "runner", "bench", "signer")} == {"web": 512, "worker": 512, "runner": 3072, "bench": 1024, "signer": 512}
    assert sum(limits.values()) <= 7 * 1024, f"jumlah mem_limit {sum(limits.values())} MiB terlalu dekat dengan VPS 8 GB"
    assert bundle.UPLOAD_COPY_MAX_WORKER_MB * 2 <= limits["worker"]
    assert bundle.UPLOAD_COPY_MAX_RUNNER_MB <= limits["runner"] // 4


def test_clamps_still_allow_and_cap_the_new_defaults():
    src = read("services/signer/signer-daemon")
    assert '_int_env("SIGN_MAX_MB", 1280, 1, 4096)' in src                      # klem atas 4096 > bawaan
    assert '_int_env("BENCH_WORKSPACE_MAX_MB", 4096' in read("services/bench/bench-daemon") or '"BENCH_WORKSPACE_MAX_MB", 4096, 1, 1_000_000' in read("services/bench/bench-daemon")
    assert read("services/worker/builds.py").count("3600") >= 2, "klem TIMEOUT_BUILD/TIMEOUT_SIGN (hi 3600) tidak diubah oleh Tahap 6"
