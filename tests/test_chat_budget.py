"""Anggaran habis: pesan ditolak (402) TANPA meninggalkan sesi chat kosong (butir 8 daftar sisa audit)."""

from __future__ import annotations

import time
from contextlib import closing

import pytest

from app import context
from rvcore import store

from conftest import query


def sessions() -> int:
    return query("SELECT COUNT(*) FROM chat_session")[0][0]


@pytest.fixture
def spent_today():
    """Catat pemakaian 1 kredit hari ini; dihapus lagi sesudahnya agar tes lain tidak ikut kehabisan anggaran."""
    with closing(context.db()) as conn:
        call_id = store.record_ai_call(conn, purpose="chat", model="test-model", cost_credits=1.0)
    yield
    query("DELETE FROM ai_call WHERE id = ?", call_id)


def send(client, seeded, headers, body: str):
    return client.post(f"/analyses/{seeded.aid}/chat/send", content=body, headers=headers)


def test_daily_budget_exhausted_creates_no_session(client, seeded, json_headers, spent_today, monkeypatch):
    monkeypatch.setenv("AI_DAILY_BUDGET_CREDITS", "0.5")
    before = sessions()
    r = send(client, seeded, json_headers, '{"text":"halo"}')
    assert r.status_code == 402 and r.json()["code"] == "budget" and "harian" in r.json()["error"]
    assert sessions() == before


def test_session_budget_exhausted_on_existing_session(client, seeded, json_headers, monkeypatch):
    monkeypatch.setenv("AI_SESSION_BUDGET_CREDITS", "0.5")
    with closing(context.db()) as conn:
        sid = store.create_chat_session(conn, seeded.aid, "mahal")
        call_id = store.record_ai_call(conn, purpose="chat", model="test-model", cost_credits=1.0, session_id=sid)
    try:
        before = sessions()
        r = send(client, seeded, json_headers, f'{{"text":"lagi","session_id":{sid}}}')
        assert r.status_code == 402 and "sesi" in r.json()["error"]
        assert sessions() == before
        # Sesi baru tidak terkena batas sesi lama: tetap boleh (anggaran harian masih cukup).
        r = send(client, seeded, json_headers, '{"text":"sesi baru"}')
        assert r.status_code == 202 and sessions() == before + 1
    finally:
        query("DELETE FROM ai_call WHERE id = ?", call_id)


def test_within_budget_creates_exactly_one_session(client, seeded, json_headers):
    before = sessions()
    assert send(client, seeded, json_headers, '{"text":"halo"}').status_code == 202
    time.sleep(0.05)
    assert sessions() == before + 1
