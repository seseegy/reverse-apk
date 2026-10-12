"""Anggaran kredit harian dan per sesi (FR-4.7). Dicek SEBELUM tiap panggilan; pemakaian dicatat SESUDAH tiap panggilan.

Sengaja konservatif: panggilan yang sudah berjalan tidak dipotong di tengah jalan, jadi pemakaian bisa melampaui batas
sebesar SATU panggilan (dibatasi AI_MAX_OUTPUT_TOKENS). Setelah itu semua panggilan baru ditolak dengan pesan jelas.
"""

from __future__ import annotations

import sqlite3
import time

from rvcore import fmt, store

from .config import AIConfig
from .pricing import PriceTable
from .provider import AIError, ChatResult


def day_start(now: float, offset_hours: int) -> float:
    """Awal 'hari' (00:00 pada zona UTC+offset) sebagai epoch. Offset tetap, tanpa database zona waktu."""
    shifted = now + offset_hours * 3600
    return (shifted - shifted % 86400) - offset_hours * 3600


def snapshot(conn: sqlite3.Connection, cfg: AIConfig, session_id: int | None = None) -> dict:
    today = store.ai_spent(conn, since=day_start(time.time(), cfg.day_offset_hours))
    sess = store.ai_spent(conn, session_id=session_id) if session_id is not None else None
    return {
        "today": today, "today_limit": cfg.daily_budget, "today_idr": cfg.idr(today),
        "session": sess, "session_limit": cfg.session_budget,
        "daily_exhausted": bool(cfg.daily_budget and today >= cfg.daily_budget),
        "session_exhausted": bool(cfg.session_budget and sess is not None and sess >= cfg.session_budget),
    }


def check(conn: sqlite3.Connection, cfg: AIConfig, session_id: int | None = None) -> None:
    """Lempar AIError(kind='budget') bila batas harian/sesi sudah tercapai. 0 = tanpa batas."""
    s = snapshot(conn, cfg, session_id)
    if s["daily_exhausted"]:
        raise AIError("budget", f"Anggaran harian habis ({fmt.num(s['today'], 3)} dari {fmt.num(cfg.daily_budget, None)} kredit ≈ "
                                f"Rp{fmt.num(cfg.idr(s['today']))}). Naikkan AI_DAILY_BUDGET_CREDITS atau coba lagi besok.")
    if s["session_exhausted"]:
        raise AIError("budget", f"Anggaran sesi percakapan habis ({fmt.num(s['session'], 3)} dari {fmt.num(cfg.session_budget, None)} kredit). "
                                "Mulai sesi baru atau naikkan AI_SESSION_BUDGET_CREDITS.")


def record(conn: sqlite3.Connection, cfg: AIConfig, prices: PriceTable, *, purpose: str, model: str,
           result: ChatResult | None, error: AIError | None = None, analysis_id: int | None = None,
           session_id: int | None = None) -> float:
    """Catat satu panggilan (sukses atau gagal) dan kembalikan biayanya dalam kredit."""
    if result is None:
        store.record_ai_call(conn, purpose=purpose, model=model, ok=False,
                             error=(error.kind + ": " + error.message) if error else "gagal",
                             analysis_id=analysis_id, session_id=session_id)
        return 0.0
    u = result.usage
    cost = prices.cost(model, u.prompt, u.completion)
    store.record_ai_call(conn, purpose=purpose, model=model, prompt_tokens=u.prompt, completion_tokens=u.completion,
                         cached_tokens=u.cached, cost_credits=cost,
                         estimated=u.estimated or not prices.rate(model).known, analysis_id=analysis_id,
                         session_id=session_id)
    return cost
