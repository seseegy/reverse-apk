"""Pengelola giliran chat: menjalankan agent di thread, mengalirkan peristiwa ke SSE, dan menyimpan hasilnya.

Satu giliran aktif per sesi (pesan kedua saat giliran berjalan ditolak). Peristiwa disimpan di antrean per giliran;
klien SSE yang terputus tidak menghentikan giliran (hasil tetap disimpan), kecuali pengguna menekan Berhenti.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from contextlib import closing
from dataclasses import dataclass, field
from typing import Any

from rvcore import store

from . import agent
from . import budget as ai_budget
from . import tools as T
from .config import AIConfig
from .pricing import PriceTable
from .provider import Client
from .redact import Redactor

QUEUE_MAX = 5000
TURN_TTL = 600           # detik: giliran selesai dibersihkan dari memori setelah ini


@dataclass
class Turn:
    session_id: int
    events: "queue.Queue[tuple[str, dict[str, Any]]]" = field(default_factory=lambda: queue.Queue(QUEUE_MAX))
    cancel: threading.Event = field(default_factory=threading.Event)
    done: bool = False
    finished_at: float = 0.0


class TurnRegistry:
    def __init__(self) -> None:
        self._turns: dict[int, Turn] = {}
        self._lock = threading.Lock()

    def start(self, session_id: int) -> Turn | None:
        with self._lock:
            self._gc()
            cur = self._turns.get(session_id)
            if cur is not None and not cur.done:
                return None
            t = Turn(session_id)
            self._turns[session_id] = t
            return t

    def get(self, session_id: int) -> Turn | None:
        with self._lock:
            return self._turns.get(session_id)

    def _gc(self) -> None:
        now = time.time()
        for sid in [k for k, t in self._turns.items() if t.done and now - t.finished_at > TURN_TTL]:
            del self._turns[sid]


REGISTRY = TurnRegistry()


def run_in_thread(turn: Turn, *, cfg: AIConfig, prices: PriceTable, analysis_id: int, work, db, session_id: int,
                  user_text: str, model: str | None) -> threading.Thread:
    """Mulai giliran di thread. Pesan pengguna disimpan SEBELUM memanggil AI; jawaban disimpan sesudahnya."""

    def emit(event: str, data: dict[str, Any]) -> None:
        try:
            turn.events.put_nowait((event, data))
        except queue.Full:
            pass

    def work_fn() -> None:
        try:
            with closing(db()) as conn:
                rows = store.get_chat_messages(conn, session_id)
                history = [{"role": r["role"], "content": r["content"]} for r in rows]
                store.add_chat_message(conn, session_id, "user", user_text)
            ctx = T.ToolContext(analysis_id, work, cfg, db, Redactor(cfg.redact_secrets))
            res = agent.run_turn(client=Client(cfg), cfg=cfg, prices=prices, ctx=ctx, history=history, user_text=user_text,
                                 model=model, session_id=session_id, emit=emit, cancel=turn.cancel)
            content = res.content or (res.error or "(tidak ada jawaban)")
            with closing(db()) as conn:
                store.add_chat_message(conn, session_id, "assistant", content, tool_calls=res.tool_calls,
                                       citations=res.citations, model=res.model)
                spent = store.ai_spent(conn, session_id=session_id)
                snap = ai_budget.snapshot(conn, cfg, session_id)
            emit("final", {"content": content, "stopped": res.stopped, "error": res.error, "steps": res.steps,
                           "citations": res.citations, "cost_credits": res.cost_credits, "session_credits": spent,
                           "session_idr": cfg.idr(spent), "turn_idr": cfg.idr(res.cost_credits),
                           "tools": len(res.tool_calls),
                           "budget": {"today": snap["today"], "today_limit": snap["today_limit"], "today_idr": snap["today_idr"]}})
        except Exception as exc:  # noqa: BLE001 - giliran tidak boleh meninggalkan klien menunggu selamanya
            emit("final", {"content": "", "stopped": "error", "error": f"Galat internal ({type(exc).__name__}).",
                           "steps": 0, "citations": [], "cost_credits": 0, "session_credits": 0, "session_idr": 0,
                           "turn_idr": 0, "tools": 0})
        finally:
            turn.done = True
            turn.finished_at = time.time()
            emit("end", {})

    th = threading.Thread(target=work_fn, name=f"chat-{session_id}", daemon=True)
    th.start()
    return th


def sse_format(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False, separators=(',', ':'))}\n\n"
