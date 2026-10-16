"""Pengelola giliran chat: menjalankan agent di thread, mengalirkan peristiwa ke SSE, dan menyimpan hasilnya.

Satu giliran aktif per sesi (pesan kedua saat giliran berjalan ditolak). Peristiwa disimpan dalam LOG per giliran (bukan antrean yang
habis dikonsumsi), sehingga:
  * klien yang terputus (pindah tab/halaman, jaringan putus) bisa MENYAMBUNG LAGI dan memutar ulang dari awal, atau melanjutkan dari
    `Last-Event-ID` tanpa duplikat;
  * beberapa tab boleh menonton giliran yang sama.
Giliran tetap berjalan dan hasilnya tersimpan walau tak ada yang menonton, kecuali pengguna menekan Berhenti.
"""

from __future__ import annotations

import json
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
from .logutil import describe
from .logutil import log as ai_log
from .pricing import PriceTable
from .provider import Client
from .redact import Redactor

LOG_MAX = 500_000          # pengaman memori per giliran (peristiwa); jauh di atas giliran normal
TURN_TTL = 600             # detik: giliran selesai dibersihkan dari memori setelah ini


@dataclass
class Turn:
    session_id: int
    analysis_id: int | None = None
    model: str = ""
    log: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    cancel: threading.Event = field(default_factory=threading.Event)
    done: bool = False
    finished_at: float = 0.0
    started_at: float = field(default_factory=time.time)
    _cond: threading.Condition = field(default_factory=threading.Condition, repr=False)

    def append(self, event: str, data: dict[str, Any]) -> None:
        with self._cond:
            if len(self.log) < LOG_MAX:
                self.log.append((event, data))
            self._cond.notify_all()

    def finish(self) -> None:
        with self._cond:
            self.done = True
            self.finished_at = time.time()
            self._cond.notify_all()

    def wait_after(self, pos: int, timeout: float) -> tuple[list[tuple[int, str, dict[str, Any]]], bool]:
        """Blokir sampai ada peristiwa di indeks >= pos (atau giliran selesai / timeout). Mengembalikan ([(indeks, event, data)], done)."""
        with self._cond:
            if len(self.log) <= pos and not self.done:
                self._cond.wait(timeout)
            return [(i, e, d) for i, (e, d) in enumerate(self.log[pos:], pos)], self.done

    def replay(self) -> list[tuple[int, str, dict[str, Any]]]:
        """Seluruh peristiwa sejauh ini untuk pelanggan BARU. Potongan teks berurutan digabung agar ringkas; id tiap entri = indeks
        peristiwa asli terakhir di kelompoknya, jadi `Last-Event-ID` tetap konsisten dengan log asli."""
        with self._cond:
            snap = list(self.log)
        out: list[tuple[int, str, dict[str, Any]]] = []
        for i, (e, d) in enumerate(snap):
            if e == "delta" and out and out[-1][1] == "delta":
                out[-1] = (i, "delta", {"text": out[-1][2]["text"] + d["text"]})
            else:
                out.append((i, e, d))
        return out


class TurnRegistry:
    def __init__(self) -> None:
        self._turns: dict[int, Turn] = {}
        self._lock = threading.Lock()

    def start(self, session_id: int, analysis_id: int | None = None, model: str = "") -> Turn | None:
        with self._lock:
            self._gc()
            cur = self._turns.get(session_id)
            if cur is not None and not cur.done:
                return None
            t = Turn(session_id, analysis_id, model)
            self._turns[session_id] = t
            return t

    def get(self, session_id: int) -> Turn | None:
        with self._lock:
            return self._turns.get(session_id)

    def active_for(self, analysis_id: int) -> Turn | None:
        """Giliran yang masih berjalan pada analisis ini (terbaru bila ada beberapa)."""
        with self._lock:
            live = [t for t in self._turns.values() if t.analysis_id == analysis_id and not t.done]
        return max(live, key=lambda t: t.started_at) if live else None

    def _gc(self) -> None:
        now = time.time()
        for sid in [k for k, t in self._turns.items() if t.done and now - t.finished_at > TURN_TTL]:
            del self._turns[sid]


REGISTRY = TurnRegistry()


# --- penanda "berhenti karena batas" (Tahap 6). Tabel chat_message tidak punya kolom `stopped` dan migrasi sengaja dihindari (skema v5 dipakai bersama tahap build),
# jadi alasan berhenti dicatat sebagai baris ai_call BERBIAYA NOL (purpose=chat_stop, error="stopped:<alasan>:<id pesan asisten>"). Ia tidak ikut anggaran (cost 0), tidak
# punya klien lain, dan hanya berlaku bila id pesan itu masih pesan TERAKHIR sesi: begitu pengguna melanjutkan, kartunya hilang sendiri.
STOP_PURPOSE = "chat_stop"
MARKED_STOPS = agent.CONTINUABLE | agent.NEEDS_OWNER        # hanya yang punya kartu bermakna setelah muat ulang (cancelled/error tidak)


def mark_stop(conn: Any, *, analysis_id: int, session_id: int, message_id: int, stopped: str, model: str = "") -> None:
    if stopped in MARKED_STOPS:
        store.record_ai_call(conn, purpose=STOP_PURPOSE, model=model or "-", ok=True, error=f"stopped:{stopped}:{int(message_id)}", analysis_id=analysis_id, session_id=session_id)


def stop_card_for(conn: Any, session_id: int, messages: list[Any]) -> dict[str, Any] | None:
    """Kartu berhenti untuk pesan terakhir sesi (muat ulang halaman, ekspor), atau None. Penanda harus menunjuk PESAN TERAKHIR dan pesan itu milik asisten."""
    if not messages or messages[-1]["role"] != "assistant":
        return None
    row = conn.execute("SELECT error FROM ai_call WHERE session_id = ? AND purpose = ? ORDER BY id DESC LIMIT 1", (session_id, STOP_PURPOSE)).fetchone()
    parts = str(row[0] or "").split(":") if row else []
    if len(parts) != 3 or parts[0] != "stopped" or parts[1] not in MARKED_STOPS or parts[2] != str(messages[-1]["id"]):
        return None
    return agent.stop_info(parts[1])


def file_view(f: dict[str, Any]) -> dict[str, Any]:
    """Bentuk ringkas berkas untuk UI (peristiwa SSE 'file' / 'final')."""
    return {"id": f["id"], "path": f.get("path"), "name": f["name"], "size": f["size"], "revision": f.get("link_revision", f.get("revision", 1)),
            "created": bool(f.get("created")), "media": f.get("media", "text")}


def budget_view(snap: dict[str, Any]) -> dict[str, Any]:
    """Bagian snapshot anggaran yang dikirim ke browser (peristiwa final) dan dirender template: pemakaian, batas, sisa, persen, peringatan dini."""
    keys = ("today", "today_limit", "today_idr", "today_remaining", "today_pct", "session", "session_limit", "session_remaining", "session_pct",
            "daily_exhausted", "session_exhausted", "warn", "wrapup")
    return {k: snap[k] for k in keys}


def run_in_thread(turn: Turn, *, cfg: AIConfig, prices: PriceTable, analysis_id: int, work, db, session_id: int,
                  user_text: str, model: str | None, files=None, attachment_ids: list[int] | None = None) -> threading.Thread:
    """Mulai giliran di thread. Pesan pengguna (+ lampiran) disimpan SEBELUM memanggil AI; jawaban disimpan sesudahnya."""

    def emit(event: str, data: dict[str, Any]) -> None:
        turn.append(event, data)

    def work_fn() -> None:
        try:
            with closing(db()) as conn:
                rows = store.get_chat_messages(conn, session_id)
                fmap = store.files_for_messages(conn, [r["id"] for r in rows])
                history = [{"role": r["role"], "content": r["content"],
                            "attachments": [f for f in fmap.get(r["id"], []) if f["role"] == "attachment"],
                            "outputs": [f for f in fmap.get(r["id"], []) if f["role"] == "output"]} for r in rows]
                uid = store.add_chat_message(conn, session_id, "user", user_text)
                attached = [dict(f) for f in store.attach_uploads(conn, uid, analysis_id, attachment_ids or [])]
            ctx = T.ToolContext(analysis_id, work, cfg, db, Redactor(cfg.redact_secrets), files=files, cancel=turn.cancel)
            ctx.session_id = session_id      # dari parameter yang diberikan rute chat (sesi milik analisis ini), BUKAN dari model; tool build menolak bila None
            if cfg.shell_enabled:
                # sha256 APK untuk $APK di bench: dibaca dari DB (BUKAN dari pesan atau argumen model), hanya bila shell menyala.
                with closing(db()) as conn:
                    an = store.get_analysis(conn, analysis_id)
                ctx.bench_sha256 = an["sha256"] if an else None
            res = agent.run_turn(client=Client(cfg), cfg=cfg, prices=prices, ctx=ctx, history=history, user_text=user_text,
                                 model=model, session_id=session_id, emit=emit, cancel=turn.cancel, attachments=attached)
            content = res.content or (res.error or "(tidak ada jawaban)")
            outputs = ctx.final_outputs()
            with closing(db()) as conn:
                mid = store.add_chat_message(conn, session_id, "assistant", content, tool_calls=res.tool_calls,
                                             citations=res.citations, model=res.model)
                store.link_outputs(conn, mid, [(o["id"], o["revision"]) for o in outputs])
                mark_stop(conn, analysis_id=analysis_id, session_id=session_id, message_id=mid, stopped=res.stopped, model=res.model)
                spent = store.ai_spent(conn, session_id=session_id)
                snap = ai_budget.snapshot(conn, cfg, session_id)
            emit("final", {"content": content, "stopped": res.stopped, "error": res.error, "steps": res.steps, "model": res.model,
                           "citations": res.citations, "cost_credits": res.cost_credits, "session_credits": spent,
                           "session_idr": cfg.idr(spent), "turn_idr": cfg.idr(res.cost_credits),
                           "tools": len(res.tool_calls), "files": [file_view(o) for o in outputs],
                           "stop": agent.stop_info(res.stopped), "message_id": mid,
                           "budget": budget_view(snap)})
        except Exception as exc:  # noqa: BLE001 - giliran tidak boleh meninggalkan klien menunggu selamanya
            ai_log.error("giliran chat gagal: session=%s analysis=%s model=%s: %s", session_id, analysis_id, turn.model, describe(exc, cfg))
            emit("final", {"content": "", "stopped": "error", "error": f"Galat internal ({type(exc).__name__}).",
                           "steps": 0, "citations": [], "cost_credits": 0, "session_credits": 0, "session_idr": 0,
                           "turn_idr": 0, "tools": 0})
        finally:
            emit("end", {})
            turn.finish()

    th = threading.Thread(target=work_fn, name=f"chat-{session_id}", daemon=True)
    th.start()
    return th


def sse_format(event: str, data: dict[str, Any], event_id: int | None = None) -> str:
    head = f"id: {event_id}\n" if event_id is not None else ""
    return f"{head}event: {event}\ndata: {json.dumps(data, ensure_ascii=False, separators=(',', ':'))}\n\n"
