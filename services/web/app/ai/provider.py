"""Klien API kompatibel OpenAI (Chat Completions): non-stream, streaming SSE, tool calling, pemakaian token.

Sengaja hanya pustaka standar (http.client): tanpa dependensi baru dan mudah diuji. Blocking: dipanggil dari thread
(agent berjalan di thread dan mengalirkan peristiwa ke SSE browser).

KEAMANAN
  * Kunci API tidak pernah masuk pesan galat, log, atau hasil (semua teks dari server disaring `cfg.redact`).
  * Badan permintaan (berisi potongan kode APK) tidak pernah dicatat.
  * Ukuran respons dibatasi; timeout koneksi/baca ketat.
  * Retry hanya SEBELUM ada keluaran yang sampai ke pemanggil (menghindari jawaban ganda).
"""

from __future__ import annotations

import http.client
import json
import random
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

from .config import AIConfig
from .logutil import log

MAX_BODY = 16 * 1024 * 1024          # batas jawaban non-stream
MAX_STREAM_BYTES = 32 * 1024 * 1024  # batas total satu stream
MAX_ERROR_TEXT = 300
RETRY_DELAYS = (1.0, 3.0, 7.0)


class AIError(Exception):
    """Galat penyedia. `kind`: auth | credits | model | bad_request | rate_limit | server | network | timeout |
    cancelled | protocol | budget | config. `retryable` hanya berarti 'layak dicoba lagi', bukan pasti."""

    def __init__(self, kind: str, message: str, status: int | None = None, retryable: bool = False,
                 retry_after: float | None = None) -> None:
        super().__init__(message)
        self.kind, self.message, self.status = kind, message, status
        self.retryable, self.retry_after = retryable, retry_after


@dataclass
class Usage:
    prompt: int = 0
    completion: int = 0
    cached: int = 0
    estimated: bool = False


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str          # string JSON mentah dari model (TIDAK TEPERCAYA; divalidasi pemanggil)


@dataclass
class ChatResult:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str | None = None
    usage: Usage = field(default_factory=Usage)
    model: str = ""


def estimate_tokens(text: str) -> int:
    """Perkiraan kasar (≈ 3,5 karakter/token) saat provider tidak melaporkan pemakaian."""
    return int(len(text) / 3.5) + 1


IMAGE_TOKENS = 1200   # perkiraan kasar token per gambar bila provider tidak melaporkan pemakaian


def _without_images(messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Salinan pesan dengan gambar base64 diganti penanda pendek (dan jumlah gambarnya), agar perkiraan token tidak membengkak."""
    out, n = [], 0
    for m in messages:
        c = m.get("content")
        if isinstance(c, list):
            parts = []
            for part in c:
                if isinstance(part, dict) and part.get("type") == "image_url":
                    n += 1
                    parts.append({"type": "text", "text": "[gambar]"})
                else:
                    parts.append(part)
            m = {**m, "content": parts}
        out.append(m)
    return out, n


class Client:
    def __init__(self, cfg: AIConfig) -> None:
        self.cfg = cfg
        parts = urlsplit(cfg.base_url)
        self._tls = parts.scheme == "https"
        self._host = parts.hostname or ""
        self._port = parts.port or (443 if self._tls else 80)
        self._prefix = parts.path.rstrip("/")
        self._ctx = ssl.create_default_context() if self._tls else None
        self._stream_options_ok = True      # diturunkan ke False bila provider menolak stream_options

    # ------------------------------------------------------------------ publik
    def chat(self, messages: list[dict[str, Any]], *, model: str | None = None,
             tools: list[dict[str, Any]] | None = None, tool_choice: str | dict | None = None,
             max_tokens: int | None = None, temperature: float | None = None, stream: bool = False,
             on_delta: Callable[[str], None] | None = None, cancel: threading.Event | None = None,
             on_tool: Callable[[int, str, str], None] | None = None) -> ChatResult:
        if not self.cfg.enabled:
            raise AIError("config", "AI belum dikonfigurasi (atur base URL, kunci API, dan model di halaman Pengaturan AI).")
        model = model or self.cfg.model
        attempt = 0
        while True:
            emitted = [False]

            def delta(text: str) -> None:
                emitted[0] = True
                if on_delta:
                    on_delta(text)

            try:
                return self._once(messages, model, tools, tool_choice, max_tokens, temperature, stream,
                                  delta if stream else None, cancel, on_tool if stream else None)
            except AIError as exc:
                if cancel is not None and cancel.is_set():
                    raise AIError("cancelled", "Dibatalkan.") from exc
                if exc.kind == "bad_request" and stream and self._stream_options_ok and "stream_options" in exc.message.lower():
                    self._stream_options_ok = False         # provider tidak mengenal stream_options: coba lagi TANPA itu
                    continue                                # (hanya sekali: flag sudah False, jadi tidak bisa berputar)
                # Timeout hanya diulang SEKALI: provider yang lambat kemungkinan sedang bermasalah, dan mengulang 3x
                # berarti pengguna menunggu puluhan detik. Galat 429/5xx/jaringan boleh sampai 3x.
                limit = 1 if exc.kind == "timeout" else len(RETRY_DELAYS)
                if not exc.retryable or emitted[0] or attempt >= limit:
                    raise
                wait = exc.retry_after if exc.retry_after is not None else RETRY_DELAYS[attempt] * random.uniform(0.8, 1.2)
                attempt += 1
                log.warning("provider %s (HTTP %s), coba ulang %d/%d dalam %.1f dtk: model=%s", exc.kind, exc.status, attempt, limit,
                            min(wait, 30.0), model)
                if self._sleep(min(wait, 30.0), cancel):
                    raise AIError("cancelled", "Dibatalkan.") from exc

    # ------------------------------------------------------------------ internal
    @staticmethod
    def _sleep(seconds: float, cancel: threading.Event | None) -> bool:
        if cancel is None:
            time.sleep(seconds)
            return False
        return cancel.wait(seconds)

    def _once(self, messages, model, tools, tool_choice, max_tokens, temperature, stream, on_delta, cancel, on_tool=None) -> ChatResult:  # noqa: ANN001
        body: dict[str, Any] = {"model": model, "messages": messages,
                                "max_tokens": max_tokens or self.cfg.max_output_tokens, "stream": bool(stream)}
        if temperature is not None:
            body["temperature"] = temperature
        if tools:
            body["tools"] = tools
            if tool_choice is not None:
                body["tool_choice"] = tool_choice
        if stream and self._stream_options_ok:
            body["stream_options"] = {"include_usage": True}
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")

        conn = (http.client.HTTPSConnection(self._host, self._port, timeout=self.cfg.connect_timeout, context=self._ctx)
                if self._tls else http.client.HTTPConnection(self._host, self._port, timeout=self.cfg.connect_timeout))
        try:
            try:
                conn.connect()
                if conn.sock is not None:
                    conn.sock.settimeout(self.cfg.read_timeout)
                conn.request("POST", self._prefix + "/chat/completions", body=payload, headers={
                    "Authorization": f"Bearer {self.cfg.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream" if stream else "application/json",
                    "User-Agent": "reverse-apk/1",
                })
                resp = conn.getresponse()
            except TimeoutError as exc:
                raise AIError("timeout", "Provider tidak merespons tepat waktu.", retryable=True) from exc
            except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
                raise AIError("network", self.cfg.redact(f"Tidak bisa terhubung ke provider ({type(exc).__name__})."),
                              retryable=True) from exc

            if resp.status != 200:
                raise self._http_error(resp)
            ctype = (resp.getheader("Content-Type") or "").lower()
            if stream and "text/event-stream" in ctype:
                return self._read_stream(resp, model, messages, tools, on_delta, cancel, on_tool)
            if stream and on_delta is not None:
                # Beberapa router mengabaikan stream=true dan membalas JSON biasa: tetap diterima.
                result = self._parse_full(resp.read(MAX_BODY + 1), model, messages, tools)
                if result.content:
                    on_delta(result.content)
                return result
            return self._parse_full(resp.read(MAX_BODY + 1), model, messages, tools)
        except TimeoutError as exc:
            raise AIError("timeout", "Provider berhenti merespons di tengah jawaban.", retryable=True) from exc
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise AIError("network", self.cfg.redact(f"Koneksi ke provider terputus ({type(exc).__name__})."),
                          retryable=True) from exc
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _http_error(self, resp: http.client.HTTPResponse) -> AIError:
        status = resp.status
        try:
            raw = resp.read(MAX_ERROR_TEXT * 8).decode("utf-8", errors="replace")
        except (OSError, http.client.HTTPException):
            raw = ""
        detail = ""
        try:
            err = json.loads(raw).get("error")
            detail = err.get("message", "") if isinstance(err, dict) else str(err or "")
        except (ValueError, AttributeError):
            detail = raw
        detail = self.cfg.redact(" ".join(detail.split()))[:MAX_ERROR_TEXT]
        low = detail.lower()
        retry_after = None
        try:
            retry_after = float(resp.getheader("Retry-After") or "")
        except ValueError:
            pass
        if status in (401, 403) and not any(w in low for w in ("credit", "kredit", "balance", "quota", "insufficient")):
            return AIError("auth", "Kunci API ditolak oleh provider (periksa di halaman Pengaturan AI)." + (f" [{detail}]" if detail else ""), status)
        if status == 402 or any(w in low for w in ("insufficient", "credit", "kredit", "balance", "quota")):
            return AIError("credits", "Kredit provider habis atau tidak cukup." + (f" [{detail}]" if detail else ""), status)
        if status == 404 or "model" in low and any(w in low for w in ("not found", "does not exist", "unknown", "tidak ditemukan")):
            return AIError("model", "Model tidak ditemukan di provider (periksa slug model di halaman Pengaturan AI)." + (f" [{detail}]" if detail else ""), status)
        if status == 429:
            return AIError("rate_limit", "Provider membatasi laju permintaan." + (f" [{detail}]" if detail else ""),
                           status, retryable=True, retry_after=retry_after)
        if status >= 500:
            return AIError("server", f"Provider mengalami galat (HTTP {status})." + (f" [{detail}]" if detail else ""),
                           status, retryable=True, retry_after=retry_after)
        return AIError("bad_request", f"Permintaan ditolak provider (HTTP {status}): {detail or 'tanpa keterangan'}", status)

    # ------------------------------------------------------------------ penguraian
    def _usage(self, data: dict | None, messages, tools, content: str, calls: list[ToolCall]) -> Usage:
        u = data if isinstance(data, dict) else None
        if u and isinstance(u.get("prompt_tokens"), int) and isinstance(u.get("completion_tokens"), int):
            details = u.get("prompt_tokens_details") if isinstance(u.get("prompt_tokens_details"), dict) else {}
            cached = details.get("cached_tokens") or u.get("prompt_cache_hit_tokens") or 0
            return Usage(u["prompt_tokens"], u["completion_tokens"], int(cached) if isinstance(cached, int) else 0)
        # Provider tidak melaporkan pemakaian: perkirakan dari panjang teks dan tandai sebagai perkiraan.
        flat, n_images = _without_images(messages)
        prompt = estimate_tokens(json.dumps(flat, ensure_ascii=False) + (json.dumps(tools) if tools else "")) + n_images * IMAGE_TOKENS
        comp = estimate_tokens(content + "".join(c.name + c.arguments for c in calls))
        return Usage(prompt, comp, 0, estimated=True)

    def _parse_full(self, raw: bytes, model, messages, tools) -> ChatResult:  # noqa: ANN001
        if len(raw) > MAX_BODY:
            raise AIError("protocol", "Jawaban provider terlalu besar.")
        try:
            data = json.loads(raw)
            choice = data["choices"][0]
            msg = choice.get("message") or {}
        except (ValueError, KeyError, IndexError, TypeError, AttributeError) as exc:
            raise AIError("protocol", "Jawaban provider bukan format Chat Completions yang valid.") from exc
        content = msg.get("content") if isinstance(msg.get("content"), str) else ""
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = (tc or {}).get("function") or {}
            if isinstance(fn.get("name"), str):
                args = fn.get("arguments")
                calls.append(ToolCall(str(tc.get("id") or f"call_{len(calls)}"), fn["name"],
                                      args if isinstance(args, str) else json.dumps(args or {})))
        return ChatResult(content, calls, choice.get("finish_reason"),
                          self._usage(data.get("usage"), messages, tools, content, calls), str(data.get("model") or model))

    def _read_stream(self, resp, model, messages, tools, on_delta, cancel, on_tool=None) -> ChatResult:  # noqa: ANN001
        parts: list[str] = []
        calls: dict[int, dict[str, str]] = {}
        finish = None
        usage_raw = None
        seen_model = model
        total = 0
        done = False
        while True:
            if cancel is not None and cancel.is_set():
                raise AIError("cancelled", "Dibatalkan.")
            try:
                line = resp.readline()
            except TimeoutError as exc:
                if parts or calls:                          # sudah ada keluaran: kembalikan yang terkumpul, jangan diulang
                    finish = finish or "incomplete"
                    break
                raise AIError("timeout", "Provider berhenti mengirim data sebelum ada jawaban.", retryable=True) from exc
            except (OSError, http.client.HTTPException) as exc:
                if parts or calls:
                    finish = finish or "incomplete"
                    break
                raise AIError("network", self.cfg.redact(f"Koneksi terputus ({type(exc).__name__})."), retryable=True) from exc
            if not line:
                break
            total += len(line)
            if total > MAX_STREAM_BYTES:
                raise AIError("protocol", "Aliran jawaban terlalu besar.")
            line = line.strip()
            if not line.startswith(b"data:"):
                continue                                  # komentar keep-alive (": ping"), event lain, baris kosong
            chunk = line[5:].strip()
            if chunk == b"[DONE]":
                done = True
                break
            try:
                obj = json.loads(chunk)
            except ValueError:
                continue
            if not isinstance(obj, dict):
                continue
            if isinstance(obj.get("error"), (dict, str)):
                e = obj["error"]
                msg = e.get("message", "") if isinstance(e, dict) else str(e)
                raise AIError("server", "Provider melaporkan galat di tengah aliran: " + self.cfg.redact(str(msg))[:MAX_ERROR_TEXT],
                              retryable=not parts)
            if isinstance(obj.get("model"), str):
                seen_model = obj["model"]
            if isinstance(obj.get("usage"), dict):
                usage_raw = obj["usage"]
            for ch in obj.get("choices") or []:
                if not isinstance(ch, dict):
                    continue
                d = ch.get("delta") or {}
                text = d.get("content")
                if isinstance(text, str) and text:
                    parts.append(text)
                    if on_delta:
                        on_delta(text)
                for tc in d.get("tool_calls") or []:
                    if not isinstance(tc, dict):
                        continue
                    idx = tc.get("index") if isinstance(tc.get("index"), int) else len(calls)
                    slot = calls.setdefault(idx, {"id": "", "name": "", "arguments": ""})
                    if tc.get("id"):
                        slot["id"] = str(tc["id"])
                    fn = tc.get("function") or {}
                    if isinstance(fn.get("name"), str):
                        slot["name"] += fn["name"]
                    if isinstance(fn.get("arguments"), str):
                        slot["arguments"] += fn["arguments"]
                    if on_tool and slot["name"]:
                        # Model sedang MENYUSUN pemanggilan tool (mis. menulis isi file): beri tahu pemanggil agar UI tidak tampak diam.
                        on_tool(idx, slot["name"], slot["arguments"])
                if ch.get("finish_reason"):
                    finish = ch["finish_reason"]
        if not done and not finish and (parts or calls):
            finish = "incomplete"                          # stream terputus sebelum selesai; hasil parsial dikembalikan
        elif not done and not finish:
            raise AIError("network", "Aliran jawaban berakhir tanpa isi.", retryable=True)
        tool_calls = [ToolCall(c["id"] or f"call_{i}", c["name"], c["arguments"] or "{}")
                      for i, c in sorted(calls.items()) if c["name"]]
        content = "".join(parts)
        return ChatResult(content, tool_calls, finish, self._usage(usage_raw, messages, tools, content, tool_calls), seen_model)
