"""`make ai-check`: uji kesiapan provider sebelum dipakai chat.

    docker compose run --rm --no-deps web python -m app.ai.check

Menguji berurutan: konfigurasi, koneksi + chat sederhana, streaming, tool calling, pelaporan pemakaian token, dan (hanya untuk model
yang ditandai "vision": true di config/ai_models.json) membaca gambar. Penanda vision di berkas itu perkiraan; uji ini yang membuktikannya.
Setiap baris [OK ] / [GAGAL] / [INFO]. Kode keluar 0 hanya bila semua yang WAJIB lulus.
Panggilan uji dicatat di ai_call (purpose=check) dan ikut menghitung anggaran. Kunci API tidak pernah dicetak.
"""

from __future__ import annotations

import base64
import json
import os
import struct
import sys
import time
import zlib
from contextlib import closing

from rvcore import db as rvdb
from rvcore.paths import Layout

from . import budget
from . import settings as ai_settings
from .config import ConfigError
from .pricing import PriceTable
from .provider import AIError, Client

OK, BAD, INFO = "[OK ]", "[GAGAL]", "[INFO]"


def _red_png(size: int = 48) -> bytes:
    """PNG persegi merah polos: jawaban benar ('merah') tidak bisa ditebak tanpa benar-benar melihat gambarnya."""
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * size for _ in range(size))

    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
ADD_TOOL = [{"type": "function", "function": {
    "name": "tambah", "description": "Menjumlahkan dua bilangan.",
    "parameters": {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
                   "required": ["a", "b"]}}}]


def main() -> int:
    failed = False

    def line(tag: str, text: str) -> None:
        nonlocal failed
        failed = failed or tag == BAD
        print(f"{tag} {text}", flush=True)

    layout = Layout(os.environ.get("DATA_DIR", "/data"))
    rvdb.migrate(layout.db_path)
    try:
        with closing(rvdb.connect(layout.db_path)) as conn:
            cfg = ai_settings.effective_config(conn)     # koneksi AI dari Pengaturan AI (DB), bukan .env
    except ConfigError as exc:
        line(BAD, f"konfigurasi: {exc}")
        return 1
    if not cfg.enabled:
        line(BAD, "konfigurasi belum lengkap — atur di halaman Pengaturan AI: "
                  + ", ".join(ai_settings.missing_labels(cfg)))
        return 1
    line(OK, f"konfigurasi: {cfg.base_url} | model {cfg.model} | kunci {'*' * 6}{cfg.api_key[-4:] if len(cfg.api_key) > 8 else ''}")

    prices = PriceTable.load(cfg.models_file)
    rate = prices.rate(cfg.model)
    if rate.known:
        line(OK, f"harga {cfg.model}: {rate.in_per_m:g} kredit/1 juta token masuk, {rate.out_per_m:g} keluar "
                 f"(≈ Rp{cfg.idr(rate.in_per_m):,.0f} / Rp{cfg.idr(rate.out_per_m):,.0f})")
    else:
        line(BAD, f"model '{cfg.model}' tidak ada di {cfg.models_file}; biaya dihitung dengan tarif default "
                  f"{rate.in_per_m:g} (mahal). Periksa slug (salin dari portal) atau tambahkan harganya.")
    for name, slug in (("model kuat", cfg.model_pro), ("model cadangan", cfg.fallback_model)):
        if slug and not prices.rate(slug).known:
            line(BAD, f"{name}='{slug}' tidak ada di tabel harga")

    conn = rvdb.connect(layout.db_path)
    with closing(conn):
        try:
            budget.check(conn, cfg)
            snap = budget.snapshot(conn, cfg)
            line(OK, f"anggaran: terpakai hari ini {snap['today']:.3f} dari {cfg.daily_budget:g} kredit "
                     f"(sesi chat maks {cfg.session_budget:g}); 1 kredit ≈ Rp{cfg.credit_idr:,.0f}")
        except AIError as exc:
            line(BAD, exc.message)
            return 1

        client = Client(cfg)
        total_tokens = 0

        def call(label: str, model: str | None = None, **kw):  # noqa: ANN003
            nonlocal total_tokens
            t0 = time.time()
            use = model or cfg.model
            try:
                result = client.chat(model=use, **kw) if model else client.chat(**kw)
            except AIError as exc:
                budget.record(conn, cfg, prices, purpose="check", model=use, result=None, error=exc)
                line(BAD, f"{label}: {exc.message}")
                return None
            cost = budget.record(conn, cfg, prices, purpose="check", model=use, result=result)
            total_tokens += result.usage.prompt + result.usage.completion
            return result, time.time() - t0, cost

        # 1. chat sederhana
        out = call("chat sederhana", messages=[{"role": "user", "content": "Balas hanya dengan kata: SIAP"}],
                   max_tokens=16, temperature=0)
        if out is None:
            return 1
        r, dt, _ = out
        line(OK if r.content.strip() else BAD, f"chat sederhana: dibalas {r.content.strip()[:40]!r} dalam {dt:.1f} dtk")

        # 2. pemakaian token dilaporkan?
        u = r.usage
        if u.estimated:
            line(BAD, "provider TIDAK melaporkan pemakaian token (usage). Biaya hanya perkiraan; anggaran kurang akurat.")
        else:
            line(OK, f"pemakaian token dilaporkan provider: {u.prompt} masuk + {u.completion} keluar"
                     f" (cache {u.cached})")

        # 3. streaming
        chunks: list[str] = []
        out = call("streaming", messages=[{"role": "user", "content": "Hitung 1 sampai 5, dipisah spasi."}],
                   max_tokens=40, temperature=0, stream=True, on_delta=chunks.append)
        if out is not None:
            r, dt, _ = out
            if len(chunks) >= 2:
                line(OK, f"streaming: {len(chunks)} potongan diterima bertahap ({dt:.1f} dtk)")
            elif r.content:
                line(INFO, "streaming: jawaban datang sekaligus (provider tidak mengalirkan); chat tetap berfungsi")
            else:
                line(BAD, "streaming: tidak ada isi")
            if not r.usage.estimated:
                line(OK, "streaming melaporkan pemakaian token")
            else:
                line(INFO, "streaming tidak melaporkan pemakaian (dihitung perkiraan)")

        # 4. tool calling (WAJIB untuk agent)
        msgs = [{"role": "user", "content": "Berapa 17 + 25? Gunakan alat 'tambah'."}]
        out = call("tool calling", messages=msgs, tools=ADD_TOOL, max_tokens=120, temperature=0)
        tool_ok = False
        if out is not None:
            r, dt, _ = out
            if r.tool_calls and r.tool_calls[0].name == "tambah":
                try:
                    args = json.loads(r.tool_calls[0].arguments)
                    tool_ok = float(args.get("a")) + float(args.get("b")) == 42
                except (ValueError, TypeError):
                    tool_ok = False
                if tool_ok:
                    line(OK, f"tool calling: model memanggil tambah({r.tool_calls[0].arguments}) dengan argumen JSON valid")
                    followup = msgs + [
                        {"role": "assistant", "content": r.content or None, "tool_calls": [
                            {"id": r.tool_calls[0].id, "type": "function",
                             "function": {"name": "tambah", "arguments": r.tool_calls[0].arguments}}]},
                        {"role": "tool", "tool_call_id": r.tool_calls[0].id, "content": "42"}]
                    out2 = call("tool calling putaran 2", messages=followup, tools=ADD_TOOL, max_tokens=60, temperature=0)
                    if out2 is not None:
                        line(OK if "42" in out2[0].content else BAD,
                             f"tool calling putaran 2: hasil tool dipakai ({out2[0].content.strip()[:50]!r})")
                else:
                    line(BAD, f"tool calling: argumen tidak valid/salah: {r.tool_calls[0].arguments!r}")
            else:
                line(BAD, "tool calling: model TIDAK memanggil alat (provider/model ini tidak mendukung function calling). "
                          "Chat agent membutuhkannya; pilih model lain atau gunakan mode cadangan.")

        # 5. gambar: hanya untuk model yang boleh dipilih di chat DAN ditandai vision (satu permintaan kecil per model)
        data_url = "data:image/png;base64," + base64.b64encode(_red_png()).decode("ascii")
        for name, slug in (("model utama", cfg.model), ("model kuat", cfg.model_pro)):
            if not slug:
                continue
            if not prices.supports_vision(slug):
                line(INFO, f"gambar: {slug} tidak bertanda \"vision\" di {cfg.models_file}, jadi lampiran gambar ditolak di chat untuk model ini. "
                           "Bila sebenarnya mendukung gambar, tambahkan \"vision\": true lalu jalankan uji ini lagi.")
                continue
            out = call(f"gambar ({slug})", model=slug, max_tokens=24, temperature=0, messages=[{"role": "user", "content": [
                {"type": "text", "text": "Gambar ini satu warna polos. Sebutkan warnanya dalam satu kata bahasa Inggris (red/green/blue/black/white)."},
                {"type": "image_url", "image_url": {"url": data_url}}]}])
            if out is not None:
                answer = out[0].content.strip().lower()
                if "red" in answer or "merah" in answer:
                    line(OK, f"gambar: {slug} benar-benar melihat gambar (menjawab {answer[:30]!r})")
                else:
                    line(BAD, f"gambar: {slug} ditandai vision tetapi tidak mengenali gambar (jawab {answer[:40]!r}). Hapus \"vision\": true untuk "
                              f"model ini di {cfg.models_file} agar UI tidak menawarkan lampiran gambar yang tidak bisa dibaca.")

        snap = budget.snapshot(conn, cfg)
        spent = prices.cost(cfg.model, total_tokens, 0)
        line(INFO, f"uji ini memakai ±{total_tokens} token ≈ {spent:.4f} kredit (Rp{cfg.idr(spent):,.2f}). "
                   f"Cocokkan dengan selisih saldo di portal untuk memastikan harga input/output.")
        line(INFO, f"total terpakai hari ini: {snap['today']:.4f} dari {cfg.daily_budget:g} kredit")
    print()
    print("Siap dipakai untuk chat agent." if not failed else "Ada masalah di atas; perbaiki sebelum memakai chat.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
