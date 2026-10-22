"""Pengaturan koneksi AI dari UI (halaman Pengaturan AI) — sumber kebenaran koneksi AI sekarang.

Base URL, kunci API, dan pilihan model TIDAK lagi dibaca dari .env: nilainya tersimpan di tabel
`ai_setting` (database server) dan diatur lewat halaman Pengaturan AI. Satu-satunya sentuhan env
yang tersisa adalah SEED SEKALI: bila tabel masih kosong sama sekali dan env lama terisi, nilainya
disalin sekali ke DB agar peningkatan versi tidak mematikan AI yang sedang berjalan; sesudah baris
pertama tersimpan, env tidak pernah dibaca lagi untuk kelima bidang ini.

Kunci API: tersimpan hanya di server, tidak pernah dikembalikan utuh ke browser (UI hanya menerima
samaran), tidak pernah dicatat, dan pesan galat di modul ini tidak memuatnya.
"""

from __future__ import annotations

import http.client
import json
import sqlite3
import ssl
from dataclasses import replace
from urllib.parse import urlsplit

from rvcore import db as rvdb
from rvcore import store

from .config import AIConfig, ConfigError, load_ai_config, validate_base_url

KEYS = store.AI_SETTING_KEYS
LABELS = {"base_url": "Base URL", "api_key": "Kunci API", "model": "Model utama",
          "model_pro": "Model kuat", "fallback_model": "Model cadangan"}
MAX_MODELS = 500          # pagat daftar model dari router (portal bisa memuat ratusan slug)
MAX_BODY = 4 * 1024 * 1024


class SettingsError(ValueError):
    """Galat pengaturan/daftar model yang aman ditampilkan ke pengguna (tidak memuat kunci)."""


def read_settings(conn: sqlite3.Connection) -> dict[str, str]:
    """Nilai mentah dari DB untuk kelima kunci (yang belum tersimpan = '')."""
    raw = store.get_ai_settings(conn)
    return {k: (raw.get(k) or "") for k in KEYS}


def seed_from_env_once(conn: sqlite3.Connection) -> bool:
    """Salin konfigurasi env lama ke DB — HANYA bila tabel ai_setting masih kosong sama sekali."""
    if store.get_ai_settings(conn):
        return False
    try:
        env_cfg = load_ai_config()
    except ConfigError:
        return False                       # env lama pun tidak sah: jangan seed nilai rusak
    values = {"base_url": env_cfg.base_url, "api_key": env_cfg.api_key, "model": env_cfg.model,
              "model_pro": env_cfg.model_pro, "fallback_model": env_cfg.fallback_model}
    if not any(values.values()):
        return False
    with rvdb.tx(conn):
        store.save_ai_settings(conn, values)
    return True


def effective_config(conn: sqlite3.Connection) -> AIConfig:
    """AIConfig efektif: knob umum tetap dari env; lima bidang koneksi dari DB (sesudah seed sekali)."""
    seed_from_env_once(conn)
    s = read_settings(conn)
    base = load_ai_config()
    updates = {k: s[k].strip() for k in KEYS}
    updates["base_url"] = validate_base_url(updates["base_url"])
    return replace(base, **updates)


def save_settings(conn: sqlite3.Connection, values: dict[str, str]) -> dict[str, str]:
    """Validasi + simpan nilai dari formulir. Mengembalikan nilai bersih yang tersimpan."""
    clean = {k: (values.get(k) or "").strip() for k in KEYS}
    clean["base_url"] = validate_base_url(clean["base_url"])      # ConfigError -> ditangkap rute
    for k in ("model", "model_pro", "fallback_model"):
        if len(clean[k]) > 200 or any(ord(c) < 32 for c in clean[k]):
            raise ConfigError(f"{LABELS[k]} tidak sah (maksimal 200 karakter, tanpa karakter kontrol).")
    if len(clean["api_key"]) > 4096:
        raise ConfigError("Kunci API terlalu panjang (maksimal 4096 karakter).")
    with rvdb.tx(conn):
        store.save_ai_settings(conn, clean)
    return clean


def mask_key(key: str) -> str:
    """Samaran kunci untuk UI: tidak pernah mengembalikan kunci utuh."""
    if not key:
        return ""
    return "••••••••" + (key[-4:] if len(key) > 8 else "")


def missing_labels(cfg: AIConfig) -> list[str]:
    """Nama bidang koneksi yang masih kosong (untuk pesan 'belum dikonfigurasi')."""
    out = []
    if not cfg.base_url:
        out.append(LABELS["base_url"])
    if not cfg.api_key:
        out.append(LABELS["api_key"])
    if not cfg.model:
        out.append(LABELS["model"])
    return out


def fetch_models(base_url: str, api_key: str, *, connect_timeout: float = 10.0,
                 read_timeout: float = 30.0) -> list[dict]:
    """Tarik daftar model dari router: GET {base_url}/models (kompatibel OpenAI), kunci sebagai Bearer.

    Mengembalikan [{id, context_window?, max_output_tokens?}] — metadata disertakan hanya bila
    router memberikannya (mis. GripHub). Galat -> SettingsError berpesan aman (tanpa kunci).
    """
    base = validate_base_url(base_url)                    # ConfigError (ValueError) -> ditangkap pemanggil
    if not base:
        raise SettingsError("Base URL masih kosong. Isi dulu, misalnya https://griphubrouter.web.id/v1.")
    if not api_key:
        raise SettingsError("Kunci API masih kosong. Isi dulu, atau simpan pengaturan yang memuat kunci.")
    parts = urlsplit(base)
    tls = parts.scheme == "https"
    host = parts.hostname or ""
    port = parts.port or (443 if tls else 80)
    path = parts.path.rstrip("/") + "/models"
    if tls:
        conn = http.client.HTTPSConnection(host, port, timeout=connect_timeout,
                                           context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=connect_timeout)
    try:
        conn.connect()
        if conn.sock is not None:
            conn.sock.settimeout(read_timeout)
        conn.request("GET", path, headers={"Authorization": f"Bearer {api_key}",
                                           "Accept": "application/json"})
        resp = conn.getresponse()
        raw = resp.read(MAX_BODY + 1)
        status = resp.status
    except (OSError, http.client.HTTPException) as exc:
        raise SettingsError(f"Tidak bisa menghubungi router di {host}: {type(exc).__name__}. "
                            "Periksa Base URL dan jaringan server.") from None
    finally:
        conn.close()
    if status in (401, 403):
        raise SettingsError(f"Kunci API ditolak router (HTTP {status}). Periksa kembali kuncinya.")
    if status != 200:
        raise SettingsError(f"Router menjawab HTTP {status} untuk daftar model. Periksa Base URL "
                            "(harus berakhiran /v1 untuk router kompatibel OpenAI).")
    if len(raw) > MAX_BODY:
        raise SettingsError("Jawaban daftar model terlalu besar; tidak diproses.")
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        raise SettingsError("Jawaban router bukan JSON yang sah; daftar model tidak bisa dibaca.") from None
    items = data.get("data") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise SettingsError("Format daftar model tidak dikenal (tidak ada daftar 'data').")
    out: list[dict] = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
            continue
        row: dict = {"id": item["id"]}
        for src, dst in (("context_window", "context_window"), ("context_length", "context_window"),
                         ("max_output_tokens", "max_output_tokens"), ("max_tokens", "max_output_tokens")):
            v = item.get(src)
            if isinstance(v, int) and v > 0 and dst not in row:
                row[dst] = v
        out.append(row)
        if len(out) >= MAX_MODELS:
            break
    if not out:
        raise SettingsError("Router tidak mengembalikan model apa pun.")
    return out
