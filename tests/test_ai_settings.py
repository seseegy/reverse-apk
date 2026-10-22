"""Pengaturan AI dari UI: penyimpanan DB, seed sekali dari env, resolver konfigurasi efektif,
penarikan daftar model dari router, dan rute halaman /pengaturan/ai.

Yang dibuktikan: base URL/kunci/model TIDAK lagi bersumber dari .env sesudah tersimpan di DB;
kunci tidak pernah tampil utuh di halaman; simpan kosong = pertahankan kunci; daftar model
ditarik dari {base}/models dengan Bearer dan metadata router (mis. context_window) dipertahankan.
DB uji dipakai bersama satu sesi: fixture di sini memotret & memulihkan baris ai_setting.
"""

from __future__ import annotations

import json
import threading
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app import context
from app.ai import settings as ai_settings
from app.ai.config import ConfigError
from app.routes_apk import _ai
from rvcore import db as rvdb
from rvcore import store
from rvcore.db import tx

ENV_KEYS = ("AI_BASE_URL", "AI_API_KEY", "AI_MODEL", "AI_MODEL_PRO", "AI_FALLBACK_MODEL")


@pytest.fixture(autouse=True)
def _preserve_ai_settings():
    with closing(context.db()) as conn:
        before = store.get_ai_settings(conn)
    yield
    with closing(context.db()) as conn, tx(conn):
        conn.execute("DELETE FROM ai_setting")
        if before:
            store.save_ai_settings(conn, before)


def _fresh_db(tmp_path: Path):
    path = tmp_path / "uji.db"
    rvdb.migrate(path)
    return rvdb.connect(path)


# ================================================================================ penyimpanan & migrasi
def test_migrasi_membuat_tabel_dan_store_roundtrip(tmp_path):
    conn = _fresh_db(tmp_path)
    with closing(conn):
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "ai_setting" in tables
        with tx(conn):
            store.save_ai_settings(conn, {"base_url": "https://router.invalid/v1", "model": "m1",
                                          "kunci_asing": "tidak-disimpan"})
        got = store.get_ai_settings(conn)
        assert got == {"base_url": "https://router.invalid/v1", "model": "m1"}


# ================================================================================ resolver & seed
def test_seed_sekali_dari_env_lalu_db_menang(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("AI_API_KEY", "kunci-env")
    monkeypatch.setenv("AI_MODEL", "model-env")
    conn = _fresh_db(tmp_path)
    with closing(conn):
        cfg = ai_settings.effective_config(conn)
        assert (cfg.base_url, cfg.api_key, cfg.model) == ("http://127.0.0.1:9/v1", "kunci-env", "model-env")
        assert store.get_ai_settings(conn)["model"] == "model-env"          # seed tertulis di DB
        with tx(conn):
            store.save_ai_settings(conn, {"model": "model-ui"})             # pengguna mengubah lewat UI
        cfg2 = ai_settings.effective_config(conn)
        assert cfg2.model == "model-ui" and cfg2.api_key == "kunci-env"     # DB menang, env tak dibaca lagi


def test_efektif_kosong_tanpa_env_dan_tanpa_db(tmp_path, monkeypatch):
    for k in ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    conn = _fresh_db(tmp_path)
    with closing(conn):
        cfg = ai_settings.effective_config(conn)
    assert cfg.enabled is False
    assert ai_settings.missing_labels(cfg) == ["Base URL", "Kunci API", "Model utama"]


def test_simpan_validasi(tmp_path):
    conn = _fresh_db(tmp_path)
    with closing(conn):
        with pytest.raises(ConfigError):
            ai_settings.save_settings(conn, {"base_url": "http://router-publik.invalid/v1"})
        with pytest.raises(ConfigError):
            ai_settings.save_settings(conn, {"base_url": "https://ok.invalid/v1", "model": "jelek\nmodel"})
        clean = ai_settings.save_settings(conn, {"base_url": "https://ok.invalid/v1/", "model": " m1 "})
        assert clean["base_url"] == "https://ok.invalid/v1" and clean["model"] == "m1"


def test_mask_key():
    assert ai_settings.mask_key("") == ""
    assert "kunci" not in ai_settings.mask_key("kunci-rahasia-1234")
    assert ai_settings.mask_key("kunci-rahasia-1234").endswith("1234")


# ================================================================================ daftar model dari router
class _RouterHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - nama warisan BaseHTTPRequestHandler
        if self.path != "/v1/models":
            self.send_response(404)
            self.end_headers()
            return
        if self.headers.get("Authorization") != "Bearer kunci-uji":
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":"unauthorized"}')
            return
        body = json.dumps({"data": [
            {"id": "model-a", "context_window": 200000, "max_output_tokens": 8192,
             "capabilities": ["chat", "vision"]},
            {"id": "model-b", "capabilities": ["chat"]},
            {"id": "model-c", "capabilities": {"vision": True}},
            {"id": "model-d", "architecture": {"input_modalities": ["text", "image"]}},
            {"id": "model-e"},
            {"tanpa_id": True}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # diam
        pass


@pytest.fixture
def fake_router():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _RouterHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1"
    srv.shutdown()


def test_fetch_models_mempertahankan_metadata(fake_router):
    models = ai_settings.fetch_models(fake_router, "kunci-uji")
    assert models == [
        {"id": "model-a", "context_window": 200000, "max_output_tokens": 8192, "vision": True},
        {"id": "model-b", "vision": False},          # capabilities ada tanpa vision = pernyataan "tidak"
        {"id": "model-c", "vision": True},           # bentuk dict
        {"id": "model-d", "vision": True},           # bentuk architecture.input_modalities
        {"id": "model-e"},                           # router diam = tidak ada kunci vision (tidak tahu)
    ]


def test_fetch_models_kunci_ditolak_dan_base_kosong(fake_router):
    with pytest.raises(ai_settings.SettingsError, match="ditolak"):
        ai_settings.fetch_models(fake_router, "kunci-salah")
    with pytest.raises(ai_settings.SettingsError, match="kosong"):
        ai_settings.fetch_models("", "kunci-uji")


# ================================================================================ rute halaman
def test_halaman_butuh_login(anon):
    r = anon.get("/pengaturan/ai")
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_simpan_lalu_halaman_memakai_nilai_baru(client, seeded):
    r = client.post("/pengaturan/ai", data={
        "csrf": seeded.csrf, "base_url": "http://127.0.0.1:9/v1",
        "api_key": "sk-live-rahasia-9876", "model": "model-ui", "model_pro": "", "fallback_model": ""})
    assert r.status_code == 303 and "notice=saved" in r.headers["location"]
    cfg, _prices, err = _ai()
    assert err is None and cfg.model == "model-ui" and cfg.api_key == "sk-live-rahasia-9876"
    page = client.get("/pengaturan/ai")
    assert page.status_code == 200
    assert "model-ui" in page.text and "9876" in page.text          # samaran menampilkan 4 terakhir
    assert "sk-live-rahasia-9876" not in page.text                  # kunci utuh TIDAK pernah dirender
    assert "/pengaturan/ai" in client.get("/").text                 # tautan navigasi hadir


def test_simpan_kunci_kosong_mempertahankan_kunci_lama(client, seeded):
    with closing(context.db()) as conn, tx(conn):
        store.save_ai_settings(conn, {"base_url": "http://127.0.0.1:9/v1", "api_key": "kunci-lama-5555",
                                      "model": "m-lama", "model_pro": "", "fallback_model": ""})
    r = client.post("/pengaturan/ai", data={
        "csrf": seeded.csrf, "base_url": "http://127.0.0.1:9/v1", "api_key": "",
        "model": "m-baru", "model_pro": "", "fallback_model": ""})
    assert r.status_code == 303
    with closing(context.db()) as conn:
        s = ai_settings.read_settings(conn)
    assert s["api_key"] == "kunci-lama-5555" and s["model"] == "m-baru"


def test_simpan_csrf_salah_dan_base_url_salah(client, seeded):
    r = client.post("/pengaturan/ai", data={
        "csrf": "salah", "base_url": "http://127.0.0.1:9/v1", "api_key": "", "model": "m",
        "model_pro": "", "fallback_model": ""})
    assert r.status_code == 403
    r = client.post("/pengaturan/ai", data={
        "csrf": seeded.csrf, "base_url": "http://router-publik.invalid/v1", "api_key": "", "model": "m",
        "model_pro": "", "fallback_model": ""})
    assert r.status_code == 400 and "https" in r.text


def test_endpoint_models_dari_router(client, seeded, fake_router):
    r = client.post("/pengaturan/ai/models", data={
        "csrf": seeded.csrf, "base_url": fake_router, "api_key": "kunci-uji"})
    assert r.status_code == 200
    d = r.json()
    assert d["count"] == 5 and d["models"][0]["id"] == "model-a" and d["models"][0]["vision"] is True
    with closing(context.db()) as conn:      # tarikan sukses menyimpan cache katalog di DB
        cache = ai_settings.read_models_cache(conn)
    assert {m["id"] for m in cache} == {"model-a", "model-b", "model-c", "model-d", "model-e"}
    r = client.post("/pengaturan/ai/models", data={
        "csrf": "salah", "base_url": fake_router, "api_key": "kunci-uji"})
    assert r.status_code == 403
    r = client.post("/pengaturan/ai/models", data={
        "csrf": seeded.csrf, "base_url": fake_router, "api_key": "kunci-salah"})
    assert r.status_code == 400 and "ditolak" in r.json()["error"]


# ================================================================================ vision dari metadata router
def test_cache_vision_dan_override_mengalahkan_tebakan_json():
    import json as _json
    from pathlib import Path as _Path
    from app.ai.pricing import PriceTable
    catalog = _json.loads((_Path(__file__).resolve().parent.parent / "config" / "ai_models.json").read_text())
    json_vision_slug = next(s for s, spec in catalog["models"].items() if spec.get("vision"))
    with closing(context.db()) as conn:
        with tx(conn):
            store.save_ai_settings(conn, {"base_url": "http://127.0.0.1:9/v1", "api_key": "kunci-x",
                                          "model": "model-tanpa-json", "model_pro": "", "fallback_model": ""})
        ai_settings.save_models_cache(conn, [{"id": "model-tanpa-json", "vision": True},
                                             {"id": json_vision_slug, "vision": False}])
    with closing(context.db()) as conn:
        assert ai_settings.vision_overrides(conn) == {"model-tanpa-json": True, json_vision_slug: False}
    _cfg, prices, err = _ai()
    assert err is None
    assert prices.supports_vision("model-tanpa-json") is True    # router bilang bisa, JSON diam -> bisa
    assert prices.supports_vision(json_vision_slug) is False     # router bilang tidak, JSON bilang bisa -> router menang


def test_tanpa_cache_keputusan_vision_dari_json_saja():
    with closing(context.db()) as conn, tx(conn):
        store.save_ai_settings(conn, {"base_url": "http://127.0.0.1:9/v1", "api_key": "kunci-x",
                                      "model": "model-tanpa-json", "model_pro": "", "fallback_model": ""})
    _cfg, prices, err = _ai()
    assert err is None and prices.supports_vision("model-tanpa-json") is False   # perilaku lama utuh
