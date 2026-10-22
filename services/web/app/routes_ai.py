"""Halaman Pengaturan AI: base URL, kunci API, dan model diatur dari UI (bukan .env lagi).

Nilai tersimpan di tabel ai_setting lewat app/ai/settings.py dan langsung berlaku untuk chat
(konfigurasi dibaca ulang tiap permintaan). Kunci API tidak pernah dirender utuh ke halaman:
formulir hanya menampilkan samarannya, dan bidang kunci yang dikosongkan berarti "pertahankan".
"""

from __future__ import annotations

from contextlib import closing
from typing import Any

from fastapi import APIRouter, Form, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse, Response

from .ai import settings as ai_settings
from .ai.config import ConfigError
from .context import audit_event, current_session, db, render
from .security import tokens_equal

router = APIRouter()

NOTICES = {
    "saved": ("ok", "Pengaturan AI disimpan. Nilai baru langsung berlaku untuk chat, tanpa restart."),
}


def _notice(code: str | None) -> dict[str, str] | None:
    if code and code in NOTICES:
        kind, text = NOTICES[code]
        return {"kind": kind, "text": text}
    return None


def _load_page() -> dict[str, Any]:
    with closing(db()) as conn:
        cfg = ai_settings.effective_config(conn)
        values = ai_settings.read_settings(conn)
    return {"values": values, "key_masked": ai_settings.mask_key(values["api_key"]),
            "key_set": bool(values["api_key"]), "enabled": cfg.enabled,
            "missing": ai_settings.missing_labels(cfg)}


def _save(values: dict[str, str]) -> dict[str, str]:
    with closing(db()) as conn:
        return ai_settings.save_settings(conn, values)


def _stored_key_and_base() -> tuple[str, str]:
    with closing(db()) as conn:
        s = ai_settings.read_settings(conn)
    return s["base_url"], s["api_key"]


@router.get("/pengaturan/ai", include_in_schema=False)
async def ai_settings_page(request: Request, notice: str | None = Query(None, max_length=16)) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    data = await run_in_threadpool(_load_page)
    return render(request, "ai_settings.html", {
        "user": session.user, "csrf": session.csrf, "nav": "ai_settings",
        "notice": _notice(notice), "error": None, **data})


@router.post("/pengaturan/ai", include_in_schema=False)
async def ai_settings_save(request: Request,
                           csrf: str = Form("", max_length=256),
                           base_url: str = Form("", max_length=2048),
                           api_key: str = Form("", max_length=4096),
                           model: str = Form("", max_length=200),
                           model_pro: str = Form("", max_length=200),
                           fallback_model: str = Form("", max_length=200),
                           clear_key: str = Form("", max_length=2)) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if not tokens_equal(session.csrf, csrf):
        return Response("CSRF token tidak valid", status_code=403)
    stored_base, stored_key = await run_in_threadpool(_stored_key_and_base)
    if clear_key == "1":
        new_key = ""
    elif api_key.strip():
        new_key = api_key.strip()
    else:
        new_key = stored_key                       # bidang dikosongkan = pertahankan kunci lama
    values = {"base_url": base_url.strip(), "api_key": new_key, "model": model.strip(),
              "model_pro": model_pro.strip(), "fallback_model": fallback_model.strip()}
    try:
        saved = await run_in_threadpool(_save, values)
    except ConfigError as exc:
        data = await run_in_threadpool(_load_page)
        shown = dict(values)
        shown["api_key"] = ""                      # kunci tidak pernah digemakan kembali ke halaman
        return render(request, "ai_settings.html", {
            "user": session.user, "csrf": session.csrf, "nav": "ai_settings",
            "notice": None, "error": str(exc), **data, "values": shown}, status_code=400)
    audit_event("ai_settings_save", {"base_url": saved["base_url"], "model": saved["model"],
                                     "model_pro": saved["model_pro"], "fallback_model": saved["fallback_model"],
                                     "key_set": bool(saved["api_key"]), "key_cleared": clear_key == "1"})
    return RedirectResponse("/pengaturan/ai?notice=saved", status_code=303)


@router.post("/pengaturan/ai/models", include_in_schema=False)
async def ai_settings_models(request: Request,
                             csrf: str = Form("", max_length=256),
                             base_url: str = Form("", max_length=2048),
                             api_key: str = Form("", max_length=4096)) -> Response:
    """Daftar model dari router untuk pengisi pilihan model (JSON). Nilai formulir yang terisi
    didahulukan agar pengguna bisa mencoba koneksi SEBELUM menyimpan; kunci kosong = kunci tersimpan."""
    session = current_session(request)
    if not session:
        return JSONResponse({"error": "Sesi berakhir. Muat ulang halaman dan masuk lagi."}, status_code=401)
    if not tokens_equal(session.csrf, csrf):
        return JSONResponse({"error": "CSRF token tidak valid."}, status_code=403)
    stored_base, stored_key = await run_in_threadpool(_stored_key_and_base)
    base = base_url.strip() or stored_base
    key = api_key.strip() or stored_key
    try:
        models = await run_in_threadpool(ai_settings.fetch_models, base, key)
    except (ConfigError, ai_settings.SettingsError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception:  # noqa: BLE001 - jangan bocorkan rincian internal ke browser
        return JSONResponse({"error": "Gagal menarik daftar model. Lihat log server untuk rinciannya."},
                            status_code=502)
    return JSONResponse({"models": models, "count": len(models)})
