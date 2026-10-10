"""Rute APK (M1): dashboard, upload, detail analisis, status live (SSE), dan aksi.

Semua rute butuh sesi. Rute yang mengubah state memeriksa token CSRF (form: field `csrf`;
XHR: header `X-CSRF-Token`) selain cookie SameSite=Strict.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from contextlib import closing
from typing import Annotated, Any

import redis
from fastapi import APIRouter, Form, Path, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from starlette.requests import ClientDisconnect

from rvcore import store
from rvcore.db import tx
from rvcore.fsutil import read_json_under, safe_rmtree

from . import status as system_status
from .apkcheck import ApkRejected, Limits, validate_apk
from .context import (
    client_ip,
    current_session,
    db,
    layout,
    log,
    redis_conn,
    render,
    settings,
)
from .jobs import enqueue_analysis
from .security import tokens_equal
from .uploads import UploadError, clean_display_name, receive_to_tmp

router = APIRouter()

AnalysisId = Annotated[int, Path(ge=1, le=2**31 - 1)]
ApkId = Annotated[int, Path(ge=1, le=2**31 - 1)]

# Pesan notifikasi lewat kode (?notice=kode) supaya tidak ada teks bebas yang dipantulkan ke halaman.
NOTICES: dict[str, tuple[str, str]] = {
    "retry_ok": ("ok", "Analisis dijalankan ulang."),
    "cancelled": ("ok", "Analisis dibatalkan."),
    "cancel_requested": ("ok", "Permintaan pembatalan dikirim. Job berhenti dalam beberapa detik."),
    "busy": ("error", "Analisis masih berjalan. Batalkan dulu sebelum mengubahnya."),
    "deleted": ("ok", "APK dan seluruh hasil analisisnya telah dihapus."),
    "enqueue_failed": ("error", "Antrean tidak tersedia saat ini. Coba lagi beberapa saat."),
    "file_missing": ("error", "Berkas APK asli tidak ditemukan di penyimpanan."),
    "not_found": ("error", "Data tidak ditemukan."),
}


def _notice(code: str | None) -> dict[str, str] | None:
    if code and code in NOTICES:
        kind, text = NOTICES[code]
        return {"kind": kind, "text": text}
    return None


def _json(http_status: int, /, **payload: Any) -> JSONResponse:
    # Posisional-saja: payload boleh memuat kunci bernama "status" tanpa bentrok.
    return JSONResponse(payload, status_code=http_status, headers={"Cache-Control": "no-store"})


def _limits() -> Limits:
    return Limits(
        max_entries=settings.zip_max_entries,
        max_total_uncompressed=settings.zip_max_total_uncompressed,
        max_entry_uncompressed=settings.zip_max_entry_uncompressed,
        max_ratio=settings.zip_max_ratio,
    )


# ================================================================== dashboard


def _list_apks(q: str) -> list[dict[str, Any]]:
    with closing(db()) as conn:
        return [dict(r) for r in store.list_apks(conn, q or None)]


@router.get("/", include_in_schema=False)
async def dashboard(request: Request, q: str = Query("", max_length=100),
                    notice: str | None = Query(None, max_length=32)) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    apks = await run_in_threadpool(_list_apks, q.strip())
    sys_status = await run_in_threadpool(
        system_status.collect, redis_conn, layout.work, settings.disk_warn_percent
    )
    return render(
        request,
        "dashboard.html",
        {"user": session.user, "csrf": session.csrf, "status": sys_status, "apks": apks,
         "q": q.strip(), "notice": _notice(notice), "nav": "dashboard"},
    )


# ================================================================== upload


@router.get("/upload", include_in_schema=False)
async def upload_page(request: Request) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    return render(
        request,
        "upload.html",
        {"user": session.user, "csrf": session.csrf, "nav": "upload",
         "max_mb": settings.max_upload_bytes // (1024 * 1024)},
    )


def _store_upload(received, name: str, options: dict[str, Any], ip: str) -> dict[str, Any]:
    """Pindahkan berkas tervalidasi ke penyimpanan permanen dan buat baris DB — atau kenali duplikat."""
    with closing(db()) as conn:
        with tx(conn):
            existing = store.find_apk_by_sha(conn, received.sha256)
            if existing:
                analysis_id = store.latest_analysis_id(conn, existing["id"])
                an = store.get_analysis(conn, analysis_id) if analysis_id else None
                store.audit(conn, "upload_duplicate", {
                    "sha256": received.sha256, "filename": name, "ip": ip, "apk_id": existing["id"],
                })
                received.path.unlink(missing_ok=True)
                return {
                    "duplicate": True,
                    "apk_id": existing["id"],
                    "analysis_id": analysis_id,
                    "status": an["status"] if an else None,
                    "name": existing["filename_display"],
                    "size": existing["size"],
                    "sha256": received.sha256,
                }

            final = layout.upload_path(received.sha256)
            os.replace(received.path, final)
            try:
                os.chmod(final, 0o444)  # read-only setelah tervalidasi (NFR-1.3)
                apk_id, analysis_id = store.create_apk_with_analysis(
                    conn, sha256=received.sha256, md5=received.md5, filename=name,
                    size=received.size, options=options,
                )
                store.audit(conn, "upload", {
                    "sha256": received.sha256, "filename": name, "size": received.size,
                    "authorized": True, "ip": ip, "apk_id": apk_id, "analysis_id": analysis_id,
                })
            except BaseException:
                final.unlink(missing_ok=True)
                raise
            return {"duplicate": False, "apk_id": apk_id, "analysis_id": analysis_id,
                    "sha256": received.sha256}


def _reject_audit(code: str, name: str, ip: str, sha256: str | None = None) -> None:
    try:
        with closing(db()) as conn, tx(conn):
            store.audit(conn, "upload_rejected", {"code": code, "filename": name, "ip": ip, "sha256": sha256})
    except Exception:  # noqa: BLE001 - audit tidak boleh menggagalkan jawaban ke pengguna
        log.exception("gagal mencatat audit upload_rejected")


def _mark_enqueue_failed(analysis_id: int) -> None:
    with closing(db()) as conn:
        store.finish_analysis(conn, analysis_id, store.FAILED, store.E_INTERNAL,
                              "Antrean (Redis) tidak tersedia saat upload. Gunakan “Coba lagi”.")


@router.post("/api/uploads", include_in_schema=False)
async def upload(request: Request) -> Response:
    session = current_session(request)
    if not session:
        return _json(401, error="Sesi berakhir. Muat ulang halaman lalu masuk lagi.", code="auth")
    if not tokens_equal(session.csrf, request.headers.get("x-csrf-token")):
        return _json(403, error="Token keamanan tidak valid. Muat ulang halaman lalu coba lagi.", code="csrf")

    ip = client_ip(request)
    name = clean_display_name(request.headers.get("x-upload-name"))

    # Pemeriksaan murah SEBELUM membaca badan (hemat bandwidth).
    if request.headers.get("x-authorized") != "1":
        return _json(422, error="Centang pernyataan bahwa Anda berwenang menganalisis berkas ini.",
                     code="not_authorized")
    if not name:
        return _json(422, error="Nama berkas tidak ada.", code="no_name")
    if not name.lower().endswith(".apk"):
        return _json(422, error="Hanya berkas .apk yang didukung saat ini (XAPK/APKS menyusul).",
                     code="bad_extension")
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > settings.max_upload_bytes:
        return _json(413, error=f"Berkas melebihi batas {settings.max_upload_bytes // (1024 * 1024)} MB.",
                     code="too_large")
    try:
        free = shutil.disk_usage(layout.uploads).free
    except OSError:
        free = 0
    if free < settings.min_free_bytes:
        log.warning("upload ditolak: disk tersisa %s byte < batas %s", free, settings.min_free_bytes)
        return _json(507, error="Ruang disk server hampir habis; unggahan ditolak untuk melindungi sistem.",
                     code="disk_low")

    options = {"deobf": request.headers.get("x-opt-deobf") == "1"}

    try:
        received = await receive_to_tmp(request, layout.uploads_tmp, settings.max_upload_bytes)
    except UploadError as exc:
        await run_in_threadpool(_reject_audit, exc.code, name, ip)
        return _json(exc.status, error=exc.message, code=exc.code)
    except ClientDisconnect:
        log.info("klien memutus unggahan %r", name)
        return Response(status_code=499)

    try:
        info = await run_in_threadpool(validate_apk, received.path, _limits())
    except ApkRejected as exc:
        received.path.unlink(missing_ok=True)
        await run_in_threadpool(_reject_audit, exc.code, name, ip, received.sha256)
        log.info("upload ditolak code=%s name=%r", exc.code, name)
        return _json(422, error=exc.message, code=exc.code)
    except BaseException:
        received.path.unlink(missing_ok=True)
        raise

    try:
        result = await run_in_threadpool(_store_upload, received, name, options, ip)
    except BaseException:
        received.path.unlink(missing_ok=True)
        raise

    if result["duplicate"]:
        return _json(200, **result)

    analysis_id = result["analysis_id"]
    try:
        await run_in_threadpool(enqueue_analysis, redis_conn, analysis_id, settings.job_timeout)
    except redis.RedisError:
        log.exception("gagal mengantrekan analisis %s", analysis_id)
        await run_in_threadpool(_mark_enqueue_failed, analysis_id)
        return _json(503, error="APK tersimpan, tetapi antrean tidak tersedia. Buka halamannya lalu pilih “Coba lagi”.",
                     code="queue_down", analysis_id=analysis_id, redirect=f"/analyses/{analysis_id}")

    log.info("upload diterima apk=%s analysis=%s size=%s entries=%s", result["apk_id"], analysis_id,
             received.size, info.entries)
    return _json(201, **result, redirect=f"/analyses/{analysis_id}")


# ================================================================== detail


def _detail(analysis_id: int) -> dict[str, Any] | None:
    with closing(db()) as conn:
        an = store.get_analysis(conn, analysis_id)
        if an is None:
            return None
        snap = store.analysis_snapshot(conn, analysis_id)
        artifacts = [dict(a) for a in store.get_artifacts(conn, analysis_id)]
    def _loads(raw: str | None) -> dict[str, Any]:
        try:
            data = json.loads(raw) if raw else {}
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    return {"an": dict(an), "snap": snap, "artifacts": artifacts,
            "versions": _loads(an["tool_versions"]), "options": _loads(an["options"])}


_PERM_RANK = {"dangerous": 0, "special": 1}


def _manifest(analysis_id: int) -> dict[str, Any] | None:
    data = read_json_under(layout.work, str(analysis_id), "manifest.json")
    if not isinstance(data, dict):
        return None
    perms = data.get("permissions")
    if isinstance(perms, list):
        # Berbahaya dulu, lalu khusus, lalu sisanya; urut abjad di dalam tiap kelompok.
        data["permissions"] = sorted(
            (p for p in perms if isinstance(p, dict)),
            key=lambda p: (_PERM_RANK.get(p.get("level"), 2), str(p.get("name") or "")),
        )
    return data


@router.get("/analyses/{analysis_id}", include_in_schema=False)
async def analysis_detail(request: Request, analysis_id: AnalysisId,
                          notice: str | None = Query(None, max_length=32)) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    data = await run_in_threadpool(_detail, analysis_id)
    if data is None:
        return RedirectResponse("/?notice=not_found", status_code=303)
    return render(request, "analysis.html", {
        "user": session.user, "csrf": session.csrf, "nav": "dashboard", "tab": "summary",
        "notice": _notice(notice), **data,
    })


@router.get("/analyses/{analysis_id}/manifest", include_in_schema=False)
async def analysis_manifest(request: Request, analysis_id: AnalysisId) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    data = await run_in_threadpool(_detail, analysis_id)
    if data is None:
        return RedirectResponse("/?notice=not_found", status_code=303)
    # Tampilkan manifest hanya bila apktool selesai pada percobaan ini (berkas lama dari percobaan
    # sebelumnya mungkin masih ada di disk selama analisis menunggu dijalankan ulang).
    apktool_done = any(s["name"] == "apktool" and s["status"] in (store.OK, store.WARN)
                       for s in data["snap"]["stages"])
    manifest = await run_in_threadpool(_manifest, analysis_id) if apktool_done else None
    return render(request, "manifest.html", {
        "user": session.user, "csrf": session.csrf, "nav": "dashboard", "tab": "manifest",
        "notice": None, "manifest": manifest, **data,
    })


# ================================================================== status live


def _snapshot(analysis_id: int) -> dict[str, Any] | None:
    with closing(db()) as conn:
        return store.analysis_snapshot(conn, analysis_id)


@router.get("/analyses/{analysis_id}/status", include_in_schema=False)
async def analysis_status(request: Request, analysis_id: AnalysisId) -> Response:
    if not current_session(request):
        return _json(401, error="auth")
    snap = await run_in_threadpool(_snapshot, analysis_id)
    if snap is None:
        return _json(404, error="not_found")
    return _json(200, **snap)


SSE_MAX_SECONDS = 600  # klien (EventSource) menyambung ulang otomatis
SSE_KEEPALIVE_EVERY = 15


@router.get("/analyses/{analysis_id}/events", include_in_schema=False)
async def analysis_events(request: Request, analysis_id: AnalysisId) -> Response:
    if not current_session(request):
        return PlainTextResponse("auth", status_code=401)

    async def stream():
        loop = asyncio.get_running_loop()
        started = loop.time()
        last_payload = None
        quiet_ticks = 0
        yield "retry: 3000\n\n"
        while True:
            if await request.is_disconnected():
                return
            snap = await run_in_threadpool(_snapshot, analysis_id)
            if snap is None:
                yield "event: gone\ndata: {}\n\n"
                return
            payload = json.dumps(snap, ensure_ascii=False, separators=(",", ":"))
            # server_now selalu berubah; bandingkan tanpa itu supaya hanya perubahan nyata yang dikirim.
            comparable = json.dumps({**snap, "server_now": 0}, ensure_ascii=False, separators=(",", ":"))
            if comparable != last_payload:
                last_payload = comparable
                quiet_ticks = 0
                yield f"data: {payload}\n\n"
            else:
                quiet_ticks += 1
                if quiet_ticks % SSE_KEEPALIVE_EVERY == 0:
                    yield ": keepalive\n\n"
            if snap["terminal"]:
                yield "event: end\ndata: {}\n\n"
                return
            if loop.time() - started > SSE_MAX_SECONDS:
                return
            await asyncio.sleep(1)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            # no-transform: cegah proxy (Caddy encode) membuffer/mengompres aliran.
            "Cache-Control": "no-store, no-transform",
            "X-Accel-Buffering": "no",
        },
    )


# ================================================================== aksi


def _csrf_ok(session, token: str) -> bool:  # noqa: ANN001
    return tokens_equal(session.csrf, token)


def _cancel(analysis_id: int, ip: str) -> str:
    with closing(db()) as conn:
        outcome = store.request_cancel(conn, analysis_id)
        if outcome != "noop":
            with tx(conn):
                store.audit(conn, "analysis_cancel", {"analysis_id": analysis_id, "outcome": outcome, "ip": ip})
        return outcome


@router.post("/analyses/{analysis_id}/cancel", include_in_schema=False)
async def analysis_cancel(request: Request, analysis_id: AnalysisId,
                          csrf: str = Form("", max_length=256)) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if not _csrf_ok(session, csrf):
        return PlainTextResponse("CSRF token tidak valid", status_code=403)
    outcome = await run_in_threadpool(_cancel, analysis_id, client_ip(request))
    code = {"cancelled": "cancelled", "requested": "cancel_requested"}.get(outcome)
    return RedirectResponse(f"/analyses/{analysis_id}" + (f"?notice={code}" if code else ""), status_code=303)


def _prepare_retry(analysis_id: int, ip: str) -> str:
    """Kembalikan 'ok' | 'busy' | 'not_found' | 'file_missing'."""
    with closing(db()) as conn:
        an = store.get_analysis(conn, analysis_id)
        if an is None:
            return "not_found"
        if an["status"] in store.ACTIVE:
            return "busy"
        if not layout.upload_path(an["sha256"]).is_file():
            return "file_missing"
        if not store.reset_for_retry(conn, analysis_id):
            return "busy"
        with tx(conn):
            store.audit(conn, "analysis_retry", {"analysis_id": analysis_id, "ip": ip})
    # Sengaja TIDAK menghapus work/<id> di sini: worker membersihkannya sendiri begitu mengklaim
    # analisis (satu-satunya penulis), sehingga tidak ada balapan antara web dan worker.
    return "ok"


@router.post("/analyses/{analysis_id}/retry", include_in_schema=False)
async def analysis_retry(request: Request, analysis_id: AnalysisId,
                         csrf: str = Form("", max_length=256)) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if not _csrf_ok(session, csrf):
        return PlainTextResponse("CSRF token tidak valid", status_code=403)
    result = await run_in_threadpool(_prepare_retry, analysis_id, client_ip(request))
    if result != "ok":
        target = "/" if result == "not_found" else f"/analyses/{analysis_id}"
        return RedirectResponse(f"{target}?notice={result}", status_code=303)
    try:
        await run_in_threadpool(enqueue_analysis, redis_conn, analysis_id, settings.job_timeout)
    except redis.RedisError:
        log.exception("gagal mengantrekan ulang analisis %s", analysis_id)
        await run_in_threadpool(_mark_enqueue_failed, analysis_id)
        return RedirectResponse(f"/analyses/{analysis_id}?notice=enqueue_failed", status_code=303)
    return RedirectResponse(f"/analyses/{analysis_id}?notice=retry_ok", status_code=303)


def _delete(apk_id: int, ip: str) -> str:
    with closing(db()) as conn:
        row = conn.execute("SELECT sha256, filename_display FROM apk WHERE id = ?", (apk_id,)).fetchone()
        if row is None:
            return "not_found"
        ids = store.delete_apk(conn, apk_id)
        if ids is None:
            return "busy"
        with tx(conn):
            store.audit(conn, "apk_delete", {"apk_id": apk_id, "sha256": row["sha256"],
                                             "filename": row["filename_display"], "analyses": ids, "ip": ip})
    for analysis_id in ids:
        safe_rmtree(layout.work_dir(analysis_id))
    try:
        path = layout.upload_path(row["sha256"])
        path.unlink(missing_ok=True)
    except OSError:
        log.exception("gagal menghapus berkas upload %s", row["sha256"])
    return "deleted"


@router.post("/apks/{apk_id}/delete", include_in_schema=False)
async def apk_delete(request: Request, apk_id: ApkId,
                     csrf: str = Form("", max_length=256)) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if not _csrf_ok(session, csrf):
        return PlainTextResponse("CSRF token tidak valid", status_code=403)
    result = await run_in_threadpool(_delete, apk_id, client_ip(request))
    if result == "busy":
        with closing(db()) as conn:
            aid = store.latest_analysis_id(conn, apk_id)
        return RedirectResponse(f"/analyses/{aid}?notice=busy" if aid else "/?notice=busy", status_code=303)
    return RedirectResponse(f"/?notice={result}", status_code=303)
