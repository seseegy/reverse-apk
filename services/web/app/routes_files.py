"""Rute berkas per analisis: unggah lampiran chat, lihat / unduh / hapus, halaman Berkas, dan ZIP hasil AI.

Semua rute butuh sesi. Rute yang mengubah state memeriksa CSRF (header `X-CSRF-Token` untuk XHR, field `csrf` untuk form).
Penyajian aman: nama asli tidak pernah jadi path; Content-Type ditentukan dari ISI (bukan klaim klien); selain gambar raster
(png/jpeg/gif/webp) semuanya hanya bisa DIUNDUH (attachment + octet-stream + nosniff) sehingga HTML/SVG/JS buatan AI atau lampiran
tidak pernah dieksekusi browser di origin ini. Pratinjau teks lewat JSON dan dirender klien sebagai teks.
"""

from __future__ import annotations

import os
import shutil
from contextlib import closing
from typing import Annotated, Any, Iterator

from fastapi import APIRouter, Form, Path as FPath, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse, RedirectResponse, Response, StreamingResponse
from starlette.requests import ClientDisconnect

from rvcore import store

from . import userfiles as U
from .context import client_ip, current_session, db, file_store, layout, log, render, settings
from .routes_apk import AnalysisId, _json, _tab_context
from .security import tokens_equal
from .uploads import UploadError, clean_display_name, receive_to_tmp

router = APIRouter()
FileId = Annotated[int, FPath(ge=1, le=2**31 - 1)]

TEXT_PREVIEW_BYTES = 512 * 1024      # batas TAMPILAN pratinjau teks di UI (berkas utuh tetap bisa diunduh)
IMAGE_CACHE = "private, max-age=3600"


def describe(analysis_id: int, r: Any) -> dict[str, Any]:
    """Bentuk JSON satu berkas untuk UI. `kind` upload|ai; URL selalu relatif ke origin ini."""
    base = f"/analyses/{int(analysis_id)}/files/{int(r['id'])}"
    return {"id": r["id"], "kind": r["kind"], "name": r["name"], "path": r["path"] if r["kind"] == "ai" else None, "media": r["media"],
            "mime": r["mime"], "size": r["size"], "revision": r["revision"], "download": base + "/download", "text": base + "/text",
            "raw": base + "/raw" if r["media"] == "image" else None}


def _disposition(kind: str, name: str) -> str:
    ascii_name, encoded = U.display_name_for_header(name)
    return f"{kind}; filename=\"{ascii_name}\"; filename*=UTF-8''{encoded}"


def _stream(fh, chunk: int = 256 * 1024) -> Iterator[bytes]:
    try:
        while True:
            data = fh.read(chunk)
            if not data:
                return
            yield data
    finally:
        fh.close()


def _lookup(analysis_id: int, file_id: int):
    with closing(db()) as conn:
        return store.get_file(conn, analysis_id, file_id)


def _open(row) -> tuple[Any, int] | None:
    path = file_store.abs_path(row)
    if path is None:
        return None
    try:
        fh = U.open_regular(path)
    except U.FileError:
        return None
    return fh, os.fstat(fh.fileno()).st_size


def _csrf_header_ok(session, request: Request) -> bool:  # noqa: ANN001
    return tokens_equal(session.csrf, request.headers.get("x-csrf-token"))


# ================================================================== unggah lampiran chat


@router.post("/api/files/upload", include_in_schema=False)
async def upload_attachment(request: Request, analysis: int = Query(..., ge=1, le=2**31 - 1)) -> Response:
    """Lampiran chat: BADAN MENTAH (bukan multipart; alasan sama dengan /api/uploads), nama di header X-File-Name."""
    session = current_session(request)
    if not session:
        return _json(401, error="Sesi berakhir. Muat ulang halaman lalu masuk lagi.", code="auth")
    if not _csrf_header_ok(session, request):
        return _json(403, error="Token keamanan tidak valid. Muat ulang halaman lalu coba lagi.", code="csrf")
    name = clean_display_name(request.headers.get("x-file-name"))
    if not name:
        return _json(422, error="Nama berkas tidak ada.", code="no_name")
    lim = file_store.limits
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > lim.max_file_bytes:
        return _json(413, error=f"Berkas melebihi batas {lim.max_file_bytes // U.MB} MB per berkas (ATTACH_MAX_MB).", code="too_large")

    def pre():
        with closing(db()) as conn:
            if store.get_analysis(conn, analysis) is None:
                return "not_found"
            used, count = store.files_usage(conn, analysis)
        if lim.quota_bytes and used >= lim.quota_bytes:
            return "quota"
        if lim.max_count and count >= lim.max_count:
            return "count"
        try:
            if shutil.disk_usage(layout.files).free < settings.min_free_bytes:
                return "disk"
        except OSError:
            return "disk"
        file_store.purge_stale_uploads(analysis)
        return "ok"

    state = await run_in_threadpool(pre)
    if state == "not_found":
        return _json(404, error="Analisis tidak ditemukan.", code="not_found")
    if state in ("quota", "count"):
        return _json(413, error="Kuota berkas analisis ini penuh. Hapus berkas lama di tab Berkas, atau naikkan FILES_QUOTA_MB di .env.",
                     code="quota")
    if state == "disk":
        return _json(507, error="Ruang disk server hampir habis; unggahan ditolak untuk melindungi sistem.", code="disk_low")

    try:
        received = await receive_to_tmp(request, layout.files_tmp, lim.max_file_bytes)
    except UploadError as exc:
        return _json(exc.status, error=exc.message, code=exc.code)
    except ClientDisconnect:
        return Response(status_code=499)
    try:
        saved = await run_in_threadpool(file_store.save_upload, analysis, received.path, name, received.size, received.sha256)
    except (U.FileError, store.FileQuotaError) as exc:
        return _json(413 if isinstance(exc, store.FileQuotaError) else 500, error=str(exc), code="save_failed")
    except BaseException:
        received.path.unlink(missing_ok=True)
        raise
    row = await run_in_threadpool(_lookup, analysis, saved["id"])
    return _json(201, **describe(analysis, row))


# ================================================================== lihat / unduh / hapus


@router.get("/analyses/{analysis_id}/files/{file_id}/raw", include_in_schema=False)
async def file_raw(request: Request, analysis_id: AnalysisId, file_id: FileId) -> Response:
    """Gambar untuk <img> (thumbnail & pratinjau). HANYA raster yang lolos sniffing; selain itu 404 (pakai /download)."""
    if not current_session(request):
        return PlainTextResponse("auth", status_code=401)
    row = await run_in_threadpool(_lookup, analysis_id, file_id)
    if row is None or row["media"] != "image":
        return PlainTextResponse("tidak ditemukan", status_code=404)
    opened = await run_in_threadpool(_open, row)
    if opened is None:
        return PlainTextResponse("tidak ditemukan", status_code=404)
    fh, size = opened
    head = fh.read(16)
    fh.seek(0)
    kind = U.sniff_image(head)
    if kind is None:                                   # isi berubah / bukan gambar: jangan sajikan inline
        fh.close()
        return PlainTextResponse("bukan gambar", status_code=415)
    return StreamingResponse(_stream(fh), media_type=U._IMAGE_MIME[kind], headers={
        "Content-Length": str(size), "Content-Disposition": _disposition("inline", row["name"]), "Cache-Control": IMAGE_CACHE,
        "Content-Security-Policy": "default-src 'none'; sandbox", "X-Content-Type-Options": "nosniff"})


@router.get("/analyses/{analysis_id}/files/{file_id}/download", include_in_schema=False)
async def file_download(request: Request, analysis_id: AnalysisId, file_id: FileId) -> Response:
    if not current_session(request):
        return PlainTextResponse("auth", status_code=401)
    row = await run_in_threadpool(_lookup, analysis_id, file_id)
    opened = await run_in_threadpool(_open, row) if row is not None else None
    if row is None or opened is None:
        return PlainTextResponse("tidak ditemukan", status_code=404)
    fh, size = opened
    return StreamingResponse(_stream(fh), media_type="application/octet-stream", headers={
        "Content-Length": str(size), "Content-Disposition": _disposition("attachment", row["name"]), "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; sandbox", "X-Content-Type-Options": "nosniff"})


def _preview(row) -> dict[str, Any]:
    d: dict[str, Any] = {"id": row["id"], "name": row["name"], "kind": row["kind"], "path": row["path"] if row["kind"] == "ai" else None,
                         "media": row["media"], "size": row["size"], "revision": row["revision"]}
    if row["media"] == "image":
        return {**d, "image": True}
    try:
        raw = file_store.read_bytes(row, TEXT_PREVIEW_BYTES + 1)
    except U.FileError:
        return {**d, "missing": True}
    if row["media"] == "binary" or b"\x00" in raw[:8192]:
        return {**d, "binary": True}
    truncated = len(raw) > TEXT_PREVIEW_BYTES
    text = raw[:TEXT_PREVIEW_BYTES].decode("utf-8", errors="replace")
    return {**d, "text": text, "truncated": truncated, "lines": text.count("\n") + 1}


@router.get("/analyses/{analysis_id}/files/{file_id}/text", include_in_schema=False)
async def file_text(request: Request, analysis_id: AnalysisId, file_id: FileId) -> Response:
    """Pratinjau teks (JSON). Klien menampilkannya lewat textContent: tidak pernah sebagai HTML."""
    if not current_session(request):
        return _json(401, error="Sesi berakhir. Muat ulang halaman.")
    row = await run_in_threadpool(_lookup, analysis_id, file_id)
    if row is None:
        return _json(404, error="Berkas tidak ditemukan.")
    return _json(200, **await run_in_threadpool(_preview, row))


@router.post("/analyses/{analysis_id}/files/{file_id}/delete", include_in_schema=False)
async def file_delete(request: Request, analysis_id: AnalysisId, file_id: FileId, csrf: str = Form("", max_length=256)) -> Response:
    """Hapus berkas. XHR (header X-CSRF-Token) -> JSON; form (field csrf) -> redirect ke tab Berkas."""
    session = current_session(request)
    xhr = "x-csrf-token" in request.headers
    if not session:
        return _json(401, error="Sesi berakhir.") if xhr else RedirectResponse("/login", status_code=303)
    if not (_csrf_header_ok(session, request) if xhr else tokens_equal(session.csrf, csrf)):
        return _json(403, error="Token keamanan tidak valid.") if xhr else PlainTextResponse("CSRF token tidak valid", status_code=403)
    ok = await run_in_threadpool(file_store.delete, analysis_id, file_id)
    if ok:
        log.info("berkas %s dihapus (analisis %s) ip=%s", file_id, analysis_id, client_ip(request))
    return _json(200 if ok else 404, ok=ok) if xhr else RedirectResponse(f"/analyses/{analysis_id}/files", status_code=303)


# ================================================================== halaman Berkas + ZIP


def _page_data(analysis_id: int) -> dict[str, Any]:
    with closing(db()) as conn:
        ups = [describe(analysis_id, r) | {"created_at": r["created_at"], "updated_at": r["updated_at"]}
               for r in store.list_files(conn, analysis_id, "upload")]
        ais = [describe(analysis_id, r) | {"created_at": r["created_at"], "updated_at": r["updated_at"]}
               for r in store.list_files(conn, analysis_id, "ai")]
        used, count = store.files_usage(conn, analysis_id)
    lim = file_store.limits
    return {"uploads": ups, "ai_files": ais, "used": used, "count": count, "quota": lim.quota_bytes, "max_file": lim.max_file_bytes}


@router.get("/analyses/{analysis_id}/files", include_in_schema=False)
async def analysis_files(request: Request, analysis_id: AnalysisId) -> Response:
    early, ctx = await _tab_context(request, analysis_id, "files")
    if early is not None:
        return early
    data = await run_in_threadpool(_page_data, analysis_id)
    return render(request, "files.html", {**ctx, **data})


@router.get("/analyses/{analysis_id}/files/download.zip", include_in_schema=False)
async def files_zip(request: Request, analysis_id: AnalysisId, kind: str = Query("ai", max_length=6)) -> Response:
    """Semua berkas satu jenis dalam satu ZIP, dialirkan (memori konstan)."""
    if not current_session(request):
        return PlainTextResponse("auth", status_code=401)
    kind = "upload" if kind == "upload" else "ai"

    def build():
        with closing(db()) as conn:
            rows = store.list_files(conn, analysis_id, kind)
        entries, seen = [], set()
        for r in rows:
            path = file_store.abs_path(r)
            if path is None:
                continue
            arc = r["path"] if kind == "ai" else f"{r['id']}-" + r["name"].replace("/", "_").replace("\\", "_").lstrip(".")[:150]
            if arc in seen:
                continue
            seen.add(arc)
            entries.append((arc, path, r["updated_at"]))
        return entries

    entries = await run_in_threadpool(build)
    if not entries:
        return PlainTextResponse("tidak ada berkas", status_code=404)
    label = "hasil-ai" if kind == "ai" else "lampiran"
    return StreamingResponse(U.iter_zip(entries), media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="analisis-{analysis_id}-{label}.zip"', "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff"})
