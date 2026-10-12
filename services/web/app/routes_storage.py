"""Halaman Penyimpanan (PRD 10, tahap 1): HANYA MELIHAT. Tidak ada rute di sini yang menghapus atau mengubah apa pun.

GET  /storage        angka dari DB (instan) + hasil pemindaian disk terakhir bila ada. Tidak pernah memindai disk sendiri.
POST /storage/scan   memindai disk atas permintaan (CSRF), lalu kembali ke halaman. Satu pemindaian pada satu waktu.
"""

from __future__ import annotations

import time
from contextlib import closing
from typing import Any

from fastapi import APIRouter, Form, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse, RedirectResponse, Response

from . import storage
from .context import current_session, db, layout, log, render
from .security import tokens_equal

router = APIRouter()
SCAN_CACHE = storage.ScanCache()

NOTICES = {
    "scanned": ("ok", "Pemeriksaan disk selesai."),
    "busy": ("info", "Pemeriksaan lain sedang berjalan. Tunggu sebentar lalu muat ulang halaman ini."),
    "failed": ("error", "Pemeriksaan disk gagal. Lihat log server untuk rinciannya."),
}

# Urutan tabel "Per APK" (tautan di judul kolom; tanpa JavaScript). Kunci = nilai ?urut=, bawaan "total".
SORTS: dict[str, tuple[str, Any, bool]] = {
    "total": ("Total", lambda i: (i["total"], i["apk_id"]), True),
    "dekompilasi": ("Hasil dekompilasi", lambda i: (i["decompile"], i["apk_id"]), True),
    "nama": ("Nama", lambda i: ((i["name"] or "").lower(), i["apk_id"]), False),
}


def _notice(code: str | None) -> dict[str, str] | None:
    if code and code in NOTICES:
        kind, text = NOTICES[code]
        return {"kind": kind, "text": text}
    return None


def _view(sort: str) -> dict[str, Any]:
    """Susun semua data halaman. Blocking (SQLite + statvfs): panggil lewat threadpool. TIDAK menyentuh isi folder data."""
    key = sort if sort in SORTS else "total"
    with closing(db()) as conn:
        data = storage.from_db(conn)
    items = sorted(data["items"], key=SORTS[key][1], reverse=SORTS[key][2])
    last = SCAN_CACHE.peek()
    scan = last if last is not None and not last.error else None
    comp = storage.composition(data["totals"], scan)
    # "Dipakai aplikasi" untuk kartu disk server: ukuran di disk bila sudah dipindai, selain itu perkiraan dari catatan DB.
    if scan is not None:
        app_bytes = sum(scan.roots[k].disk for k in ("uploads", "work", "files", "db")) + scan.tmp.disk
    else:
        app_bytes = sum(data["totals"].values())
    usage = storage.disk_usage(layout.work)
    host = storage.host_view(usage, app_bytes) if usage else None
    if scan:
        for it in items:
            w = scan.work_by_analysis.get(it["analysis_id"]) if it["analysis_id"] else None
            f = scan.files_by_analysis.get(it["analysis_id"]) if it["analysis_id"] else None
            it["on_disk"] = (w.disk if w else 0) + (f.disk if f else 0)
    return {"data": data, "items": items, "sort": key, "sorts": {k: v[0] for k, v in SORTS.items()},
            "scan": scan, "scan_failed": bool(last is not None and last.error),
            "comp": comp, "host": host, "app_estimated": scan is None, "limit": storage.LIST_LIMIT}


@router.get("/storage", include_in_schema=False)
async def storage_page(request: Request, urut: str = Query("total", max_length=16),
                       notice: str | None = Query(None, max_length=16)) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    view = await run_in_threadpool(_view, urut)
    return render(request, "storage.html", {"user": session.user, "csrf": session.csrf, "nav": "storage",
                                            "notice": _notice(notice), **view})


def _run_scan() -> storage.DiskScan:
    with closing(db()) as conn:
        return storage.scan_disk(layout, conn)


@router.post("/storage/scan", include_in_schema=False)
async def storage_scan(request: Request, csrf: str = Form("", max_length=256)) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if not tokens_equal(session.csrf, csrf):
        return PlainTextResponse("CSRF token tidak valid", status_code=403)
    started = time.monotonic()
    result, busy = await run_in_threadpool(SCAN_CACHE.get, _run_scan, True)
    if busy:
        return RedirectResponse("/storage?notice=busy", status_code=303)
    if result is None or result.error:
        log.error("pemeriksaan disk gagal: %s", result.error if result else "tanpa hasil")
        return RedirectResponse("/storage?notice=failed", status_code=303)
    log.info("pemeriksaan disk selesai dalam %.1f dtk (partial=%s)", time.monotonic() - started, result.partial)
    return RedirectResponse("/storage?notice=scanned", status_code=303)
