"""Halaman Penyimpanan (PRD 10): melihat (tahap 1) dan membersihkan (tahap 2).

GET  /storage                angka dari DB (instan) + hasil pemindaian disk terakhir bila ada. Tidak pernah memindai disk sendiri.
POST /storage/scan           memindai disk atas permintaan (CSRF), lalu kembali ke halaman. Satu pemindaian pada satu waktu.
GET  /storage/bersihkan      HALAMAN KONFIRMASI: pratinjau apa yang akan dihapus dan akibatnya. TIDAK mengubah apa pun (aman di-refresh).
POST /storage/bersihkan      menghapus (CSRF). Menerima jenis + nama/id yang divalidasi, TIDAK PERNAH path; semua syarat dicek ulang di sini.

Aturan penghapusan ada di storage_clean.py; modul ini hanya HTTP: sesi, CSRF, validasi masukan, dan tampilan.
"""

from __future__ import annotations

import re
import time
from contextlib import closing
from typing import Any

from fastapi import APIRouter, Form, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse, RedirectResponse, Response

from . import storage, storage_clean
from .context import client_ip, current_session, db, layout, log, reaper, render
from .security import tokens_equal

router = APIRouter()
SCAN_CACHE = storage.ScanCache()

MAX_KEYS = 500             # batas jumlah item dalam satu aksi massal (form tidak boleh membawa ribuan nama)
MAX_KEY_LEN = 220
NOTICES = {
    "scanned": ("ok", "Pemeriksaan disk selesai."),
    "cleaned": ("ok", ""),                       # teks disusun dari LAST_RESULT (angka tidak pernah lewat URL)
    "nothing": ("info", "Tidak ada yang dihapus: semuanya sudah tidak memenuhi syarat atau sudah bersih."),
    "bad": ("error", "Permintaan pembersihan tidak valid."),
    "busy": ("info", "Pemeriksaan lain sedang berjalan. Tunggu sebentar lalu muat ulang halaman ini."),
    "failed": ("error", "Pemeriksaan disk gagal. Lihat log server untuk rinciannya."),
}

# Urutan tabel "Per APK" (tautan di judul kolom; tanpa JavaScript). Kunci = nilai ?urut=, bawaan "total".
SORTS: dict[str, tuple[str, Any, bool]] = {
    "total": ("Total", lambda i: (i["total"], i["apk_id"]), True),
    "dekompilasi": ("Hasil dekompilasi", lambda i: (i["decompile"], i["apk_id"]), True),
    "nama": ("Nama", lambda i: ((i["name"] or "").lower(), i["apk_id"]), False),
}


# Hasil pembersihan terakhir, ditampilkan SEKALI di /storage?notice=cleaned. Satu pengguna, satu proses (--workers 1): variabel modul cukup.
LAST_RESULT: dict[str, Any] = {}


def _notice(code: str | None) -> dict[str, str] | None:
    if code == "cleaned":
        r = LAST_RESULT.pop("r", None)
        if r is None:
            return None
        return {"kind": "ok" if r.removed else "info", "text": _result_text(r)}
    if code and code in NOTICES:
        kind, text = NOTICES[code]
        return {"kind": kind, "text": text}
    return None


def _result_text(r: storage_clean.Result) -> str:
    """Satu kalimat jujur: apa yang BENAR-BENAR dipindahkan, berapa yang dilewati, dan bahwa penghapusan akhir berjalan di belakang layar."""
    from .context import fmt_bytes
    if r.kind == storage_clean.Kind.RECORDS:
        out = f"{r.removed} catatan dihapus dari database."
    elif r.kind == storage_clean.Kind.TMP:
        out = f"{r.removed} sisa unggahan sementara dihapus ({fmt_bytes(r.freed)})."
    else:
        out = f"{r.removed} item dibersihkan ({fmt_bytes(r.freed)})."
        if r.removed:
            out += " Penghapusan akhir berjalan di belakang layar; ruang disk bebas bertambah sebentar lagi."
    if r.skipped:
        out += f" {len(r.skipped)} dilewati karena tidak lagi memenuhi syarat."
    return out


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
    tmp_plan = storage_clean.plan_tmp(layout) if scan is not None else None      # baca-saja, murah: hanya isi dua folder .tmp
    return {"data": data, "items": items, "sort": key, "sorts": {k: v[0] for k, v in SORTS.items()},
            "tmp_old": (len(tmp_plan.items), tmp_plan.disk) if tmp_plan and tmp_plan.items else None,
            "trashing": reaper.pending(),
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


# ================================================================== pembersihan (tahap 2)
ACTIONS = {"hasil": storage_clean.Kind.DECOMPILE, "sisa": storage_clean.Kind.ORPHAN, "sementara": storage_clean.Kind.TMP,
           "catatan": storage_clean.Kind.RECORDS}
_KEY_OK = re.compile(r"^[A-Za-z0-9._/\-]{1,%d}$" % MAX_KEY_LEN)


def _clean_keys(raw: list[str]) -> list[str] | None:
    """Daftar kunci dari form -> daftar tervalidasi, atau None bila ada yang janggal. Validasi bentuk di sini; keputusan 'boleh dihapus?'
    tetap dibuat ulang di storage_clean (lapisan lain yang tidak bergantung pada ini)."""
    if len(raw) > MAX_KEYS or any(not _KEY_OK.match(k) or ".." in k or "//" in k or k.startswith("/") or k.endswith("/") for k in raw):
        return None
    return list(dict.fromkeys(raw))


def _clean_ids(raw: list[str]) -> list[int] | None:
    if len(raw) > MAX_KEYS or any(not r.isascii() or not r.isdigit() or len(r) > 10 for r in raw):
        return None
    return list(dict.fromkeys(int(r) for r in raw))


def _preview(aksi: str, analisis: int | None, keys: list[str] | None, ids: list[int] | None) -> storage_clean.Plan:
    """Rencana SAAT INI (membaca saja). Dipakai halaman konfirmasi; eksekusi menghitung ulang sendiri."""
    with closing(db()) as conn:
        kind = ACTIONS[aksi]
        if kind == storage_clean.Kind.DECOMPILE:
            return storage_clean.plan_decompile(layout, conn, analisis or 0)
        if kind == storage_clean.Kind.ORPHAN:
            return storage_clean.plan_orphans(layout, conn, keys)
        if kind == storage_clean.Kind.TMP:
            return storage_clean.plan_tmp(layout)
        return storage_clean.plan_records(layout, conn, ids)


@router.get("/storage/bersihkan", include_in_schema=False)
async def clean_preview(request: Request, aksi: str = Query("", max_length=12), analisis: int = Query(0, ge=0, le=2**31 - 1)) -> Response:
    """Halaman konfirmasi. TIDAK mengubah apa pun. `aksi=sisa|catatan` tanpa daftar = pratinjau SEMUA yang kini memenuhi syarat; daftar yang
    dikirim form konfirmasi adalah hasil pratinjau ini, jadi yang dihapus tidak pernah lebih luas dari yang ditampilkan."""
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if aksi not in ACTIONS or (aksi == "hasil" and not analisis):
        return RedirectResponse("/storage?notice=bad", status_code=303)
    plan = await run_in_threadpool(_preview, aksi, analisis or None, None, None)
    return render(request, "storage_confirm.html", {"user": session.user, "csrf": session.csrf, "nav": "storage", "aksi": aksi,
                                                    "analisis": analisis, "plan": plan, "limit": storage.LIST_LIMIT})


def _do_clean(kind: str, analisis: int | None, keys: list[str] | None, ids: list[int] | None, ip: str) -> storage_clean.Result:
    with closing(db()) as conn:
        return storage_clean.execute(layout, conn, kind, analysis_id=analisis, keys=keys, ids=ids, ip=ip, reaper=reaper)


@router.post("/storage/bersihkan", include_in_schema=False)
async def clean_execute(request: Request) -> Response:
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    # Batas eksplisit (jangan bergantung pada bawaan Starlette yang bisa berubah): form ini tidak pernah membawa berkas.
    form = await request.form(max_files=0, max_fields=MAX_KEYS + 10, max_part_size=64 * 1024)
    if not tokens_equal(session.csrf, str(form.get("csrf", ""))[:256]):
        return PlainTextResponse("CSRF token tidak valid", status_code=403)
    aksi = str(form.get("aksi", ""))[:12]
    if aksi not in ACTIONS:
        return RedirectResponse("/storage?notice=bad", status_code=303)
    kind = ACTIONS[aksi]
    analisis_raw = str(form.get("analisis", ""))
    if kind == storage_clean.Kind.DECOMPILE and not (analisis_raw.isascii() and analisis_raw.isdigit() and 0 < int(analisis_raw) < 2**31):
        return RedirectResponse("/storage?notice=bad", status_code=303)
    # Aksi yang menghapus HARUS membawa pernyataan bahwa pengguna sudah membaca akibatnya (kecuali hasil dekompilasi yang bisa dibuat ulang).
    plan_irreversible = kind != storage_clean.Kind.DECOMPILE
    if plan_irreversible and form.get("paham") != "1":
        return RedirectResponse("/storage?notice=bad", status_code=303)
    keys = ids = None
    if kind == storage_clean.Kind.ORPHAN:
        keys = _clean_keys([str(v) for v in form.getlist("kunci")])
        if keys is None or not keys:
            return RedirectResponse("/storage?notice=bad", status_code=303)
    elif kind == storage_clean.Kind.RECORDS:
        ids = _clean_ids([str(v) for v in form.getlist("kunci")])
        if ids is None or not ids:
            return RedirectResponse("/storage?notice=bad", status_code=303)
    try:
        result = await run_in_threadpool(_do_clean, kind, int(analisis_raw) if analisis_raw.isdigit() else None, keys, ids, client_ip(request))
    except Exception:
        log.exception("pembersihan penyimpanan gagal (%s)", kind)
        return RedirectResponse("/storage?notice=failed", status_code=303)
    SCAN_CACHE.invalidate()                                  # daftar & ukuran lama tidak lagi benar
    LAST_RESULT["r"] = result
    log.info("pembersihan %s: %d item, %d byte, %d dilewati ip=%s", kind, result.removed, result.freed, len(result.skipped), client_ip(request))
    if not result.removed and not result.skipped:
        return RedirectResponse("/storage?notice=nothing", status_code=303)
    return RedirectResponse("/storage?notice=cleaned", status_code=303)

