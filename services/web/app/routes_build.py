"""Rute web build (Tahap 5): tab Build, LAYAR PERSETUJUAN (FR-9.18/9.40), tolak/batalkan, ajukan dari ruang kerja, dan unduhan (FR-9.25).

Semua rute butuh sesi pemilik. Rute yang mengubah state (POST) memeriksa CSRF (field `csrf`, pola `tokens_equal`) SEBELUM menyentuh apa pun. Persetujuan HANYA di
`approve` di bawah: sesi + CSRF + pernyataan wewenang (kotak centang) + hash diff yang tersimpan (field tersembunyi, dibandingkan oleh `builds.approve_build(via='ui')` dan
sekali lagi oleh CAS di `store.approve_build`). Modul ini TIDAK diimpor oleh kode AI (`app/ai/*`, `aibuild`); dijaga tes AST.

Prinsip tampilan: SEMUA teks dari AI/diff/log (path berkas, catatan, galat, stage_log) adalah data tak tepercaya: dirender oleh Jinja dengan autoescape, TIDAK PERNAH `|safe`.
Galat `BuildsError` dipetakan ke pesan Indonesia TETAP lewat kode stabil (`?notice=<kode>`): teks dari bench/runner/store tidak pernah dipantulkan ke halaman.
Unduhan: salin-lalu-hash-lalu-bandingkan (`builds.open_download`), lalu salinan itulah yang dialirkan.
"""

from __future__ import annotations

import json
import threading
from contextlib import closing
from functools import partial
from typing import Annotated, Any, Callable, Iterator

from fastapi import APIRouter, Form, Path as FPath, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from rvcore import buildproto, shellspool, store

from . import builds
from .context import audit_event, client_ip, current_session, db, layout, log, redis_conn, render
from .routes_apk import AnalysisId, _tab_context
from .security import tokens_equal

router = APIRouter()
BuildId = Annotated[int, FPath(ge=1, le=2**31 - 1)]

DOWNLOAD_SLOTS = 2                  # salinan unduhan serentak (tiap salinan bisa ~1 GiB di disk)
STREAM_CHUNK = 256 * 1024
KIND_ORDER = ("smali", "res", "manifest", "aset", "lib", "lain")
KIND_LABEL = {"smali": "Smali (kode)", "res": "Resource", "manifest": "Manifes", "aset": "Aset", "lib": "Library native", "lain": "Lain-lain"}
OP_LABEL = {"A": "Baru", "M": "Diubah", "R": "Dihapus"}
ACTIVE_POLL = (store.B_APPROVED, store.B_QUEUED, store.B_BUILDING, store.B_SIGNING)       # status yang berubah sendiri; awaiting_approval menunggu manusia
WARNING_TEXT = {
    "target_sdk_di_bawah_23": "targetSdkVersion di bawah 23: Android 14 ke atas menolak memasang APK seperti ini walau tanda tangannya benar.",
    "target_sdk_tidak_diketahui": "targetSdkVersion/minSdkVersion tidak terbaca, jadi kelayakan pasang di Android 14+ tidak bisa dinilai.",
    "paket_beda_dari_analisis": "Nama paket APK hasil berbeda dari APK asal (analisis).",
    "version_code_beda_dari_analisis": "versionCode APK hasil berbeda dari APK asal (analisis).",
}
NOT_PROMISED = (
    "Tanda tangan berbeda dari aslinya: APK hasil tidak bisa memperbarui aplikasi asli yang sudah terpasang. Aplikasi asli harus dicopot dulu (datanya hilang).",
    "“Siap pasang” bukan “pasti jalan”: yang dicek hanya struktur, tanda tangan, dan badging. Anti-tamper, packer, Play Integrity, atau pemeriksaan hash .so bisa membuatnya gagal berjalan.",
    "Tidak ada uji jalan: aplikasi tidak pernah dijalankan di server ini (tanpa emulator). Pasang dan uji sendiri di perangkat Anda.",
)

# Kode notifikasi (?notice=kode) -> (jenis, teks). Teks tetap; tidak ada teks bebas yang dipantulkan.
NOTICES: dict[str, tuple[str, str]] = {
    "diminta": ("ok", "Permintaan build dibuat. Tinjau perubahan di bawah, lalu setujui atau tolak."),
    "disetujui": ("ok", "Build disetujui dan masuk antrean. Halaman ini memperbarui statusnya otomatis."),
    "disetujui_antrean_mati": ("warn", "Build disetujui tetapi antrean (Redis) tidak terjangkau, jadi belum berjalan. Tekan “Kirim ulang ke antrean” beberapa saat lagi."),
    "dikirim_ulang": ("ok", "Build dikirim ulang ke antrean."),
    "ditolak": ("ok", "Build ditolak. Tidak ada yang dibangun."),
    "dibatalkan": ("ok", "Build dibatalkan."),
    "pembatalan_diminta": ("ok", "Permintaan pembatalan dikirim. Build berhenti dalam beberapa saat."),
    "ruang_kerja_siap": ("ok", "Ruang kerja disiapkan dari hasil apktool. Ubah berkasnya (lewat asisten atau CLI), lalu ajukan build."),
    "ruang_kerja_ada": ("ok", "Ruang kerja sudah ada; isinya tidak diubah."),
    "pernyataan_wajib": ("error", "Centang pernyataan wewenang dulu. Persetujuan tidak dicatat."),
    "diff_berubah": ("error", "Diff berubah sejak diajukan, jadi persetujuan TIDAK dicatat. Muat ulang halaman dan tinjau lagi."),
    "status_salah": ("error", "Status build sudah berubah (mungkin sudah disetujui, ditolak, atau dibatalkan). Muat ulang halaman."),
    "build_tidak_ada": ("error", "Build tidak ditemukan pada analisis ini."),
    "analisis_tidak_ada": ("error", "Analisis tidak ditemukan."),
    "analisis_belum_siap": ("error", "Analisis belum selesai; tunggu sampai selesai."),
    "apktool_tidak_ada": ("error", "Hasil apktool tidak tersedia untuk analisis ini, jadi tidak bisa dibangun."),
    "build_aktif": ("error", "Sudah ada build aktif untuk analisis ini. Batalkan atau tunggu sampai selesai."),
    "tidak_ada_perubahan": ("error", "Ruang kerja tidak berbeda dari hasil apktool asli; tidak ada yang perlu dibangun."),
    "belum_init": ("error", "Ruang kerja belum disiapkan. Tekan “Siapkan ruang kerja” dulu."),
    "baseline_tidak_ada": ("error", "Hasil apktool asli tidak ditemukan; jalankan analisis ulang."),
    "kuota": ("error", "Ruang kerja melebihi kuota yang diizinkan."),
    "pohon_terlalu_besar": ("error", "Ruang kerja terlalu besar atau terlalu dalam untuk dibandingkan."),
    "bench_mati": ("error", "Bench (kontainer ruang kerja) tidak aktif atau terlalu sibuk. Jalankan `make up`, lalu coba lagi."),
    "paket_belum_didukung": ("error", "Format paket ini belum didukung untuk build; hanya APK, XAPK, dan APKS."),
    "sudah_final": ("error", "Build sudah berstatus final; tidak ada yang dibatalkan."),
    "masukan_tidak_valid": ("error", "Permintaan tidak valid."),
    "gagal": ("error", "Operasi gagal. Lihat log server untuk rinciannya."),
}
for _alias in ("id_tidak_valid", "id_terlalu_besar", "hash_tidak_valid", "argumen_salah", "ringkasan_terlalu_besar"):
    NOTICES[_alias] = NOTICES["masukan_tidak_valid"]


def notice_code(kode: str) -> str:
    """Kode galat `BuildsError` -> kode notifikasi yang dikenal (selain itu `gagal`)."""
    return kode if kode in NOTICES else "gagal"


def _notice(code: str | None) -> dict[str, str] | None:
    if code and code in NOTICES:
        kind, text = NOTICES[code]
        return {"kind": kind, "text": text}
    return None


def _deps() -> builds.Deps:
    """Deps produksi (web sama dengan CLI). Tes mengganti fungsi ini dengan Deps berbench/Redis palsu."""
    return builds.Deps(layout=layout, db=db, redis=redis_conn, bench_spool=shellspool.make_spool(layout.root / "benchspool"))


def _redirect(url: str, notice: str | None = None) -> RedirectResponse:
    return RedirectResponse(url + (f"?notice={notice}" if notice else ""), status_code=303)


def _list_url(analysis_id: int) -> str:
    return f"/analyses/{int(analysis_id)}/build"


def _detail_url(analysis_id: int, build_id: int) -> str:
    return f"/analyses/{int(analysis_id)}/build/{int(build_id)}"


# ---------------------------------------------------------------------------------------------------- model tampilan (murni; diuji langsung)
def _loads_dict(raw: Any) -> dict[str, Any]:
    try:
        data = json.loads(raw) if isinstance(raw, str) and raw else {}
    except (ValueError, RecursionError):
        return {}
    return data if isinstance(data, dict) else {}


def _int(value: Any) -> int:
    return value if type(value) is int and 0 <= value <= 2 ** 62 else 0


def _opt_int(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 2 ** 62 else None


def _printable(value: Any, limit: int = 300) -> str:
    """Teks tak tepercaya -> aman ditampilkan: kontrol dan pengendali arah tulisan dibuang, dipotong. (Jinja tetap meng-escape HTML-nya.)"""
    if not isinstance(value, str):
        return ""
    return "".join(ch for ch in value if ch.isprintable() and ch not in store._BIDI_CHARS)[:limit]


def path_kind(path: str) -> str:
    """Jenis berkas dari segmen pertama path (aturan yang sama dengan `treediff`): smali*, res, AndroidManifest.xml, assets, lib, lain."""
    first = path.split("/", 1)[0]
    return ("smali" if first.startswith("smali") else "res" if first == "res" else "manifest" if first == "AndroidManifest.xml"
            else "aset" if first == "assets" else "lib" if first == "lib" else "lain")


def parse_requested_by(value: Any) -> dict[str, Any]:
    text = value if isinstance(value, str) else ""
    if text.startswith("ai:") and text[3:].isdigit():
        return {"ai": True, "label": f"Asisten AI (sesi percakapan #{int(text[3:])})"}
    return {"ai": False, "label": "Anda (pemilik)"}


def diff_view(row: Any, kind: str = "", q: str = "") -> dict[str, Any]:
    """Ringkasan diff dari `build.diff_summary` (JSON tersimpan; dinormalkan LAGI di sini) + daftar berkas tersaring/terurut/terkelompok.

    Urutan: paling banyak baris berubah, lalu ukuran terbesar, lalu path. `top` di ringkasan terbatas (store menyimpan <= 8 KiB), jadi `shown_of` jujur menyebut
    berapa dari total perubahan yang bisa dirinci di layar ini."""
    data = _loads_dict(row["diff_summary"])
    counts = {k: _int((data.get("counts") or {}).get(k)) for k in ("added", "modified", "removed")} if isinstance(data.get("counts"), dict) else dict.fromkeys(("added", "modified", "removed"), 0)
    sizes = {k: _int((data.get("bytes") or {}).get(k)) for k in ("added", "modified", "removed")} if isinstance(data.get("bytes"), dict) else dict.fromkeys(("added", "modified", "removed"), 0)
    kinds = {k: _int((data.get("kinds") or {}).get(k)) for k in KIND_ORDER} if isinstance(data.get("kinds"), dict) else dict.fromkeys(KIND_ORDER, 0)
    lines = {k: _int((data.get("lines") or {}).get(k)) for k in ("plus", "minus", "files", "skipped_files")} if isinstance(data.get("lines"), dict) else dict.fromkeys(("plus", "minus", "files", "skipped_files"), 0)
    skipped = {k: _int(v) for k, v in (data.get("skipped") or {}).items() if isinstance(k, str)} if isinstance(data.get("skipped"), dict) else {}
    items: list[dict[str, Any]] = []
    for raw in (data.get("top") if isinstance(data.get("top"), list) else [])[:200]:
        if not isinstance(raw, dict) or raw.get("op") not in OP_LABEL:
            continue
        path = _printable(raw.get("path"))
        items.append({"op": raw["op"], "op_label": OP_LABEL[raw["op"]], "dir": raw.get("kind") == "d", "path": path, "size": _int(raw.get("size")),
                      "plus": _opt_int(raw.get("plus")), "minus": _opt_int(raw.get("minus")), "kind": path_kind(path)})
    items.sort(key=lambda i: (-((i["plus"] or 0) + (i["minus"] or 0)), -i["size"], i["path"]))
    needle = q.strip().lower()
    shown = [i for i in items if (not kind or i["kind"] == kind) and (not needle or needle in i["path"].lower())]
    groups = [{"kind": k, "label": KIND_LABEL[k], "files": [i for i in shown if i["kind"] == k]} for k in KIND_ORDER]
    total = sum(counts.values())
    return {"counts": counts, "total": total, "bytes": sizes, "kinds": kinds, "lines": lines, "skipped": skipped,
            "groups": [g for g in groups if g["files"]], "listed": len(items), "matched": len(shown), "shown_of": f"{len(items)} dari {total}",
            "truncated": bool(data.get("truncated")) or len(items) < total, "filtered": bool(kind or needle)}


def build_view(row: Any) -> dict[str, Any]:
    """Satu baris build -> dict untuk template (tanpa diff_summary berat). Semua teks tak tepercaya diperlakukan sebagai data."""
    status = row["status"]
    by = parse_requested_by(row["requested_by"])
    stage = buildproto.parse_badging_stage_log(row["stage_log"])
    bundle = row["output_format"] in builds.BUNDLE_KINDS
    script = builds.INSTALL_SCRIPT_RE.search(row["stage_log"] or "") if bundle else None
    code = row["error_code"] or ""
    hint = builds.HINTS.get(code) or (builds.bundle_hint(code, row["error_text"] or "")[0] if code else "")
    warnings = [{"kode": w, "teks": WARNING_TEXT.get(w, w)} for w in stage["peringatan"]]
    return {
        "id": row["id"], "analysis_id": row["analysis_id"], "status": status, "label": store.BUILD_STATUS_LABEL.get(status, status), "final": status in store.BUILD_FINAL,
        "poll": status in ACTIVE_POLL, "ai": by["ai"], "requested_label": by["label"], "source_kind": row["source_kind"], "diff_sha256": row["diff_sha256"],
        "created_at": row["created_at"], "approved_at": row["approved_at"], "finished_at": row["finished_at"], "cancel_requested": bool(row["cancel_requested"]),
        "output_name": row["output_name"] or "", "output_size": row["output_size"], "output_sha256": row["output_sha256"] or "", "cert_sha256": row["cert_sha256"] or "",
        "output_format": row["output_format"] or "", "verify_ok": row["verify_ok"], "error_code": code, "error_text": _printable(row["error_text"], 500), "hint": hint,
        "rejected_reason": _printable(row["rejected_reason"], 500), "has_script": script is not None, "bundle": bundle, "badging": stage["badging"], "banding": stage["banding"],
        "warnings": warnings, "stage_log": (row["stage_log"] or "") if status in (store.B_DONE, store.B_FAILED, store.B_CANCELLED) else "",
        "can_download": status == store.B_DONE and bool(row["output_name"]),
    }


# ---------------------------------------------------------------------------------------------------- pemeriksa bersama
def _form_guard(request: Request, csrf: str) -> Response | None:
    """Sesi dulu (tanpa sesi -> /login), lalu CSRF (salah -> 403). None = lanjut."""
    session = current_session(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if not tokens_equal(session.csrf, csrf):
        return PlainTextResponse("CSRF token tidak valid", status_code=403)
    return None


def _owned(analysis_id: int, build_id: int | None = None) -> Any:
    """Baris build milik analisis di path (atau True bila hanya analisisnya yang dicek); None bila tidak ada / milik analisis lain."""
    with closing(db()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return None
        if build_id is None:
            return True
        return store.get_build(conn, build_id, analysis_id=analysis_id)


def _lookup(analysis_id: int, build_id: int) -> Any:
    with closing(db()) as conn:
        row = store.get_build(conn, build_id, analysis_id=analysis_id)
        return dict(row) if row is not None else None


# ---------------------------------------------------------------------------------------------------- halaman
# Baris per halaman daftar build. Sama dengan batas lama dan PAGE_SIZE halaman Berkas; di ponsel tiap build menjadi kartu ±150-200 px,
# jadi 50 kartu sudah gulir yang panjang, sementara HTML-nya tetap kecil. Retensi (BUILD_KEEP) tidak terkait dan tidak diubah.
BUILD_PAGE_SIZE = 50
_PAGE_MAX_DIGITS = 9            # lebih panjang dari ini pasti melampaui jumlah halaman -> dijepit ke halaman terakhir tanpa int() atas masukan raksasa


def _parse_page(raw: str | None) -> int | None:
    """None = parameter tidak ada atau sampah (-> halaman 1). Angka ASCII >= 1; terlalu panjang -> nilai sangat besar (dijepit pemanggil)."""
    if raw is None:
        return 1
    if not (raw.isascii() and raw.isdigit()):
        return None
    if len(raw) > _PAGE_MAX_DIGITS:
        return 10 ** _PAGE_MAX_DIGITS if set(raw) != {"0"} else None
    value = int(raw)
    return value if value >= 1 else None


def _list_data(analysis_id: int, page: int = 1) -> dict[str, Any]:
    with closing(db()) as conn:
        total = store.count_builds(conn, analysis_id)
        pages = max(1, -(-total // BUILD_PAGE_SIZE))
        if page > pages:
            return {"redirect_page": pages}
        rows = [build_view(r) for r in store.list_builds(conn, analysis_id, BUILD_PAGE_SIZE, (page - 1) * BUILD_PAGE_SIZE)]
        stages = {s["name"]: s["status"] for s in store.get_stages(conn, analysis_id)}
        an = store.get_analysis(conn, analysis_id)
        act = store.active_build(conn, analysis_id)              # bukan dari baris halaman: tetap benar di halaman > 1
    active = build_view(act) if act is not None else None
    can_build = an is not None and an["status"] == store.DONE and stages.get("apktool") in (store.OK, store.WARN)
    paging = {"total": total, "page": page, "pages": pages, "first": (page - 1) * BUILD_PAGE_SIZE + 1 if total else 0,
              "last": min(page * BUILD_PAGE_SIZE, total), "prev": f"?halaman={page - 1}" if page > 1 else None,
              "next": f"?halaman={page + 1}" if page < pages else None}
    return {"builds": rows, "active": active, "can_build": can_build, "paging": paging,
            "poll_url": f"/analyses/{analysis_id}/build/{active['id']}/status" if active and active["poll"] else "",
            "poll_status": active["status"] if active else ""}


@router.get("/analyses/{analysis_id}/build", include_in_schema=False)
async def build_list(request: Request, analysis_id: AnalysisId, notice: str | None = Query(None, max_length=40),
                     halaman: str | None = Query(None)) -> Response:
    early, ctx = await _tab_context(request, analysis_id, "build")
    if early is not None:
        return early
    page = _parse_page(halaman)
    if page is None:                                                  # sampah / 0 -> halaman 1 (tanpa parameter)
        return RedirectResponse(_list_url(analysis_id), status_code=303)
    data = await run_in_threadpool(_list_data, analysis_id, page)
    if "redirect_page" in data:                                       # melewati halaman terakhir -> halaman terakhir
        return RedirectResponse(f"{_list_url(analysis_id)}?halaman={data['redirect_page']}" if data["redirect_page"] > 1 else _list_url(analysis_id), status_code=303)
    return render(request, "build.html", {**ctx, **data, "notice": _notice(notice), "limit_notice": builds.LIMIT_NOTICE, "limits_list": NOT_PROMISED})


def _detail_data(analysis_id: int, build_id: int, kind: str, q: str) -> dict[str, Any] | None:
    with closing(db()) as conn:
        row = store.get_build(conn, build_id, analysis_id=analysis_id)
        if row is None:
            return None
        view = build_view(row)
        diff = diff_view(row, kind, q)
    return {"b": view, "diff": diff}


@router.get("/analyses/{analysis_id}/build/{build_id}", include_in_schema=False)
async def build_detail(request: Request, analysis_id: AnalysisId, build_id: BuildId, notice: str | None = Query(None, max_length=40),
                       kind: str = Query("", max_length=8), q: str = Query("", max_length=80)) -> Response:
    early, ctx = await _tab_context(request, analysis_id, "build")
    if early is not None:
        return early
    kind = kind if kind in KIND_ORDER else ""
    q = "".join(ch for ch in q if ch.isprintable()).strip()
    data = await run_in_threadpool(_detail_data, analysis_id, build_id, kind, q)
    if data is None:
        return _redirect(_list_url(analysis_id), "build_tidak_ada")
    statement = store.approval_statement()
    return render(request, "build_detail.html", {
        **ctx, **data, "notice": _notice(notice), "f_kind": kind, "f_q": q, "kind_order": KIND_ORDER, "kind_label": KIND_LABEL, "statement": statement,
        "statement_version": store.APPROVAL_STATEMENT_VERSION, "limit_notice": builds.LIMIT_NOTICE, "limits_list": NOT_PROMISED,
        "poll_url": f"/analyses/{analysis_id}/build/{build_id}/status" if data["b"]["poll"] else ""})


@router.get("/analyses/{analysis_id}/build/{build_id}/status", include_in_schema=False)
async def build_status(request: Request, analysis_id: AnalysisId, build_id: BuildId) -> Response:
    """Status ringan untuk polling halaman (JSON dari basis data saja; tanpa Redis/bench)."""
    if not current_session(request):
        return JSONResponse({"error": "Sesi berakhir."}, status_code=401, headers={"Cache-Control": "no-store"})
    row = await run_in_threadpool(_lookup, analysis_id, build_id)
    if row is None:
        return JSONResponse({"error": "Tidak ditemukan."}, status_code=404, headers={"Cache-Control": "no-store"})
    return JSONResponse({"status": row["status"], "label": store.BUILD_STATUS_LABEL.get(row["status"], row["status"]), "final": row["status"] in store.BUILD_FINAL,
                         "cancel_requested": bool(row["cancel_requested"])}, headers={"Cache-Control": "no-store"})


# ---------------------------------------------------------------------------------------------------- aksi (POST)
@router.post("/analyses/{analysis_id}/build/init", include_in_schema=False)
async def build_init(request: Request, analysis_id: AnalysisId, csrf: str = Form("", max_length=256)) -> Response:
    """Siapkan ruang kerja (op `init` bench): salin hasil apktool ke `bench/<id>/project` bila belum ada. Tidak pernah menimpa pekerjaan yang ada."""
    if (bad := _form_guard(request, csrf)) is not None:
        return bad
    if not await run_in_threadpool(_owned, analysis_id):
        return RedirectResponse("/?notice=not_found", status_code=303)
    try:
        res = await run_in_threadpool(builds.init_workspace, _deps(), analysis_id, False)
    except builds.BuildsError as exc:
        return _redirect(_list_url(analysis_id), notice_code(exc.kode))
    return _redirect(_list_url(analysis_id), "ruang_kerja_siap" if res["created"] else "ruang_kerja_ada")


@router.post("/analyses/{analysis_id}/build/request", include_in_schema=False)
async def build_request(request: Request, analysis_id: AnalysisId, csrf: str = Form("", max_length=256)) -> Response:
    """Ajukan build dari diff ruang kerja SAAT INI (diff dihitung ulang oleh bench). Hanya membuat permintaan `awaiting_approval`; belum ada yang berjalan."""
    if (bad := _form_guard(request, csrf)) is not None:
        return bad
    if not await run_in_threadpool(_owned, analysis_id):
        return RedirectResponse("/?notice=not_found", status_code=303)
    try:
        res = await run_in_threadpool(builds.request_build, _deps(), analysis_id, "user", "")
    except builds.BuildsError as exc:
        return _redirect(_list_url(analysis_id), notice_code(exc.kode))
    return _redirect(_detail_url(analysis_id, res["build_id"]), "diminta")


@router.post("/analyses/{analysis_id}/build/{build_id}/approve", include_in_schema=False)
async def build_approve(request: Request, analysis_id: AnalysisId, build_id: BuildId, csrf: str = Form("", max_length=256),
                        diff_sha256: str = Form("", max_length=128), statement: str = Form("", max_length=8),
                        statement_version: str = Form("", max_length=8)) -> Response:
    """SATU-SATUNYA jalan web ke persetujuan. Syarat: sesi + CSRF + kotak pernyataan wewenang dicentang + `diff_sha256` sama dengan yang tersimpan di baris build (diperiksa di
    `builds.approve_build` dan CAS `store.approve_build`). Gagal apa pun -> redirect dengan notifikasi tetap; tidak ada yang dicatat sebagai disetujui."""
    if (bad := _form_guard(request, csrf)) is not None:
        return bad
    detail = _detail_url(analysis_id, build_id)
    if await run_in_threadpool(_owned, analysis_id, build_id) is None:
        return _redirect(_list_url(analysis_id), "build_tidak_ada")
    if statement != "1":
        return _redirect(detail, "pernyataan_wajib")
    if not (statement_version.isascii() and statement_version.isdigit() and int(statement_version) in store.APPROVAL_STATEMENTS):
        return _redirect(detail, "masukan_tidak_valid")
    try:
        res = await run_in_threadpool(partial(builds.approve_build, _deps(), build_id, diff_sha256.strip(), statement_version=int(statement_version), via="ui"))
    except builds.BuildsError as exc:
        return _redirect(detail, notice_code(exc.kode))
    return _redirect(detail, "disetujui" if res["enqueued"] else "disetujui_antrean_mati")


@router.post("/analyses/{analysis_id}/build/{build_id}/requeue", include_in_schema=False)
async def build_requeue(request: Request, analysis_id: AnalysisId, build_id: BuildId, csrf: str = Form("", max_length=256)) -> Response:
    """Kirim ulang build yang SUDAH disetujui (`approved|queued`) ke antrean (Redis sempat mati). Tidak menyetujui apa pun: build `awaiting_approval` ditolak di sini."""
    if (bad := _form_guard(request, csrf)) is not None:
        return bad
    detail = _detail_url(analysis_id, build_id)
    row = await run_in_threadpool(_lookup, analysis_id, build_id)
    if row is None:
        return _redirect(_list_url(analysis_id), "build_tidak_ada")
    if row["status"] not in (store.B_APPROVED, store.B_QUEUED):
        return _redirect(detail, "status_salah")
    try:
        res = await run_in_threadpool(partial(builds.approve_build, _deps(), build_id, row["diff_sha256"], via="ui"))
    except builds.BuildsError as exc:
        return _redirect(detail, notice_code(exc.kode))
    return _redirect(detail, "dikirim_ulang" if res["enqueued"] else "disetujui_antrean_mati")


def _reject(build_id: int, reason: str) -> None:
    with closing(db()) as conn:
        store.reject_build(conn, build_id, reason)


@router.post("/analyses/{analysis_id}/build/{build_id}/reject", include_in_schema=False)
async def build_reject(request: Request, analysis_id: AnalysisId, build_id: BuildId, csrf: str = Form("", max_length=256),
                       reason: str = Form("", max_length=200)) -> Response:
    if (bad := _form_guard(request, csrf)) is not None:
        return bad
    detail = _detail_url(analysis_id, build_id)
    if await run_in_threadpool(_owned, analysis_id, build_id) is None:
        return _redirect(_list_url(analysis_id), "build_tidak_ada")
    try:
        await run_in_threadpool(_reject, build_id, reason)
    except store.BuildError:
        return _redirect(detail, "status_salah")
    return _redirect(detail, "ditolak")


@router.post("/analyses/{analysis_id}/build/{build_id}/cancel", include_in_schema=False)
async def build_cancel(request: Request, analysis_id: AnalysisId, build_id: BuildId, csrf: str = Form("", max_length=256)) -> Response:
    if (bad := _form_guard(request, csrf)) is not None:
        return bad
    detail = _detail_url(analysis_id, build_id)
    if await run_in_threadpool(_owned, analysis_id, build_id) is None:
        return _redirect(_list_url(analysis_id), "build_tidak_ada")
    try:
        res = await run_in_threadpool(builds.cancel_build, _deps(), build_id)
    except builds.BuildsError as exc:
        return _redirect(detail, notice_code(exc.kode))
    return _redirect(detail, "dibatalkan" if res["hasil"] == "cancelled" else "pembatalan_diminta")


# ---------------------------------------------------------------------------------------------------- unduhan (FR-9.25)
DOWNLOAD_ERRORS: dict[str, tuple[int, str]] = {
    "build_tidak_ada": (404, "Build tidak ditemukan pada analisis ini."),
    "belum_selesai": (409, "Build belum selesai; belum ada berkas untuk diunduh."),
    "berkas_tidak_ada": (404, "Berkas hasil build tidak ditemukan di server."),
    "skrip_tidak_ada": (404, "Build ini tidak punya skrip install-multiple."),
    "hash_tidak_cocok": (409, "Hash berkas di server TIDAK sama dengan yang dicatat saat build selesai (berkas berubah setelah terbit). Unduhan dibatalkan dan tidak ada byte yang dikirim."),
    "skrip_tidak_lolos_lint": (409, "Skrip memuat baris di luar allowlist. Unduhan dibatalkan."),
    "ruang_disk": (507, "Ruang disk server tidak cukup untuk menyiapkan unduhan."),
}
_DL_SLOTS = threading.BoundedSemaphore(DOWNLOAD_SLOTS)


def _once(fn: Callable[[], None]) -> Callable[[], None]:
    lock, state = threading.Lock(), [False]

    def run() -> None:
        with lock:
            if state[0]:
                return
            state[0] = True
        fn()

    return run


def _iter_copy(copy: builds.DownloadCopy) -> Iterator[bytes]:
    try:
        while True:
            block = copy.fh.read(STREAM_CHUNK)
            if not block:
                return
            yield block
    finally:                                                 # selesai, terputus, atau generator dibuang: salinan anonim ditutup dan slot dilepas
        copy.close()


async def _download(request: Request, analysis_id: int, build_id: int, which: str) -> Response:
    if not current_session(request):
        return PlainTextResponse("auth", status_code=401)
    if not _DL_SLOTS.acquire(blocking=False):
        return PlainTextResponse("Unduhan lain sedang disiapkan. Coba lagi beberapa saat.", status_code=503, headers={"Retry-After": "5"})
    release = _once(_DL_SLOTS.release)
    try:
        copy = await run_in_threadpool(partial(builds.open_download, _deps(), build_id, analysis_id=analysis_id, which=which, tmp_dir=layout.files_tmp, release=release))
    except builds.BuildsError as exc:                        # open_download sudah menutup salinan dan melepas slot
        status, text = DOWNLOAD_ERRORS.get(exc.kode, (404, "Berkas tidak tersedia."))
        if exc.kode == "hash_tidak_cocok":
            log.warning("unduhan build %s dibatalkan: hash/ukuran berkas tidak cocok dengan DB", build_id)
        return PlainTextResponse(text, status_code=status, headers={"Cache-Control": "no-store"})
    except BaseException:
        release()
        raise
    row = await run_in_threadpool(_lookup, analysis_id, build_id)
    await run_in_threadpool(audit_event, "build_download", {
        "analysis_id": analysis_id, "build_id": build_id, "which": which, "output_sha256": copy.sha256, "diff_sha256": row["diff_sha256"] if row else "",
        "size": copy.size, "ip": client_ip(request)})
    return StreamingResponse(_iter_copy(copy), media_type=copy.media_type, background=BackgroundTask(copy.close), headers={
        "Content-Length": str(copy.size), "Content-Disposition": f'attachment; filename="{copy.name}"', "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; sandbox", "X-Content-Type-Options": "nosniff"})


@router.get("/analyses/{analysis_id}/build/{build_id}/download", include_in_schema=False)
async def build_download(request: Request, analysis_id: AnalysisId, build_id: BuildId) -> Response:
    """APK (atau paket XAPK/APKS) hasil build. Disalin, di-hash ulang dari SALINAN, dibandingkan dengan DB, baru dialirkan."""
    return await _download(request, analysis_id, build_id, "artifact")


@router.get("/analyses/{analysis_id}/build/{build_id}/script", include_in_schema=False)
async def build_script(request: Request, analysis_id: AnalysisId, build_id: BuildId) -> Response:
    """Skrip `adb install-multiple` (hanya build XAPK/APKS); teks biasa, hash dicocokkan dengan catatan build."""
    return await _download(request, analysis_id, build_id, "script")
