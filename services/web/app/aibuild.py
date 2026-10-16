"""Helper berlingkup-analisis untuk permintaan build & status oleh AI (Tahap 4, sub-area store/service). TANPA FastAPI, TANPA rute, TANPA tool (tool membungkus modul ini).

Prinsip (mengikat; dijaga tes AST di tests/test_aibuild_helpers.py):
  * Modul ini TIDAK mengimpor `app.builds`/`app.buildctl`/`app.jobs`/RQ/Redis/signspool dan tidak memanggil persetujuan, tanda tangan, unduh, atau pembacaan artefak.
    Jalur AI hanya bisa membuat build `awaiting_approval` (`store.create_build`); `approved` hanya lewat `store.approve_build` milik pemilik (CLI).
  * `analysis_id` dan `session_id` datang dari `Scope` (dibuat server dari konteks chat), TIDAK PERNAH dari argumen model. `build_id` dari model divalidasi dan dicek milik analisis ini.
  * Hash diff SELALU dihitung ulang dari bench (`shellspool` op `diff`). Hash dari model hanya pembanding dan tidak pernah disimpan.
  * Hasil bench/DB/runner = data tak tepercaya: pesan galat disusun dari tabel teks tetap (tanpa teks bench/DB), teks lain disaring `sanitize_status`/`sanitize_content`.
  * Fail closed: fitur nonaktif, sesi tidak sah, ruang kerja belum init, bench mati -> galat berkode, tidak ada build.
Duplikasi kecil dari `builds` (`build_summary`, penentu `source_kind`, konstanta) dijaga tes paritas, supaya jalur pemilik tidak tersentuh.
"""

from __future__ import annotations

import hmac
import json
import re
import threading
from contextlib import closing
from dataclasses import dataclass
from typing import Any, Callable

from rvcore import shellspool, store
from rvcore.fsutil import scrub_paths
from rvcore.paths import MAX_PROTO_ID

Redactor = Callable[[str], str]

SUMMARY_MAX_CHARS = 7000                      # sama dengan builds.SUMMARY_MAX_CHARS (store menolak > 8192)
BUNDLE_KINDS = ("xapk", "apks")
LIST_MAX = 40                                 # sama dengan batas bench (shellspool.TOP_MAX)
PATH_MAX = 300
ERROR_TEXT_MAX = 500
LOG_MAX = 1500
AI_NOTE = "Diminta oleh AI (chat)."           # teks tetap: tidak ada catatan bebas dari model
HEX64_RE = re.compile(r"[0-9a-f]{64}")
ERROR_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,39}")
SPLIT_N_RE = re.compile(r"(?m)^split_n=([0-9]{1,3})$")

# Petunjuk pemulihan per kode galat build (teks tetap; kunci = builds.HINTS + builds.BUNDLE_HINTS, dijaga tes paritas). Tanpa path, tanpa perintah make, tanpa kata terlarang.
HINTS = {
    "signer_unavailable": "penanda tangan mati atau bermasalah: minta pemilik memeriksa layanan penanda tangan lalu ajukan build baru",
    "runner_unavailable": "runner mati atau tidak merespons: minta pemilik memeriksa layanan runner lalu ajukan build baru",
    "workspace_changed": "project berubah setelah diajukan: periksa diff lagi lalu ajukan build baru",
    "interrupted": "worker dimulai ulang saat build berjalan: ajukan build baru",
    "timeout": "melewati batas waktu build: minta pemilik memeriksa log build atau menaikkan batas waktu",
    "bundle_changed": "paket unggahan berubah atau hilang sejak dianalisis: ajukan build baru",
    "bundle_invalid": "susunan paket XAPK/APKS tidak valid: periksa berkas asal",
    "split_missing": "paket menyebut split yang tidak ada: periksa berkas asal",
    "split_invalid": "ada split yang rusak atau tidak didukung: periksa berkas asal",
    "bundle_too_large": "paket melebihi batas ukuran, jumlah entri, atau rasio kompresi: kecilkan paket",
    "sign_cert_mismatch": "sertifikat salah satu berkas tidak sama dengan sertifikat pemilik: semua split harus satu sertifikat",
    "sign_bad_result": "hasil tanda tangan salah satu berkas tidak memenuhi syarat (v2 dan v3, satu penanda tangan)",
    "sign_stale_signature": "ada split yang masih membawa tanda tangan lama: hasil dibuang",
    "artifact_changed": "berkas berubah di antara tahap build: ajukan build baru",
    "assemble_failed": "perakitan paket akhir gagal: ajukan build baru",
    "no_space": "ruang disk tidak cukup: minta pemilik mengosongkan ruang lalu ajukan build baru",
}

# Pesan galat: TABEL TETAP per kode (+ id bilangan bulat). Teks dari bench/DB/runner/nama berkas TIDAK PERNAH masuk pesan galat.
_MESSAGES = {
    "fitur_nonaktif": "Fitur build oleh AI tidak aktif untuk sesi ini.",
    "argumen_tidak_valid": "Argumen tidak valid.",
    "batas_giliran": "Sudah ada satu permintaan build baru pada giliran ini; lanjutkan di giliran berikutnya.",
    "analisis_belum_siap": "Analisis belum selesai atau tidak ditemukan; tidak bisa membuat build.",
    "apktool_tidak_ada": "Hasil apktool tidak tersedia untuk analisis ini; tidak bisa dibangun.",
    "paket_belum_didukung": "Format paket ini belum didukung untuk build; hanya APK, XAPK, dan APKS.",
    "tidak_ada_ruang_kerja": "Ruang kerja bench belum diinisialisasi untuk analisis ini; minta pemilik menjalankan `buildctl init {aid}`.",
    "bench_mati": "Bench (kontainer shell) tidak aktif, sibuk, atau hasilnya rusak; coba lagi nanti.",
    "bench_timeout": "Bench melewati batas waktu saat menghitung diff.",
    "dibatalkan": "Perhitungan diff dibatalkan.",
    "pohon_terlalu_besar": "Ruang kerja terlalu besar atau terlalu dalam untuk dihitung diff-nya.",
    "diff_kosong": "Ruang kerja tidak berbeda dari baseline; tidak ada yang perlu dibangun.",
    "hash_tidak_cocok": "Hash diff yang diberikan tidak sama dengan diff ruang kerja saat ini; periksa lagi dengan bench_diff.",
    "build_tertunda": "Sudah ada build aktif #{bid} ({label}) untuk analisis ini; AI tidak dapat menggantinya. Pemilik bisa membatalkan lewat CLI.",
    "baseline_tidak_utuh": "Hampir seluruh proyek terhapus dari baseline; permintaan ditolak. Pemilik tetap bisa memeriksa lewat CLI.",
    "build_bukan_milik_analisis": "Build tidak ditemukan untuk analisis ini.",
    "ringkasan_terlalu_besar": "Ringkasan diff terlalu besar untuk disimpan.",
    "gagal": "Permintaan gagal diproses.",
}


class BuildScopeError(Exception):
    """Galat berkode stabil (Indonesia). `pesan` sudah aman: dari tabel teks tetap, tanpa teks dari bench/DB."""

    def __init__(self, kode: str, **fmt: Any) -> None:
        pesan = _MESSAGES[kode].format(**fmt) if fmt else _MESSAGES[kode]
        super().__init__(pesan)
        self.kode = kode
        self.pesan = pesan


@dataclass(frozen=True)
class Scope:
    """Lingkup satu panggilan, dibuat pemanggil (server) dari konteks chat; BUKAN dari model. `enabled=False` (bawaan) = fail closed."""
    analysis_id: int
    session_id: int | None
    db: Callable[[], Any]
    spool: shellspool.Spool
    cancel: threading.Event | None = None
    enabled: bool = False
    pickup_timeout: float = shellspool.OP_PICKUP_TIMEOUT
    poll: float = 0.1


def _gate(scope: Scope) -> None:
    sid = scope.session_id
    if scope.enabled is not True or type(sid) is not int or not 1 <= sid <= MAX_PROTO_ID:
        raise BuildScopeError("fitur_nonaktif")
    if type(scope.analysis_id) is not int or not 1 <= scope.analysis_id <= MAX_PROTO_ID:
        raise BuildScopeError("argumen_tidak_valid")


# ---------------------------------------------------------------------------------------------------- sanitasi
_BIDI = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://\S+|\bwww\.\S+")
_SECRET_RE = re.compile(r"\S*(?:keystore|\.p12|\.jks|\.pfx|\.pem|\.key\b|signing_|signwork|signspool|apksigner|secrets?[/\\]|storepass|keypass|sandi|password)\S*",
                        re.IGNORECASE)


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def sanitize_status(text: object, limit: int, redactor: Redactor | None = None) -> str:
    """Profil PENUH untuk teks status/galat dari DB/bench/runner. Urutan tetap: pangkas input -> '<' '>' -> kontrol+jalur -> URL -> token rahasia -> redaksi -> potong.

    '<' dan '>' dari sumber diganti SEBELUM penanda tetap (`<path>`, `<url>`, `<rahasia>`) disisipkan, jadi `</hasil_tool>` palsu tidak bisa menutup pembungkus hasil tool."""
    raw = "" if text is None else str(text)
    raw = raw[: max(1, limit) * 4].replace("<", "‹").replace(">", "›")      # pangkas dulu: regex `\S*…\S*` tidak boleh kuadratik pada masukan raksasa
    raw = scrub_paths(raw)
    raw = _URL_RE.sub("<url>", raw)
    raw = _SECRET_RE.sub("<rahasia>", raw)
    if redactor is not None:
        raw = redactor(raw)
    return _clip(raw, limit)


def sanitize_content(text: object, limit: int, redactor: Redactor | None = None) -> str:
    """Profil ISI untuk daftar path dan pratinjau diff: hanya buang kontrol/pengendali arah, redaksi, potong (path seperti `assets/keystore.jks` tetap terbaca)."""
    raw = "" if text is None else str(text)
    raw = "".join(ch for ch in raw[: max(1, limit) * 4] if ch in "\n\t" or (ch.isprintable() and ch not in _BIDI))
    if redactor is not None:
        raw = redactor(raw)
    return _clip(raw, limit)


# ---------------------------------------------------------------------------------------------------- source_kind & ringkasan
def source_kind_of(row: Any) -> str:
    """Aturan sama dengan `builds.request_build`: default apk; `options.bundle.format` xapk/apks; bundle lain -> paket_belum_didukung; options rusak/rekursif -> apk."""
    try:
        options = json.loads(row["options"] or "{}")
    except (ValueError, TypeError, RecursionError):
        options = {}
    marked = options.get("bundle") if isinstance(options, dict) else None
    if not marked:
        return "apk"
    fmt = marked.get("format") if isinstance(marked, dict) else None
    if fmt not in BUNDLE_KINDS:
        raise BuildScopeError("paket_belum_didukung")
    return fmt


def build_summary(diff: dict[str, Any]) -> dict[str, Any]:
    """Ringkasan untuk `diff_summary` (paritas dengan `builds.build_summary`): `top` dipotong separuh-demi-separuh sampai JSON <= SUMMARY_MAX_CHARS."""
    summary: dict[str, Any] = {"v": 1, "counts": diff["counts"], "bytes": diff["bytes"], "kinds": diff["kinds"], "lines": diff["lines"], "skipped": diff["skipped"],
                               "top": list(diff["top"]), "truncated": bool(diff["truncated"])}
    while len(json.dumps(summary, sort_keys=True, ensure_ascii=False)) > SUMMARY_MAX_CHARS:
        if not summary["top"]:
            raise BuildScopeError("ringkasan_terlalu_besar")
        summary["top"] = summary["top"][: len(summary["top"]) // 2]
        summary["truncated"] = True
    return summary


# ---------------------------------------------------------------------------------------------------- diff dari bench
_BENCH_CODES = {"belum_init": "tidak_ada_ruang_kerja", "tree_too_large": "pohon_terlalu_besar", "tree_too_deep": "pohon_terlalu_besar"}
_BENCH_STATUS = {shellspool.STATUS_FAILED: "bench_mati", shellspool.STATUS_TIMEOUT: "bench_timeout", shellspool.STATUS_CANCELLED: "dibatalkan"}


def current_diff(scope: Scope) -> dict[str, Any]:
    """Diff kanonik `project/` terhadap baseline untuk analisis di `scope`, DIHITUNG ULANG dari bench (tidak ada hash yang dipercaya dari luar). Hasil dinormalkan oleh
    `shellspool.parse_diff_result`. Ruang kerja belum init / bench mati / hasil rusak -> BuildScopeError (fail closed)."""
    _gate(scope)
    try:
        res = shellspool.run_op(scope.spool, shellspool.build_diff_request(scope.analysis_id), shellspool.parse_diff_result, cancel=scope.cancel,
                                pickup_timeout=scope.pickup_timeout, poll=scope.poll)
    except shellspool.BenchUnavailable:
        raise BuildScopeError("bench_mati") from None
    except ValueError:
        raise BuildScopeError("argumen_tidak_valid") from None
    if res["status"] != shellspool.STATUS_OK:
        code = _BENCH_CODES.get(res["code"]) or _BENCH_STATUS.get(res["status"]) or "gagal"
        raise BuildScopeError(code, aid=scope.analysis_id) if code == "tidak_ada_ruang_kerja" else BuildScopeError(code)
    removed, base = res["counts"]["removed"], res["base_entries"]
    return {"diff_sha256": res["diff_sha256"], "counts": res["counts"], "bytes": res["bytes"], "kinds": res["kinds"], "lines": res["lines"], "skipped": res["skipped"],
            "entries_total": res["entries_total"], "base_entries": base, "top": res["top"], "truncated": res["truncated"],
            "peringatan": "baseline_tidak_utuh" if base > 0 and removed * 10 >= base * 9 else ""}


def diff_view(diff: dict[str, Any], redactor: Redactor | None = None) -> dict[str, Any]:
    """Bentuk keluaran untuk AI: op R->D, daftar path <= 40 (tanpa isi file), jumlah, hash. `terpotong` bila bench memotong atau ada lebih banyak perubahan dari daftar."""
    daftar = [{"op": "D" if item["op"] == "R" else item["op"], "path": sanitize_content(item["path"], PATH_MAX, redactor)} for item in diff["top"][:LIST_MAX]]
    jumlah = sum(diff["counts"].values())
    return {"diff_sha256": diff["diff_sha256"], "counts": diff["counts"], "jumlah_berubah": jumlah, "bytes": diff.get("bytes"), "kinds": diff.get("kinds"),
            "lines": diff.get("lines"), "daftar": daftar, "terpotong": bool(diff.get("truncated")) or jumlah > len(daftar), "peringatan": diff.get("peringatan", "")}


# ---------------------------------------------------------------------------------------------------- request_build
def _owner_step(build_id: int, diff_sha256: str) -> str:
    return (f"Build menunggu persetujuan MANUAL pemilik (AI tidak bisa menyetujui): docker compose exec -T web python -m app.buildctl approve {build_id} "
            f"--diff-sha256 {diff_sha256}")


def _tertunda(row: Any) -> BuildScopeError:
    return BuildScopeError("build_tertunda", bid=int(row["id"]), label=store.BUILD_STATUS_LABEL.get(row["status"], "aktif"))


def _requested(row: Any, reused: bool, counts: dict[str, int] | None) -> dict[str, Any]:
    return {"ringkas": f"build #{row['id']} menunggu persetujuan pemilik", "build_id": row["id"], "status": store.B_AWAITING, "diff_sha256": row["diff_sha256"],
            "dipakai_ulang": reused, "source_kind": row["source_kind"], "counts": counts, "langkah_pemilik": _owner_step(row["id"], row["diff_sha256"]),
            "jangan_klaim_selesai": True}


def request(scope: Scope, expected_sha256: object, redactor: Redactor | None = None, *, build_requests: int = 0,
            count_bench: Callable[[], None] | None = None) -> dict[str, Any]:
    """Ajukan build dari diff SAAT INI (status `awaiting_approval`). Urutan fail-closed, murah dulu:
    gerbang -> argumen -> analisis/apktool/source_kind -> tolak murah bila ada build aktif non-awaiting (tanpa bench) -> hitung ulang diff dari bench ->
    kosong / baseline rusak / hash model beda -> pakai ulang awaiting berhash sama atau tolak -> batas 1 build baru per giliran -> `store.create_build`.
    `expected_sha256` (opsional, dari model) hanya pembanding. `build_requests` = jumlah build baru yang sudah dibuat pada giliran ini (dihitung pemanggil)."""
    _gate(scope)
    if expected_sha256 is not None and (type(expected_sha256) is not str or not HEX64_RE.fullmatch(expected_sha256)):
        raise BuildScopeError("argumen_tidak_valid")
    aid = scope.analysis_id
    with closing(scope.db()) as conn:
        row = store.get_analysis(conn, aid)
        if row is None or row["status"] != store.DONE:
            raise BuildScopeError("analisis_belum_siap")
        if next((s["status"] for s in store.get_stages(conn, aid) if s["name"] == "apktool"), None) not in (store.OK, store.WARN):
            raise BuildScopeError("apktool_tidak_ada")
        source_kind = source_kind_of(row)
        active = store.active_build(conn, aid)
        if active is not None and active["status"] != store.B_AWAITING:
            raise _tertunda(active)
    if count_bench is not None:
        count_bench()
    diff = current_diff(scope)
    if sum(diff["counts"].values()) == 0:
        raise BuildScopeError("diff_kosong")
    if diff["peringatan"]:
        raise BuildScopeError("baseline_tidak_utuh")
    fresh = diff["diff_sha256"]
    if expected_sha256 is not None and not hmac.compare_digest(expected_sha256, fresh):
        raise BuildScopeError("hash_tidak_cocok")
    with closing(scope.db()) as conn:
        active = store.active_build(conn, aid)
    if active is not None:
        if active["status"] == store.B_AWAITING and hmac.compare_digest(active["diff_sha256"], fresh):
            return _requested(active, True, diff["counts"])
        raise _tertunda(active)
    if build_requests >= 1:
        raise BuildScopeError("batas_giliran")
    summary = build_summary(diff)
    with closing(scope.db()) as conn:
        try:
            build_id = store.create_build(conn, aid, requested_by=f"ai:{scope.session_id}", source_kind=source_kind, diff_sha256=fresh, diff_summary=summary, note=AI_NOTE)
        except store.BuildInputError:
            raise BuildScopeError("gagal") from None
        except store.BuildStateError:
            racing = store.active_build(conn, aid)
            raise (_tertunda(racing) if racing is not None else BuildScopeError("gagal")) from None
        created = store.get_build(conn, build_id, analysis_id=aid)
    return _requested(created, False, diff["counts"])


# ---------------------------------------------------------------------------------------------------- status
_LOG_LINE_RES = (
    re.compile(r"build: [0-9.]+ dtk, [0-9]+ B(?:, puncak memori [0-9]+ MiB)?"),
    re.compile(r"tanda_tangan: [0-9.]+ dtk \([^)\n]{1,80}\)"),
    re.compile(r"split_n=[0-9]{1,3}"),
    re.compile(r"peringatan=[a-z0-9_,]{1,120}"),
)


def _stage_log(raw: str, redactor: Redactor | None) -> str:
    """ALLOWLIST per baris (bukan ekor mentah): `install_script=`, `signing_mulai=`, catatan, dan baris lain dibuang."""
    keep = [line for line in raw.splitlines() if any(rx.fullmatch(line) for rx in _LOG_LINE_RES)]
    return sanitize_status("\n".join(keep)[:LOG_MAX], LOG_MAX, redactor)


def _status_dict(row: Any, redactor: Redactor | None) -> dict[str, Any]:
    status = row["status"]
    kind = row["source_kind"]
    log = row["stage_log"] or ""
    split = SPLIT_N_RE.search(log)
    code = row["error_code"]
    code = None if not code else code if ERROR_CODE_RE.fullmatch(code) else "tidak_dikenal"
    fmt = row["output_format"]
    verify = row["verify_ok"]
    label = store.BUILD_STATUS_LABEL.get(status, status)
    return {
        "ringkas": f"build #{row['id']}: {label}", "ada_build": True, "build_id": row["id"], "status": status, "tahap": label,
        "diminta_oleh_ai": str(row["requested_by"]).startswith("ai:"), "source_kind": kind,
        "format_keluaran": fmt if fmt in store.BUILD_SOURCE_KINDS else None,
        "jumlah_split": int(split.group(1)) if split and kind in BUNDLE_KINDS else None,
        "artefak_tercatat": status == store.B_DONE,
        "verifikasi_tanda_tangan": True if verify == 1 else False if verify == 0 else None,
        "kode_galat": code, "pesan_galat": sanitize_status(row["error_text"] or "", ERROR_TEXT_MAX, redactor),
        "log_tahap": _stage_log(log, redactor), "petunjuk": HINTS.get(code, "") if code else "", "diff_sha256": row["diff_sha256"],
        "langkah_pemilik": _owner_step(row["id"], row["diff_sha256"]) if status == store.B_AWAITING else None,
        "jangan_klaim_selesai": status != store.B_DONE,
    }


def status(scope: Scope, build_id: object, redactor: Redactor | None = None) -> dict[str, Any]:
    """Status satu build milik analisis ini (hanya membaca). `build_id` None -> build aktif, lalu build terbaru; analisis tanpa build -> sukses `ada_build=False`.
    `build_id` diisi -> harus bilangan bulat murni 1..MAX_PROTO_ID dan milik analisis ini; tak ada / milik analisis lain -> galat IDENTIK (tanpa oracle keberadaan)."""
    _gate(scope)
    if build_id is not None and (type(build_id) is not int or not 1 <= build_id <= MAX_PROTO_ID):
        raise BuildScopeError("argumen_tidak_valid")
    with closing(scope.db()) as conn:
        if build_id is not None:
            row = store.get_build(conn, build_id, analysis_id=scope.analysis_id)
            if row is None:
                raise BuildScopeError("build_bukan_milik_analisis")
        else:
            row = store.active_build(conn, scope.analysis_id)
            if row is None:
                latest = store.list_builds(conn, scope.analysis_id, limit=1)
                row = latest[0] if latest else None
    if row is None:
        return {"ringkas": "belum ada build", "ada_build": False, "jangan_klaim_selesai": True}
    return _status_dict(row, redactor)
