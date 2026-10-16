"""Protokol worker <-> runner untuk tahap `build` (Tahap 2b; PRD 09): `apktool b` atas snapshot ruang kerja yang hash-nya cocok dengan yang disetujui.

Memakai antrean `spool` yang SAMA dengan analisis (satu runner, satu job sekali jalan; build mengantre di belakang analisis). Job id `a<aid>-build-<hex8>`.

Kepercayaan:
  * runner TIDAK mempercayai path dari worker. Request hanya memuat bilangan bulat dan hash; sumber (`bench/<aid>/project`), dasar (`work/<aid>/apktool`),
    dan keluaran (`builds/<aid>/<bid>/`) dihitung runner sendiri lewat `Layout`. Bidang lain (`path`, `src`, `out`, ...) tidak pernah dibaca.
  * worker TIDAK mempercayai hasil runner (kontainer yang memproses pohon tak tepercaya). Hasil dibaca dengan `signkeys.read_small` (batas ukuran, tanpa
    mengikuti symlink/FIFO) lalu dinormalkan ketat oleh `parse_build_result`. `ok` benar hanya bila `status == "ok"` DAN hash/ukuran koheren.
  * ukuran hasil dijamin kecil oleh pengirim (`dump_result` <= 8 KiB) karena `read_small` MENOLAK berkas > 64 KiB, tidak memotong.
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any

from .fsutil import scrub_paths
from .paths import MAX_PROTO_ID, check_proto_id
from .spool import new_job_id

STAGE = "build"
MIN_TIMEOUT, MAX_TIMEOUT = 10, 3600
ERROR_TEXT_MAX = 300
LOG_TAIL_MAX = 2000
RESULT_MAX_BYTES = 8 * 1024            # dijamin oleh dump_result; pembaca worker memakai batas 64 KiB (signkeys.read_small)
RESULT_MAX_BYTES_BUNDLE = 32 * 1024    # hanya bila hasil memuat `splits` (<= 199 elemen ~ 20 KiB); tetap di bawah batas baca 64 KiB
SOURCE_KINDS = ("apk", "xapk", "apks")
MAX_SPLITS = 199                       # base + 199 split = 200 APK (FR-9.3); sama dengan signspool.MAX_SPLITS
MAX_ALIASES = 8
MAX_WARNINGS = 32
WARNING_RE = re.compile(r"[a-z][a-z0-9_]{0,63}(?:=[0-9]{1,9})?\Z")
HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
PACKAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*\Z")      # nama paket Android yang sah; di luar ini = badging dianggap tidak terbaca
PACKAGE_MAX, VERSION_NAME_MAX, VERSION_CODE_MAX, SDK_MAX = 255, 64, 2 ** 63 - 1, 10 ** 6
TARGET_SDK_MIN = 23                    # Android 14+ menolak memasang APK dengan targetSdkVersion di bawah 23 (FR-9.41)

BUILD_ERROR_CODES = (
    "bad_request", "no_workspace", "baseline_missing", "tree_too_large", "tree_unreadable", "no_space", "workspace_changed", "snapshot_failed",
    "build_failed", "no_output", "timeout", "cancelled", "aborted", "output_limit", "internal",
    "bundle_changed", "bundle_invalid", "split_missing", "split_invalid", "bundle_too_large", "memfd_unavailable",
)
# Satu kalimat Indonesia per kode. 'bad_result' hanya dibuat pembaca (hasil tidak bisa dipercaya). Aman ditampilkan: tanpa path.
ERROR_TEXT: dict[str, str] = {
    "bad_request": "Permintaan build tidak valid.",
    "no_workspace": "Ruang kerja proyek tidak ditemukan; jalankan 'init' lalu ajukan build lagi.",
    "baseline_missing": "Pohon dasar hasil apktool tidak ada atau tidak lengkap; analisis ulang diperlukan.",
    "tree_too_large": "Pohon proyek melebihi batas ukuran atau jumlah berkas yang boleh dibangun.",
    "tree_unreadable": "Ada berkas atau direktori di pohon proyek yang tidak bisa dibaca (izin), sehingga build dibatalkan.",
    "no_space": "Ruang disk tidak cukup untuk membangun APK ini.",
    "workspace_changed": "Ruang kerja atau baseline berubah setelah build diajukan (hash diff tidak sama); ajukan build baru.",
    "snapshot_failed": "Snapshot ruang kerja gagal dibuat atau diberi berkas jejak sistem.",
    "build_failed": "apktool gagal membangun APK; lihat build.log.",
    "no_output": "apktool selesai tetapi tidak menghasilkan unsigned.apk yang sah.",
    "timeout": "Build melewati batas waktu dan dihentikan.",
    "cancelled": "Build dibatalkan.",
    "aborted": "Runner dimulai ulang saat build berjalan; ajukan lagi.",
    "output_limit": "Keluaran build melebihi batas dan dihentikan.",
    "internal": "Terjadi galat internal pada runner.",
    "bundle_changed": "Berkas unggahan paket berubah atau hilang sejak dianalisis; ajukan build baru.",
    "bundle_invalid": "Susunan paket XAPK/APKS tidak valid atau tidak sesuai permintaan.",
    "split_missing": "Paket menyebut split yang tidak ada di dalamnya.",
    "split_invalid": "Ada APK di dalam paket yang rusak atau tidak didukung (terenkripsi, kompresi tak umum, bukan ZIP).",
    "bundle_too_large": "Paket melebihi batas ukuran, jumlah entri, atau rasio kompresi yang diizinkan.",
    "memfd_unavailable": "Runner tidak dapat membuat salinan memori yang aman untuk paket; build dibatalkan tanpa cadangan.",
    "bad_result": "hasil runner rusak",
}
_STATUS_CODE = {"aborted": "aborted", "timeout": "timeout", "cancelled": "cancelled"}


@dataclass(frozen=True)
class BuildRequest:
    analysis_id: int
    build_id: int
    diff_sha256: str
    sha256: str
    timeout: int
    source_kind: str = "apk"             # "apk" | "xapk" | "apks"; runner menolak bad_request bila format turunan dari upload tidak sama


def _check_kind(value: Any) -> str:
    if type(value) is not str or value not in SOURCE_KINDS:
        raise ValueError("source_kind harus apk, xapk, atau apks")
    return value


def build_build_request(analysis_id: int, build_id: int, diff_sha256: str, sha256: str, timeout: int, source_kind: str = "apk") -> dict[str, Any]:
    """Request (sisi pengirim). ValueError untuk id bukan int murni / di luar 1..MAX_PROTO_ID, hash bukan heks-64 huruf kecil. Path TIDAK ikut dikirim."""
    aid = check_proto_id("analysis_id", analysis_id)
    bid = check_proto_id("build_id", build_id)
    for name, value in (("diff_sha256", diff_sha256), ("sha256", sha256)):
        if not isinstance(value, str) or not HEX64_RE.match(value):
            raise ValueError(f"{name} harus 64 karakter heks huruf kecil")
    if type(timeout) is not int:
        raise ValueError("timeout harus bilangan bulat")
    kind = _check_kind(source_kind)
    job = {"job_id": new_job_id(aid, STAGE), "stage": STAGE, "analysis_id": aid, "build_id": bid, "diff_sha256": diff_sha256,
           "sha256": sha256, "timeout": max(MIN_TIMEOUT, min(MAX_TIMEOUT, timeout)), "created": time.time()}
    if kind != "apk":
        job["source_kind"] = kind                # APK tunggal: request byte-identik dengan 2b
    return job


def validate_build_request(job: Any) -> BuildRequest:
    """Validasi request (sisi runner, TIDAK tepercaya). ValueError bila tidak valid. Bidang lain DIABAIKAN, tidak pernah dibaca."""
    if not isinstance(job, dict) or job.get("stage") != STAGE:
        raise ValueError("tahap bukan 'build'")
    try:
        aid = check_proto_id("analysis_id", job.get("analysis_id"))
        bid = check_proto_id("build_id", job.get("build_id"))
    except ValueError as exc:
        raise ValueError(str(exc)) from None
    for name in ("diff_sha256", "sha256"):
        value = job.get(name)
        if not isinstance(value, str) or not HEX64_RE.match(value):
            raise ValueError(f"{name} tidak valid")
    timeout = job.get("timeout")
    if type(timeout) is not int:
        raise ValueError("timeout tidak valid")
    kind = _check_kind(job["source_kind"]) if "source_kind" in job else "apk"          # tanpa bidang = APK tunggal (kompatibel mundur)
    return BuildRequest(aid, bid, job["diff_sha256"], job["sha256"], max(MIN_TIMEOUT, min(MAX_TIMEOUT, timeout)), kind)


# ------------------------------------------------------------------------------------------------ hasil
def _text(value: Any, limit: int) -> str:
    """Teks bebas dari runner: karakter kontrol/arah dibuang, jalur internal disamarkan LAGI (sabuk kedua), dipotong. Baris baru dipertahankan."""
    if not isinstance(value, str):
        return ""
    return scrub_paths(value)[:limit].strip()


def _int_or_none(value: Any) -> int | None:
    return value if type(value) is int else None


def _nonneg(value: Any, cap: int = 2 ** 50) -> int:
    return value if type(value) is int and 0 <= value <= cap else 0


def parse_build_result(raw: Any) -> dict[str, Any]:
    """Normalkan hasil dari runner (TIDAK TEPERCAYA). Tidak pernah melempar.

    Pemetaan `status` lebih dulu (A-11): aborted/timeout/cancelled -> kode yang sama (runner_restart bawaan `abort_orphans` ikut `aborted`); `failed` dengan
    kode di luar daftar (mis. tool_error dari jalur pengecualian `main`) -> `internal`. `bad_result` HANYA untuk JSON rusak/tak koheren (bukan dict, status
    tak dikenal, klaim ok tanpa hash/ukuran)."""
    result: dict[str, Any] = {
        "status": "failed", "ok": False, "error_code": None, "error_text": "", "output_size": 0, "output_sha256": None, "elapsed": 0.0,
        "peak_mem_mib": None, "apktool_log_tail": "", "files": 0, "bytes": 0,
        "source_kind": "apk", "plan_sha256": None, "aliases": [], "splits": [], "warnings": [], "badging": None,
    }
    if not isinstance(raw, dict):
        return _fail(result, "bad_result", "")
    status = raw.get("status") if isinstance(raw.get("status"), str) else None          # list/dict tak-hashable tidak boleh melempar
    elapsed = raw.get("elapsed")
    result["elapsed"] = float(elapsed) if type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 1e7 else 0.0
    peak = raw.get("peak_mem_mib")
    result["peak_mem_mib"] = peak if type(peak) is int and 0 <= peak <= 10 ** 7 else None
    result["apktool_log_tail"] = _text(raw.get("apktool_log_tail"), LOG_TAIL_MAX)
    result["files"], result["bytes"] = _nonneg(raw.get("files")), _nonneg(raw.get("bytes"))
    size = _int_or_none(raw.get("output_size"))
    sha = raw.get("output_sha256") if isinstance(raw.get("output_sha256"), str) and HEX64_RE.match(raw["output_sha256"]) else None
    text = _text(raw.get("error_text"), ERROR_TEXT_MAX) or _text(raw.get("message"), ERROR_TEXT_MAX)
    code = raw.get("error_code") if isinstance(raw.get("error_code"), str) else None

    if status == "ok":
        if sha is not None and size is not None and size > 0 and not code:
            extra = _parse_bundle_fields(raw)
            if extra is None:
                return _fail(result, "bad_result", "")
            result.update(status="ok", ok=True, output_size=size, output_sha256=sha, badging=normalize_badging(raw.get("badging")), **extra)
            return result
        return _fail(result, "bad_result", "")          # klaim sukses tanpa hash/ukuran yang koheren
    if status in _STATUS_CODE:
        return _fail(result, _STATUS_CODE[status], text, status=status)
    if status == "failed":
        if code not in BUILD_ERROR_CODES:
            code = "internal"
        return _fail(result, code, text)
    return _fail(result, "bad_result", "")


def _parse_bundle_fields(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Bidang paket dari hasil `ok` (TIDAK tepercaya), dinormalkan ketat; `None` bila tak koheren. Tidak ada nama berkas dari kontainer: hanya indeks, hash, ukuran.
    APK tunggal tidak boleh membawa bidang paket (hasil 2b tetap persis)."""
    kind = raw.get("source_kind", "apk")
    if type(kind) is not str or kind not in SOURCE_KINDS:
        return None
    splits, aliases, warnings = raw.get("splits", []), raw.get("aliases", []), raw.get("warnings", [])
    plan = raw.get("plan_sha256")
    if kind == "apk":
        if splits or aliases or warnings or plan is not None:
            return None
        return {"source_kind": "apk"}
    if not isinstance(plan, str) or not HEX64_RE.match(plan):
        return None
    if not isinstance(splits, list) or len(splits) > MAX_SPLITS or not isinstance(aliases, list) or not isinstance(warnings, list):
        return None
    out_splits: list[dict[str, Any]] = []
    for pos, item in enumerate(splits, start=1):
        if not isinstance(item, dict) or type(item.get("index")) is not int or item["index"] != pos:
            return None
        sha, size = item.get("sha256"), item.get("size")
        if not isinstance(sha, str) or not HEX64_RE.match(sha) or type(size) is not int or not 0 < size <= 2 ** 50:
            return None
        out_splits.append({"index": pos, "sha256": sha, "size": size})
    if len(aliases) > MAX_ALIASES or len(set(aliases)) != len(aliases) or any(type(a) is not int or not 0 <= a <= MAX_SPLITS + MAX_ALIASES for a in aliases):
        return None
    if len(warnings) > MAX_WARNINGS or any(not isinstance(w, str) or not WARNING_RE.match(w) for w in warnings):
        return None
    return {"source_kind": kind, "plan_sha256": plan, "aliases": list(aliases), "splits": out_splits, "warnings": list(warnings)}


def _fail(result: dict[str, Any], code: str, text: str, *, status: str = "failed") -> dict[str, Any]:
    result.update(status=status, ok=False, error_code=code, output_size=0, output_sha256=None, source_kind="apk", plan_sha256=None, aliases=[], splits=[], warnings=[],
                  badging=None)
    result["error_text"] = text if text and code != "bad_result" else ERROR_TEXT[code]
    return result


# ------------------------------------------------------------------------------------------------ badging (FR-9.24 / FR-9.41; Tahap 5)
def _sdk(value: Any) -> int | None:
    """Level SDK numerik; nama kode pratinjau ('VanillaIceCream') atau nilai di luar batas -> None (tidak diketahui, bukan galat)."""
    return value if type(value) is int and 0 <= value <= SDK_MAX else None


def normalize_badging(raw: Any) -> dict[str, Any] | None:
    """Normalkan badging dari runner (TIDAK TEPERCAYA) menjadi {package, version_code, version_name, min_sdk, target_sdk} atau None (tidak terbaca).

    Hanya `package` yang wajib dan harus nama paket Android yang sah (<= 255); selain itu seluruh badging dianggap tidak terbaca. versionName hanya boleh
    [A-Za-z0-9._+~:-] (karakter lain -> `_`, dipotong 64) agar satu baris teks tetap-format di stage_log bisa dibaca ulang tanpa ambiguitas. Tidak pernah melempar."""
    if not isinstance(raw, dict):
        return None
    package = raw.get("package")
    if not isinstance(package, str) or len(package) > PACKAGE_MAX or not PACKAGE_RE.match(package):
        return None
    code = raw.get("version_code")
    name = raw.get("version_name")
    name = re.sub(r"[^A-Za-z0-9._+~:-]", "_", name)[:VERSION_NAME_MAX] if isinstance(name, str) else ""
    return {"package": package, "version_code": code if type(code) is int and 0 <= code <= VERSION_CODE_MAX else None, "version_name": name,
            "min_sdk": _sdk(raw.get("min_sdk")), "target_sdk": _sdk(raw.get("target_sdk"))}


def badging_warnings(badging: dict[str, Any]) -> list[str]:
    """Peringatan tetap dari badging (tidak memblokir). targetSdkVersion yang tidak tertulis berlaku sama dengan minSdkVersion (aturan Android)."""
    target = badging["target_sdk"] if badging["target_sdk"] is not None else badging["min_sdk"]
    if target is None:
        return ["target_sdk_tidak_diketahui"]
    return ["target_sdk_di_bawah_23"] if target < TARGET_SDK_MIN else []


def _val(value: Any) -> str:
    return "-" if value is None or value == "" else str(value)


def badging_stage_lines(badging: dict[str, Any], origin: dict[str, Any] | None = None) -> list[str]:
    """Baris teks TETAP untuk stage_log: `badging: ...`, `banding: ...` (dengan paket/versi analisis asal), dan satu `peringatan: <kode>` per peringatan.
    `origin` = {package, version_code, version_name} dari analisis (apa adanya; kosong/None = tidak diketahui). Perbandingan TIDAK memblokir."""
    lines = [f"badging: paket={badging['package']} versionCode={_val(badging['version_code'])} versionName={_val(badging['version_name'])} "
             f"minSdk={_val(badging['min_sdk'])} targetSdk={_val(badging['target_sdk'])}"]
    warnings = badging_warnings(badging)

    def compare(mine: Any, theirs: Any) -> str:
        theirs = str(theirs).strip() if theirs is not None else ""
        return "tidak_diketahui" if not theirs or mine in (None, "") else ("sama" if str(mine) == theirs else "beda")

    o = origin or {}
    pkg, code, name = (compare(badging["package"], o.get("package")), compare(badging["version_code"], o.get("version_code")),
                       compare(badging["version_name"], o.get("version_name")))
    lines.append(f"banding: paket={pkg} versionCode={code} versionName={name}")
    if pkg == "beda":
        warnings.append("paket_beda_dari_analisis")
    if code == "beda":
        warnings.append("version_code_beda_dari_analisis")
    lines.extend(f"peringatan: {w}" for w in warnings)
    return lines


BADGING_LINE_RE = re.compile(r"^badging: paket=(\S+) versionCode=(\S+) versionName=(\S+) minSdk=(\S+) targetSdk=(\S+)$", re.M)
BANDING_LINE_RE = re.compile(r"^banding: paket=(\w+) versionCode=(\w+) versionName=(\w+)$", re.M)
WARNING_LINE_RE = re.compile(r"^peringatan: ([a-z][a-z0-9_]{0,63})$", re.M)


def parse_badging_stage_log(stage_log: Any) -> dict[str, Any]:
    """Baca ulang baris badging dari stage_log (DB; ditulis worker). Mengembalikan {'badging': dict|None, 'banding': dict|None, 'peringatan': [kode]}; tidak melempar."""
    text = stage_log if isinstance(stage_log, str) else ""
    out: dict[str, Any] = {"badging": None, "banding": None, "peringatan": []}
    m = BADGING_LINE_RE.search(text)
    if m:
        out["badging"] = dict(zip(("package", "version_code", "version_name", "min_sdk", "target_sdk"), (None if g == "-" else g for g in m.groups())))
    m = BANDING_LINE_RE.search(text)
    if m:
        out["banding"] = dict(zip(("paket", "versionCode", "versionName"), m.groups()))
    out["peringatan"] = WARNING_LINE_RE.findall(text)
    return out


def dump_result(result: dict[str, Any]) -> dict[str, Any]:
    """Hasil runner (sisi pengirim) dengan panjang tiap bidang dibatasi dan total JSON <= 8 KiB (32 KiB bila memuat `splits`): bila lebih, `apktool_log_tail`
    dikosongkan lalu `error_text` dipotong; `splits` TIDAK pernah dipotong. Tidak pernah menghasilkan hasil yang akan ditolak pembaca (`read_small` menolak)."""
    out = dict(result)
    for key, limit in (("error_text", ERROR_TEXT_MAX), ("apktool_log_tail", LOG_TAIL_MAX)):
        if isinstance(out.get(key), str):
            out[key] = out[key][:limit]
    for key in ("message",):
        out.pop(key, None)
    limit = RESULT_MAX_BYTES_BUNDLE if out.get("splits") else RESULT_MAX_BYTES
    if len(json.dumps(out, ensure_ascii=False).encode("utf-8")) > limit:
        out["apktool_log_tail"] = ""
    while len(json.dumps(out, ensure_ascii=False).encode("utf-8")) > limit and out.get("error_text"):
        out["error_text"] = out["error_text"][: len(out["error_text"]) // 2]
    return out


__all__ = ["STAGE", "MAX_PROTO_ID", "SOURCE_KINDS", "BUILD_ERROR_CODES", "ERROR_TEXT", "BuildRequest", "build_build_request", "validate_build_request",
           "parse_build_result", "dump_result", "normalize_badging", "badging_stage_lines", "badging_warnings", "parse_badging_stage_log", "TARGET_SDK_MIN"]
