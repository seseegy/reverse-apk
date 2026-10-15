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
HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")

BUILD_ERROR_CODES = (
    "bad_request", "no_workspace", "baseline_missing", "tree_too_large", "tree_unreadable", "no_space", "workspace_changed", "snapshot_failed",
    "build_failed", "no_output", "timeout", "cancelled", "aborted", "output_limit", "internal",
)
# Satu kalimat Indonesia per kode. 'bad_result' hanya dibuat pembaca (hasil tidak bisa dipercaya). Aman ditampilkan: tanpa path.
ERROR_TEXT: dict[str, str] = {
    "bad_request": "Permintaan build tidak valid.",
    "no_workspace": "Ruang kerja (bench/<analisis>/project) tidak ditemukan; jalankan 'init' lalu ajukan build lagi.",
    "baseline_missing": "Pohon dasar hasil apktool (work/<analisis>/apktool) tidak ada atau tidak lengkap; analisis ulang diperlukan.",
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


def build_build_request(analysis_id: int, build_id: int, diff_sha256: str, sha256: str, timeout: int) -> dict[str, Any]:
    """Request (sisi pengirim). ValueError untuk id bukan int murni / di luar 1..MAX_PROTO_ID, hash bukan heks-64 huruf kecil. Path TIDAK ikut dikirim."""
    aid = check_proto_id("analysis_id", analysis_id)
    bid = check_proto_id("build_id", build_id)
    for name, value in (("diff_sha256", diff_sha256), ("sha256", sha256)):
        if not isinstance(value, str) or not HEX64_RE.match(value):
            raise ValueError(f"{name} harus 64 karakter heks huruf kecil")
    if type(timeout) is not int:
        raise ValueError("timeout harus bilangan bulat")
    return {"job_id": new_job_id(aid, STAGE), "stage": STAGE, "analysis_id": aid, "build_id": bid, "diff_sha256": diff_sha256,
            "sha256": sha256, "timeout": max(MIN_TIMEOUT, min(MAX_TIMEOUT, timeout)), "created": time.time()}


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
    return BuildRequest(aid, bid, job["diff_sha256"], job["sha256"], max(MIN_TIMEOUT, min(MAX_TIMEOUT, timeout)))


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
            result.update(status="ok", ok=True, output_size=size, output_sha256=sha)
            return result
        return _fail(result, "bad_result", "")          # klaim sukses tanpa hash/ukuran yang koheren
    if status in _STATUS_CODE:
        return _fail(result, _STATUS_CODE[status], text, status=status)
    if status == "failed":
        if code not in BUILD_ERROR_CODES:
            code = "internal"
        return _fail(result, code, text)
    return _fail(result, "bad_result", "")


def _fail(result: dict[str, Any], code: str, text: str, *, status: str = "failed") -> dict[str, Any]:
    result.update(status=status, ok=False, error_code=code, output_size=0, output_sha256=None)
    result["error_text"] = text if text and code != "bad_result" else ERROR_TEXT[code]
    return result


def dump_result(result: dict[str, Any]) -> dict[str, Any]:
    """Hasil runner (sisi pengirim) dengan panjang tiap bidang dibatasi dan total JSON <= 8 KiB: bila lebih, `apktool_log_tail` dikosongkan lalu
    `error_text` dipotong. Tidak pernah menghasilkan hasil yang akan ditolak pembaca (`read_small` menolak, tidak memotong)."""
    out = dict(result)
    for key, limit in (("error_text", ERROR_TEXT_MAX), ("apktool_log_tail", LOG_TAIL_MAX)):
        if isinstance(out.get(key), str):
            out[key] = out[key][:limit]
    for key in ("message",):
        out.pop(key, None)
    if len(json.dumps(out, ensure_ascii=False).encode("utf-8")) > RESULT_MAX_BYTES:
        out["apktool_log_tail"] = ""
    while len(json.dumps(out, ensure_ascii=False).encode("utf-8")) > RESULT_MAX_BYTES and out.get("error_text"):
        out["error_text"] = out["error_text"][: len(out["error_text"]) // 2]
    return out


__all__ = ["STAGE", "MAX_PROTO_ID", "BUILD_ERROR_CODES", "ERROR_TEXT", "BuildRequest", "build_build_request", "validate_build_request",
           "parse_build_result", "dump_result"]
