"""Lapisan web pipeline build (Tahap 2b, FEAT E): fungsi murni di atas store/shellspool/jobs. TANPA FastAPI, TANPA rute, TANPA tool AI.

Satu-satunya pemanggil adalah `app.buildctl` (CLI pemilik di kontainer web, lewat `docker compose exec`). Persetujuan build HANYA terjadi di `approve_build` dan terikat pada
`diff_sha256` yang tercatat; tidak ada modul di `app/ai/` yang mengimpor modul ini (dijaga tes).

Semua kebergantungan masuk lewat `Deps` (tes menyuntik bench/Redis palsu). Galat selalu `BuildsError(kode, pesan)` dengan `kode` yang stabil; CLI mencetaknya sebagai `kode=`.
Semua id divalidasi 1..MAX_PROTO_ID SEBELUM menyentuh bench/runner (id lebih besar akan dibuang diam-diam oleh spool: "pickup timeout" yang menyesatkan).
Akses ke `builds/<aid>/<bid>` HANYA lewat `fsutil.open_dir_chain` (rantai O_NOFOLLOW): runner menulis akar `builds`, jadi jalur string tidak aman (desain §7.7).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import time
from contextlib import closing
from dataclasses import dataclass, field
from typing import Any, Callable

import redis
from rq import Queue

from rvcore import shellspool, store
from rvcore.fsutil import open_dir_chain
from rvcore.paths import MAX_PROTO_ID, Layout
from rvcore.spool import Spool

from . import jobs
from .status import QUEUE_NAME, RUNNER_HEARTBEAT_KEY

SIGNER_HEARTBEAT_KEY = "signer:heartbeat"
HEARTBEAT_STALE_AFTER = 30.0                 # detik; worker menulis tiap 10 dtk dengan TTL 30
SUMMARY_MAX_CHARS = 7000                     # store menolak > 8192; sisanya untuk pembungkus
TRACE_FILE = "assets/reverse-apk-modified.txt"
JOB_TIMEOUT_MARGIN = 600                     # sama dengan worker.builds.JOB_TIMEOUT_MARGIN
BUNDLE_JOB_MARGIN = 3800                     # sama dengan worker.builds.BUNDLE_JOB_MARGIN (paket xapk/apks; dijaga tes paritas)
BUNDLE_KINDS = ("xapk", "apks")
HASH_BLOCK = 1024 * 1024
OPEN_ARTIFACT = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
HEX64_RE = re.compile(r"[0-9a-f]{64}")
OUTPUT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}")
SIGNING_MULAI_RE = re.compile(r"(?m)^signing_mulai=(\d+(?:\.\d+)?)\s*$")
JOB_FRAGMENT_RE = re.compile(r"[A-Za-z0-9._-]{1,60}")

# Petunjuk pemulihan per kode galat build (hanya teks tetap; tidak ada teks dari runner/AI).
HINTS = {
    "signer_unavailable": "signer mati atau keystore bermasalah: jalankan `make up` (dan `make keystore-check`), lalu ajukan build baru",
    "runner_unavailable": "runner mati atau tidak merespons: jalankan `make up`, lalu ajukan build baru",
    "workspace_changed": "project berubah setelah diajukan: jalankan diff lalu request lagi",
    "interrupted": "worker dimulai ulang saat build berjalan: ajukan build baru",
    "timeout": "melewati batas waktu: periksa build.log atau naikkan TIMEOUT_BUILD",
}


class BuildsError(Exception):
    """Galat operasional dengan `kode` stabil (dicetak CLI sebagai `kode=`). `extra` = pasangan kunci=nilai tambahan yang tetap berguna saat gagal."""

    def __init__(self, kode: str, pesan: str, **extra: Any) -> None:
        super().__init__(pesan)
        self.kode = kode
        self.pesan = pesan
        self.extra = extra


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(os.environ.get(name, "").strip())
    except ValueError:
        return default
    return max(lo, min(hi, value))


def job_margin(source_kind: str) -> int:
    """Margin `job_timeout` RQ menurut format: paket memakai margin besar, APK tunggal tetap 600 (sama dengan `worker.builds.job_margin`)."""
    return BUNDLE_JOB_MARGIN if source_kind in BUNDLE_KINDS else JOB_TIMEOUT_MARGIN


def job_timeout_from_env() -> int:
    """`job_timeout` RQ untuk build = TIMEOUT_BUILD + TIMEOUT_SIGN + margin (rumus yang sama dengan worker.builds.BuildConfig.job_timeout)."""
    return _env_int("TIMEOUT_BUILD", 1800, 10, 3600) + _env_int("TIMEOUT_SIGN", 900, 10, 3600) + JOB_TIMEOUT_MARGIN


@dataclass
class Deps:
    layout: Layout
    db: Callable[[], Any]                    # koneksi SQLite BARU tiap panggilan (pemanggil menutupnya)
    redis: Any
    bench_spool: Spool                       # shellspool.make_spool(<data>/benchspool)
    now: Callable[[], float] = time.time
    job_timeout: int = field(default_factory=job_timeout_from_env)
    op_pickup_timeout: float = shellspool.OP_PICKUP_TIMEOUT
    poll: float = 1.0


# ---------------------------------------------------------------------------------------------------- validasi
def _check_id(name: str, value: object) -> int:
    if type(value) is not int or value < 1:
        raise BuildsError("id_tidak_valid", f"{name} harus bilangan bulat positif.")
    if value > MAX_PROTO_ID:
        raise BuildsError("id_terlalu_besar", f"{name} melebihi {MAX_PROTO_ID} (batas id protokol spool).")
    return value


def _ready_analysis(conn: Any, analysis_id: int) -> Any:
    row = store.get_analysis(conn, analysis_id)
    if row is None:
        raise BuildsError("analisis_tidak_ada", f"Analisis #{analysis_id} tidak ditemukan.")
    if row["status"] != store.DONE:
        raise BuildsError("analisis_belum_siap", f"Analisis #{analysis_id} belum selesai (status: {row['status']}).")
    return row


def _get_build(conn: Any, build_id: int) -> Any:
    row = store.get_build(conn, build_id)
    if row is None:
        raise BuildsError("build_tidak_ada", f"Build #{build_id} tidak ditemukan.")
    return row


# ---------------------------------------------------------------------------------------------------- bench: init / diff / shell
def _run_op(d: Deps, request: dict[str, Any], parser: Callable[[Any], dict[str, Any]]) -> dict[str, Any]:
    try:
        return shellspool.run_op(d.bench_spool, request, parser, pickup_timeout=d.op_pickup_timeout, poll=min(d.poll, 0.1))
    except shellspool.BenchUnavailable as exc:
        raise BuildsError("bench_mati", exc.message) from None


def _bench_failure(res: dict[str, Any], mapping: dict[str, str]) -> BuildsError:
    code = res.get("code") or ""
    message = res.get("message") or f"bench menjawab {res['status']}"
    return BuildsError(mapping.get(code, "gagal"), message)


def init_workspace(d: Deps, analysis_id: int, force: bool = False) -> dict[str, Any]:
    """Op `init`: salin baseline `work/<id>/apktool` ke `bench/<id>/project` (hanya bila belum ada kecuali `force`)."""
    _check_id("analysis_id", analysis_id)
    with closing(d.db()) as conn:
        _ready_analysis(conn, analysis_id)
        if force and store.active_build(conn, analysis_id) is not None:       # A-15: reset project selagi ada build aktif merusak hash yang disetujui
            raise BuildsError("build_aktif", "Ada build aktif untuk analisis ini; batalkan atau tunggu selesai sebelum `init --force`.")
    res = _run_op(d, shellspool.build_init_request(analysis_id, force), shellspool.parse_init_result)
    if res["status"] != shellspool.STATUS_OK:
        raise _bench_failure(res, {"baseline_tidak_ada": "baseline_tidak_ada", "kuota": "kuota"})
    return {"created": res["created"], "reason": res["reason"], "files": res["files"], "dirs": res["dirs"], "bytes": res["bytes"], "skipped": res["skipped"],
            "message": res["message"]}


def workspace_diff(d: Deps, analysis_id: int) -> dict[str, Any]:
    """Op `diff`: diff kanonik `project/` terhadap baseline. Hasil dinormalkan (bench tidak tepercaya)."""
    _check_id("analysis_id", analysis_id)
    res = _run_op(d, shellspool.build_diff_request(analysis_id), shellspool.parse_diff_result)
    if res["status"] != shellspool.STATUS_OK:
        raise _bench_failure(res, {"belum_init": "belum_init", "tree_too_large": "pohon_terlalu_besar", "tree_too_deep": "pohon_terlalu_besar"})
    removed, base = res["counts"]["removed"], res["base_entries"]
    return {"diff_sha256": res["diff_sha256"], "counts": res["counts"], "bytes": res["bytes"], "kinds": res["kinds"], "lines": res["lines"], "skipped": res["skipped"],
            "entries_total": res["entries_total"], "base_entries": base, "top": res["top"], "truncated": res["truncated"],
            "peringatan": "baseline_tidak_utuh" if base > 0 and removed * 10 >= base * 9 else "", "jejak_sistem": TRACE_FILE}


def run_shell(d: Deps, analysis_id: int, command: str, timeout: int) -> dict[str, Any]:
    """Perintah shell pemilik lewat jalur bench + Landlock yang sama dengan tool AI, TANPA `ai.tools` dan tanpa syarat AI_SHELL_ENABLED (D15)."""
    _check_id("analysis_id", analysis_id)
    try:
        return shellspool.run_command(d.bench_spool, analysis_id, command, timeout=timeout, sha256=None, poll=min(d.poll, 0.1))
    except shellspool.BenchUnavailable as exc:
        raise BuildsError("bench_mati", exc.message) from None


# ---------------------------------------------------------------------------------------------------- request
def build_summary(diff: dict[str, Any]) -> dict[str, Any]:
    """Ringkasan untuk `diff_summary`: `top` dipotong separuh-demi-separuh (40->20->10->5->2->1->0) sampai JSON <= SUMMARY_MAX_CHARS (store menolak > 8192, tidak memotong)."""
    summary: dict[str, Any] = {"v": 1, "counts": diff["counts"], "bytes": diff["bytes"], "kinds": diff["kinds"], "lines": diff["lines"], "skipped": diff["skipped"],
                               "top": list(diff["top"]), "truncated": bool(diff["truncated"])}
    while len(json.dumps(summary, sort_keys=True, ensure_ascii=False)) > SUMMARY_MAX_CHARS:
        if not summary["top"]:
            raise BuildsError("ringkasan_terlalu_besar", "Ringkasan diff melebihi batas walau daftar berkas dikosongkan.")
        summary["top"] = summary["top"][: len(summary["top"]) // 2]
        summary["truncated"] = True
    return summary


def _state_kode(message: str) -> str:
    text = message.lower()
    for needle, kode in (("build aktif", "build_aktif"), ("belum siap", "analisis_belum_siap"), ("apktool", "apktool_tidak_ada"), ("tidak ditemukan", "analisis_tidak_ada")):
        if needle in text:
            return kode
    return "status_salah"


def request_build(d: Deps, analysis_id: int, requested_by: str = "user", note: str = "") -> dict[str, Any]:
    """Ajukan build dari diff `project/` saat ini (status `awaiting_approval`). Belum ada yang berjalan sampai `approve_build`."""
    _check_id("analysis_id", analysis_id)
    with closing(d.db()) as conn:
        row = _ready_analysis(conn, analysis_id)
        try:
            options = json.loads(row["options"] or "{}")
        except (ValueError, RecursionError):
            options = {}
        source_kind = "apk"
        marked = options.get("bundle") if isinstance(options, dict) else None
        if marked:
            fmt = marked.get("format") if isinstance(marked, dict) else None
            if fmt not in BUNDLE_KINDS:
                raise BuildsError("paket_belum_didukung", "Format paket ini belum didukung untuk build; hanya APK, XAPK, dan APKS.")
            source_kind = fmt
        stage = next((s["status"] for s in store.get_stages(conn, analysis_id) if s["name"] == "apktool"), None)
        if stage not in (store.OK, store.WARN):
            raise BuildsError("apktool_tidak_ada", "Hasil apktool tidak tersedia untuk analisis ini; tidak bisa dibangun.")
        if store.active_build(conn, analysis_id) is not None:
            raise BuildsError("build_aktif", "Sudah ada build aktif untuk analisis ini. Batalkan atau tunggu sampai selesai.")
    diff = workspace_diff(d, analysis_id)
    if sum(diff["counts"].values()) == 0:
        raise BuildsError("tidak_ada_perubahan", "project tidak berbeda dari baseline; tidak ada yang perlu dibangun.")
    summary = build_summary(diff)
    with closing(d.db()) as conn:
        try:
            build_id = store.create_build(conn, analysis_id, requested_by=requested_by, source_kind=source_kind, diff_sha256=diff["diff_sha256"], diff_summary=summary, note=note)
        except store.BuildInputError as exc:
            raise BuildsError("masukan_tidak_valid", str(exc)) from None
        except store.BuildStateError as exc:
            raise BuildsError(_state_kode(str(exc)), str(exc)) from None
    return {"build_id": build_id, "status": store.B_AWAITING, "diff_sha256": diff["diff_sha256"], "counts": diff["counts"], "peringatan": diff["peringatan"],
            "jejak_sistem": TRACE_FILE, "top": diff["top"]}


# ---------------------------------------------------------------------------------------------------- approve / cancel
def _has_job(conn: Any, build_id: int) -> bool:
    return any(str(j).startswith(f"build-{build_id}-") for j in Queue(QUEUE_NAME, connection=conn).job_ids)


def approve_build(d: Deps, build_id: int, diff_sha256: str, *, statement_version: int = 1, hold: bool = False, via: str = "ui") -> dict[str, Any]:
    """Setujui build TERIKAT hash (`store.approve_build`) lalu `queue_build` lalu kirim ke RQ (urutan D10: gagal Redis meninggalkan `queued` tanpa job, bukan `approved`).

    Idempoten: approve ulang pada `approved|queued` dengan hash SAMA tidak menyetujui lagi, hanya memastikan `queued` dan ada job RQ. `hold=True` = setujui + `queued` TANPA job
    (penahan uji, hanya CLI); approve ulang tanpa hold melepasnya. Hash lain -> `diff_berubah`; status lain -> `status_salah`."""
    _check_id("build_id", build_id)
    if type(diff_sha256) is not str or not HEX64_RE.fullmatch(diff_sha256):
        raise BuildsError("hash_tidak_valid", "diff_sha256 harus 64 karakter heksadesimal huruf kecil.")
    try:
        statement_sha = store.approval_statement_sha256(statement_version)
    except store.BuildInputError as exc:
        raise BuildsError("masukan_tidak_valid", str(exc)) from None
    with closing(d.db()) as conn:
        row = _get_build(conn, build_id)
        status = row["status"]
        if status == store.B_AWAITING:
            try:
                store.approve_build(conn, build_id, diff_sha256=diff_sha256, statement_sha256=statement_sha, statement_version=statement_version, via=via)
            except store.BuildDiffMismatchError as exc:
                raise BuildsError("diff_berubah", str(exc)) from None
            except store.BuildInputError as exc:
                raise BuildsError("masukan_tidak_valid", str(exc)) from None
            except store.BuildStateError as exc:
                raise BuildsError("status_salah", str(exc)) from None
            status = store.B_APPROVED
        elif status in (store.B_APPROVED, store.B_QUEUED):
            if not hmac.compare_digest(diff_sha256, row["diff_sha256"]):
                raise BuildsError("diff_berubah", "Diff berubah sejak diajukan; muat ulang dan tinjau lagi.")
        else:
            raise BuildsError("status_salah", f"Build #{build_id} berstatus {status}; tidak bisa disetujui.")
        if status == store.B_APPROVED:
            try:
                store.queue_build(conn, build_id)
            except store.BuildStateError as exc:
                if _get_build(conn, build_id)["status"] != store.B_QUEUED:        # kalah balapan (mis. dibatalkan); `queued` oleh pihak lain = aman
                    raise BuildsError("status_salah", str(exc)) from None
    result: dict[str, Any] = {"build_id": build_id, "status": store.B_QUEUED, "enqueued": False, "hold": bool(hold), "galat": "",
                              "pernyataan_versi": statement_version, "pernyataan_sha256": statement_sha}
    if hold:
        return result
    try:
        if not _has_job(d.redis, build_id):
            jobs.enqueue_build(d.redis, build_id, d.job_timeout + job_margin(row["source_kind"]) - JOB_TIMEOUT_MARGIN)
        result["enqueued"] = True
    except redis.RedisError as exc:
        result["galat"] = f"antrean (Redis) tidak terjangkau: {type(exc).__name__}"
    return result


def cancel_build(d: Deps, build_id: int) -> dict[str, Any]:
    _check_id("build_id", build_id)
    with closing(d.db()) as conn:
        try:
            outcome = store.request_cancel_build(conn, build_id)
        except store.BuildStateError:
            raise BuildsError("build_tidak_ada", f"Build #{build_id} tidak ditemukan.") from None
    if outcome == "noop":
        raise BuildsError("sudah_final", f"Build #{build_id} sudah berstatus final; tidak ada yang dibatalkan.")
    return {"build_id": build_id, "hasil": outcome}


# ---------------------------------------------------------------------------------------------------- status
def _beat(d: Deps, key: str) -> dict[str, Any] | None:
    """Detak jantung dari Redis, divalidasi ketat. None = mati/basi/rusak/tidak ada. RedisError naik (pemanggil menandai 'tidak terjangkau')."""
    raw = d.redis.get(key)
    if not raw:
        return None
    try:
        beat = json.loads(raw)
        ts = float(beat["ts"])
    except (ValueError, KeyError, TypeError, RecursionError):
        return None
    if not isinstance(beat, dict) or not math.isfinite(ts) or d.now() - ts > HEARTBEAT_STALE_AFTER:
        return None
    state = beat.get("state")
    job = beat.get("job")
    return {"state": state if state in ("idle", "busy") else None, "job": job if isinstance(job, str) and JOB_FRAGMENT_RE.fullmatch(job) else None,
            "keystore_state": beat.get("keystore_state") if isinstance(beat.get("keystore_state"), str) else None}


def _runner_text(beat: dict[str, Any] | None) -> str:
    if beat is None:
        return "runner MATI"
    return f"runner sibuk (job {beat['job']})" if beat["state"] == "busy" and beat["job"] else f"runner {beat['state'] or 'hidup'}"


def _signer_text(beat: dict[str, Any] | None) -> str:
    if beat is None:
        return "signer MATI: build akan gagal signer_unavailable"
    if beat["keystore_state"] not in (None, "ok"):
        return f"signer hidup tetapi keystore {beat['keystore_state']}: build akan gagal signer_unavailable"
    return f"signer hidup ({beat['state'] or 'hidup'})"


def _since(d: Deps, ts: float | None) -> str:
    return f", sudah {max(0, int(d.now() - ts))} dtk" if ts else ""


def _reason(d: Deps, row: Any, mulai: float | None) -> str:
    status = row["status"]
    if status == store.B_AWAITING:
        return f"menunggu persetujuan: jalankan approve --diff-sha256 {row['diff_sha256']}"
    if status == store.B_APPROVED:
        return "disetujui, menunggu masuk antrean: jalankan approve lagi dengan hash yang sama bila macet"
    if status == store.B_DONE:
        return f"selesai: {row['output_name']} ({row['output_size']} byte)"
    if status == store.B_REJECTED:
        return "ditolak"
    if status in (store.B_FAILED, store.B_CANCELLED):
        code = row["error_code"] or status
        text = f"{status}: {code}"
        if row["error_text"]:
            text += f" - {row['error_text']}"
        hint = HINTS.get(code)
        return f"{text}. {hint}" if hint else text
    try:                                                           # queued / building / signing: butuh Redis
        if status == store.B_QUEUED:
            ids = [str(j) for j in Queue(QUEUE_NAME, connection=d.redis).job_ids]
            mine = [i for i, j in enumerate(ids) if j.startswith(f"build-{row['id']}-")]
            if not mine:
                return "queued tanpa job di antrean (ditahan --hold atau Redis gagal saat disetujui): jalankan approve lagi dengan hash yang sama"
            return f"antre di worker: {mine[0]} pekerjaan di depan; {_runner_text(_beat(d, RUNNER_HEARTBEAT_KEY))}; {_signer_text(_beat(d, SIGNER_HEARTBEAT_KEY))}"
        if status == store.B_BUILDING:
            runner = _beat(d, RUNNER_HEARTBEAT_KEY)
            return f"membangun di runner{_since(d, row['started_at'])}; " + (_runner_text(runner) if runner else "detak runner hilang")
        signer = _beat(d, SIGNER_HEARTBEAT_KEY)
        return f"tahap tanda tangan{_since(d, mulai)}; " + (f"signer {signer['state'] or 'hidup'}" if signer else "detak signer hilang")
    except redis.RedisError:
        return f"{status}: antrean/detak tidak terjangkau (Redis tidak bisa dibaca)"


def _build_dirs(layout: Layout, analysis_id: int) -> list[int]:
    """Id build yang punya folder di `builds/<aid>` (rantai O_NOFOLLOW; `<aid>` symlink/tak ada -> kosong). Hanya nama bilangan bulat kanonik dan direktori sungguhan."""
    try:
        fd = open_dir_chain(layout.builds, str(analysis_id))
    except OSError:
        return []
    try:
        found = []
        for name in os.listdir(fd):
            if not (name.isascii() and name.isdigit() and str(int(name)) == name and int(name) > 0):
                continue
            try:
                if stat.S_ISDIR(os.lstat(name, dir_fd=fd).st_mode):
                    found.append(int(name))
            except OSError:
                continue
        return sorted(found)
    finally:
        os.close(fd)


def _delta(a: float | None, b: float | None) -> float | None:
    return b - a if a is not None and b is not None else None


def get_status(d: Deps, build_id: int | None = None, analysis_id: int | None = None) -> dict[str, Any]:
    """Keadaan satu build (+ alasan, cap waktu A-04) ATAU ringkasan satu analisis (`builds`, `build_dirs`). Hanya membaca."""
    if (build_id is None) == (analysis_id is None):
        raise BuildsError("argumen_salah", "Beri tepat salah satu: build_id atau analysis_id.")
    if analysis_id is not None:
        _check_id("analysis_id", analysis_id)
        with closing(d.db()) as conn:
            rows = conn.execute("SELECT id, status FROM build WHERE analysis_id = ? ORDER BY id", (analysis_id,)).fetchall()
        return {"analysis_id": analysis_id, "builds": [{"build_id": r["id"], "status": r["status"]} for r in rows], "build_dirs": _build_dirs(d.layout, analysis_id)}
    _check_id("build_id", build_id)
    with closing(d.db()) as conn:
        row = _get_build(conn, build_id)
    match = SIGNING_MULAI_RE.search(row["stage_log"] or "")
    mulai = float(match.group(1)) if match else None
    final = row["status"] in store.BUILD_FINAL
    return {
        "build_id": row["id"], "analysis_id": row["analysis_id"], "status": row["status"], "alasan": _reason(d, row, mulai), "diff_sha256": row["diff_sha256"],
        "error_code": row["error_code"] or "", "error_text": row["error_text"] or "", "cancel_requested": row["cancel_requested"], "output_name": row["output_name"] or "",
        "output_size": row["output_size"], "output_sha256": row["output_sha256"] or "", "cert_sha256": row["cert_sha256"] or "", "verify_ok": row["verify_ok"],
        "approved_at": row["approved_at"], "started_at": row["started_at"], "signing_mulai": mulai, "finished_at": row["finished_at"],
        "waktu_antre": _delta(row["approved_at"], row["started_at"]), "waktu_build": _delta(row["started_at"], mulai),
        "waktu_tanda_tangan": _delta(mulai, row["finished_at"]) if final else None, "stage_log": row["stage_log"] or "",
    }


def wait_build(d: Deps, build_id: int, timeout: float, on_change: Callable[[str, float], None] | None = None) -> dict[str, Any]:
    """Tunggu build mencapai status final (poll `d.poll`). `on_change(status, detik)` dipanggil tiap status berubah (termasuk yang pertama). Waktu habis ->
    BuildsError('waktu_habis') dengan status terakhir di `extra`."""
    _check_id("build_id", build_id)
    start = time.monotonic()
    last = None
    while True:
        with closing(d.db()) as conn:
            status = _get_build(conn, build_id)["status"]
        elapsed = time.monotonic() - start
        if status != last:
            last = status
            if on_change is not None:
                on_change(status, elapsed)
        if status in store.BUILD_FINAL:
            return {**get_status(d, build_id), "elapsed": round(elapsed, 1)}
        if elapsed >= timeout:
            raise BuildsError("waktu_habis", f"Build #{build_id} belum selesai dalam {int(timeout)} detik (status terakhir: {status}).", status=status, elapsed=round(elapsed, 1))
        time.sleep(d.poll)


# ---------------------------------------------------------------------------------------------------- artefak
def artifact_info(d: Deps, build_id: int) -> dict[str, Any]:
    """Hash ULANG berkas artefak di disk dan bandingkan dengan DB (runner bisa menulis `builds/`, jadi DB saja tidak cukup). Berkas dibuka lewat rantai
    O_NOFOLLOW, harus berkas biasa (FIFO/symlink/direktori -> `berkas_tidak_ada`, tanpa menggantung)."""
    _check_id("build_id", build_id)
    with closing(d.db()) as conn:
        row = _get_build(conn, build_id)
    if row["status"] != store.B_DONE:
        raise BuildsError("belum_selesai", f"Build #{build_id} berstatus {row['status']}; belum ada artefak.")
    name = row["output_name"] or ""
    if not OUTPUT_NAME_RE.fullmatch(name):
        raise BuildsError("berkas_tidak_ada", "Nama artefak di DB tidak valid.")
    info = {"build_id": build_id, "output_name": name, "output_size": row["output_size"], "output_sha256": row["output_sha256"], "cert_sha256": row["cert_sha256"]}
    try:
        bfd = open_dir_chain(d.layout.builds, str(row["analysis_id"]), str(build_id))
    except OSError:
        raise BuildsError("berkas_tidak_ada", "Folder build tidak ada atau tidak aman.", **info) from None
    try:
        try:
            fd = os.open(name, OPEN_ARTIFACT, dir_fd=bfd)
        except OSError:
            raise BuildsError("berkas_tidak_ada", "Berkas artefak tidak ada atau bukan berkas biasa.", **info) from None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise BuildsError("berkas_tidak_ada", "Artefak bukan berkas biasa.", **info)
            digest = hashlib.sha256()
            while True:
                block = os.read(fd, HASH_BLOCK)
                if not block:
                    break
                digest.update(block)
        finally:
            os.close(fd)
    finally:
        os.close(bfd)
    disk = digest.hexdigest()
    match = hmac.compare_digest(disk, row["output_sha256"])
    if not match:
        raise BuildsError("hash_tidak_cocok", "Hash berkas di disk TIDAK sama dengan hash di DB (artefak berubah setelah terbit).", disk_sha256=disk, cocok=False, **info)
    return {**info, "disk_sha256": disk, "cocok": True}
