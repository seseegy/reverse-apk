"""Orkestrasi pipeline analisis (M1): validasi -> apktool -> jadx -> ringkasan manifest.

Worker TIDAK menjalankan jadx/apktool sendiri. Ia menitipkan job ke runner (container terpisah, tanpa
jaringan) lewat spool berkas, lalu memantau hasilnya. Lihat rvcore/spool.py untuk protokolnya.

Kebijakan kegagalan (disengaja):
  * timeout / batas keluaran terlampaui / runner mati  -> seluruh analisis GAGAL (kode galat jelas)
  * jadx melaporkan error parsial tetapi ada keluaran  -> tahap "peringatan", analisis tetap lanjut
  * satu tool gagal, tool lain berhasil               -> analisis SELESAI dengan peringatan
  * kedua tool gagal                                   -> GAGAL
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rvcore import store
from rvcore.db import connect, migrate
from rvcore.fsutil import atomic_write_json, safe_rmtree, tree_stats
from rvcore.paths import Layout
from rvcore.spool import (
    RESULT_ABORTED,
    RESULT_CANCELLED,
    RESULT_FAILED,
    RESULT_OK,
    RESULT_TIMEOUT,
    RESULT_WARN,
    Spool,
    new_job_id,
)

from logtail import LogTail
from manifest import ManifestError, parse_manifest

log = logging.getLogger("reverse-apk.pipeline")

POLL_INTERVAL = 1.0
RUNNER_STALE_AFTER = 45.0  # detik tanpa detak jantung runner saat job sudah diambil = runner mati
GRACE_AFTER_TIMEOUT = 60.0  # runner seharusnya sudah menghentikan job lewat timeout + ini


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw and raw.strip() else default


@dataclass(frozen=True)
class Config:
    layout: Layout
    spool: Spool
    timeouts: dict[str, int]
    pickup_timeout: int
    min_free_bytes: int

    @classmethod
    def from_env(cls) -> "Config":
        layout = Layout(os.environ.get("DATA_DIR", "/data"))
        return cls(
            layout=layout,
            spool=Spool(layout.spool),
            timeouts={
                "apktool": _env_int("TIMEOUT_APKTOOL", 300),
                "jadx": _env_int("TIMEOUT_JADX", 900),
            },
            pickup_timeout=_env_int("RUNNER_PICKUP_TIMEOUT", 120),
            min_free_bytes=_env_int("JOB_MIN_FREE_GB", 5) * 1024**3,
        )


class PipelineFailure(Exception):
    """Kegagalan yang menghentikan seluruh analisis. `message` ditampilkan ke pengguna."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class Cancelled(Exception):
    pass


def _fmt_secs(seconds: int) -> str:
    if seconds >= 120 and seconds % 60 == 0:
        return f"{seconds // 60} menit"
    if seconds >= 60:
        return f"{seconds // 60} menit {seconds % 60} detik" if seconds % 60 else f"{seconds // 60} menit"
    return f"{seconds} detik"


def _fmt_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


class Run:
    """Konteks satu eksekusi analisis."""

    def __init__(self, conn, cfg: Config, analysis: Any) -> None:  # noqa: ANN001
        self.conn = conn
        self.cfg = cfg
        self.id: int = analysis["id"]
        self.apk_id: int = analysis["apk_id"]
        self.sha256: str = analysis["sha256"]
        self.size: int = analysis["size"]
        self.options: dict[str, Any] = _load_options(analysis["options"])
        self.work = cfg.layout.work_dir(self.id)
        self.versions: dict[str, Any] = {}
        self.current_stage: str | None = None

    def log(self, level: str, message: str, stage: str | None = None) -> None:
        store.add_log(self.conn, self.id, stage or self.current_stage, level, message)

    def check_cancel(self) -> None:
        if store.is_cancel_requested(self.conn, self.id):
            raise Cancelled()


def _load_options(raw: str | None) -> dict[str, Any]:
    try:
        data = json.loads(raw or "{}")
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


# ====================================================================== titik masuk


def run_analysis(analysis_id: int) -> None:
    cfg = Config.from_env()
    conn = connect(cfg.layout.db_path)
    try:
        if not store.claim_analysis(conn, analysis_id):
            log.info("analisis %s dilewati (sudah diambil/dibatalkan)", analysis_id)
            return
        analysis = store.get_analysis(conn, analysis_id)
        run = Run(conn, cfg, analysis)
        log.info("mulai analisis %s (apk=%s, percobaan %s)", run.id, run.apk_id, analysis["attempt"])
        started = time.monotonic()
        try:
            _execute(run)
        except Cancelled:
            _finish_cancelled(run)
        except PipelineFailure as failure:
            _finish_failed(run, failure.code, failure.message)
        except BaseException as exc:  # noqa: BLE001 - termasuk timeout RQ; analisis tidak boleh menggantung 'running'
            log.exception("galat tak terduga pada analisis %s", run.id)
            _finish_failed(run, store.E_INTERNAL, f"Galat internal: {type(exc).__name__}: {str(exc)[:200]}")
            if not isinstance(exc, Exception):
                raise
        else:
            log.info("analisis %s selesai dalam %.1fs", run.id, time.monotonic() - started)
    finally:
        conn.close()


# ====================================================================== alur utama


def _execute(run: Run) -> None:
    cfg = run.cfg
    cfg.spool.ensure_dirs()

    # Bersihkan sisa percobaan sebelumnya. Worker adalah satu-satunya penulis di sini.
    safe_rmtree(run.work)
    run.work.mkdir(parents=True, exist_ok=True)
    (run.work / "logs").mkdir(exist_ok=True)

    _stage_validate(run)

    outcomes: dict[str, str] = {}
    for stage in ("apktool", "jadx"):
        run.check_cancel()
        outcomes[stage] = _stage_tool(run, stage)

    usable = [s for s, o in outcomes.items() if o in (store.OK, store.WARN)]
    if not usable:
        raise PipelineFailure(
            store.E_TOOL,
            "apktool dan jadx sama-sama gagal; tidak ada hasil yang bisa dipakai. Lihat log untuk detailnya.",
        )

    run.current_stage = None
    _summarize_manifest(run, outcomes)
    _record_artifacts(run, outcomes)
    store.set_tool_versions(run.conn, run.id, run.versions)

    problems = [s for s, o in outcomes.items() if o in (store.WARN, store.FAILED)]
    if problems:
        run.log("warn", "Selesai dengan peringatan pada: " + ", ".join(problems) + ".")
    else:
        run.log("info", "Semua tahap selesai.")
    if not store.finish_analysis(run.conn, run.id, store.DONE):
        # Status sudah berubah di luar kita (mis. dibatalkan persis di akhir). Hormati status itu.
        log.info("analisis %s: status akhir sudah ditetapkan di tempat lain", run.id)


# ====================================================================== tahap: validasi


def _stage_validate(run: Run) -> None:
    run.current_stage = "validating"
    store.set_stage(run.conn, run.id, "validating", store.RUNNING)
    run.log("info", "Memeriksa integritas berkas upload…")

    path = run.cfg.layout.upload_path(run.sha256)
    try:
        st = path.lstat()
    except OSError:
        store.set_stage(run.conn, run.id, "validating", store.FAILED, "berkas upload tidak ditemukan")
        raise PipelineFailure(store.E_VALIDATION, "Berkas APK asli tidak ditemukan di penyimpanan.")
    if not path.is_file() or path.is_symlink() or st.st_size != run.size:
        store.set_stage(run.conn, run.id, "validating", store.FAILED, "ukuran/jenis berkas tidak cocok")
        raise PipelineFailure(store.E_VALIDATION, "Berkas upload tidak cocok dengan catatan (ukuran/jenis berbeda).")

    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != run.sha256:
        store.set_stage(run.conn, run.id, "validating", store.FAILED, "SHA-256 tidak cocok")
        raise PipelineFailure(store.E_VALIDATION, "SHA-256 berkas tidak cocok dengan catatan; berkas mungkin rusak.")

    free = shutil.disk_usage(run.cfg.layout.work).free
    if free < run.cfg.min_free_bytes:
        store.set_stage(run.conn, run.id, "validating", store.FAILED, "disk hampir penuh")
        raise PipelineFailure(
            store.E_VALIDATION,
            f"Sisa disk {_fmt_bytes(free)} di bawah batas aman {_fmt_bytes(run.cfg.min_free_bytes)}.",
        )

    store.set_stage(run.conn, run.id, "validating", store.OK, f"SHA-256 cocok, {_fmt_bytes(run.size)}")
    run.log("info", f"Berkas utuh ({_fmt_bytes(run.size)}, SHA-256 cocok).")


# ====================================================================== tahap: tool


def _stage_tool(run: Run, stage: str) -> str:
    """Jalankan satu tool lewat runner. Mengembalikan status tahap akhir (ok/warn/failed)."""
    run.current_stage = stage
    timeout = run.cfg.timeouts[stage]
    store.set_stage(run.conn, run.id, stage, store.RUNNING)
    run.log("info", f"Menjalankan {stage} (batas waktu {_fmt_secs(timeout)})…")

    result = _run_job(run, stage, timeout)
    status = result.get("status")
    message = str(result.get("message") or "")
    code = str(result.get("error_code") or "")

    tool = result.get("tool") or {}
    run.versions[stage] = {
        "version": tool.get("version"),
        "args": result.get("args"),
        "duration_s": result.get("duration"),
        "exit_code": result.get("exit_code"),
    }
    if result.get("java"):
        run.versions["java"] = result["java"]

    if status == RESULT_CANCELLED:
        raise Cancelled()
    if status == RESULT_TIMEOUT:
        store.set_stage(run.conn, run.id, stage, store.FAILED, "timeout")
        raise PipelineFailure(
            store.E_TIMEOUT, f"Tahap {stage} melebihi batas waktu {_fmt_secs(timeout)} dan dihentikan."
        )
    if code == "output_limit":
        store.set_stage(run.conn, run.id, stage, store.FAILED, "keluaran terlalu besar")
        raise PipelineFailure(store.E_OUTPUT_LIMIT, message or f"Keluaran {stage} melebihi batas dan dihentikan.")
    if code in (store.E_RUNNER, "runner_lost") or status == RESULT_ABORTED:
        # Runner mati/berulang restart: tahap berikutnya pasti ikut gagal, jadi hentikan sekarang.
        store.set_stage(run.conn, run.id, stage, store.FAILED, "runner tidak tersedia")
        raise PipelineFailure(store.E_RUNNER, message or "Runner tidak tersedia atau berulang kali dimulai ulang.")

    summary = ""
    if result.get("output_files") is not None:
        summary = f"{result.get('output_files'):,} berkas, {_fmt_bytes(int(result.get('output_bytes') or 0))}"

    if status == RESULT_OK:
        store.set_stage(run.conn, run.id, stage, store.OK, summary)
        run.log("info", f"{stage} selesai ({float(result.get('duration') or 0):.0f} dtk; {summary}).")
        return store.OK
    if status == RESULT_WARN:
        store.set_stage(run.conn, run.id, stage, store.WARN, message or summary)
        run.log("warn", f"{stage} selesai dengan peringatan: {message or 'error parsial'} ({summary}).")
        return store.WARN

    # failed / aborted / lainnya: tool lain mungkin masih berguna, jadi lanjutkan.
    detail = message or f"gagal (kode {result.get('exit_code')})"
    store.set_stage(run.conn, run.id, stage, store.FAILED, detail)
    run.log("error", f"{stage} gagal: {detail}")
    return store.FAILED


def _run_job(run: Run, stage: str, timeout: int) -> dict[str, Any]:
    """Kirim job ke runner dan tunggu hasilnya. Mengulang 1× bila runner dimulai ulang saat job berjalan (FR-2.7)."""
    for attempt in (1, 2):
        job_id = new_job_id(run.id, stage)
        run.cfg.spool.submit({
            "job_id": job_id,
            "analysis_id": run.id,
            "stage": stage,
            "sha256": run.sha256,
            "options": {"deobf": bool(run.options.get("deobf"))},
            "timeout": timeout,
            "created": time.time(),
        })
        result = _wait_result(run, stage, job_id, timeout)
        if result.get("status") == RESULT_ABORTED and attempt == 1:
            run.log("warn", f"Runner dimulai ulang saat {stage} berjalan; mengulang tahap ini sekali.")
            continue
        return result
    return result  # pragma: no cover - loop selalu return


def _wait_result(run: Run, stage: str, job_id: str, timeout: int) -> dict[str, Any]:
    spool = run.cfg.spool
    tail = LogTail(run.conn, run.cfg.layout.work, run.id, stage)
    submitted = time.monotonic()
    claimed_at: float | None = None
    cancel_sent = False
    try:
        while True:
            result = spool.result(job_id)
            if result is not None:
                tail.flush()
                return result

            now = time.monotonic()
            if claimed_at is None:
                if spool.is_waiting(job_id):
                    if now - submitted > run.cfg.pickup_timeout:
                        if spool.withdraw(job_id):
                            return {"status": RESULT_FAILED, "error_code": store.E_RUNNER,
                                    "message": f"Runner tidak mengambil job dalam {run.cfg.pickup_timeout} detik "
                                               "(runner mati atau terlalu sibuk)."}
                        # Terambil persis sekarang; lanjutkan menunggu.
                        claimed_at = now
                else:
                    claimed_at = now  # sudah pindah ke running/ (atau selesai; hasilnya dibaca di putaran berikut)
            else:
                age = spool.heartbeat_age()
                if age is None or age > RUNNER_STALE_AFTER:
                    # Beri satu kesempatan terakhir membaca hasil yang mungkin baru ditulis.
                    time.sleep(0.5)
                    late = spool.result(job_id)
                    if late is not None:
                        tail.flush()
                        return late
                    return {"status": RESULT_ABORTED, "error_code": "runner_lost",
                            "message": "Runner berhenti merespons saat job berjalan."}
                if now - claimed_at > timeout + GRACE_AFTER_TIMEOUT and not cancel_sent:
                    spool.request_cancel(job_id)  # sabuk pengaman bila runner gagal menegakkan timeout
                    cancel_sent = True
                if now - claimed_at > timeout + 2 * GRACE_AFTER_TIMEOUT:
                    return {"status": RESULT_TIMEOUT, "error_code": store.E_TIMEOUT,
                            "message": "Job tidak selesai meski sudah melewati batas waktu."}

            if not cancel_sent and store.is_cancel_requested(run.conn, run.id):
                spool.request_cancel(job_id)
                cancel_sent = True
                run.log("warn", f"Pembatalan diminta; menghentikan {stage}…")

            tail.pump()
            time.sleep(POLL_INTERVAL)
    finally:
        spool.forget(job_id)


# ====================================================================== pascaproses


def _summarize_manifest(run: Run, outcomes: dict[str, str]) -> None:
    sources = []
    if outcomes.get("apktool") in (store.OK, store.WARN):
        sources.append(("apktool", run.work / "apktool"))
    if outcomes.get("jadx") in (store.OK, store.WARN):
        sources.append(("jadx", run.work / "jadx" / "resources"))

    for name, directory in sources:
        try:
            if (directory / "AndroidManifest.xml").is_symlink():
                raise ManifestError("AndroidManifest.xml adalah symlink")
            data = parse_manifest(directory)
        except ManifestError as exc:
            run.log("warn", f"Manifest dari {name} tidak bisa diringkas: {exc}")
            continue
        # Direktori temp HARUS satu filesystem (volume `work`) dengan tujuan agar os.replace atomik.
        atomic_write_json(run.work / "manifest.json", run.cfg.layout.work / ".tmp", data)
        store.update_apk_meta(
            run.conn, run.apk_id,
            package=data.get("package"), app_label=data.get("app_label"),
            version_name=data.get("version_name"), version_code=data.get("version_code"),
            min_sdk=data.get("min_sdk"), target_sdk=data.get("target_sdk"),
        )
        run.log("info", f"Manifest diringkas dari {name}: {data.get('package') or '?'} "
                        f"v{data.get('version_name') or '?'}.")
        return
    run.log("warn", "Manifest tidak tersedia; metadata paket tidak terisi.")


def _record_artifacts(run: Run, outcomes: dict[str, str]) -> None:
    items = []
    for stage in ("apktool", "jadx"):
        if outcomes.get(stage) in (store.OK, store.WARN):
            size, files, _ = tree_stats(run.work / stage)
            items.append((stage, stage, size, files))
    store.replace_artifacts(run.conn, run.id, items)


# ====================================================================== penutup


def _finish_failed(run: Run, code: str, message: str) -> None:
    run.log("error", message)
    _settle_stages(run, running_to=store.FAILED, pending_detail="dilewati karena kegagalan sebelumnya")
    if run.versions:
        store.set_tool_versions(run.conn, run.id, run.versions)
    store.finish_analysis(run.conn, run.id, store.FAILED, code, message)
    log.warning("analisis %s gagal [%s]: %s", run.id, code, message)


def _finish_cancelled(run: Run) -> None:
    run.log("warn", "Analisis dibatalkan oleh pengguna.")
    _settle_stages(run, running_to=store.CANCELLED, pending_detail="dibatalkan")
    # Runner sudah berhenti (hasil 'cancelled' diterima), jadi aman membuang keluaran parsial.
    for sub in ("apktool", "jadx"):
        safe_rmtree(run.work / sub)
    store.finish_analysis(run.conn, run.id, store.CANCELLED, store.E_CANCELLED, "Dibatalkan oleh pengguna.")
    log.info("analisis %s dibatalkan", run.id)


def _settle_stages(run: Run, running_to: str, pending_detail: str) -> None:
    for s in store.get_stages(run.conn, run.id):
        if s["status"] == store.RUNNING:
            store.set_stage(run.conn, run.id, s["name"], running_to, s["detail"])
        elif s["status"] == store.PENDING:
            store.set_stage(run.conn, run.id, s["name"], store.SKIPPED, pending_detail)


# ====================================================================== pemulihan (dipanggil worker.py)


def reconcile(spool: Spool | None = None) -> list[int]:
    """Dipanggil saat worker mulai. Analisis 'running' yang ditinggal proses lama -> failed, dan
    runner diminta menghentikan job yatim. Mengembalikan id yang ditandai terputus."""
    cfg = Config.from_env()
    migrate(cfg.layout.db_path)
    conn = connect(cfg.layout.db_path)
    try:
        ids = store.mark_interrupted(conn)
    finally:
        conn.close()
    sp = spool or cfg.spool
    try:
        sp.ensure_dirs()
        for job_id in sp.running_job_ids():
            sp.request_cancel(job_id)
        for p in list(sp.requests.glob("*.json")):
            p.unlink(missing_ok=True)
    except OSError:
        log.exception("gagal membersihkan spool saat pemulihan")
    return ids
