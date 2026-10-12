"""Protokol web <-> bench untuk tool AI `shell_run` (PRD 09, Bagian C).

Sama dengan spool.py (rename atomik; request/running/results/cancel), tetapi di VOLUME TERPISAH (`benchspool`) yang hanya dipasang di web
dan bench, dengan pola id dan batas ukuran sendiri. Jangan pernah berbagi direktori dengan spool worker<->runner: `claim_next` mengklaim
apa saja yang lolos pola id di `requests/`.

Kepercayaan:
  * bench TIDAK mempercayai path dari web. Ia hanya menerima `analysis_id` (angka), `sha256` (heksa 64) dan teks perintah; semua path dihitung sendiri.
  * web TIDAK mempercayai hasil dari bench. Bench memproses isi APK dan menjalankan perintah yang disusun AI; kontainernya bisa saja terkompromi.
    Ukuran berkas hasil diperiksa SEBELUM dibaca, di-parse sebagai JSON ketat, dan setiap bidang dinormalkan (jenis, panjang) di `parse_result`.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .paths import SHA256_RE
from .spool import RESULT_CANCELLED, RESULT_FAILED, RESULT_OK, RESULT_TIMEOUT, Spool

JOB_ID_RE = re.compile(r"^s(\d{1,9})-[0-9a-f]{12}$")
MAX_COMMAND_CHARS = 8000
MAX_REQUEST_BYTES = 64 * 1024            # perintah 8000 karakter UTF-8 <= 32 KB + bidang lain
MAX_RESULT_BYTES = 1024 * 1024           # diperiksa SEBELUM membaca berkas hasil
MAX_STREAM_CHARS = 200_000               # batas mutlak per aliran setelah dibaca web (bench membatasi lebih ketat)
HEARTBEAT_STALE_AFTER = 20.0             # detik; bench menulis detak jantung tiap 5 detik

OP_RUN = "run"

# Status hasil yang dikenal web. Selain ini dianggap rusak.
STATUS_OK = RESULT_OK                    # perintah selesai (apa pun kode keluarnya)
STATUS_TIMEOUT = RESULT_TIMEOUT
STATUS_CANCELLED = RESULT_CANCELLED
STATUS_FAILED = RESULT_FAILED            # bench gagal menjalankan (bukan kegagalan perintah)
STATUS_REFUSED = "refused"               # ditolak sebelum jalan: kuota ruang kerja, permintaan tidak valid, pengurungan tidak bisa dipasang
STATUSES = frozenset({STATUS_OK, STATUS_TIMEOUT, STATUS_CANCELLED, STATUS_FAILED, STATUS_REFUSED})


class BenchUnavailable(Exception):
    """Bench tidak bisa dipakai (mati, sibuk, atau hasilnya rusak). `message` aman ditampilkan ke AI."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def new_job_id(analysis_id: int) -> str:
    return f"s{int(analysis_id)}-{uuid.uuid4().hex[:12]}"


def make_spool(root: str | os.PathLike[str]) -> Spool:
    return Spool(root, id_re=JOB_ID_RE, max_request=MAX_REQUEST_BYTES)


def build_run_request(analysis_id: int, command: str, timeout: int, sha256: str | None) -> dict[str, Any]:
    if not isinstance(command, str) or not command.strip() or "\x00" in command or len(command) > MAX_COMMAND_CHARS:
        raise ValueError("perintah tidak valid")
    if sha256 is not None and not SHA256_RE.match(sha256):
        raise ValueError("sha256 tidak valid")
    return {"job_id": new_job_id(analysis_id), "op": OP_RUN, "analysis_id": int(analysis_id), "command": command, "timeout": int(timeout),
            "sha256": sha256, "created": time.time()}


def _int(v: Any, lo: int, hi: int, default: int | None = None) -> int | None:
    if isinstance(v, bool) or not isinstance(v, int):
        return default
    return max(lo, min(hi, v))


def _text(v: Any, limit: int) -> str:
    return v[:limit] if isinstance(v, str) else ""


def parse_result(raw: Any) -> dict[str, Any]:
    """Normalkan hasil dari bench (TIDAK TEPERCAYA). Bidang tak dikenal dibuang, jenis dan panjang dipaksa. Tidak pernah melempar."""
    if not isinstance(raw, dict):
        raw = {}                                  # tetap lewat jalur normalisasi di bawah: pemanggil membaca SEMUA kunci tanpa `.get`
        message = "hasil bench rusak"
    else:
        message = _text(raw.get("message"), 600)
    status = raw.get("status") if raw.get("status") in STATUSES else STATUS_FAILED
    return {
        "status": status,
        "exit_code": _int(raw.get("exit_code"), -255, 255),
        "signal": _int(raw.get("signal"), 1, 64),
        "stdout": _text(raw.get("stdout"), MAX_STREAM_CHARS),
        "stderr": _text(raw.get("stderr"), MAX_STREAM_CHARS),
        "truncated": bool(raw.get("truncated")),
        "omitted_bytes": _int(raw.get("omitted_bytes"), 0, 1 << 40, 0),
        "duration_ms": _int(raw.get("duration_ms"), 0, 10**9, 0),
        "message": message,
        "workspace_bytes": _int(raw.get("workspace_bytes"), 0, 1 << 50),
    }


def read_result(spool: Spool, job_id: str) -> dict[str, Any] | None:
    """Hasil job, atau None bila belum ada. Ukuran dibatasi SEBELUM dibaca; JSON rusak -> status failed."""
    path = spool.results / f"{job_id}.json"
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return parse_result({"status": STATUS_FAILED, "message": "hasil bench tidak bisa dibaca"})
    if not path.is_file() or path.is_symlink():
        return parse_result({"status": STATUS_FAILED, "message": "hasil bench bukan berkas biasa"})
    if st.st_size > MAX_RESULT_BYTES:
        return parse_result({"status": STATUS_FAILED, "message": "hasil bench terlalu besar"})
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_RESULT_BYTES + 1)
        return parse_result(json.loads(data.decode("utf-8")))
    except (OSError, ValueError):
        return parse_result({"status": STATUS_FAILED, "message": "hasil bench rusak"})


def run_command(spool: Spool, analysis_id: int, command: str, *, timeout: int, sha256: str | None = None, cancel: threading.Event | None = None,
                pickup_timeout: float = 30.0, grace: float = 15.0, poll: float = 0.1) -> dict[str, Any]:
    """Kirim satu perintah ke bench dan tunggu hasilnya. Memblokir. Melempar BenchUnavailable bila bench mati/sibuk/rusak.

    Ketahanan: bench mati -> gagal CEPAT (sebelum mengirim); tidak diambil dalam `pickup_timeout` -> ditarik; melewati batas waktu + `grace` -> minta
    batal lalu menyerah; `cancel` (pengguna menekan Batal) -> minta batal dan kembali segera. Berkas job selalu dibersihkan."""
    age = spool.heartbeat_age()
    if age is None or age > HEARTBEAT_STALE_AFTER:
        raise BenchUnavailable("Bench (kontainer shell) tidak aktif, jadi tidak ada perintah yang dijalankan.")
    try:
        job = build_run_request(analysis_id, command, timeout, sha256)
    except ValueError as exc:
        raise BenchUnavailable(f"Permintaan tidak valid: {exc}.") from exc
    job_id = job["job_id"]
    spool.submit(job)
    submitted = time.monotonic()
    started: float | None = None
    try:
        while True:
            res = read_result(spool, job_id)
            if res is not None:
                return res
            now = time.monotonic()
            if cancel is not None and cancel.is_set():
                spool.request_cancel(job_id)
                if spool.withdraw(job_id):
                    return {**parse_result({"status": STATUS_CANCELLED}), "message": "dibatalkan sebelum berjalan"}
                started = started or now
                deadline = min(started + timeout + grace, now + 5.0)         # beri bench waktu singkat untuk menutup rapi
                while time.monotonic() < deadline:
                    res = read_result(spool, job_id)
                    if res is not None:
                        return res
                    time.sleep(poll)
                return {**parse_result({"status": STATUS_CANCELLED}), "message": "dibatalkan"}
            if started is None:
                if spool.is_waiting(job_id):
                    if now - submitted > pickup_timeout:
                        if spool.withdraw(job_id):
                            raise BenchUnavailable("Bench sibuk atau tidak mengambil perintah dalam batas waktu; coba lagi sebentar lagi.")
                else:
                    started = now
            elif now - started > timeout + grace:
                spool.request_cancel(job_id)
                time.sleep(min(2.0, grace))
                res = read_result(spool, job_id)
                if res is not None:
                    return res
                raise BenchUnavailable("Bench tidak menjawab setelah batas waktu perintah; hasilnya dibuang.")
            hb = spool.heartbeat_age()
            if started is not None and (hb is None or hb > HEARTBEAT_STALE_AFTER * 2):
                raise BenchUnavailable("Bench berhenti merespons saat perintah berjalan.")
            time.sleep(poll)
    finally:
        spool.forget(job_id)


def workspace_dir(bench_root: str | os.PathLike[str], analysis_id: int) -> Path:
    """Ruang kerja per analisis. int() menolak '/' dan '..' sebelum menjadi bagian path."""
    return Path(bench_root) / str(int(analysis_id))
