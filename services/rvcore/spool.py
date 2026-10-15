"""Protokol antrean berbasis berkas antara worker (pengirim) dan runner (pelaksana).

Runner berjalan tanpa jaringan sama sekali, jadi tidak bisa memakai Redis. Keduanya berbagi
volume `spool`; semua perpindahan berkas memakai rename/replace atomik di filesystem yang sama.

    requests/<job_id>.json   worker membuat; menunggu diambil
    running/<job_id>.json    runner memindahkan ke sini saat mulai (klaim atomik)
    results/<job_id>.json    runner menulis saat selesai; worker membaca lalu menghapus
    cancel/<job_id>          worker membuat untuk meminta pembatalan; runner memantau
    runner.hb                detak jantung runner (JSON)
    tmp/                     area tulis sementara

Tidak ada path dari worker yang dipercaya runner: runner menghitung sendiri path dari
analysis_id + sha256 yang sudah divalidasi formatnya.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

from .fsutil import atomic_write_json

TOOL_STAGES = ("apktool", "jadx", "analyze", "build")
JOB_ID_RE = re.compile(r"^a(\d{1,9})-(apktool|jadx|analyze|build)-[0-9a-f]{8}$")
# Direktori keluaran per tahap di work/<analysis_id>/ (analyze menulis ke index/, bukan analyze/). Tahap `build` TIDAK ada di sini: keluarannya bukan di
# work/ melainkan di builds/<analysis_id>/<build_id>/ (jalur dihitung runner dari id bilangan bulat; lihat buildproto.py dan runner/buildstage.py).
STAGE_OUT_DIR = {"apktool": "apktool", "jadx": "jadx", "analyze": "index"}
MAX_REQUEST_BYTES = 16 * 1024

# Hasil akhir sebuah job di runner.
RESULT_OK = "ok"
RESULT_WARN = "warn"  # ada keluaran, tetapi tool melaporkan error parsial (mis. jadx)
RESULT_FAILED = "failed"
RESULT_TIMEOUT = "timeout"
RESULT_CANCELLED = "cancelled"
RESULT_ABORTED = "aborted"  # runner dimulai ulang saat job berjalan


def new_job_id(analysis_id: int, stage: str) -> str:
    if stage not in TOOL_STAGES:
        raise ValueError(f"tahap tidak dikenal: {stage}")
    return f"a{int(analysis_id)}-{stage}-{uuid.uuid4().hex[:8]}"


class Spool:
    def __init__(self, root: str | os.PathLike[str], *, id_re: "re.Pattern[str]" = JOB_ID_RE, max_request: int = MAX_REQUEST_BYTES) -> None:
        # Bawaan = perilaku worker<->runner. Spool lain (bench, shellspool.py) memakai pola id dan batas ukurannya sendiri, dan HARUS
        # berada di direktori/volume terpisah: claim_next mengklaim apa saja yang lolos `id_re` di requests/.
        self.id_re = id_re
        self.max_request = max_request
        self.root = Path(root)
        self.requests = self.root / "requests"
        self.running = self.root / "running"
        self.results = self.root / "results"
        self.cancel = self.root / "cancel"
        self.tmp = self.root / "tmp"
        self.heartbeat_file = self.root / "runner.hb"

    def ensure_dirs(self) -> None:
        for d in (self.requests, self.running, self.results, self.cancel, self.tmp):
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------ worker side
    def submit(self, job: dict[str, Any]) -> None:
        job_id = job["job_id"]
        if not self.id_re.match(job_id):
            raise ValueError("job_id tidak valid")
        self.ensure_dirs()
        atomic_write_json(self.requests / f"{job_id}.json", self.tmp, job)

    def request_cancel(self, job_id: str) -> None:
        if not self.id_re.match(job_id):
            return
        self.ensure_dirs()
        try:
            (self.cancel / job_id).touch(exist_ok=True)
        except OSError:
            pass

    def result(self, job_id: str) -> dict[str, Any] | None:
        try:
            return json.loads((self.results / f"{job_id}.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            return {"status": RESULT_FAILED, "error_code": "bad_result", "message": "hasil runner rusak"}

    def is_waiting(self, job_id: str) -> bool:
        return (self.requests / f"{job_id}.json").exists()

    def withdraw(self, job_id: str) -> bool:
        """Tarik request yang belum diambil runner. True bila berhasil (belum sempat berjalan)."""
        try:
            (self.requests / f"{job_id}.json").unlink()
            return True
        except FileNotFoundError:
            return False

    def forget(self, job_id: str) -> None:
        for p in (
            self.requests / f"{job_id}.json",
            self.running / f"{job_id}.json",
            self.results / f"{job_id}.json",
            self.cancel / job_id,
        ):
            try:
                p.unlink()
            except OSError:
                pass

    def read_heartbeat(self) -> dict[str, Any] | None:
        try:
            data = json.loads(self.heartbeat_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    def heartbeat_age(self) -> float | None:
        hb = self.read_heartbeat()
        if not hb:
            return None
        try:
            return max(0.0, time.time() - float(hb["ts"]))
        except (KeyError, TypeError, ValueError):
            return None

    # ------------------------------------------------------------ runner side
    def claim_next(self) -> tuple[str, dict[str, Any]] | None:
        """Ambil request tertua. Request rusak/mencurigakan dibuang agar tidak menyumbat antrean."""
        self.ensure_dirs()
        try:
            names = sorted(
                (p for p in self.requests.iterdir() if p.suffix == ".json"),
                key=lambda p: (p.stat().st_mtime, p.name),
            )
        except OSError:
            return None
        for path in names:
            job_id = path.stem
            if not self.id_re.match(job_id):
                self._discard(path)
                continue
            target = self.running / path.name
            try:
                os.rename(path, target)  # klaim atomik
            except OSError:
                continue
            try:
                if target.stat().st_size > self.max_request:
                    raise ValueError("request terlalu besar")
                job = json.loads(target.read_text(encoding="utf-8"))
                if not isinstance(job, dict) or job.get("job_id") != job_id:
                    raise ValueError("isi request tidak cocok")
            except (OSError, ValueError):
                self.finish(job_id, {"status": RESULT_FAILED, "error_code": "bad_request",
                                     "message": "request tidak valid"})
                continue
            return job_id, job
        return None

    def finish(self, job_id: str, result: dict[str, Any]) -> None:
        self.ensure_dirs()
        result = {**result, "job_id": job_id, "finished": time.time()}
        atomic_write_json(self.results / f"{job_id}.json", self.tmp, result)
        for p in (self.running / f"{job_id}.json", self.cancel / job_id):
            try:
                p.unlink()
            except OSError:
                pass

    def cancel_requested(self, job_id: str) -> bool:
        return (self.cancel / job_id).exists()

    def running_job_ids(self) -> list[str]:
        try:
            return [p.stem for p in self.running.iterdir() if p.suffix == ".json" and self.id_re.match(p.stem)]
        except OSError:
            return []

    def write_heartbeat(self, state: str, job_id: str | None = None) -> None:
        self.ensure_dirs()
        atomic_write_json(
            self.heartbeat_file, self.tmp,
            {"ts": time.time(), "pid": os.getpid(), "state": state, "job": job_id},
        )

    def _discard(self, path: Path) -> None:
        try:
            path.unlink()
        except OSError:
            pass
