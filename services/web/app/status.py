"""Pengumpul status sistem untuk dashboard (Redis, worker, antrean, disk)."""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

import redis
from rq import Queue
from rq.exceptions import NoSuchJobError
from rq.job import Job

HEARTBEAT_KEY = "worker:heartbeat"
RUNNER_HEARTBEAT_KEY = "runner:heartbeat"
SELFTEST_KEY = "selftest:last"
QUEUE_NAME = "jobs"
HEARTBEAT_STALE_AFTER = 30  # detik; worker mengirim tiap 10 detik dengan TTL 30


@dataclass
class Check:
    key: str
    label: str
    state: str  # ok | error | warn | pending
    detail: str


@dataclass
class SystemStatus:
    checks: list[Check] = field(default_factory=list)
    selftest_pending: bool = False

    @property
    def problems(self) -> list[Check]:
        return [c for c in self.checks if c.state in {"error", "warn"}]

    @property
    def summary(self) -> str:
        errors = [c for c in self.checks if c.state == "error"]
        warns = [c for c in self.checks if c.state == "warn"]
        if errors:
            return "Ada masalah: " + ", ".join(c.label for c in errors)
        if warns:
            return "Perlu perhatian: " + ", ".join(c.label for c in warns)
        return "Semua layanan normal"


def _fmt_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _check_redis(conn: redis.Redis) -> Check:
    start = time.perf_counter()
    try:
        conn.ping()
    except redis.RedisError as exc:
        return Check("redis", "Redis", "error", f"tidak terjangkau ({type(exc).__name__})")
    ms = (time.perf_counter() - start) * 1000
    return Check("redis", "Redis", "ok", f"terhubung ({ms:.1f} ms)")


def _check_worker(conn: redis.Redis) -> Check:
    try:
        raw = conn.get(HEARTBEAT_KEY)
    except redis.RedisError:
        return Check("worker", "Worker", "error", "tidak bisa dicek (Redis bermasalah)")
    if not raw:
        return Check("worker", "Worker", "error", "tidak ada detak jantung (heartbeat)")
    try:
        beat = json.loads(raw)
        age = max(0, int(time.time() - float(beat["ts"])))
    except (ValueError, KeyError, TypeError):
        return Check("worker", "Worker", "error", "data heartbeat tidak valid")
    if age > HEARTBEAT_STALE_AFTER:
        return Check("worker", "Worker", "error", f"terakhir terlihat {age} detik lalu")
    return Check("worker", "Worker", "ok", f"aktif (heartbeat {age} dtk lalu)")


def _check_runner(conn: redis.Redis) -> Check:
    """Runner tidak punya jaringan, jadi detak jantungnya diteruskan worker ke Redis."""
    try:
        raw = conn.get(RUNNER_HEARTBEAT_KEY)
    except redis.RedisError:
        return Check("runner", "Runner", "error", "tidak bisa dicek (Redis bermasalah)")
    if not raw:
        return Check("runner", "Runner", "error", "tidak aktif — jadx/apktool tidak bisa dijalankan")
    try:
        beat = json.loads(raw)
        age = max(0, int(time.time() - float(beat["ts"])))
    except (ValueError, KeyError, TypeError):
        return Check("runner", "Runner", "error", "data heartbeat tidak valid")
    if age > HEARTBEAT_STALE_AFTER:
        return Check("runner", "Runner", "error", f"terakhir terlihat {age} detik lalu")
    if beat.get("state") == "busy":
        return Check("runner", "Runner", "ok", "sedang memproses job")
    return Check("runner", "Runner", "ok", "siaga (tanpa jaringan)")


def _check_queue(conn: redis.Redis) -> tuple[Check, bool]:
    """Hasil uji antrean terakhir. Mengembalikan (Check, sedang_menunggu)."""
    try:
        job_id = conn.get(SELFTEST_KEY)
    except redis.RedisError:
        return Check("queue", "Antrean", "error", "tidak bisa dicek"), False
    if not job_id:
        return Check("queue", "Antrean", "pending", "belum diuji — tekan “Uji antrean”"), False
    job_id = job_id.decode() if isinstance(job_id, bytes) else job_id
    try:
        job = Job.fetch(job_id, connection=conn)
        status = job.get_status(refresh=True)
    except NoSuchJobError:
        return Check("queue", "Antrean", "pending", "hasil uji sebelumnya sudah kedaluwarsa"), False
    except redis.RedisError:
        return Check("queue", "Antrean", "error", "tidak bisa dicek"), False
    if status == "finished":
        result = job.return_value() or {}
        took = result.get("took_ms")
        suffix = f", {took} ms" if took is not None else ""
        return Check("queue", "Antrean", "ok", f"uji berhasil{suffix}"), False
    if status == "failed":
        return Check("queue", "Antrean", "error", "uji gagal — lihat log worker"), False
    return Check("queue", "Antrean", "pending", f"uji berjalan ({status})…"), True


def _check_disk(path: Path, warn_percent: int) -> Check:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return Check("disk", "Disk data", "error", f"{path} tidak bisa dibaca")
    used_pct = round(usage.used / usage.total * 100)
    detail = f"{_fmt_bytes(usage.free)} bebas dari {_fmt_bytes(usage.total)} ({used_pct}% terpakai)"
    state = "warn" if used_pct >= warn_percent else "ok"
    return Check("disk", "Disk data", state, detail)


def collect(conn: redis.Redis, data_dir: Path, disk_warn_percent: int) -> SystemStatus:
    status = SystemStatus()
    status.checks.append(Check("web", "Web", "ok", "berjalan"))
    redis_check = _check_redis(conn)
    status.checks.append(redis_check)
    if redis_check.state == "ok":
        status.checks.append(_check_worker(conn))
        status.checks.append(_check_runner(conn))
        queue_check, pending = _check_queue(conn)
        status.checks.append(queue_check)
        status.selftest_pending = pending
    else:
        # Jangan menunggu timeout berulang kali bila Redis sudah terbukti mati.
        status.checks.append(Check("worker", "Worker", "error", "tidak bisa dicek (Redis mati)"))
        status.checks.append(Check("runner", "Runner", "error", "tidak bisa dicek (Redis mati)"))
        status.checks.append(Check("queue", "Antrean", "error", "tidak bisa dicek (Redis mati)"))
    status.checks.append(_check_disk(data_dir, disk_warn_percent))
    return status


def enqueue_selftest(conn: redis.Redis) -> str:
    queue = Queue(QUEUE_NAME, connection=conn)
    job = queue.enqueue("tasks.selftest", job_timeout=30, result_ttl=600, failure_ttl=600)
    conn.set(SELFTEST_KEY, job.id, ex=3600)
    return job.id
