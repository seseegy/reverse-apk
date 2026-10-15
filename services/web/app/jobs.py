"""Mengantrekan analisis ke worker (RQ)."""

from __future__ import annotations

import uuid

import redis
from rq import Queue

from .status import QUEUE_NAME


def enqueue_analysis(conn: redis.Redis, analysis_id: int, job_timeout: int, only_stage: str | None = None) -> str:
    """Kirim `tasks.run_analysis(analysis_id)` ke worker.

    Worker mengklaim analisis lewat compare-and-set di DB (queued -> running), jadi pengiriman ganda
    atau job yang sudah dibatalkan tidak berbahaya: job yang kalah klaim langsung selesai tanpa kerja.
    """
    queue = Queue(QUEUE_NAME, connection=conn)
    job = queue.enqueue(
        "tasks.run_analysis",
        analysis_id,
        only_stage,
        job_id=f"analysis-{int(analysis_id)}-{uuid.uuid4().hex[:8]}",
        job_timeout=job_timeout,
        result_ttl=300,
        failure_ttl=86400,
    )
    return job.id


def enqueue_build(conn: redis.Redis, build_id: int, job_timeout: int) -> str:
    """Kirim `tasks.run_build(build_id)` ke worker (antrean `jobs` yang sama dengan analisis; build mengantre FIFO di belakangnya).

    Worker mengklaim build lewat compare-and-set (queued -> building), jadi job ganda atau job untuk build yang sudah dibatalkan tidak berbahaya.
    Awalan `build-<id>-` dipakai `approve` (idempoten) dan `worker.builds.requeue_orphans` untuk mengenali build yang sudah punya job."""
    queue = Queue(QUEUE_NAME, connection=conn)
    job = queue.enqueue(
        "tasks.run_build",
        int(build_id),
        job_id=f"build-{int(build_id)}-{uuid.uuid4().hex[:8]}",
        job_timeout=job_timeout,
        result_ttl=300,
        failure_ttl=86400,
    )
    return job.id
