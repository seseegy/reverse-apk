"""Tugas yang bisa dijalankan worker. Diimpor RQ lewat nama bertitik, mis. `tasks.selftest`."""

from __future__ import annotations

import socket
from datetime import datetime, timezone

from rq import get_current_job


def selftest() -> dict:
    """Tugas uji: membuktikan web → Redis → worker → hasil kembali ke web berfungsi."""
    job = get_current_job()
    took_ms = None
    if job is not None and job.enqueued_at is not None:
        enq = job.enqueued_at
        if enq.tzinfo is None:
            enq = enq.replace(tzinfo=timezone.utc)
        took_ms = round((datetime.now(timezone.utc) - enq).total_seconds() * 1000)
    return {"pong": True, "took_ms": took_ms, "worker": socket.gethostname()}
