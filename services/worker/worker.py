"""Worker RQ: menjalankan antrean `jobs`, mengorkestrasi pipeline, dan mengirim heartbeat ke Redis.

Alat berat (jadx, apktool) sengaja TIDAK ada di image ini; mereka berjalan di service `runner`
yang terisolasi (tanpa jaringan). Worker hanya menitipkan job lewat spool berkas (rvcore/spool.py).
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
import uuid
from urllib.parse import quote

import redis
from rq import Queue, Worker

from rvcore import store
from rvcore.db import connect, migrate
from rvcore.paths import Layout
from rvcore.spool import Spool

HEARTBEAT_KEY = "worker:heartbeat"
RUNNER_HEARTBEAT_KEY = "runner:heartbeat"
HEARTBEAT_EVERY = 10  # detik
HEARTBEAT_TTL = 30  # detik; web menganggap worker mati bila lebih lama dari ini
RUNNER_FRESH_WITHIN = 30  # detik; heartbeat runner yang lebih tua dari ini tidak diteruskan
QUEUE_NAME = "jobs"

log = logging.getLogger("reverse-apk.worker")


def redis_url() -> str:
    url = os.environ.get("REDIS_URL")
    if url:
        return url
    host = os.environ.get("REDIS_HOST", "redis")
    port = os.environ.get("REDIS_PORT", "6379")
    password = os.environ.get("REDIS_PASSWORD", "")
    auth = f":{quote(password, safe='')}@" if password else ""
    return f"redis://{auth}{host}:{port}/0"


def heartbeat_loop(conn: redis.Redis, stop: threading.Event) -> None:
    payload_base = {"host": socket.gethostname(), "pid": os.getpid()}
    spool = Spool(Layout(os.environ.get("DATA_DIR", "/data")).spool)
    while not stop.is_set():
        try:
            conn.set(HEARTBEAT_KEY, json.dumps({**payload_base, "ts": time.time()}), ex=HEARTBEAT_TTL)
            # Runner tanpa jaringan: detak jantungnya (berkas di spool) diteruskan ke Redis agar web bisa melihatnya.
            age = spool.heartbeat_age()
            beat = spool.read_heartbeat()
            if beat is not None and age is not None and age <= RUNNER_FRESH_WITHIN:
                conn.set(RUNNER_HEARTBEAT_KEY, json.dumps(beat), ex=HEARTBEAT_TTL)
        except redis.RedisError as exc:
            log.warning("heartbeat gagal: %s", type(exc).__name__)
        except Exception:  # noqa: BLE001 - heartbeat tidak boleh mematikan worker
            log.exception("heartbeat: galat tak terduga")
        stop.wait(HEARTBEAT_EVERY)


def requeue_orphans(conn: redis.Redis) -> list[int]:
    """Analisis berstatus 'queued' di DB tetapi tidak punya job di antrean (mis. Redis dikosongkan) dikirim ulang.
    Aman terhadap duplikat: worker mengklaim analisis lewat compare-and-set."""
    layout = Layout(os.environ.get("DATA_DIR", "/data"))
    timeout = int(os.environ.get("JOB_TIMEOUT", "2700") or 2700)
    queue = Queue(QUEUE_NAME, connection=conn)
    waiting = set(queue.job_ids)
    db = connect(layout.db_path)
    try:
        ids = store.queued_analysis_ids(db)
    finally:
        db.close()
    requeued = []
    for analysis_id in ids:
        if any(job_id.startswith(f"analysis-{analysis_id}-") for job_id in waiting):
            continue
        queue.enqueue(
            "tasks.run_analysis", analysis_id,
            job_id=f"analysis-{analysis_id}-{uuid.uuid4().hex[:8]}",
            job_timeout=timeout, result_ttl=300, failure_ttl=86400,
        )
        requeued.append(analysis_id)
    return requeued


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    conn = redis.Redis.from_url(redis_url(), socket_connect_timeout=5, health_check_interval=30)

    # Tunggu Redis siap (compose sudah menunggu healthcheck, ini sabuk pengaman).
    for attempt in range(1, 31):
        try:
            conn.ping()
            break
        except redis.RedisError:
            log.info("menunggu Redis… (%s/30)", attempt)
            time.sleep(2)
    else:
        raise SystemExit("Redis tidak terjangkau")

    # Pemulihan setelah restart (NFR-2.3): job 'running' yang terputus ditandai gagal, job yatim dikirim ulang.
    import pipeline

    layout = Layout(os.environ.get("DATA_DIR", "/data"))
    migrate(layout.db_path)
    interrupted = pipeline.reconcile()
    if interrupted:
        log.warning("analisis terputus oleh restart, ditandai gagal: %s", interrupted)
    requeued = requeue_orphans(conn)
    if requeued:
        log.info("analisis antre tanpa job di Redis, dikirim ulang: %s", requeued)

    stop = threading.Event()
    threading.Thread(target=heartbeat_loop, args=(conn, stop), daemon=True).start()

    worker = Worker([Queue(QUEUE_NAME, connection=conn)], connection=conn)
    log.info("worker siap, mendengarkan antrean '%s'", QUEUE_NAME)
    try:
        worker.work(with_scheduler=False)
    finally:
        stop.set()


if __name__ == "__main__":
    main()
