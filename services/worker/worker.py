"""Worker RQ (M0): menjalankan antrean `jobs` dan mengirim heartbeat ke Redis.

Pada M1+ worker ini yang mengorkestrasi pipeline dekompilasi. Alat berat (jadx, apktool)
sengaja TIDAK ada di image ini; mereka berjalan di image `runner` yang terisolasi.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from urllib.parse import quote

import redis
from rq import Queue, Worker

HEARTBEAT_KEY = "worker:heartbeat"
HEARTBEAT_EVERY = 10  # detik
HEARTBEAT_TTL = 30  # detik; web menganggap worker mati bila lebih lama dari ini
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
    while not stop.is_set():
        try:
            conn.set(HEARTBEAT_KEY, json.dumps({**payload_base, "ts": time.time()}), ex=HEARTBEAT_TTL)
        except redis.RedisError as exc:
            log.warning("heartbeat gagal: %s", type(exc).__name__)
        stop.wait(HEARTBEAT_EVERY)


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
