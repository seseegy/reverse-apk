"""Healthcheck container worker: sehat bila heartbeat masih ada di Redis."""

import sys

import redis

from worker import HEARTBEAT_KEY, redis_url

try:
    conn = redis.Redis.from_url(redis_url(), socket_connect_timeout=3, socket_timeout=3)
    sys.exit(0 if conn.exists(HEARTBEAT_KEY) else 1)
except Exception:  # noqa: BLE001 - healthcheck: apa pun yang salah berarti tidak sehat
    sys.exit(1)
