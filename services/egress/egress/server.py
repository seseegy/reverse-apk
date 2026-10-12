"""Proxy keluar `egress`: satu-satunya jalan dari kontainer `bench` ke internet (PRD 09, jaringan shell AI).

Hanya metode CONNECT (HTTPS). Permintaan lain (GET http://..., dll.) ditolak dengan alasan yang jelas. Isi lalu lintas tidak dibaca dan tidak dicatat;
yang dicatat hanya host, port, alamat, status, dan jumlah byte. Aturan akses ada di policy.py.
"""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from . import policy

MAX_REQUEST_LINE = 2048
MAX_HEADER_BYTES = 8192
MAX_HEADERS = 32
HEADER_TIMEOUT = 10.0
CONNECT_TIMEOUT = 10.0


@dataclass
class Config:
    allow: tuple[str, ...] = ()
    ports: frozenset[int] = frozenset({443})
    max_connections: int = 32
    max_seconds: float = 300.0
    idle_seconds: float = 60.0
    max_bytes_per_conn: int = 100 * 1024 * 1024
    max_bytes_per_hour: int = 1024 * 1024 * 1024
    allow_private_for_tests: bool = False       # HANYA untuk tes; tidak dibaca dari lingkungan


Resolver = Callable[[str, int], Awaitable[list[str]]]
Logger = Callable[[str], None]


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    out: list[str] = []
    for family, _t, _p, _c, sockaddr in infos:
        addr = sockaddr[0]
        if addr not in out:
            out.append(addr)
    return out


@dataclass
class Stats:
    active: int = 0
    window_start: float = field(default_factory=time.monotonic)
    window_bytes: int = 0

    def hour_bytes(self, now: float) -> int:
        if now - self.window_start >= 3600:
            self.window_start, self.window_bytes = now, 0
        return self.window_bytes


class Proxy:
    def __init__(self, cfg: Config, resolver: Resolver = system_resolver, log: Logger = print) -> None:
        self.cfg, self.resolve, self.log = cfg, resolver, log
        self.stats = Stats()

    # ------------------------------------------------------------------ penanganan satu klien
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            target = await asyncio.wait_for(self._read_connect(reader, writer), HEADER_TIMEOUT)
            if target is None:
                return
            host, port = target
            await self._tunnel(host, port, reader, writer, peer)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        except Exception as exc:  # noqa: BLE001 - satu klien buruk tidak boleh mematikan proxy
            self.log(f"galat internal: {type(exc).__name__}")
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _deny(self, writer: asyncio.StreamWriter, code: int, reason: str, text: str) -> None:
        body = text.encode()
        head = (f"HTTP/1.1 {code} {reason}\r\nX-Egress-Reason: {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        writer.write(head + body)
        await writer.drain()

    async def _read_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> tuple[str, int] | None:
        try:
            line = await reader.readline()
        except (ValueError, asyncio.LimitOverrunError):
            await self._deny(writer, 414, "request_line_too_long", "Baris permintaan terlalu panjang.")
            return None
        if not line or len(line) > MAX_REQUEST_LINE or not line.endswith(b"\n"):
            await self._deny(writer, 400, "bad_request", "Permintaan tidak valid.")
            return None
        total, count = len(line), 0
        while True:                                                       # baca (dan buang) header sampai baris kosong, dengan batas
            try:
                h = await reader.readline()
            except (ValueError, asyncio.LimitOverrunError):               # satu baris header melewati batas StreamReader: jawab jelas, jangan putus diam-diam
                await self._deny(writer, 431, "headers_too_large", "Header terlalu besar.")
                return None
            total += len(h)
            count += 1
            if not h or total > MAX_HEADER_BYTES or count > MAX_HEADERS:
                await self._deny(writer, 431, "headers_too_large", "Header terlalu besar.")
                return None
            if h in (b"\r\n", b"\n"):
                break
        try:
            method, target, version = line.decode("ascii").strip().split(" ")
        except (UnicodeDecodeError, ValueError):
            await self._deny(writer, 400, "bad_request", "Permintaan tidak valid.")
            return None
        if method != "CONNECT" or not version.startswith("HTTP/1."):
            self.log(f"TOLAK method={method[:16]!r} alasan=only_connect")
            await self._deny(writer, 405, "only_connect",
                             "Proxy ini hanya menerima HTTPS (CONNECT). Gunakan URL https://, bukan http://.")
            return None
        host, sep, port_s = target.rpartition(":")
        if not sep or not port_s.isascii() or not port_s.isdigit() or not host:
            await self._deny(writer, 400, "bad_target", "Target harus berbentuk host:port.")
            return None
        return host, int(port_s)

    async def _tunnel(self, host: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer) -> None:
        cfg = self.cfg
        now = time.monotonic()
        d = policy.check_target(host, port, cfg.allow, cfg.ports)
        if not d.allowed:
            return await self._refuse(writer, host, port, d.reason, peer)
        if self.stats.active >= cfg.max_connections:
            return await self._refuse(writer, host, port, "too_many_connections", peer)
        if self.stats.hour_bytes(now) >= cfg.max_bytes_per_hour:
            return await self._refuse(writer, host, port, "hourly_quota_exceeded", peer)
        ip = policy.as_ip(policy.normalize_host(host))
        try:
            addrs = [str(ip)] if ip is not None else await asyncio.wait_for(self.resolve(policy.normalize_host(host), port), CONNECT_TIMEOUT)
        except (asyncio.TimeoutError, OSError):
            return await self._refuse(writer, host, port, "dns_failed", peer)
        if not cfg.allow_private_for_tests:
            d = policy.check_addresses(addrs)
            if not d.allowed:
                return await self._refuse(writer, host, port, d.reason, peer)
        up_reader = up_writer = None
        for addr in addrs:                                                # koneksi ke ALAMAT yang sudah diperiksa, bukan ke nama (anti-rebinding)
            try:
                up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(addr, port), CONNECT_TIMEOUT)
                break
            except (asyncio.TimeoutError, OSError):
                continue
        if up_writer is None:
            return await self._refuse(writer, host, port, "connect_failed", peer, status=502)
        self.stats.active += 1
        sent = recv = 0
        started = time.monotonic()
        try:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            sent, recv = await self._splice(reader, writer, up_reader, up_writer)
        finally:
            self.stats.active -= 1
            self.stats.window_bytes += sent + recv
            try:
                up_writer.close()
            except Exception:  # noqa: BLE001
                pass
            self.log(f"IZIN host={policy.normalize_host(host)} port={port} ip={addrs[0]} naik={sent} turun={recv} detik={time.monotonic() - started:.1f}")

    async def _refuse(self, writer: asyncio.StreamWriter, host: str, port: int, reason: str, peer, status: int = 403) -> None:
        shown = policy.normalize_host(host)[:80]
        self.log(f"TOLAK host={shown!r} port={port} alasan={reason}")
        hints = {
            "network_disabled": "Jaringan untuk shell AI tidak diaktifkan (AI_SHELL_NET_ALLOW kosong).",
            "host_not_allowed": "Host ini tidak ada di daftar putih (AI_SHELL_NET_ALLOW).",
            "port_not_allowed": "Port ini tidak diizinkan.",
            "ip_literal_not_allowed": "Alamat IP mentah tidak diizinkan; gunakan nama host.",
            "private_address": "Alamat internal/privat tidak boleh dijangkau.",
            "too_many_connections": "Terlalu banyak koneksi bersamaan.",
            "hourly_quota_exceeded": "Kuota data per jam habis.",
            "dns_failed": "Nama host tidak dapat di-resolve.",
            "connect_failed": "Tidak bisa terhubung ke host tujuan.",
        }
        await self._deny(writer, status, reason, hints.get(reason, "Ditolak."))

    async def _splice(self, c_reader, c_writer, u_reader, u_writer) -> tuple[int, int]:
        cfg = self.cfg
        counts = {"up": 0, "down": 0}
        deadline = time.monotonic() + cfg.max_seconds

        async def pump(src, dst, key: str) -> None:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                data = await asyncio.wait_for(src.read(65536), min(cfg.idle_seconds, remaining))
                if not data:
                    return
                counts[key] += len(data)
                if counts["up"] + counts["down"] > cfg.max_bytes_per_conn:
                    return
                dst.write(data)
                await dst.drain()

        tasks = [asyncio.create_task(pump(c_reader, u_writer, "up")), asyncio.create_task(pump(u_reader, c_writer, "down"))]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        return counts["up"], counts["down"]


async def serve(cfg: Config, host: str = "0.0.0.0", port: int = 3128, resolver: Resolver = system_resolver, log: Logger = print) -> asyncio.AbstractServer:
    proxy = Proxy(cfg, resolver, log)
    server = await asyncio.start_server(proxy.handle, host, port, limit=MAX_REQUEST_LINE * 2)
    server.proxy = proxy                                                  # type: ignore[attr-defined]  (untuk tes)
    return server
