"""Kebijakan proxy keluar `egress` untuk shell AI (PRD 09, Bagian C, jaringan). Logika murni tanpa soket, supaya setiap aturan bisa diuji.

Ancaman yang dijaga (teks di dalam APK bisa membujuk AI menjalankan perintah jaringan):
  * SSRF / pivot ke jaringan internal: nama host yang di-resolve ke alamat privat, loopback, link-local (169.254.169.254 metadata cloud), CGNAT,
    multicast, atau alamat yang MEMBUNGKUS IPv4 (IPv4-mapped, NAT64, 6to4, Teredo) DITOLAK. Semua alamat hasil resolusi harus publik.
  * DNS rebinding: nama di-resolve SEKALI di sini, lalu koneksi dibuat ke ALAMAT (bukan ke nama lagi).
  * Penyalahgunaan: hanya CONNECT, hanya port yang diizinkan (bawaan 443), daftar putih host, batas koneksi paralel, durasi, byte per koneksi, dan byte per jam.
Daftar putih: nama persis, `*.contoh.com` (hanya subdomain, bukan apex), atau `*` (semua host PUBLIK). Alamat IP mentah hanya diterima pada mode `*`.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
MAX_HOST_LEN = 253

# Rentang yang secara teknis "global" menurut ipaddress tetapi tidak boleh dijangkau: mengandung/menerjemahkan IPv4 lain atau bukan alamat host biasa.
_EXTRA_DENY = tuple(ipaddress.ip_network(n) for n in (
    "64:ff9b::/96", "64:ff9b:1::/48",      # NAT64 (membungkus IPv4 apa pun, termasuk 10.0.0.0/8)
    "2002::/16",                            # 6to4
    "2001::/32",                            # Teredo
    "100.64.0.0/10",                        # CGNAT / shared address space (sering dipakai jaringan internal penyedia)
    "192.0.0.0/24", "198.18.0.0/15",        # protokol IETF / benchmarking
))


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""          # kode pendek, aman ditampilkan ke AI dan dicatat


def parse_allowlist(raw: str) -> tuple[str, ...]:
    """'a.com, *.b.com ,*' -> ('a.com', '*.b.com', '*'). Entri tidak valid DIBUANG (bukan dibuka lebar): salah ketik tidak boleh melonggarkan."""
    out: list[str] = []
    for item in (raw or "").split(","):
        item = item.strip().lower()
        if not item:
            continue
        if item.endswith("."):                  # 'api.com.' ditoleransi; tetapi '*.' (salah ketik) BUKAN '*': jangan biarkan salah ketik membuka semua
            if item in ("*.",) or item.rstrip(".") == "*":
                continue
            item = item.rstrip(".")
        if item == "*":
            out.append(item)
        elif item.startswith("*.") and valid_hostname(item[2:]):
            out.append(item)
        elif valid_hostname(item):
            out.append(item)
    return tuple(dict.fromkeys(out))


def parse_ports(raw: str, default: tuple[int, ...] = (443,)) -> frozenset[int]:
    ports = set()
    for item in (raw or "").split(","):
        item = item.strip()
        if item.isascii() and item.isdigit() and 1 <= int(item) <= 65535:
            ports.add(int(item))
    return frozenset(ports or default)


_NUMERIC_LIKE = re.compile(r"^(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+))*$")
_SPECIAL_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "broadcasthost", "metadata", "metadata.google.internal"})
_INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home", ".corp", ".intranet", ".home.arpa", ".in-addr.arpa", ".ip6.arpa")


def looks_internal(host: str) -> bool:
    """Nama yang jelas merujuk ke mesin lokal/internal, atau bentuk IPv4 gaya lama (`127.1`, `0x7f.1`, `2130706433`) yang tidak di-parse `ipaddress`
    tetapi dipahami libc sebagai alamat. Ditolak SEBELUM DNS; pemeriksaan alamat setelah DNS tetap berlaku sebagai lapis kedua."""
    h = normalize_host(host)
    return h in _SPECIAL_NAMES or h.endswith(_INTERNAL_SUFFIXES) or bool(_NUMERIC_LIKE.match(h)) or "." not in h


def valid_hostname(host: str) -> bool:
    if not host or len(host) > MAX_HOST_LEN or host.endswith("."):
        return False
    labels = host.split(".")
    return all(_LABEL.match(label) for label in labels) and len(labels) >= 1


def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    h = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        return None


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True hanya untuk alamat yang aman dijangkau dari internet publik. Alamat yang membungkus IPv4 dinilai berdasarkan IPv4 di dalamnya."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_public_ip(ip.ipv4_mapped)
        if getattr(ip, "sixtofour", None) is not None or getattr(ip, "teredo", None) is not None:
            return False
    if not ip.is_global or ip.is_multicast:
        return False
    return not any(ip in net for net in _EXTRA_DENY if net.version == ip.version)


def host_allowed(host: str, allow: tuple[str, ...]) -> bool:
    if not allow:
        return False
    if "*" in allow:
        return True
    h = normalize_host(host)
    for rule in allow:
        if rule.startswith("*."):
            if h.endswith(rule[1:]) and len(h) > len(rule) - 1:       # subdomain saja; 'contoh.com' sendiri TIDAK cocok dengan '*.contoh.com'
                return True
        elif h == rule:
            return True
    return False


def check_target(host: str, port: int, allow: tuple[str, ...], ports: frozenset[int]) -> Decision:
    """Keputusan SEBELUM resolusi DNS (murah). Alamat hasil resolusi diperiksa terpisah oleh `check_addresses`."""
    if not allow:
        return Decision(False, "network_disabled")
    if not isinstance(port, int) or isinstance(port, bool) or port not in ports:
        return Decision(False, "port_not_allowed")
    h = normalize_host(host)
    ip = as_ip(h)
    if ip is not None:
        if "*" not in allow:
            return Decision(False, "ip_literal_not_allowed")
        return Decision(True) if is_public_ip(ip) else Decision(False, "private_address")
    if not valid_hostname(h):
        return Decision(False, "bad_host")
    if looks_internal(h):
        return Decision(False, "private_address")
    if not host_allowed(h, allow):
        return Decision(False, "host_not_allowed")
    return Decision(True)


def check_addresses(addrs: list[str]) -> Decision:
    """SEMUA alamat hasil resolusi harus publik. Satu saja yang privat = tolak (jawaban DNS campuran adalah ciri serangan rebinding)."""
    if not addrs:
        return Decision(False, "no_address")
    for a in addrs:
        ip = as_ip(a)
        if ip is None or not is_public_ip(ip):
            return Decision(False, "private_address")
    return Decision(True)
