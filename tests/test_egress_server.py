"""Proxy keluar `egress`: SERVER dengan soket asli di loopback. Upstream palsu menjawab di 127.0.0.1, jadi pengujian memakai `allow_private_for_tests`
(satu-satunya pintu; TIDAK dibaca dari lingkungan). Tes penolakan alamat privat memakai resolver palsu TANPA pintu itu."""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "services" / "egress"))

from egress import server as S  # noqa: E402

LOGS: list[str] = []


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 30))


async def echo_upstream():
    """Upstream: membalas apa pun yang diterima dengan awalan 'ECHO:'. Kembalikan (server, port)."""
    async def h(r, w):
        try:
            while True:
                d = await r.read(65536)
                if not d:
                    break
                w.write(b"ECHO:" + d)
                await w.drain()
        finally:
            w.close()
    srv = await asyncio.start_server(h, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


async def make_proxy(cfg: S.Config, resolver=None):
    LOGS.clear()
    srv = await S.serve(cfg, "127.0.0.1", 0, resolver=resolver or S.system_resolver, log=LOGS.append)
    return srv, srv.sockets[0].getsockname()[1]


async def talk(port: int, payload: bytes, read: int = 4096, timeout: float = 5.0) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(payload)
    await w.drain()
    try:
        data = await asyncio.wait_for(r.read(read), timeout)
    except asyncio.TimeoutError:
        data = b"<timeout>"
    w.close()
    return data


def fake_dns(mapping: dict[str, list[str]]):
    async def resolve(host: str, port: int):
        if host not in mapping:
            raise OSError("NXDOMAIN")
        return mapping[host]
    return resolve


def status(resp: bytes) -> int:
    m = re.match(rb"HTTP/1\.[01] (\d{3})", resp)
    return int(m.group(1)) if m else -1


def reason(resp: bytes) -> str:
    m = re.search(rb"X-Egress-Reason: (\S+)", resp)
    return m.group(1).decode() if m else ""


def test_tunnel_relays_bytes_both_ways_for_an_allowed_host():
    async def go():
        up, up_port = await echo_upstream()
        proxy, port = await make_proxy(S.Config(allow=("api.contoh.com",), ports=frozenset({up_port}), allow_private_for_tests=True),
                                       fake_dns({"api.contoh.com": ["127.0.0.1"]}))
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(f"CONNECT api.contoh.com:{up_port} HTTP/1.1\r\nHost: api.contoh.com:{up_port}\r\n\r\n".encode())
        await w.drain()
        head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
        w.write(b"halo")
        await w.drain()
        body = await asyncio.wait_for(r.read(100), 5)
        w.close()
        await asyncio.sleep(0.2)
        up.close(); proxy.close()
        return head, body
    head, body = run(go())
    assert status(head) == 200 and body == b"ECHO:halo"
    assert any("IZIN host=api.contoh.com" in line and "naik=4" in line and "turun=9" in line for line in LOGS), LOGS


@pytest.mark.parametrize("request_line,code,why", [
    (b"GET http://api.contoh.com/ HTTP/1.1\r\nHost: api.contoh.com\r\n\r\n", 405, "only_connect"),
    (b"POST / HTTP/1.1\r\n\r\n", 405, "only_connect"),
    (b"CONNECT api.contoh.com HTTP/1.1\r\n\r\n", 400, "bad_target"),
    (b"CONNECT api.contoh.com:abc HTTP/1.1\r\n\r\n", 400, "bad_target"),
    (b"CONNECT :443 HTTP/1.1\r\n\r\n", 400, "bad_target"),
    (b"CONNECT api.contoh.com:443\r\n\r\n", 400, "bad_request"),
    (b"CONNECT a b:443 HTTP/1.1\r\n\r\n", 400, "bad_request"),
    (b"\xff\xfe CONNECT x:443 HTTP/1.1\r\n\r\n", 400, "bad_request"),
], ids=["GET-absolut", "POST", "tanpa-port", "port-bukan-angka", "host-kosong", "tanpa-versi", "spasi-ganda", "bukan-ascii"])
def test_non_connect_and_malformed_requests_are_refused_with_a_reason(request_line, code, why):
    async def go():
        proxy, port = await make_proxy(S.Config(allow=("*",)))
        resp = await talk(port, request_line)
        proxy.close()
        return resp
    resp = run(go())
    assert status(resp) == code and reason(resp) == why, resp[:120]


def test_only_connect_message_tells_the_ai_what_to_do():
    async def go():
        proxy, port = await make_proxy(S.Config(allow=("*",)))
        resp = await talk(port, b"GET http://a.com/ HTTP/1.1\r\n\r\n")
        proxy.close()
        return resp
    assert b"https://" in run(go())


def test_policy_refusals_are_403_with_distinct_reasons_and_are_logged_without_payload():
    async def go():
        proxy, port = await make_proxy(S.Config(allow=("api.contoh.com",)), fake_dns({"api.contoh.com": ["93.184.216.34"]}))
        out = {}
        for name, target in (("host", "evil.com:443"), ("port", "api.contoh.com:22"), ("ip", "10.0.0.1:443"), ("internal", "redis:443"), ("meta", "169.254.169.254:443")):
            out[name] = await talk(port, f"CONNECT {target} HTTP/1.1\r\n\r\n".encode())
        proxy.close()
        return out
    out = run(go())
    assert {k: (status(v), reason(v)) for k, v in out.items()} == {
        "host": (403, "host_not_allowed"), "port": (403, "port_not_allowed"), "ip": (403, "ip_literal_not_allowed"),
        "internal": (403, "private_address"), "meta": (403, "ip_literal_not_allowed")}
    assert sum(line.startswith(("TOLAK")) for line in LOGS) == 5


def test_disabled_network_refuses_everything():
    async def go():
        proxy, port = await make_proxy(S.Config(allow=()))
        resp = await talk(port, b"CONNECT api.contoh.com:443 HTTP/1.1\r\n\r\n")
        proxy.close()
        return resp
    resp = run(go())
    assert status(resp) == 403 and reason(resp) == "network_disabled" and "AI_SHELL_NET_ALLOW".encode() in resp


@pytest.mark.parametrize("resolved", [["10.0.0.5"], ["127.0.0.1"], ["169.254.169.254"], ["93.184.216.34", "10.0.0.5"], ["::1"], ["::ffff:10.0.0.5"], ["64:ff9b::a00:1"]],
                         ids=["privat", "loopback", "metadata", "campuran", "ipv6-loopback", "mapped", "nat64"])
def test_a_public_looking_name_that_resolves_to_a_private_address_is_refused(resolved):
    """DNS rebinding / SSRF: nama lolos daftar putih, tetapi alamat hasil resolusinya internal. TANPA pintu uji, harus ditolak."""
    async def go():
        proxy, port = await make_proxy(S.Config(allow=("*",)), fake_dns({"api.contoh.com": resolved}))
        resp = await talk(port, b"CONNECT api.contoh.com:443 HTTP/1.1\r\n\r\n")
        proxy.close()
        return resp
    resp = run(go())
    assert status(resp) == 403 and reason(resp) == "private_address", resp[:100]


def test_dns_failure_and_connect_failure_are_reported():
    async def go():
        proxy, port = await make_proxy(S.Config(allow=("*",), allow_private_for_tests=True), fake_dns({"ada.contoh.com": ["127.0.0.1"]}))
        r1 = await talk(port, b"CONNECT tidak-ada.contoh.com:443 HTTP/1.1\r\n\r\n")
        r2 = await talk(port, b"CONNECT ada.contoh.com:443 HTTP/1.1\r\n\r\n")      # 127.0.0.1:443 tidak ada yang mendengarkan
        proxy.close()
        return r1, r2
    r1, r2 = run(go())
    assert (status(r1), reason(r1)) == (403, "dns_failed") and (status(r2), reason(r2)) == (502, "connect_failed")


def test_the_connection_goes_to_the_checked_address_not_to_a_second_lookup():
    """Anti-rebinding: resolver dipanggil SEKALI per koneksi; koneksi dibuat ke alamat itu."""
    calls = []

    async def resolver(host, port):
        calls.append(host)
        return ["127.0.0.1"] if len(calls) == 1 else ["10.9.9.9"]

    async def go():
        up, up_port = await echo_upstream()
        proxy, port = await make_proxy(S.Config(allow=("api.contoh.com",), ports=frozenset({up_port}), allow_private_for_tests=True), resolver)
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(f"CONNECT api.contoh.com:{up_port} HTTP/1.1\r\n\r\n".encode())
        head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
        w.write(b"x")
        body = await asyncio.wait_for(r.read(10), 5)
        w.close(); await asyncio.sleep(0.1); up.close(); proxy.close()
        return head, body
    head, body = run(go())
    assert status(head) == 200 and body == b"ECHO:x" and len(calls) == 1


def test_oversized_headers_and_lines_are_cut_off():
    async def go():
        proxy, port = await make_proxy(S.Config(allow=("*",)))
        long_line = b"CONNECT " + b"a" * 5000 + b".com:443 HTTP/1.1\r\n\r\n"
        many = b"CONNECT a.com:443 HTTP/1.1\r\n" + b"".join(b"X-%d: y\r\n" % i for i in range(60)) + b"\r\n"
        big = b"CONNECT a.com:443 HTTP/1.1\r\nX-Besar: " + b"z" * 20000 + b"\r\n\r\n"
        res = [await talk(port, p) for p in (long_line, many, big)]
        proxy.close()
        return res
    res = run(go())
    assert [(status(r), reason(r)) for r in res] == [(414, "request_line_too_long"), (431, "headers_too_large"), (431, "headers_too_large")], [r[:60] for r in res]


def test_a_client_that_sends_nothing_does_not_hold_the_connection_forever(monkeypatch):
    monkeypatch.setattr(S, "HEADER_TIMEOUT", 0.5)

    async def go():
        proxy, port = await make_proxy(S.Config(allow=("*",)))
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"CONNECT a.com:443 HTTP/1.1\r\n")                       # tidak pernah mengirim baris kosong
        await w.drain()
        data = await asyncio.wait_for(r.read(10), 5)                      # proxy menutup koneksi
        proxy.close()
        return data
    assert run(go()) == b""


def test_connection_limit_is_enforced():
    async def go():
        up, up_port = await echo_upstream()
        proxy, port = await make_proxy(S.Config(allow=("api.contoh.com",), ports=frozenset({up_port}), max_connections=2, allow_private_for_tests=True),
                                       fake_dns({"api.contoh.com": ["127.0.0.1"]}))
        held = []
        for _ in range(2):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(f"CONNECT api.contoh.com:{up_port} HTTP/1.1\r\n\r\n".encode())
            await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
            held.append(w)
        third = await talk(port, f"CONNECT api.contoh.com:{up_port} HTTP/1.1\r\n\r\n".encode())
        for w in held:
            w.close()
        await asyncio.sleep(0.2)
        after = proxy.proxy.stats.active
        up.close(); proxy.close()
        return third, after
    third, after = run(go())
    assert status(third) == 403 and reason(third) == "too_many_connections" and after == 0, (third[:80], after)


def test_per_connection_byte_cap_closes_the_tunnel():
    async def go():
        up, up_port = await echo_upstream()
        proxy, port = await make_proxy(S.Config(allow=("api.contoh.com",), ports=frozenset({up_port}), max_bytes_per_conn=1000, allow_private_for_tests=True),
                                       fake_dns({"api.contoh.com": ["127.0.0.1"]}))
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(f"CONNECT api.contoh.com:{up_port} HTTP/1.1\r\n\r\n".encode())
        await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
        got = 0
        try:
            for _ in range(50):
                w.write(b"x" * 400)
                await w.drain()
                chunk = await asyncio.wait_for(r.read(65536), 1.0)
                if not chunk:
                    break
                got += len(chunk)
        except (asyncio.TimeoutError, ConnectionError):
            pass
        w.close(); await asyncio.sleep(0.2); up.close(); proxy.close()
        return got
    assert run(go()) < 5000, "terowongan harus ditutup setelah batas byte"


def test_hourly_quota_refuses_new_connections():
    async def go():
        proxy, port = await make_proxy(S.Config(allow=("api.contoh.com",), max_bytes_per_hour=100, allow_private_for_tests=True), fake_dns({"api.contoh.com": ["127.0.0.1"]}))
        proxy.proxy.stats.window_bytes = 100
        resp = await talk(port, b"CONNECT api.contoh.com:443 HTTP/1.1\r\n\r\n")
        proxy.close()
        return resp
    resp = run(go())
    assert status(resp) == 403 and reason(resp) == "hourly_quota_exceeded"


def test_idle_tunnel_is_closed():
    async def go():
        up, up_port = await echo_upstream()
        proxy, port = await make_proxy(S.Config(allow=("api.contoh.com",), ports=frozenset({up_port}), idle_seconds=5.0, max_seconds=5.0, allow_private_for_tests=True),
                                       fake_dns({"api.contoh.com": ["127.0.0.1"]}))
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(f"CONNECT api.contoh.com:{up_port} HTTP/1.1\r\n\r\n".encode())
        await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
        closed = await asyncio.wait_for(r.read(10), 12)                   # tidak ada lalu lintas -> ditutup oleh batas idle/durasi
        w.close(); up.close(); proxy.close()
        return closed
    assert run(go()) == b""


# ================================================================================ celah yang ditemukan mutasi
def test_bytes_that_pass_through_a_tunnel_count_toward_the_hourly_quota():
    """Kuota per jam hanya berarti bila byte benar-benar menambahnya. (Mutan: kuota tidak pernah terisi.)"""
    async def go():
        up, up_port = await echo_upstream()
        proxy, port = await make_proxy(S.Config(allow=("api.contoh.com",), ports=frozenset({up_port}), max_bytes_per_hour=100, allow_private_for_tests=True),
                                       fake_dns({"api.contoh.com": ["127.0.0.1"]}))
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(f"CONNECT api.contoh.com:{up_port} HTTP/1.1\r\n\r\n".encode())
        await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
        w.write(b"x" * 60)
        await w.drain()
        await asyncio.wait_for(r.read(200), 5)                                  # 60 naik + 65 turun = 125 > 100
        w.close()
        await asyncio.sleep(0.3)
        counted = proxy.proxy.stats.window_bytes
        second = await talk(port, f"CONNECT api.contoh.com:{up_port} HTTP/1.1\r\n\r\n".encode())
        up.close(); proxy.close()
        return counted, second
    counted, second = run(go())
    assert counted >= 100 and status(second) == 403 and reason(second) == "hourly_quota_exceeded", (counted, second[:80])


def test_the_hourly_quota_window_resets_after_an_hour():
    """Tanpa reset, satu jam pemakaian padat memblokir proxy SELAMANYA."""
    # Titik awal TETAP (terwakili tepat oleh float). Sebelumnya memakai time.monotonic() asli: pada ~0,2% nilai awal, (t0 + 3600) - t0 menjadi 3599,99999999998 sehingga
    # asersi gagal acak (terukur: 210 dari 100.000 t0 acak). Itu bug tes, bukan bug proxy.
    t0 = 1000.0
    st = S.Stats(window_start=t0)
    st.window_bytes = 999
    assert st.hour_bytes(t0 + 3599) == 999
    assert st.hour_bytes(t0 + 3600) == 0 and st.window_bytes == 0 and st.window_start == t0 + 3600


def test_tunnel_is_closed_when_the_max_duration_is_reached(monkeypatch):
    """Batas durasi diuji SENDIRI: lalu lintas terus mengalir (idle tidak pernah tercapai), tetapi terowongan tetap harus ditutup oleh durasi maksimum."""
    async def go():
        up, up_port = await echo_upstream()
        proxy, port = await make_proxy(S.Config(allow=("api.contoh.com",), ports=frozenset({up_port}), max_seconds=1.5, idle_seconds=60.0, allow_private_for_tests=True),
                                       fake_dns({"api.contoh.com": ["127.0.0.1"]}))
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(f"CONNECT api.contoh.com:{up_port} HTTP/1.1\r\n\r\n".encode())
        await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
        start = asyncio.get_running_loop().time()
        closed_after = None
        try:
            while asyncio.get_running_loop().time() - start < 8:
                w.write(b"k")
                await w.drain()
                chunk = await asyncio.wait_for(r.read(100), 2)
                if not chunk:
                    closed_after = asyncio.get_running_loop().time() - start
                    break
                await asyncio.sleep(0.2)
        except (ConnectionError, asyncio.TimeoutError):
            closed_after = asyncio.get_running_loop().time() - start
        w.close(); up.close(); proxy.close()
        return closed_after
    closed_after = run(go())
    assert closed_after is not None and closed_after < 6, "terowongan dengan lalu lintas terus-menerus harus tetap ditutup oleh batas durasi"


def test_an_overlong_request_line_is_refused_by_length_not_by_luck():
    """Baris permintaan yang melewati batas diperiksa panjangnya; bukan hanya kebetulan ditolak karena isinya tidak valid."""
    async def go():
        proxy, port = await make_proxy(S.Config(allow=("*",)))
        ok_line = b"CONNECT " + b"a" * 40 + b".com:443 HTTP/1.1\r\n\r\n"
        padded = b"CONNECT api.contoh.com:443 HTTP/1.1" + b" " * (S.MAX_REQUEST_LINE - 30) + b"\r\n\r\n"      # isi VALID di awal, hanya terlalu panjang
        r_ok = await talk(port, ok_line)
        r_long = await talk(port, padded)
        proxy.close()
        return r_ok, r_long
    r_ok, r_long = run(go())
    assert reason(r_ok) != "request_line_too_long"
    assert status(r_long) == 400 and reason(r_long) == "bad_request", r_long[:80]


@pytest.mark.parametrize("digits", ["٤٤٣", "４４３", "٤٤٣٤"])
def test_non_ascii_digits_never_become_a_real_port(digits):
    """`int('٤٤٣') == 443` dan `'٤٤٣'.isdigit()` benar. Tanpa isascii(), port digit Arab-Indic DITERIMA sebagai 443 dan terowongan terbuka. Diuji dengan host yang
    sah dan di-resolve: bila port diterima, terowongan 200 terbentuk; seharusnya ditolak SEBELUM itu."""
    async def go():
        up, up_port = await echo_upstream()
        proxy, port = await make_proxy(S.Config(allow=("api.contoh.com",), ports=frozenset({443, up_port}), allow_private_for_tests=True),
                                       fake_dns({"api.contoh.com": ["127.0.0.1"]}))
        # digit ASCII yang sama -> terowongan terbentuk (kontrol positif, memakai port upstream sungguhan)
        ok = await talk(port, f"CONNECT api.contoh.com:{up_port} HTTP/1.1\r\n\r\n".encode())
        # digit Unicode yang bernilai SAMA dengan port upstream -> harus ditolak
        shifted = str(up_port).translate({ord(str(d)): ord("٠") + d for d in range(10)})
        bad = await talk(port, f"CONNECT api.contoh.com:{shifted} HTTP/1.1\r\n\r\n".encode("utf-8"))
        up.close(); proxy.close()
        return ok, bad, shifted
    ok, bad, shifted = run(go())
    assert status(ok) == 200, "kontrol positif harus membuka terowongan"
    assert int(shifted) == int(shifted.translate({ord("٠") + d: ord(str(d)) for d in range(10)})), "prasyarat: int() memahami digit Arab-Indic"
    # Ditolak LEBIH AWAL oleh dekode ASCII baris permintaan (`bad_request`); pemeriksaan isascii() pada port adalah sabuk pengaman kedua yang tidak terjangkau dari luar.
    assert status(bad) == 400 and reason(bad) == "bad_request", (shifted, bad[:80])


@pytest.mark.parametrize("port_s", ["²", "443\u200b", "+443", "-1", "4 43", "0443x"])
def test_other_malformed_ports_are_refused(port_s):
    async def go():
        proxy, port = await make_proxy(S.Config(allow=("*",)))
        resp = await talk(port, f"CONNECT api.contoh.com:{port_s} HTTP/1.1\r\n\r\n".encode("utf-8"))
        proxy.close()
        return resp
    resp = run(go())
    assert status(resp) in (400, 403) and reason(resp) in ("bad_target", "bad_request", "port_not_allowed"), resp[:80]
