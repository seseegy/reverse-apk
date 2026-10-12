"""`bench/netprobe.py` (probe jaringan untuk bench-selftest) diuji terhadap soket NYATA dan proxy `egress` NYATA di loopback, supaya pembaca jawabannya terbukti cocok
dengan format jawaban proxy dan daftar `DENY_TARGETS` terbukti benar-benar ditolak (bukan sekadar kita ASUMSIKAN ditolak)."""

from __future__ import annotations

import asyncio
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "services" / "bench"))
sys.path.insert(0, str(ROOT / "services" / "egress"))

from bench import netprobe as NP  # noqa: E402
from egress import server as S  # noqa: E402


def free_closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_direct_reports_connected_and_the_errno_name():
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        assert NP.direct("127.0.0.1", srv.getsockname()[1]) == "CONNECTED"
    assert NP.direct("127.0.0.1", free_closed_port()) == "ERRNO ECONNREFUSED"


def test_resolve_reports_the_address_or_nxdomain():
    assert NP.resolve("localhost").startswith("RESOLVED ")
    assert NP.resolve("nama-yang-tidak-ada.invalid") == "NXDOMAIN"


def test_connect_without_a_proxy_is_reported_as_noproxy():
    assert NP.connect("127.0.0.1", free_closed_port(), "x.com:443").startswith("NOPROXY")


def _with_proxy(cfg: S.Config, fn):
    async def go():
        srv = await S.serve(cfg, "127.0.0.1", 0, log=lambda m: None)
        port = srv.sockets[0].getsockname()[1]
        try:
            return await asyncio.wait_for(asyncio.to_thread(fn, port), 40)      # probe memakai soket sinkron: jalankan di thread agar loop proxy tetap hidup
        finally:
            srv.close()
            await srv.wait_closed()
    return asyncio.run(go())


def test_every_deny_target_is_refused_with_403_even_when_everything_is_allowed():
    def fn(port):
        return {t: NP.connect("127.0.0.1", port, t.replace("{proxy}", f"egress:{port}")) for t in NP.DENY_TARGETS}
    out = _with_proxy(S.Config(allow=("*",), ports=frozenset({443, 6379, 8000})), fn)
    assert set(out) == set(NP.DENY_TARGETS)
    for target, got in out.items():
        assert got.startswith("STATUS 403 REASON ") and got.split()[-1], (target, got)


def test_with_an_empty_allowlist_everything_is_refused_as_network_disabled():
    out = _with_proxy(S.Config(allow=(), ports=frozenset({443})), lambda port: NP.connect("127.0.0.1", port, "api.contoh.com:443"))
    assert out == "STATUS 403 REASON network_disabled"


def test_a_host_outside_the_allowlist_is_refused():
    out = _with_proxy(S.Config(allow=("api.contoh.com",), ports=frozenset({443})), lambda port: NP.connect("127.0.0.1", port, "lain.contoh.net:443"))
    assert out == "STATUS 403 REASON host_not_allowed"


def test_an_allowed_tunnel_is_reported_as_200():
    async def go():
        async def h(r, w):
            w.close()
        up = await asyncio.start_server(h, "127.0.0.1", 0)
        up_port = up.sockets[0].getsockname()[1]
        proxy = await S.serve(S.Config(allow=("api.contoh.com",), ports=frozenset({up_port}), allow_private_for_tests=True), "127.0.0.1", 0,
                              resolver=lambda host, port: _fixed(["127.0.0.1"]), log=lambda m: None)
        port = proxy.sockets[0].getsockname()[1]
        try:
            return await asyncio.wait_for(asyncio.to_thread(NP.connect, "127.0.0.1", port, f"api.contoh.com:{up_port}"), 20)
        finally:
            proxy.close()
            up.close()
    assert asyncio.run(go()) == "STATUS 200 REASON "


async def _fixed(addrs):
    return addrs


@pytest.mark.parametrize("argv,code", [([], 2), (["direct"], 2), (["direct", "h"], 2), (["resolve"], 2), (["connect", "a", "1"], 2), (["lain"], 2)])
def test_bad_arguments_exit_with_usage(argv, code, capsys):
    assert NP.main(argv) == code and "pemakaian" in capsys.readouterr().err


def test_main_prints_one_line(capsys):
    assert NP.main(["resolve", "nama-yang-tidak-ada.invalid"]) == 0
    assert capsys.readouterr().out == "NXDOMAIN\n"


def test_a_timeout_is_reported_as_timeout_not_as_a_connection(monkeypatch):
    def slow(*a, **k):
        raise socket.timeout("timed out")
    monkeypatch.setattr(NP.socket, "create_connection", slow)
    assert NP.direct("10.255.255.1", 443) == "ERRNO TIMEOUT"


def test_the_deny_list_keeps_the_critical_targets():
    """Daftar ini adalah BUKTI selftest bagi pemilik; tidak boleh menyusut diam-diam."""
    must = {"169.254.169.254:443": "metadata cloud", "127.0.0.1:443": "loopback", "localhost:443": "loopback (nama)", "[::1]:443": "loopback IPv6",
            "10.0.0.1:443": "alamat privat", "redis:6379": "layanan Docker lain (Redis)", "web:8000": "layanan Docker lain (web)", "{proxy}": "proxy sendiri",
            "metadata.google.internal:443": "metadata cloud (nama)", "2130706433:443": "IPv4 gaya lama"}
    for target, why in must.items():
        assert target in NP.DENY_TARGETS, f"{target} ({why}) hilang dari DENY_TARGETS"
    assert len(NP.DENY_TARGETS) == len(set(NP.DENY_TARGETS))
