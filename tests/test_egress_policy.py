"""Proxy keluar `egress` (jaringan shell AI): KEBIJAKAN. Logika murni, tanpa soket. Inilah yang mencegah SSRF ke jaringan internal / metadata cloud dan
penyalahgunaan; tiap aturan diuji sendiri."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "services" / "egress"))

from egress import policy as P  # noqa: E402

PORTS = frozenset({443})
ALLOW = ("api.contoh.com", "*.cdn.contoh.com")


# ================================================================================ alamat
@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.255.255.254", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "169.254.0.1", "0.0.0.0",
    "100.64.0.1", "100.127.255.254", "224.0.0.1", "255.255.255.255", "192.0.0.1", "198.18.0.1", "198.19.255.255", "192.0.2.1", "198.51.100.1", "203.0.113.1",
    "::1", "::", "fe80::1", "fc00::1", "fd00::1", "ff02::1",
    "::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:192.168.0.1",
    "64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "2002:a00:1::", "2002:7f00:1::", "2001:0:a00:1::",
], ids=lambda v: v)
def test_non_public_addresses_are_refused(ip):
    assert not P.is_public_ip(ipaddress.ip_address(ip)), ip


@pytest.mark.parametrize("ip", ["1.1.1.1", "8.8.8.8", "93.184.216.34", "142.250.80.46", "2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8"])
def test_public_addresses_are_accepted(ip):
    assert P.is_public_ip(ipaddress.ip_address(ip)), ip


def test_check_addresses_requires_every_resolved_address_to_be_public():
    """Jawaban DNS campuran (satu publik, satu privat) adalah ciri rebinding: ditolak seluruhnya."""
    assert P.check_addresses(["93.184.216.34", "2606:4700:4700::1111"]).allowed
    for mixed in (["93.184.216.34", "10.0.0.5"], ["10.0.0.5", "93.184.216.34"], ["169.254.169.254"], ["::ffff:10.0.0.5"]):
        d = P.check_addresses(mixed)
        assert not d.allowed and d.reason == "private_address", mixed
    assert P.check_addresses([]).reason == "no_address"
    assert P.check_addresses(["bukan-ip"]).reason == "private_address"


# ================================================================================ daftar putih
def test_exact_and_wildcard_rules():
    assert P.host_allowed("api.contoh.com", ALLOW) and P.host_allowed("API.Contoh.COM.", ALLOW)
    assert P.host_allowed("a.cdn.contoh.com", ALLOW) and P.host_allowed("x.y.cdn.contoh.com", ALLOW)
    for no in ("contoh.com", "cdn.contoh.com", "evilapi.contoh.com", "api.contoh.com.evil.com", "xcdn.contoh.com", "api-contoh.com", "contoh.com.api.contoh.com.evil.id", ""):
        assert not P.host_allowed(no, ALLOW), no


def test_wildcard_subdomain_rule_does_not_match_the_apex_or_lookalikes():
    assert not P.host_allowed("cdn.contoh.com", ("*.cdn.contoh.com",))
    assert not P.host_allowed("notcdn.contoh.com", ("*.cdn.contoh.com",))
    assert not P.host_allowed("cdn.contoh.com.evil.com", ("*.cdn.contoh.com",))


def test_star_means_any_name_and_empty_means_nothing():
    assert P.host_allowed("apa.saja.id", ("*",))
    assert not P.host_allowed("api.contoh.com", ())


def test_allowlist_parsing_drops_invalid_entries_instead_of_widening():
    assert P.parse_allowlist(" API.contoh.com , *.cdn.contoh.com,, *, *.,  ,a b,.com,-x.com, x..com , ok.id.") == ("api.contoh.com", "*.cdn.contoh.com", "*", "ok.id")
    assert P.parse_allowlist("") == () and P.parse_allowlist("***, *.*.com, *x.com, http://a.com, a.com/x, a.com:443") == ()
    assert P.parse_allowlist("a.com, a.com, A.COM") == ("a.com",)


def test_ports_parsing():
    assert P.parse_ports("443, 8443 ,abc,0,70000,-1,٤٤٣") == frozenset({443, 8443})
    assert P.parse_ports("") == frozenset({443}) and P.parse_ports("x,y") == frozenset({443})


# ================================================================================ keputusan sebelum DNS
def test_network_disabled_when_allowlist_is_empty():
    d = P.check_target("api.contoh.com", 443, (), PORTS)
    assert not d.allowed and d.reason == "network_disabled"


@pytest.mark.parametrize("port", [0, 22, 80, 3306, 6379, 8000, 65535, -1, True, None, "443"])
def test_only_allowed_ports(port):
    d = P.check_target("api.contoh.com", port, ALLOW, PORTS)
    assert not d.allowed and d.reason == "port_not_allowed"


def test_allowed_target_passes_pre_dns_check():
    assert P.check_target("api.contoh.com", 443, ALLOW, PORTS).allowed
    assert P.check_target("x.cdn.contoh.com", 8443, ALLOW, frozenset({443, 8443})).allowed


@pytest.mark.parametrize("host,reason", [
    ("evil.com", "host_not_allowed"), ("contoh.com", "host_not_allowed"),
    # nama internal/tanpa titik ditolak lebih awal sebagai private_address (sebelum daftar putih dinilai)
    ("localhost", "private_address"), ("metadata.google.internal", "private_address"), ("egress", "private_address"), ("web", "private_address"), ("redis", "private_address"),
    ("10.0.0.1", "ip_literal_not_allowed"), ("1.1.1.1", "ip_literal_not_allowed"), ("[::1]", "ip_literal_not_allowed"), ("169.254.169.254", "ip_literal_not_allowed"),
])
def test_specific_allowlist_refuses_everything_else_including_ip_literals(host, reason):
    d = P.check_target(host, 443, ALLOW, PORTS)
    assert not d.allowed and d.reason == reason, (host, d)


@pytest.mark.parametrize("host", ["10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.0.1", "[::1]", "::1", "0.0.0.0", "100.64.0.1", "::ffff:10.0.0.1", "[::ffff:127.0.0.1]", "64:ff9b::a00:1"])
def test_star_mode_still_refuses_private_ip_literals(host):
    d = P.check_target(host, 443, ("*",), PORTS)
    assert not d.allowed and d.reason == "private_address", host


def test_star_mode_accepts_public_ip_literals_and_names():
    assert P.check_target("1.1.1.1", 443, ("*",), PORTS).allowed and P.check_target("[2606:4700:4700::1111]", 443, ("*",), PORTS).allowed
    assert P.check_target("api.apa-saja.id", 443, ("*",), PORTS).allowed


@pytest.mark.parametrize("host", ["", " ", "a b.com", "a_b.com", "-a.com", "a-.com", "a..com", "a.com/x", "a.com\r\nHost: x", "a.com\x00", "ａ.com", "a" * 64 + ".com",
                                  ("a" * 60 + ".") * 5 + "com", "user@a.com", "a.com:80", "http://a.com", "a.com#"])
def test_malformed_hosts_are_refused_even_in_star_mode(host):
    d = P.check_target(host, 443, ("*",), PORTS)
    assert not d.allowed, repr(host)


def test_trailing_dot_and_case_are_normalised_before_matching():
    assert P.check_target("API.CONTOH.COM.", 443, ALLOW, PORTS).allowed
    assert P.normalize_host(" A.B. ") == "a.b"


def test_hostname_validation_edges():
    assert P.valid_hostname("a.b.c") and P.valid_hostname("xn--bcher-kva.example") and P.valid_hostname("localhost") and P.valid_hostname("a-b.c1")
    assert not P.valid_hostname("") and not P.valid_hostname("a.") and not P.valid_hostname("a" * 254) and not P.valid_hostname("a.b..c")


# ================================================================================ temuan saat pemeriksaan langsung (regresi)
@pytest.mark.parametrize("raw", ["*.", "*..", " *. ", "a.com,*.", "*.,*.*.com"])
def test_a_mistyped_star_never_becomes_the_open_star(raw):
    """Regresi: `rstrip('.')` mengubah '*.' (salah ketik) menjadi '*' = IZINKAN SEMUA HOST. Salah ketik harus MEMPERSEMPIT, bukan membuka."""
    assert "*" not in P.parse_allowlist(raw), raw


def test_a_correct_star_and_trailing_dot_hosts_still_work():
    assert P.parse_allowlist("*") == ("*",) and P.parse_allowlist("a.com.") == ("a.com",) and P.parse_allowlist("a.com., *") == ("a.com", "*")


@pytest.mark.parametrize("host", ["0x7f.1", "0x7f000001", "2130706433", "017700000001", "127.1", "10.1", "0300.0250.0.1", "1.2.3", "4294967295",
                                  "localhost", "LOCALHOST.", "localhost.localdomain", "ip6-localhost", "metadata.google.internal", "metadata",
                                  "svc.internal", "host.local", "app.localhost", "router.lan", "x.corp", "1.0.0.127.in-addr.arpa",
                                  "egress", "web", "redis", "caddy", "bench", "worker", "runner"])
def test_internal_names_and_oldstyle_ip_forms_are_refused_before_dns_even_in_star_mode(host):
    """IPv4 gaya lama dipahami libc tetapi TIDAK di-parse `ipaddress`; nama tanpa titik adalah nama kontainer di DNS Docker. Jangan bergantung pada pemeriksaan
    setelah DNS saja."""
    d = P.check_target(host, 443, ("*",), PORTS)
    assert not d.allowed and d.reason == "private_address", (host, d)


@pytest.mark.parametrize("host", ["api.contoh.com", "a.b", "xn--bcher-kva.example", "x1.y2.id", "internal.example.com", "local.example.com", "my-intranet.com"])
def test_ordinary_public_names_are_not_caught_by_the_internal_name_filter(host):
    assert P.check_target(host, 443, ("*",), PORTS).allowed, host


def test_looks_internal_is_about_names_only():
    assert P.looks_internal("localhost") and P.looks_internal("web") and P.looks_internal("0x7f.1")
    assert not P.looks_internal("example.com") and not P.looks_internal("a.io")


# ================================================================================ tiap lapis diuji SENDIRI (is_global sengaja dibuat "salah")
def test_the_extra_deny_list_covers_what_is_global_misses():
    nat64 = ipaddress.ip_address("64:ff9b::a00:1")
    assert nat64.is_global, "prasyarat: Python menganggap NAT64 'global' (itulah alasan aturan tambahan ada)"
    assert not P.is_public_ip(nat64)


def test_ipv4_mapped_addresses_are_judged_by_the_embedded_ipv4(monkeypatch):
    """Lapis pembukaan IPv4-mapped diuji sendiri: bila is_global (di versi Python lain) menyebut ::ffff:10.0.0.1 'global', pembukaan ini yang menolaknya."""
    seen = []
    real_fn = P.is_public_ip

    def spy(ip):
        seen.append(str(ip))
        return real_fn(ip)
    monkeypatch.setattr(P, "is_public_ip", spy)
    assert not P.is_public_ip(ipaddress.ip_address("::ffff:10.0.0.1"))
    assert "10.0.0.1" in seen, "alamat IPv4 di dalam harus dinilai ulang sendiri"
    seen.clear()
    assert P.is_public_ip(ipaddress.ip_address("::ffff:8.8.8.8")) and "8.8.8.8" in seen


@pytest.mark.parametrize("ip", ["2002:a00:1::", "2001:0:a00:1::"])
def test_6to4_and_teredo_are_refused_by_their_own_attribute_check(ip, monkeypatch):
    """Dua lapis menjaga ini: rentang _EXTRA_DENY dan pemeriksaan atribut sixtofour/teredo. Rentang dimatikan di sini agar lapis atribut diuji SENDIRIAN
    (is_global dipaksa True, seperti perilaku Python yang berbeda)."""
    monkeypatch.setattr(P, "_EXTRA_DENY", tuple(n for n in P._EXTRA_DENY if n.version == 4))

    class Fake(ipaddress.IPv6Address):
        is_global = property(lambda self: True)
    f = Fake(ip)
    assert f.is_global and (f.sixtofour is not None or f.teredo is not None)
    assert not P.is_public_ip(f), ip


@pytest.mark.parametrize("ip", ["2002:a00:1::", "2001:0:a00:1::"])
def test_6to4_and_teredo_are_refused_by_the_range_alone(ip, monkeypatch):
    """Lapis rentang diuji SENDIRIAN: pemeriksaan atribut dimatikan lewat objek tanpa sixtofour/teredo."""
    class Plain(ipaddress.IPv6Address):
        is_global = property(lambda self: True)
        sixtofour = property(lambda self: None)
        teredo = property(lambda self: None)
    assert not P.is_public_ip(Plain(ip)), ip


def test_cgnat_is_refused_by_the_explicit_range_even_if_is_global_says_yes():
    class Fake(ipaddress.IPv4Address):
        is_global = property(lambda self: True)
    f = Fake("100.64.0.1")
    assert f.is_global and not P.is_public_ip(f)


def test_bool_is_not_a_valid_port_even_if_the_set_contains_one():
    """`True == 1` dan `True in {1}`: tanpa pemeriksaan tipe, True lolos bila port 1 ada di himpunan."""
    d = P.check_target("api.contoh.com", True, ALLOW, frozenset({1, 443}))
    assert not d.allowed and d.reason == "port_not_allowed"
    assert P.check_target("api.contoh.com", 1, ALLOW, frozenset({1, 443})).allowed
