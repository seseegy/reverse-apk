"""Jaringan untuk shell AI, sisi BENCH dan WEB: variabel proxy, kunci TCP Landlock (ABI >= 4), gagal tertutup, konfigurasi, prompt, dan compose.
Sandbox pengembangan memakai Landlock ABI v2, jadi pengunci TCP diuji lewat simulasi syscall; bukti nyata ada di `make bench-selftest` di server."""

from __future__ import annotations

import ctypes
import json
import os
import re
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "services" / "bench"))

from app.ai import agent  # noqa: E402
from app.ai.config import _net_allow, _net_ports, load_ai_config  # noqa: E402
from bench import executor as E  # noqa: E402
from bench import landlock as LL  # noqa: E402
from bench import policy as P  # noqa: E402

sys.path.insert(0, str(ROOT / "services" / "egress"))
from egress import policy as EP  # noqa: E402

SHA = "a" * 64
DIRS = P.Dirs(Path("/data"))


# ================================================================================ variabel proxy di lingkungan perintah
def test_no_proxy_variables_without_network():
    env = P.env_for(DIRS, 1, SHA, Path("/tmp/j"), "s1-x")
    assert not [k for k in env if "proxy" in k.lower()]


def test_proxy_variables_when_network_is_on():
    env = P.env_for(DIRS, 1, SHA, Path("/tmp/j"), "s1-x", proxy="http://egress:3128")
    for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "ALL_PROXY", "all_proxy"):
        assert env[k] == "http://egress:3128", k
    assert env["NO_PROXY"] == "" and env["no_proxy"] == "", "NO_PROXY harus kosong: tidak ada host yang dikecualikan dari proxy"
    assert not [k for k in env if any(t in k for t in ("KEY", "SECRET", "TOKEN", "PASSWORD", "REDIS"))]


def test_net_config_url():
    assert E.NetConfig("egress", 3128).url == "http://egress:3128"


# ================================================================================ pengunci TCP Landlock (disimulasikan)
class FakeSys:
    """Pengganti syscall: mencatat panggilan, dan memungkinkan memaksa kegagalan."""

    def __init__(self, abi=4, fail_on=None):
        self.abi, self.fail_on, self.calls = abi, fail_on, []

    def __call__(self, num, *args):
        self.calls.append((num, args))
        if num == LL.SYS_CREATE:
            if args[2] & LL.CREATE_VERSION:
                return self.abi
            return os.open("/dev/null", os.O_RDONLY)                 # fd NYATA: Confinement menutupnya sendiri saat gagal
        if self.fail_on and num == self.fail_on:
            ctypes.set_errno(22)
            return -1
        return 0


def rule_bytes(call):
    num, args = call
    return ctypes.string_at(args[2], 16 if args[1] == LL.RULE_NET_PORT else 12)


def test_kernel_abi_constants_are_pinned_to_the_linux_uapi_values():
    """Angka literal dari <linux/landlock.h> dan tabel syscall — BUKAN dari modul yang diuji (tes lain memakai konstanta modul sehingga salah nilai tak terdeteksi).
    Salah satu angka ini keliru = kernel menolak/menafsirkan aturan lain, jadi kunci TCP bisa diam-diam tidak berlaku."""
    assert (LL.SYS_CREATE, LL.SYS_ADD, LL.SYS_RESTRICT) == (444, 445, 446)
    assert LL.CREATE_VERSION == 1
    assert LL.RULE_PATH_BENEATH == 1 and LL.RULE_NET_PORT == 2
    assert LL.NET_BIND_TCP == 1 and LL.NET_CONNECT_TCP == 2


def test_connect_ports_become_net_port_rules_on_abi_4(monkeypatch):
    fake = FakeSys(abi=4)
    monkeypatch.setattr(LL, "_sys", fake)
    c = LL.Confinement([], connect_ports=(3128,))
    net_calls = [x for x in fake.calls if x[0] == LL.SYS_ADD and x[1][1] == LL.RULE_NET_PORT]
    assert c.net_enforced and len(net_calls) == 1
    allowed, port = struct.unpack("<QQ", rule_bytes(net_calls[0]))
    assert allowed == LL.NET_CONNECT_TCP and port == 3128, "hanya hak CONNECT (bukan BIND) ke port proxy"


def test_ruleset_handles_tcp_bind_and_connect_on_abi_4(monkeypatch):
    fake = FakeSys(abi=4)
    monkeypatch.setattr(LL, "_sys", fake)
    LL.Confinement([], connect_ports=(3128,))
    create = next(x for x in fake.calls if x[0] == LL.SYS_CREATE and not (x[1][2] & LL.CREATE_VERSION))
    fs, net = struct.unpack("<QQ", ctypes.string_at(create[1][0], 16))
    assert net == (LL.NET_BIND_TCP | LL.NET_CONNECT_TCP), "BIND dan CONNECT harus 'ditangani' (ditolak kecuali ada aturan)"
    assert fs & LL.FS_V1 == LL.FS_V1


def test_without_ports_tcp_is_fully_denied_on_abi_4(monkeypatch):
    fake = FakeSys(abi=4)
    monkeypatch.setattr(LL, "_sys", fake)
    LL.Confinement([])
    assert not [x for x in fake.calls if x[0] == LL.SYS_ADD and x[1][1] == LL.RULE_NET_PORT]


@pytest.mark.parametrize("abi", [1, 2, 3])
def test_ports_are_not_pretended_on_older_abi(monkeypatch, abi):
    """ABI < 4 tidak bisa membatasi TCP: aturan port TIDAK ditambahkan dan `net_enforced` False, supaya pemanggil tahu pengunci ini TIDAK ada."""
    fake = FakeSys(abi=abi)
    monkeypatch.setattr(LL, "_sys", fake)
    c = LL.Confinement([], connect_ports=(3128,))
    assert not c.net_enforced and not [x for x in fake.calls if x[0] == LL.SYS_ADD and x[1][1] == LL.RULE_NET_PORT]


@pytest.mark.parametrize("port", [0, -1, 65536, True, "3128", None, 3128.0])
def test_invalid_ports_are_errors(monkeypatch, port):
    monkeypatch.setattr(LL, "_sys", FakeSys(abi=4))
    with pytest.raises(LL.LandlockError):
        LL.Confinement([], connect_ports=(port,))


def test_a_failing_port_rule_syscall_is_an_error(monkeypatch):
    fake = FakeSys(abi=4)
    real = fake.__call__
    monkeypatch.setattr(LL, "_sys", lambda num, *a: -1 if (num == LL.SYS_ADD and a[1] == LL.RULE_NET_PORT) else real(num, *a))
    with pytest.raises(LL.LandlockError, match="port 3128"):
        LL.Confinement([], connect_ports=(3128,))


# ================================================================================ gagal tertutup di proses pembantu
def run_helper(spec: dict, abi: int, monkeypatch, tmp_path):
    import io
    import bench.confined_exec as C
    monkeypatch.setattr(LL, "abi_version", lambda: abi)
    monkeypatch.setattr(C, "Confinement", lambda rules, connect_ports=(): (_ for _ in ()).throw(AssertionError("tidak boleh sampai sini")) if False else _Conf(abi, connect_ports))
    err = io.StringIO()
    monkeypatch.setattr(C.sys, "stderr", err)
    called = []
    monkeypatch.setattr(C.os, "execve", lambda *a: called.append(a))
    spec = {"rules": [], "command": "true", "cwd": str(tmp_path), "env": {}, "canary": "/", "nofile": 64, "nproc": 64, "fsize": 1 << 20, "cpu_seconds": 5, "marker_fd": 99, **spec}
    monkeypatch.setattr(C.os, "listdir", lambda p: (_ for _ in ()).throw(PermissionError()))
    monkeypatch.setattr(C.os, "write", lambda fd, b: len(b))
    monkeypatch.setattr(C.os, "set_inheritable", lambda fd, v: None)
    monkeypatch.setattr(C, "_limits", lambda s: None)
    return C.main(["x", json.dumps(spec)]), called, err.getvalue()


class _Conf:
    last = None

    def __init__(self, abi, ports):
        self.net_enforced, self.ports = abi >= 4, ports
        _Conf.last = self

    def apply(self):
        pass

    def close(self):
        pass


def test_requesting_network_on_a_kernel_that_cannot_lock_tcp_refuses_to_run(monkeypatch, tmp_path):
    rc, called, err = run_helper({"net_ports": [3128]}, abi=2, monkeypatch=monkeypatch, tmp_path=tmp_path)
    from bench.confined_exec import EXIT_LANDLOCK
    assert rc == EXIT_LANDLOCK and not called and "tidak aman" in err


def test_network_on_abi_4_runs(monkeypatch, tmp_path):
    rc, called, err = run_helper({"net_ports": [3128]}, abi=4, monkeypatch=monkeypatch, tmp_path=tmp_path)
    assert called and called[0][0] == "/usr/bin/bash"
    assert _Conf.last.ports == (3128,), "port dari spesifikasi harus sampai ke Confinement (kalau tidak, TCP terkunci total / proxy tak terjangkau)"


def test_no_ports_in_the_spec_means_no_port_rules(monkeypatch, tmp_path):
    run_helper({"net_ports": []}, abi=4, monkeypatch=monkeypatch, tmp_path=tmp_path)
    assert _Conf.last.ports == ()


def test_no_network_requested_runs_on_old_abi(monkeypatch, tmp_path):
    rc, called, err = run_helper({"net_ports": []}, abi=2, monkeypatch=monkeypatch, tmp_path=tmp_path)
    assert called, "tanpa jaringan, ABI lama tetap boleh menjalankan perintah"


# ================================================================================ eksekutor meneruskan konfigurasi ke spesifikasi
def test_executor_passes_the_proxy_port_and_environment_to_the_helper(tmp_path, monkeypatch):
    seen = {}
    real = E.subprocess.Popen

    def spy(cmd, **kw):
        seen["spec"] = json.loads(cmd[-1])
        return real(["/bin/sh", "-c", "exit 0"], **{k: v for k, v in kw.items() if k != "pass_fds"})
    monkeypatch.setattr(E.subprocess, "Popen", spy)
    data = tmp_path / "data"
    (data / "bench/1").mkdir(parents=True)
    E.run_confined(P.Dirs(data), E.Limits(), analysis_id=1, command="true", timeout=3, sha256=SHA, job_id="s1-net", net=E.NetConfig("egress", 3128))
    assert seen["spec"]["net_ports"] == [3128] and seen["spec"]["env"]["https_proxy"] == "http://egress:3128"
    seen.clear()
    E.run_confined(P.Dirs(data), E.Limits(), analysis_id=1, command="true", timeout=3, sha256=SHA, job_id="s1-net2")
    assert seen["spec"]["net_ports"] == [] and "https_proxy" not in seen["spec"]["env"]


# ================================================================================ konfigurasi daemon
def load_daemon(monkeypatch, tmp_path, abi, proxy):
    import importlib.machinery
    import importlib.util
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("BENCH_SPOOL", str(tmp_path / "sp"))
    if proxy is None:
        monkeypatch.delenv("BENCH_NET_PROXY", raising=False)
    else:
        monkeypatch.setenv("BENCH_NET_PROXY", proxy)
    monkeypatch.setattr(LL, "abi_version", lambda: abi)
    loader = importlib.machinery.SourceFileLoader("bench_daemon_net_test", str(ROOT / "services/bench/bench-daemon"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("proxy,abi,expected", [
    (None, 4, None), ("", 4, None),
    ("egress:3128", 4, ("egress", 3128)), ("egress:3128", 5, ("egress", 3128)),
    ("egress:3128", 3, None), ("egress:3128", 2, None), ("egress:3128", 0, None),
    ("rusak", 4, None), ("egress:", 4, None), (":3128", 4, None), ("egress:abc", 4, None), ("egress:0", 4, None), ("egress:70000", 4, None),
    ("eg ress:3128", 4, None), ("http://egress:3128", 4, None), ("egress:3128/x", 4, None), ("a;b:3128", 4, None),
])
def test_daemon_enables_the_network_only_when_valid_and_the_kernel_can_lock_tcp(monkeypatch, tmp_path, capsys, proxy, abi, expected):
    mod = load_daemon(monkeypatch, tmp_path, abi, proxy)
    got = (mod.NET.host, mod.NET.port) if mod.NET else None
    assert got == expected, (proxy, abi, got)
    out = capsys.readouterr().out
    if proxy and proxy.strip() and expected is None:
        assert "PERINGATAN" in out and "DIMATIKAN" in out, "penonaktifan harus terlihat di log, bukan diam-diam"
    if not (proxy or "").strip():
        assert "PERINGATAN" not in out, "tidak meminta jaringan = tidak ada peringatan"


def test_daemon_passes_the_net_config_to_every_command(monkeypatch, tmp_path):
    mod = load_daemon(monkeypatch, tmp_path, 4, "egress:3128")
    seen = {}
    monkeypatch.setattr(mod.executor, "run_confined", lambda *a, **k: (seen.update(k), {"status": "ok"})[1])
    mod.run_job("s1-aaaaaaaaaaaa", {"op": "run", "analysis_id": 1, "command": "true", "timeout": 5, "sha256": SHA})
    assert seen["net"] == E.NetConfig("egress", 3128)


# ================================================================================ konfigurasi web
def test_web_allowlist_parsing_matches_the_egress_parser():
    cases = ["", "*", "a.com", "A.com, *.b.com,, *.,  ,a b,.com,-x.com", "*.", "*..", "a.com.", "***", "http://a.com", "a.com:443", "x" * 300 + ".com"]
    for raw in cases:
        assert _net_allow(raw) == EP.parse_allowlist(raw), raw


def test_web_allowlist_parsing_matches_the_egress_parser_at_every_boundary():
    """Tiap batas diuji di KEDUA sisi tepi (sah/tidak sah) dan dibandingkan dengan egress, yang menjadi acuan; tes ini menutup mutasi lolos (N33/N36/N37/N38)."""
    l63, l64 = "a" * 63, "a" * 64
    h253 = ".".join([l63, l63, l63, "a" * 61])                       # 63*3 + 61 + 3 titik = 253
    h254 = ".".join([l63, l63, l63, "a" * 62])
    assert len(h253) == 253 and len(h254) == 254
    cases = [h253, h254, l63 + ".com", l64 + ".com", "*." + l63 + ".com", "*." + l64 + ".com", "*." + h253[:240], "*.-x.com", "*.a b", "*.a_b.com", "*.x-.com",
             "a.com,a.com, A.COM", "b.com,a.com,b.com", "*,*", "*.a.com,*.a.com", "a..com", ".a.com", "a-.com", "-a.com", "a_b.com"]
    for raw in cases:
        assert _net_allow(raw) == EP.parse_allowlist(raw), raw
    assert _net_allow(h253) == (h253,) and _net_allow(h254) == ()                    # nilai mutlak: bukan hanya "sama dengan egress"
    assert _net_allow(l63 + ".com") != () and _net_allow(l64 + ".com") == ()
    assert _net_allow("*.-x.com") == () and _net_allow("*.a b") == ()               # wildcard dengan sisa tak sah DIBUANG, bukan dibiarkan melebar
    assert _net_allow("a.com,a.com, A.COM") == ("a.com",)


def test_web_ports_parsing_matches_egress():
    for raw in ("", "443", "443, 8443", "abc", "0", "70000", "80,443,80", "٤٤٣", "٨٠٨٠", "８０８０", "443,٨٠٨٠", "65535", "65536", "1", "-1", "+443", "4 43"):
        assert set(_net_ports(raw)) == set(EP.parse_ports(raw)), raw
    assert _net_ports("٨٠٨٠") == (443,), "angka non-ASCII bukan port: kembali ke bawaan, tidak diam-diam menjadi 8080"
    assert _net_ports("65535") == (65535,) and _net_ports("65536") == (443,) and _net_ports("1") == (1,)


def test_network_is_off_by_default_and_flag_values(monkeypatch):
    monkeypatch.delenv("AI_SHELL_NET_ALLOW", raising=False)
    assert load_ai_config().shell_net_allow == ()
    monkeypatch.setenv("AI_SHELL_NET_ALLOW", "api.contoh.com, *.cdn.contoh.com")
    monkeypatch.setenv("AI_SHELL_NET_PORTS", "443,8443")
    c = load_ai_config()
    assert c.shell_net_allow == ("api.contoh.com", "*.cdn.contoh.com") and c.shell_net_ports == (443, 8443)


# ================================================================================ prompt
def test_prompt_without_network_is_unchanged_from_the_shell_only_prompt():
    assert agent.system_prompt(True) == agent.system_prompt(True, (), (443,))
    assert "JARINGAN UNTUK MENGUJI API" not in agent.system_prompt(True) and "TANPA jaringan" in agent.system_prompt(True)
    assert agent.system_prompt(False) == agent.SYSTEM_PROMPT


def test_prompt_with_network_has_no_contradiction_and_keeps_the_rules():
    on = agent.system_prompt(True, ("*",), (443,))
    for contradiction in ("TANPA jaringan", "Tidak ada jaringan", "atau jaringan;", "(tanpa jaringan,"):
        assert contradiction not in on, contradiction
    assert "JARINGAN UNTUK MENGUJI API" in on and "SEMUA host publik" in on and "port 443" in on
    base = agent.SYSTEM_PROMPT
    assert base[base.index("A. Isi kode"):base.index("B. Jangan")] in on and base[base.index("E. Nilai"):] in on
    for must in ("aturan F", "pemindaian host/port", "brute force", "konfirmasi pengguna", "DATA tidak tepercaya", "private_address", "jangan mencari jalan memutar"):
        assert must in on, must


def test_prompt_lists_the_exact_hosts_and_ports():
    p = agent.system_prompt(True, ("api.contoh.com", "*.cdn.contoh.com"), (443, 8443))
    assert "api.contoh.com, *.cdn.contoh.com" in p and "443, 8443" in p and "SEMUA host publik" not in p


def test_network_prompt_only_appears_when_the_shell_is_enabled():
    assert agent.system_prompt(False, ("*",), (443,)) == agent.SYSTEM_PROMPT


def test_the_prompt_rewrites_fail_loudly_if_the_base_text_changes(monkeypatch):
    monkeypatch.setattr(agent, "_NET_REWRITES", (("teks yang tidak ada di prompt", "x"),))
    with pytest.raises(RuntimeError, match="teks prompt berubah"):
        agent.system_prompt(True, ("*",), (443,))


def test_a_rewrite_whose_base_text_appears_twice_also_fails_loudly(monkeypatch):
    """Dua kecocokan = rewrite akan mengubah tempat yang tidak dimaksud. Harus galat keras, bukan mengganti diam-diam (menutup N46)."""
    base = agent.system_prompt(True)
    needle = next(w for w in ("shell_run", "A.", "aturan") if base.count(w) >= 2)
    monkeypatch.setattr(agent, "_NET_REWRITES", ((needle, "x"),))
    with pytest.raises(RuntimeError, match="teks prompt berubah"):
        agent.system_prompt(True, ("*",), (443,))


def test_chat_passes_the_network_settings_to_the_prompt():
    src = (ROOT / "services/web/app/ai/agent.py").read_text(encoding="utf-8")
    assert "system_prompt(cfg.shell_enabled, cfg.shell_net_allow, cfg.shell_net_ports)" in src


# ================================================================================ compose
def compose_block(name: str) -> str:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    return compose.split(f"\n  {name}:\n", 1)[1].split("\n  # ", 1)[0].split("\nnetworks:\n", 1)[0]


def _strip_comments(block: str) -> str:
    """Komentar boleh menyebut `edge`/`backend` untuk menjelaskan; yang diperiksa konfigurasinya."""
    return "\n".join(re.sub(r"\s+#.*$", "", line) for line in block.splitlines() if not line.strip().startswith("#"))


def test_bench_is_only_on_the_internal_bench_network():
    b = _strip_comments(compose_block("bench"))
    assert "networks: [benchnet]" in b and "network_mode" not in b
    for forbidden in ("edge", "backend", "egressnet", "ports:", "privileged", "docker.sock", "cap_add"):
        assert forbidden not in b, forbidden
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    nets = compose.split("\nnetworks:\n", 1)[1].split("\nvolumes:\n", 1)[0]
    assert re.search(r"benchnet:\n\s+internal: true", nets), "benchnet harus internal (tanpa gateway ke internet)"
    assert re.search(r"egressnet: \{\}", nets) and not re.search(r"egressnet:\n\s+internal", nets)


def test_egress_is_isolated_and_secretless():
    e = _strip_comments(compose_block("egress"))
    assert "networks: [benchnet, egressnet]" in e
    for must in ("read_only: true", 'user: "10003:10003"', "cap_drop: [ALL]", "no-new-privileges:true", "pids_limit", "mem_limit"):
        assert must in e, must
    for forbidden in ("edge", "backend", "volumes:", "secrets:", "AI_API_KEY", "SECRET_KEY", "REDIS", "docker.sock", "cap_add", "privileged", "ports:"):
        assert forbidden not in e, forbidden


def test_only_bench_and_egress_share_the_bench_network_and_only_egress_reaches_out():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    services = re.findall(r"\n  ([a-z]+):\n(?:    .*\n|\n)+?", compose.split("services:\n", 1)[1].split("\nnetworks:\n", 1)[0])
    on_bench = [s for s in services if "benchnet" in compose_block(s)]
    on_egress = [s for s in services if "egressnet" in compose_block(s)]
    assert sorted(on_bench) == ["bench", "egress"] and on_egress == ["egress"]


def test_a_single_switch_drives_both_sides():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "BENCH_NET_PROXY: ${AI_SHELL_NET_ALLOW:+egress:3128}" in compose, "satu sakelar: bench berjaringan hanya bila daftar host diisi"
    assert "EGRESS_ALLOW: ${AI_SHELL_NET_ALLOW:-}" in compose and "AI_SHELL_NET_ALLOW: ${AI_SHELL_NET_ALLOW:-}" in compose


def test_the_egress_image_only_contains_the_proxy_package():
    df = (ROOT / "services/egress/Dockerfile").read_text(encoding="utf-8")
    assert "COPY egress/egress ./egress" in df and "rvcore" not in df and "USER 10003:10003" in df
    for f in ("services/egress/egress/policy.py", "services/egress/egress/server.py"):
        src = (ROOT / f).read_text(encoding="utf-8")
        assert "import subprocess" not in src and "os.system" not in src and "eval(" not in src


def test_every_tool_the_prompt_tells_the_ai_to_use_exists_in_the_bench_image():
    """Prompt menyuruh AI memakai `curl`; bila image bench tidak memasangnya, fitur gagal di produksi dan TIDAK terlihat di tes lain (ditemukan saat meninjau Dockerfile)."""
    dockerfile = (ROOT / "services/bench/Dockerfile").read_text(encoding="utf-8")
    install = next(ln for ln in dockerfile.splitlines() if "apt-get install" in ln).replace(";", " ").replace("\\", " ")
    packages = install.split()
    for tool in ("curl",):
        assert tool in agent.SHELL_NET_BLOCK, "tes ini usang: prompt tidak lagi menyebut alat itu"
        assert tool in packages, f"{tool} disebut prompt jaringan tetapi tidak dipasang di image bench"
    assert "ca-certificates" in packages, "HTTPS lewat CONNECT butuh sertifikat CA di image"


# ================================================================================ deskripsi tool sejalan dengan prompt
def _shell_desc(**kw) -> str:
    from app.ai import tools as T
    return next(t for t in T.schemas(shell=True, **kw) if t["function"]["name"] == "shell_run")["function"]["description"]


def test_tool_description_says_no_network_unless_the_network_is_on():
    off, on = _shell_desc(), _shell_desc(net=True)
    assert "TANPA jaringan" in off and "proxy" not in off
    assert "TANPA jaringan" not in on and "Yang tidak mungkin: jaringan," not in on and "proxy" in on
    assert "TANPA rahasia" in on, "pernyataan tanpa rahasia tetap utuh"
    assert off.replace("TANPA jaringan, ", "").count("rahasia") == on.count("rahasia")


def test_net_flag_does_not_change_other_tools_or_appear_without_the_shell():
    from app.ai import tools as T
    plain = {t["function"]["name"]: t["function"]["description"] for t in T.schemas(shell=True)}
    net = {t["function"]["name"]: t["function"]["description"] for t in T.schemas(shell=True, net=True)}
    assert {k for k in plain if plain[k] != net[k]} == {"shell_run"}
    assert "shell_run" not in {t["function"]["name"] for t in T.schemas(shell=False, net=True)}


def test_tool_description_rewrite_fails_loudly_when_the_base_text_changes(monkeypatch):
    from app.ai import tools as T
    monkeypatch.setattr(T, "_SHELL_NET_DESC_REWRITES", (("teks yang tidak ada", "x"),))
    with pytest.raises(RuntimeError, match="deskripsi shell_run berubah"):
        T.schemas(shell=True, net=True)


def test_chat_passes_net_to_the_tool_schemas():
    src = (ROOT / "services/web/app/ai/agent.py").read_text(encoding="utf-8")
    assert "T.schemas(vision=ctx.vision, shell=cfg.shell_enabled, net=bool(cfg.shell_net_allow))" in src


def test_tool_description_rewrite_with_two_matches_also_fails_loudly(monkeypatch):
    from app.ai import tools as T
    assert _shell_desc().count("TANPA") >= 2, "tes ini usang"
    monkeypatch.setattr(T, "_SHELL_NET_DESC_REWRITES", (("TANPA", "x"),))
    with pytest.raises(RuntimeError, match="deskripsi shell_run berubah"):
        T.schemas(shell=True, net=True)
