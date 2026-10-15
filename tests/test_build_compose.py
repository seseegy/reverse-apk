"""Invarian compose Tahap 2b: matriks mount per layanan, hardening, dan tmpfs (SATU tabel ketat, bukan penjaga terpisah-pisah).

Diperkenalkan di FEAT C ketika runner mulai membaca `bench` (pekerjaan AI) dan menulis `builds`: invarian lama yang dicabut SADAR ('runner tak melihat bench',
'builds hanya worker + signer') digantikan di sini oleh tabel yang lebih ketat:
  * runner : bench READ-ONLY SAJA, builds rw; TANPA benchspool/signspool/signwork/files/db, tanpa secrets, tanpa Docker socket, tmpfs tidak berubah.
  * bench  : TANPA builds/signwork/signspool.
  * signer : builds + signspool + signwork (+ keystore lewat berkas tambahan, bukan di sini).
  * web    : builds rw (hapus/sajikan; akses lewat rantai-dirfd).
  * signwork HANYA signer; signspool HANYA worker + signer.
Parser teks (tanpa PyYAML, yang tidak ada di requirements CI); bila PyYAML ada, tabel yang sama diperiksa ulang lewat parser YAML sungguhan.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

# Matriks mount (sumber -> mode). `-` = tidak dipasang. Volume bernama saja; bind (./config, ./deploy/Caddyfile) ada di BINDS.
MATRIX: dict[str, dict[str, str]] = {
    "web":     {"uploads": "rw", "work": "rw", "files": "rw", "db": "rw", "bench": "rw", "benchspool": "rw", "builds": "rw"},
    "worker":  {"uploads": "ro", "work": "rw", "db": "rw", "spool": "rw", "builds": "rw", "signspool": "rw"},
    "runner":  {"uploads": "ro", "work": "rw", "spool": "rw", "bench": "ro", "builds": "rw"},
    "bench":   {"uploads": "ro", "work": "ro", "bench": "rw", "benchspool": "rw"},
    "signer":  {"builds": "rw", "signspool": "rw", "signwork": "rw"},
    "redis":   {"redisdata": "rw"},
    "caddy":   {"caddy_data": "rw", "caddy_config": "rw"},
    "egress":  {},
}
BINDS = {"web": {"./config": "ro"}, "caddy": {"./deploy/Caddyfile": "ro"}}
FORBIDDEN_FOR_RUNNER = ("benchspool", "signspool", "signwork", "files", "db")


def _code(text: str) -> str:
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def block(name: str) -> str:
    """Blok satu layanan (komentar baris-penuh dibuang)."""
    body = COMPOSE.split("\nservices:\n", 1)[1].split("\nnetworks:\n", 1)[0]
    parts = re.split(r"(?m)^  ([\w-]+):[ \t]*$", body)
    found = {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}
    return _code(found[name])


def service_names() -> list[str]:
    body = COMPOSE.split("\nservices:\n", 1)[1].split("\nnetworks:\n", 1)[0]
    return re.findall(r"(?m)^  ([\w-]+):[ \t]*$", body)


def list_items(text: str, key: str) -> list[str]:
    m = re.search(rf"(?m)^    {key}:\n((?:      - .*\n?)+)", text)
    return [re.sub(r"\s+#.*$", "", ln.strip()[2:]).strip().strip("\"'") for ln in m.group(1).splitlines()] if m else []


def mounts(name: str) -> tuple[dict[str, str], dict[str, str]]:
    named, binds = {}, {}
    for item in list_items(block(name), "volumes"):
        src, _dst, *opt = item.split(":")
        mode = "ro" if opt and opt[0] == "ro" else "rw"
        (binds if src.startswith(".") else named)[src] = mode
    return named, binds


def test_every_service_is_in_the_matrix_and_nothing_else():
    assert sorted(service_names()) == sorted(MATRIX)


@pytest.mark.parametrize("name", sorted(MATRIX))
def test_mount_matrix_is_exact(name):
    """Himpunan pemasang dan MODE tiap volume persis tabel: volume tambahan, mode longgar (ro -> rw), atau hilang = gagal."""
    named, binds = mounts(name)
    assert named == MATRIX[name], f"{name}: {named}"
    assert binds == BINDS.get(name, {}), f"{name}: {binds}"


def test_each_volume_has_the_intended_holders():
    holders = lambda vol: {n for n, m in MATRIX.items() if vol in m}  # noqa: E731
    assert holders("builds") == {"web", "worker", "runner", "signer"}
    assert holders("signwork") == {"signer"}
    assert holders("signspool") == {"worker", "signer"}
    assert holders("bench") == {"web", "runner", "bench"} and MATRIX["runner"]["bench"] == "ro"
    assert holders("benchspool") == {"web", "bench"}
    top = COMPOSE.split("\nvolumes:\n", 1)[1].split("\nsecrets:\n", 1)[0]
    assert set(re.findall(r"(?m)^  ([A-Za-z0-9_]+):", top)) == {v for m in MATRIX.values() for v in m}


def test_runner_sees_bench_read_only_writes_builds_and_nothing_sensitive():
    named, _ = mounts("runner")
    assert named["bench"] == "ro" and named["builds"] == "rw"
    assert not set(named) & set(FORBIDDEN_FOR_RUNNER)
    runner = block("runner")
    for forbidden in ("secrets:", "docker.sock", "privileged", "cap_add", "networks:", "ports:", "keystore", "signer"):
        assert forbidden not in runner, forbidden
    for must in ("network_mode: none", "read_only: true", 'user: "10001:10001"', "cap_drop: [ALL]", "no-new-privileges:true", "mem_limit: 3g", "cpus: 2", "pids_limit: 512"):
        assert must in runner, must


def test_runner_tmpfs_is_unchanged_and_is_the_only_exec_mount_in_the_stack():
    """Penjaga exec (tidak boleh berubah di 2b): /tmp runner tetap noexec; SATU-SATUNYA tmpfs exec = /opt/aapt-exec milik runner (16m, uid 10001)."""
    assert list_items(block("runner"), "tmpfs") == ["/tmp:rw,size=256m,nosuid", "/opt/aapt-exec:rw,exec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0755"]
    execs = []
    for name in service_names():
        for entry in list_items(block(name), "tmpfs"):
            opts = entry.split(":", 1)[1].split(",") if ":" in entry else []
            if "exec" in [o.strip() for o in opts]:
                execs.append((name, entry.split(":", 1)[0]))
    assert execs == [("runner", "/opt/aapt-exec")]


def test_bench_has_no_builds_and_signer_has_exactly_three_volumes():
    assert "builds" not in mounts("bench")[0] and "builds" not in block("bench").replace("benchspool", "")
    assert list_items(block("signer"), "volumes") == ["builds:/data/builds", "signspool:/data/signspool", "signwork:/data/signwork"]


def test_hardening_does_not_drop_for_any_service():
    """Kunci hardening per layanan = daftar tetap (turun = gagal). Layanan memakai anchor `*hardening` ATAU menulisnya sendiri."""
    anchored = ("caddy", "web", "worker", "redis")
    for name in anchored:
        assert "<<: *hardening" in block(name), name
    base = COMPOSE.split("x-hardening: &hardening\n", 1)[1].split("\nservices:\n", 1)[0]
    for must in ("restart: unless-stopped", "init: true", "no-new-privileges:true", "- ALL"):
        assert must in base, must
    for name in ("runner", "bench", "signer", "egress"):
        b = block(name)
        for must in ("init: true", "read_only: true", "cap_drop: [ALL]", "no-new-privileges:true"):
            assert must in b, (name, must)
    for name in ("web", "worker", "caddy"):
        assert "read_only: true" in block(name), name
    assert "cap_add" not in "\n".join(block(n) for n in service_names() if n != "caddy")
    assert "docker.sock" not in _code(COMPOSE) and "privileged" not in _code(COMPOSE)


def test_dockerfiles_create_the_mount_points_for_uid_10001():
    """Volume bernama mewarisi izin titik mount dari image saat pertama dibuat (pelajaran 3): `mkdir -p` + chown 10001 di Dockerfile pemasangnya."""
    def mk(name: str) -> str:
        text = (ROOT / "services" / name / "Dockerfile").read_text(encoding="utf-8")
        m = re.search(r"mkdir -p ([^\\&;]*?)\s*(?:\\\n\s*)?&& chown -R 10001:10001 /data", text)
        assert m, name
        return m.group(1)

    assert {"/data/bench", "/data/builds"} <= set(mk("runner").split())
    assert "/data/signwork" in mk("signer").split() and "/data/builds" in mk("signer").split()
    assert "/data/builds" in mk("web").split() and "/data/builds" in mk("worker").split()
    assert "/data/builds" not in mk("bench").split() and "/data/signwork" not in " ".join(mk(n) for n in ("web", "worker", "runner", "bench"))


def test_same_matrix_holds_under_a_real_yaml_parser():
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load(COMPOSE)
    for name, expected in MATRIX.items():
        got = {}
        for item in doc["services"][name].get("volumes", []):
            src, _dst, *opt = item.split(":")
            if not src.startswith("."):
                got[src] = "ro" if opt and opt[0] == "ro" else "rw"
        assert got == expected, name
    assert sorted(doc["volumes"]) == sorted({v for m in MATRIX.values() for v in m})
    assert doc["services"]["runner"]["tmpfs"] == ["/tmp:rw,size=256m,nosuid", "/opt/aapt-exec:rw,exec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0755"]
    assert doc["services"]["runner"]["network_mode"] == "none" and doc["services"]["runner"]["read_only"] is True
