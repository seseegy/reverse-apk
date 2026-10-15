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


# ================================================================================ FEAT F: invarian final (parser YAML, env, Dockerfile, dokumen)
# Bagian ini MEM-PARSE YAML sungguhan (PyYAML ada di tests/requirements.txt sejak FEAT F; tanpa PyYAML tes dilewati, sehingga CI WAJIB memasangnya). Docker/Compose
# rusak di sandbox dan tidak dipakai: `docker compose config` BELUM DIUJI; yang dibuktikan di sini hanya isi berkas.
@pytest.fixture(scope="module")
def doc():
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(COMPOSE)


@pytest.fixture(scope="module")
def merged():
    """Compose dasar + berkas tambahan keystore, digabung per layanan seperti Compose (kunci layanan ditimpa/ditambah, secrets top-level digabung)."""
    yaml = pytest.importorskip("yaml")
    base = yaml.safe_load(COMPOSE)
    extra = yaml.safe_load((ROOT / "docker-compose.keystore.yml").read_text(encoding="utf-8"))
    for svc, over in extra["services"].items():
        base["services"][svc].update(over)
    base["secrets"].update(extra["secrets"])
    return base


USER_10001 = ("runner", "bench", "signer")
# Hardening yang HARUS tetap, per layanan (nilai persis dari berkas; turun/berubah = gagal).
LIMITS = {
    "caddy": {"mem_limit": "256m"},
    "web": {"mem_limit": "512m", "pids_limit": 256},
    "worker": {"mem_limit": "512m", "pids_limit": 256},
    "redis": {"mem_limit": "320m"},
    "runner": {"mem_limit": "3g", "cpus": 2, "pids_limit": 512},
    "bench": {"mem_limit": "1g", "cpus": 1, "pids_limit": 512},
    "egress": {"mem_limit": "256m", "cpus": 0.5, "pids_limit": 128},
    "signer": {"mem_limit": "512m", "cpus": 1, "pids_limit": 128},
}


def test_yaml_hardening_every_service_keeps_its_limits_and_privileges(doc):
    svcs = doc["services"]
    assert sorted(svcs) == sorted(LIMITS)
    for name, s in svcs.items():
        assert s["init"] is True and s["restart"] == "unless-stopped", name
        assert s["security_opt"] == ["no-new-privileges:true"], name
        assert s["cap_drop"] == ["ALL"], name
        for key, val in LIMITS[name].items():
            assert s[key] == val, (name, key)
        assert not {"privileged", "devices", "pid", "ipc", "cgroup_parent", "extra_hosts", "dns", "sysctls", "ulimits", "userns_mode", "uts"} & set(s), name
        assert s.get("read_only") is (None if name == "redis" else True), name
        assert ("cap_add" in s) == (name == "caddy"), name
    assert svcs["caddy"]["cap_add"] == ["NET_BIND_SERVICE"]
    assert {n: svcs[n]["user"] for n in USER_10001} == {n: "10001:10001" for n in USER_10001}
    assert svcs["egress"]["user"] == "10003:10003" and svcs["redis"]["user"] == "redis"
    assert "user" not in svcs["web"] and "user" not in svcs["worker"]  # web/worker: Dockerfile menurunkan ke 10001 sendiri; tidak diubah di 2b


def test_yaml_network_isolation(doc):
    svcs = doc["services"]
    assert svcs["runner"]["network_mode"] == "none" and svcs["signer"]["network_mode"] == "none"
    assert "networks" not in svcs["runner"] and "networks" not in svcs["signer"] and "ports" not in svcs["runner"]
    assert svcs["bench"]["networks"] == ["benchnet"] and svcs["worker"]["networks"] == ["backend"]
    assert svcs["egress"]["networks"] == ["benchnet", "egressnet"] and svcs["web"]["networks"] == ["edge", "backend"]
    assert [n for n, s in svcs.items() if "ports" in s] == ["caddy"]
    assert doc["networks"]["backend"] == {"internal": True} and doc["networks"]["benchnet"] == {"internal": True}
    assert doc["networks"]["egressnet"] == {} and doc["networks"]["edge"] == {}


def test_yaml_no_docker_socket_no_host_binds_beyond_the_two_known_ones(doc):
    binds = {}
    for name, s in doc["services"].items():
        for item in s.get("volumes", []):
            assert "docker.sock" not in item and not item.startswith("/"), (name, item)
            if item.startswith("."):
                binds[name] = item
    assert binds == {"web": "./config:/config:ro", "caddy": "./deploy/Caddyfile:/etc/caddy/Caddyfile:ro"}
    assert "docker.sock" not in _code(COMPOSE)


def test_yaml_mount_matrix_with_destinations_and_modes(doc):
    """Tujuan mount tetap /data/<volume> (bench/builds/... tidak dipasang di jalur lain) dan mode persis MATRIX."""
    for name, expected in MATRIX.items():
        got = {}
        for item in doc["services"][name].get("volumes", []):
            src, dst, *opt = item.split(":")
            if src.startswith("."):
                continue
            assert len(opt) <= 1 and (not opt or opt[0] in ("ro", "rw")), item
            if name not in ("redis", "caddy"):
                assert dst == f"/data/{src}", (name, item)
            got[src] = opt[0] if opt else "rw"
        assert got == expected, name
    assert sorted(doc["volumes"]) == sorted({v for m in MATRIX.values() for v in m})


def test_yaml_tmpfs_only_runner_aapt_exec_is_exec_and_nothing_new(doc):
    tm = {n: s["tmpfs"] for n, s in doc["services"].items() if "tmpfs" in s}
    assert tm == {
        "caddy": ["/tmp"], "web": ["/tmp"], "worker": ["/tmp"], "bench": ["/tmp:rw,size=256m,nosuid"], "signer": ["/tmp:rw,size=256m,nosuid"],
        "runner": ["/tmp:rw,size=256m,nosuid", "/opt/aapt-exec:rw,exec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0755"],
    }
    execs = [(n, e.split(":")[0]) for n, lst in tm.items() for e in lst if "exec" in e.split(":", 1)[-1].split(",")]
    assert execs == [("runner", "/opt/aapt-exec")]
    assert not [e for n, lst in tm.items() for e in lst if n != "runner" and "exec" in e.split(":", 1)[-1].split(",")]


def test_yaml_keystore_overlay_gives_secrets_to_signer_only(doc, merged):
    holders = [n for n, s in merged["services"].items() if s.get("secrets")]
    assert sorted(holders) == ["signer", "web"]  # web: hanya hash password admin (berkas dasar), bukan kunci
    assert merged["services"]["signer"]["secrets"] == ["signing_keystore", "signing_keystore_pass"]
    assert merged["services"]["web"]["secrets"] == ["admin_password_hash"]
    for key in ("network_mode", "read_only", "user", "cap_drop", "security_opt", "tmpfs", "volumes", "mem_limit", "cpus", "pids_limit"):
        assert merged["services"]["signer"][key] == doc["services"]["signer"][key], key
    for name in set(merged["services"]) - {"signer"}:
        assert merged["services"][name] == doc["services"][name], name
    assert doc["secrets"] == {"admin_password_hash": {"file": "./secrets/admin_password_hash"}}


def test_yaml_runner_has_no_secrets_and_signer_profile_is_the_only_profile(doc):
    r = doc["services"]["runner"]
    assert "secrets" not in r and "networks" not in r and "ports" not in r
    assert [n for n, s in doc["services"].items() if "profiles" in s] == ["signer"] and doc["services"]["signer"]["profiles"] == ["build"]


def test_yaml_build_env_is_forwarded_to_worker_and_web_and_listed_in_env_example(doc):
    """TIMEOUT_BUILD/TIMEOUT_SIGN (pola OP-01): diteruskan ke worker (dibaca run_build) dan web (job_timeout RQ), TIDAK ke runner/bench/signer/egress."""
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for var, default in (("TIMEOUT_BUILD", 1800), ("TIMEOUT_SIGN", 900), ("BUILD_KEEP", 10)):
        for svc in ("worker", "web"):
            assert doc["services"][svc]["environment"][var] == f"${{{var}:-{default}}}", (svc, var)
        for svc in ("runner", "bench", "signer", "egress", "caddy", "redis"):
            assert var not in doc["services"][svc].get("environment", {}), (svc, var)
        assert re.search(rf"(?m)^#{var}={default}$", example), var
    assert "min(" in example and "SIGN_TIMEOUT" in example and "1-100" in example


def test_dockerfiles_final_state_for_2b():
    def text(name):
        return (ROOT / "services" / name / "Dockerfile").read_text(encoding="utf-8")

    assert "worker/builds.py" in text("worker")
    assert "buildstage.py" in text("runner")
    for name in ("bench", "egress"):
        assert not re.search(r"builds|signwork|signspool", text(name)), name
    for name in ("web", "worker", "runner", "bench", "egress"):
        assert "signwork" not in text(name), name                     # HANYA signer
        assert ("signspool" in text(name)) == (name == "worker"), name  # worker + signer (signer dicek terpisah di bawah)
    assert "signwork" in text("signer") and "signspool" in text("signer") and "/data/builds" in text("signer")


def test_worker_dockerfile_copies_every_module_the_entry_points_import():
    worker = ROOT / "services" / "worker"
    copied = set(re.findall(r"worker/(\w+)\.py", (worker / "Dockerfile").read_text(encoding="utf-8")))
    assert {"builds", "tasks", "worker", "pipeline", "healthcheck"} <= copied


# ---------------------------------------------------------------- dokumen (tes teks; klaim yang belum teruji dilarang)
def _read(p: str) -> str:
    return (ROOT / p).read_text(encoding="utf-8")


def test_prd09_records_the_deferral_of_fr_9_24_and_9_41_and_the_stage5_download_prerequisite():
    prd = _read("docs/prd/09-bundles-and-workbench.md")
    assert "Keputusan tercatat Tahap 2b" in prd
    note = prd.split("Keputusan tercatat Tahap 2b", 1)[1]
    for needle in ("FR-9.23", "DIKERJAKAN", "FR-9.24", "FR-9.41", "DITUNDA ke Tahap 5", "menunggu konfirmasi pemilik", "salin-lalu-hash", "BUILD_KEEP"):
        assert needle in note, needle
    row = next(ln for ln in prd.splitlines() if ln.startswith("| FR-9.28 |"))
    assert "usul 5" not in row and "(10 bawaan, `BUILD_KEEP`" in row
    assert next(ln for ln in prd.splitlines() if ln.startswith("| FR-9.24 |")).count("DITUNDA ke Tahap 5") == 1
    assert next(ln for ln in prd.splitlines() if ln.startswith("| FR-9.41 |")).count("DITUNDA ke Tahap 5") == 1


def test_deploy_doc_covers_2b_matrix_symptoms_and_the_stage5_prerequisite():
    deploy = _read("docs/deploy.md")
    assert "Tahap 2b" in deploy and "bench:ro" in deploy and "salin-lalu-hash" in deploy
    section = deploy.split("### Build APK Tahap 2b", 1)[1].split("\n## ", 1)[0]
    for needle in ("TIMEOUT_BUILD", "TIMEOUT_SIGN", "SIGN_TIMEOUT", "MIN_UPTIME_BEFORE_RECYCLE", "/opt/aapt-exec", "signwork", "no_space", "workspace_changed",
                   "BELUM DIUJI", "FR-9.24", "FR-9.41", "app.buildctl", "mem_limit", "R-1"):
        assert needle in section, needle
    for volume in ("uploads", "work", "files", "db", "spool", "bench", "benchspool", "builds", "signspool", "signwork"):
        assert f"| `{volume}` |" in section, volume
    assert "verify-build" not in section  # skrip itu baru ada di FEAT G


def test_docs_do_not_make_the_wrong_runner_recycle_claim():
    """A-12: tidak ada 'belasan detik'/'jendela 12 dtk'; 12 dtk hanya melindungi runner baru-hidup dari backoff restart Docker."""
    for p in ("docs/deploy.md", "README.md", "audit.md", "docs/prd/09-bundles-and-workbench.md", ".env.example"):
        text = _read(p)
        assert "belasan detik" not in text and "jendela 12 dtk" not in text, p
    section = _read("docs/deploy.md").split("### Build APK Tahap 2b", 1)[1]
    assert "keluar SEGERA" in section and "backoff" in section


def test_readme_and_audit_state_2b_status_honestly():
    readme, audit = _read("README.md"), _read("audit.md")
    assert "Tahap 2b" in readme and "BELUM DIUJI" in readme and "FR-9.24" in readme
    assert "### 10.18 " in audit
    entry = audit.split("### 10.18 ", 1)[1]
    for needle in ("R3", "R10", "R-1", "Belum terbukti", "fakeredis", "RQ nyata", "Docker", "FR-9.24"):
        assert needle in entry, needle
    assert "verify-build" not in readme.split("Tahap 2b", 1)[1].split("\n## ", 1)[0] and "verify-build" not in entry
