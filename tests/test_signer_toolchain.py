"""Toolchain penanda tangan (PRD 09 Bagian B, paket B-1b): Dockerfile signer, layanan compose, Makefile, konsistensi pin, helper selftest.

Hanya yang bisa diuji TANPA Docker: pemeriksaan teks (PyYAML tidak ada di requirements CI) dan helper murni di `signer-selftest`.
Bukti nyata (build image, alat berjalan, isolasi kontainer) ada di `make signer-selftest` di server.

Tahap 2a mengubah SECARA SADAR beberapa penjaga Tahap 1 (signer kini daemon: volume, env, restart, healthcheck, CMD; kunci dipasang berkas tambahan);
yang dipertahankan (jaringan mati, read-only, uid 10001, cap_drop, tmpfs TANPA exec, tanpa secrets di berkas dasar) tetap dijaga di bawah.
"""

from __future__ import annotations

import os
import re
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = (ROOT / "services/signer/Dockerfile").read_text(encoding="utf-8")


def _instructions(text: str) -> list[str]:
    """Instruksi Dockerfile tanpa komentar; baris lanjutan (`\\`) digabung."""
    joined = re.sub(r"\\\n", " ", text)
    return [ln.strip() for ln in joined.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def _arg(name: str, text: str = DOCKERFILE) -> str:
    m = re.search(rf"^ARG {name}=(\S+)$", text, re.M)
    assert m, f"ARG {name} tidak ada"
    return m.group(1)


def compose_block(name: str) -> str:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    # `networks:` tingkat atas dipotong LEBIH DULU: signer adalah layanan terakhir dan komentar `  # ...` di bawah `networks:` akan memotong terlalu awal.
    return compose.split(f"\n  {name}:\n", 1)[1].split("\nnetworks:\n", 1)[0].split("\n  # ", 1)[0]


def _strip_comments(block: str) -> str:
    return "\n".join(re.sub(r"\s+#.*$", "", line) for line in block.splitlines() if not line.strip().startswith("#"))


# ================================================================================ (a) Dockerfile
def test_dockerfile_pins_build_tools_by_sha256_and_verifies_before_extraction():
    assert re.fullmatch(r"[0-9a-f]{64}", _arg("BUILD_TOOLS_SHA256"))
    assert re.fullmatch(r"\d+\.\d+\.\d+", _arg("BUILD_TOOLS_VERSION"))
    assert DOCKERFILE.startswith("#") and "\nFROM python:3.12-slim-trixie\n" in DOCKERFILE
    run = next(i for i in _instructions(DOCKERFILE) if i.startswith("RUN set -eux") and "curl" in i)
    assert "https://dl.google.com/android/repository/" in run and "http://" not in run
    assert 'echo "${BUILD_TOOLS_SHA256}  /tmp/build-tools.zip" | sha256sum -c -' in run
    assert run.index("sha256sum -c") < run.index("unzip -q"), "hash harus diverifikasi SEBELUM ekstraksi"
    # Hanya tiga anggota yang diekstrak, bukan seluruh zip.
    unzip = re.search(r"unzip -q /tmp/build-tools\.zip (.+?) -d /tmp/bt", run)
    assert unzip, "unzip harus menyebut anggota satu per satu"
    members = unzip.group(1).replace('"', "").split()
    assert [m.rsplit("/", 1)[-1] for m in members] == ["zipalign", "apksigner.jar", "libc++.so"]
    # curl/unzip dibuang dan sisa unduhan dihapus dalam layer yang sama dengan unduhannya.
    assert "apt-get purge -y --auto-remove curl unzip" in run and "rm -rf /var/lib/apt/lists/* /tmp/*" in run
    assert "openjdk-21-jre-headless" in run


def test_dockerfile_runs_as_uid_10001_and_embeds_no_key_material():
    """Tahap 2a (sadar): `/data/builds` dan `/data/signspool` (HANYA mkdir/chown) dan `CMD ["signer-daemon"]` diizinkan; VOLUME dan material kunci tetap dilarang."""
    ins = _instructions(DOCKERFILE)
    users = [i for i in ins if i.startswith("USER ")]
    assert users and users[-1] == "USER 10001:10001"
    for i in ins:
        if re.match(r"(ENV|ARG|COPY|ADD)\b", i):
            assert not re.search(r"keystore|\.jks|\.p12|\.pfx|storepass|password|secret", i, re.I), i
    install = [i for i in ins if "apt-get install" in i]
    assert install and not any(re.search(r"\b(apksigner|zipalign)\b", i.split("apt-get install", 1)[1].split(";", 1)[0]) for i in install)
    assert "VOLUME" not in DOCKERFILE, "titik mount dibuat dengan mkdir; tanpa instruksi VOLUME"
    assert [i for i in ins if "/data" in i] == ["RUN mkdir -p /data/builds /data/signspool && chown -R 10001:10001 /data"]
    assert ins.index("RUN mkdir -p /data/builds /data/signspool && chown -R 10001:10001 /data") > next(n for n, i in enumerate(ins) if i.startswith("RUN groupadd"))
    assert "COPY signer/signer-daemon signer/signer-selftest /usr/local/bin/" in ins
    assert "RUN chmod 0755 /usr/local/bin/signer-daemon /usr/local/bin/signer-selftest" in ins
    assert ins[-1] == 'CMD ["signer-daemon"]' and "--toolchain-only" not in DOCKERFILE


def test_apksigner_wrapper_is_a_separate_run_after_the_download_layer():
    """Mengubah flag JVM tidak boleh membatalkan cache lapisan unduhan Build-Tools (apt + 66 MB): wrapper dibuat oleh `RUN printf` TERPISAH sesudah `RUN set -eux`."""
    ins = _instructions(DOCKERFILE)
    download = next(n for n, i in enumerate(ins) if i.startswith("RUN set -eux") and "curl" in i)
    wrappers = [n for n, i in enumerate(ins) if i.startswith("RUN printf") and "/usr/local/bin/apksigner" in i]
    assert len(wrappers) == 1 and wrappers[0] > download
    wrapper = ins[wrappers[0]]
    for flag in ("-XX:MaxDirectMemorySize=64m", "-Xmx256m", "--enable-native-access=ALL-UNNAMED", "-jar /opt/build-tools/apksigner.jar"):
        assert flag in wrapper, flag
    assert "chmod 0755 /usr/local/bin/apksigner" in wrapper
    assert "printf" not in ins[download] and "/usr/local/bin/apksigner" not in ins[download] and "MaxDirectMemorySize" not in ins[download]


def test_dockerfile_guards_missing_shared_libraries_correctly():
    """zipalign memuat libc++.so lewat RUNPATH; build harus gagal bila tidak ditemukan. `! cmd` TIDAK menggagalkan `set -e`, jadi harus `if ...; then ...; exit 1`."""
    assert "if ldd /opt/build-tools/zipalign | grep -q 'not found'; then" in DOCKERFILE
    assert not re.search(r"!\s*ldd", DOCKERFILE)
    assert "ldd /usr/local/bin/zipalign" not in DOCKERFILE, "ldd pada symlink menyesatkan (RUNPATH $ORIGIN dihitung dari path asli)"
    assert "install -m 0644 \"/tmp/bt/${BUILD_TOOLS_DIR}/lib64/libc++.so\" /opt/build-tools/lib64/libc++.so" in DOCKERFILE
    assert "ln -s /opt/build-tools/zipalign /usr/local/bin/zipalign" in DOCKERFILE


# ================================================================================ (b) compose
def _list_items(block: str, key: str) -> list[str]:
    """Butir daftar YAML (`- x`) di bawah `    key:` pada blok layanan (komentar sudah dibuang)."""
    m = re.search(rf"(?m)^    {re.escape(key)}:\n((?:      - .*\n?)+)", block)
    return [ln.strip()[2:] for ln in m.group(1).splitlines()] if m else []


def test_signer_service_is_isolated_secretless_and_profiled():
    """Dilonggarkan SADAR (Tahap 2a, signer kini daemon): `volumes:`, `environment:`, `restart: unless-stopped`, healthcheck, stop_grace_period diizinkan.
    TETAP dilarang di berkas dasar: `secrets:`, jaringan, port, depends_on, docker.sock, privileged, cap_add, edge/backend, keystore."""
    block = _strip_comments(compose_block("signer"))
    for must in ("network_mode: none", "read_only: true", "cap_drop: [ALL]", "no-new-privileges:true", 'user: "10001:10001"',
                 'profiles: ["build"]', "restart: unless-stopped", "stop_grace_period: 20s", "mem_limit: 512m", "cpus: 1", "pids_limit: 128",
                 "- /tmp:rw,size=256m,nosuid", "dockerfile: signer/Dockerfile", "init: true",
                 'test: ["CMD", "signer-daemon", "--health"]', "interval: 10s", "timeout: 5s", "retries: 3", "start_period: 30s"):
        assert must in block, must
    for forbidden in ("secrets:", "networks:", "ports:", "depends_on", "docker.sock", "privileged", "cap_add", "edge", "backend", "keystore",
                      "<<: *hardening", 'restart: "no"'):
        assert forbidden not in block, forbidden
    # Tepat dua volume dan tiga env; tmpfs hanya /tmp tanpa exec.
    assert _list_items(block, "volumes") == ["builds:/data/builds", "signspool:/data/signspool"]
    assert _list_items(block, "tmpfs") == ["/tmp:rw,size=256m,nosuid"]
    assert _list_items(block, "security_opt") == ["no-new-privileges:true"]
    env = re.search(r"(?m)^    environment:\n((?:      \w+: .*\n?)+)", block).group(1)
    assert [ln.strip() for ln in env.splitlines()] == ["DATA_DIR: /data", "SIGN_TIMEOUT: ${SIGN_TIMEOUT:-900}", "SIGN_MAX_MB: ${SIGN_MAX_MB:-1100}"]


def test_signer_is_the_only_profiled_service():
    """`profiles:` hanya pada signer: `make up` tetap menjalankan semua layanan lain dan tidak menyentuh signer."""
    compose = _strip_comments((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose.count("profiles:") == 1
    assert "profiles:" in _strip_comments(compose_block("signer"))
    up = next(ln for ln in (ROOT / "Makefile").read_text(encoding="utf-8").splitlines() if "up -d --build" in ln)
    assert "--profile" not in up


def test_no_other_service_receives_keystore_or_signer_material():
    """Kunci hanya untuk `signer` dan hanya lewat berkas tambahan; berkas DASAR tidak menyebut keystore sama sekali (asersi dasar TIDAK dilonggarkan)."""
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    for name in ("caddy", "web", "worker", "redis", "runner", "bench", "egress"):
        block = _strip_comments(compose_block(name))
        assert not re.search(r"keystore|signer|SIGNER_", block, re.I), name
    top = compose.split("\nsecrets:\n", 1)[1]
    assert re.findall(r"^  (\w+):$", top, re.M) == ["admin_password_hash"]
    assert "secrets:" not in _strip_comments(compose_block("signer"))
    assert "signing_keystore" not in compose
    # Berkas tambahan: satu layanan (signer) dan persis dua secret.
    extra = _strip_comments((ROOT / "docker-compose.keystore.yml").read_text(encoding="utf-8"))
    assert re.findall(r"(?m)^  (\w[\w-]*):\s*$", extra.split("\nsecrets:\n", 1)[0].split("services:\n", 1)[1]) == ["signer"]
    assert re.findall(r"(?m)^  (\w+):", extra.split("\nsecrets:\n", 1)[1]) == ["signing_keystore", "signing_keystore_pass"]
    assert "secrets: [signing_keystore, signing_keystore_pass]" in extra


def _service_mounts() -> dict[str, list[str]]:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    body = compose.split("\nservices:\n", 1)[1].split("\nnetworks:\n", 1)[0]
    names = re.findall(r"(?m)^  ([\w-]+):[ \t]*$", body)
    return {n: _list_items(_strip_comments(compose_block(n)), "volumes") for n in names}


def test_builds_and_signspool_are_mounted_only_where_intended():
    mounts = _service_mounts()
    assert {"caddy", "web", "worker", "redis", "runner", "bench", "egress", "signer"} <= set(mounts)
    holders_builds = {n for n, v in mounts.items() if any(x.startswith("builds:") for x in v)}
    holders_spool = {n for n, v in mounts.items() if any(x.startswith("signspool:") for x in v)}
    assert holders_builds == {"worker", "signer"}
    assert holders_spool == {"worker", "signer"}
    assert "builds:/data/builds" in mounts["worker"] and "signspool:/data/signspool" in mounts["worker"]
    for name in ("runner", "bench", "egress", "caddy", "web", "redis"):
        assert not re.search(r"builds|signspool", "\n".join(mounts[name])), name
        assert not re.search(r"/data/builds|signspool", _strip_comments(compose_block(name))), name
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    vols = compose.split("\nvolumes:\n", 1)[1].split("\nsecrets:\n", 1)[0]
    assert set(re.findall(r"(?m)^  ([A-Za-z0-9_]+):", vols)) == {
        "uploads", "work", "files", "db", "spool", "bench", "benchspool", "builds", "signspool", "redisdata", "caddy_data", "caddy_config"}


def test_worker_block_stays_free_of_keystore_and_signer_words():
    """Worker memasang builds/signspool tetapi TIDAK boleh menerima kunci/penanda tangan (test_build_store._block hanya membuang komentar satu-baris-penuh)."""
    block = compose_block("worker")
    block = "\n".join(ln for ln in block.splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r"keystore|signer|SIGNER_", block, re.I)
    assert "secrets:" not in block


def test_other_dockerfiles_do_not_know_signspool():
    for name in ("web", "runner", "bench", "egress"):
        text = (ROOT / "services" / name / "Dockerfile").read_text(encoding="utf-8")
        assert "signspool" not in text and "/data/builds" not in text, name


def test_signer_hardening_survives_in_the_base_compose():
    """Daftar kunci hardening signer + nilai persis; tmpfs hanya /tmp TANPA exec (penjaga lain: test_runner_aapt2, tidak diubah)."""
    block = _strip_comments(compose_block("signer"))
    keys = re.findall(r"(?m)^    ([a-z_]+):", block)
    for must in ("profiles", "restart", "init", "network_mode", "read_only", "user", "cap_drop", "security_opt", "tmpfs", "environment", "volumes",
                 "stop_grace_period", "healthcheck", "mem_limit", "cpus", "pids_limit", "build"):
        assert must in keys, must
    assert not re.search(r"(?m)^    (ports|networks|secrets|privileged|cap_add|devices|pid|ipc|extra_hosts|dns|labels):", block)
    assert re.search(r"(?m)^    tmpfs:\n      - /tmp:rw,size=256m,nosuid$", block)
    assert not re.search(r"exec", block) and "mem_limit: 512m" in block


def test_sign_env_read_by_the_daemon_is_forwarded_by_compose_and_listed_in_env_example():
    """Pola OP-01: setiap env SIGN* yang dibaca signer-daemon diteruskan compose DAN ada di .env.example; kecualian eksplisit hanya pengungkit uji."""
    src = (ROOT / "services/signer/signer-daemon").read_text(encoding="utf-8")
    names = set(re.findall(r'_int_env\(\s*"(SIGN\w*)"', src)) | set(re.findall(r'environ(?:\.get)?[\[(]\s*"(SIGN\w*)"', src))
    excepted = {"SIGNER_SECRETS_DIR", "SIGNCHECK_DIAG"}  # pengungkit uji, SENGAJA tidak diteruskan compose
    assert names - excepted == {"SIGN_TIMEOUT", "SIGN_MAX_MB"}, names
    block = _strip_comments(compose_block("signer"))
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for n in names - excepted:
        assert re.search(rf"(?m)^      {n}: \$\{{{n}:-\d+\}}$", block), f"{n} dibaca signer-daemon tetapi tidak diteruskan compose"
        assert re.search(rf"(?m)^#{n}=\d+$", example), f"{n} tidak ada di .env.example"
    for n in excepted & names:
        assert n not in block and n not in example, n
    assert "DATA_DIR" in src and "      DATA_DIR: /data" in block
    # Bawaan di compose/.env.example sama dengan bawaan kode.
    assert '_int_env("SIGN_TIMEOUT", 900,' in src and "SIGN_TIMEOUT: ${SIGN_TIMEOUT:-900}" in block and "#SIGN_TIMEOUT=900" in example
    assert '_int_env("SIGN_MAX_MB", 1100,' in src and "SIGN_MAX_MB: ${SIGN_MAX_MB:-1100}" in block and "#SIGN_MAX_MB=1100" in example


# ================================================================================ (c) Makefile + skrip
def _make_recipe(target: str) -> str:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    m = re.search(rf"^{target}:.*\n((?:\t.*\n)+)", makefile, re.M)
    assert m, f"target {target} tidak ada"
    return m.group(1)


def test_makefile_has_signer_targets():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    phony = next(ln for ln in makefile.splitlines() if ln.startswith(".PHONY:"))
    for target in ("signer-selftest", "tools-check", "keystore-access"):
        assert re.search(rf"^{target}:.*## ", makefile, re.M), f"{target} harus punya deskripsi `## ` agar muncul di `make help`"
        assert re.search(rf"\b{target}\b", phony), f"{target} harus ada di .PHONY"
    assert "./scripts/keystore.sh access" in _make_recipe("keystore-access") and "--auto" not in _make_recipe("keystore-access")
    # Gerbang keystore: variabel ekspor HANYA di dalam ifeq; resep `up`/`restart` memperbaiki akses lebih dulu; `down` selalu dengan profil build.
    gate = makefile.split("ifeq ($(KEYSTORE_PRESENT),1)\n", 1)[1].split("\nendif", 1)[0]
    for must in ("export COMPOSE_FILE := docker-compose.yml:docker-compose.keystore.yml", "export COMPOSE_PROFILES := build", "export KEYSTORE_STAMP := $(shell stat -c '%i-%s-%Y'"):
        assert must in gate, must
    assert "KEYSTORE_PRESENT := $(shell ./scripts/keystore.sh present >/dev/null 2>&1 && echo 1)" in makefile
    outside = makefile.replace(gate, "")
    assert not re.search(r"(?m)^export\s+(COMPOSE_FILE|COMPOSE_PROFILES|KEYSTORE_STAMP)\b", outside)
    for target, run in (("up", "$(COMPOSE) up -d --build"), ("restart", "$(COMPOSE) up -d")):
        lines = _make_recipe(target).splitlines()
        access = next(n for n, ln in enumerate(lines) if "./scripts/keystore.sh access --auto || true" in ln)
        assert access < next(n for n, ln in enumerate(lines) if ln.strip() == run), target
    assert "COMPOSE_PROFILES=build $(COMPOSE) down" in _make_recipe("down")
    assert "./scripts/keystore.sh status || true" in _make_recipe("doctor")
    recipe = _make_recipe("signer-selftest")
    for must in ("--profile build build signer", "--profile build run --rm --no-deps signer signer-selftest"):
        assert must in recipe, must
    assert "--toolchain-only" not in recipe
    assert "./scripts/tools-check.sh" in _make_recipe("tools-check")


def test_tools_check_script_is_executable_bash():
    script = ROOT / "scripts/tools-check.sh"
    text = script.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n") and "set -uo pipefail" in text
    assert os.access(script, os.X_OK), "scripts/tools-check.sh harus executable (Makefile memanggilnya langsung)"
    assert "--profile build" in text and "--no-deps" in text


# ================================================================================ (d) pin konsisten dengan yang didokumentasikan
def test_pins_in_dockerfiles_match_the_documented_table():
    runner = (ROOT / "services/runner/Dockerfile").read_text(encoding="utf-8")
    deploy = (ROOT / "docs/deploy.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    versions = {
        "apktool": _arg("APKTOOL_VERSION", runner),
        "jadx": _arg("JADX_VERSION", runner),
        "build-tools": _arg("BUILD_TOOLS_VERSION"),
    }
    hashes = {
        "apktool": _arg("APKTOOL_SHA256", runner),
        "jadx": _arg("JADX_SHA256", runner),
        "build-tools": _arg("BUILD_TOOLS_SHA256"),
    }
    for name, h in hashes.items():
        assert re.fullmatch(r"[0-9a-f]{64}", h), name
        assert h in deploy, f"SHA-256 {name} di Dockerfile tidak ada di docs/deploy.md"
    for name, v in versions.items():
        assert re.search(rf"\b{re.escape(v)}\b", deploy), f"versi {name} {v} tidak ada di docs/deploy.md"
        assert re.search(rf"\b{re.escape(v)}\b", readme), f"versi {name} {v} tidak ada di README.md"
    # SHA-1 yang diterbitkan Google (pembanding SHA-256 yang dihitung sendiri) harus tercatat di dokumen.
    assert DOCKERFILE.count("70954e99f4c3d9d46ee70fa32624672fe7cd6ebe") == 1 and "70954e99f4c3d9d46ee70fa32624672fe7cd6ebe" in deploy


def test_build_tools_zip_and_dir_follow_the_pinned_version():
    major, minor, _patch = _arg("BUILD_TOOLS_VERSION").split(".")
    rev = major if minor == "0" else f"{major}.{minor}"
    assert _arg("BUILD_TOOLS_ZIP") == f"build-tools_r{rev}_linux.zip"
    assert _arg("BUILD_TOOLS_DIR") == f"android-{major}.{minor}"


def test_scripts_read_pins_from_the_image_instead_of_duplicating_them():
    runner = (ROOT / "services/runner/Dockerfile").read_text(encoding="utf-8")
    pins = [_arg("BUILD_TOOLS_VERSION"), _arg("BUILD_TOOLS_SHA256"), _arg("APKTOOL_VERSION", runner), _arg("APKTOOL_SHA256", runner),
            _arg("JADX_VERSION", runner), _arg("JADX_SHA256", runner)]
    for rel in ("services/signer/signer-selftest", "services/runner/runner-selftest", "scripts/tools-check.sh"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        for pin in pins:
            assert pin not in text, f"{rel} menyalin pin {pin}; baca dari ENV image"
    assert "BUILD_TOOLS_VERSION" in (ROOT / "scripts/tools-check.sh").read_text(encoding="utf-8")


# ================================================================================ helper signer-selftest (tanpa Docker/Java)
def _selftest():
    import importlib.machinery
    import importlib.util

    path = str(ROOT / "services/signer/signer-selftest")
    loader = importlib.machinery.SourceFileLoader("signer_selftest", path)
    spec = importlib.util.spec_from_loader("signer_selftest", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_selftest_builds_valid_zip_and_misaligned_variant(tmp_path):
    st = _selftest()
    good, bad = str(tmp_path / "a.apk"), str(tmp_path / "b.apk")
    st.make_test_apk(good)
    st.make_test_apk(bad, misaligned=True)
    for p in (good, bad):
        with zipfile.ZipFile(p) as zf:
            assert zf.testzip() is None
            assert {"AndroidManifest.xml", "classes.dex", "resources.arsc", "lib/arm64-v8a/libuji.so"} <= set(zf.namelist())
            assert all(zf.getinfo(n).compress_type == zipfile.ZIP_STORED for n in ("resources.arsc", "lib/arm64-v8a/libuji.so", "classes.dex"))
    assert any(off % 4 for off in st.stored_data_offsets(bad).values()), "varian tak selaras harus punya offset ganjil"
    assert st.DEX_MARKER in Path(good).read_bytes()


def test_selftest_tamper_flips_exactly_one_payload_byte_and_keeps_zip_readable(tmp_path):
    st = _selftest()
    src, dst = str(tmp_path / "s.apk"), str(tmp_path / "t.apk")
    st.make_test_apk(src)
    st.tamper(src, dst)
    a, b = Path(src).read_bytes(), Path(dst).read_bytes()
    assert len(a) == len(b) and sum(x != y for x, y in zip(a, b)) == 1
    with zipfile.ZipFile(dst) as zf:
        assert zf.namelist() == zipfile.ZipFile(src).namelist()
        assert zf.testzip() == "classes.dex", "CRC entri yang dirusak harus tidak cocok"
    with pytest.raises(ValueError):
        st.tamper(src, dst, marker=b"TIDAK-ADA")


def test_selftest_finds_keystores_but_not_the_public_cacerts_or_pruned_dirs(tmp_path):
    st = _selftest()
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "x.p12").write_bytes(b"k")
    (tmp_path / "opt").mkdir()
    (tmp_path / "opt" / "A.JKS").write_bytes(b"k")
    (tmp_path / "opt" / "id_rsa").write_bytes(b"k")
    (tmp_path / "opt" / "cacerts").write_bytes(b"publik")
    (tmp_path / "opt" / "biasa.txt").write_bytes(b"x")
    (tmp_path / "tmp").mkdir()
    (tmp_path / "tmp" / "sementara.p12").write_bytes(b"k")
    found = {os.path.relpath(p, tmp_path) for p in st.find_keystores(str(tmp_path), skip=(str(tmp_path / "tmp"),))}
    assert found == {os.path.join("etc", "x.p12"), os.path.join("opt", "A.JKS"), os.path.join("opt", "id_rsa")}


def test_selftest_fails_with_exit_1_when_tools_are_missing(tmp_path, monkeypatch, capsys):
    st = _selftest()
    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    assert st.main(["--toolchain-only"]) == 1
    out = capsys.readouterr().out
    assert "[GAGAL] java" in out and "DILEWATI" in out
    assert not list((tmp_path / "home").glob("selftest-*")), "direktori kerja sementara harus dibersihkan walau gagal"


# ================================================================================ signer-selftest: cek lama yang berubah (Tahap 2a)
def test_selftest_prune_and_wrapper_flags_follow_the_daemon_image():
    st = _selftest()
    assert st.PRUNE == ("/proc", "/sys", "/dev", "/tmp", "/run/secrets", "/data")
    assert st.WRAPPER_FLAGS == ("--enable-native-access=ALL-UNNAMED", "-Xmx256m", "-XX:MaxDirectMemorySize=64m")
    assert all(flag in DOCKERFILE for flag in st.WRAPPER_FLAGS), "flag wajib selftest harus ada di wrapper Dockerfile"


def test_selftest_secrets_dir_check_accepts_only_the_two_keystore_files_or_nothing(tmp_path):
    st = _selftest()
    ok, detail = st.check_secrets_dir(str(tmp_path / "tidak-ada"))
    assert ok and "tidak dipasang" in detail
    d = tmp_path / "secrets"
    d.mkdir()
    assert st.check_secrets_dir(str(d))[0], "kosong = keystore tidak dipasang"
    (d / "signing_keystore").write_bytes(b"RAHASIA-P12")
    assert not st.check_secrets_dir(str(d))[0], "satu berkas saja bukan keadaan yang sah"
    (d / "signing_keystore_pass").write_bytes(b"RAHASIA-SANDI")
    ok, detail = st.check_secrets_dir(str(d))
    assert ok and "RAHASIA" not in detail
    (d / "admin_password_hash").write_bytes(b"x")
    ok, detail = st.check_secrets_dir(str(d))
    assert not ok and "admin_password_hash" in detail and "RAHASIA" not in detail
    (d / "admin_password_hash").unlink()
    (d / "signing_keystore_pass").unlink()
    (d / "signing_keystore_pass").symlink_to(d / "signing_keystore")
    assert not st.check_secrets_dir(str(d))[0], "symlink bukan berkas biasa"
    f = tmp_path / "bukan-direktori"
    f.write_text("x")
    assert not st.check_secrets_dir(str(f))[0]


def test_selftest_data_dir_check_requires_exactly_builds_and_signspool_writable(tmp_path, monkeypatch):
    st = _selftest()
    assert not st.check_data_dir(str(tmp_path / "tidak-ada"))[0]
    data = tmp_path / "data"
    data.mkdir()
    (data / "builds").mkdir()
    ok, detail = st.check_data_dir(str(data))
    assert not ok and "signspool" in detail
    (data / "signspool").mkdir()
    removed: list[str] = []
    real_remove = os.remove
    monkeypatch.setattr(st.os, "remove", lambda p, *a, **k: (removed.append(str(p)), real_remove(p, *a, **k))[1])
    ok, detail = st.check_data_dir(str(data))
    monkeypatch.undo()
    assert ok and "builds" in detail
    # Bukti tulis-hapus NYATA (juga sebagai root, yang mengabaikan izin): satu berkas `.selftest-<acak>` per akar volume.
    assert sorted(Path(r).parent.name for r in removed) == ["builds", "signspool"] and all(re.fullmatch(r".selftest-[0-9a-f]{12}", Path(r).name) for r in removed)
    assert sorted(p.name for p in (data / "builds").iterdir()) == [] and sorted(p.name for p in (data / "signspool").iterdir()) == [], "berkas uji harus dihapus"
    (data / "spool").mkdir()
    ok, detail = st.check_data_dir(str(data))
    assert not ok and "spool" in detail
    (data / "spool").rmdir()
    if os.geteuid() != 0:  # root mengabaikan izin; bukti akar-tak-bisa-ditulis di sandbox dilakukan lewat setpriv (verification.md)
        (data / "signspool").chmod(0o555)
        try:
            ok, detail = st.check_data_dir(str(data))
        finally:
            (data / "signspool").chmod(0o755)
        assert not ok and "signspool" in detail
