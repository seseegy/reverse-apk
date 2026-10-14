"""Toolchain penanda tangan (PRD 09 Bagian B, paket B-1b): Dockerfile signer, layanan compose, Makefile, konsistensi pin, helper selftest.

Hanya yang bisa diuji TANPA Docker: pemeriksaan teks (PyYAML tidak ada di requirements CI) dan helper murni di `signer-selftest`.
Bukti nyata (build image, alat berjalan, isolasi kontainer) ada di `make signer-selftest` di server.
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
    ins = _instructions(DOCKERFILE)
    users = [i for i in ins if i.startswith("USER ")]
    assert users and users[-1] == "USER 10001:10001"
    for i in ins:
        if re.match(r"(ENV|ARG|COPY|ADD)\b", i):
            assert not re.search(r"keystore|\.jks|\.p12|\.pfx|storepass|password|secret", i, re.I), i
    install = [i for i in ins if "apt-get install" in i]
    assert install and not any(re.search(r"\b(apksigner|zipalign)\b", i.split("apt-get install", 1)[1].split(";", 1)[0]) for i in install)
    assert "VOLUME" not in DOCKERFILE and "/data" not in "\n".join(ins)
    assert ins[-1] == 'CMD ["signer-selftest"]' and "--toolchain-only" not in DOCKERFILE


def test_dockerfile_guards_missing_shared_libraries_correctly():
    """zipalign memuat libc++.so lewat RUNPATH; build harus gagal bila tidak ditemukan. `! cmd` TIDAK menggagalkan `set -e`, jadi harus `if ...; then ...; exit 1`."""
    assert "if ldd /opt/build-tools/zipalign | grep -q 'not found'; then" in DOCKERFILE
    assert not re.search(r"!\s*ldd", DOCKERFILE)
    assert "ldd /usr/local/bin/zipalign" not in DOCKERFILE, "ldd pada symlink menyesatkan (RUNPATH $ORIGIN dihitung dari path asli)"
    assert "install -m 0644 \"/tmp/bt/${BUILD_TOOLS_DIR}/lib64/libc++.so\" /opt/build-tools/lib64/libc++.so" in DOCKERFILE
    assert "ln -s /opt/build-tools/zipalign /usr/local/bin/zipalign" in DOCKERFILE


# ================================================================================ (b) compose
def test_signer_service_is_isolated_secretless_and_profiled():
    block = _strip_comments(compose_block("signer"))
    for must in ("network_mode: none", "read_only: true", "cap_drop: [ALL]", "no-new-privileges:true", 'user: "10001:10001"',
                 'profiles: ["build"]', 'restart: "no"', "mem_limit: 512m", "cpus: 1", "pids_limit: 128", "- /tmp:rw,size=256m,nosuid",
                 "dockerfile: signer/Dockerfile"):
        assert must in block, must
    for forbidden in ("volumes:", "secrets:", "networks:", "ports:", "environment:", "depends_on", "docker.sock", "privileged",
                      "cap_add", "edge", "backend", "keystore", "<<: *hardening"):
        assert forbidden not in block, forbidden


def test_signer_is_the_only_profiled_service():
    """`profiles:` hanya pada signer: `make up` tetap menjalankan semua layanan lain dan tidak menyentuh signer."""
    compose = _strip_comments((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose.count("profiles:") == 1
    assert "profiles:" in _strip_comments(compose_block("signer"))
    up = next(ln for ln in (ROOT / "Makefile").read_text(encoding="utf-8").splitlines() if "up -d --build" in ln)
    assert "--profile" not in up


def test_no_other_service_receives_keystore_or_signer_material():
    """Bila B-1c menambah rahasia keystore, tes ini diubah SECARA SADAR bersama tes isolasi lain (bench/egress/runner tetap tanpa keystore)."""
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    for name in ("caddy", "web", "worker", "redis", "runner", "bench", "egress"):
        block = _strip_comments(compose_block(name))
        assert not re.search(r"keystore|signer|SIGNER_", block, re.I), name
    top = compose.split("\nsecrets:\n", 1)[1]
    assert re.findall(r"^  (\w+):$", top, re.M) == ["admin_password_hash"]
    assert "secrets:" not in _strip_comments(compose_block("signer"))


# ================================================================================ (c) Makefile + skrip
def _make_recipe(target: str) -> str:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    m = re.search(rf"^{target}:.*\n((?:\t.*\n)+)", makefile, re.M)
    assert m, f"target {target} tidak ada"
    return m.group(1)


def test_makefile_has_signer_targets():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    phony = next(ln for ln in makefile.splitlines() if ln.startswith(".PHONY:"))
    for target in ("signer-selftest", "tools-check"):
        assert re.search(rf"^{target}:.*## ", makefile, re.M), f"{target} harus punya deskripsi `## ` agar muncul di `make help`"
        assert re.search(rf"\b{target}\b", phony), f"{target} harus ada di .PHONY"
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
