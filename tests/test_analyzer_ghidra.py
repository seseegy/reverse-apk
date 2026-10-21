"""Tes tahap analisis native mendalam (analyzer/ghidra.py, tahap 3b).

Ghidra sungguhan TIDAK dijalankan di sini: `analyzeHeadless` digantikan stub skrip
yang meniru kontraknya (menerima argumen yang sama, menulis JSON + berkas .c hasil
ekspor). Yang diuji adalah logika tahapnya: pemilihan library, pagar budget/timeout,
pemetaan hasil ekspor -> temuan + ringkasan, dan sifat tidak fatalnya. Bukti Ghidra
asli berjalan ada di runner-selftest (image) dan verifikasi manual saat pengembangan.
"""

from __future__ import annotations

import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

from analyzer import ghidra
from analyzer.common import Findings

ROOT = Path(__file__).resolve().parent.parent

STUB_JSON = {
    "program": "libtest.so",
    "language": "AARCH64:LE:64:v8A",
    "compiler": "default",
    "image_base": "00100000",
    "functions_truncated": False,
    "imports": ["ptrace", "dlopen", "memcpy"],
    "crypto_constants": ["aes_sbox@00103000"],
    "functions": [
        {"name": "Java_com_x_Loader_load", "addr": "00101100", "size": 64, "thunk": False,
         "jni": True, "vector_fp": False, "callers": [], "callees": ["vec_calc"]},
        {"name": "vec_calc", "addr": "00101200", "size": 128, "thunk": False,
         "jni": False, "vector_fp": True, "callers": ["Java_com_x_Loader_load"], "callees": []},
    ],
    "strings": [
        {"addr": "00102000", "value": "https://contoh.example.net/api",
         "xrefs": [{"from": "00101110", "in": "Java_com_x_Loader_load"}]},
        {"addr": "00102040", "value": "frida-agent-cek", "xrefs": []},
    ],
    "strings_truncated": False,
}

STUB_SCRIPT = """#!/usr/bin/env python3
import json, os, sys, time
mode = os.environ.get("STUB_GHIDRA_MODE", "ok")
if mode == "fail":
    print("stub: simulasi kegagalan headless", file=sys.stderr)
    sys.exit(3)
if mode == "sleep":
    time.sleep(120)
args = sys.argv[1:]
i = args.index("GhidraExport.java")
json_out, c_out = args[i + 1], args[i + 2]
data = json.loads(os.environ["STUB_GHIDRA_JSON"])
with open(json_out, "w", encoding="utf-8") as fh:
    json.dump(data, fh)
with open(c_out, "w", encoding="utf-8") as fh:
    fh.write("/* uji */\\n\\n/* ==== 00101100 Java_com_x_Loader_load ==== */\\nvoid a() {}\\n")
    fh.write("\\n/* ==== 00101200 vec_calc ==== */\\nvoid b() {}\\n")
sys.exit(0)
"""


@pytest.fixture
def stub_home(tmp_path, monkeypatch):
    """GHIDRA_HOME palsu berisi analyzeHeadless stub; mengembalikan path-nya."""
    home = tmp_path / "ghidra"
    support = home / "support"
    support.mkdir(parents=True)
    script = support / "analyzeHeadless"
    script.write_text(STUB_SCRIPT, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("GHIDRA_HOME", str(home))
    monkeypatch.setenv("STUB_GHIDRA_JSON", json.dumps(STUB_JSON))
    monkeypatch.setenv("STUB_GHIDRA_MODE", "ok")
    return home


def make_apk(tmp_path: Path, libs: list[tuple[str, int]]) -> Path:
    """APK zip minimal: entri lib/<abi>/<nama> sebesar n byte (isi nol)."""
    apk = tmp_path / "uji.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        for entry, size in libs:
            zf.writestr(entry, b"\0" * size)
        zf.writestr("classes.dex", b"dex")
    return apk


def run_stage(apk: Path, tmp_path: Path, budget_s: int = 300):
    work = tmp_path / "work"
    out = tmp_path / "out"
    work.mkdir(exist_ok=True)
    out.mkdir(exist_ok=True)
    findings = Findings()
    result = ghidra.analyze_ghidra(apk, work, out, findings, lambda msg: None, budget_s=budget_s)
    return result, findings, out, work


# ---------------------------------------------------------------- pemilihan library

def test_select_prioritas_arm64_dan_batas(tmp_path):
    libs = [(f"lib/x86/lib{i}.so", 100) for i in range(5)]
    libs += [(f"lib/arm64-v8a/lib{i}.so", 100) for i in range(3)]
    libs += [("lib/armeabi-v7a/libz.so", 100), ("lib/arm64-v8a/libbig.so", ghidra.MAX_LIB_BYTES + 1)]
    apk = make_apk(tmp_path, libs)
    chosen, skipped = ghidra._select_libs(apk)
    # arm64 dulu, lalu v7a, lalu x86; total terpancang MAX_LIBS; yang raksasa dilewati.
    assert [c["abi"] for c in chosen[:3]] == ["arm64-v8a"] * 3
    assert len(chosen) == ghidra.MAX_LIBS
    assert "arm64-v8a/libbig.so" in skipped   # kegedean ukuran
    assert "x86/lib4.so" in skipped           # ekor terpotong MAX_LIBS
    assert len(skipped) == 2


def test_select_apk_rusak_kosong(tmp_path):
    apk = tmp_path / "rusak.apk"
    apk.write_bytes(b"bukan zip")
    assert ghidra._select_libs(apk) == ([], [])


# ---------------------------------------------------------------- jalur tahap

def test_ghidra_tidak_terpasang_dilewati(tmp_path, monkeypatch):
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path / "tidak-ada"))
    apk = make_apk(tmp_path, [("lib/arm64-v8a/libtest.so", 64)])
    result, findings, _out, _work = run_stage(apk, tmp_path)
    assert result["available"] is False
    assert len(findings) == 0


def test_tanpa_library_native(tmp_path, stub_home):
    apk = make_apk(tmp_path, [])
    result, findings, _out, _work = run_stage(apk, tmp_path)
    assert result["available"] is True
    assert result["libs"] == []
    assert len(findings) == 0


def test_end_to_end_stub(tmp_path, stub_home):
    apk = make_apk(tmp_path, [("lib/arm64-v8a/libtest.so", 2048)])
    result, findings, out, work = run_stage(apk, tmp_path)
    assert result["available"] is True
    (item,) = result["libs"]
    assert item["status"] == "ok"
    assert item["language"] == "AARCH64:LE:64:v8A"
    assert item["functions"] == 2 and item["jni"] == 1 and item["vector_fp"] == 1
    assert item["decompiled"] == 2
    assert result["total_functions"] == 2
    # Artefak tertulis, direktori scratch dibersihkan.
    assert (out / "ghidra" / "libtest.json").is_file()
    assert (out / "ghidra" / "libtest.c").is_file()
    assert not (work / ".ghidra-deep").exists()
    # Temuan sinyal kuat dari hasil ekspor.
    rules = {(f["rule_id"], f["severity"]) for f in findings.items()}
    assert ("native.antidebug_ptrace", "medium") in rules
    assert ("native.dynamic_loading", "low") in rules
    assert ("native.antitamper_strings", "medium") in rules
    assert ("native.urls", "info") in rules
    assert ("native.crypto_constants", "info") in rules
    assert ("native.deep_analysis", "info") in rules
    deep = next(f for f in findings.items() if f["rule_id"] == "native.deep_analysis")
    assert deep["evidence"][0]["file"] == "index/ghidra/libtest.json"


def test_semua_gagal_menandai_failed_tanpa_lempar(tmp_path, stub_home, monkeypatch):
    monkeypatch.setenv("STUB_GHIDRA_MODE", "fail")
    apk = make_apk(tmp_path, [("lib/arm64-v8a/libtest.so", 64)])
    result, _findings, _out, _work = run_stage(apk, tmp_path)
    assert result["failed"] is True
    assert result["libs"][0]["status"] == "error"
    assert result["libs"][0]["error"]  # ekor log kegagalan ikut tercatat


def test_timeout_library(tmp_path, stub_home, monkeypatch):
    monkeypatch.setenv("STUB_GHIDRA_MODE", "sleep")
    monkeypatch.setattr(ghidra, "MIN_PER_LIB_S", 2)
    monkeypatch.setattr(ghidra, "GRACE_S", 1)
    apk = make_apk(tmp_path, [("lib/arm64-v8a/libtest.so", 64)])
    result, _findings, _out, _work = run_stage(apk, tmp_path, budget_s=5)
    assert result["libs"][0]["status"] == "timeout"
    assert result["failed"] is True


def test_budget_habis_library_sisa_ditunda(tmp_path, stub_home, monkeypatch):
    # Library pertama (stub tidur 3 dtk) memakan budget; yang kedua masuk libs_undone.
    monkeypatch.setattr(ghidra, "MIN_PER_LIB_S", 4)
    monkeypatch.setenv("STUB_GHIDRA_MODE", "ok")
    slow = STUB_SCRIPT.replace('mode = os.environ.get("STUB_GHIDRA_MODE", "ok")',
                               'mode = os.environ.get("STUB_GHIDRA_MODE", "ok")\ntime.sleep(3)')
    script = Path(os.environ["GHIDRA_HOME"]) / "support" / "analyzeHeadless"
    script.write_text(slow, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    apk = make_apk(tmp_path, [("lib/arm64-v8a/liba.so", 64), ("lib/arm64-v8a/libb.so", 64)])
    result, _findings, _out, _work = run_stage(apk, tmp_path, budget_s=6)
    assert result["libs"][0]["status"] == "ok"
    assert result.get("libs_undone") == ["arm64-v8a/libb.so"]
    assert result["truncated"] is True


def test_home_passwd_dibuat_sebelum_headless(tmp_path, stub_home, monkeypatch):
    # JVM memakai user.home dari /etc/passwd; LaunchSupport Ghidra menolak jalan bila
    # direktori itu belum ada. Tahap harus membuatnya lebih dulu.
    from types import SimpleNamespace
    home_baru = tmp_path / "home-passwd"
    monkeypatch.setattr(ghidra.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(home_baru)))
    apk = make_apk(tmp_path, [("lib/arm64-v8a/libtest.so", 64)])
    result, _findings, _out, _work = run_stage(apk, tmp_path)
    assert result["libs"][0]["status"] == "ok"
    assert home_baru.is_dir()


def test_bahasa_menyimpang_tercatat(tmp_path, stub_home, monkeypatch):
    data = dict(STUB_JSON, language="x86:LE:64:default")
    monkeypatch.setenv("STUB_GHIDRA_JSON", json.dumps(data))
    apk = make_apk(tmp_path, [("lib/arm64-v8a/libtest.so", 64)])
    result, _findings, _out, _work = run_stage(apk, tmp_path)
    item = result["libs"][0]
    assert item["status"] == "ok"
    assert item["language_mismatch"] == "diharapkan AARCH64:LE:64:v8A"


# ---------------------------------------------------------------- pin image

def test_dockerfile_pin_ghidra_dan_versi():
    dockerfile = (ROOT / "services" / "runner" / "Dockerfile").read_text(encoding="utf-8")
    assert "GHIDRA_VERSION=11.4" in dockerfile
    assert "GHIDRA_SHA256=8b2902bb3166901bc6297a06892eee077c08605be65abfe73ce7aaaafb651632" in dockerfile
    assert "ANALYZER_VERSION=5" in dockerfile
    assert "openjdk-21-jdk-headless" in dockerfile       # Ghidra 11.x wajib JDK, bukan JRE
    assert "MAXMEM=1200M" in dockerfile                  # heap terpancang untuk runner 3 GB
    # JVM mengambil user.home dari /etc/passwd (bukan $HOME); LaunchSupport Ghidra menulis
    # java_home.save ke sana dan gagal total bila tidak bisa ditulis (rootfs read-only).
    assert "--home-dir /tmp/home" in dockerfile
    selftest = (ROOT / "services" / "runner" / "runner-selftest").read_text(encoding="utf-8")
    assert "analyzeHeadless" in selftest
