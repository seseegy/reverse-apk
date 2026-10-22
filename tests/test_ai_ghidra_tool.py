"""Tool AI `analyze_native_library` + `read_native_function`: Ghidra on-demand di bench untuk library PILIHAN AI.

Yang dibuktikan di sini: skema & gerbang (shell), validasi argumen, dispatch ke bench dengan
kind="ghidra" + argv tetap + timeout AI_GHIDRA_TIMEOUT, pembentukan ringkasan (termasuk kegagalan
yang dilaporkan skrip dan status bench bukan-ok), protokol shellspool (kind diteruskan, request
lama tidak berubah), validasi daemon bench (pagat kelas ghidra + entrypoint wajib), dan fungsi murni
skrip bench-ghidra (deteksi ELF, resolusi path, ringkasan). Bench PALSU = WebRig (protokol nyata);
Ghidra/JDK/Landlock nyata dibuktikan `make bench-selftest`, bukan di sini.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from web_rig import WebRig

from app.ai import agent, tools as T
from app.ai.config import load_ai_config
from app.ai.redact import Redactor
from rvcore import shellspool

ROOT = Path(__file__).resolve().parent.parent
SID = 7

SUMMARY = {"ok": True, "library": "libloader.so", "language": "AARCH64:LE:64:v8A", "image_base": "00100000",
           "functions_total": 18, "functions_truncated": False, "jni_functions": ["JNI_OnLoad"],
           "vector_fp_functions": ["vec_formula"], "imports_total": 42, "imports_flagged": ["ptrace"],
           "strings_total": 9, "urls": ["https://contoh.invalid/api"], "crypto_constants": [],
           "decompiled": 9, "artifacts": {"json": "hasil_ai/ghidra/libloader.json", "c": "hasil_ai/ghidra/libloader.c"},
           "duration_s": 12.3}


@pytest.fixture
def rig(tmp_path):
    r = WebRig(tmp_path)
    yield r
    r.stop()


def ctx_for(rig, aid, *, enabled=True, **over):
    cfg = replace(load_ai_config(), shell_enabled=enabled, shell_spool_dir=str(rig.layout.root / "benchspool"), **over)
    return T.ToolContext(aid, ROOT, cfg, rig.conn, Redactor(True), session_id=SID)


def call(ctx, name, **args):
    out, ok = T.run_tool(ctx, name, json.dumps(args))
    if not ok:
        return False, out.split(">", 1)[1].rsplit("</hasil_tool", 1)[0]
    return True, json.loads(out.split("\n", 2)[2].rsplit("\n</hasil_tool>", 1)[0])


def behave_run(result: dict):
    def behave(bench, job):
        assert job["op"] == "run"
        return result
    return behave


def ok_result(summary: dict) -> dict:
    return {"status": "ok", "exit_code": 0, "stdout": json.dumps(summary) + "\n", "stderr": "", "duration_ms": 1234}


# ================================================================================ skema & gerbang
def test_schema_gated_by_shell_like_the_other_bench_tools():
    on = {t["function"]["name"] for t in T.schemas(vision=True, shell=True)}
    off = {t["function"]["name"] for t in T.schemas(vision=True, shell=False)}
    assert "analyze_native_library" in on and "analyze_native_library" not in off
    assert "read_native_function" in on and "read_native_function" not in off
    assert T.GHIDRA_ONLY == frozenset({"analyze_native_library", "read_native_function"})
    spec = next(t["function"] for t in T.schemas(shell=True) if t["function"]["name"] == "analyze_native_library")
    assert spec["parameters"]["required"] == ["library"] and set(spec["parameters"]["properties"]) == {"library"}
    assert spec["parameters"]["additionalProperties"] is False
    spec2 = next(t["function"] for t in T.schemas(shell=True) if t["function"]["name"] == "read_native_function")
    assert spec2["parameters"]["required"] == ["library", "function"]
    assert set(spec2["parameters"]["properties"]) == {"library", "function"}
    assert spec2["parameters"]["additionalProperties"] is False


def test_gate_is_fail_closed_when_shell_is_off(rig):
    aid = rig.analysis_with()
    ok, msg = call(ctx_for(rig, aid, enabled=False), "analyze_native_library", library="lib/libloader.so")
    assert not ok and "tidak diaktifkan" in msg
    assert rig.bench.jobs == []


def test_prompt_block_only_when_shell_on():
    assert "analyze_native_library" not in agent.system_prompt(False)
    on = agent.system_prompt(True)
    assert agent.GHIDRA_PROMPT_BLOCK in on
    assert on.index(agent.BUILD_PROMPT_BLOCK) < on.index(agent.GHIDRA_PROMPT_BLOCK) < on.index("HEMAT PUTARAN")
    assert len(agent.GHIDRA_PROMPT_BLOCK) < 1600


# ================================================================================ validasi argumen
@pytest.mark.parametrize("bad", ["", "../libx.so", "/abs/libx.so", "lib/lib x.so", "bukan-so.txt", "lib//libx.so",
                                 "lib/./libx.so", "lib\\..\\libx.so", "libx.so; rm -rf /"])
def test_bad_library_names_are_rejected_before_bench(rig, bad):
    aid = rig.analysis_with()
    ok, _msg = call(ctx_for(rig, aid), "analyze_native_library", library=bad)
    assert not ok
    assert rig.bench.jobs == []


# ================================================================================ dispatch & ringkasan
def test_dispatch_uses_fixed_argv_kind_and_ghidra_timeout(rig):
    aid = rig.analysis_with()
    rig.bench.behave = behave_run(ok_result(SUMMARY))
    ok, res = call(ctx_for(rig, aid), "analyze_native_library", library="lib/libloader.so")
    assert ok and res["berhasil"] is True
    (job,) = rig.bench.jobs
    assert job["kind"] == "ghidra"
    assert job["command"] == "/usr/local/bin/bench-ghidra lib/libloader.so"
    assert job["timeout"] == 300                       # AI_GHIDRA_TIMEOUT bawaan, BUKAN pagat shell 120
    assert res["jumlah_fungsi"] == 18 and res["fungsi_jni"] == ["JNI_OnLoad"]
    assert res["fungsi_vektor_fp"] == ["vec_formula"] and res["impor_penting"] == ["ptrace"]
    assert res["artefak"] == {"json": "$WS/hasil_ai/ghidra/libloader.json", "c": "$WS/hasil_ai/ghidra/libloader.c"}
    assert "shell_run" in res["catatan"]               # model diarahkan membaca .c berkeping


def test_script_reported_failure_is_returned_as_data(rig):
    aid = rig.analysis_with()
    rig.bench.behave = behave_run(ok_result({"ok": False, "error": "bukan berkas ELF"}))
    ok, res = call(ctx_for(rig, aid), "analyze_native_library", library="libx.so")
    assert ok and res["berhasil"] is False and "ELF" in res["alasan"]


def test_bench_timeout_status_is_returned_as_data(rig):
    aid = rig.analysis_with()
    rig.bench.behave = behave_run({"status": "timeout", "exit_code": None, "stdout": "", "stderr": "",
                                   "duration_ms": 300000, "message": "melebihi batas waktu 300 detik; proses dihentikan"})
    ok, res = call(ctx_for(rig, aid), "analyze_native_library", library="libx.so")
    assert ok and res["berhasil"] is False and res["status"] == "timeout"


def test_unreadable_bench_output_is_a_tool_error(rig):
    aid = rig.analysis_with()
    rig.bench.behave = behave_run({"status": "ok", "exit_code": 0, "stdout": "bukan json sama sekali\n", "stderr": "", "duration_ms": 5})
    ok, msg = call(ctx_for(rig, aid), "analyze_native_library", library="libx.so")
    assert not ok and "tidak terbaca" in msg


def test_result_stays_within_the_tool_char_budget(rig):
    aid = rig.analysis_with()
    big = dict(SUMMARY, jni_functions=[f"Java_com_x_Fungsi{i}" for i in range(300)],
               vector_fp_functions=[f"vec{i}" for i in range(300)], urls=[f"https://contoh{i}.invalid/x" for i in range(50)])
    rig.bench.behave = behave_run(ok_result(big))
    out, ok = T.run_tool(ctx_for(rig, aid), "analyze_native_library", json.dumps({"library": "lib/libloader.so"}))
    assert ok and len(out) <= 14000 + 2000 + 400       # pagat run_tool (max_tool_chars + margin) + pembungkus


def test_parse_ghidra_stdout_picks_the_contract_line():
    noisy = 'Picked up JAVA_TOOL_OPTIONS: -Duser.home=/tmp/x\n{"bukan": "kontrak"}\n' + json.dumps(SUMMARY) + "\n"
    assert T._parse_ghidra_stdout(noisy)["library"] == "libloader.so"
    assert T._parse_ghidra_stdout("tidak ada json") is None


# ================================================================================ protokol shellspool
def test_run_request_kind_passthrough_and_default_unchanged():
    plain = shellspool.build_run_request(3, "ls", 60, None)
    assert "kind" not in plain                          # request lama persis sama seperti sebelum fitur ini
    marked = shellspool.build_run_request(3, "/usr/local/bin/bench-ghidra libx.so", 300, None, kind="ghidra")
    assert marked["kind"] == "ghidra" and marked["timeout"] == 300
    with pytest.raises(ValueError):
        shellspool.build_run_request(3, "ls", 60, None, kind="sembarang")


# ================================================================================ daemon bench: validasi kelas ghidra
def _load_daemon():
    for sub in ("services", "services/bench"):
        p = str(ROOT / sub)
        if p not in sys.path:
            sys.path.insert(0, p)
    loader = importlib.machinery.SourceFileLoader("bench_daemon_uji", str(ROOT / "services" / "bench" / "bench-daemon"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_daemon_clamps_ghidra_by_its_own_cap_and_requires_the_fixed_entry():
    d = _load_daemon()
    base = {"analysis_id": 3, "sha256": None}
    _aid, _cmd, timeout, _sha, kind = d.validate_run({**base, "command": "ls", "timeout": 9999})
    assert timeout == 120 and kind is None              # shell biasa tetap diclamp pagat umum
    _aid, _cmd, timeout, _sha, kind = d.validate_run(
        {**base, "command": "/usr/local/bin/bench-ghidra lib/libx.so", "timeout": 9999, "kind": "ghidra"})
    assert timeout == d.GHIDRA_MAX_TIMEOUT == 300 and kind == "ghidra"
    with pytest.raises(ValueError):
        d.validate_run({**base, "command": "sleep 999", "timeout": 9999, "kind": "ghidra"})       # kind tanpa entry tetap: ditolak
    with pytest.raises(ValueError):
        d.validate_run({**base, "command": "/usr/local/bin/bench-ghidra libx.so", "timeout": 10, "kind": "lain"})


# ================================================================================ skrip bench-ghidra: fungsi murni
def _load_bench_ghidra():
    loader = importlib.machinery.SourceFileLoader("bench_ghidra_uji", str(ROOT / "services" / "bench" / "bench-ghidra"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _elf(machine: int, data: int = 1) -> bytes:
    return b"\x7fELF" + bytes([2, data, 1]) + b"\x00" * 9 + b"\x02\x00" + machine.to_bytes(2, "little") + b"\x00" * 32


def test_detect_language():
    g = _load_bench_ghidra()
    assert g.detect_language(_elf(183)) == ("aarch64", "AARCH64:LE:64:v8A")
    assert g.detect_language(_elf(40))[1] == "ARM:LE:32:v7"
    for bad in (b"teks biasa", _elf(183, data=2), _elf(999)):
        with pytest.raises(ValueError):
            g.detect_language(bad)


def test_resolve_library_stays_inside_workspace(tmp_path):
    g = _load_bench_ghidra()
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "libx.so").write_bytes(_elf(183))
    assert g.resolve_library("lib/libx.so", tmp_path).name == "libx.so"
    for bad in ("../libx.so", "/etc/libx.so", "lib/hilang.so", "libx.txt"):
        with pytest.raises(ValueError):
            g.resolve_library(bad, tmp_path)
    outside = tmp_path.parent / "luar.so"
    outside.write_bytes(_elf(183))
    (tmp_path / "lib" / "tautan.so").symlink_to(outside)
    with pytest.raises(ValueError):
        g.resolve_library("lib/tautan.so", tmp_path)     # symlink keluar ruang kerja ditolak


def test_build_summary_shape_and_caps():
    g = _load_bench_ghidra()
    data = {"language": "AARCH64:LE:64:v8A", "image_base": "00100000", "functions_truncated": False,
            "functions": [{"name": "JNI_OnLoad", "jni": True, "vector_fp": False},
                          {"name": "vec", "jni": False, "vector_fp": True},
                          {"name": "biasa", "jni": False, "vector_fp": False}],
            "imports": ["ptrace", "dlopen", "printf"],
            "strings": [{"value": "kunjungi https://a.invalid/x dan https://a.invalid/x"}, {"value": "halo"}],
            "crypto_constants": ["aes_sbox@001234"]}
    s = g.build_summary(data, "libx.so", "libx", decompiled=2, duration_s=3.21)
    assert s["ok"] is True and s["functions_total"] == 3 and s["jni_functions"] == ["JNI_OnLoad"]
    assert s["imports_flagged"] == ["ptrace", "dlopen"] and s["urls"] == ["https://a.invalid/x"]
    assert s["crypto_constants"] == ["aes_sbox"] and s["artifacts"]["c"] == "hasil_ai/ghidra/libx.c"


def test_bench_ghidra_pagar_ukuran_dan_jumlah_fungsi():
    # Nilai yang diminta pemilik 22 Okt 2026: library s.d. 200 MB, dekompilasi s.d. 1000 fungsi.
    # Paritas dengan analyzer runner dijaga tes di test_analyzer_ghidra.py (nilai yang sama di sana).
    g = _load_bench_ghidra()
    assert g.MAX_LIB_BYTES == 200 * 1024 * 1024
    assert g.MAX_DECOMPILE == 1000


def test_bench_ghidra_env_mengamankan_home_dan_tmpdir(tmp_path, monkeypatch):
    # Umpan balik produksi: java.io.tmpdir bawaan (/tmp) tertutup Landlock — env Ghidra
    # WAJIB mengarahkan user.home + tmpdir ke $HOME terkurung (scratch), dan JAVA_HOME
    # hanya diisi dari kandidat yang berkas javanya benar ada (tidak menimpa yang ter-set).
    g = _load_bench_ghidra()
    env = g._ghidra_env({"HOME": "/scratch-x", "PATH": "/usr/bin"}, "/fallback")
    assert "-Duser.home=/scratch-x" in env["JAVA_TOOL_OPTIONS"]
    assert "-Djava.io.tmpdir=/scratch-x" in env["JAVA_TOOL_OPTIONS"]
    env2 = g._ghidra_env({"PATH": "/usr/bin"}, "/fallback")
    assert "-Duser.home=/fallback" in env2["JAVA_TOOL_OPTIONS"]
    assert "-Djava.io.tmpdir=/fallback" in env2["JAVA_TOOL_OPTIONS"]
    env3 = g._ghidra_env({"HOME": "/s", "JAVA_HOME": "/jvm/lain"}, "/fallback")
    assert env3["JAVA_HOME"] == "/jvm/lain"
    jvm = tmp_path / "jvm"
    (jvm / "bin").mkdir(parents=True)
    (jvm / "bin" / "java").touch()
    monkeypatch.setattr(g, "JVM_CANDIDATES", (str(tmp_path / "tidak-ada"), str(jvm)))
    env4 = g._ghidra_env({"HOME": "/s"}, "/fallback")
    assert env4["JAVA_HOME"] == str(jvm)


# ================================================================================ read_native_function: dispatch
READ_SUMMARY = {"ok": True, "library": "libloader.so", "function": "vec_formula", "address": "00102000",
                "code": "void vec_formula(float *a) {\n  a[0] = a[0] * 2.0f;\n}", "truncated": False,
                "line_start": 12, "line_end": 14, "total_lines": 3, "artifact": "hasil_ai/ghidra/libloader.c"}


def test_read_native_function_dispatch_dan_kode_utuh(rig):
    aid = rig.analysis_with()
    rig.bench.behave = behave_run(ok_result(READ_SUMMARY))
    ok, res = call(ctx_for(rig, aid), "read_native_function", library="lib/libloader.so", function="vec_formula")
    assert ok and res["berhasil"] is True
    (job,) = rig.bench.jobs
    assert job["kind"] == "ghidra"
    assert job["command"] == "/usr/local/bin/bench-ghidra fungsi lib/libloader.so vec_formula"
    assert res["kode_c"] == READ_SUMMARY["code"] and res["fungsi"] == "vec_formula" and res["alamat"] == "00102000"
    assert res["terpotong"] is False and "ASLI" in res["catatan"]


def test_read_native_function_gate_dan_validasi(rig):
    aid = rig.analysis_with()
    ok, msg = call(ctx_for(rig, aid, enabled=False), "read_native_function", library="lib/libloader.so", function="vec_formula")
    assert not ok and "tidak diaktifkan" in msg
    ok, _ = call(ctx_for(rig, aid), "read_native_function", library="../libx.so", function="vec_formula")
    assert not ok
    ok, _ = call(ctx_for(rig, aid), "read_native_function", library="lib/libloader.so", function="")
    assert not ok
    assert rig.bench.jobs == []


def test_read_native_function_kegagalan_skrip_jadi_data(rig):
    aid = rig.analysis_with()
    rig.bench.behave = behave_run(ok_result({"ok": False, "error": "artefak dekompilasi libloader.c belum ada"}))
    ok, res = call(ctx_for(rig, aid), "read_native_function", library="lib/libloader.so", function="vec_formula")
    assert ok and res["berhasil"] is False and "belum ada" in res["alasan"]


# ================================================================================ bench-ghidra mode fungsi: potong per fungsi
C_ARTIFACT = ("/* Dekompilasi Ghidra untuk libx.so */\n"
              "/* ==== 00101000 JNI_OnLoad [jni] ==== */\n"
              "jint JNI_OnLoad(void) { return 1; }\n"
              "\n"
              "/* ==== 00102000 vec_formula [vektor-fp] ==== */\n"
              "void vec_formula(float *a) {\n  a[0] = a[0] * 2.0f;\n}\n"
              "\n"
              "/* ==== 00103000 vec_helper ==== */\n"
              "void vec_helper(void) { }\n"
              "/* total didekompilasi: 3 */\n")


def _ws_dengan_artefak(tmp_path, monkeypatch, isi=C_ARTIFACT):
    g = _load_bench_ghidra()
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "libx.so").write_bytes(_elf(183))
    out = tmp_path / "hasil_ai" / "ghidra"
    out.mkdir(parents=True)
    if isi is not None:
        (out / "libx.c").write_text(isi, encoding="utf-8")
    monkeypatch.setenv("WS", str(tmp_path))
    return g


def _fungsi_json(g, capsys, *argv):
    assert g.read_function(*argv) == 0
    return json.loads(capsys.readouterr().out.strip().splitlines()[-1])


def test_fungsi_exact_dan_kode_utuh(tmp_path, monkeypatch, capsys):
    g = _ws_dengan_artefak(tmp_path, monkeypatch)
    r = _fungsi_json(g, capsys, "lib/libx.so", "vec_formula")
    assert r["ok"] is True and r["function"] == "vec_formula" and r["address"] == "00102000"
    assert "a[0] = a[0] * 2.0f;" in r["code"] and r["truncated"] is False
    assert r["artifact"] == "hasil_ai/ghidra/libx.c" and r["line_start"] < r["line_end"]


def test_fungsi_substring_unik_dan_ambigu(tmp_path, monkeypatch, capsys):
    g = _ws_dengan_artefak(tmp_path, monkeypatch)
    r = _fungsi_json(g, capsys, "lib/libx.so", "JNI_On")
    assert r["ok"] is True and r["function"] == "JNI_OnLoad"
    r = _fungsi_json(g, capsys, "lib/libx.so", "vec")
    assert r["ok"] is False and "ambigu" in r["error"] and "vec_formula" in r["error"]


def test_fungsi_tidak_ada_dan_artefak_belum_ada(tmp_path, monkeypatch, capsys):
    g = _ws_dengan_artefak(tmp_path, monkeypatch)
    r = _fungsi_json(g, capsys, "lib/libx.so", "tidak_ada")
    assert r["ok"] is False and "tidak ada di dekompilasi" in r["error"] and "JNI_OnLoad" in r["error"]
    (tmp_path / "lib" / "liby.so").write_bytes(_elf(183))
    r = _fungsi_json(g, capsys, "lib/liby.so", "vec_formula")
    assert r["ok"] is False and "belum ada" in r["error"]


def test_fungsi_terpotong_pada_batas_baris(tmp_path, monkeypatch, capsys):
    g = _ws_dengan_artefak(tmp_path, monkeypatch)
    monkeypatch.setattr(g, "MAX_CODE_CHARS", 30)
    r = _fungsi_json(g, capsys, "lib/libx.so", "vec_formula")
    assert r["ok"] is True and r["truncated"] is True
    assert len(r["code"]) <= 30 and r["total_lines"] == 3
