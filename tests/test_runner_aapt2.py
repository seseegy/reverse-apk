"""Perbaikan `apktool b` di kontainer runner: /tmp runner SENGAJA noexec, jadi aapt2 dipasang di rootfs read-only (/opt/apktool/aapt2).

Akar masalah (terbukti di VPS dan direproduksi di tmpfs noexec nyata): tanpa `--aapt`, apktool 3.0.3 mengekstrak aapt2 dari jarnya ke direktori
sementara lalu menjalankannya; exec di tmpfs noexec ditolak (errno 13). Perbaikan BUKAN menambah `exec` ke tmpfs, melainkan memasang aapt2 yang
bisa dieksekusi di luar /tmp dan mengarahkan apktool ke sana.

Hanya yang bisa diuji TANPA Docker: pemeriksaan teks, wrapper yang dijalankan sungguhan dengan `java` palsu, dan helper galat di runner-selftest.
Bukti nyata (build image, `make runner-selftest`) ada di VPS.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNNER_DOCKERFILE = (ROOT / "services/runner/Dockerfile").read_text(encoding="utf-8")
SELFTEST = (ROOT / "services/runner/runner-selftest").read_text(encoding="utf-8")
BUILD_PY = (ROOT / "scripts/sample-apk/build.py").read_text(encoding="utf-8")
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
AAPT2 = "/opt/apktool/aapt2"


def _joined(text: str) -> list[str]:
    """Instruksi Dockerfile tanpa komentar; baris lanjutan (`\\`) digabung."""
    joined = re.sub(r"\\\n", " ", text)
    return [ln.strip() for ln in joined.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def _tool_run() -> str:
    return next(i for i in _joined(RUNNER_DOCKERFILE) if i.startswith("RUN set -eux") and "apktool.jar" in i)


def _compose_block(name: str) -> str:
    # `networks:` tingkat atas dipotong lebih dulu (layanan terakhir), lalu komentar berindentasi 2 spasi.
    return COMPOSE.split(f"\n  {name}:\n", 1)[1].split("\nnetworks:\n", 1)[0].split("\n  # ", 1)[0]


def tmpfs_entries(block: str) -> list[str]:
    """Isi daftar `tmpfs:` pada sebuah blok layanan (tanpa komentar)."""
    out, inside = [], False
    for line in block.splitlines():
        code = re.sub(r"\s+#.*$", "", line).rstrip()
        if re.match(r"^    tmpfs:\s*$", code):
            inside = True
        elif inside and re.match(r"^      - ", code):
            out.append(code.split("- ", 1)[1].strip().strip("\"'"))
        elif code.strip():
            inside = False
    return out


def has_exec_option(entry: str) -> bool:
    """True bila opsi `exec` (BUKAN `noexec`) ada pada entri tmpfs `/jalur:opsi,opsi`."""
    opts = entry.split(":", 1)[1].split(",") if ":" in entry else []
    return "exec" in [o.strip() for o in opts]


# ================================================================================ (a) Dockerfile runner
def test_dockerfile_extracts_pinned_aapt2_into_read_only_rootfs_before_unzip_is_purged():
    sha = re.search(r"^ARG AAPT2_SHA256=(\S+)$", RUNNER_DOCKERFILE, re.M)
    assert sha and re.fullmatch(r"[0-9a-f]{64}", sha.group(1)), "ARG AAPT2_SHA256 (64 heksadesimal) harus ada"
    run = _tool_run()
    extract = run.index("prebuilt/linux/aapt2")
    assert re.search(rf"unzip -p /opt/apktool/apktool\.jar prebuilt/linux/aapt2 > {AAPT2}\b", run), "aapt2 harus diekstrak dari jar ke /opt/apktool/aapt2"
    verify = f'echo "${{AAPT2_SHA256}}  {AAPT2}" | sha256sum -c -'
    assert verify in run and run.index(verify) > extract, "sha256 aapt2 diverifikasi SETELAH ekstraksi"
    assert f"chmod 0755 {AAPT2}" in run
    assert run.index("unzip -p") < run.index("apt-get purge -y --auto-remove curl unzip"), "ekstraksi harus SEBELUM unzip dibuang"
    # Tidak ada instruksi lain (RUN/COPY/ADD, mis. chown) yang menyentuh /opt/apktool sehingga aapt2 bisa ditulis runner; ENV hanya menyebut jalurnya.
    others = [i for i in _joined(RUNNER_DOCKERFILE) if i != run and "/opt/apktool" in i and re.match(r"(RUN|COPY|ADD)\b", i)]
    assert not others, others


def test_dockerfile_fails_loudly_on_non_x86_64_and_checks_the_elf():
    run = _tool_run()
    assert 'uname -m' in run and "x86_64" in run
    guard = run.index("uname -m")
    assert guard < run.index("curl -fsSL"), "pemeriksaan arsitektur harus sebelum unduhan (gagal cepat)"
    assert "exit 1" in run[guard:run.index("curl -fsSL")], "arsitektur lain harus menggagalkan build, bukan diam-diam"
    assert "GALAT" in run[guard:run.index("curl -fsSL")] and "amd64" in run[guard:run.index("curl -fsSL")], "pesan galat harus menjelaskan"
    # Berkas harus ELF 64-bit x86-64 (sha256 sudah mengikat isinya; ini jaring pengaman bila pin diganti sembarangan) dan bisa dijalankan.
    assert "7f454c46" in run and f"{AAPT2} version" in run


def test_dockerfile_exports_pin_as_env_for_the_selftest():
    assert re.search(r"^\s+AAPT2_SHA256=\$\{AAPT2_SHA256\}", RUNNER_DOCKERFILE, re.M), "selftest membaca pin dari ENV image, bukan menyalinnya"
    assert re.search(r"^\s+AAPT2_PATH=/opt/apktool/aapt2", RUNNER_DOCKERFILE, re.M)


def _write_wrapper(tmp_path: Path) -> Path:
    """Jalankan fragmen `printf ... > /usr/local/bin/apktool` dari Dockerfile APA ADANYA, tetapi menulis ke tmp_path."""
    m = re.search(r"(printf '%s\\n' .*?) > /usr/local/bin/apktool;", _tool_run())
    assert m, "wrapper /usr/local/bin/apktool harus dibuat dengan printf"
    dest = tmp_path / "apktool"
    subprocess.run(["sh", "-c", f"{m.group(1)} > '{dest}'"], check=True)
    dest.chmod(0o755)
    return dest


def _run_wrapper(tmp_path: Path, *args: str) -> list[str]:
    """Kembalikan argumen yang diterima `java` bila wrapper dipanggil dengan args (java palsu mencetak satu argumen per baris)."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    fake = bindir / "java"
    fake.write_text('#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done\n')
    fake.chmod(0o755)
    wrapper = _write_wrapper(tmp_path)
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": "/tmp/home-uji"}
    out = subprocess.run([str(wrapper), *args], capture_output=True, text=True, env=env, check=True)
    return out.stdout.splitlines()


def test_wrapper_inserts_aapt_for_build_subcommand_only(tmp_path):
    for sub in ("b", "build"):
        argv = _run_wrapper(tmp_path, sub, "/w/proj dengan spasi", "-o", "/w/out.apk")
        i = argv.index("/opt/apktool/apktool.jar")
        assert argv[i + 1:] == [sub, "--aapt", AAPT2, "/w/proj dengan spasi", "-o", "/w/out.apk"], argv
        assert "-Duser.home=/tmp/home-uji" in argv and "-Djava.io.tmpdir=/tmp" in argv and "-Xmx2g" in argv
    for args in (["d", "-f", "-o", "/o", "/a.apk"], ["--version"], ["decode", "x.apk"]):
        argv = _run_wrapper(tmp_path, *args)
        assert "--aapt" not in argv, f"{args}: `--aapt` hanya untuk b/build"
        assert argv[argv.index("/opt/apktool/apktool.jar") + 1:] == args


# ================================================================================ (b) penjaga anti-regresi isolasi
def test_no_tmpfs_of_runner_bench_signer_egress_allows_exec():
    """Jangan 'memperbaiki' bug aapt2 dengan menambah `exec` ke tmpfs: runner memproses APK tak tepercaya, /tmp tanpa exec adalah pertahanan berlapis."""
    seen = {}
    for name in ("runner", "bench", "signer", "egress"):
        entries = tmpfs_entries(_compose_block(name))
        seen[name] = entries
        for e in entries:
            assert not has_exec_option(e), f"{name}: tmpfs {e!r} memuat `exec`; perbaiki dengan aapt2 terpasang, bukan melemahkan isolasi"
    assert seen["runner"] == ["/tmp:rw,size=256m,nosuid"], "tmpfs runner berubah; pastikan tetap TANPA exec"
    assert seen["bench"] and seen["signer"], "pembaca tmpfs tidak menemukan entri (penjaga jadi hampa)"
    # Bentuk panjang (`type: tmpfs`) dan --tmpfs di skrip juga tidak boleh membawa exec.
    for name in ("runner", "bench", "signer", "egress"):
        assert "type: tmpfs" not in _compose_block(name), f"{name}: gunakan daftar `tmpfs:` agar penjaga dapat memeriksanya"
    for flag in re.findall(r"--tmpfs\W+([^\s\"',]+(?:,[^\s\"']*)?)", BUILD_PY):
        assert not has_exec_option(flag), flag


def test_exec_option_detector_distinguishes_exec_from_noexec():
    assert has_exec_option("/tmp:rw,exec,size=256m") and has_exec_option("/tmp:exec") and has_exec_option("/tmp:rw,nosuid,exec")
    assert not has_exec_option("/tmp:rw,size=256m,nosuid") and not has_exec_option("/tmp:rw,noexec,nosuid") and not has_exec_option("/tmp")
    block = "  runner:\n    tmpfs:\n      - /tmp:rw,exec  # komentar\n    mem_limit: 1g\n"
    assert tmpfs_entries(block) == ["/tmp:rw,exec"]


# ================================================================================ (c) runner-selftest
def test_selftest_checks_tmp_noexec_and_installed_aapt2():
    assert "noexec" in SELFTEST and "tmp runner noexec" in SELFTEST
    assert "/proc/self/mountinfo" in SELFTEST, "noexec dibaca dari opsi mount /tmp"
    assert "/bin/true" in SELFTEST and "PermissionError" in SELFTEST, "dan dibuktikan dengan percobaan exec sungguhan"
    assert "AAPT2_PATH" in SELFTEST and "AAPT2_SHA256" in SELFTEST and "hashlib" in SELFTEST
    assert "b'\\x7fELF'" in SELFTEST or '\\x7fELF' in SELFTEST
    assert "os.access" in SELFTEST and "os.X_OK" in SELFTEST
    # Pin dibaca dari ENV image, tidak disalin ke skrip.
    assert re.search(r"^ARG AAPT2_SHA256=(\S+)$", RUNNER_DOCKERFILE, re.M).group(1) not in SELFTEST


def test_selftest_runs_apktool_b_through_the_wrapper_like_production():
    assert '["apktool", "b"' in SELFTEST
    assert "apktool.jar" not in SELFTEST and "-jar" not in SELFTEST, "apktool b harus lewat wrapper, bukan java -jar langsung"
    assert "--aapt" in SELFTEST, "selftest juga memastikan wrapper menyisipkan --aapt"


def _selftest_function(name: str):
    tree = ast.parse(SELFTEST)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    ns: dict = {"re": re}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "runner-selftest", "exec"), ns)  # noqa: S102 - fungsi murni dari berkas repo sendiri
    return ns[name]


TRACE = """I: Using Apktool 3.0.3 on proj
I: Building resources with aapt2...
Exception in thread "main" brut.androlib.exceptions.AndrolibException: brut.common.BrutException: could not exec: [/tmp/aapt2_1.tmp, compile]
\tat brut.androlib.res.Aapt2.invoke(Aapt2.java:80)
Caused by: java.io.IOException: Cannot run program "/tmp/aapt2_1.tmp": error=13, Permission denied
\tat java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1170)
\tat java.base/java.lang.ProcessImpl.start(ProcessImpl.java:225)
\t... 5 more
"""


def test_selftest_error_report_keeps_the_root_cause_instead_of_the_stack_tail():
    diagnose = _selftest_function("diagnose")
    msg = diagnose(TRACE)
    assert "Caused by: java.io.IOException" in msg and "error=13, Permission denied" in msg
    assert "ProcessImpl.start" not in msg and "5 more" not in msg, "ekor stack trace yang menyesatkan tidak boleh jadi satu-satunya isi"
    assert "Building resources with aapt2" in msg, "300 karakter pertama keluaran bermakna ikut ditampilkan"
    assert "\n" not in msg
    long = diagnose("x" * 5000)
    assert len(long) < 700
    assert diagnose("") == "(tanpa keluaran)"
    # Tanpa 'Caused by:'/'error=' tetap menampilkan awal keluaran.
    assert "galat biasa" in diagnose("galat biasa\n\tat a.b(C.java:1)\n")


def test_selftest_uses_diagnose_for_the_apktool_b_failure_message():
    block = SELFTEST.split("# 6.", 1)[1]
    assert "diagnose(text)" in block
    assert "[-3:]" not in block, "ekor 3 baris stack trace adalah pelaporan lama yang memotong akar masalah"


# ================================================================================ (d) scripts/sample-apk/build.py
def test_sample_build_script_uses_installed_aapt2():
    cmd = BUILD_PY.split("def main()", 1)[1]
    assert "-jar /opt/apktool/apktool.jar " in cmd and f"--aapt {AAPT2}" in cmd
    assert cmd.index(f"--aapt {AAPT2}") < cmd.index("/w/proj"), "opsi --aapt sebelum argumen posisi"
    assert "tmpfs" in BUILD_PY and "noexec" in BUILD_PY, "komentar menjelaskan mengapa --aapt wajib (tmpfs Docker noexec)"
    assert not has_exec_option(re.search(r'"--tmpfs", "([^"]+)"', cmd).group(1))


# ================================================================================ (e) dokumen
def test_docs_record_noexec_invariant_and_installed_aapt2_pin():
    pin = re.search(r"^ARG AAPT2_SHA256=(\S+)$", RUNNER_DOCKERFILE, re.M).group(1)
    deploy = (ROOT / "docs/deploy.md").read_text(encoding="utf-8")
    prd = (ROOT / "docs/prd/09-bundles-and-workbench.md").read_text(encoding="utf-8")
    assert pin in deploy and AAPT2 in deploy and "noexec" in deploy
    assert "terbukti jalan offline di sandbox" not in prd, "klaim lama (keliru untuk kontainer runner) harus dikoreksi"
    assert "noexec" in prd and AAPT2 in prd
    assert os.path.exists(ROOT / "audit.md") and "noexec" in (ROOT / "audit.md").read_text(encoding="utf-8")
