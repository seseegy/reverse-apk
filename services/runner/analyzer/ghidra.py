"""Analisis native mendalam via Ghidra headless (tahap 3b, sesudah sinyal).

Menjalankan `analyzeHeadless` (auto-analysis penuh + skrip ekspor GhidraExport.java)
pada sebagian library .so dari APK, lalu menuangkan hasilnya ke:
  - artefak per library di out/ghidra/<lib>.json (fungsi + call graph ringkas,
    impor, string + xref, konstanta kripto) dan out/ghidra/<lib>.c (dekompilasi);
  - temuan kategori `native` untuk sinyal kuat saja (anti-debug, anti-tamper,
    pemuatan dinamis, URL, konstanta kripto);
  - ringkasan summary["native_deep"].

Sifat tahap ini TIDAK FATAL: kegagalan per library dicatat di ringkasan; bila semua
library yang dicoba gagal, ringkasan membawa flag "failed" agar __main__ menandainya
di failures[] (rincian per library tetap tersimpan). Bila Ghidra tidak terpasang,
tahap dilewati diam-diam (available=False) — image runner memasangnya dan
runner-selftest yang menjaga keberadaannya.

Pagar sumber daya (runner: 3 GB RAM / 2 CPU):
  - timeout TETAP PER_LIB_S (240 dtk) per library; budget total tahap = PER_LIB_S x
    jumlah library terpilih (maks 8 -> 1920 dtk). Rantai di atasnya sudah diselaraskan:
    TIMEOUT_ANALYZE worker 2400 dtk (1920 Ghidra + sisa untuk sub-tahap analyzer lain)
    dan JOB_TIMEOUT 6300 dtk (600 apktool + 2400 jadx + 2400 analyze + sisa);
  - heap JVM dipatok lewat MAXMEM di skrip analyzeHeadless image (lihat Dockerfile);
  - jumlah & ukuran library dibatasi; prioritas ABI arm64-v8a lebih dulu.
Isi .so berasal dari APK yang TIDAK TEPERCAYA: .so tidak pernah dieksekusi — Ghidra
hanya menganalisisnya secara statis di dalam runner yang terisolasi (tanpa jaringan).
"""

from __future__ import annotations

import json
import os
import pwd
import re
import shutil
import signal
import subprocess
import time
import zipfile
from pathlib import Path

from .common import Findings

PER_LIB_S = 240           # timeout tetap per library (4 menit); total tahap = ini x jumlah library
MAX_LIBS = 8
MAX_LIB_BYTES = 200 * 1024 * 1024   # paritas pagar bench-ghidra (dinaikkan 22 Okt atas permintaan pemilik: 64 MB -> 200 MB)
MAX_DECOMPILE = 1000      # fungsi didekompilasi per library (prioritas di skrip ekspor; dulu 200)
MIN_PER_LIB_S = 30        # sisa budget di bawah ini -> library berikutnya tidak dicoba
GRACE_S = 30              # kelonggaran di atas timeout analisis untuk start/pembacaan hasil JVM

ABI_RANK = {"arm64-v8a": 0, "armeabi-v7a": 1, "armeabi": 2, "x86_64": 3, "x86": 4}
EXPECTED_LANGUAGE = {
    "arm64-v8a": "AARCH64:LE:64:v8A",
    "armeabi-v7a": "ARM:LE:32:v7",
    "armeabi": "ARM:LE:32:v7",
    "x86_64": "x86:LE:64:default",
    "x86": "x86:LE:32:default",
}

_URL_RE = re.compile(r"https?://[^\s\"'<>]{4,200}")
_ANTITAMPER_MARKERS = ("frida", "xposed", "substrate", "magisk", "supersu", "/system/bin/su", "rootbeer")
_IMPORT_SIGNALS = (
    # (nama impor, rule_id, severity, judul, deskripsi)
    ("ptrace", "native.antidebug_ptrace", "medium",
     "Kode native memakai ptrace (indikasi anti-debug)",
     "ptrace(PTRACE_TRACEME) lazim dipakai library native untuk menolak debugger. "
     "Kehadirannya sendiri bukan bukti berbahaya, tetapi pola umum pada proteksi/anti-tamper."),
    ("dlopen", "native.dynamic_loading", "low",
     "Kode native memuat library secara dinamis (dlopen)",
     "Pemuatan dinamis menyembunyikan dependensi dari daftar impor statis; fungsi yang sebenarnya "
     "dipakai diputuskan saat runtime lewat dlsym."),
    ("system", "native.shell_exec", "medium",
     "Kode native dapat menjalankan perintah shell (system/popen)",
     "Impor system/popen memberi kode native kemampuan mengeksekusi perintah; periksa string "
     "perintah dan pemanggilnya di artefak Ghidra."),
    ("popen", "native.shell_exec", "medium",
     "Kode native dapat menjalankan perintah shell (system/popen)",
     "Impor system/popen memberi kode native kemampuan mengeksekusi perintah; periksa string "
     "perintah dan pemanggilnya di artefak Ghidra."),
    ("mprotect", "native.mprotect_exec", "low",
     "Kode native mengubah izin halaman memori (mprotect)",
     "mprotect sering dipakai packer/JIT untuk membuat memori bisa dieksekusi saat runtime; "
     "kode yang sebenarnya berjalan mungkin tidak terlihat statis."),
)


def _ghidra_home() -> Path:
    return Path(os.environ.get("GHIDRA_HOME", "/opt/ghidra"))


def _select_libs(apk: Path) -> tuple[list[dict], list[str]]:
    """Pilih .so yang dianalisis: urut prioritas ABI lalu nama; kembalikan (terpilih, dilewati)."""
    try:
        with zipfile.ZipFile(apk) as zf:
            infos = [i for i in zf.infolist()
                     if i.filename.startswith("lib/") and i.filename.endswith(".so")
                     and len(i.filename.split("/")) == 3]
    except (zipfile.BadZipFile, OSError):
        return [], []
    entries = []
    for i in infos:
        _, abi, name = i.filename.split("/")
        entries.append({"entry": i.filename, "abi": abi, "name": name, "size": i.file_size})
    entries.sort(key=lambda e: (ABI_RANK.get(e["abi"], 9), e["name"]))
    chosen, skipped = [], []
    for e in entries:
        if len(chosen) >= MAX_LIBS or e["size"] > MAX_LIB_BYTES:
            skipped.append(f"{e['abi']}/{e['name']}")
        else:
            chosen.append(e)
    return chosen, skipped


def _extract(apk: Path, entry: str, dest: Path) -> bool:
    try:
        with zipfile.ZipFile(apk) as zf, zf.open(entry) as src, open(dest, "wb") as fh:
            shutil.copyfileobj(src, fh, 1024 * 1024)
        return True
    except (zipfile.BadZipFile, OSError, KeyError):
        return False


def _run_headless(headless: Path, proj_dir: Path, lib_path: Path,
                  json_out: Path, c_out: Path, timeout_s: int, log) -> tuple[int | None, str]:
    """Jalankan analyzeHeadless untuk satu library. (None, log) bila timeout/dibunuh."""
    script_dir = Path(__file__).resolve().parent
    cmd = [str(headless), str(proj_dir), "RvNative", "-import", str(lib_path),
           "-scriptPath", str(script_dir),
           "-postScript", "GhidraExport.java", str(json_out), str(c_out), str(MAX_DECOMPILE),
           "-deleteProject", "-analysisTimeoutPerFile", str(timeout_s)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=timeout_s + GRACE_S)
        return proc.returncode, out or ""
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        out, _ = proc.communicate()
        log(f"W: Ghidra timeout ({timeout_s} dtk) pada {lib_path.name}; proses dibunuh")
        return None, out or ""


def _tail(text: str, n: int = 300) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return " | ".join(lines[-3:])[:n] if lines else ""


def _emit_findings(lib: str, data: dict, findings: Findings, art_rel: str) -> dict:
    """Temuan sinyal kuat dari satu library + hitungan ringkas untuk summary."""
    imports = set(data.get("imports") or [])
    funcs = data.get("functions") or []
    strings = data.get("strings") or []
    jni = [f for f in funcs if f.get("jni")]
    vector = [f for f in funcs if f.get("vector_fp")]

    for name, rule_id, severity, title, desc in _IMPORT_SIGNALS:
        if name in imports:
            findings.add(category="native", severity=severity, rule_id=rule_id,
                         title=f"{title} — {lib}", key=f"{lib}:{name}",
                         file=art_rel, snippet=f"import {name}",
                         description=desc + f" (library: {lib})")

    tamper = [s.get("value", "") for s in strings
              if any(m in s.get("value", "").lower() for m in _ANTITAMPER_MARKERS)]
    if tamper:
        findings.add(category="native", severity="medium", rule_id="native.antitamper_strings",
                     title=f"String anti-tamper/root di kode native {lib}: " + ", ".join(tamper[:3]),
                     key=lib, file=art_rel, snippet=tamper[0][:240],
                     description="String rujukan alat rooting/instrumentasi di library native mengindikasikan "
                                 "pemeriksaan lingkungan (anti-Frida/anti-root) di dalam kode native.")

    urls = sorted({u.rstrip(").,;") for s in strings for u in _URL_RE.findall(s.get("value", ""))})
    if urls:
        findings.add(category="native", severity="info", rule_id="native.urls",
                     title=f"{len(urls)} URL di kode native {lib}", key=lib,
                     file=art_rel, snippet=urls[0],
                     description="URL yang tertanam di library native (tidak terlihat dari pemindaian "
                                 "string Java/smali): " + ", ".join(urls[:5]))

    crypto = data.get("crypto_constants") or []
    if crypto:
        findings.add(category="native", severity="info", rule_id="native.crypto_constants",
                     title=f"Konstanta kripto dikenal di {lib}: " + ", ".join(c.split("@")[0] for c in crypto),
                     key=lib, file=art_rel, snippet=crypto[0],
                     description="Pola byte konstanta kriptografi standar ditemukan di memori library; "
                                 "menandakan implementasi kripto tertanam (mis. AES/SHA-256) di kode native.")

    findings.add(category="native", severity="info", rule_id="native.deep_analysis",
                 title=f"Analisis native mendalam {lib}: {len(funcs)} fungsi, "
                       f"{len(jni)} ekspor JNI, {len(vector)} fungsi FP vektor",
                 key=lib, file=art_rel,
                 description="Dekompilasi C, daftar fungsi + call graph, string + xref tersedia di "
                             f"artefak {art_rel} dan berkas .c pendampingnya.")
    return {"functions": len(funcs), "jni": len(jni), "vector_fp": len(vector),
            "imports": len(imports), "strings": len(strings), "urls": len(urls)}


def analyze_ghidra(apk: Path, work: Path, out: Path, findings: Findings, log,
                   budget_s: int | None = None) -> dict:
    """Tahap 3b. Mengembalikan dict untuk summary["native_deep"].

    budget_s None = bawaan produksi: PER_LIB_S per library terpilih. Nilai eksplisit
    (tes) menjadi pagat total tahap.
    """
    headless = _ghidra_home() / "support" / "analyzeHeadless"
    if not headless.is_file():
        log("I: Ghidra tidak terpasang; analisis native mendalam dilewati")
        return {"available": False, "reason": "analyzeHeadless tidak ditemukan"}

    chosen, skipped = _select_libs(apk)
    if budget_s is None:
        budget_s = PER_LIB_S * len(chosen)
    result: dict = {"available": True, "libs": [], "libs_skipped": skipped,
                    "budget_s": budget_s, "per_lib_s": PER_LIB_S, "total_functions": 0}
    if not chosen:
        return result

    # JVM mengambil user.home dari /etc/passwd (BUKAN $HOME) dan LaunchSupport Ghidra
    # menolak berjalan bila direktori itu belum ada: ia menyimpan java_home.save di
    # <user.home>/.config/ghidra/. Pastikan ada sebelum headless dipanggil.
    try:
        Path(pwd.getpwuid(os.getuid()).pw_dir).mkdir(parents=True, exist_ok=True)
    except (OSError, KeyError):
        pass

    scratch = work / ".ghidra-deep"
    proj_dir = scratch / "proj"
    libs_dir = scratch / "libs"
    art_dir = out / "ghidra"
    try:
        proj_dir.mkdir(parents=True, exist_ok=True)   # analyzeHeadless menuntut dir proyek SUDAH ada
        libs_dir.mkdir(parents=True, exist_ok=True)
        art_dir.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + budget_s
        attempted = succeeded = 0
        for idx, entry in enumerate(chosen):
            remaining = int(deadline - time.monotonic())
            if remaining < MIN_PER_LIB_S:
                result.setdefault("libs_undone", []).append(f"{entry['abi']}/{entry['name']}")
                continue
            stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", entry["name"][:-3])  # buang ".so"
            lib_path = libs_dir / f"{entry['abi']}__{stem}.so"
            if not _extract(apk, entry["entry"], lib_path):
                continue
            attempted += 1
            # Timeout per library: tetap PER_LIB_S, dipotong sisa budget total tahap.
            per_lib = max(MIN_PER_LIB_S, min(PER_LIB_S, remaining))
            json_tmp = scratch / f"{stem}.json"
            c_tmp = scratch / f"{stem}.c"
            t0 = time.monotonic()
            rc, output = _run_headless(headless, proj_dir, lib_path, json_tmp, c_tmp, per_lib, log)
            dur = round(time.monotonic() - t0, 1)
            item: dict = {"lib": entry["name"], "abi": entry["abi"], "size": entry["size"],
                          "duration_s": dur}
            data = None
            if rc == 0 and json_tmp.is_file():
                try:
                    data = json.loads(json_tmp.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    data = None
            if data is None:
                item["status"] = "timeout" if rc is None else "error"
                item["error"] = _tail(output)
                log(f"W: Ghidra gagal pada {entry['name']} ({item['status']})")
            else:
                succeeded += 1
                art_json = art_dir / f"{stem}.json"
                shutil.copyfile(json_tmp, art_json)
                decompiled = 0
                if c_tmp.is_file():
                    shutil.copyfile(c_tmp, art_dir / f"{stem}.c")
                    try:
                        decompiled = c_tmp.read_text(encoding="utf-8", errors="replace").count("\n/* ==== ")
                    except OSError:
                        decompiled = 0
                counts = _emit_findings(entry["name"], data, findings,
                                        f"index/ghidra/{stem}.json")
                item.update(counts)
                item["language"] = data.get("language")
                item["image_base"] = data.get("image_base")
                item["decompiled"] = decompiled
                item["status"] = "ok"
                expected = EXPECTED_LANGUAGE.get(entry["abi"])
                if expected and data.get("language") != expected:
                    item["language_mismatch"] = f"diharapkan {expected}"
                result["total_functions"] += counts["functions"]
                log(f"I: Ghidra {entry['name']}: {counts['functions']} fungsi, "
                    f"{decompiled} didekompilasi, {dur} dtk")
            result["libs"].append(item)
        result["truncated"] = bool(skipped or result.get("libs_undone"))
        if attempted and not succeeded:
            # Semua percobaan gagal: rincian per library tetap dipertahankan di ringkasan;
            # __main__ menandai tahap ini di failures[] lewat flag ini.
            result["failed"] = True
            log("E: semua library gagal dianalisis Ghidra")
        return result
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
