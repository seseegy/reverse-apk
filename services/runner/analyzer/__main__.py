"""Titik masuk analisis statis: python -m analyzer --apk X --work W --out W/index

Kode keluar: 0 = sukses penuh, 2 = selesai tetapi ada sub-langkah gagal (hasil parsial tetap ditulis), lainnya = gagal.
`done.json` ditulis TERAKHIR dan atomik; ketiadaannya berarti analisis tidak lengkap.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from pathlib import Path

from rvcore.fsutil import atomic_write_json

from . import VERSION, callgraph
from .common import Findings
from .index import IndexWriter
from .scan import Scanner
from .signals import analyze_native, analyze_network_config, analyze_obfuscation, scan_sensitive_assets
from .signing import analyze_signing


def log(msg: str) -> None:
    print(msg, flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    apk, work, out = Path(a.apk), Path(a.work), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tmp = out / ".tmp"
    t0 = time.monotonic()
    failures: list[str] = []
    findings = Findings()
    summary: dict = {"analyzer_version": VERSION}

    manifest = None
    mpath = work / "manifest.json"
    try:
        if mpath.is_file() and not mpath.is_symlink() and mpath.stat().st_size < 8 * 1024 * 1024:
            manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = None

    # --- 1. indeks + pemindaian kode & string
    index = IndexWriter(out)
    stats = None
    try:
        log("I: Membangun indeks & memindai kode…")
        scanner = Scanner(work, index, findings, log)
        scanner.run()
        stats = scanner.stats
    except Exception as exc:  # noqa: BLE001 - satu langkah gagal tidak boleh menghentikan yang lain
        failures.append("scan")
        log(f"E: pemindaian kode gagal: {type(exc).__name__}: {exc}")
        traceback.print_exc()

    # --- 1b. call graph & hierarki class dari smali (tidak fatal: tanpa ini tool xref/jalur dimatikan, sisanya jalan)
    cg_state = "failed"
    try:
        log("I: Membangun call graph dari smali…")
        cg = callgraph.build(work, index.conn, log)
        summary["callgraph"] = cg
        cg_state = "complete" if cg["complete"] else "partial"
    except Exception as exc:  # noqa: BLE001
        failures.append("callgraph")
        log(f"E: call graph gagal: {type(exc).__name__}: {exc}")
        traceback.print_exc()

    # --- 2. sertifikat penanda tangan
    try:
        log("I: Membaca tanda tangan & sertifikat…")
        summary["signing"] = analyze_signing(apk, findings, log)
    except Exception as exc:  # noqa: BLE001
        failures.append("signing")
        log(f"E: analisis tanda tangan gagal: {type(exc).__name__}: {exc}")
        summary["signing"] = {"schemes": [], "certificates": [], "error": True}

    # --- 3. native, obfuscation, konfigurasi jaringan, aset sensitif
    native = {"libs": {}, "packers": []}
    try:
        native = analyze_native(apk, findings)
        summary["native"] = native
        if stats is not None:
            summary["obfuscation"] = analyze_obfuscation(stats, native["packers"], findings)
        summary["network_config"] = analyze_network_config(work, manifest, findings)
        scan_sensitive_assets(work, findings)
    except Exception as exc:  # noqa: BLE001
        failures.append("signals")
        log(f"E: analisis sinyal gagal: {type(exc).__name__}: {exc}")

    # --- 4. ringkasan & penutupan
    if stats is not None:
        summary["code"] = {
            "java_files": stats.java_files, "app_classes": stats.app_classes, "lib_classes": stats.lib_classes,
            "resource_files": stats.resource_files, "decompile_failures": stats.decompile_failures,
            "methods_not_decompiled": stats.methods_not_decompiled, "failed_samples": stats.failed_samples,
            "smali_fallback_files": stats.smali_fallback_files, "skipped_large": stats.skipped_large,
            "smali_only_files": stats.smali_only_files, "smali_only_samples": stats.smali_only_samples, "per_dex": stats.per_dex,
        }
        summary["network"] = {
            "stack": stats.stack, "retrofit": stats.retrofit, "base_urls": stats.base_urls, "pins": stats.pins,
            "string_counts": stats.string_counts,
        }
        if stats.smali_only_files:
            findings.add(category="obfuscation", severity="low" if stats.smali_only_files > max(50, stats.app_classes // 20) else "info",
                         rule_id="coverage.jadx_missing_classes",
                         title=f"{stats.smali_only_files} class aplikasi tidak dihasilkan jadx (hanya ada sebagai smali)",
                         key="missing",
                         description="Class ini ada di bytecode (smali) tetapi tidak muncul di Java hasil jadx, biasanya karena jadx "
                                     "gagal atau melewati sebagian dex. String, secret, dan URL di dalamnya tetap dipindai dari smali "
                                     "dan bisa dicari, tetapi kodenya hanya bisa dibaca sebagai smali (tab Kode > Smali). Contoh: "
                                     + ", ".join(stats.smali_only_samples[:5]) + ". Per dex (class aplikasi / tanpa Java): "
                                     + "; ".join(f"{k}: {v['app']}/{v['tanpa_java']}" for k, v in stats.per_dex.items() if v["app"]))
        if stats.decompile_failures:
            findings.add(category="obfuscation", severity="info", rule_id="coverage.decompile_gaps",
                         title=f"{stats.methods_not_decompiled} method di {stats.decompile_failures} class gagal didekompilasi jadx",
                         key="gaps", description="Isi method tersebut tidak muncul di Java. String di dalamnya tetap "
                                                 "dipindai dari smali, tetapi logikanya perlu dibaca di tab Kode (smali).")
    if findings.dropped:
        log(f"W: {findings.dropped} temuan tambahan dibuang (melebihi batas)")
    summary["findings_total"] = len(findings)

    try:
        index_size = index.finish({"analyzer_version": str(VERSION), "created": str(int(time.time())), "callgraph": cg_state})
        summary["index_bytes"] = index_size
    except Exception as exc:  # noqa: BLE001
        failures.append("index")
        index.abort()
        log(f"E: gagal menyelesaikan indeks: {type(exc).__name__}: {exc}")

    items = findings.items()
    fpath = out / "findings.jsonl"
    with open(fpath, "w", encoding="utf-8") as fh:
        for item in items:
            fh.write(json.dumps(item, ensure_ascii=False) + "\n")
    os.chmod(fpath, 0o644)
    summary["duration_s"] = round(time.monotonic() - t0, 2)
    atomic_write_json(out / "summary.json", tmp, summary)
    atomic_write_json(out / "done.json", tmp, {"ok": not failures, "failures": failures,
                                               "findings": len(items), "duration_s": summary["duration_s"]})
    try:
        tmp.rmdir()
    except OSError:
        pass
    log(f"I: Selesai: {len(items)} temuan, {summary['duration_s']} dtk" + (f", gagal: {failures}" if failures else ""))
    return 2 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
