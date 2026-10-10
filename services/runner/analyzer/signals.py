"""Sinyal obfuscation, library native, dan konfigurasi jaringan (FR-3.6, 3.9, 3.11)."""

from __future__ import annotations

import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

from . import rules as R
from .common import Findings, iter_files, read_text
from .scan import ScanStats

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
NATIVE_SCAN_MAX_LIBS = 400


def analyze_obfuscation(stats: ScanStats, packers: list[str], findings: Findings) -> dict:
    """Rasio nama 1–2 huruf, marker R8, dan packer dikenal."""
    named = max(stats.app_named_classes, 1)
    short_ratio = stats.short_names / named
    result = {
        "short_name_ratio": round(short_ratio, 3), "short_names": stats.short_names,
        "app_classes": stats.app_classes, "lib_classes": stats.lib_classes,
        "r8_detected": stats.r8_marker, "jadx_renamed": stats.renamed_markers, "packers": packers,
    }
    level = None
    if packers:
        level = "high"
        findings.add(category="obfuscation", severity="high", rule_id="obfuscation.packer",
                     title="Terdeteksi packer/protector: " + ", ".join(sorted(set(packers))), key="packer",
                     description="Kode asli kemungkinan dienkripsi dan dibuka saat runtime sehingga analisis statis hanya "
                                 "melihat loader. Hasil Kode/Temuan akan tidak lengkap.")
    elif short_ratio >= 0.35 and stats.app_named_classes >= 30:
        level = "high"
    elif short_ratio >= 0.12 and stats.app_named_classes >= 30:
        level = "medium"
    elif stats.r8_marker:
        level = "low"
    if level and not packers:
        findings.add(category="obfuscation", severity={"high": "medium", "medium": "low", "low": "info"}[level],
                     rule_id="obfuscation.minified", key=level,
                     title=f"Kode di-obfuscate/minify ({short_ratio:.0%} nama class 1–2 huruf)",
                     description="Nama class/method dipendekkan (ProGuard/R8). Pencarian berdasarkan nama menjadi kurang "
                                 "informatif; andalkan string, struktur, dan pemanggilan API." +
                                 (" Marker R8 ditemukan." if stats.r8_marker else ""))
    result["level"] = level or "none"
    return result


def analyze_native(apk: Path, findings: Findings) -> dict:
    """Daftar library native per ABI + packer dikenal dari nama .so (FR-3.11)."""
    libs: dict[str, list[str]] = {}
    packers: list[str] = []
    try:
        with zipfile.ZipFile(apk) as zf:
            names = [n for n in zf.namelist() if n.startswith("lib/") and n.endswith(".so")][:NATIVE_SCAN_MAX_LIBS]
    except (zipfile.BadZipFile, OSError):
        return {"libs": {}, "packers": []}
    for n in names:
        parts = n.split("/")
        if len(parts) == 3:
            libs.setdefault(parts[1], []).append(parts[2])
            for key, vendor in R.PACKER_LIBS.items():
                if parts[2].startswith(key):
                    packers.append(vendor)
    if libs:
        total = sum(len(v) for v in libs.values())
        findings.add(category="native", severity="info", rule_id="native.libraries",
                     title=f"{total} library native ({', '.join(sorted(libs))})", key="libs",
                     description="Analisis kode native (.so) belum didukung; pemanggilan JNI tetap terlihat di Java.")
    return {"libs": {abi: sorted(v) for abi, v in libs.items()}, "packers": sorted(set(packers))}


def analyze_network_config(work: Path, manifest: dict | None, findings: Findings) -> dict:
    """Ringkas res/xml/network_security_config.xml: cleartext, trust anchor user, dan certificate pinning."""
    summary: dict = {"present": False, "cleartext_permitted": None, "user_certs_trusted": False,
                     "pins": [], "domains": [], "debug_overrides": False}
    cfg_ref = ((manifest or {}).get("flags") or {}).get("network_security_config")
    candidates = []
    if cfg_ref and str(cfg_ref).startswith("@xml/"):
        candidates.append(work / "apktool" / "res" / "xml" / (str(cfg_ref)[5:] + ".xml"))
    candidates.append(work / "apktool" / "res" / "xml" / "network_security_config.xml")
    path = next((c for c in candidates if c.is_file() and not c.is_symlink()), None)
    if path is None:
        return summary
    text = read_text(path, 512 * 1024)
    if text is None or "<!DOCTYPE" in text or "<!ENTITY" in text:
        return summary
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return summary
    summary["present"] = True
    summary["file"] = path.relative_to(work).as_posix()
    base = root.find("base-config")
    if base is not None and base.get("cleartextTrafficPermitted") is not None:
        summary["cleartext_permitted"] = base.get("cleartextTrafficPermitted", "").lower() == "true"
    for dc in root.iter("domain-config"):
        domains = [(d.text or "").strip() for d in dc.findall("domain")][:20]
        entry = {"domains": domains, "cleartext": dc.get("cleartextTrafficPermitted"),
                 "pins": [(p.get("digest", "") + "/" + (p.text or "").strip())[:100] for p in dc.iter("pin")][:10]}
        summary["domains"].append(entry)
        summary["pins"].extend(entry["pins"])
        if (dc.get("cleartextTrafficPermitted") or "").lower() == "true":
            summary["cleartext_domains"] = summary.get("cleartext_domains", []) + domains
    for anchors in root.iter("trust-anchors"):
        if any(c.get("src") == "user" for c in anchors.findall("certificates")):
            summary["user_certs_trusted"] = True
    summary["debug_overrides"] = root.find("debug-overrides") is not None
    rel = summary["file"]
    if summary["cleartext_permitted"] or summary.get("cleartext_domains"):
        scope = "seluruh aplikasi" if summary["cleartext_permitted"] else ", ".join(summary["cleartext_domains"][:5])
        findings.add(category="network", severity="medium" if summary["cleartext_permitted"] else "low",
                     rule_id="network.nsc_cleartext", title=f"network_security_config mengizinkan cleartext (HTTP): {scope}",
                     key=rel, file=rel, line=1, snippet="cleartextTrafficPermitted=\"true\"",
                     description="Konfigurasi jaringan mengizinkan lalu lintas HTTP tanpa enkripsi.")
    if summary["user_certs_trusted"]:
        findings.add(category="network", severity="medium", rule_id="network.nsc_user_certs",
                     title="Mempercayai sertifikat CA yang dipasang pengguna", key=rel, file=rel, line=1,
                     snippet="<certificates src=\"user\"/>",
                     description="Aplikasi menerima CA pengguna sehingga lalu lintas TLS dapat disadap dengan CA buatan. "
                                 "Tidak lazim untuk rilis produksi.")
    if summary["pins"]:
        findings.add(category="network", severity="info", rule_id="network.nsc_pinning",
                     title=f"Certificate pinning di network_security_config ({len(summary['pins'])} pin)", key=rel,
                     file=rel, line=1, snippet="<pin-set>",
                     description="Pinning mempersulit intersepsi lalu lintas saat pengujian dinamis.")
    return summary


def scan_sensitive_assets(work: Path, findings: Findings) -> None:
    """Berkas aset yang namanya menyiratkan rahasia (keystore, kunci, .env)."""
    names = re.compile(r"(?i)(\.jks|\.keystore|\.p12|\.pfx|\.pem|\.key|\.env|id_rsa|google-services\.json|credentials)$")
    root = work / "apktool"
    for sub in ("assets", "res/raw", "unknown"):
        for p in iter_files(root / sub):
            if names.search(p.name):
                rel = p.relative_to(work).as_posix()
                sev = "high" if re.search(r"(?i)(\.jks|\.keystore|\.p12|\.pfx|id_rsa|\.env)$", p.name) else "low"
                findings.add(category="secret", severity=sev, rule_id="secret.sensitive_file",
                             title=f"Berkas sensitif di dalam APK: {p.name}", key=rel, file=rel, line=None,
                             description="Berkas dengan nama/ekstensi yang lazim memuat kunci, keystore, atau konfigurasi "
                                         "rahasia ikut dikemas di APK.")
