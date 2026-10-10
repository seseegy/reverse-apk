"""Impor temuan ke DB + temuan dari manifest (FR-3.1).

Berkas keluaran analyzer ditulis oleh runner, yang memproses APK tak tepercaya. Maka SEMUA nilainya divalidasi di sini:
enum dibatasi, panjang dipotong, jumlah dibatasi, dan path evidence harus relatif tanpa '..'.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from rvcore import store
from rvcore.fsutil import resolve_under

MAX_IMPORT = 3000
MAX_LINE_BYTES = 64 * 1024
MAX_EVIDENCE = 10
_RULE_RE = re.compile(r"^[a-z0-9_.]{3,64}$")


def _s(v: Any, n: int) -> str:
    return str(v if v is not None else "").replace("\x00", "")[:n]


def _clean_path(v: Any) -> str | None:
    p = _s(v, 400)
    if not p or p.startswith("/") or "\\" in p or ".." in p.split("/"):
        return None
    return p


def validate(item: Any) -> dict[str, Any] | None:
    """Kembalikan temuan yang sudah dibersihkan, atau None bila tidak valid."""
    if not isinstance(item, dict):
        return None
    category, severity, rule_id = item.get("category"), item.get("severity"), item.get("rule_id")
    if category not in store.FINDING_CATEGORIES or severity not in store.FINDING_SEVERITIES:
        return None
    if not isinstance(rule_id, str) or not _RULE_RE.match(rule_id):
        return None
    evidence = []
    for ev in (item.get("evidence") or [])[:MAX_EVIDENCE]:
        if not isinstance(ev, dict):
            continue
        path = _clean_path(ev.get("file"))
        if path is None:
            continue
        line = ev.get("line")
        evidence.append({"file": path, "line": line if isinstance(line, int) and 0 < line < 10**7 else None,
                         "snippet": _s(ev.get("snippet"), 300)})
    secret = item.get("secret")
    occ = item.get("occurrences")
    return {
        "category": category, "severity": severity, "rule_id": rule_id,
        "title": _s(item.get("title"), 200) or rule_id, "description": _s(item.get("description"), 1000),
        "evidence": evidence, "secret": _s(secret, 300) if isinstance(secret, str) and secret else None,
        "occurrences": occ if isinstance(occ, int) and 0 < occ < 10**7 else 1,
    }


def read_findings(work: Path) -> tuple[list[dict[str, Any]], int]:
    """(temuan_valid, jumlah_baris_ditolak) dari work/index/findings.jsonl."""
    target = resolve_under(work, "index", "findings.jsonl")
    if target is None:
        return [], 0
    out: list[dict[str, Any]] = []
    rejected = 0
    try:
        with open(target, "rb") as fh:
            for raw in fh:
                if len(out) >= MAX_IMPORT:
                    rejected += 1
                    continue
                if len(raw) > MAX_LINE_BYTES:
                    rejected += 1
                    continue
                try:
                    item = validate(json.loads(raw))
                except ValueError:
                    item = None
                if item is None:
                    rejected += 1
                else:
                    out.append(item)
    except OSError:
        return [], 0
    return out, rejected


# ---------------------------------------------------------------- temuan dari manifest (FR-3.1)
def manifest_findings(m: dict[str, Any]) -> list[dict[str, Any]]:
    f = m.get("flags") or {}
    out: list[dict[str, Any]] = []

    def add(severity: str, rule_id: str, title: str, description: str, snippet: str | None = None,
            occurrences: int = 1, evidence_file: str = "apktool/AndroidManifest.xml") -> None:
        out.append({"category": "manifest", "severity": severity, "rule_id": rule_id, "title": title,
                    "description": description, "occurrences": occurrences, "secret": None,
                    "evidence": [{"file": evidence_file, "line": None, "snippet": snippet or ""}]})

    if f.get("debuggable"):
        add("high", "manifest.debuggable", "Aplikasi dapat di-debug (android:debuggable=true)",
            "Build dengan debuggable=true memungkinkan debugger dilampirkan dan data aplikasi dibaca lewat adb. "
            "Tidak boleh ada pada rilis produksi.", 'android:debuggable="true"')
    if f.get("uses_cleartext_traffic"):
        add("medium", "manifest.cleartext", "Lalu lintas cleartext diizinkan (usesCleartextTraffic=true)",
            "Aplikasi diizinkan memakai HTTP tanpa enkripsi.", 'android:usesCleartextTraffic="true"')
    if f.get("allow_backup") is True:
        add("low", "manifest.allow_backup", "Cadangan data diizinkan (allowBackup=true)",
            "Data aplikasi dapat disalin lewat `adb backup`/cadangan cloud. Matikan bila ada data sensitif.",
            'android:allowBackup="true"')
    elif f.get("allow_backup") is None:
        add("info", "manifest.allow_backup_default", "allowBackup tidak diset (default Android: aktif)",
            "Tanpa atribut ini, Android mengaktifkan cadangan data secara bawaan.", None)
    if f.get("test_only"):
        add("medium", "manifest.test_only", "Build uji (android:testOnly=true)",
            "APK testOnly tidak ditujukan untuk distribusi.", 'android:testOnly="true"')
    if f.get("request_legacy_external_storage"):
        add("low", "manifest.legacy_storage", "Meminta akses penyimpanan lama",
            "requestLegacyExternalStorage melewati scoped storage.", None)

    comps = m.get("components") or {}
    kinds = {"activity": "Activity", "activity-alias": "Activity alias", "service": "Service",
             "receiver": "Receiver", "provider": "Provider"}
    for kind, label in kinds.items():
        exposed = [c for c in comps.get(kind, []) if isinstance(c, dict) and c.get("exported")
                   and not c.get("permission") and not c.get("launcher")]
        if not exposed:
            continue
        names = [str(c.get("name")) for c in exposed]
        sev = "medium" if kind in ("service", "receiver", "provider") else "low"
        add(sev, f"manifest.exported_{kind.replace('-', '_')}",
            f"{len(exposed)} {label} exported tanpa izin pelindung",
            "Komponen yang dapat dipanggil aplikasi lain tanpa izin. Periksa apakah memvalidasi masukan dari "
            "Intent dan apakah memang perlu diekspos. Ini heuristik, bukan klaim kerentanan.",
            ", ".join(names[:5]) + ("…" if len(names) > 5 else ""), occurrences=len(exposed))
    for c in comps.get("provider", []):
        if isinstance(c, dict) and c.get("exported") and c.get("grant_uri_permissions"):
            add("medium", "manifest.provider_grant_uri", "ContentProvider exported dengan grantUriPermissions",
                "Provider yang diekspos dan mengizinkan pemberian akses URI dapat membocorkan data bila path tidak dibatasi.",
                str(c.get("name")))
            break
    dangerous = [p["name"] for p in m.get("permissions", []) if isinstance(p, dict) and p.get("level") in ("dangerous", "special")]
    if dangerous:
        add("info", "manifest.dangerous_permissions", f"{len(dangerous)} izin sensitif diminta",
            "Izin runtime berbahaya atau izin khusus: " + ", ".join(n.rsplit(".", 1)[-1] for n in dangerous[:25]) +
            ("…" if len(dangerous) > 25 else ""), None, occurrences=len(dangerous))
    return out
