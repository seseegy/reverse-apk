"""Laporan kualitas dekompilasi jadx: rincian method yang gagal + penanda kualitas di dalam kode hasil.

Dua sumber, keduanya sudah ada di work/<id>/ (tidak ada proses tambahan):
  1. logs/jadx.log  — dengan `--log-level error` jadx mencetak SATU baris per kegagalan:
         ERROR - <Jenis>[ in pass: <Pass>] in method: <tanda tangan>, file: classes.dex[, details|error: <alasan>]
     dan di akhir ringkasan: `N errors occurred in following nodes:` + `ERROR -   Method: <tanda tangan>`, lalu
     `ERROR - finished with errors, count: N`. (Log lama dari level `progress` hanya punya baris "count: N" tanpa rincian.)
  2. Komentar `/* JADX WARN: ... */` di Java hasil jadx (kode ada tetapi mutunya dipertanyakan) — dihitung di scan.py.

KEAMANAN. Isi log berasal dari proses yang mem-parsing APK tak tepercaya (nama class/method dari APK). Di sini: baca terbatas (8 MiB,
O_NOFOLLOW), regex berjangkar tanpa backtracking berbahaya, semua string dipotong, jumlah entri dibatasi, hanya stdlib. Hasilnya
divalidasi ulang oleh web sebelum ditampilkan, dan di UI selalu lewat escape.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 20_000          # batas penyimpanan daftar rinci (hitungan per jenis tetap EXACT)
MAX_REASON = 240
MAX_SIG = 400

_PROGRESS_TOTAL = re.compile(r"progress:\s*\d+\s+of\s+(\d+)")
_FINISHED = re.compile(r"^ERROR - finished with errors, count: (\d+)\s*$")
_NODES_HEAD = re.compile(r"^ERROR - (\d+) errors occurred in following nodes:\s*$")
_NODE_LINE = re.compile(r"^ERROR -\s{2,}(Method|Class):\s*(.+?)\s*$")
# Baris kegagalan: "ERROR - <Jenis>[ in pass: <Pass>] in method: <tanda tangan>, file: <dex>[, details|error: <alasan>]".
# SENGAJA bukan satu regex: dua kuantifier lazy bersarang + bagian opsional membuat baris berisi ribuan " in method: " memakan puluhan
# detik (ReDoS; terukur 20 dtk pada 260 KB) dan isi log berasal dari APK tak tepercaya. split_failure() memakai find() linear.
_PASS = re.compile(r"\w{1,60}\Z")
_DEX = re.compile(r"[^,\s]{1,120}\Z")
_WHY_SEP = (", details: ", ", error: ")
MAX_LINE = 20_000                # batas keras satu baris yang diurai; nilainya DIPOTONG setelah diurai (method sangat panjang tetap terdaftar)


def split_failure(line: str) -> dict | None:
    """Urai satu baris kegagalan tanpa backtracking. None bila bentuknya tidak cocok."""
    if not line.startswith("ERROR - "):
        return None
    body = line[8:MAX_LINE]
    k = body.find(" in method: ")
    if k <= 0:
        return None
    head, rest = body[:k], body[k + 12:]
    f = rest.find(", file: ")
    if f <= 0:
        return None
    sig, tail = rest[:f], rest[f + 8:]
    why = ""
    cut = len(tail)
    for sep in _WHY_SEP:
        c = tail.find(sep)
        if 0 <= c < cut:
            cut, why = c, tail[c + len(sep):]
    dex = tail[:cut]
    if not _DEX.match(dex):
        return None
    kind, pas = head, None
    pi = head.rfind(" in pass: ")
    if pi >= 0 and _PASS.match(head[pi + 10:]):
        kind, pas = head[:pi], head[pi + 10:]
    kind = kind.strip()
    if not kind or not sig.strip():
        return None
    return {"kind": kind, "pass": pas, "sig": sig.strip(), "dex": dex, "why": why.strip()}


_ERR_NOMETHOD = re.compile(r"^ERROR - (?P<kind>[A-Za-z][A-Za-z ]{3,60}?)\s*$")
_LEVEL_PREFIX = re.compile(r"^(?:INFO|WARN|ERROR|DEBUG)\s+- ")
_EXC_LINE = re.compile(r"^(?:Caused by: )?(?:[\w$]+\.)+[\w$]+(?:Exception|Error)(?::\s*(?P<msg>.*))?$")

# Jenis -> kategori ringkas untuk pengelompokan di UI (teks penjelasan ada di sisi web).
_CATEGORY = (
    ("overflow", ("JadxOverflowException", "StackOverflowError", "OutOfMemoryError")),
    ("tipe", ("Type inference failed", "Types fix failed", "Failed to calculate best type", "Type inference")),
    ("restruktur", ("Code restructure failed", "RegionMaker", "Inconsistent code")),
    ("finally", ("MarkFinallyVisitor",)),
    ("internal", ("JadxRuntimeException", "NullPointerException", "UnsupportedOperationException", "IllegalStateException",
                  "IndexOutOfBoundsException", "ClassCastException", "ArrayIndexOutOfBoundsException")),
)


# Penanda di dalam kode hasil: `/* JADX WARN: <teks> */`. Dikelompokkan menurut dampaknya pada KEBENARAN kode yang dibaca:
#   kosmetik  = kode benar, hanya bentuknya berbeda dari sumber asli (blok diduplikasi, urutan super() dipindah, dst.)
#   tipe      = tipe variabel ditebak/tidak pasti: logika terbaca, tipe bisa keliru
#   hilang    = ada bagian kode yang hilang/tak dapat direkonstruksi: JANGAN dipercaya, baca smali
_MARKER_RULES = (
    ("hilang", ("code lost", "restructure failed", "removed from duplicated", "unreachable blocks removed", "bottom block not found",
                "undo finally", "not initialized variable", "instruction removed")),
    ("tipe", ("type inference", "best type", "immutable type", "types fix", "multi-variable type")),
    ("kosmetik", ("code duplicated", "super' call moved", "'super' call", "'this' call moved", "failed to restore enum", "enum visitor",
                  "unknown enum class", "access modifiers", "unsupported multi", "can't rename method", "illegal instructions before constructor")),
    # struktur kendali tidak pasti: alur bisa berbeda dari aslinya (urutan case switch, blok 'out' tak ditemukan) -> perlu dicek di smali
    ("struktur", ("switch cases order", "'out' block", "switch over string", "switch 'out'", "failed to find")),
)


def marker_severity(text: str) -> str:
    t = text.lower()
    for sev, needles in _MARKER_RULES:
        if any(n in t for n in needles):
            return sev
    return "lainnya"


def categorize(kind: str) -> str:
    for cat, needles in _CATEGORY:
        if any(n in kind for n in needles):
            return cat
    return "lainnya"


def _read_limited(path: Path) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(MAX_LOG_BYTES + 1)
    except OSError:
        return None
    return data[:MAX_LOG_BYTES].decode("utf-8", errors="replace")


def _split_class(sig: str) -> str:
    """'a.b.C.method(args):ret' -> 'a.b.C' (kelas dalam memakai '$' atau '.N', dibiarkan apa adanya)."""
    head = sig.split("(", 1)[0]
    cls, _, _name = head.rpartition(".")
    return cls or head


def parse_log(log_path: Path) -> dict:
    """Hasil: {available, jadx_total_classes, jadx_error_count, detail, entries[], by_type{}, by_category{}, unattributed{}, truncated, log_truncated}."""
    text = _read_limited(log_path)
    out: dict = {"available": False, "jadx_total_classes": None, "jadx_error_count": None, "detail": False,
                 "entries": [], "by_type": {}, "by_category": {}, "unattributed": {}, "truncated": False, "log_truncated": False}
    if text is None:
        return out
    out["available"] = True
    out["log_truncated"] = "[log dipotong" in text
    totals = _PROGRESS_TOTAL.findall(text)
    if totals:
        out["jadx_total_classes"] = int(totals[-1])

    entries: dict[str, dict] = {}          # kunci = tanda tangan method (satu method bisa punya beberapa baris error)
    n_lines_detail = 0
    pending: dict | None = None            # entri terakhir yang menunggu baris pesan lanjutan
    for raw in re.split(r"[\r\n]+", text):
        line = raw.rstrip()[:MAX_LINE]
        if not line or "progress:" in line:
            continue
        m = _FINISHED.match(line)
        if m:
            out["jadx_error_count"] = int(m.group(1))
            pending = None
            continue
        if _NODES_HEAD.match(line):
            pending = None
            continue
        m = _NODE_LINE.match(line)
        if m:
            pending = None
            sig = m.group(2)[:MAX_SIG]
            if m.group(1) == "Method" and sig not in entries and len(entries) < MAX_ENTRIES:
                entries[sig] = {"method": sig, "class": _split_class(sig), "type": "tidak dirinci", "pass": None, "reason": ""}
            continue
        fl = split_failure(line)
        if fl is not None:
            n_lines_detail += 1
            sig = fl["sig"][:MAX_SIG]
            ent = entries.get(sig)
            if ent is None:
                if len(entries) >= MAX_ENTRIES:
                    out["truncated"] = True
                    pending = None
                    continue
                ent = entries[sig] = {"method": sig, "class": _split_class(sig), "type": "", "pass": None, "reason": ""}
            kind = fl["kind"][:80]
            if not ent["type"] or ent["type"] == "tidak dirinci":      # jenis pertama menang; baris berikutnya hanya menambah alasan
                ent["type"], ent["pass"] = kind, fl["pass"]
            if fl["why"] and not ent["reason"]:
                ent["reason"] = fl["why"][:MAX_REASON]
            pending = ent
            continue
        if line.startswith("ERROR - "):
            m = _ERR_NOMETHOD.match(line)         # mis. "ERROR - MarkFinallyVisitor error" (tanpa tanda tangan)
            pending = None
            if m and m.group("kind") != "finished with errors":
                k = m.group("kind")[:80]
                out["unattributed"][k] = out["unattributed"].get(k, 0) + 1      # error tanpa tanda tangan method (dihitung terpisah)
            continue
        if _LEVEL_PREFIX.match(line):
            pending = None
            continue
        # baris pesan lanjutan (stack frame sudah dibuang runner): ambil pesan pengecualian untuk entri yang belum beralasan
        if pending is not None and not pending["reason"]:
            m = _EXC_LINE.match(line.strip())
            if m and m.group("msg"):
                pending["reason"] = m.group("msg").strip()[:MAX_REASON]

    out["entries"] = list(entries.values())
    out["detail"] = n_lines_detail > 0
    for e in out["entries"]:
        out["by_type"][e["type"]] = out["by_type"].get(e["type"], 0) + 1
        cat = categorize(e["type"] + " " + (e["pass"] or ""))
        e["category"] = cat
        out["by_category"][cat] = out["by_category"].get(cat, 0) + 1
    out["entries"].sort(key=lambda e: (e["category"], e["class"], e["method"]))
    return out


def verdict(failed: int, total_classes: int | None, smali_only: int, app_classes: int) -> tuple[str, float]:
    """('baik'|'sebagian'|'banyak', persen method gagal terhadap jumlah class). Ambang konservatif dan dijelaskan di UI."""
    base = max(1, total_classes or 0)
    pct = 100.0 * failed / base
    lost = 100.0 * smali_only / max(1, app_classes)
    if pct > 5.0 or lost > 15.0:
        return "banyak", round(pct, 2)
    if pct > 1.0 or lost > 3.0:
        return "sebagian", round(pct, 2)
    return "baik", round(pct, 2)


def write_report(out_dir: Path, parsed: dict) -> int:
    """Tulis decompile_errors.jsonl (satu entri per baris). Mengembalikan jumlah entri."""
    path = out_dir / "decompile_errors.jsonl"
    with open(path, "w", encoding="utf-8") as fh:
        for e in parsed["entries"]:
            fh.write(json.dumps({k: e[k] for k in ("method", "class", "type", "category", "pass", "reason")}, ensure_ascii=False) + "\n")
    os.chmod(path, 0o644)
    return len(parsed["entries"])
