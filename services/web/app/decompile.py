"""Laporan kualitas dekompilasi untuk halaman Ringkasan, endpoint daftar lengkap, dan ringkasan untuk AI.

Sumber: `index/summary.json["decompile"]` + `index/decompile_errors.jsonl`, keduanya ditulis analyzer di runner (analyzer/jadxlog.py).
Berkas itu berasal dari proses yang mem-parsing APK tak tepercaya, jadi di sini TIDAK dipercaya begitu saja: dibaca lewat path yang
diverifikasi + O_NOFOLLOW dengan batas ukuran, jenis dan panjang setiap nilai diperiksa ulang, angka dipaksa int, string dipotong, dan
kategori di luar daftar dibuang. Di template semuanya selalu di-escape.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from rvcore.fsutil import resolve_under

from . import codeindex

MAX_FILE_BYTES = 12 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_STR = 400

# Penjelasan awam per kategori error jadx: apa artinya, dan apa yang bisa dilakukan.
CATEGORIES: dict[str, dict[str, str]] = {
    "overflow": {
        "label": "Terlalu rumit untuk jadx",
        "arti": "Struktur kendali method terlalu bersarang/panjang sehingga jadx menyerah menyusunnya jadi Java. Hampir selalu method "
                "invokeSuspend (state machine coroutine Kotlin) atau method hasil optimasi R8.",
        "solusi": "Baca smali-nya: logikanya utuh di bytecode. Pada percobaan kami (NewPipe), menaikkan ukuran tumpukan atau batas tipe jadx "
                  "tidak mengurangi jumlah error ini.",
    },
    "tipe": {
        "label": "Tipe variabel tidak bisa ditebak",
        "arti": "jadx gagal menentukan tipe sebuah variabel. Alur logika biasanya terbaca, tetapi tipe/cast di Java bisa keliru.",
        "solusi": "Pakai Java untuk alur, lalu cek tipe pastinya di smali bila penting.",
    },
    "restruktur": {
        "label": "Struktur if/loop gagal disusun",
        "arti": "Blok kode tidak bisa disusun menjadi if/loop yang rapi, sehingga sebagian kode bisa hilang dari hasil Java.",
        "solusi": "Jangan percaya Java untuk method ini; baca smali.",
    },
    "internal": {
        "label": "Galat internal jadx",
        "arti": "jadx terbentur bug internalnya sendiri pada pola kode tertentu (mis. NullPointerException saat memproses blok).",
        "solusi": "Method ini tidak punya Java yang bisa dipakai; baca smali.",
    },
    "finally": {
        "label": "Blok finally rumit",
        "arti": "jadx gagal mengenali blok `finally` yang digandakan compiler.",
        "solusi": "Baca smali untuk memastikan alur pembersihan.",
    },
    "lainnya": {
        "label": "Lainnya",
        "arti": "Jenis error yang belum dikelompokkan.",
        "solusi": "Baca smali method ini.",
    },
}

# Penanda `/* JADX WARN */` di dalam kode hasil (dihitung per berkas).
MARKER_LEVELS: dict[str, dict[str, str]] = {
    "hilang": {"label": "Kode mungkin hilang", "arti": "Ada bagian kode yang tak dapat direkonstruksi. JANGAN dipercaya; baca smali.", "tone": "bad"},
    "struktur": {"label": "Alur tidak pasti", "arti": "Urutan case switch atau blok keluar tidak pasti; alur bisa berbeda dari aslinya.", "tone": "warn"},
    "tipe": {"label": "Tipe tidak pasti", "arti": "Tipe variabel ditebak/tidak pasti; logika terbaca, cast bisa keliru.", "tone": "warn"},
    "kosmetik": {"label": "Hanya kosmetik", "arti": "Kode benar; hanya bentuknya berbeda dari sumber asli (blok digandakan, super() dipindah, dsb.).", "tone": "ok"},
    "lainnya": {"label": "Lainnya", "arti": "Penanda lain.", "tone": "warn"},
}

VERDICTS = {
    "baik": ("Baik", "ok", "Hampir semua method berhasil didekompilasi."),
    "sebagian": ("Sebagian", "warn", "Sebagian kecil method gagal; sisanya utuh."),
    "banyak": ("Perlu perhatian", "bad", "Banyak method atau class tidak terdekompilasi; andalkan smali untuk bagian itu."),
}


def _int(v: Any, default: int | None = 0) -> int | None:
    if isinstance(v, bool):
        return default
    if isinstance(v, int):
        return max(0, min(v, 10**9))
    if isinstance(v, float) and v == v:
        return max(0, min(int(v), 10**9))
    return default


def _str(v: Any, n: int = MAX_STR) -> str:
    return v[:n] if isinstance(v, str) else ""


def _counts(d: Any, allowed: set[str] | None = None, limit: int = 60) -> dict[str, int]:
    out: dict[str, int] = {}
    if isinstance(d, dict):
        for k, v in list(d.items())[:limit]:
            if isinstance(k, str) and (allowed is None or k in allowed):
                out[k[:100]] = _int(v) or 0
    return out


def read_summary_block(work: Path, analysis_id: int) -> dict[str, Any] | None:
    """`summary.json["decompile"]` yang sudah divalidasi, atau None bila belum ada (analisis lama / jadx tanpa log)."""
    summary = codeindex.read_summary(work, analysis_id)
    block = summary.get("decompile") if isinstance(summary, dict) else None
    if not isinstance(block, dict):
        return None
    code = summary.get("code") if isinstance(summary.get("code"), dict) else {}
    verdict = block.get("verdict") if block.get("verdict") in VERDICTS else "baik"
    return {
        "jadx_error_count": _int(block.get("jadx_error_count"), None),
        "jadx_units": _int(block.get("jadx_units"), None),
        "methods_listed": _int(block.get("methods_listed")),
        "detail": bool(block.get("detail")),
        "by_type": _counts(block.get("by_type")),
        "by_category": _counts(block.get("by_category"), set(CATEGORIES)),
        "unattributed": _counts(block.get("unattributed")),
        "list_truncated": bool(block.get("list_truncated")),
        "log_truncated": bool(block.get("log_truncated")),
        "warn_markers": _counts(block.get("warn_markers"), limit=40),
        "warn_by_severity": _counts(block.get("warn_by_severity"), set(MARKER_LEVELS)),
        "files_with_warn": _int(block.get("files_with_warn")),
        "verdict": verdict,
        "failed_pct": float(block["failed_pct"]) if isinstance(block.get("failed_pct"), (int, float)) and not isinstance(block.get("failed_pct"), bool) else 0.0,
        # angka dari ringkasan kode (sudah ada sejak M2/M5): class tanpa Java, method yang tidak terdekompilasi
        "java_files": _int(code.get("java_files")),
        "app_classes": _int(code.get("app_classes")),
        "methods_not_decompiled": _int(code.get("methods_not_decompiled")),
        "classes_with_gaps": _int(code.get("decompile_failures")),
        "smali_only": _int(code.get("smali_only_files")),
        "smali_only_samples": [_str(x, 200) for x in (code.get("smali_only_samples") or [])[:8] if isinstance(x, str)],
    }


def short_name(sig: str) -> str:
    """'androidx.collection.Entries.iterator.1.invokeSuspend(java.lang.Object):java.lang.Object' -> 'Entries.iterator.1.invokeSuspend'.

    jadx menamai kelas anonim 'Luar.metode.1', jadi mengambil segmen terakhir saja menghasilkan '1'. Ambil dari belakang sampai segmen
    pertama yang berawalan huruf besar (nama class); angka tidak dihitung. Kode ter-obfuscate (semua huruf kecil) dibatasi 4 segmen."""
    head = sig.split("(", 1)[0]
    segs = [x for x in head.split(".") if x != ""]
    if len(segs) <= 2:
        return head
    out = [segs[-1]]                                   # nama method
    for seg in reversed(segs[:-1]):
        out.append(seg)
        if seg[:1].isalpha() and seg[:1].isupper():
            break
        if len(out) >= 4:
            break
    return ".".join(reversed(out))


def read_errors(work: Path, analysis_id: int, limit: int | None = MAX_ENTRIES) -> list[dict[str, str]]:
    """Daftar method yang gagal (tervalidasi). Setiap baris JSON yang rusak dilewati, bukan menggagalkan seluruhnya."""
    target = resolve_under(work, str(analysis_id), "index", "decompile_errors.jsonl")
    if target is None:
        return []
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return []
    out: list[dict[str, str]] = []
    try:
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                return []
            data = fh.read(MAX_FILE_BYTES)
    except OSError:
        return []
    for raw in data.decode("utf-8", errors="replace").split("\n"):
        if not raw.strip():
            continue
        try:
            e = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(e, dict) or not isinstance(e.get("method"), str):
            continue
        cat = e.get("category") if e.get("category") in CATEGORIES else "lainnya"
        out.append({"method": _str(e["method"]), "short": short_name(_str(e["method"])), "class": _str(e.get("class")), "type": _str(e.get("type"), 100),
                    "category": cat, "pass": _str(e.get("pass"), 60), "reason": _str(e.get("reason"), 240)})
        if limit is not None and len(out) >= limit:
            break
    return out


def build_view(work: Path, analysis_id: int, show: int = 100) -> dict[str, Any] | None:
    """Struktur siap-render untuk kartu 'Hasil dekompilasi'. None bila laporan belum ada."""
    info = read_summary_block(work, analysis_id)
    if info is None:
        return None
    errors = read_errors(work, analysis_id)
    by_cat = info["by_category"]
    cats = []
    for key, n in sorted(by_cat.items(), key=lambda kv: -kv[1]):
        meta = CATEGORIES[key]
        cats.append({"key": key, "n": n, **meta, "examples": [e for e in errors if e["category"] == key][:3]})
    markers = []
    for key, meta in MARKER_LEVELS.items():
        n = info["warn_by_severity"].get(key, 0)
        if n:
            markers.append({"key": key, "n": n, **meta})
    label, tone, blurb = VERDICTS[info["verdict"]]
    n_err = info["jadx_error_count"]
    # Satu method bisa menghasilkan beberapa baris error; hitung keduanya agar angkanya jujur.
    view = {**info, "label": label, "tone": tone, "blurb": blurb, "categories": cats, "markers": markers,
            "errors": errors[:show], "errors_total": len(errors), "errors_hidden": max(0, len(errors) - show),
            "no_detail": bool(n_err) and not info["detail"],
            "has_anything": bool(n_err or info["smali_only"] or info["methods_not_decompiled"] or markers)}
    return view


def ai_summary(work: Path, analysis_id: int, examples: int = 12) -> dict[str, Any] | None:
    """Ringkasan padat untuk get_overview: agar AI tahu method mana yang tidak bisa dipercaya dari Java dan harus dibaca sebagai smali."""
    info = read_summary_block(work, analysis_id)
    if info is None:
        return None
    errs = read_errors(work, analysis_id, limit=examples)
    return {
        "penilaian": VERDICTS[info["verdict"]][0],
        "error_jadx": info["jadx_error_count"], "method_terdaftar": info["methods_listed"],
        "persen_gagal": info["failed_pct"], "class_hanya_smali": info["smali_only"],
        "jenis_error": info["by_category"],
        "penanda_dalam_kode": info["warn_by_severity"],
        "contoh_method_gagal": [f"{e['method']} [{e['type']}]" for e in errs],
        "catatan": "Method di daftar ini tidak punya Java yang bisa dipercaya: gunakan get_method/read_file (otomatis smali). "
                   "Penanda 'hilang' = kode mungkin hilang dari Java; 'kosmetik' = aman.",
    }
