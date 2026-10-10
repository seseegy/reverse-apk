"""Akses baca-saja ke indeks kode (index.sqlite) dan sistem berkas hasil dekompilasi untuk penjelajah kode.

KEAMANAN. Berkas ini ditulis oleh runner (yang mem-parsing APK tak tepercaya) lalu dibaca web. Perlakukan sebagai masukan
tak tepercaya:
  * SQLite dibuka `mode=ro` + DEFENSIVE + trusted_schema=OFF + query_only, dengan batas waktu per kueri;
  * path berkas SELALU lewat `resolve_under` + O_NOFOLLOW (runner yang dikompromikan tak bisa mengarahkan ke berkas lain);
  * hanya akar yang di-allowlist yang bisa dibaca; berkas biner dan besar ditolak;
  * kata kunci pencarian dikutip sehingga tidak bisa menyuntikkan sintaks FTS.
"""

from __future__ import annotations

import os
import re
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from rvcore.fsutil import read_json_under, resolve_under

MAX_VIEW_BYTES = 2 * 1024 * 1024
MAX_TREE_ENTRIES = 3000
QUERY_TIMEOUT_S = 2.0
SEARCH_LIMIT = 100
PROBE_LIMIT = 301   # kecocokan sebanyak ini atau lebih dianggap 'umum': hasil dipotong tanpa pengurutan relevansi

# Akar yang boleh dijelajahi. Kunci = id di URL; nilai = (label, path relatif terhadap work/<id>/).
ROOTS: dict[str, tuple[str, str]] = {
    "java": ("Java (jadx)", "jadx/sources"),
    "jres": ("Resource (jadx)", "jadx/resources"),
    "smali": ("Smali (apktool)", "apktool"),
}
_SMALI_PREFIXES = ("smali", "res", "AndroidManifest.xml", "assets", "unknown")


def root_dir(root: str) -> str | None:
    return ROOTS[root][1] if root in ROOTS else None


def _safe_parts(rel: str) -> list[str] | None:
    """Pecah path relatif; None bila mengandung '..', mutlak, NUL, atau backslash."""
    if not rel:
        return []
    if rel.startswith("/") or "\x00" in rel or "\\" in rel or len(rel) > 600:
        return None
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return parts


def _resolve(work: Path, analysis_id: int, root: str, rel: str) -> Path | None:
    rd = root_dir(root)
    parts = _safe_parts(rel)
    if rd is None or parts is None:
        return None
    if root == "smali" and parts and not parts[0].startswith(_SMALI_PREFIXES):
        return None
    base = resolve_under(work, str(analysis_id), *rd.split("/"))
    if base is None:
        return None
    if not parts:
        return base
    return resolve_under(base, *parts)


# ------------------------------------------------------------------------- pohon
def list_dir(work: Path, analysis_id: int, root: str, rel: str) -> dict[str, Any] | None:
    """Isi satu direktori (lazy). Direktori berisi satu-subdirektori digabung seperti paket Java (a.b.c)."""
    target = _resolve(work, analysis_id, root, rel)
    if target is None or not target.is_dir():
        return None
    dirs: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    truncated = False
    try:
        with os.scandir(target) as it:
            entries = sorted(it, key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower()))
    except OSError:
        return None
    base_rel = rel.strip("/")
    for e in entries:
        try:
            if e.is_symlink():
                continue
            if len(dirs) + len(files) >= MAX_TREE_ENTRIES:
                truncated = True
                break
            sub = f"{base_rel}/{e.name}" if base_rel else e.name
            if e.is_dir(follow_symlinks=False):
                label, cur = e.name, Path(e.path)
                # Gabungkan rantai paket Java yang hanya berisi satu direktori: com/example/app -> com.example.app
                for _ in range(12):
                    try:
                        kids = [k for k in os.scandir(cur) if not k.is_symlink()]
                    except OSError:
                        break
                    if len(kids) == 1 and kids[0].is_dir(follow_symlinks=False):
                        label += "." + kids[0].name
                        sub = f"{sub}/{kids[0].name}"
                        cur = Path(kids[0].path)
                    else:
                        break
                dirs.append({"name": label, "path": sub, "type": "dir"})
            elif e.is_file(follow_symlinks=False):
                files.append({"name": e.name, "path": sub, "type": "file", "size": e.stat(follow_symlinks=False).st_size})
        except OSError:
            continue
    return {"path": base_rel, "entries": dirs + files, "truncated": truncated}


# ------------------------------------------------------------------------- berkas
def read_file(work: Path, analysis_id: int, root: str, rel: str) -> dict[str, Any] | None:
    """Isi berkas teks (dipotong MAX_VIEW_BYTES). `binary=True` untuk berkas biner (tanpa isi)."""
    target = _resolve(work, analysis_id, root, rel)
    if target is None:
        return None
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                return None
            data = fh.read(MAX_VIEW_BYTES + 1)
    except OSError:
        return None
    size = st.st_size
    if b"\x00" in data[:8192]:
        return {"path": rel, "size": size, "binary": True, "truncated": False, "text": "", "lines": 0}
    truncated = len(data) > MAX_VIEW_BYTES
    text = data[:MAX_VIEW_BYTES].decode("utf-8", errors="replace")
    return {"path": rel, "size": size, "binary": False, "truncated": truncated, "text": text,
            "lines": text.count("\n") + 1}


# ------------------------------------------------------------------------- pencarian
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def to_fts_query(q: str) -> str | None:
    """Ubah masukan pengguna menjadi kueri FTS5 yang aman: tiap token dikutip, AND, token terakhir prefiks."""
    tokens = _TOKEN_RE.findall(q)[:8]
    if not tokens:
        return None
    parts = [f'"{t}"' for t in tokens]
    parts[-1] += "*"
    return " AND ".join(parts)


@contextmanager
def open_index(work: Path, analysis_id: int) -> Iterator[sqlite3.Connection | None]:
    target = resolve_under(work, str(analysis_id), "index", "index.sqlite")
    if target is None or not target.is_file():
        yield None
        return
    conn = None
    try:
        conn = sqlite3.connect(f"file:{target}?mode=ro", uri=True, timeout=2, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        conn.execute("PRAGMA trusted_schema = OFF")
        conn.execute("PRAGMA query_only = ON")
        yield conn
    except sqlite3.DatabaseError:
        yield None
    finally:
        if conn is not None:
            conn.close()


def _with_deadline(conn: sqlite3.Connection, fn):  # noqa: ANN001
    """Jalankan fn() dengan batas waktu: kueri yang terlalu lama dibatalkan lewat interrupt()."""
    timer = threading.Timer(QUERY_TIMEOUT_S, conn.interrupt)
    timer.start()
    try:
        return fn()
    finally:
        timer.cancel()


def search_code(work: Path, analysis_id: int, q: str, scope: str = "all") -> dict[str, Any]:
    """Cari di isi kode (FTS5) dan nama class. scope: all | app (sembunyikan pustaka)."""
    started = time.perf_counter()
    fts = to_fts_query(q)
    result: dict[str, Any] = {"query": q, "hits": [], "classes": [], "available": False, "ms": 0, "error": None,
                              "truncated": False}
    if fts is None:
        return result
    with open_index(work, analysis_id) as conn:
        if conn is None:
            return result
        result["available"] = True
        try:
            def run():
                lib_filter = "AND coalesce(c.is_lib, 0) = 0 " if scope == "app" else ""
                base = ("SELECT code.path AS path, snippet(code, 1, char(2), char(3), '…', 14) AS snip, "
                        "       coalesce(c.is_lib, 0) AS is_lib FROM code LEFT JOIN classes c ON c.path = code.path "
                        "WHERE code MATCH ? " + lib_filter)
                # Pengurutan relevansi (rank) memaksa FTS5 menilai SEMUA kecocokan: kata umum seperti "public" yang cocok
                # di ribuan berkas bisa memakan detik. Maka ambil kandidat tanpa rank dulu. Bila kecocokan sedikit
                # (kata langka), barulah diurutkan; bila banyak, urutan relevansi tidak bermakna -> dipotong.
                probe = conn.execute(base + "LIMIT ?", (fts, PROBE_LIMIT)).fetchall()
                if len(probe) <= PROBE_LIMIT - 1:
                    hits = conn.execute(base + "ORDER BY rank LIMIT ?", (fts, SEARCH_LIMIT)).fetchall()
                    truncated = False
                else:
                    hits, truncated = probe[:SEARCH_LIMIT], True
                like = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                classes = conn.execute(
                    "SELECT path, name, package, is_lib FROM classes WHERE name LIKE ? ESCAPE '\\' "
                    + ("AND is_lib = 0 " if scope == "app" else "") + "ORDER BY is_lib, length(name), name LIMIT 30",
                    (like,)).fetchall()
                return hits, classes, truncated
            hits, classes, truncated = _with_deadline(conn, run)
            result["truncated"] = truncated
            result["hits"] = [dict(h) for h in hits]
            result["classes"] = [dict(c) for c in classes]
        except sqlite3.OperationalError as exc:
            result["error"] = "Pencarian terlalu lama atau kueri tidak valid." if "interrupt" in str(exc).lower() \
                else "Kueri tidak valid."
        except sqlite3.DatabaseError:
            result["error"] = "Indeks tidak dapat dibaca."
    result["ms"] = round((time.perf_counter() - started) * 1000, 1)
    return result


# ------------------------------------------------------------------------- paket & class (untuk tool agent)
def list_packages(work: Path, analysis_id: int, prefix: str = "", include_libs: bool = False, limit: int = 200) -> dict[str, Any]:
    out: dict[str, Any] = {"available": False, "packages": []}
    with open_index(work, analysis_id) as conn:
        if conn is None:
            return out
        out["available"] = True
        like = prefix.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        rows = conn.execute(
            "SELECT package, COUNT(*) AS n, MIN(is_lib) AS is_lib FROM classes WHERE package LIKE ? ESCAPE '\\' "
            + ("" if include_libs else "AND is_lib = 0 ") + "GROUP BY package ORDER BY package LIMIT ?", (like, limit)).fetchall()
        out["packages"] = [{"package": r["package"] or "(default)", "classes": r["n"], "library": bool(r["is_lib"])} for r in rows]
    return out


def list_classes_in(work: Path, analysis_id: int, package: str, limit: int = 200) -> dict[str, Any]:
    out: dict[str, Any] = {"available": False, "classes": []}
    with open_index(work, analysis_id) as conn:
        if conn is None:
            return out
        out["available"] = True
        rows = conn.execute("SELECT path, name, lines, size FROM classes WHERE package = ? ORDER BY name LIMIT ?",
                            (package.strip(), limit)).fetchall()
        out["classes"] = [dict(r) for r in rows]
    return out


def find_class(work: Path, analysis_id: int, name: str, limit: int = 10) -> dict[str, Any]:
    """Cari class berdasarkan nama lengkap (com.x.A / com/x/A) atau nama sederhana (A, tidak peka huruf besar-kecil)."""
    out: dict[str, Any] = {"available": False, "matches": []}
    name = name.strip().replace("/", ".").removesuffix(".java")
    if not name:
        return out
    with open_index(work, analysis_id) as conn:
        if conn is None:
            return out
        out["available"] = True
        if "." in name:
            pkg, _, simple = name.rpartition(".")
            rows = conn.execute("SELECT path, name, package, lines, is_lib FROM classes WHERE package = ? AND name = ? LIMIT ?",
                                (pkg, simple, limit)).fetchall()
        else:
            rows = conn.execute("SELECT path, name, package, lines, is_lib FROM classes WHERE name = ? COLLATE NOCASE "
                                "ORDER BY is_lib, package LIMIT ?", (name, limit)).fetchall()
        out["matches"] = [dict(r) for r in rows]
    return out


# ------------------------------------------------------------------------- string / jaringan
STRING_KINDS = ("url", "domain", "ip", "path", "base64", "hex")


def list_strings(work: Path, analysis_id: int, kind: str | None, q: str | None, scope: str = "app",
                 limit: int = 300) -> dict[str, Any]:
    out: dict[str, Any] = {"rows": [], "counts": {}, "available": False}
    with open_index(work, analysis_id) as conn:
        if conn is None:
            return out
        out["available"] = True
        try:
            for r in conn.execute("SELECT kind, COUNT(*) n, SUM(is_lib = 0) app FROM strings GROUP BY kind"):
                out["counts"][r["kind"]] = {"all": r["n"], "app": r["app"] or 0}
            where, params = [], []
            if kind in STRING_KINDS:
                where.append("kind = ?")
                params.append(kind)
            if scope == "app":
                where.append("is_lib = 0")
            if q:
                where.append("lower(value) LIKE ? ESCAPE '\\'")
                params.append("%" + q.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
            sql = "SELECT kind, value, host, scheme, file, line, count, is_lib FROM strings"
            if where:
                sql += " WHERE " + " AND ".join(where)
            sql += " ORDER BY is_lib, count DESC, value LIMIT ?"
            out["rows"] = [dict(r) for r in _with_deadline(conn, lambda: conn.execute(sql, [*params, limit]).fetchall())]
        except sqlite3.DatabaseError:
            out["error"] = "Indeks tidak dapat dibaca."
    return out


def read_summary(work: Path, analysis_id: int) -> dict[str, Any] | None:
    data = read_json_under(work, str(analysis_id), "index", "summary.json")
    return data if isinstance(data, dict) else None


def index_exists(work: Path, analysis_id: int) -> bool:
    target = resolve_under(work, str(analysis_id), "index", "index.sqlite")
    return bool(target and target.is_file())
