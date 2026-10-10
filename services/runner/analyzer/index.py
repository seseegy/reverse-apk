"""Penulis indeks SQLite untuk penjelajah kode & pencarian (FR-3.3, NFR-3.2).

Tabel:
  code(path UNINDEXED, content)  FTS5 unicode61 — isi kode/resource teks (path relatif terhadap work/)
  classes(path, name, package, lines, size, is_lib)  — satu baris per berkas Java (pencarian nama class)
  strings(kind, value, host, scheme, file, line, count, is_lib)  — URL/domain/IP/path/base64/hex, dedup per (kind, value)
  cls/impl/msym/fsym/call/fref/cref/sref  — hierarki class & call graph dari smali (callgraph.py); valid hanya bila
                                            meta.callgraph = complete|partial
  meta(key, value)

Ditulis ke index.sqlite.tmp lalu di-rename atomik setelah selesai, jadi web tidak pernah melihat berkas setengah jadi.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from . import callgraph

SCHEMA_VERSION = 2   # 2: + tabel call graph (cls, impl, msym, fsym, call, fref, cref, sref); lihat callgraph.py
MAX_STRINGS_PER_KIND = 20000
MAX_INDEX_CONTENT = 1024 * 1024  # potong isi per berkas pada 1 MiB agar satu berkas raksasa tak menggelembungkan indeks


class IndexWriter:
    def __init__(self, out_dir: Path) -> None:
        self.final = out_dir / "index.sqlite"
        self.tmp = out_dir / "index.sqlite.tmp"
        for p in (self.tmp, self.final):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        self.conn = sqlite3.connect(self.tmp)
        c = self.conn
        c.execute("PRAGMA journal_mode = OFF")
        c.execute("PRAGMA synchronous = OFF")
        c.execute("PRAGMA temp_store = MEMORY")
        c.execute("CREATE VIRTUAL TABLE code USING fts5(path UNINDEXED, content, tokenize = \"unicode61 tokenchars '_'\")")
        c.execute("CREATE TABLE classes (path TEXT PRIMARY KEY, name TEXT NOT NULL, package TEXT NOT NULL, "
                  "lines INTEGER NOT NULL, size INTEGER NOT NULL, is_lib INTEGER NOT NULL)")
        c.execute("CREATE TABLE strings (kind TEXT NOT NULL, value TEXT NOT NULL, host TEXT, scheme TEXT, "
                  "file TEXT, line INTEGER, count INTEGER NOT NULL DEFAULT 1, is_lib INTEGER NOT NULL DEFAULT 0, "
                  "PRIMARY KEY (kind, value))")
        c.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        callgraph.create_tables(c)
        c.execute("BEGIN")
        self._kind_counts: dict[str, int] = {}
        self.code_rows = 0

    def add_code(self, rel_path: str, text: str) -> None:
        self.conn.execute("INSERT INTO code(path, content) VALUES (?, ?)", (rel_path, text[:MAX_INDEX_CONTENT]))
        self.code_rows += 1

    def add_class(self, rel_path: str, name: str, package: str, lines: int, size: int, is_lib: bool) -> None:
        self.conn.execute("INSERT OR REPLACE INTO classes VALUES (?, ?, ?, ?, ?, ?)",
                          (rel_path, name, package, lines, size, int(is_lib)))

    def add_string(self, kind: str, value: str, file: str | None, line: int | None, *, host: str | None = None,
                   scheme: str | None = None, is_lib: bool = False) -> None:
        """Dedup per (kind, value): kemunculan berikutnya hanya menambah `count`. Kode aplikasi mengalahkan pustaka."""
        n = self._kind_counts.get(kind, 0)
        row = self.conn.execute("SELECT is_lib FROM strings WHERE kind = ? AND value = ?", (kind, value)).fetchone()
        if row is None:
            if n >= MAX_STRINGS_PER_KIND:
                return
            self._kind_counts[kind] = n + 1
            self.conn.execute("INSERT INTO strings VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                              (kind, value[:600], host, scheme, file, line, int(is_lib)))
        else:
            if row[0] and not is_lib:  # pertama kali dilihat di pustaka, kini ditemukan di kode aplikasi
                self.conn.execute("UPDATE strings SET file = ?, line = ?, is_lib = 0, count = count + 1 "
                                  "WHERE kind = ? AND value = ?", (file, line, kind, value))
            else:
                self.conn.execute("UPDATE strings SET count = count + 1 WHERE kind = ? AND value = ?", (kind, value))

    def finish(self, meta: dict[str, str]) -> int:
        c = self.conn
        c.execute("CREATE INDEX classes_name ON classes(name COLLATE NOCASE)")
        c.execute("CREATE INDEX classes_pkg ON classes(package)")
        c.execute("CREATE INDEX strings_kind ON strings(kind, is_lib, count DESC)")
        c.execute("INSERT INTO meta VALUES ('schema', ?)", (str(SCHEMA_VERSION),))
        for k, v in meta.items():
            c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (k, v))
        c.execute("COMMIT")
        c.execute("INSERT INTO code(code) VALUES ('optimize')")  # gabungkan segmen FTS agar pencarian cepat
        c.commit()
        c.close()
        os.replace(self.tmp, self.final)
        return self.final.stat().st_size

    def abort(self) -> None:
        try:
            self.conn.close()
        finally:
            try:
                self.tmp.unlink()
            except FileNotFoundError:
                pass
