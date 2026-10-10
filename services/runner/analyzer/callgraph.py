"""Call graph & hierarki class dari smali (apktool) — dasar tool xref/jalur untuk agent (M4+).

Mengapa smali, bukan Java hasil jadx: smali adalah bytecode apa adanya. Setiap `invoke-*`/`iget`/`sput`/`new-instance`
menyebut simbol LENGKAP (class->nama(deskriptor)), jadi tautannya pasti, tidak ditebak dari teks. Java hasil jadx kehilangan
informasi ini (tipe diketik ulang, lambda diubah, method gagal-dekompilasi hilang).

Yang direkam, dan sengaja TIDAK direkam:
  * Isi `invoke` hanya dibaca untuk class APLIKASI. Class pustaka (androidx, okhttp, dst.) cukup header-nya: nama, super,
    interface. Sisi pustaka->aplikasi hampir selalu lewat refleksi/callback yang memang tidak tampak sebagai invoke, dan
    membaca seluruh pustaka melipatgandakan waktu dan ukuran indeks.
  * Edge dibuat per pasangan (method pemanggil, simbol dipanggil) tanpa duplikat; jumlah panggilan tidak disimpan.
  * Yang TIDAK terlihat dari smali statis: refleksi, JNI, callback lewat framework (onClick dipanggil sistem), dispatch
    interface dinamis, kode yang diunduh saat runtime. Tool di sisi web menyebutkan batas ini ke model.

Semua masukan berasal dari APK tak tepercaya: berkas hanya dibaca sebagai teks (O_NOFOLLOW lewat read_text), diurai dengan
operasi string sederhana (tanpa regex berbahaya), dan setiap jumlah dibatasi.
"""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

from .common import LIB_PREFIXES, iter_files, read_text

MAX_SMALI_BYTES = 8 * 1024 * 1024     # satu berkas smali lebih besar dari ini dilewati (dicatat)
HEADER_BYTES = 8192                   # class pustaka: hanya bagian kepala yang dibaca
HEADER_CHARS = 8192
MAX_CALLS = 4_000_000
MAX_FIELD_REFS = 2_000_000
MAX_CLASS_REFS = 1_000_000
MAX_STRING_REFS = 500_000
MAX_STRINGS_PER_METHOD = 60
MIN_STRING_LEN, MAX_STRING_LEN = 3, 300
MAX_LINE = 6000                       # deskriptor 255 parameter pun muat; baris lebih panjang = bukan instruksi wajar (serangan)
MAX_SYM_BYTES = 128 * 1024 * 1024     # total teks simbol (nama+deskriptor) yang boleh ditampung; lewat ini graf dipotong
DEFAULT_BUDGET_S = 150.0

KIND_VIRTUAL, KIND_INTERFACE, KIND_DIRECT, KIND_STATIC, KIND_SUPER = range(5)
_INVOKE_KINDS = {"virtual": KIND_VIRTUAL, "interface": KIND_INTERFACE, "direct": KIND_DIRECT, "static": KIND_STATIC,
                 "super": KIND_SUPER, "polymorphic": KIND_VIRTUAL}
CREF_NEW, CREF_CONST, CREF_CAST, CREF_INSTANCEOF = range(4)
_CREF_OPS = {"new-instance": CREF_NEW, "const-class": CREF_CONST, "check-cast": CREF_CAST, "instance-of": CREF_INSTANCEOF}

_LIB_SLASH = LIB_PREFIXES

SCHEMA_SQL = (
    "CREATE TABLE cls (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, simple TEXT NOT NULL, super INTEGER, "
    "flags TEXT NOT NULL DEFAULT '', declared INTEGER NOT NULL DEFAULT 0, is_lib INTEGER NOT NULL DEFAULT 0, "
    "file TEXT)",
    "CREATE TABLE impl (cls INTEGER NOT NULL, iface INTEGER NOT NULL, PRIMARY KEY (cls, iface)) WITHOUT ROWID",
    "CREATE TABLE msym (id INTEGER PRIMARY KEY, cls INTEGER NOT NULL, name TEXT NOT NULL, desc TEXT NOT NULL, "
    "flags TEXT NOT NULL DEFAULT '', declared INTEGER NOT NULL DEFAULT 0, UNIQUE (cls, name, desc))",
    "CREATE TABLE fsym (id INTEGER PRIMARY KEY, cls INTEGER NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL, "
    "UNIQUE (cls, name))",
    "CREATE TABLE call (src INTEGER NOT NULL, dst INTEGER NOT NULL, kind INTEGER NOT NULL, PRIMARY KEY (src, dst)) "
    "WITHOUT ROWID",
    "CREATE TABLE fref (src INTEGER NOT NULL, dst INTEGER NOT NULL, rw INTEGER NOT NULL, PRIMARY KEY (src, dst, rw)) "
    "WITHOUT ROWID",
    "CREATE TABLE cref (src INTEGER NOT NULL, cls INTEGER NOT NULL, kind INTEGER NOT NULL, PRIMARY KEY (src, cls, kind)) "
    "WITHOUT ROWID",
    "CREATE TABLE sref (src INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY (src, value)) WITHOUT ROWID",
)
INDEX_SQL = (
    "CREATE INDEX cls_simple ON cls(simple COLLATE NOCASE)",
    "CREATE INDEX cls_super ON cls(super)",
    "CREATE INDEX impl_iface ON impl(iface)",
    "CREATE INDEX msym_name ON msym(name)",
    "CREATE INDEX call_dst ON call(dst, src)",
    "CREATE INDEX fref_dst ON fref(dst, src)",
    "CREATE INDEX cref_cls ON cref(cls, src)",
)


def create_tables(conn: sqlite3.Connection) -> None:
    for stmt in SCHEMA_SQL:
        conn.execute(stmt)


def create_indexes(conn: sqlite3.Connection) -> None:
    for stmt in INDEX_SQL:
        conn.execute(stmt)


def _dotted(desc: str) -> str | None:
    """'Lcom/x/A$B;' -> 'com.x.A$B'. None untuk array/primitif (bukan class)."""
    if len(desc) < 3 or desc[0] != "L" or desc[-1] != ";":
        return None
    return desc[1:-1].replace("/", ".")


def _is_lib_slash(path_in_smali_root: str) -> bool:
    return path_in_smali_root.startswith(_LIB_SLASH)


class Graph:
    """Penampung selama pengurai berjalan: id class/method/field di memori, baris edge langsung ke SQLite."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.cids: dict[str, int] = {}
        self.cls_rows: dict[int, dict] = {}
        self.impls: set[tuple[int, int]] = set()
        self.mids: dict[tuple[int, str, str], int] = {}
        self.mrows: dict[int, list] = {}      # id -> [cls, name, desc, flags, declared]
        self.fids: dict[tuple[int, str], int] = {}
        self.frows: dict[int, tuple[int, str, str]] = {}
        self.n_calls = self.n_frefs = self.n_crefs = self.n_srefs = 0
        self.sym_bytes = 0
        self.capped: set[str] = set()

    def cid(self, name: str) -> int:
        i = self.cids.get(name)
        if i is None:
            i = self.cids[name] = len(self.cids) + 1
        return i

    def mid(self, cls: int, name: str, desc: str) -> int:
        key = (cls, name, desc)
        i = self.mids.get(key)
        if i is None:
            i = self.mids[key] = len(self.mids) + 1
            self.sym_bytes += len(name) + len(desc) + 64
            self.mrows[i] = [cls, name, desc, "", 0]
        return i

    def fid(self, cls: int, name: str, ftype: str) -> int:
        key = (cls, name)
        i = self.fids.get(key)
        if i is None:
            i = self.fids[key] = len(self.fids) + 1
            self.sym_bytes += len(name) + len(ftype) + 48
            self.frows[i] = (cls, name, ftype)
        return i


class CallGraphBuilder:
    def __init__(self, work: Path, conn: sqlite3.Connection, log, budget_s: float = DEFAULT_BUDGET_S) -> None:  # noqa: ANN001
        self.work = work
        self.conn = conn
        self.log = log
        self.g = Graph(conn)
        self.deadline = time.monotonic() + budget_s
        self.files = 0
        self.app_files = 0
        self.skipped: list[str] = []
        self.timed_out = False

    # ------------------------------------------------------------------ kepala class (semua class)
    def _parse_header(self, text: str, is_lib: bool, file_rel: str) -> int | None:
        g = self.g
        cname = None
        flags = ""
        sup = None
        ifaces: list[str] = []
        if len(text) > HEADER_CHARS:                       # cukup kepala berkas; potong di batas baris
            text = text[:HEADER_CHARS]
            text = text[:text.rfind("\n")]
        for line in text.split("\n"):
            if line.startswith(".class"):
                parts = line.split()
                if len(parts) >= 2:
                    cname = _dotted(parts[-1])
                    flags = " ".join(parts[1:-1])
            elif line.startswith(".super"):
                parts = line.split()
                if len(parts) == 2:
                    sup = _dotted(parts[1])
            elif line.startswith(".implements"):
                parts = line.split()
                if len(parts) == 2:
                    d = _dotted(parts[1])
                    if d:
                        ifaces.append(d)
            elif line.startswith((".field", ".method", ".annotation")):
                break
        if not cname:
            return None
        cid = g.cid(cname)
        row = g.cls_rows.get(cid)
        if row is not None and row["declared"]:
            return None   # nama class kembar di dex lain: yang pertama dipakai
        g.cls_rows[cid] = {"super": g.cid(sup) if sup else None, "flags": flags[:120], "declared": 1,
                           "is_lib": int(is_lib), "file": file_rel}
        for i in ifaces[:40]:
            g.impls.add((cid, g.cid(i)))
        return cid

    # ------------------------------------------------------------------ badan class (aplikasi)
    def _parse_body(self, text: str, cid: int) -> None:
        g = self.g
        cur = 0                      # id method yang sedang dibaca (0 = di luar method)
        calls: dict[tuple[int, int], int] = {}
        frefs: set[tuple[int, int, int]] = set()
        crefs: set[tuple[int, int, int]] = set()
        strs: list[tuple[int, str]] = []
        cur_strs: set[str] = set()
        for line in text.split("\n"):
            if len(line) > MAX_LINE:
                if line.startswith(".end method"):
                    cur = 0
                continue                     # baris sepanjang ini bukan instruksi smali yang wajar (string raksasa / serangan)
            if line.startswith("    "):
                if not cur or len(line) < 6:
                    continue
                c = line[4]
                if c == "i":
                    if line.startswith("    invoke-"):
                        end = line.find(" ", 11)
                        if end < 0:
                            continue
                        kind_s = line[11:end]
                        slash = kind_s.find("/")
                        if slash >= 0:
                            kind_s = kind_s[:slash]
                        kind = _INVOKE_KINDS.get(kind_s)
                        arrow = line.find("->", end)
                        if kind is None or arrow < 0:
                            continue
                        comma = line.rfind(",", end, arrow)
                        owner_d = line[comma + 1:arrow].strip()
                        paren = line.find("(", arrow)
                        close = line.find(")", paren) if paren > 0 else -1
                        if close < 0:
                            continue
                        owner = _dotted(owner_d)
                        if owner is None:
                            continue
                        name = line[arrow + 2:paren]
                        ret_end = line.find(",", close)
                        ret = line[close + 1:ret_end if ret_end > 0 else len(line)].strip()
                        dst = g.mid(g.cid(owner), name, line[paren:close] + ")" + ret)
                        if (cur, dst) not in calls:
                            calls[(cur, dst)] = kind
                    elif line.startswith(("    iget", "    iput")):
                        self._field(line, cur, 0 if line[5:8] == "get" else 1, frefs)
                    elif line.startswith("    instance-of"):
                        self._cref(line, cur, CREF_INSTANCEOF, crefs)
                elif c == "s":
                    if line.startswith(("    sget", "    sput")):
                        self._field(line, cur, 0 if line[5:8] == "get" else 1, frefs)
                elif c == "c":
                    if line.startswith("    const-string"):
                        q1 = line.find('"')
                        q2 = line.rfind('"')
                        if 0 < q1 < q2 and len(cur_strs) < MAX_STRINGS_PER_METHOD:
                            v = line[q1 + 1:q2]
                            if MIN_STRING_LEN <= len(v) <= MAX_STRING_LEN:
                                cur_strs.add(v)
                    elif line.startswith("    const-class"):
                        self._cref(line, cur, CREF_CONST, crefs)
                    elif line.startswith("    check-cast"):
                        self._cref(line, cur, CREF_CAST, crefs)
                elif c == "n":
                    if line.startswith("    new-instance"):
                        self._cref(line, cur, CREF_NEW, crefs)
            elif line.startswith(".method "):
                if cur and cur_strs:
                    strs.extend((cur, s) for s in cur_strs)
                cur_strs = set()
                head = line[8:]
                p = head.find("(")
                if p < 0:
                    cur = 0
                    continue
                before = head[:p]
                sp = before.rfind(" ")
                mflags, name = (before[:sp], before[sp + 1:]) if sp >= 0 else ("", before)
                rest = head[p + 1:]
                q = rest.find(")")
                if q < 0:
                    cur = 0
                    continue
                cur = g.mid(cid, name, "(" + rest[:q] + ")" + rest[q + 1:].strip())
                row = g.mrows[cur]
                row[3] = mflags[:100]
                row[4] = 1
            elif line.startswith(".end method"):
                if cur and cur_strs:
                    strs.extend((cur, s) for s in cur_strs)
                cur_strs = set()
                cur = 0
        self._flush(calls, frefs, crefs, strs)

    def _field(self, line: str, cur: int, rw: int, out: set) -> None:  # noqa: ANN001
        arrow = line.find("->")
        if arrow < 0:
            return
        comma = line.rfind(",", 0, arrow)
        owner = _dotted(line[comma + 1:arrow].strip())
        colon = line.find(":", arrow)
        if owner is None or colon < 0:
            return
        g = self.g
        dst = g.fid(g.cid(owner), line[arrow + 2:colon], line[colon + 1:].strip())
        out.add((cur, dst, rw))

    def _cref(self, line: str, cur: int, kind: int, out: set) -> None:  # noqa: ANN001
        comma = line.rfind(",")
        tok = line[comma + 1:].strip() if comma >= 0 else ""
        name = _dotted(tok)
        if name:
            out.add((cur, self.g.cid(name), kind))

    def _flush(self, calls, frefs, crefs, strs) -> None:  # noqa: ANN001
        g, c = self.g, self.conn
        if calls and g.n_calls < MAX_CALLS:
            c.executemany("INSERT OR IGNORE INTO call VALUES (?, ?, ?)", ((s, d, k) for (s, d), k in calls.items()))
            g.n_calls += len(calls)
        elif calls:
            g.capped.add("call")
        if frefs and g.n_frefs < MAX_FIELD_REFS:
            c.executemany("INSERT OR IGNORE INTO fref VALUES (?, ?, ?)", frefs)
            g.n_frefs += len(frefs)
        elif frefs:
            g.capped.add("fref")
        if crefs and g.n_crefs < MAX_CLASS_REFS:
            c.executemany("INSERT OR IGNORE INTO cref VALUES (?, ?, ?)", crefs)
            g.n_crefs += len(crefs)
        elif crefs:
            g.capped.add("cref")
        if strs and g.n_srefs < MAX_STRING_REFS:
            c.executemany("INSERT OR IGNORE INTO sref VALUES (?, ?)", strs)
            g.n_srefs += len(strs)
        elif strs:
            g.capped.add("sref")

    # ------------------------------------------------------------------ orkestrasi
    def _smali_roots(self) -> list[Path]:
        apktool = self.work / "apktool"
        try:
            roots = [apktool / "smali"] + sorted(p for p in apktool.glob("smali_classes*") if p.is_dir() and not p.is_symlink())
        except OSError:
            return []
        return [r for r in roots if r.is_dir() and not r.is_symlink()]

    def run(self) -> bool:
        """True bila graf lengkap; False bila dipotong (batas waktu / jumlah)."""
        roots = self._smali_roots()
        if not roots:
            self.log("W: tidak ada direktori smali: call graph dilewati")
            return False
        last = time.monotonic()
        for root in roots:
            for path in iter_files(root, (".smali",)):
                if time.monotonic() > self.deadline:
                    self.timed_out = True
                    break
                if self.g.sym_bytes > MAX_SYM_BYTES:
                    self.g.capped.add("simbol")
                    break
                rel_in_root = path.relative_to(root).as_posix()
                is_lib = _is_lib_slash(rel_in_root)
                file_rel = path.relative_to(self.work).as_posix()
                self.files += 1
                if is_lib:
                    text = self._head(path)
                    if text:
                        self._parse_header(text, True, file_rel)
                else:
                    text = read_text(path, MAX_SMALI_BYTES)
                    if text is None:
                        if len(self.skipped) < 30:
                            self.skipped.append(file_rel)
                        continue
                    cid = self._parse_header(text, False, file_rel)
                    if cid is not None:
                        self.app_files += 1
                        self._parse_body(text, cid)
                if time.monotonic() - last > 3:
                    last = time.monotonic()
                    self.log(f"progress: smali {self.files}")
            if self.timed_out or "simbol" in self.g.capped:
                break
        self._finish_tables()
        complete = not self.timed_out and not self.g.capped
        self.log(f"I: Call graph: {self.files:,} class smali ({self.app_files:,} aplikasi), {self.g.n_calls:,} edge panggilan, "
                 f"{self.g.n_frefs:,} ref field, {self.g.n_srefs:,} ref string"
                 + ("" if complete else f" — DIPOTONG ({'waktu' if self.timed_out else ', '.join(sorted(self.g.capped))})"))
        return complete

    @staticmethod
    def _head(path: Path) -> str | None:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return None
        try:
            with os.fdopen(fd, "rb") as fh:
                data = fh.read(HEADER_BYTES)
        except OSError:
            return None
        if b"\x00" in data:
            return None
        return data.decode("utf-8", errors="replace")

    def _finish_tables(self) -> None:
        g, c = self.g, self.conn
        # Class: semua nama yang pernah disebut; hanya yang punya smali bertanda declared=1 (sisanya kelas framework).
        rows = []
        for name, cid in g.cids.items():
            r = g.cls_rows.get(cid)
            simple = name.rpartition(".")[2]
            rows.append((cid, name, simple, r["super"] if r else None, r["flags"] if r else "", 1 if r else 0,
                         r["is_lib"] if r else 0, r["file"] if r else None))
        c.executemany("INSERT INTO cls VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
        c.executemany("INSERT INTO impl VALUES (?, ?)", sorted(g.impls))
        c.executemany("INSERT INTO msym VALUES (?, ?, ?, ?, ?, ?)",
                      ((i, r[0], r[1], r[2], r[3], r[4]) for i, r in g.mrows.items()))
        c.executemany("INSERT INTO fsym VALUES (?, ?, ?, ?)", ((i, r[0], r[1], r[2]) for i, r in g.frows.items()))


def build(work: Path, conn: sqlite3.Connection, log, budget_s: float = DEFAULT_BUDGET_S) -> dict:  # noqa: ANN001
    """Bangun semua tabel call graph di `conn` (dalam transaksi yang sedang berjalan). Mengembalikan ringkasan."""
    b = CallGraphBuilder(work, conn, log, budget_s)
    complete = b.run()
    create_indexes(conn)
    g = b.g
    return {"complete": complete, "files": b.files, "app_files": b.app_files, "classes": len(g.cids),
            "methods": len(g.mids), "fields": len(g.fids), "calls": g.n_calls, "field_refs": g.n_frefs,
            "class_refs": g.n_crefs, "string_refs": g.n_srefs, "capped": sorted(g.capped),
            "timed_out": b.timed_out, "skipped": b.skipped}
