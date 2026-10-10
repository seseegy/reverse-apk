"""Kueri BACA-SAJA atas call graph & hierarki class di index.sqlite (ditulis runner: analyzer/callgraph.py).

Sama seperti codeindex: berkas ini berasal dari proses yang mem-parsing APK tak tepercaya, jadi dibuka mode=ro + DEFENSIVE +
trusted_schema=OFF + query_only (lewat `codeindex.open_index`), setiap kueri berbatas waktu, dan semua nilai dari
berkas diperlakukan sebagai data (tidak pernah dijadikan SQL/path).

Semantik penting (disampaikan juga ke model lewat tool):
  * Edge = "method A memuat instruksi yang menyebut simbol B". Itu FAKTA bytecode, bukan tebakan teks.
  * Penerima virtual/interface bisa runtime-nya subclass. Karena itu pemanggil sebuah method dilaporkan dengan
    hubungan: langsung (simbol persis), lewat subclass (instruksi menyebut subclass yang tidak meng-override), dan
    lewat supertype (instruksi menyebut tipe induk/interface; saat runtime BISA sampai ke method ini).
  * Tidak terlihat: refleksi, JNI, callback yang dipanggil framework (onClick, Handler, coroutine), kode dinamis.
"""

from __future__ import annotations

import heapq
import sqlite3
import threading
import time
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import codeindex

KIND_NAMES = {0: "virtual", 1: "interface", 2: "direct", 3: "static", 4: "super"}
CREF_NAMES = {0: "new-instance", 1: "const-class", 2: "check-cast", 3: "instance-of"}
RELATION_RANK = {"langsung": 0, "lewat subclass": 1, "lewat supertype": 2}

MAX_SUBTYPES = 400
MAX_SUPERTYPES = 80
MAX_DISPATCH_FANOUT = 8     # lebih banyak override dari ini = dispatch tidak informatif (mis. View.OnClickListener): dilewati
MAX_PATH_NODES = 40_000
PATH_TIME_BUDGET_S = 3.0
IN_CHUNK = 400
MAX_CALLBACK_METHODS = 12

# Titik masuk yang dipanggil SISTEM, bukan kode aplikasi. `const-class X` pada class turunan komponen berarti X dijalankan lewat
# Intent/WorkManager; method siklus hidupnya menjadi tujuan edge "intent".
COMPONENT_BASES = {"android.app.Activity", "android.app.Service", "android.content.BroadcastReceiver",
                   "android.content.ContentProvider", "android.app.Application", "androidx.work.ListenableWorker"}
LIFECYCLE_METHODS = {"onCreate", "onStart", "onResume", "onNewIntent", "onStartCommand", "onBind", "onHandleIntent", "onReceive",
                     "onActivityResult", "doWork", "attachBaseContext", "query", "insert", "update", "delete", "openFile", "call"}

_PRIM = {"V": "void", "Z": "boolean", "B": "byte", "S": "short", "C": "char", "I": "int", "J": "long", "F": "float",
         "D": "double"}


class GraphError(Exception):
    """Galat yang aman ditampilkan ke model (nama tidak ditemukan, graf tidak ada, dst.)."""


# ------------------------------------------------------------------------- pembukaan & status
@contextmanager
def open_graph(work: Path, analysis_id: int) -> Iterator[tuple[sqlite3.Connection, str]]:
    """Buka indeks dan pastikan call graph tersedia. Menghasilkan (koneksi, status: complete|partial).
    Melempar GraphError bila graf tidak ada / gagal dibuat."""
    with codeindex.open_index(work, analysis_id) as conn:
        if conn is None:
            raise GraphError("indeks kode belum tersedia (jalankan analisis statis)")
        try:
            row = conn.execute("SELECT value FROM meta WHERE key = 'callgraph'").fetchone()
        except sqlite3.DatabaseError:
            row = None
        if row is None:
            raise GraphError("call graph belum ada untuk analisis ini (dibuat analyzer versi lama). "
                             "Jalankan ulang analisis statis dari halaman analisis, lalu coba lagi.")
        if row[0] == "failed":
            raise GraphError("pembuatan call graph gagal saat analisis; xref/jalur tidak tersedia. Gunakan search_code/get_class.")
        try:
            yield conn, row[0]
        except sqlite3.OperationalError as exc:
            if "interrupt" in str(exc).lower():
                raise GraphError("kueri terlalu lama dan dibatalkan; persempit pencarian") from exc
            raise GraphError("indeks tidak dapat dibaca") from exc
        except sqlite3.DatabaseError as exc:
            raise GraphError("indeks tidak dapat dibaca") from exc


def graph_state(work: Path, analysis_id: int) -> str | None:
    """'complete' | 'partial' | 'failed' | None (belum ada)."""
    with codeindex.open_index(work, analysis_id) as conn:
        if conn is None:
            return None
        try:
            row = conn.execute("SELECT value FROM meta WHERE key = 'callgraph'").fetchone()
        except sqlite3.DatabaseError:
            return None
        return row[0] if row else None


def _run_with_deadline(conn: sqlite3.Connection, seconds: float, fn):  # noqa: ANN001
    timer = threading.Timer(seconds, conn.interrupt)
    timer.start()
    try:
        return fn()
    finally:
        timer.cancel()


# ------------------------------------------------------------------------- format nama
def parse_desc(desc: str) -> tuple[list[str], str]:
    """'(ILjava/lang/String;[B)V' -> (['int','String','byte[]'], 'void'). Tidak pernah melempar."""
    def one(s: str, i: int) -> tuple[str, int]:
        dims = 0
        while i < len(s) and s[i] == "[":
            dims += 1
            i += 1
        if i >= len(s):
            return "?", i
        if s[i] == "L":
            j = s.find(";", i)
            if j < 0:
                return "?", len(s)
            name = s[i + 1:j].rsplit("/", 1)[-1]
            return name + "[]" * dims, j + 1
        return _PRIM.get(s[i], "?") + "[]" * dims, i + 1

    try:
        if not desc.startswith("("):
            return [], "?"
        close = desc.index(")")
        params, i = [], 1
        while i < close and len(params) < 40:
            t, i = one(desc, i)
            params.append(t)
        ret, _ = one(desc, close + 1)
        return params, ret
    except ValueError:
        return [], "?"


def fmt_method(cls: str, name: str, desc: str) -> str:
    params, _ret = parse_desc(desc)
    return f"{cls}.{name}({', '.join(params)})"


def fmt_field_type(t: str) -> str:
    params = parse_desc("(" + t + ")V")[0] if t else []
    return params[0] if params else "?"


# ------------------------------------------------------------------------- class
def find_classes(conn: sqlite3.Connection, name: str, limit: int = 8) -> list[sqlite3.Row]:
    name = name.strip().replace("/", ".").removesuffix(".java").removesuffix(".smali")
    if name.startswith("L") and name.endswith(";") and "." in name:
        name = name[1:-1]
    if not name:
        return []
    rows = conn.execute("SELECT * FROM cls WHERE name = ? LIMIT ?", (name, limit)).fetchall()
    if rows:
        return rows
    if "." in name:
        # a.b.C.D -> a.b.C$D (kelas dalam ditulis dengan titik oleh jadx / pengguna)
        parts = name.split(".")
        for k in range(1, min(4, len(parts) - 1) + 1):
            cand = ".".join(parts[:-k]) + "$" + "$".join(parts[-k:])
            rows = conn.execute("SELECT * FROM cls WHERE name = ? LIMIT ?", (cand, limit)).fetchall()
            if rows:
                return rows
        return []
    like = "%$" + name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return conn.execute(
        "SELECT * FROM cls WHERE (simple = ? COLLATE NOCASE OR simple LIKE ? ESCAPE '\\') "
        "ORDER BY declared DESC, is_lib, name LIMIT ?", (name, like, limit)).fetchall()


def resolve_class(conn: sqlite3.Connection, name: str) -> sqlite3.Row:
    rows = find_classes(conn, name)
    if not rows:
        raise GraphError(f"class '{name[:120]}' tidak dikenal di call graph: tidak ada smali-nya dan tidak pernah disebut oleh kode "
                         "aplikasi (kode pustaka tidak dianalisis; nama bisa juga sudah di-obfuscate). Gunakan nama lengkap "
                         "(com.x.Kelas); cari dulu dengan search_code atau list_classes.")
    if len(rows) > 1 and "." not in name:
        opts = ", ".join(r["name"] for r in rows[:8])
        raise GraphError("nama class ambigu; gunakan nama lengkap: " + opts)
    return rows[0]


def _chunks(items: list, n: int = IN_CHUNK) -> Iterator[list]:
    for i in range(0, len(items), n):
        yield items[i:i + n]


def supertypes(conn: sqlite3.Connection, cid: int, limit: int = MAX_SUPERTYPES) -> list[int]:
    """Semua super class & interface (transitif), terdekat dulu. Tanpa cid itu sendiri."""
    seen: dict[int, None] = {}
    queue = deque([cid])
    while queue and len(seen) < limit:
        cur = queue.popleft()
        row = conn.execute("SELECT super FROM cls WHERE id = ?", (cur,)).fetchone()
        nxt = [row[0]] if row and row[0] else []
        nxt += [r[0] for r in conn.execute("SELECT iface FROM impl WHERE cls = ?", (cur,))]
        for n in nxt:
            if n not in seen and n != cid:
                seen[n] = None
                queue.append(n)
    return list(seen)


def subtypes(conn: sqlite3.Connection, cid: int, limit: int = MAX_SUBTYPES) -> tuple[list[int], bool]:
    """Semua subclass & implementer (transitif). Mengembalikan (daftar, dipotong)."""
    seen: dict[int, None] = {}
    queue = deque([cid])
    truncated = False
    while queue:
        cur = queue.popleft()
        for (n,) in conn.execute("SELECT id FROM cls WHERE super = ? UNION SELECT cls FROM impl WHERE iface = ?", (cur, cur)):
            if n not in seen and n != cid:
                if len(seen) >= limit:
                    truncated = True
                    queue.clear()
                    break
                seen[n] = None
                queue.append(n)
    return list(seen), truncated


def _class_names(conn: sqlite3.Connection, ids: list[int]) -> dict[int, sqlite3.Row]:
    out: dict[int, sqlite3.Row] = {}
    for ch in _chunks(list(dict.fromkeys(ids))):
        q = ",".join("?" * len(ch))
        for r in conn.execute(f"SELECT id, name, declared, is_lib FROM cls WHERE id IN ({q})", ch):
            out[r["id"]] = r
    return out


def _method_rows(conn: sqlite3.Connection, ids: list[int]) -> dict[int, sqlite3.Row]:
    out: dict[int, sqlite3.Row] = {}
    for ch in _chunks(list(dict.fromkeys(ids))):
        q = ",".join("?" * len(ch))
        for r in conn.execute(
                f"SELECT m.id, m.cls, m.name, m.desc, m.flags, m.declared, c.name AS cname, c.is_lib AS is_lib, "
                f"c.declared AS cdeclared FROM msym m JOIN cls c ON c.id = m.cls WHERE m.id IN ({q})", ch):
            out[r["id"]] = r
    return out


def _is_app(r: sqlite3.Row) -> bool:
    return bool(r["cdeclared"]) and not r["is_lib"]


def _label(r: sqlite3.Row) -> str:
    return fmt_method(r["cname"], r["name"], r["desc"])


# ------------------------------------------------------------------------- xref
def _related(conn: sqlite3.Connection, cid: int) -> tuple[dict[int, str], bool]:
    related: dict[int, str] = {cid: "langsung"}
    subs, cut = subtypes(conn, cid)
    for s in subs:
        related[s] = "lewat subclass"
    for s in supertypes(conn, cid):
        related.setdefault(s, "lewat supertype")
    return related, cut


def _methods_named(conn: sqlite3.Connection, cid: int, name: str) -> tuple[list[sqlite3.Row], str | None]:
    """Method bernama `name` pada class (atau, bila tidak dideklarasikan di situ, pada induk terdekat yang mendeklarasikannya)."""
    rows = conn.execute("SELECT id, cls, name, desc, flags, declared FROM msym WHERE cls = ? AND name = ?", (cid, name)).fetchall()
    if any(r["declared"] for r in rows):
        return rows, None
    for sid in supertypes(conn, cid):
        sr = conn.execute("SELECT id, cls, name, desc, flags, declared FROM msym WHERE cls = ? AND name = ? AND declared = 1",
                          (sid, name)).fetchall()
        if sr:
            owner = conn.execute("SELECT name FROM cls WHERE id = ?", (sid,)).fetchone()[0]
            return sr, owner
    return rows, None


def xrefs_for_member(conn: sqlite3.Connection, cls: sqlite3.Row, member: str, limit: int = 60) -> dict[str, Any]:
    cid = cls["id"]
    methods, inherited_from = _methods_named(conn, cid, member)
    related, subs_cut = _related(conn, cid)
    out: dict[str, Any] = {"class": cls["name"], "member": member, "method": None, "field": None}

    if methods:
        descs = sorted({m["desc"] for m in methods})
        rel_ids = list(related)
        cand: dict[int, str] = {}                 # id msym yang disebut instruksi -> hubungan
        for ch in _chunks(rel_ids):
            qc = ",".join("?" * len(ch))
            qd = ",".join("?" * len(descs))
            for r in conn.execute(f"SELECT id, cls FROM msym WHERE name = ? AND desc IN ({qd}) AND cls IN ({qc})",
                                  [member, *descs, *ch]):
                cand[r["id"]] = related[r["cls"]]
        callers: dict[int, tuple[str, int, int]] = {}   # src -> (hubungan terbaik, kind, dst)
        for ch in _chunks(list(cand)):
            q = ",".join("?" * len(ch))
            for r in conn.execute(f"SELECT src, dst, kind FROM call WHERE dst IN ({q})", ch):
                rel = cand[r["dst"]]
                old = callers.get(r["src"])
                if old is None or RELATION_RANK[rel] < RELATION_RANK[old[0]]:
                    callers[r["src"]] = (rel, r["kind"], r["dst"])
        rows = _method_rows(conn, list(callers))
        items = []
        for src, (rel, kind, _dst) in callers.items():
            r = rows.get(src)
            if r is None:
                continue
            items.append({"pemanggil": _label(r), "hubungan": rel, "jenis": KIND_NAMES.get(kind, "?"), "aplikasi": _is_app(r)})
        items.sort(key=lambda x: (RELATION_RANK[x["hubungan"]], not x["aplikasi"], x["pemanggil"]))
        out["method"] = {
            "dideklarasikan": sorted({fmt_method(cls["name"] if inherited_from is None else inherited_from, m["name"], m["desc"])
                                      for m in methods})[:12],
            "diwarisi_dari": inherited_from,
            "total_pemanggil": len(items),
            "pemanggil": items[:limit],
        }

    fields = []
    for ch in _chunks(list(related)):
        q = ",".join("?" * len(ch))
        fields += conn.execute(f"SELECT id, cls, name, type FROM fsym WHERE name = ? AND cls IN ({q})", [member, *ch]).fetchall()
    if fields:
        fmap = {f["id"]: f for f in fields}
        readers: dict[int, dict[str, Any]] = {}
        for ch in _chunks(list(fmap)):
            q = ",".join("?" * len(ch))
            for r in conn.execute(f"SELECT src, dst, rw FROM fref WHERE dst IN ({q})", ch):
                rel = related[fmap[r["dst"]]["cls"]]
                ent = readers.setdefault(r["src"], {"rel": rel, "ops": set()})
                ent["ops"].add("tulis" if r["rw"] else "baca")
                if RELATION_RANK[rel] < RELATION_RANK[ent["rel"]]:
                    ent["rel"] = rel
        rows = _method_rows(conn, list(readers))
        items = [{"method": _label(rows[s]), "akses": sorted(v["ops"]), "hubungan": v["rel"], "aplikasi": _is_app(rows[s])}
                 for s, v in readers.items() if s in rows]
        items.sort(key=lambda x: (RELATION_RANK[x["hubungan"]], not x["aplikasi"], x["method"]))
        out["field"] = {"tipe": fmt_field_type(fields[0]["type"]), "total": len(items), "pengakses": items[:limit]}
    if subs_cut:
        out["catatan_subclass"] = f"hierarki subclass dipotong pada {MAX_SUBTYPES}; hasil bisa kurang lengkap"
    return out


def xrefs_for_class(conn: sqlite3.Connection, cls: sqlite3.Row, limit: int = 60) -> dict[str, Any]:
    """Siapa yang memakai class ini: memanggil method-nya, mengakses field-nya, new-instance/const-class/cast."""
    cid = cls["id"]
    users: dict[int, dict[str, int]] = {}

    def bump(src: int, key: str, n: int = 1) -> None:
        d = users.setdefault(src, {})
        d[key] = d.get(key, 0) + n

    for r in conn.execute("SELECT k.src AS src, COUNT(*) AS n FROM call k JOIN msym m ON m.id = k.dst WHERE m.cls = ? "
                          "GROUP BY k.src LIMIT 3000", (cid,)):
        bump(r["src"], "memanggil method", r["n"])
    for r in conn.execute("SELECT f.src AS src, COUNT(*) AS n FROM fref f JOIN fsym s ON s.id = f.dst WHERE s.cls = ? "
                          "GROUP BY f.src LIMIT 3000", (cid,)):
        bump(r["src"], "mengakses field", r["n"])
    for r in conn.execute("SELECT src, kind FROM cref WHERE cls = ? LIMIT 3000", (cid,)):
        bump(r["src"], CREF_NAMES.get(r["kind"], "?"))
    rows = _method_rows(conn, list(users))
    items = [{"pengguna": _label(rows[s]), "cara": sorted(v), "aplikasi": _is_app(rows[s])} for s, v in users.items() if s in rows]
    items.sort(key=lambda x: (not x["aplikasi"], x["pengguna"]))
    return {"class": cls["name"], "total_pengguna": len(items), "pengguna": items[:limit]}


def xrefs_for_string(conn: sqlite3.Connection, text: str, limit: int = 40) -> dict[str, Any]:
    like = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

    def run():
        return conn.execute("SELECT src, value FROM sref WHERE value LIKE ? ESCAPE '\\' LIMIT 400", (like,)).fetchall()

    hits = _run_with_deadline(conn, 2.0, run)
    rows = _method_rows(conn, [h["src"] for h in hits])
    by_value: dict[str, list[dict]] = {}
    for h in hits:
        r = rows.get(h["src"])
        if r is None:
            continue
        by_value.setdefault(h["value"], []).append({"method": _label(r), "aplikasi": _is_app(r)})
    items = [{"string": v, "dipakai_di": sorted(m, key=lambda x: (not x["aplikasi"], x["method"]))[:8], "jumlah_method": len(m)}
             for v, m in by_value.items()]
    items.sort(key=lambda x: (-x["jumlah_method"], x["string"]))
    return {"kueri": text, "total_string_cocok": len(items), "hasil": items[:limit], "dipotong": len(hits) >= 400}


# ------------------------------------------------------------------------- callees
_HIDE_CLASSES = {"java.lang.StringBuilder", "java.lang.StringBuffer"}


def callees_of(conn: sqlite3.Connection, cls: sqlite3.Row, method: str, limit: int = 70) -> dict[str, Any]:
    cid = cls["id"]
    rows = conn.execute("SELECT id, cls, name, desc, flags, declared FROM msym WHERE cls = ? AND name = ? AND declared = 1",
                        (cid, method)).fetchall()
    if not rows:
        raise GraphError(f"method '{method}' tidak dideklarasikan di {cls['name']}"
                         + (" (class framework/pustaka: isinya tidak dianalisis)" if not cls["declared"] or cls["is_lib"] else "")
                         + ". Gunakan class_info untuk daftar method.")
    out = []
    for m in rows[:6]:
        calls = conn.execute("SELECT dst, kind FROM call WHERE src = ?", (m["id"],)).fetchall()
        dmap = _method_rows(conn, [c["dst"] for c in calls])
        callee, hidden = [], 0
        for c in calls:
            d = dmap.get(c["dst"])
            if d is None:
                continue
            if d["cname"] in _HIDE_CLASSES or (d["cname"] == "java.lang.Object" and d["name"] == "<init>"):
                hidden += 1
                continue
            callee.append({"method": _label(d), "jenis": KIND_NAMES.get(c["kind"], "?"), "aplikasi": _is_app(d)})
        callee.sort(key=lambda x: (not x["aplikasi"], x["method"]))
        fields = []
        for f in conn.execute("SELECT s.name AS name, s.type AS type, c.name AS cname, f.rw AS rw FROM fref f "
                              "JOIN fsym s ON s.id = f.dst JOIN cls c ON c.id = s.cls WHERE f.src = ? LIMIT 80", (m["id"],)):
            fields.append(f"{'tulis' if f['rw'] else 'baca'} {f['cname']}.{f['name']}: {fmt_field_type(f['type'])}")
        strings = [r[0] for r in conn.execute("SELECT value FROM sref WHERE src = ? LIMIT 40", (m["id"],))]
        creates = [r[0] for r in conn.execute("SELECT c.name FROM cref r JOIN cls c ON c.id = r.cls WHERE r.src = ? AND r.kind IN (0, 1) "
                                              "LIMIT 40", (m["id"],))]
        out.append({"method": fmt_method(cls["name"], m["name"], m["desc"]), "bendera": m["flags"],
                    "memanggil": callee[:limit], "total_panggilan": len(callee), "disembunyikan": hidden,
                    "field": fields[:30], "string": strings, "class_dipakai": creates})
    return {"class": cls["name"], "hasil": out, "overload_lain": max(0, len(rows) - 6)}


# ------------------------------------------------------------------------- class info
def class_info(conn: sqlite3.Connection, cls: sqlite3.Row, method_limit: int = 150) -> dict[str, Any]:
    cid = cls["id"]
    chain, cur, guard = [], cls["super"], 0
    while cur and guard < 14:
        r = conn.execute("SELECT id, name, super, declared, is_lib FROM cls WHERE id = ?", (cur,)).fetchone()
        if r is None:
            break
        chain.append({"class": r["name"], "ada_kode": bool(r["declared"]), "pustaka": bool(r["is_lib"])})
        cur, guard = r["super"], guard + 1
    ifaces = [r[0] for r in conn.execute("SELECT c.name FROM impl i JOIN cls c ON c.id = i.iface WHERE i.cls = ? ORDER BY c.name", (cid,))]
    subs, cut = subtypes(conn, cid, 200)
    srows = _class_names(conn, subs)
    sub_items = sorted((srows[s]["name"] for s in subs if s in srows and srows[s]["declared"] and not srows[s]["is_lib"]))
    mrows = conn.execute("SELECT name, desc, flags FROM msym WHERE cls = ? AND declared = 1 ORDER BY name, desc LIMIT ?",
                         (cid, method_limit + 1)).fetchall()
    methods = [{"method": fmt_method(cls["name"], m["name"], m["desc"]), "bendera": m["flags"]} for m in mrows[:method_limit]]
    natives = [m["method"] for m in methods if "native" in m["bendera"].split()]
    return {"class": cls["name"], "bendera": cls["flags"], "ada_kode_smali": bool(cls["declared"]), "pustaka": bool(cls["is_lib"]),
            "berkas_smali": cls["file"], "super_chain": chain, "interface": ifaces,
            "turunan_aplikasi": sub_items[:40], "total_turunan_aplikasi": len(sub_items), "hierarki_dipotong": cut,
            "method": methods, "method_dipotong": len(mrows) > method_limit, "method_native": natives}


# ------------------------------------------------------------------------- jalur
# Bobot edge pada pencarian jalur (Dijkstra): invoke nyata murah, edge perkiraan mahal, sehingga jalur dengan sedikit tebakan
# diutamakan walau lebih panjang.
EDGE_COST = {"langsung": 1, "dispatch (override)": 3, "intent (const-class)": 3,
             "callback (instance dibuat di sini; perkiraan)": 4}
HOW_INTENT = "intent (const-class)"
HOW_CALLBACK = "callback (instance dibuat di sini; perkiraan)"
HOW_DISPATCH = "dispatch (override)"


class _PathSearch:
    """Pencarian jalur terbobot pada call graph + edge perkiraan (dispatch/intent/callback). Satu instans = satu kueri."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.sub_cache: dict[int, list[int]] = {}
        self.inherit_cache: dict[tuple[int, str, str], int | None] = {}
        self.component_cache: dict[int, bool] = {}
        self.declared_cache: dict[tuple[int, bool], list[int]] = {}
        self.skipped_dispatch = 0

    def overrides_of(self, m: sqlite3.Row) -> list[int]:
        subs = self.sub_cache.get(m["cls"])
        if subs is None:
            subs = self.sub_cache[m["cls"]] = subtypes(self.conn, m["cls"], 120)[0]
        out: list[int] = []
        for ch in _chunks(subs):
            qq = ",".join("?" * len(ch))
            out += [r[0] for r in self.conn.execute(
                f"SELECT m.id FROM msym m JOIN cls c ON c.id = m.cls WHERE m.declared = 1 AND m.name = ? AND m.desc = ? "
                f"AND m.cls IN ({qq}) ORDER BY c.is_lib, m.id", [m["name"], m["desc"], *ch])]
        return out

    def resolve(self, m: sqlite3.Row) -> int | None:
        """Method yang SEBENARNYA dijalankan untuk simbol m: dirinya bila terdeklarasi, atau milik induk terdekat."""
        if m["declared"]:
            return m["id"]
        key = (m["cls"], m["name"], m["desc"])
        if key not in self.inherit_cache:
            res = None
            for sid in supertypes(self.conn, m["cls"], 30):
                r = self.conn.execute("SELECT id FROM msym WHERE cls = ? AND name = ? AND desc = ? AND declared = 1",
                                      (sid, m["name"], m["desc"])).fetchone()
                if r:
                    res = r[0]
                    break
            self.inherit_cache[key] = res
        return self.inherit_cache[key]

    def is_component(self, cid: int) -> bool:
        v = self.component_cache.get(cid)
        if v is None:
            names = _class_names(self.conn, [cid, *supertypes(self.conn, cid, 30)])
            v = self.component_cache[cid] = any(r["name"] in COMPONENT_BASES for r in names.values())
        return v

    def declared_methods(self, cid: int, lifecycle: bool) -> list[int]:
        key = (cid, lifecycle)
        v = self.declared_cache.get(key)
        if v is None:
            rows = self.conn.execute("SELECT id, name FROM msym WHERE cls = ? AND declared = 1 ORDER BY name, id", (cid,)).fetchall()
            if lifecycle:
                v = [r["id"] for r in rows if r["name"] in LIFECYCLE_METHODS]
            else:
                v = [r["id"] for r in rows if r["name"] not in ("<init>", "<clinit>")][:MAX_CALLBACK_METHODS]
            self.declared_cache[key] = v
        return v

    def edges(self, node: int, allow_approx: bool) -> list[tuple[int, str]]:
        """Semua edge keluar dari method `node`: (id tujuan, how). Id tujuan bisa simbol yang tak terdeklarasi (target framework)."""
        conn = self.conn
        out: list[tuple[int, str]] = []
        calls = conn.execute("SELECT dst, kind FROM call WHERE src = ? ORDER BY dst", (node,)).fetchall()
        dmap = _method_rows(conn, [c["dst"] for c in calls])
        for c in calls:
            d = dmap.get(c["dst"])
            if d is None:
                continue
            out.append((c["dst"], "langsung"))               # simbol persis (cocok bila itu target)
            res = self.resolve(d)
            if res is not None and res != c["dst"]:
                out.append((res, "langsung"))                # warisan: simbol disebut lewat subclass, kodenya milik induk
            if allow_approx and c["kind"] in (0, 1):
                ovr = [o for o in self.overrides_of(d) if o != res and o != c["dst"]]
                if 0 < len(ovr) <= MAX_DISPATCH_FANOUT:
                    out += [(o, HOW_DISPATCH) for o in ovr]
                elif ovr:
                    self.skipped_dispatch += 1
        if allow_approx:
            for r in conn.execute("SELECT cls, kind FROM cref WHERE src = ? AND kind IN (0, 1) ORDER BY cls", (node,)):
                info = conn.execute("SELECT name, declared, is_lib FROM cls WHERE id = ?", (r["cls"],)).fetchone()
                if info is None or not info["declared"] or info["is_lib"]:
                    continue
                if r["kind"] == 1 and self.is_component(r["cls"]):
                    out += [(m, HOW_INTENT) for m in self.declared_methods(r["cls"], True)]
                elif r["kind"] == 0 and "$" in info["name"]:
                    out += [(m, HOW_CALLBACK) for m in self.declared_methods(r["cls"], False)]
        return out


def _like_prefix(name: str) -> str:
    return name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "$%"


def find_paths(conn: sqlite3.Connection, src_cls: sqlite3.Row, src_method: str | None, dst_cls: sqlite3.Row,
               dst_method: str | None, max_depth: int = 8, max_paths: int = 3, max_approx: int = 2) -> dict[str, Any]:
    """Jalur terpendek-terbobot dari titik awal ke target.

    max_approx = jumlah maksimum langkah PERKIRAAN (dispatch/intent/callback) per jalur; 0 = hanya invoke nyata.
    """
    strict = max_approx <= 0
    started = time.monotonic()
    q = ("SELECT m.id FROM msym m JOIN cls c ON c.id = m.cls WHERE m.declared = 1 AND (c.id = ? OR c.name LIKE ? ESCAPE '\\')")
    params: list[Any] = [src_cls["id"], _like_prefix(src_cls["name"])]
    if src_method:
        q += " AND m.name = ?"
        params.append(src_method)
    starts = [r[0] for r in conn.execute(q + " ORDER BY m.id LIMIT 400", params)]
    if not starts:
        raise GraphError(f"tidak ada method terdeklarasi untuk titik awal {src_cls['name']}"
                         + (f".{src_method}" if src_method else "") + " (class framework/pustaka tidak dianalisis).")

    tcls, _ = _related_down(conn, dst_cls["id"])
    targets: set[int] = set()
    if dst_method:
        for ch in _chunks(tcls):
            qq = ",".join("?" * len(ch))
            targets.update(r[0] for r in conn.execute(f"SELECT id FROM msym WHERE name = ? AND cls IN ({qq})", [dst_method, *ch]))
    else:
        targets.update(r[0] for r in conn.execute(
            "SELECT m.id FROM msym m JOIN cls c ON c.id = m.cls WHERE c.id = ? OR c.name LIKE ? ESCAPE '\\'",
            (dst_cls["id"], _like_prefix(dst_cls["name"]))))
    if not targets:
        raise GraphError(f"tidak ada simbol {dst_cls['name']}" + (f".{dst_method}" if dst_method else "")
                         + " yang pernah dipanggil/dideklarasikan oleh kode aplikasi (kode pustaka tidak dianalisis; "
                         "nama pustaka yang di-obfuscate R8 juga tidak akan cocok).")

    ps = _PathSearch(conn)
    # state per node: (biaya, jumlah langkah, jumlah langkah perkiraan, induk, how)
    best: dict[int, tuple[int, int, int, int | None, str]] = {s: (0, 0, 0, None, "awal") for s in starts}
    heap: list[tuple[int, int, int]] = [(0, s, s) for s in starts]       # (biaya, urutan, node)
    heapq.heapify(heap)
    done: set[int] = set()
    found: list[int] = []
    expanded = 0
    stop_reason = None
    tie = len(starts) + 1

    while heap and len(found) < max_paths:
        if time.monotonic() - started > PATH_TIME_BUDGET_S:
            stop_reason = "waktu"
            break
        if expanded >= MAX_PATH_NODES:
            stop_reason = "jumlah node"
            break
        cost, _t, node = heapq.heappop(heap)
        if node in done or best[node][0] != cost:
            continue
        done.add(node)
        if node in targets:
            found.append(node)
            continue                      # sampai target: jangan diperluas melewatinya
        _c, steps, approx, _p, _h = best[node]
        if steps >= max_depth:
            continue
        expanded += 1
        for nxt, how in ps.edges(node, not strict):
            if nxt in done:
                continue
            is_approx = how != "langsung"
            if is_approx and approx >= max_approx:
                continue
            nc = cost + EDGE_COST[how]
            old = best.get(nxt)
            if old is None or nc < old[0]:
                best[nxt] = (nc, steps + 1, approx + (1 if is_approx else 0), node, how)
                tie += 1
                heapq.heappush(heap, (nc, tie, nxt))

    def chain(node: int) -> list[tuple[int, str]]:
        out, cur = [], node
        while cur is not None and len(out) < 40:
            _c, _s, _a, parent, how = best[cur]
            out.append((cur, how))
            cur = parent  # type: ignore[assignment]
        out.reverse()
        return out

    chains = [chain(n) for n in found]
    names = _method_rows(conn, [n for c in chains for n, _ in c])
    resolved = {n: ps.resolve(r) for n, r in names.items() if not r["declared"]}
    names.update(_method_rows(conn, [v for v in resolved.values() if v is not None and v not in names]))
    paths = []
    for c in chains:
        steps_out = []
        for n, how in c:
            r = names.get(n)
            step = {"method": _label(r) if r else f"#{n}", "via": how, "aplikasi": bool(r and _is_app(r))}
            real = resolved.get(n)
            if real is not None and real in names and real != n:
                step["kode_ada_di"] = _label(names[real])        # simbol disebut lewat subclass, isinya milik induk
            steps_out.append(step)
        approx = sum(1 for st in steps_out if st["via"] not in ("awal", "langsung"))
        paths.append({"langkah": len(steps_out) - 1, "langkah_perkiraan": approx, "rantai": steps_out})
    result: dict[str, Any] = {
        "dari": src_cls["name"] + (f".{src_method}" if src_method else " (semua method + kelas dalam)"),
        "ke": dst_cls["name"] + (f".{dst_method}" if dst_method else ""),
        "mode": "ketat (hanya invoke nyata)" if strict else f"dengan perkiraan (maks {max_approx} langkah per jalur)",
        "jalur": paths, "node_diperiksa": expanded,
        "keterangan_via": "langsung = invoke nyata; dispatch = override dari tipe yang dipanggil; intent = const-class ke komponen; "
                          "callback = instance listener/lambda dibuat di method itu lalu dipanggil framework. Selain 'langsung' "
                          "adalah PERKIRAAN."}
    if ps.skipped_dispatch:
        result["dispatch_dilewati"] = (f"{ps.skipped_dispatch} panggilan virtual/interface dengan >{MAX_DISPATCH_FANOUT} implementer "
                                       "tidak diikuti (terlalu ambigu)")
    if not paths:
        result["catatan"] = ("Tidak ditemukan jalur statis"
                             + (f" (pencarian berhenti karena {stop_reason})" if stop_reason else f" dalam {max_depth} langkah")
                             + ". Itu BUKAN bukti tidak terjangkau: refleksi, callback framework, dan JNI tidak tampak di call graph.")
    return result


def _related_down(conn: sqlite3.Connection, cid: int) -> tuple[list[int], bool]:
    subs, cut = subtypes(conn, cid, 200)
    return [cid, *subs], cut


def smali_only_in_package(conn: sqlite3.Connection, package: str, java_names: set[str], limit: int = 100) -> list[str]:
    """Class aplikasi di `package` yang ada di smali tetapi tidak dihasilkan jadx (nama sederhana tidak ada di `java_names`)."""
    pre = package.strip()
    if not pre:
        return []
    like = pre.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + ".%"
    out: list[str] = []
    for r in conn.execute("SELECT name, simple FROM cls WHERE declared = 1 AND is_lib = 0 AND name LIKE ? ESCAPE '\\' "
                          "ORDER BY name LIMIT 4000", (like,)):
        if "." in r["name"][len(pre) + 1:]:
            continue                                   # subpackage lain
        simple = r["simple"]
        if "$$ExternalSynthetic" in simple or "$$Lambda" in simple:
            continue
        if simple in java_names or simple.split("$", 1)[0] in java_names:
            continue
        out.append(simple)
        if len(out) >= limit:
            break
    return out
