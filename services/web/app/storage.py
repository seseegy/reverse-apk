"""Halaman Penyimpanan (PRD 10, tahap 1): apa yang memakai disk, berapa besarnya, dan mana yang sudah tidak punya pemilik.

HANYA MEMBACA. Tidak ada fungsi di sini yang menghapus atau mengubah berkas/DB.

Dua sumber angka, sengaja dipisahkan karena biayanya jauh berbeda:
  * `from_db`   - dari DB (apk.size, artifact.size, analysis_file.size): instan, dipakai setiap halaman dibuka. Ini angka yang
                  DICATAT aplikasi; bisa berbeda dari disk bila ada berkas yang hilang/yatim.
  * `scan_disk` - memindai folder sungguhan: lambat (ratusan ribu berkas/detik; satu APK besar bisa jutaan berkas), jadi dijalankan
                  atas permintaan, berhenti dini bila melewati batas, dan hasilnya disimpan sebentar di memori (`ScanCache`).

Ukuran yang dilaporkan adalah ukuran DI DISK (blok terpakai, seperti `du`), bukan jumlah byte isi: ribuan berkas kecil masing-masing
memakai minimal satu blok, sehingga jumlah byte isi lebih kecil dari ruang yang benar-benar terpakai: 26% (apktool AntennaPod, 13.736
berkas), 19% (apktool NewPipe), 12% (jadx NexLoad, 22.014 berkas); terukur 12 Okt 2026 di sandbox pengembangan. Tanpa ini halaman akan
selalu tampak lebih kecil daripada `df`/`du` dan membingungkan.
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from rvcore import store
from rvcore.paths import SHA256_RE, Layout

# Batas pemindaian. Melewati salah satunya = hasil ditandai `partial` (angka adalah batas bawah), bukan galat.
SCAN_MAX_FILES = 3_000_000
SCAN_MAX_SECONDS = 20.0
CACHE_TTL = 120.0            # detik: pemindaian yang sama tidak diulang selama ini (tombol "Periksa ulang" mengabaikannya)
LIST_LIMIT = 200             # baris maksimum untuk daftar yatim / tak berkas (sisanya diringkas jumlahnya)

# Folder tanpa catatan DB yang lebih muda dari ini TIDAK dianggap yatim: worker membuat work/<id> sesaat sebelum/sesudah baris DB terlihat,
# dan unggahan bisa baru saja ditulis. Melaporkannya sebagai yatim berbahaya begitu ada tombol hapus (tahap berikutnya).
GRACE_SECONDS = 600

ANALYSIS_DIR_RE = re.compile(r"^[1-9][0-9]{0,9}$")
# Kategori untuk bar komposisi. `regen`: bisa dibuat ulang tanpa kehilangan data pengguna (lewat "Analisis ulang").
CATEGORIES = (
    ("apk", "APK asli", False),
    ("decompile", "Hasil dekompilasi", True),
    ("files", "Lampiran & hasil AI", False),
    ("db", "Database", False),
    ("tmp", "Sisa unggahan sementara", True),
)


# ---------------------------------------------------------------------------------------------- ukuran di disk
@dataclass
class TreeSize:
    disk: int = 0            # byte di disk (st_blocks x 512), hanya berkas biasa; blok folder sendiri tidak dihitung (≈1-3% lebih kecil dari `du`)
    apparent: int = 0        # jumlah byte isi (untuk perbandingan)
    files: int = 0
    newest: float = 0.0      # waktu ubah terbaru di antara berkas yang terlihat (0 = tidak ada berkas)
    partial: bool = False    # pemindaian berhenti sebelum selesai: angka adalah batas bawah

    def add(self, other: "TreeSize") -> None:
        self.disk += other.disk
        self.apparent += other.apparent
        self.files += other.files
        self.newest = max(self.newest, other.newest)
        self.partial = self.partial or other.partial


class Budget:
    """Batas bersama satu pemindaian penuh (jumlah berkas dan waktu), supaya total beban terbatas walau ada banyak folder."""

    def __init__(self, max_files: int = SCAN_MAX_FILES, max_seconds: float = SCAN_MAX_SECONDS,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.max_files, self.deadline, self.clock = max_files, clock() + max_seconds, clock
        self.seen = 0

    def exhausted(self) -> bool:
        return self.seen >= self.max_files or self.clock() >= self.deadline


def tree_size(root: Path | str, budget: Budget | None = None) -> TreeSize:
    """Ukuran di disk satu pohon. Tidak mengikuti symlink (symlink tidak dihitung). Folder tidak ada = 0."""
    out = TreeSize()
    stack = [str(root)]
    while stack:
        if budget is not None and budget.exhausted():
            out.partial = True
            return out
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            out.disk += st.st_blocks * 512
                            out.apparent += st.st_size
                            out.files += 1
                            out.newest = max(out.newest, st.st_mtime)
                            if budget is not None:
                                budget.seen += 1
                                # Diperiksa PER BERKAS, bukan hanya per folder: satu folder dengan jutaan berkas (res/, smali/) akan
                                # melewati batas sepenuhnya kalau anggaran hanya dicek di awal tiap folder. Jam dibaca tiap 512 berkas.
                                if budget.seen >= budget.max_files or (budget.seen & 511 == 0 and budget.exhausted()):
                                    out.partial = True
                                    return out
                    except OSError:
                        continue
        except OSError:
            continue
    return out


# ---------------------------------------------------------------------------------------------- bagian 1: dari DB
def from_db(conn: sqlite3.Connection) -> dict[str, Any]:
    """Angka yang DICATAT aplikasi, per APK dan total. Instan: tidak menyentuh disk."""
    rows = conn.execute(
        "SELECT a.id AS apk_id, a.filename_display AS name, a.app_label AS label, a.package AS package, a.version_name AS version, "
        "       a.size AS apk_size, a.created_at AS created_at, "
        "       an.id AS analysis_id, an.status AS status, "
        "       COALESCE((SELECT SUM(ar.size) FROM artifact ar JOIN analysis x ON x.id = ar.analysis_id "
        "                  WHERE x.apk_id = a.id AND ar.kind IN ('jadx','apktool','index')), 0) AS decompile, "
        "       COALESCE((SELECT SUM(ar.size) FROM artifact ar JOIN analysis x ON x.id = ar.analysis_id "
        "                  WHERE x.apk_id = a.id AND ar.kind IN ('jadx','apktool')), 0) AS cleanable, "
        "       COALESCE((SELECT SUM(f.size) FROM analysis_file f JOIN analysis x ON x.id = f.analysis_id WHERE x.apk_id = a.id), 0) AS files_size, "
        "       COALESCE((SELECT COUNT(*) FROM analysis_file f JOIN analysis x ON x.id = f.analysis_id WHERE x.apk_id = a.id), 0) AS files_count "
        "FROM apk a LEFT JOIN analysis an ON an.id = (SELECT MAX(id) FROM analysis WHERE apk_id = a.id) "
        "ORDER BY a.created_at DESC, a.id DESC"
    ).fetchall()
    items = []
    totals = {"apk": 0, "decompile": 0, "files": 0}
    for r in rows:
        decompile = int(r["decompile"] or 0)
        files_size = int(r["files_size"] or 0)
        apk_size = int(r["apk_size"] or 0)
        totals["apk"] += apk_size
        totals["decompile"] += decompile
        totals["files"] += files_size
        items.append({
            "apk_id": r["apk_id"], "analysis_id": r["analysis_id"], "status": r["status"],
            "name": r["label"] or r["name"], "file": r["name"], "package": r["package"], "version": r["version"],
            "apk": apk_size, "decompile": decompile, "cleanable": int(r["cleanable"] or 0), "files": files_size, "files_count": int(r["files_count"] or 0),
            "total": apk_size + decompile + files_size, "created_at": r["created_at"],
            "active": r["status"] in store.ACTIVE if r["status"] else False,
        })
    items.sort(key=lambda i: (-i["total"], i["apk_id"]))
    return {"items": items, "totals": totals, "count": len(items)}


# ---------------------------------------------------------------------------------------------- bagian 2: dari disk
@dataclass
class DiskScan:
    """Hasil satu pemindaian disk. `orphan_*` = ada di disk tanpa catatan DB; `missing_*` = dicatat DB tanpa berkas di disk.

    `partial`: pemindaian berhenti sebelum selesai (anggaran habis). Angka ukuran adalah batas bawah. `orphan_*` yang terlihat tetap
    benar, tetapi daftar belum tentu lengkap. `missing_*` tidak bergantung pada anggaran, jadi selalu lengkap."""
    taken_at: float = 0.0
    seconds: float = 0.0
    roots: dict[str, TreeSize] = field(default_factory=dict)       # uploads / work / files / db
    tmp: TreeSize = field(default_factory=TreeSize)               # uploads/.tmp + files/.tmp
    work_by_analysis: dict[int, TreeSize] = field(default_factory=dict)
    files_by_analysis: dict[int, TreeSize] = field(default_factory=dict)
    orphan_work: list[dict[str, Any]] = field(default_factory=list)
    orphan_files: list[dict[str, Any]] = field(default_factory=list)
    orphan_uploads: list[dict[str, Any]] = field(default_factory=list)
    missing_uploads: list[dict[str, Any]] = field(default_factory=list)
    missing_files: list[dict[str, Any]] = field(default_factory=list)
    unknown_work: list[dict[str, Any]] = field(default_factory=list)   # isi work/ yang bukan folder analisis (mis. berkas liar)
    recent: list[dict[str, Any]] = field(default_factory=list)         # tanpa catatan DB tetapi baru dibuat (< GRACE_SECONDS): bukan yatim
    trash: TreeSize = field(default_factory=TreeSize)                  # .trash: sudah dipindahkan, menunggu dihapus di belakang layar
    partial: bool = False
    error: str | None = None


def _children(path: Path) -> list[os.DirEntry]:
    try:
        with os.scandir(path) as it:
            return sorted(it, key=lambda e: e.name)
    except OSError:
        return []


def scan_disk(layout: Layout, conn: sqlite3.Connection, budget: Budget | None = None,
              clock: Callable[[], float] = time.time) -> DiskScan:
    """Pindai folder data dan cocokkan dengan DB. Hanya membaca. Berhenti dini (partial=True) bila anggaran habis."""
    started = time.monotonic()
    budget = budget or Budget()
    res = DiskScan(taken_at=clock())

    analysis_ids = {int(r[0]) for r in conn.execute("SELECT id FROM analysis")}
    apk_hashes = {r[0]: int(r[1]) for r in conn.execute("SELECT sha256, id FROM apk")}

    # --- db/ dan .tmp (kecil: dipindai lebih dulu, supaya angkanya tidak ikut hilang bila anggaran habis di folder besar)
    res.roots["db"] = tree_size(layout.db_dir, budget)
    for tmp_dir in (layout.uploads_tmp, layout.files_tmp):
        res.tmp.add(tree_size(tmp_dir, budget))

    # --- uploads/<sha256>.apk : APK asli
    up = TreeSize()
    on_disk_hashes: set[str] = set()
    for e in _children(layout.uploads):
        if e.name == ".tmp":
            continue
        if e.name == ".trash":
            res.trash.add(tree_size(e.path, budget))
            continue
        if e.is_symlink() or not e.is_file(follow_symlinks=False):
            continue
        try:
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue
        up.disk += st.st_blocks * 512
        up.apparent += st.st_size
        up.files += 1
        stem = e.name[:-len(".apk")] if e.name.endswith(".apk") else ""
        if SHA256_RE.match(stem) and stem in apk_hashes:
            on_disk_hashes.add(stem)
        elif res.taken_at - st.st_mtime < GRACE_SECONDS:
            res.recent.append({"where": "uploads", "name": e.name, "disk": st.st_blocks * 512})
        else:
            res.orphan_uploads.append({"name": e.name, "disk": st.st_blocks * 512, "mtime": st.st_mtime})
    res.roots["uploads"] = up

    # --- work/<analysis_id>/ : hasil dekompilasi
    work = TreeSize()
    for e in _children(layout.work):
        if budget.exhausted():
            res.partial = True
            break
        if e.is_symlink():
            continue
        if e.name == ".trash":
            res.trash.add(tree_size(e.path, budget))
            continue
        if not e.is_dir(follow_symlinks=False):
            res.unknown_work.append({"name": e.name})
            continue
        size = tree_size(e.path, budget)
        work.add(size)
        if ANALYSIS_DIR_RE.match(e.name) and int(e.name) in analysis_ids:
            res.work_by_analysis[int(e.name)] = size
        else:
            _unowned(res, "work", e, size, res.orphan_work)
    res.roots["work"] = work

    # --- files/<analysis_id>/{up,ai}/ : lampiran & hasil AI
    files = TreeSize()
    for e in _children(layout.files):
        if e.name == ".tmp":
            continue
        if e.name == ".trash":
            res.trash.add(tree_size(e.path, budget))
            continue
        if budget.exhausted():
            res.partial = True
            break
        if e.is_symlink() or not e.is_dir(follow_symlinks=False):
            continue
        size = tree_size(e.path, budget)
        files.add(size)
        if ANALYSIS_DIR_RE.match(e.name) and int(e.name) in analysis_ids:
            res.files_by_analysis[int(e.name)] = size
        else:
            _unowned(res, "files", e, size, res.orphan_files)
    res.roots["files"] = files

    # --- catatan DB tanpa berkas
    for sha, apk_id in apk_hashes.items():
        if sha not in on_disk_hashes:
            row = conn.execute("SELECT filename_display, size FROM apk WHERE id = ?", (apk_id,)).fetchone()
            res.missing_uploads.append({"apk_id": apk_id, "name": row["filename_display"], "size": int(row["size"] or 0)})
    res.missing_files = _missing_files(layout, conn)

    res.partial = res.partial or any(t.partial for t in res.roots.values()) or res.tmp.partial
    res.seconds = round(time.monotonic() - started, 2)
    for lst in (res.orphan_work, res.orphan_files, res.orphan_uploads):
        lst.sort(key=lambda x: -x.get("disk", 0))
    return res


def _mtime(entry: os.DirEntry) -> float:
    try:
        return entry.stat(follow_symlinks=False).st_mtime
    except OSError:
        return 0.0


def _unowned(res: DiskScan, where: str, entry: os.DirEntry, size: TreeSize, orphans: list[dict[str, Any]]) -> None:
    """Folder tanpa catatan DB: yatim bila sudah cukup lama, atau 'baru' (bukan yatim) bila baru dibuat. Umur diukur dari
    waktu ubah TERBARU di dalam folder yang terlihat (folder induk saja tidak cukup: isinya bisa baru ditulis)."""
    mtime = max(_mtime(entry), size.newest)
    row = {"name": entry.name, "disk": size.disk, "files": size.files, "partial": size.partial, "mtime": mtime}
    if res.taken_at - mtime < GRACE_SECONDS:
        res.recent.append({"where": where, **row})
    else:
        orphans.append(row)


def _missing_files(layout: Layout, conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Baris analysis_file yang berkasnya tidak ada di disk. Memakai aturan lokasi yang sama dengan FileStore.abs_path
    (aman terhadap symlink) supaya hasilnya sama dengan yang dilihat halaman Berkas."""
    from rvcore.fsutil import resolve_under     # impor lokal: hanya dipakai di sini

    out: list[dict[str, Any]] = []
    for r in conn.execute("SELECT id, analysis_id, kind, path, name, size FROM analysis_file ORDER BY analysis_id, id"):
        kind_dir = layout.files_dir(r["analysis_id"]) / ("up" if r["kind"] == "upload" else "ai")
        target = resolve_under(kind_dir, *str(r["path"]).split("/"))
        if target is None or not target.is_file():
            out.append({"id": r["id"], "analysis_id": r["analysis_id"], "kind": r["kind"], "name": r["name"], "size": int(r["size"] or 0)})
    return out


# ---------------------------------------------------------------------------------------------- cache pemindaian
class ScanCache:
    """Satu pemindaian pada satu waktu; hasil dipakai ulang selama `ttl` detik.

    Web berjalan dengan SATU proses (`--workers 1`), jadi cache di memori konsisten. Bila nanti jumlah proses bertambah, tiap proses
    punya cache sendiri: tidak salah, hanya memindai lebih sering."""

    def __init__(self, ttl: float = CACHE_TTL) -> None:
        self.ttl = ttl
        self._lock = threading.Lock()
        self._busy = threading.Lock()
        self._scan: DiskScan | None = None

    def peek(self) -> DiskScan | None:
        with self._lock:
            return self._scan

    def invalidate(self) -> None:
        """Buang hasil lama (dipakai sesudah penghapusan: daftar yatim/ukuran lama tidak lagi benar)."""
        with self._lock:
            self._scan = None

    def fresh(self, now: float | None = None) -> bool:
        with self._lock:
            s = self._scan
        return s is not None and ((now if now is not None else time.time()) - s.taken_at) < self.ttl

    def get(self, run: Callable[[], DiskScan], force: bool = False) -> tuple[DiskScan | None, bool]:
        """(hasil, sedang_dipindai_proses_lain). Bila ada pemindaian yang sedang berjalan, tidak menunggu dan tidak memulai yang baru."""
        if not force and self.fresh():
            return self.peek(), False
        if not self._busy.acquire(blocking=False):
            return self.peek(), True
        try:
            try:
                result = run()
            except Exception as exc:  # noqa: BLE001 - kegagalan memindai tidak boleh menjatuhkan halaman
                result = DiskScan(taken_at=time.time(), error=type(exc).__name__)
            with self._lock:
                self._scan = result
            return result, False
        finally:
            self._busy.release()


# ---------------------------------------------------------------------------------------------- ringkasan untuk tampilan
def composition(totals_db: dict[str, int], scan: DiskScan | None) -> dict[str, Any]:
    """Segmen bar komposisi. Memakai ukuran DI DISK bila sudah dipindai; bila belum, angka catatan DB (diberi label jelas)."""
    if scan is not None and not scan.error:
        sizes = {"apk": scan.roots["uploads"].disk, "decompile": scan.roots["work"].disk,
                 "files": scan.roots["files"].disk, "db": scan.roots["db"].disk, "tmp": scan.tmp.disk}
        source = "disk"
    else:
        sizes = {"apk": totals_db["apk"], "decompile": totals_db["decompile"], "files": totals_db["files"], "db": None, "tmp": None}
        source = "db"
    known = sum(v for v in sizes.values() if v)
    segments = []
    for key, label, regen in CATEGORIES:
        v = sizes[key]
        if v is None:
            continue
        segments.append({"key": key, "label": label, "bytes": v, "regen": regen,
                         "pct": round(v / known * 100, 1) if known else 0.0})
    return {"segments": segments, "known": known, "source": source}


def host_view(usage: Any, app_bytes: int) -> dict[str, Any]:
    """Pisahkan disk server menjadi: dipakai aplikasi / dipakai hal lain (OS, Docker, log) / cadangan filesystem / bebas.

    `usage` = shutil.disk_usage. `used` Python = total - f_bfree (tidak menghitung blok cadangan root); `free` = f_bavail. Selisih
    total - used - free umumnya blok cadangan filesystem (ext4 bawaan ±5%) yang tidak bisa dipakai pengguna biasa; angka ini DIHITUNG,
    penyebabnya tidak diperiksa."""
    total, used, free = int(usage.total), int(usage.used), int(usage.free)
    reserved = max(0, total - used - free)
    app = min(max(0, app_bytes), used)                  # tidak mungkin lebih besar dari yang terpakai; selisih pembulatan/blok folder
    other = used - app

    def seg(key: str, label: str, value: int) -> dict[str, Any]:
        return {"key": key, "label": label, "bytes": value, "pct": round(value / total * 100, 1) if total else 0.0}

    return {"total": total, "used": used, "free": free, "reserved": reserved, "app": app, "other": other,
            "used_pct": round(used / total * 100) if total else 0,
            "free_pct": round(free / total * 100) if total else 0,
            "segments": [seg("app", "Dipakai aplikasi", app), seg("other", "Hal lain (OS, Docker, log)", other),
                         seg("reserved", "Cadangan sistem berkas", reserved), seg("free", "Bebas", free)]}


def disk_usage(path: Path | str) -> Any | None:
    try:
        return shutil.disk_usage(path)
    except OSError:
        return None
