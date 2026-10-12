"""Pembersihan penyimpanan (PRD 10, tahap 2): satu-satunya tempat yang MENGHAPUS dari halaman Penyimpanan.

Prinsip (urut dari yang paling penting):
  1. Tidak ada penghapus berkas mentah. Yang bisa dihapus hanya lima hal yang bernama dan tahu akibatnya (lihat `Kind`); jalurnya
     DIHITUNG di sini dari id/nama yang divalidasi, tidak pernah diterima dari klien sebagai path.
  2. Keputusan "boleh dihapus?" dibuat ULANG tepat sebelum menghapus (`plan_*`), bukan memakai hasil pemindaian lama: keadaan bisa
     berubah sejak pratinjau (analisis baru dimulai, folder baru muncul, catatan DB bertambah).
  3. Yang dipratinjau = yang boleh dihapus. Aksi massal membawa daftar nama eksplisit; yang tak lagi memenuhi syarat DILEWATI dan dilaporkan.
  4. Folder besar tidak dihapus di jalur permintaan: `rename` atomik ke `.trash` (cepat, tidak bisa setengah terhapus), lalu dihapus di
     belakang layar oleh `Reaper`. Sisa `.trash` setelah crash dibersihkan saat startup.
  5. Tidak menyentuh `db/`. Tidak mengikuti symlink. Tidak menghapus analisis yang sedang berjalan/antre.
  6. Yang dilaporkan adalah ukuran yang DIUKUR sebelum menghapus, bukan janji; jumlah yang benar-benar terhapus dihitung dari hasil.
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from rvcore import store
from rvcore.db import tx
from rvcore.fsutil import resolve_under, safe_rmtree
from rvcore.paths import SHA256_RE, Layout

from . import storage

TRASH = ".trash"
# Yang dibuang saat "Bersihkan hasil dekompilasi": hanya hasil dua alat. index/ (tab Temuan/Jaringan/pencarian), logs/, dan manifest.json
# SENGAJA dipertahankan: murah (index ±38 MB pada AntennaPod) dan masih dipakai halaman.
DECOMPILE_DIRS = ("apktool", "jadx")
TMP_MIN_AGE = 3600          # .tmp lebih muda dari ini mungkin unggahan yang sedang berjalan (sama dengan context.STALE_TMP_SECONDS)
ORPHAN_NAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,200}$")      # nama entri yang boleh dipilih; tanpa '/', '\', spasi, atau karakter kontrol


class Kind:
    DECOMPILE = "decompile"        # hasil dekompilasi satu analisis (bisa dibuat ulang)
    ORPHAN = "orphan"              # folder/berkas tanpa pemilik (tidak bisa dibuat ulang)
    TMP = "tmp"                    # sisa unggahan sementara
    RECORDS = "records"            # catatan lampiran/hasil AI yang berkasnya hilang
    ALL = (DECOMPILE, ORPHAN, TMP, RECORDS)


@dataclass
class Item:
    """Satu hal yang akan dihapus. `path` None untuk catatan DB."""
    key: str                       # pengenal stabil yang dikirim lewat form (bukan path)
    label: str
    disk: int = 0
    files: int = 0
    path: Path | None = None
    note: str = ""


@dataclass
class Plan:
    kind: str
    items: list[Item] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)      # (label, alasan)
    irreversible: bool = True
    title: str = ""
    consequence: str = ""

    @property
    def disk(self) -> int:
        return sum(i.disk for i in self.items)

    @property
    def files(self) -> int:
        return sum(i.files for i in self.items)


@dataclass
class Result:
    kind: str
    removed: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)
    freed: int = 0                 # ukuran di disk yang diukur sebelum dipindah
    pending: int = 0               # byte yang masih menunggu dihapus di .trash
    at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------------------------- trash
def trash_dir(root: Path) -> Path:
    return root / TRASH


def to_trash(path: Path, root: Path) -> Path | None:
    """Pindahkan `path` (di bawah `root`) ke root/.trash/<uuid>-<nama> dengan rename atomik. None bila gagal.

    rename hanya berhasil dalam filesystem yang sama; .trash sengaja berada di akar yang sama dengan sumbernya."""
    dest_dir = trash_dir(root)
    try:
        dest_dir.mkdir(exist_ok=True)
        dest = dest_dir / f"{uuid.uuid4().hex[:12]}-{path.name}"
        os.rename(path, dest)
        return dest
    except OSError:
        return None


def trash_size(layout: Layout) -> int:
    return sum(storage.tree_size(trash_dir(r)).disk for r in (layout.work, layout.files, layout.uploads))


class Reaper:
    """Menghapus isi `.trash` di belakang layar. Satu thread pada satu waktu; aman dipanggil berulang (idempoten)."""

    def __init__(self, layout: Layout, remover: Callable[[Path], None] = safe_rmtree) -> None:
        self.layout, self.remover = layout, remover
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def roots(self) -> list[Path]:
        return [trash_dir(r) for r in (self.layout.work, self.layout.files, self.layout.uploads)]

    def pending(self) -> bool:
        for t in self.roots():
            try:
                if any(True for _ in os.scandir(t)):
                    return True
            except OSError:
                continue
        return False

    def sweep(self) -> int:
        """Hapus semua isi .trash sekarang (sinkron). Mengembalikan jumlah entri yang berhasil dihapus."""
        n = 0
        for t in self.roots():
            try:
                entries = list(os.scandir(t))
            except OSError:
                continue
            for e in entries:
                try:
                    if e.is_dir(follow_symlinks=False) and not e.is_symlink():
                        self.remover(Path(e.path))
                    else:
                        os.unlink(e.path)
                    n += 1
                except OSError:
                    continue                      # coba lagi pada sapuan berikutnya; tidak boleh menjatuhkan thread
        return n

    def start(self) -> bool:
        """Mulai sapuan di thread latar bila belum ada yang berjalan. True bila thread baru dimulai."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._thread = threading.Thread(target=self._run, name="storage-reaper", daemon=True)
            self._thread.start()
            return True

    def _run(self) -> None:
        try:
            self.sweep()
        except Exception:  # noqa: BLE001 - thread latar tidak boleh mati diam-diam tanpa jejak
            import logging
            logging.getLogger("reverse-apk").exception("sapuan .trash gagal")

    def join(self, timeout: float = 30.0) -> None:
        t = self._thread
        if t is not None:
            t.join(timeout)


# ---------------------------------------------------------------------------------------------- perencanaan (verifikasi)
def _analysis(conn: sqlite3.Connection, analysis_id: int):
    return conn.execute("SELECT id, status FROM analysis WHERE id = ?", (analysis_id,)).fetchone()


def plan_decompile(layout: Layout, conn: sqlite3.Connection, analysis_id: int) -> Plan:
    """Hasil dekompilasi satu analisis. Ditolak (items kosong + alasan) bila analisis tidak ada atau masih aktif."""
    plan = Plan(Kind.DECOMPILE, irreversible=False, title="Bersihkan hasil dekompilasi",
                consequence=("Tab Kode menjadi kosong dan asisten AI tidak bisa membaca kode sampai Anda menjalankan Analisis ulang. "
                             "Temuan, jaringan, pencarian, manifes, dan log tetap ada. Hasil bisa dibuat ulang selama APK aslinya masih ada."))
    row = _analysis(conn, analysis_id)
    if row is None:
        plan.skipped.append((f"analisis #{analysis_id}", "tidak ditemukan"))
        return plan
    if row["status"] in store.ACTIVE:
        plan.skipped.append((f"analisis #{analysis_id}", "masih antre/berjalan; tunggu selesai atau batalkan dulu"))
        return plan
    for name in DECOMPILE_DIRS:
        path = resolve_under(layout.work, str(int(analysis_id)), name)
        if path is None or not path.is_dir() or path.is_symlink():
            continue
        # Cek keberadaan di bawah work/<id>/ lewat realpath: symlink yang menunjuk keluar ditolak (resolve_under mengembalikan None).
        size = storage.tree_size(path)
        plan.items.append(Item(key=f"{int(analysis_id)}/{name}", label=f"{name}/ (analisis #{int(analysis_id)})", disk=size.disk,
                               files=size.files, path=path))
    if not plan.items:
        plan.skipped.append((f"analisis #{analysis_id}", "tidak ada hasil dekompilasi di disk (sudah bersih)"))
    return plan


def _orphan_candidates(layout: Layout, conn: sqlite3.Connection, now: float) -> dict[str, Item]:
    """Semua yang SEKARANG memenuhi syarat 'tanpa pemilik', diindeks dengan key stabil `<akar>/<nama>`."""
    out: dict[str, Item] = {}
    analysis_ids = {int(r[0]) for r in conn.execute("SELECT id FROM analysis")}
    hashes = {r[0] for r in conn.execute("SELECT sha256 FROM apk")}
    for where, root in (("work", layout.work), ("files", layout.files)):
        try:
            entries = list(os.scandir(root))
        except OSError:
            continue
        for e in entries:
            if e.name in (".tmp", TRASH) or e.is_symlink() or not ORPHAN_NAME_RE.match(e.name):
                continue
            is_dir = e.is_dir(follow_symlinks=False)
            if where == "files" and not is_dir:
                continue
            if is_dir and storage.ANALYSIS_DIR_RE.match(e.name) and int(e.name) in analysis_ids:
                continue                                                  # punya pemilik
            size = storage.tree_size(e.path) if is_dir else _file_size(e)
            newest = max(size.newest, _mtime(e))
            if now - newest < storage.GRACE_SECONDS:
                continue                                                  # baru dibuat: mungkin sedang dikerjakan
            what = "folder" if is_dir else "berkas liar"
            out[f"{where}/{e.name}"] = Item(key=f"{where}/{e.name}", label=f"{where}/{e.name} ({what})", disk=size.disk,
                                            files=size.files, path=Path(e.path))
    try:
        entries = list(os.scandir(layout.uploads))
    except OSError:
        entries = []
    for e in entries:
        if e.name in (".tmp", TRASH) or e.is_symlink() or not e.is_file(follow_symlinks=False) or not ORPHAN_NAME_RE.match(e.name):
            continue
        stem = e.name[:-len(".apk")] if e.name.endswith(".apk") else ""
        if SHA256_RE.match(stem) and stem in hashes:
            continue
        try:
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue
        if now - st.st_mtime < storage.GRACE_SECONDS:
            continue
        out[f"uploads/{e.name}"] = Item(key=f"uploads/{e.name}", label=f"uploads/{e.name} (APK tanpa catatan)", disk=st.st_blocks * 512,
                                        files=1, path=Path(e.path))
    return out


def _file_size(e: os.DirEntry) -> "storage.TreeSize":
    t = storage.TreeSize()
    try:
        st = e.stat(follow_symlinks=False)
        t.disk, t.apparent, t.files, t.newest = st.st_blocks * 512, st.st_size, 1, st.st_mtime
    except OSError:
        pass
    return t


def _mtime(e: os.DirEntry) -> float:
    try:
        return e.stat(follow_symlinks=False).st_mtime
    except OSError:
        return 0.0


def plan_orphans(layout: Layout, conn: sqlite3.Connection, keys: Iterable[str] | None = None, now: float | None = None) -> Plan:
    """Sisa tanpa pemilik. `keys=None` = pratinjau SEMUA yang sekarang memenuhi syarat; `keys=[...]` = hanya yang dipilih, dan yang
    sudah tidak memenuhi syarat dilewati (dengan alasan) alih-alih dihapus."""
    plan = Plan(Kind.ORPHAN, irreversible=True, title="Hapus sisa tanpa pemilik",
                consequence=("Tidak ada catatan yang terkait dengan item ini, jadi tidak bisa dibuat ulang dan tidak bisa dikembalikan. "
                             "Item yang baru dibuat (kurang dari 10 menit) atau yang kini ternyata punya pemilik tidak ikut dihapus."))
    now = time.time() if now is None else now
    candidates = _orphan_candidates(layout, conn, now)
    if keys is None:
        plan.items = sorted(candidates.values(), key=lambda i: -i.disk)
        return plan
    for key in dict.fromkeys(keys):                                       # buang duplikat, pertahankan urutan
        item = candidates.get(key)
        if item is None:
            plan.skipped.append((key, "tidak lagi memenuhi syarat (sudah hilang, baru dibuat, atau kini punya pemilik)"))
        else:
            plan.items.append(item)
    return plan


def plan_tmp(layout: Layout, now: float | None = None) -> Plan:
    """Sisa unggahan sementara yang lebih tua dari TMP_MIN_AGE. Unggahan yang sedang berjalan TIDAK pernah ikut."""
    plan = Plan(Kind.TMP, irreversible=True, title="Hapus sisa unggahan sementara",
                consequence="Berkas sisa unggahan yang terputus (lebih dari 1 jam). Unggahan yang sedang berjalan tidak ikut dihapus.")
    now = time.time() if now is None else now
    for where, d in (("uploads", layout.uploads_tmp), ("files", layout.files_tmp)):
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            if e.is_symlink() or not e.is_file(follow_symlinks=False) or not ORPHAN_NAME_RE.match(e.name):
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if now - st.st_mtime < TMP_MIN_AGE:
                continue
            plan.items.append(Item(key=f"{where}/{e.name}", label=f"{where}/.tmp/{e.name}", disk=st.st_blocks * 512, files=1, path=Path(e.path)))
    plan.items.sort(key=lambda i: -i.disk)
    return plan


def plan_records(layout: Layout, conn: sqlite3.Connection, ids: Iterable[int] | None = None) -> Plan:
    """Catatan analysis_file yang berkasnya tidak ada. Dicek ulang per id: yang berkasnya ternyata ada kembali dilewati."""
    plan = Plan(Kind.RECORDS, irreversible=True, title="Bereskan catatan tanpa berkas",
                consequence="Hanya baris database yang dihapus (berkasnya memang sudah tidak ada). Halaman Berkas berhenti menampilkannya.")
    missing = {m["id"]: m for m in storage._missing_files(layout, conn)}
    if ids is None:
        wanted = list(missing)
    else:
        wanted = list(dict.fromkeys(int(i) for i in ids))
    for fid in wanted:
        m = missing.get(fid)
        if m is None:
            plan.skipped.append((f"catatan #{fid}", "tidak lagi hilang atau sudah tidak ada"))
            continue
        row = conn.execute("SELECT a.status FROM analysis a WHERE a.id = ?", (m["analysis_id"],)).fetchone()
        if row is not None and row["status"] in store.ACTIVE:
            plan.skipped.append((f"catatan #{fid}", "analisisnya sedang berjalan"))
            continue
        plan.items.append(Item(key=str(fid), label=f"{m['name']} (analisis #{m['analysis_id']}, {'lampiran' if m['kind'] == 'upload' else 'hasil AI'})",
                               disk=0, files=0, note=f"analysis={m['analysis_id']}"))
    return plan


# ---------------------------------------------------------------------------------------------- eksekusi
def _root_for(layout: Layout, key: str) -> Path | None:
    """Akar tempat sebuah key `<akar>/<nama>` berada. Hanya tiga akar yang dikenal; `db/` tidak pernah."""
    head = key.split("/", 1)[0]
    return {"work": layout.work, "files": layout.files, "uploads": layout.uploads}.get(head)


def _move_item(item: Item, root: Path) -> Path | None:
    """Pindahkan satu item ke .trash. Mengembalikan lokasi di .trash (untuk bisa dibatalkan), atau None bila ditolak/gagal.

    Menolak bila path bukan di bawah `root` (pertahanan berlapis: path sudah dihitung dari nama yang divalidasi, tetapi penghapusan tidak
    boleh bergantung pada satu lapis saja).

    IZIN: memindahkan SEBUAH DIREKTORI ke induk lain butuh izin tulis pada direktori itu sendiri (entri '..' di dalamnya harus diperbarui),
    bukan hanya pada induknya. Hasil jadx/apktool bisa berupa direktori r-x (terukur: rename gagal dengan PermissionError sebagai non-root,
    uid 10001 seperti di produksi). Karena itu izin tulis direktori ITU dipulihkan dulu bila rename pertama gagal. Hanya direktori teratas
    yang perlu; isinya tidak disentuh (penghapusan akhir oleh Reaper/safe_rmtree memperbaiki izin sisanya)."""
    path = item.path
    if path is None:
        return None
    try:
        real_root = Path(os.path.realpath(root))
        parent = Path(os.path.realpath(path.parent))
        if path.is_symlink() or real_root not in (parent, *parent.parents) or path.name in ("", ".", "..", TRASH):
            return None
    except OSError:
        return None
    if not path.exists():
        return None
    moved = to_trash(path, root)
    if moved is None and path.is_dir():
        try:
            os.chmod(path, 0o700)
        except OSError:
            return None
        moved = to_trash(path, root)
    return moved


def _restore(moved: list[tuple[Path, Path]]) -> None:
    """Kembalikan item yang sudah dipindah ke .trash ke tempat asalnya (dipakai bila transaksi DB gagal sesudah rename)."""
    for original, in_trash in reversed(moved):
        try:
            if in_trash.exists() and not original.exists():
                os.rename(in_trash, original)
        except OSError:
            pass


def execute(layout: Layout, conn: sqlite3.Connection, kind: str, *, analysis_id: int | None = None,
            keys: Iterable[str] | None = None, ids: Iterable[int] | None = None, ip: str = "-",
            audit: Callable[[sqlite3.Connection, str, dict[str, Any]], None] | None = None,
            reaper: Reaper | None = None, now: float | None = None) -> Result:
    """Verifikasi ulang lalu hapus. Mengembalikan apa yang BENAR-BENAR dipindahkan.

    Penghapusan folder analisis dilakukan DI DALAM transaksi DB (BEGIN IMMEDIATE) bersama pemeriksaan status: 'Analisis ulang' dan klaim
    worker juga mengubah status lewat transaksi tulis, jadi keduanya tidak bisa menyelinap di antara pemeriksaan dan rename."""
    if kind not in Kind.ALL:
        raise ValueError(f"jenis tidak dikenal: {kind!r}")
    audit = audit or store_audit
    res = Result(kind=kind)

    if kind == Kind.DECOMPILE:
        if analysis_id is None:
            raise ValueError("analysis_id wajib untuk membersihkan hasil dekompilasi")
        moved: list[tuple[Path, Path]] = []
        try:
            with tx(conn):                                                      # BEGIN IMMEDIATE: status tidak bisa berubah di tengah
                plan = plan_decompile(layout, conn, analysis_id)
                res.skipped = list(plan.skipped)
                for item in plan.items:
                    dest = _move_item(item, layout.work)
                    if dest is None:
                        res.skipped.append((item.label, "gagal dipindahkan (berkas berubah atau tidak bisa ditulis)"))
                        continue
                    moved.append((item.path, dest))
                    res.removed += 1
                    res.freed += item.disk
                if moved:
                    conn.execute("DELETE FROM artifact WHERE analysis_id = ? AND kind IN ('apktool','jadx')", (analysis_id,))
                    conn.execute("INSERT INTO analysis_log (analysis_id, ts, stage, level, message) VALUES (?, ?, NULL, 'info', ?)",
                                 (analysis_id, time.time(), "Hasil dekompilasi (apktool/jadx) dibersihkan dari halaman Penyimpanan. "
                                                            "Jalankan Analisis ulang untuk membuatnya lagi."))
                    audit(conn, "storage_clean", {"kind": kind, "analysis_id": int(analysis_id), "items": [i.key for i in plan.items][:50],
                                                  "freed": res.freed, "ip": ip})
        except BaseException:
            _restore(moved)           # transaksi dibatalkan -> DB menganggap hasil masih ada, jadi disk harus ikut dikembalikan
            raise
    elif kind == Kind.ORPHAN:
        moved = []
        try:
            with tx(conn):            # kunci tulis: tidak ada analisis/APK baru yang bisa terdaftar di antara verifikasi dan rename
                plan = plan_orphans(layout, conn, keys, now)
                res.skipped = list(plan.skipped)
                for item in plan.items:
                    root = _root_for(layout, item.key)
                    dest = _move_item(item, root) if root is not None else None
                    if dest is None:
                        res.skipped.append((item.label, "gagal dipindahkan"))
                        continue
                    moved.append((item.path, dest))
                    res.removed += 1
                    res.freed += item.disk
                if moved or res.skipped:
                    audit(conn, "storage_clean", {"kind": kind, "items": [i.key for i in plan.items][:50], "removed": res.removed,
                                                  "skipped": len(res.skipped), "freed": res.freed, "ip": ip})
        except BaseException:
            _restore(moved)
            raise
    elif kind == Kind.TMP:
        plan = plan_tmp(layout, now)
        for item in plan.items:
            try:
                os.unlink(item.path)                                           # berkas kecil biasa: tidak perlu .trash
                res.removed += 1
                res.freed += item.disk
            except OSError:
                res.skipped.append((item.label, "gagal dihapus"))
        if res.removed:
            with tx(conn):
                audit(conn, "storage_clean", {"kind": kind, "removed": res.removed, "freed": res.freed, "ip": ip})
    else:   # RECORDS
        with tx(conn):
            plan = plan_records(layout, conn, ids)
            res.skipped = list(plan.skipped)
            for item in plan.items:
                n = conn.execute("DELETE FROM analysis_file WHERE id = ?", (int(item.key),)).rowcount
                res.removed += 1 if n else 0
            if res.removed:
                audit(conn, "storage_clean", {"kind": kind, "removed": res.removed, "ids": [int(i.key) for i in plan.items][:50], "ip": ip})

    if res.removed and kind in (Kind.DECOMPILE, Kind.ORPHAN) and reaper is not None:
        reaper.start()
    if reaper is not None:
        res.pending = trash_size(layout)
    return res


def store_audit(conn: sqlite3.Connection, action: str, detail: dict[str, Any]) -> None:
    """Catat audit di transaksi yang sedang berjalan. Berbeda dari context.audit_event: di sini audit HARUS ikut transaksi yang sama
    dengan penghapusan catatan, dan kegagalan mencatat membatalkan seluruh aksi (gagal-tertutup)."""
    store.audit(conn, action, detail)
