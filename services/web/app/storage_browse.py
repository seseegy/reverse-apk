"""Penjelajah folder (PRD 10, tahap 3): MELIHAT dan MENGUNDUH isi penyimpanan. Tidak ada satu pun fungsi di sini yang menulis atau menghapus.

Ini penyaji berkas dari disk lewat jalur yang dipilih pengguna (pola klasik path traversal), jadi aturannya sempit dan eksplisit:
  1. DAFTAR PUTIH, bukan daftar hitam. Hanya akar dan sub-folder yang disebut di `ROOTS`/`WORK_ALLOWED` yang bisa dijangkau; yang lain ditolak.
  2. `work/<id>/index/` DITUTUP. Isinya findings.jsonl (nilai rahasia MENTAH, field `secret`) dan index.sqlite (string kode); aplikasi sengaja tidak
     pernah mengirim nilai itu ke browser kecuali lewat tombol 'Tampilkan nilai' yang tercatat di audit log (`secret_reveal`). Terbukti: Scanner
     menyimpan 'AKIAIOSFODNN7EXAMPLE' apa adanya di keduanya. Penampil kode yang ada juga tidak pernah membuka index/.
  3. `db/` TIDAK bisa dijelajahi sama sekali (hanya ukurannya di halaman Penyimpanan).
  4. Penjagaan jalur memakai pola yang sama dengan codeindex: tolak '..', mutlak, NUL, backslash, lalu realpath harus tetap di bawah akar
     (symlink keluar ditolak), dan berkas dibuka dengan O_NOFOLLOW + cek berkas biasa.
  5. Nama yang ditampilkan berasal dari disk (tak tepercaya): selalu di-escape oleh Jinja; nama yang tak valid UTF-8 dipertahankan lewat
     'surrogateescape'. Nama yang bukan UTF-8 valid TIDAK ditawarkan (tidak bisa dijadikan URL; terukur: tanpa ini satu berkas membuat seluruh
     halaman folder galat 500) tetapi dihitung dan dijelaskan di UI.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rvcore.fsutil import resolve_under
from rvcore.paths import SHA256_RE, Layout

PAGE_SIZE = 200               # entri per halaman: folder res/ bisa berisi puluhan ribu berkas
MAX_VIEW_BYTES = 512 * 1024   # batas tampilan teks (berkas utuh tetap bisa diunduh)
MAX_PATH_LEN = 600
MAX_ENTRIES_SCANNED = 200_000    # pagar: folder dengan lebih banyak entri dari ini dipotong (diberi tanda), bukan dibiarkan memakan memori

# Akar yang bisa dijelajahi. id (di URL) -> label. `db` SENGAJA tidak ada.
ROOTS = {"uploads": "APK asli", "work": "Hasil dekompilasi", "files": "Lampiran & hasil AI"}

# Di dalam work/<id>/ hanya ini yang boleh dilihat. index/ ditutup (lihat docstring modul). Nama berkas di tingkat atas yang diizinkan:
WORK_ALLOWED_DIRS = ("apktool", "jadx", "logs")
WORK_ALLOWED_FILES = ("manifest.json",)
# Di dalam files/<id>/ hanya dua kategori (sama dengan FileStore): up = lampiran pengguna, ai = hasil AI.
FILES_ALLOWED_DIRS = ("up", "ai")

_ID_RE = re.compile(r"^[1-9][0-9]{0,9}$")
_TEXT_EXTS = frozenset("""txt md json xml yml yaml toml ini cfg conf properties html css js ts java kt kts smali py sh gradle sql log csv proto
    gitignore pro txt bat ps1 c h cc cpp rs go rb php swift dart lua""".split())


@dataclass
class Entry:
    name: str
    path: str                      # jalur relatif terhadap akar penjelajah (dipakai di URL), selalu dengan '/'
    is_dir: bool
    size: int = 0                  # byte di disk untuk berkas; 0 untuk folder
    mtime: float = 0.0
    note: str = ""                 # keterangan untuk pengguna (mis. 'tertutup')


@dataclass
class Listing:
    root: str
    path: str
    entries: list[Entry] = field(default_factory=list)
    total: int = 0
    page: int = 1
    pages: int = 1
    truncated: bool = False        # folder punya lebih banyak entri daripada yang dipindai
    crumbs: list[tuple[str, str]] = field(default_factory=list)       # (label, path) untuk remah roti
    hidden: list[str] = field(default_factory=list)                   # nama yang ada di disk tetapi sengaja tidak ditawarkan
    undecodable: int = 0           # entri yang namanya bukan UTF-8 valid: tidak bisa dijadikan alamat (URL), jadi tidak ditawarkan tetapi DIHITUNG


# ---------------------------------------------------------------------------------------------- penjagaan jalur
def _parts(rel: str) -> list[str] | None:
    """Pecah jalur relatif dari klien. None bila berbahaya. Komponen kosong dan '.' dibuang; '..' ditolak."""
    if not isinstance(rel, str) or len(rel) > MAX_PATH_LEN or "\x00" in rel or "\\" in rel or rel.startswith("/"):
        return None
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    if any(len(p) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in p) for p in parts):
        return None
    return parts


def allowed(root: str, parts: list[str]) -> bool:
    """Apakah jalur (sudah dipecah) boleh dijangkau? Inti daftar putih. Tidak menyentuh disk."""
    if root == "uploads":
        # Hanya <sha256>.apk di tingkat atas. Tidak ada sub-folder, tidak ada .tmp/.trash.
        return len(parts) == 0 or (len(parts) == 1 and parts[0].endswith(".apk") and bool(SHA256_RE.match(parts[0][:-4])))
    if root == "work":
        if not parts:
            return True
        if not _ID_RE.match(parts[0]):
            return False                                  # .trash, .tmp, berkas liar, nama aneh: semuanya tertutup
        if len(parts) == 1:
            return True
        head = parts[1]
        if head in WORK_ALLOWED_DIRS:
            return True
        return len(parts) == 2 and head in WORK_ALLOWED_FILES          # manifest.json saja; index/ dan lainnya tertutup
    if root == "files":
        if not parts:
            return True
        if not _ID_RE.match(parts[0]):
            return False
        if len(parts) == 1:
            return True
        return parts[1] in FILES_ALLOWED_DIRS
    return False                                           # termasuk 'db': tidak pernah


def _base(layout: Layout, root: str) -> Path | None:
    return {"uploads": layout.uploads, "work": layout.work, "files": layout.files}.get(root)


def resolve(layout: Layout, root: str, rel: str) -> tuple[Path, list[str]] | None:
    """(path di disk, bagian jalur) atau None. Gabungan daftar putih + penjagaan symlink. Tidak membuka berkas."""
    parts = _parts(rel)
    base = _base(layout, root)
    if parts is None or base is None or not allowed(root, parts):
        return None
    if not parts:
        return base, parts
    target = resolve_under(base, *parts)       # realpath harus tetap di bawah akar; symlink ke luar -> None
    if target is None:
        return None
    # Setelah realpath, jalur nyata harus sama dengan jalur yang diminta: symlink DI DALAM akar yang menunjuk ke folder tertutup
    # (mis. work/1/jadx -> work/1/index) tidak boleh dipakai untuk mengelak dari daftar putih.
    expected = Path(os.path.realpath(base)).joinpath(*parts)
    if target != expected:
        return None
    return target, parts


def _label(name: str) -> str:
    """Nama dari disk untuk ditampilkan: byte tak valid diganti, bukan membuat halaman galat."""
    return name.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


# ---------------------------------------------------------------------------------------------- daftar isi
def root_summary(layout: Layout) -> list[dict[str, Any]]:
    """Akar-akar yang bisa dijelajahi (tanpa menghitung ukuran: itu tugas halaman Penyimpanan)."""
    out = []
    for rid, label in ROOTS.items():
        base = _base(layout, rid)
        out.append({"id": rid, "label": label, "exists": bool(base and base.is_dir())})
    return out


def crumbs(root: str, parts: list[str]) -> list[tuple[str, str]]:
    out = [(ROOTS.get(root, root), "")]
    for i, p in enumerate(parts):
        out.append((_label(p), "/".join(parts[:i + 1])))
    return out


def list_dir(layout: Layout, root: str, rel: str, page: int = 1, page_size: int = PAGE_SIZE) -> Listing | None:
    """Isi satu folder (tidak rekursif), terurut: folder dulu lalu berkas, nama menaik. None bila jalur tidak boleh/ tidak ada.

    Entri yang tidak masuk daftar putih TIDAK ditawarkan (mis. work/1/index), tetapi namanya dicatat di `hidden` agar UI bisa
    menjelaskan 'ada, sengaja disembunyikan' dan bukan membuat pengguna mengira hilang."""
    res = resolve(layout, root, rel)
    if res is None:
        return None
    target, parts = res
    if not target.is_dir() or target.is_symlink():
        return None
    lst = Listing(root=root, path="/".join(parts), crumbs=crumbs(root, parts))
    entries: list[Entry] = []
    scanned = 0
    try:
        with os.scandir(target) as it:
            for e in it:
                scanned += 1
                if scanned > MAX_ENTRIES_SCANNED:
                    lst.truncated = True
                    break
                try:
                    if e.is_symlink():
                        continue                                   # symlink tidak pernah ditawarkan
                    child = parts + [e.name]
                    if not allowed(root, child):
                        lst.hidden.append(_label(e.name))
                        continue
                    try:
                        e.name.encode("utf-8")
                    except UnicodeEncodeError:
                        lst.undecodable += 1                       # byte tak valid (surrogateescape): urlencode/Jinja akan gagal; jangan jatuhkan seluruh halaman
                        continue
                    if _parts("/".join(child)) is None:
                        continue                                   # nama dengan karakter kontrol/terlalu panjang: tautannya pasti ditolak, jangan ditawarkan
                    is_dir = e.is_dir(follow_symlinks=False)
                    if not is_dir and not e.is_file(follow_symlinks=False):
                        continue                                   # socket, fifo, dsb
                    st = e.stat(follow_symlinks=False)
                    entries.append(Entry(name=_label(e.name), path="/".join(child), is_dir=is_dir,
                                         size=0 if is_dir else st.st_blocks * 512, mtime=st.st_mtime))
                except OSError:
                    continue
    except OSError:
        return None
    entries.sort(key=lambda x: (not x.is_dir, x.name.lower(), x.name))
    lst.hidden.sort()
    lst.total = len(entries)
    lst.pages = max(1, -(-lst.total // page_size))
    lst.page = min(max(1, int(page or 1)), lst.pages)
    lst.entries = entries[(lst.page - 1) * page_size: lst.page * page_size]
    return lst


# ---------------------------------------------------------------------------------------------- berkas
def open_file(layout: Layout, root: str, rel: str):
    """(file object biner, ukuran, nama) untuk berkas biasa yang BOLEH dijangkau, atau None. Pemanggil wajib menutup file object."""
    res = resolve(layout, root, rel)
    if res is None or not res[1]:
        return None
    target, parts = res
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            return None
    except OSError:
        os.close(fd)
        return None
    return os.fdopen(fd, "rb"), st.st_size, parts[-1]


def read_text(layout: Layout, root: str, rel: str, limit: int = MAX_VIEW_BYTES) -> dict[str, Any] | None:
    """Pratinjau teks. {'binary': True} untuk berkas biner (tidak ditampilkan). Dipotong di `limit` byte."""
    opened = open_file(layout, root, rel)
    if opened is None:
        return None
    fh, size, name = opened
    with fh:
        data = fh.read(limit + 1)
    if b"\x00" in data[:8192]:
        return {"name": _label(name), "size": size, "binary": True}
    truncated = len(data) > limit
    text = data[:limit].decode("utf-8", errors="replace")
    return {"name": _label(name), "size": size, "binary": False, "truncated": truncated, "text": text, "lines": text.count("\n") + 1}
