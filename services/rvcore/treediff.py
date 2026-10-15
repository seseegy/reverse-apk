"""Manifes dan diff kanonik pohon proyek, serta salinan pohon yang aman (Tahap 2b). Hanya stdlib.

Dipakai SAMA PERSIS oleh bench (menghitung diff untuk dilihat pemilik) dan runner (menghitung ulang atas snapshot sebelum build):
isi yang sama menghasilkan `diff_sha256` yang sama di kedua sisi. Pohon yang dibaca ditulis oleh AI, jadi tidak ada yang dipercaya.

Aturan manifes (satu pejalan untuk hash, diff, dan salinan):
  * Symlink TIDAK PERNAH diikuti. Akar dibuka `O_NOFOLLOW|O_DIRECTORY`; tiap subdirektori dibuka relatif `dir_fd` dengan `O_NOFOLLOW`; berkas dibuka
    `O_NOFOLLOW|O_NONBLOCK` lalu `fstat` HARUS berkas biasa sebelum dibaca (FIFO yang ditukar di antara `lstat` dan `open` tidak menggantung).
  * Entri berkas: (jalur relatif, 'f', ukuran, sha256 isi, bit-x). Hanya bit eksekusi yang dihitung (ada bit x apa pun = 1); pemilik, mode lain, dan
    mtime diabaikan. `ukuran` dan `sha256` adalah byte yang BENAR-BENAR terbaca.
  * Direktori hanya dicatat bila KOSONG menurut `scandir` (tidak ada hasil sama sekali); isi direktori tercermin lewat berkasnya. Direktori yang
    isinya habis difilter (hanya symlink/FIFO/`build` akar) TIDAK dicatat dan TIDAK dibuat oleh `copy_tree_safe`, jadi hash pohon hidup == hash snapshot.
  * Symlink, perangkat, FIFO, dan soket DIABAIKAN (tidak masuk hash, tidak disalin) dan DIHITUNG (`symlink`, `special`). Berkas yang hilang atau diganti
    jenisnya saat dibaca dilewati dan dihitung (`vanished`). Berkas/direktori yang tidak bisa dibaca (EACCES/EPERM) menggagalkan seluruh operasi
    (`TreeLimitError('unreadable')`): gagal-tertutup, bukan diam-diam menghilangkan berkas dari hash.
  * `build/` dan `dist/` DI AKAR pohon diabaikan (dan dihitung `root_ignored`): itu direktori keluaran apktool. `apktool b` TANPA `-f` memakai ulang
    `build/apk/classes.dex` yang sudah ada, jadi cache itu tidak boleh ikut ke snapshot yang dibangun. Nama yang sama di kedalaman lain TIDAK diabaikan.
  * Urutan kanonik = urutan leksikografis kunci `tuple(os.fsencode(komponen))` (BYTE per komponen, bukan string jalur penuh): `res/values/x` mendahului
    `res/values-v21/y`, kebalikan dari urutan string karena '/' (0x2F) lebih besar daripada '-' (0x2D). Penggabung memakai kunci yang SAMA. Huruf besar-kecil
    dan bentuk Unicode (NFC/NFD) membedakan entri; urutan `scandir`, inode, dan mtime tidak berpengaruh.
  * Batas (zip-bomb jujur; melampaui = `TreeLimitError`, tidak pernah memotong diam-diam), berlaku PER POHON: jumlah entri (setiap nama yang ditemui
    `scandir`, termasuk yang diabaikan), total byte isi, byte per berkas, kedalaman, panjang nama dan jalur relatif (byte).

`diff_sha256` = sha256 dari byte persis `{"v":2,"e":[<entri>,...],"base":"<hex64>"}` (separator rapat, `ensure_ascii=True`, dihitung streaming dalam satu
lintasan). `base` ditaruh TERAKHIR karena baru diketahui setelah seluruh aliran pohon dasar habis dibaca penggabung; nilainya sha256 atas rekaman manifes
pohon dasar, sehingga hash mengikat (dasar + delta) = seluruh isi pohon yang dibangun. Isi berkas di-hash, bukan teks diff; hitungan baris tidak ikut hash.
"""

from __future__ import annotations

import collections
import errno
import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterator, NamedTuple

ROOT_IGNORE = ("build", "dist")          # hanya di AKAR pohon, peka huruf besar-kecil
PAYLOAD_VERSION = 2
ERROR_CODES = ("too_many_entries", "too_large", "file_too_large", "too_deep", "name_too_long", "unreadable", "timeout", "cancelled")

TOP_MAX = 40                             # entri berubah terbesar di ringkasan
TOP_PATH_MAX = 300                       # karakter jalur yang ditampilkan di ringkasan
# Batas JSON ringkasan: lebih kecil dari rvcore.store.BUILD_SUMMARY_MAX (8192; store MENOLAK, tidak memotong) agar ada sisa untuk pembungkus.
SUMMARY_MAX_CHARS = 7000
TEXT_FILES_MAX = 300                     # berkas pertama (urutan kanonik) yang dihitung +/- barisnya
TEXT_FILE_MAX_BYTES = 256 * 1024         # per sisi
TEXT_SNIFF_BYTES = 8 * 1024              # ada NUL di sini = bukan teks

CHUNK = 1024 * 1024
TICK_ENTRIES = 1000
TICK_BYTES = 64 * 1024 * 1024
TICK_SECONDS = 2.0                       # detak jantung/pembatalan paling jarang tiap ini, walau tanpa entri/byte baru

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_BIDI = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

_clock = time.monotonic                  # dicari saat dipanggil agar tes bisa menyuntikkan jam palsu


class TreeLimitError(Exception):
    """Batas dilampaui atau pohon tidak bisa diproses. `code` salah satu `ERROR_CODES`."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message or code


@dataclass(frozen=True)
class Limits:
    max_entries: int = 600_000
    max_total_bytes: int = 3 * 1024 ** 3
    max_file_bytes: int = 1024 ** 3
    max_depth: int = 64
    max_name_bytes: int = 255            # NAME_MAX
    max_path_bytes: int = 1024


@dataclass(frozen=True)
class CopyStats:
    files: int
    dirs: int                            # subdirektori yang dibuat (akar `dst` tidak dihitung)
    bytes: int
    skipped_symlink: int
    skipped_special: int
    root_ignored: int
    vanished: int


@dataclass(frozen=True)
class DiffResult:
    diff_sha256: str
    base_sha256: str
    counts: dict[str, int]               # added, modified, removed
    entries_total: int
    base_entries: int
    byte_totals: dict[str, int]          # added, modified (ukuran baru), removed (ukuran lama)
    kinds: dict[str, int]                # smali, res, manifest, aset, lib, lain
    lines: dict[str, int]                # plus, minus, files, skipped_files (perkiraan; di luar hash)
    skipped: dict[str, int]              # entri yang diabaikan di pohon KERJA: symlink, special, root_ignored, vanished
    top: list[dict[str, Any]]
    truncated: bool

    def summary(self, max_chars: int = SUMMARY_MAX_CHARS) -> dict[str, Any]:
        """Ringkasan untuk `diff_summary` store: datar (kedalaman 4), dan serialisasinya (format yang sama dengan store) <= `max_chars`.

        `top` dipotong separuh demi separuh (40 -> 20 -> 10 -> 5 -> 2 -> 1 -> 0) sampai muat; semua bidang lain bertipe/berukuran tetap."""
        top, truncated = list(self.top), self.truncated
        while True:
            out = {"v": 1, "counts": dict(self.counts), "bytes": dict(self.byte_totals), "kinds": dict(self.kinds),
                   "lines": dict(self.lines), "skipped": dict(self.skipped), "top": top, "truncated": truncated}
            if len(json.dumps(out, sort_keys=True, ensure_ascii=False)) <= max_chars:
                return out
            if not top:
                raise ValueError("ringkasan tidak muat walau tanpa 'top'")
            top, truncated = top[:len(top) // 2], True


# ------------------------------------------------------------------ pengukur batas + detak
class _Meter:
    """Satu per pohon: menghitung entri/byte terhadap `Limits`, mencatat entri yang diabaikan, dan memanggil `on_tick` secara berkala."""

    def __init__(self, limits: Limits, on_tick: Callable[[], None] | None) -> None:
        self.limits, self.on_tick = limits, on_tick
        self.entries = self.total = 0
        self.symlink = self.special = self.root_ignored = self.vanished = 0
        self._e = self._b = 0
        self._t = _clock()

    def entry(self) -> None:
        self.entries += 1
        if self.entries > self.limits.max_entries:
            raise TreeLimitError("too_many_entries", f"lebih dari {self.limits.max_entries} entri")
        self._e += 1
        self._poll()

    def data(self, n: int) -> None:
        self.total += n
        if self.total > self.limits.max_total_bytes:
            raise TreeLimitError("too_large", f"isi lebih dari {self.limits.max_total_bytes} byte")
        self._b += n
        self._poll()

    def _poll(self) -> None:
        if self.on_tick is None:
            return
        now = _clock()
        if self._e >= TICK_ENTRIES or self._b >= TICK_BYTES or now - self._t >= TICK_SECONDS:
            self._e = self._b = 0
            self._t = now
            self.on_tick()


def _display(text: str, limit: int = TOP_PATH_MAX) -> str:
    """Teks aman untuk ditampilkan/disimpan: karakter tak tercetak, pengendali arah, dan surrogate sisa (nama non-UTF-8) diganti '?'."""
    return "".join(c if c.isprintable() and c not in _BIDI else "?" for c in text)[:limit]


def _errname(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno or 0, "EIO")


def _unreadable(parts: tuple[str, ...], exc: OSError) -> TreeLimitError:
    where = _display("/".join(parts)) or "(akar)"
    return TreeLimitError("unreadable", f"tidak bisa dibaca: {where} ({_errname(exc)})")


# ------------------------------------------------------------------ pejalan aman
class _Ev(NamedTuple):
    parts: tuple[str, ...]
    key: tuple[bytes, ...]
    kind: str                            # 'f' | 'd' (direktori kosong)
    x: int
    fd: int | None                       # berkas: fd terbuka yang sudah terbukti berkas biasa; ditutup pejalan saat dilanjutkan


def _walk(root: str, meter: _Meter) -> Iterator[_Ev]:
    """Hasilkan entri pohon dalam urutan kanonik. Pemanggil WAJIB menghabiskan atau `close()` generator ini (fd terbuka di antara dua `next`)."""
    try:
        rfd = os.open(root, DIR_FLAGS)
    except OSError as exc:
        raise TreeLimitError("unreadable", f"akar pohon tidak bisa dibuka ({_errname(exc)})") from None
    try:
        yield from _walk_dir(rfd, (), (), 0, 0, meter)
    finally:
        os.close(rfd)


def _walk_dir(dfd: int, parts: tuple[str, ...], key: tuple[bytes, ...], plen: int, depth: int, meter: _Meter) -> Iterator[_Ev]:
    limits = meter.limits
    try:
        with os.scandir(dfd) as it:
            names = [e.name for e in it]
    except OSError as exc:
        raise _unreadable(parts, exc) from None
    if not names and parts:                          # kosong menurut scandir (bukan "habis difilter")
        yield _Ev(parts, key, "d", 0, None)
    for name in sorted(names, key=os.fsencode):
        meter.entry()
        if not parts and name in ROOT_IGNORE:
            meter.root_ignored += 1
            continue
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            meter.vanished += 1
            continue
        except OSError as exc:
            raise _unreadable((*parts, name), exc) from None
        if stat.S_ISLNK(st.st_mode):
            meter.symlink += 1
            continue
        if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            meter.special += 1
            continue
        nkey = os.fsencode(name)
        child_plen = len(nkey) if not parts else plen + 1 + len(nkey)
        if len(nkey) > limits.max_name_bytes:
            raise TreeLimitError("name_too_long", f"nama lebih dari {limits.max_name_bytes} byte: {_display(name, 80)}")
        if child_plen > limits.max_path_bytes:
            raise TreeLimitError("name_too_long", f"jalur lebih dari {limits.max_path_bytes} byte: {_display('/'.join((*parts, name)), 80)}")
        cparts, ckey = (*parts, name), (*key, nkey)
        if stat.S_ISDIR(st.st_mode):
            if depth + 1 > limits.max_depth:
                raise TreeLimitError("too_deep", f"kedalaman lebih dari {limits.max_depth}")
            try:
                cfd = os.open(name, DIR_FLAGS, dir_fd=dfd)
            except FileNotFoundError:
                meter.vanished += 1
                continue
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):     # diganti symlink/berkas di antara stat dan open
                    meter.vanished += 1
                    continue
                raise _unreadable(cparts, exc) from None
            try:
                yield from _walk_dir(cfd, cparts, ckey, child_plen, depth + 1, meter)
            finally:
                os.close(cfd)
            continue
        try:
            fd = os.open(name, FILE_FLAGS, dir_fd=dfd)
        except FileNotFoundError:
            meter.vanished += 1
            continue
        except OSError as exc:
            if exc.errno == errno.ELOOP:                          # diganti symlink
                meter.vanished += 1
                continue
            raise _unreadable(cparts, exc) from None
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode):                     # FIFO/perangkat yang menggantikan berkas di antara stat dan open
                meter.special += 1
                continue
            if fst.st_size > limits.max_file_bytes:
                raise TreeLimitError("file_too_large", f"berkas lebih dari {limits.max_file_bytes} byte: {_display('/'.join(cparts), 120)}")
            yield _Ev(cparts, ckey, "f", 1 if fst.st_mode & 0o111 else 0, fd)
        finally:
            os.close(fd)


def _read_chunk(fd: int, parts: tuple[str, ...]) -> bytes:
    try:
        return os.read(fd, CHUNK)
    except OSError as exc:
        raise _unreadable(parts, exc) from None


def _hash_fd(ev: _Ev, meter: _Meter) -> tuple[int, str]:
    h, size = hashlib.sha256(), 0
    while True:
        chunk = _read_chunk(ev.fd, ev.parts)             # type: ignore[arg-type]
        if not chunk:
            return size, h.hexdigest()
        size += len(chunk)
        if size > meter.limits.max_file_bytes:
            raise TreeLimitError("file_too_large", f"berkas lebih dari {meter.limits.max_file_bytes} byte: {_display('/'.join(ev.parts), 120)}")
        meter.data(len(chunk))
        h.update(chunk)


Record = tuple[str, str, int, str, int]                  # (jalur, jenis, ukuran, sha256|"", x)


def _records(root: str, meter: _Meter) -> Iterator[tuple[tuple[bytes, ...], Record]]:
    walker = _walk(root, meter)
    try:
        for ev in walker:
            path = "/".join(ev.parts)
            if ev.kind == "d":
                yield ev.key, (path, "d", 0, "", 0)
            else:
                size, sha = _hash_fd(ev, meter)
                yield ev.key, (path, "f", size, sha, ev.x)
    finally:
        walker.close()


def _dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True)


# ------------------------------------------------------------------ hash manifes satu pohon
def manifest_hash(root: str | os.PathLike[str], limits: Limits = Limits(), *, on_tick: Callable[[], None] | None = None) -> str:
    """sha256 atas rekaman manifes satu pohon (= `base_sha256` di payload diff). Alat uji dan pembanding cepat."""
    h = hashlib.sha256()
    try:
        recs = _records(os.fspath(root), _Meter(limits, on_tick))
        try:
            for _key_, rec in recs:
                h.update((_dumps(list(rec)) + "\n").encode("ascii"))
        finally:
            recs.close()
    except RecursionError:
        raise TreeLimitError("too_deep", "pohon terlalu dalam untuk diproses") from None
    return h.hexdigest()


# ------------------------------------------------------------------ diff
def compute_diff(base: str | os.PathLike[str], work: str | os.PathLike[str], limits: Limits = Limits(), *,
                 on_tick: Callable[[], None] | None = None, text_stats: bool = True,
                 collect: list[list[Any]] | None = None) -> DiffResult:
    """Diff kanonik pohon dasar -> pohon kerja. `collect` (opsional, untuk tes/alat) menampung daftar entri diff berurutan.

    Entri: A/R `[op, jalur, jenis, ukuran, sha256|"", x]` (R mendeskripsikan entri LAMA); M `[op, jalur, "f", ukuran, sha, x, ukuran_lama, sha_lama, x_lama]`."""
    try:
        return _compute_diff(os.fspath(base), os.fspath(work), limits, on_tick, text_stats, collect)
    except RecursionError:
        raise TreeLimitError("too_deep", "pohon terlalu dalam untuk diproses") from None


class _Acc:
    """Akumulator ringkasan selama penggabungan (tanpa menyimpan daftar entri)."""

    def __init__(self, base: str, work: str, text_stats: bool) -> None:
        self.base, self.work, self.text_stats = base, work, text_stats
        self.counts = {"added": 0, "modified": 0, "removed": 0}
        self.byte_totals = {"added": 0, "modified": 0, "removed": 0}
        self.kinds = dict.fromkeys(("smali", "res", "manifest", "aset", "lib", "lain"), 0)
        self.lines = {"plus": 0, "minus": 0, "files": 0, "skipped_files": 0}
        self.attempts = 0
        self.top: list[tuple[int, tuple[bytes, ...], dict[str, Any]]] = []
        self.total = 0

    def add(self, op: str, key: tuple[bytes, ...], new: Record | None, old: Record | None) -> None:
        self.total += 1
        rec = new if new is not None else old
        assert rec is not None
        path, kind, size = rec[0], rec[1], rec[2]
        name = {"A": "added", "M": "modified", "R": "removed"}[op]
        self.counts[name] += 1
        self.byte_totals[name] += size
        first = path.split("/", 1)[0]
        group = ("smali" if first.startswith("smali") else "res" if first == "res" else "manifest" if first == "AndroidManifest.xml"
                 else "aset" if first == "assets" else "lib" if first == "lib" else "lain")
        self.kinds[group] += 1
        plus = minus = None
        if kind == "f" and self.text_stats:
            counted = self._line_stats(path, new, old)
            if counted is None:
                self.lines["skipped_files"] += 1
            else:
                plus, minus = counted
                self.lines["plus"] += plus
                self.lines["minus"] += minus
                self.lines["files"] += 1
        delta = abs(size - old[2]) if op == "M" and old is not None else size
        self.top.append((delta, key, {"op": op, "kind": kind, "path": _display(path), "size": size, "plus": plus, "minus": minus}))
        if len(self.top) > 4 * TOP_MAX:
            self._trim()

    def _trim(self) -> None:
        self.top.sort(key=lambda t: (-t[0], t[1]))
        del self.top[TOP_MAX:]

    def _line_stats(self, path: str, new: Record | None, old: Record | None) -> tuple[int, int] | None:
        if self.attempts >= TEXT_FILES_MAX:
            return None
        self.attempts += 1
        new_data = _read_text(self.work, path) if new is not None else b""
        old_data = _read_text(self.base, path) if old is not None else b""
        if new_data is None or old_data is None:
            return None
        a, b = collections.Counter(_lines(new_data)), collections.Counter(_lines(old_data))
        return sum((a - b).values()), sum((b - a).values())

    def top_list(self) -> list[dict[str, Any]]:
        self._trim()
        return [item for _d, _k, item in self.top]


def _lines(data: bytes) -> list[bytes]:
    parts = data.split(b"\n")
    if parts and parts[-1] == b"":
        parts.pop()
    return parts


def _read_text(root: str, path: str) -> bytes | None:
    """Isi berkas teks kecil lewat rantai O_NOFOLLOW; None bila bukan berkas biasa, terlalu besar, tampak biner, atau galat apa pun."""
    fds: list[int] = []
    try:
        fd = os.open(root, DIR_FLAGS)
        fds.append(fd)
        *dirs, leaf = path.split("/")
        for d in dirs:
            fd = os.open(d, DIR_FLAGS, dir_fd=fd)
            fds.append(fd)
        fd = os.open(leaf, FILE_FLAGS, dir_fd=fd)
        fds.append(fd)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > TEXT_FILE_MAX_BYTES:
            return None
        data = os.read(fd, TEXT_FILE_MAX_BYTES + 1)
        while len(data) <= TEXT_FILE_MAX_BYTES:
            more = os.read(fd, TEXT_FILE_MAX_BYTES + 1 - len(data))
            if not more:
                break
            data += more
        if len(data) > TEXT_FILE_MAX_BYTES or b"\0" in data[:TEXT_SNIFF_BYTES]:
            return None
        return data
    except OSError:
        return None
    finally:
        for f in fds:
            try:
                os.close(f)
            except OSError:
                pass


def _compute_diff(base: str, work: str, limits: Limits, on_tick: Callable[[], None] | None, text_stats: bool,
                  collect: list[list[Any]] | None) -> DiffResult:
    bmeter, wmeter = _Meter(limits, on_tick), _Meter(limits, on_tick)     # batas PER POHON
    bs, ws = _records(base, bmeter), _records(work, wmeter)
    payload = hashlib.sha256()
    base_hash = hashlib.sha256()
    acc = _Acc(base, work, text_stats)
    base_entries = 0
    payload.update(b'{"v":%d,"e":[' % PAYLOAD_VERSION)

    def emit(entry: list[Any], op: str, key: tuple[bytes, ...], new: Record | None, old: Record | None) -> None:
        payload.update((b"," if acc.total else b"") + _dumps(entry).encode("ascii"))
        if collect is not None:
            collect.append(entry)
        acc.add(op, key, new, old)

    def feed_base(rec: Record) -> None:
        nonlocal base_entries
        base_hash.update((_dumps(list(rec)) + "\n").encode("ascii"))
        base_entries += 1

    try:
        b, w = next(bs, None), next(ws, None)
        while b is not None or w is not None:
            if w is None or (b is not None and b[0] < w[0]):
                assert b is not None
                feed_base(b[1])
                emit(["R", *b[1]], "R", b[0], None, b[1])
                b = next(bs, None)
            elif b is None or w[0] < b[0]:
                emit(["A", *w[1]], "A", w[0], w[1], None)
                w = next(ws, None)
            else:
                brec, wrec = b[1], w[1]
                feed_base(brec)
                if brec[1] == "f" and wrec[1] == "f":
                    if brec[2:] != wrec[2:]:
                        emit(["M", *wrec[:1], "f", *wrec[2:], *brec[2:]], "M", w[0], wrec, brec)
                elif brec[1] != wrec[1]:             # berkas <-> direktori kosong dengan nama yang sama
                    emit(["R", *brec], "R", b[0], None, brec)
                    emit(["A", *wrec], "A", w[0], wrec, None)
                b, w = next(bs, None), next(ws, None)
    finally:
        bs.close()
        ws.close()
    base_hex = base_hash.hexdigest()
    payload.update(b'],"base":"' + base_hex.encode("ascii") + b'"}')
    top = acc.top_list()
    return DiffResult(
        diff_sha256=payload.hexdigest(), base_sha256=base_hex, counts=acc.counts, entries_total=acc.total, base_entries=base_entries,
        byte_totals=acc.byte_totals, kinds=acc.kinds, lines=acc.lines,
        skipped={"symlink": wmeter.symlink, "special": wmeter.special, "root_ignored": wmeter.root_ignored, "vanished": wmeter.vanished},
        top=top, truncated=acc.total > TOP_MAX,
    )


# ------------------------------------------------------------------ salin aman
def copy_tree_safe(src: str | os.PathLike[str], dst: str | os.PathLike[str], limits: Limits = Limits(), *,
                   on_tick: Callable[[], None] | None = None) -> CopyStats:
    """Salin `src` ke `dst` (HARUS belum ada; `FileExistsError` naik ke pemanggil) lewat pejalan aman yang sama dengan hash.

    Symlink/perangkat/FIFO/soket dan `build/`/`dist/` di akar tidak disalin; direktori dibuat 0755; berkas 0644 atau 0755 menurut bit x (mode tidak
    bergantung umask atau mode asal, tanpa 000/444 yang menyulitkan penghapusan oleh uid lain); mtime tidak dipertahankan. Galat di tengah jalan
    meninggalkan `dst` setengah jadi: pemanggil WAJIB menghapusnya."""
    try:
        return _copy(os.fspath(src), os.fspath(dst), limits, on_tick)
    except RecursionError:
        raise TreeLimitError("too_deep", "pohon terlalu dalam untuk diproses") from None


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _copy(src: str, dst: str, limits: Limits, on_tick: Callable[[], None] | None) -> CopyStats:
    meter = _Meter(limits, on_tick)
    os.mkdir(dst, 0o755)
    root_fd = os.open(dst, DIR_FLAGS)
    stack: list[tuple[str, int]] = []                # komponen direktori tujuan yang terbuka, mengikuti urutan DFS pejalan
    files = dirs = nbytes = 0
    walker = _walk(src, meter)

    def ensure(parts: tuple[str, ...]) -> int:
        nonlocal dirs
        n = 0
        while n < len(stack) and n < len(parts) and stack[n][0] == parts[n]:
            n += 1
        while len(stack) > n:
            os.close(stack.pop()[1])
        for name in parts[n:]:
            parent = stack[-1][1] if stack else root_fd
            os.mkdir(name, 0o755, dir_fd=parent)
            fd = os.open(name, DIR_FLAGS, dir_fd=parent)
            stack.append((name, fd))
            os.fchmod(fd, 0o755)
            dirs += 1
        return stack[-1][1] if stack else root_fd

    try:
        os.fchmod(root_fd, 0o755)
        for ev in walker:
            if ev.kind == "d":
                ensure(ev.parts)
                continue
            parent = ensure(ev.parts[:-1])
            mode = 0o755 if ev.x else 0o644
            ofd = os.open(ev.parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
            try:
                os.fchmod(ofd, mode)
                size = 0
                while True:
                    chunk = _read_chunk(ev.fd, ev.parts)                  # type: ignore[arg-type]
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limits.max_file_bytes:
                        raise TreeLimitError("file_too_large", f"berkas lebih dari {limits.max_file_bytes} byte: {_display('/'.join(ev.parts), 120)}")
                    meter.data(len(chunk))
                    _write_all(ofd, chunk)
            finally:
                os.close(ofd)
            files += 1
            nbytes += size
    finally:
        walker.close()
        while stack:
            os.close(stack.pop()[1])
        os.close(root_fd)
    return CopyStats(files=files, dirs=dirs, bytes=nbytes, skipped_symlink=meter.symlink, skipped_special=meter.special,
                     root_ignored=meter.root_ignored, vanished=meter.vanished)
