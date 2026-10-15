"""Pembongkaran aman APK bersarang di paket XAPK/APKS (Tahap 3, sub-area A).

Dipakai runner (ekstrak split dari salinan memfd upload, buang tanda tangan lama lewat re-zip, tentukan alias) dan signer (predikat tanda tangan
yang SAMA, agar tidak ada dua definisi "sisa tanda tangan"). Prinsip:
  * Nama entri TIDAK PERNAH menjadi path: keluaran bernama oleh sistem lewat `dir_fd` (`.split-NNN.raw`, `split-NNN.apk`).
  * Berkas keluaran dibuat `O_EXCL|O_NOFOLLOW` sebagai `<nama>.part`, hash + ukuran dihitung dari fd yang SAMA, lalu `rename` atomik.
    Nama `.part` yang sudah ditanam (mis. symlink) -> `FileExistsError` (gagal-tertutup, tidak ditimpa/diikuti). `OSError` lain dilempar apa
    adanya ke pemanggil (runner memetakannya lewat `_errno`).
  * Anggaran dekompresi (`ZipBudget`) satu per build: jumlah entri, ukuran per entri, rasio (entri >= 8 MiB), dan total byte ter-dekompres
    semua split. Ukuran terdeklarasi dicek sebelum membaca; byte nyata dicek saat membaca (header yang berbohong diputus zipfile + CRC).
  * Re-zip memakai `ZipInfo` BARU per entri (memakai ulang objek sumber merusak `header_offset`): nama, `date_time`, `compress_type` asli
    (hanya STORED/DEFLATED), urutan asli; `external_attr` TIDAK diteruskan (berkas 0o100644, folder 0o040755). Blok tanda tangan v2/v3 hilang
    dengan sendirinya (tidak disalin); berkas v1 dibuang oleh `is_signature_entry`.
Kode galat (`BundleError.code`): `split_invalid` (cacat struktur: terenkripsi, kompresi tak umum, nama ganda, CRC/ZIP rusak, bukan ZIP),
`bundle_too_large` (melampaui batas/anggaran), `bundle_invalid` (anggota tidak ada atau ganda).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import zipfile
import zlib
from pathlib import Path
from typing import Callable, Iterable

from rvcore.bundle import (BOMB_ENTRY_MIN, MIB, ZIP_MAGIC, ZIP_MAX_ENTRIES, ZIP_MAX_ENTRY_BYTES, ZIP_MAX_RATIO, ZIP_MAX_TOTAL_BYTES, BundleError,
                           _clean)

_SIG_EXTS = (".sf", ".rsa", ".dsa", ".ec")
_READ_ERRORS = (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, EOFError, RuntimeError, zlib.error)
_FLAGS_NEW = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class ZipBudget:
    """Anggaran satu build: dibagi SEMUA split (satu instance diteruskan ke tiap pemanggilan). Bawaan = ZIP_MAX_* (sama dengan web)."""

    def __init__(self, total: int | None = None, max_entries: int | None = None, max_entry: int | None = None, max_ratio: int | None = None) -> None:
        self.remaining = ZIP_MAX_TOTAL_BYTES if total is None else total
        self.max_entries = ZIP_MAX_ENTRIES if max_entries is None else max_entries
        self.max_entry = ZIP_MAX_ENTRY_BYTES if max_entry is None else max_entry
        self.max_ratio = ZIP_MAX_RATIO if max_ratio is None else max_ratio

    def charge(self, n: int) -> None:
        self.remaining -= n
        if self.remaining < 0:
            raise BundleError("bundle_too_large", "Total ukuran setelah diekstrak melebihi batas build.")


def is_signature_entry(name: str) -> bool:
    """Sisa tanda tangan lama? Satu sumber kebenaran (runner dan signer). Dibandingkan `casefold`, hanya entri LANGSUNG di `META-INF/`:
    `MANIFEST.MF`, `*.SF`, `*.RSA`, `*.DSA`, `*.EC`, `SIG-*`. Tidak menyentuh `services/`, `*.version`, `*.kotlin_module`, subfolder, atau di luar META-INF/."""
    low = name.casefold()
    if not low.startswith("meta-inf/"):
        return False
    rest = low[len("meta-inf/"):]
    if not rest or "/" in rest:
        return False
    return rest == "manifest.mf" or rest.startswith("sig-") or rest.endswith(_SIG_EXTS)


def unexpected_signature_entries(names: "Iterable[str]") -> list[str]:
    """Berkas tanda tangan yang MELANGGAR himpunan boleh keluaran apksigner (satu sumber kebenaran signer-daemon dan `signer-selftest --check-bundle`).

    Boleh: `META-INF/MANIFEST.MF` (satu), paling banyak satu `<N>.SF`, paling banyak satu blok `<N>.RSA|DSA|EC`, semuanya dengan SATU `<N>` yang sama.
    `SIG-*`, dua nama dasar, atau dua blok = pelanggaran. Bila himpunan tidak boleh, SELURUH berkas tanda tangan dikembalikan (urutan asli); himpunan
    sah -> `[]`. Entri non-tanda-tangan tidak pernah dilaporkan."""
    sigs = [n for n in names if is_signature_entry(n)]
    stems: set[str] = set()
    kinds: dict[str, int] = {"mf": 0, "sf": 0, "block": 0}
    for name in sigs:
        rest = name.casefold()[len("meta-inf/"):]
        if rest == "manifest.mf":
            kinds["mf"] += 1
        elif rest.startswith("sig-"):
            return sigs
        else:
            stem, _, ext = rest.rpartition(".")
            stems.add(stem)
            kinds["sf" if ext == "sf" else "block"] += 1
    if len(stems) > 1 or any(count > 1 for count in kinds.values()):
        return sigs
    return []


class ZipTooBig(zipfile.BadZipFile):
    """Pindaian dihentikan SEBELUM central directory dibaca karena melampaui batas jumlah/ukuran (bukan salah-baca)."""


_EOCD_TAIL = 65557                      # 22 byte rekaman akhir + komentar <= 65535


def checked_entry_names(fd: int, max_entries: int) -> list[str]:
    """Nama entri dari central directory sebuah berkas ZIP biasa (fd, `pread`; offset fd tidak dipakai) dengan pagar DoS: rekaman akhir (EOCD) dibaca LEBIH DULU
    dan jumlah entri / ukuran central directory dibandingkan batas SEBELUM `zipfile` memuat semuanya ke memori. Zip64, EOCD tidak ada, atau angka tak masuk akal
    -> `BadZipFile` (`ZipTooBig` bila melampaui batas); gagal-tertutup, tidak pernah 'dilewati'. Nama ganda TIDAK ditolak di sini (pemanggil memutuskan)."""
    size = os.fstat(fd).st_size
    tail_len = min(size, _EOCD_TAIL)
    tail = os.pread(fd, tail_len, size - tail_len) if tail_len else b""
    at = tail.rfind(b"PK\x05\x06")
    if at < 0 or len(tail) - at < 22:
        raise zipfile.BadZipFile("rekaman akhir ZIP tidak ditemukan")
    total = int.from_bytes(tail[at + 10:at + 12], "little")
    cd_size = int.from_bytes(tail[at + 12:at + 16], "little")
    if total == 0xFFFF or cd_size == 0xFFFFFFFF:
        raise zipfile.BadZipFile("ZIP64 atau rekaman akhir tak lazim tidak diterima")
    if total > max_entries:
        raise ZipTooBig(f"jumlah entri {total} melebihi batas {max_entries}")
    if cd_size > max_entries * 512 or cd_size > size:
        raise ZipTooBig("ukuran central directory tak masuk akal")
    with zipfile.ZipFile(os.fdopen(os.dup(fd), "rb")) as zf:
        names = zf.namelist()
    if len(names) > max_entries:
        raise ZipTooBig(f"jumlah entri {len(names)} melebihi batas {max_entries}")
    return names


def list_entry_names(src: "str | os.PathLike[str] | int | zipfile.ZipFile") -> list[str]:
    """Nama entri dari central directory saja (path, fd int, atau ZipFile). `BadZipFile`/`OSError` dilempar ke pemanggil -> gagal-tertutup."""
    if isinstance(src, zipfile.ZipFile):
        return src.namelist()
    if isinstance(src, int):
        with zipfile.ZipFile(os.fdopen(os.dup(src), "rb")) as zf:
            return zf.namelist()
    with zipfile.ZipFile(Path(src)) as zf:
        return zf.namelist()


def _check_method(info: zipfile.ZipInfo) -> None:
    if info.flag_bits & 0x1:
        raise BundleError("split_invalid", f"Entri terenkripsi di dalam APK ditolak: {_clean(info.filename)!r}.")
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise BundleError("split_invalid", f"Metode kompresi tak umum di dalam APK ditolak: {_clean(info.filename)!r}.")


def _check_size(info: zipfile.ZipInfo, budget: ZipBudget) -> None:
    size = info.file_size
    if size > budget.max_entry:
        raise BundleError("bundle_too_large", "Satu entri di dalam APK terlalu besar setelah diekstrak.")
    if size >= BOMB_ENTRY_MIN and size / max(info.compress_size, 1) > budget.max_ratio:
        raise BundleError("bundle_too_large", f"Terdeteksi zip bomb di dalam APK: rasio kompresi melebihi {budget.max_ratio}:1.")


def _validate(infos: list[zipfile.ZipInfo], budget: ZipBudget) -> list[zipfile.ZipInfo]:
    """Periksa seluruh central directory SEBELUM membaca isi; kembalikan entri yang dipertahankan (bukan tanda tangan). Menagih anggaran total."""
    if len(infos) > budget.max_entries:
        raise BundleError("bundle_too_large", "APK di dalam paket berisi terlalu banyak entri.")
    seen: set[str] = set()
    for info in infos:
        key = info.filename.casefold()          # Java/zipalign bisa menganggap nama beda-huruf sama atau berbeda: tolak
        if key in seen:
            raise BundleError("split_invalid", f"APK di dalam paket berisi nama entri ganda: {_clean(info.filename)!r}.")
        seen.add(key)
    kept = [i for i in infos if not is_signature_entry(i.filename)]
    for info in kept:
        _check_method(info)
        _check_size(info, budget)
    for info in kept:
        budget.charge(info.file_size)
    return kept


def _hash_fd(fd: int, on_tick: Callable[[], None] | None) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, MIB)
        if not chunk:
            return h.hexdigest(), size
        h.update(chunk)
        size += len(chunk)
        if on_tick:
            on_tick()


def _copy_entry(src: zipfile.ZipFile, info: zipfile.ZipInfo, sink: Callable[[bytes], None], on_tick: Callable[[], None] | None) -> None:
    """Baca isi entri per 1 MiB; byte nyata tidak boleh melampaui ukuran terdeklarasi (zipfile sudah memotong + memeriksa CRC di akhir)."""
    n = 0
    with src.open(info) as rd:
        while True:
            chunk = rd.read(MIB)
            if not chunk:
                break
            n += len(chunk)
            if n > info.file_size:
                raise BundleError("split_invalid", f"Isi entri melebihi ukuran terdeklarasi: {_clean(info.filename)!r}.")
            sink(chunk)
            if on_tick:
                on_tick()
    if n != info.file_size:
        raise BundleError("split_invalid", f"Isi entri lebih pendek dari ukuran terdeklarasi: {_clean(info.filename)!r}.")


def strip_signatures(src_zip: zipfile.ZipFile, dest_dirfd: int, dest_name: str, budget: ZipBudget,
                     on_tick: Callable[[], None] | None = None, mode: int = 0o644) -> tuple[str, int]:
    """Re-zip APK bersarang `src_zip` (ZipFile atas `.split-NNN.raw`) TANPA berkas tanda tangan v1 dan blok v2/v3 ke `dest_dirfd/dest_name`
    (lewat `<dest_name>.part` O_EXCL|O_NOFOLLOW + rename atomik). Mengembalikan (sha256, ukuran) yang dihitung dari fd yang sama dengan penulisan.
    Catatan antarmuka: berbeda dari sketsa awal, TIDAK ada parameter `member`: `src_zip` sudah APK bersarangnya."""
    kept = _validate(src_zip.infolist(), budget)
    part = dest_name + ".part"
    fd = os.open(part, _FLAGS_NEW, mode, dir_fd=dest_dirfd)       # FileExistsError bila ditanam: bukan milik kita, tidak dihapus
    done = False
    try:
        with os.fdopen(fd, "w+b") as out:
            with zipfile.ZipFile(out, "w") as zout:
                for info in kept:
                    zi = zipfile.ZipInfo(info.filename, info.date_time)
                    if info.is_dir():
                        zi.compress_type = zipfile.ZIP_STORED
                        zi.external_attr = (0o040755 << 16) | 0x10
                        zout.writestr(zi, b"")
                        continue
                    zi.compress_type = info.compress_type
                    zi.external_attr = 0o100644 << 16
                    with zout.open(zi, "w", force_zip64=info.file_size >= (1 << 31)) as wr:
                        _copy_entry(src_zip, info, wr.write, on_tick)
            out.flush()
            os.fsync(out.fileno())
            sha, size = _hash_fd(out.fileno(), on_tick)
        os.rename(part, dest_name, src_dir_fd=dest_dirfd, dst_dir_fd=dest_dirfd)
        done = True
        return sha, size
    except _READ_ERRORS as exc:
        raise BundleError("split_invalid", f"APK di dalam paket rusak atau tidak didukung ({type(exc).__name__}).") from exc
    finally:
        if not done:
            with contextlib.suppress(OSError):
                os.unlink(part, dir_fd=dest_dirfd)


def content_digest(zf: zipfile.ZipFile, budget: ZipBudget | None = None, on_tick: Callable[[], None] | None = None) -> str:
    """SHA-256 atas baris `nama\\tSHA256(isi tak terkompresi)\\n` seluruh entri APK bersarang SELAIN entri tanda tangan, diurut menurut nama.
    Dasar keputusan alias: isi, bukan CRC32 (lemah, mudah ditabrak) dan bukan META-INF (master dan base-master_2 identik isi tetapi beda tanda tangan)."""
    kept = _validate(zf.infolist(), budget or ZipBudget())
    lines: list[tuple[str, str]] = []
    try:
        for info in kept:
            h = hashlib.sha256()
            if not info.is_dir():
                _copy_entry(zf, info, h.update, on_tick)
            lines.append((info.filename, h.hexdigest()))
    except _READ_ERRORS as exc:
        raise BundleError("split_invalid", f"APK di dalam paket rusak atau tidak didukung ({type(exc).__name__}).") from exc
    out = hashlib.sha256()
    for name, digest in sorted(lines):
        out.update(f"{name}\t{digest}\n".encode("utf-8", "surrogatepass"))
    return out.hexdigest()


def extract_member_at(zf: zipfile.ZipFile, member: str, dest_dirfd: int, dest_name: str, max_bytes: int,
                      on_tick: Callable[[], None] | None = None, budget: ZipBudget | None = None, mode: int = 0o600) -> tuple[str, int]:
    """Ekstrak SATU anggota (APK bersarang) dari `zf` ke `dest_dirfd/dest_name` secara streaming. Yang dibatasi adalah byte yang sungguh
    ditulis (ukuran terdeklarasi tidak dipercaya). Wajib berawalan magic ZIP. Mengembalikan (sha256, ukuran) dari fd yang sama."""
    found = [i for i in zf.infolist() if i.filename == member]
    if len(found) != 1:
        raise BundleError("bundle_invalid", "Anggota paket tidak ditemukan (atau ganda).")
    info = found[0]
    if info.is_dir():
        raise BundleError("split_invalid", "Anggota paket berupa folder.")
    _check_method(info)
    if info.file_size > max_bytes:
        raise BundleError("bundle_too_large", f"Anggota paket melebihi batas {max_bytes // MIB} MB.")
    _check_size(info, budget or ZipBudget())
    if budget is not None:
        budget.charge(info.file_size)
    part = dest_name + ".part"
    fd = os.open(part, _FLAGS_NEW, mode, dir_fd=dest_dirfd)
    done = False
    try:
        with os.fdopen(fd, "w+b") as out:
            written = 0
            head = b""
            try:
                with zf.open(info) as rd:
                    while True:
                        chunk = rd.read(MIB)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > max_bytes:
                            raise BundleError("bundle_too_large", f"Anggota paket melebihi batas {max_bytes // MIB} MB setelah diekstrak.")
                        if len(head) < 4:
                            head = (head + chunk)[:4]
                        out.write(chunk)
                        if on_tick:
                            on_tick()
            except _READ_ERRORS as exc:
                raise BundleError("split_invalid", f"Anggota paket rusak atau tidak didukung ({type(exc).__name__}).") from exc
            if head != ZIP_MAGIC:
                raise BundleError("split_invalid", "Anggota paket bukan arsip APK yang valid.")
            out.flush()
            os.fsync(out.fileno())
            sha, size = _hash_fd(out.fileno(), on_tick)
        os.rename(part, dest_name, src_dir_fd=dest_dirfd, dst_dir_fd=dest_dirfd)
        done = True
        return sha, size
    finally:
        if not done:
            with contextlib.suppress(OSError):
                os.unlink(part, dir_fd=dest_dirfd)


__all__: Iterable[str] = ("ZipBudget", "is_signature_entry", "unexpected_signature_entries", "checked_entry_names", "ZipTooBig", "list_entry_names", "strip_signatures", "content_digest", "extract_member_at")
