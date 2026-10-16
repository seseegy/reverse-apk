"""Perakit paket akhir XAPK/APKS (Tahap 3, sub-area D): FORMAT ASAL dipertahankan dengan APK bertanda tangan menggantikan APK asal.

Dipanggil worker (`uploads:ro` untuk extras, `builds` rw untuk hasil tanda tangan). Aturan (design 3.6, 6):
  * nama dan URUTAN entri paket akhir = nama dan urutan entri UPLOAD (salinan memfd yang di-hash ulang); tidak pernah dari hasil runner;
  * entri base -> byte `signed.apk`; entri alias (APKS) -> byte `signed.apk` yang sama; entri split ke-k -> byte `signed-NNN.apk`; `dropped` tidak ditulis;
  * semua entri lain (ikon, OBB, toc.pb, folder, ...) disalin streaming dengan `compress_type` asal; isi, CRC, dan ukuran sama. OBB tidak ditandatangani;
  * tiap berkas bertanda tangan dibuka nofollow/nonblock (`S_ISREG`, `nlink==1`, ukuran == laporan signer) dan di-hash SAAT disalin == `output_sha256` signer,
    kalau tidak `artifact_changed`;
  * `manifest.json` disalin byte demi byte kecuali satu bilangan `total_size` yang diganti secara bedah bila SEMUA syarat design 6.2 terpenuhi;
  * paket ditulis ke berkas sementara `O_EXCL|O_NOFOLLOW` lewat `dir_fd` folder build, di-fsync, dan DIVERIFIKASI ulang (nama, CRC, ukuran, hash APK) sebelum
    pemanggil menerbitkannya. Pemanggil yang me-rename; modul ini tidak pernah menerbitkan apa pun.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from typing import Any, Callable

from .bundle import MAX_MANIFEST_BYTES, SplitSet

MIB = 1024 * 1024
_NOFOLLOW_RO = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_NEW = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
_TOTAL_RE = re.compile(rb'"total_size"\s*:\s*(\d+)(?=\s*[,}\r\n])')
_HEX64_IN_TEXT = re.compile(rb"[0-9a-fA-F]{64}")
NOTE_NOT_UPDATED = "tidak_diperbarui"


class AssembleError(Exception):
    """`code` ∈ artifact_changed | assemble_failed | bundle_changed | cancelled-diteruskan-pemanggil (pemanggil melempar sendiri dari `check`)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


@dataclass(frozen=True)
class SignedFile:
    """Berkas bertanda tangan di folder build menurut LAPORAN signer: nama dibuat sistem, hash dan ukuran harus cocok saat disalin."""
    name: str
    sha256: str
    size: int


@dataclass(frozen=True)
class Assembled:
    sha256: str
    size: int
    entries: int
    notes: tuple[str, ...]


def final_split_names(plan: SplitSet, aliases: list[int]) -> list[str]:
    """Nama entri split yang benar-benar ditandatangani (`apk_order` tanpa alias), urutan = indeks 1..n pada signer."""
    skip = set(aliases)
    return [n for i, n in enumerate(plan.apk_order) if i not in skip]


# ------------------------------------------------------------------ manifest.json (design 6.2)
def patch_manifest(raw: bytes, upload_sizes: dict[str, int], new_sizes: dict[str, int], root_apks: list[str]) -> tuple[bytes, str]:
    """(byte manifest, catatan). Penggantian `total_size` HANYA bila SEMUA syarat terpenuhi; selain itu byte asli + `tidak_diperbarui(<alasan>)`."""
    def keep(reason: str) -> tuple[bytes, str]:
        return raw, f"{NOTE_NOT_UPDATED}({reason})"

    if len(raw) > MAX_MANIFEST_BYTES:
        return keep("json_rusak")
    seen = {"n": 0}

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen["n"] += sum(1 for k, _ in pairs if k == "total_size")
        return dict(pairs)

    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=hook)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return keep("json_rusak")
    if seen["n"] == 0:
        return keep("tanpa_kunci")
    if seen["n"] > 1:
        return keep("ganda")
    if not isinstance(doc, dict) or "total_size" not in doc:
        return keep("bukan_akar")
    value = doc["total_size"]
    if type(value) is not int:
        return keep("bukan_int")
    declared = doc.get("split_apks")
    if isinstance(declared, list):
        names = {d["file"] for d in declared if isinstance(d, dict) and isinstance(d.get("file"), str)}
    else:
        names = set(root_apks)
    if not names or any(n not in upload_sizes or n not in new_sizes for n in names):
        return keep("verifikasi_gagal")
    s_old, s_new = sum(upload_sizes[n] for n in names), sum(new_sizes[n] for n in names)
    if value != s_old:
        return keep("nilai_beda")
    hits = list(_TOTAL_RE.finditer(raw))
    if len(hits) != 1:
        return keep("regex_tak_unik")
    a, b = hits[0].span(1)
    patched = raw[:a] + str(s_new).encode("ascii") + raw[b:]
    try:
        again = json.loads(patched.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return keep("verifikasi_gagal")
    want = dict(doc)
    want["total_size"] = s_new
    if again != want:
        return keep("verifikasi_gagal")
    return patched, f"diperbarui({s_old}->{s_new})"


# ------------------------------------------------------------------ berkas kecil di folder build (skrip pasang)
def write_new_file(bfd: int, name: str, data: bytes, mode: int = 0o644) -> None:
    """Tulis `data` ke `bfd/name` yang BARU (`O_EXCL|O_NOFOLLOW`), fsync. Nama yang sudah ada/ditanam (symlink) -> assemble_failed, tidak ditimpa."""
    try:
        fd = os.open(name, _NEW, mode, dir_fd=bfd)
    except OSError:
        raise AssembleError("assemble_failed", "Berkas sementara tidak dapat dibuat (sudah ada atau ditanam).") from None
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except OSError:
        raise AssembleError("assemble_failed", "Berkas sementara tidak dapat ditulis.") from None
    finally:
        os.close(fd)


def hash_file_at(bfd: int, name: str) -> tuple[str, int]:
    """(sha256, ukuran) berkas biasa `bfd/name` yang dibuka nofollow/nonblock dengan `nlink==1`; hash dari fd yang sama. Selain itu artifact_changed."""
    try:
        fd = os.open(name, _NOFOLLOW_RO, dir_fd=bfd)
    except OSError:
        raise AssembleError("artifact_changed", "Berkas hasil hilang atau tidak aman.") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise AssembleError("artifact_changed", "Berkas hasil bukan berkas biasa dengan satu tautan.")
        return _hash_stream(fd, lambda: None)
    except OSError:
        raise AssembleError("artifact_changed", "Berkas hasil tidak dapat dibaca.") from None
    finally:
        os.close(fd)


# ------------------------------------------------------------------ perakitan
def _open_signed(bfd: int, item: SignedFile) -> int:
    try:
        fd = os.open(item.name, _NOFOLLOW_RO, dir_fd=bfd)
    except OSError:
        raise AssembleError("artifact_changed", "Berkas bertanda tangan hilang atau tidak aman (symlink/FIFO).") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size != item.size:
            raise AssembleError("artifact_changed", "Berkas bertanda tangan berubah (bukan berkas biasa, tautan ganda, atau ukuran beda).")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _zinfo(src: zipfile.ZipInfo) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(src.filename, src.date_time)
    zi.compress_type = src.compress_type if src.compress_type in _METHODS else zipfile.ZIP_DEFLATED
    zi.external_attr = (0o040755 << 16) | 0x10 if src.is_dir() else 0o100644 << 16
    return zi


def _write_signed(zout: zipfile.ZipFile, src: zipfile.ZipInfo, bfd: int, item: SignedFile, check: Callable[[], None]) -> None:
    fd = _open_signed(bfd, item)
    try:
        h, n = hashlib.sha256(), 0
        with zout.open(_zinfo(src), "w", force_zip64=item.size >= (1 << 31)) as wr:
            while True:
                chunk = os.read(fd, MIB)
                if not chunk:
                    break
                h.update(chunk)
                n += len(chunk)
                wr.write(chunk)
                check()
        if n != item.size or h.hexdigest() != item.sha256:
            raise AssembleError("artifact_changed", "Isi berkas bertanda tangan tidak sama dengan yang dilaporkan signer.")
    finally:
        os.close(fd)


def _copy_member(zout: zipfile.ZipFile, zin: zipfile.ZipFile, src: zipfile.ZipInfo, check: Callable[[], None]) -> None:
    zi = _zinfo(src)
    if src.is_dir():
        zi.compress_type = zipfile.ZIP_STORED
        zout.writestr(zi, b"")
        return
    n = 0
    with zin.open(src) as rd, zout.open(zi, "w", force_zip64=src.file_size >= (1 << 31)) as wr:
        while True:
            chunk = rd.read(MIB)
            if not chunk:
                break
            n += len(chunk)
            if n > src.file_size:
                raise AssembleError("assemble_failed", "Isi entri melebihi ukuran terdeklarasi di paket asal.")
            wr.write(chunk)
            check()
    if n != src.file_size:
        raise AssembleError("assemble_failed", "Isi entri lebih pendek dari ukuran terdeklarasi di paket asal.")


def _hash_stream(fd: int, check: Callable[[], None]) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, MIB)
        if not chunk:
            return h.hexdigest(), n
        h.update(chunk)
        n += len(chunk)
        check()


def assemble(bfd: int, tmp_name: str, upload: zipfile.ZipFile, plan: SplitSet, aliases: list[int], base: SignedFile, splits: list[SignedFile],
             check: Callable[[], None]) -> Assembled:
    """Rakit paket ke `bfd/tmp_name` (dibuat O_EXCL|O_NOFOLLOW, mode 0644) dan verifikasi. Gagal -> berkas sementara DIHAPUS lalu AssembleError.
    `check()` dipanggil per potongan 1 MiB (pembatalan/tenggat: pemanggil melempar pengecualiannya sendiri; berkas sementara tetap dibersihkan)."""
    final = final_split_names(plan, aliases)
    if len(final) != len(splits):
        raise AssembleError("bundle_changed", "Jumlah split tidak sama dengan rencana paket.")
    target: dict[str, SignedFile] = {plan.base: base}
    for pos in aliases:
        target[plan.apk_order[pos]] = base
    target.update(zip(final, splits))
    infos = upload.infolist()
    dropped = set(plan.dropped)
    keep = [i for i in infos if i.filename not in dropped]
    new_sizes = {n: s.size for n, s in target.items()}
    up_sizes = {i.filename: i.file_size for i in infos}
    root_apks = [i.filename for i in infos if "/" not in i.filename and i.filename.lower().endswith(".apk")]
    notes: list[str] = []
    try:
        fd = os.open(tmp_name, _NEW, 0o644, dir_fd=bfd)
    except FileExistsError:
        raise AssembleError("assemble_failed", "Berkas sementara paket sudah ada (ditanam?); gagal-tertutup.") from None
    except OSError:
        raise AssembleError("assemble_failed", "Berkas sementara paket tidak dapat dibuat.") from None
    done = False
    patched_manifest: bytes | None = None
    try:
        with os.fdopen(fd, "w+b") as out:
            with zipfile.ZipFile(out, "w") as zout:
                for info in keep:
                    name = info.filename
                    if name in target:
                        _write_signed(zout, info, bfd, target[name], check)
                    elif name == "manifest.json" and plan.format == "xapk":
                        with upload.open(info) as rd:
                            raw = rd.read(MAX_MANIFEST_BYTES + 1)
                        data, note = patch_manifest(raw, up_sizes, new_sizes, root_apks)
                        patched_manifest = data
                        notes.append(f"manifest_total_size={note}")
                        if _HEX64_IN_TEXT.search(raw):
                            notes.append("manifest_memuat_hash_tak_diperbarui")
                        zi = _zinfo(info)
                        zout.writestr(zi, data)
                    else:
                        _copy_member(zout, upload, info, check)
            out.flush()
            os.fsync(out.fileno())
            sha, size = _hash_stream(out.fileno(), check)
            _verify(out, keep, upload, target, patched_manifest, check)
        done = True
        return Assembled(sha, size, len(keep), tuple(notes))
    except AssembleError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, EOFError, RuntimeError, OSError, ValueError) as exc:
        raise AssembleError("assemble_failed", f"Perakitan paket gagal ({type(exc).__name__}).") from None
    finally:
        if not done:
            try:
                os.unlink(tmp_name, dir_fd=bfd)
            except OSError:
                pass


def _verify(out: Any, keep: list[zipfile.ZipInfo], upload: zipfile.ZipFile, target: dict[str, SignedFile], patched: bytes | None, check: Callable[[], None]) -> None:
    """Buka ulang paket sementara: himpunan+urutan nama == rencana; extras CRC+ukuran sama dengan sumber; tiap APK bertanda tangan ber-hash laporan signer."""
    out.flush()
    with zipfile.ZipFile(os.fdopen(os.dup(out.fileno()), "rb")) as zin:
        got = zin.infolist()
        if [i.filename for i in got] != [i.filename for i in keep]:
            raise AssembleError("assemble_failed", "Daftar entri paket hasil tidak sama dengan rencana.")
        src = {i.filename: i for i in keep}
        for info in got:
            want = src[info.filename]
            if info.filename in target:
                h = hashlib.sha256()
                with zin.open(info) as rd:
                    while True:
                        chunk = rd.read(MIB)
                        if not chunk:
                            break
                        h.update(chunk)
                        check()
                if h.hexdigest() != target[info.filename].sha256 or info.file_size != target[info.filename].size:
                    raise AssembleError("artifact_changed", "APK bertanda tangan di paket hasil tidak sama dengan laporan signer.")
            elif info.filename == "manifest.json" and patched is not None:
                if zin.read(info) != patched:
                    raise AssembleError("assemble_failed", "manifest.json di paket hasil tidak sama dengan yang ditulis.")
            elif info.CRC != want.CRC or info.file_size != want.file_size:
                raise AssembleError("assemble_failed", "Entri extras di paket hasil berbeda dari sumbernya (CRC/ukuran).")


__all__ = ["AssembleError", "SignedFile", "Assembled", "assemble", "patch_manifest", "final_split_names", "write_new_file", "hash_file_at"]
