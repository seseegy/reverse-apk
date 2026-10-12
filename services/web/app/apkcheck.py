"""Validasi berkas APK yang diunggah (FR-1.5, FR-1.6).

Hanya membaca *central directory* ZIP (tidak ada dekompresi), jadi cepat dan tidak bisa dipicu
menghabiskan disk/memori oleh zip bomb. Pemeriksaan ukuran memakai nilai yang dideklarasikan;
penjaga keras terhadap header yang berbohong ada di runner (batas keluaran, waktu, memori).

Paket multi-APK (XAPK/APKS, PRD 09): dikenali dari ISI (tidak ada AndroidManifest.xml di akar tetapi ada entri .apk), bukan dari ekstensi.
Satu-satunya yang didekompresi di sini adalah 4 byte pertama APK base (untuk memastikan itu ZIP); ekstraksi sebenarnya hanya di runner.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

from rvcore import fmt
from rvcore.bundle import ZIP_MAGIC, BundleError, BundlePlan, plan_bundle

_DEX_RE = re.compile(r"^classes\d*\.dex$")
_BOMB_ENTRY_MIN = 8 * 1024 * 1024  # rasio per-entri hanya dinilai untuk entri >= 8 MiB


class ApkRejected(Exception):
    """Berkas ditolak. `message` aman ditampilkan ke pengguna; `code` untuk log/UI."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Limits:
    max_entries: int
    max_total_uncompressed: int
    max_entry_uncompressed: int
    max_ratio: int


@dataclass(frozen=True)
class ApkInfo:
    entries: int
    total_uncompressed: int
    dex_files: int
    bundle: BundlePlan | None = None       # terisi bila berkas adalah paket multi-APK (XAPK/APKS); dex_files = 0 pada paket


_fmt = fmt.size


def _check_bundle(zf: zipfile.ZipFile) -> BundlePlan:
    """Pilih base dan pastikan itu memang ZIP. Galat dari `plan_bundle` memakai kode yang sama dengan penolakan lain (UI/audit)."""
    try:
        plan = plan_bundle(zf)
        with zf.open(plan.base) as fh:
            head = fh.read(4)
    except BundleError as exc:
        raise ApkRejected(exc.code, exc.message) from exc
    except (RuntimeError, zipfile.BadZipFile, NotImplementedError, EOFError, OSError) as exc:
        raise ApkRejected("bad_bundle", f"APK base di dalam paket tidak dapat dibaca ({type(exc).__name__}).") from exc
    if head != ZIP_MAGIC:
        raise ApkRejected("bad_bundle", "APK base di dalam paket bukan arsip APK yang valid.")
    return plan


def validate_apk(path: Path, limits: Limits) -> ApkInfo:
    try:
        archive_size = path.stat().st_size
        with path.open("rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        raise ApkRejected("io", f"Berkas tidak bisa dibaca ({type(exc).__name__}).") from exc

    if archive_size == 0:
        raise ApkRejected("empty", "Berkas kosong.")
    if magic == b"PK\x05\x06":
        raise ApkRejected("not_zip", "Arsip ZIP kosong; bukan APK.")
    if magic != b"PK\x03\x04":
        raise ApkRejected("not_zip", "Bukan APK: berkas bukan arsip ZIP (magic bytes tidak cocok).")

    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, EOFError, OSError) as exc:
        raise ApkRejected("bad_zip", "Arsip ZIP rusak atau tidak dapat dibaca.") from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > limits.max_entries:
            raise ApkRejected(
                "too_many_entries",
                f"Terlalu banyak entri di dalam arsip ({fmt.num(len(infos))} > {fmt.num(limits.max_entries)}).",
            )

        seen: set[str] = set()
        total = 0
        dex_files = 0
        has_manifest = False

        for info in infos:
            name = info.filename
            if "\x00" in name:
                raise ApkRejected("bad_path", "Arsip berisi nama entri tidak valid.")
            normalized = name.replace("\\", "/")
            if normalized.startswith("/") or any(part == ".." for part in normalized.split("/")):
                raise ApkRejected("path_traversal", "Arsip berisi path berbahaya (path traversal), ditolak.")
            if name in seen:
                # Entri ganda dipakai untuk membuat parser berbeda membaca isi berbeda.
                raise ApkRejected("duplicate_entry", "Arsip berisi entri dengan nama ganda, ditolak.")
            seen.add(name)

            size, csize = info.file_size, info.compress_size
            if size > limits.max_entry_uncompressed:
                raise ApkRejected(
                    "entry_too_large",
                    f"Satu entri terlalu besar setelah diekstrak ({_fmt(size)} > {_fmt(limits.max_entry_uncompressed)}).",
                )
            if size >= _BOMB_ENTRY_MIN and size / max(csize, 1) > limits.max_ratio:
                raise ApkRejected(
                    "zip_bomb",
                    f"Terdeteksi zip bomb: rasio kompresi satu entri melebihi {limits.max_ratio}:1.",
                )
            total += size
            if total > limits.max_total_uncompressed:
                raise ApkRejected(
                    "total_too_large",
                    f"Ukuran total setelah diekstrak melebihi batas {_fmt(limits.max_total_uncompressed)}.",
                )

            if normalized == "AndroidManifest.xml":
                has_manifest = True
            elif _DEX_RE.match(normalized):
                dex_files += 1

        if archive_size and total / archive_size > limits.max_ratio:
            raise ApkRejected(
                "zip_bomb",
                f"Terdeteksi zip bomb: rasio kompresi total {fmt.num(total / archive_size)}:1 "
                f"(batas {limits.max_ratio}:1).",
            )

        if not has_manifest:
            return ApkInfo(entries=len(infos), total_uncompressed=total, dex_files=0, bundle=_check_bundle(zf))
        if dex_files == 0:
            raise ApkRejected("no_dex", "Bukan APK yang dapat dianalisis: tidak ada berkas classes*.dex.")

    return ApkInfo(entries=len(infos), total_uncompressed=total, dex_files=dex_files)
