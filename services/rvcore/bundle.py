"""Paket multi-APK (XAPK, APKS): mengenali, memilih base APK, dan mengekstraknya dengan aman (PRD 09, PR A).

Dua pemakai dengan tanggung jawab berbeda, dan keduanya memakai fungsi pemilihan YANG SAMA supaya tidak mungkin berbeda pendapat tentang
"base yang mana":
  * web   : `plan_bundle` membaca daftar isi ZIP (dan manifest.json kecil untuk XAPK) untuk menolak berkas yang salah SEBELUM antre.
            Web TIDAK mengekstrak apa pun dari isi arsip tak tepercaya.
  * runner: `prepared_apk` mengekstrak SATU entri (base) ke work/<id>/base.apk, memberikannya ke apktool/jadx/analyzer, lalu menghapusnya.
            Karena path APK dihitung di satu tempat, `--apk` analyzer (tanda tangan, library native) otomatis memakai base ASLI,
            bukan hasil penggabungan yang tanda tangannya sudah tidak sah (terukur pada XAPK nyata: v1 'SHA1 digest error').

Yang diuji pada berkas nyata:
  * XAPK v2 (manifest.json + split_apks[id=base] + 3 split): base dipilih dari manifest.
  * APKS bundletool mode universal (universal.apk + toc.pb) dan mode default (splits/base-master.apk + base-master_2.apk + puluhan split).
    Pada sampel default kedua master identik isinya (173 entri, CRC sama); pada bundel lain itu TIDAK dijamin, jadi yang dipilih
    deterministik (nomor terkecil) dan jumlah alternatif dicatat agar UI bisa jujur.
Belum diuji pada berkas nyata: .apkm (ditolak dengan pesan jelas), .aab, XAPK dengan OBB.

Hanya base yang dianalisis. Split (resource bahasa/kerapatan, library native ABI) TIDAK ikut; itu dicatat di opsi analisis dan UI.
Semua ukuran/nama dari arsip tak tepercaya: nama hanya dibandingkan dengan nama entri yang benar-benar ada, tidak pernah dijadikan path.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

MIB = 1024 * 1024
MAX_MANIFEST_BYTES = 1 * MIB          # manifest.json XAPK yang wajar hanya beberapa KB
MAX_LISTED = 20                       # nama split yang dicatat di opsi analisis (sisanya hanya dihitung)
BASE_NAME = "base.apk"                # nama sementara di work/<id>/
ZIP_MAGIC = b"PK\x03\x04"

_MASTER_RE = re.compile(r"^(?:splits/)?base-master(?:_(\d+))?\.apk$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class BundleError(Exception):
    """`message` aman ditampilkan ke pengguna; `code` dipakai web untuk kode penolakan."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class BundlePlan:
    format: str                       # "xapk" | "apks"
    base: str                         # nama entri base di dalam arsip
    apks: tuple[str, ...]             # semua entri .apk (base + split)
    alternates: int = 0               # kandidat base lain yang TIDAK dipilih (mis. base-master_2.apk)

    def to_options(self) -> dict:
        """Catatan untuk analysis.options (JSON kecil, tanpa migrasi DB). Nama berasal dari arsip: dipotong dan dibersihkan."""
        others = [_clean(n) for n in self.apks if n != self.base]
        return {"format": self.format, "base": _clean(self.base), "apk_count": len(self.apks),
                "splits": others[:MAX_LISTED], "splits_more": max(0, len(others) - MAX_LISTED), "alternates": self.alternates}


def _clean(name: str) -> str:
    return _CONTROL_RE.sub("?", name)[:120]


# ---------------------------------------------------------------------------------------------- memilih base
def _read_json_member(zf: zipfile.ZipFile, name: str) -> object:
    info = zf.getinfo(name)
    if info.file_size > MAX_MANIFEST_BYTES:
        raise BundleError("bad_bundle", f"{name} terlalu besar untuk manifest paket.")
    try:
        with zf.open(info) as fh:
            raw = fh.read(MAX_MANIFEST_BYTES + 1)
    except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError, EOFError) as exc:
        raise BundleError("bad_bundle", f"{name} tidak dapat dibaca ({type(exc).__name__}).") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise BundleError("bad_bundle", f"{name} terlalu besar untuk manifest paket.")
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BundleError("bad_bundle", f"{name} bukan JSON yang valid.") from exc


def _plan_xapk(zf: zipfile.ZipFile, names: list[str], apks: list[str]) -> BundlePlan:
    manifest = _read_json_member(zf, "manifest.json")
    if not isinstance(manifest, dict):
        raise BundleError("bad_bundle", "manifest.json XAPK bukan objek JSON.")
    base: str | None = None
    declared = manifest.get("split_apks")
    if isinstance(declared, list):
        marked = [d.get("file") for d in declared if isinstance(d, dict) and d.get("id") == "base"]
        if len(marked) == 1 and isinstance(marked[0], str):
            base = marked[0]
        elif len(marked) > 1:
            raise BundleError("bundle_no_base", "manifest.json menandai lebih dari satu APK sebagai base; tidak bisa menentukan yang benar.")
    if base is None:
        # Cadangan untuk XAPK tanpa penanda id=base: <package_name>.apk di akar, atau satu-satunya APK di akar.
        pkg = manifest.get("package_name")
        root_apks = [n for n in apks if "/" not in n]
        if isinstance(pkg, str) and f"{pkg}.apk" in root_apks:
            base = f"{pkg}.apk"
        elif len(root_apks) == 1:
            base = root_apks[0]
    if base is None:
        raise BundleError("bundle_no_base", "XAPK ini tidak menyebut APK base dan tidak bisa ditebak dengan aman; unggah base APK saja.")
    # Nama dari manifest hanya diterima bila sama persis dengan entri yang ada: tidak pernah menjadi path.
    if base not in names or not base.lower().endswith(".apk"):
        raise BundleError("bundle_no_base", "manifest.json menunjuk APK base yang tidak ada di dalam arsip.")
    return BundlePlan(format="xapk", base=base, apks=tuple(apks))


def _plan_apks(names: list[str], apks: list[str]) -> BundlePlan:
    if "universal.apk" in names:
        return BundlePlan(format="apks", base="universal.apk", apks=tuple(apks))
    masters = sorted((n for n in names if _MASTER_RE.match(n)), key=lambda n: (int(_MASTER_RE.match(n).group(1) or 0), n))
    if masters:
        return BundlePlan(format="apks", base=masters[0], apks=tuple(apks), alternates=len(masters) - 1)
    standalones = [n for n in apks if n.startswith("standalones/")]
    if len(standalones) == 1:
        return BundlePlan(format="apks", base=standalones[0], apks=tuple(apks))
    raise BundleError("bundle_no_base", "APKS ini tidak berisi universal.apk maupun base-master.apk; tidak bisa menentukan base dengan aman.")


def plan_bundle(zf: zipfile.ZipFile) -> BundlePlan:
    """Kenali paket multi-APK dari daftar isi dan pilih base. Dipanggil hanya bila AndroidManifest.xml TIDAK ada di akar."""
    infos = zf.infolist()
    names = [i.filename for i in infos]
    apks = [n for n in names if n.lower().endswith(".apk")]
    if not apks:
        raise BundleError("no_manifest", "Bukan APK: AndroidManifest.xml tidak ditemukan di akar arsip.")
    if len(set(names)) != len(names):
        raise BundleError("duplicate_entry", "Arsip berisi entri dengan nama ganda, ditolak.")
    if "toc.pb" in names or "universal.apk" in names or any(_MASTER_RE.match(n) for n in names):
        plan = _plan_apks(names, apks)
    elif "manifest.json" in names:
        plan = _plan_xapk(zf, names, apks)
    elif "info.json" in names:
        raise BundleError("unsupported_bundle", "Ini tampak seperti paket APKM. Format itu belum didukung karena belum pernah diuji pada berkas "
                                                "asli; unggah base APK, XAPK, atau APKS.")
    else:
        raise BundleError("unsupported_bundle", "Ini paket multi-APK dengan susunan yang tidak dikenal (bukan XAPK maupun APKS). "
                                                "Unggah base APK saja.")
    info = zf.getinfo(plan.base)
    if info.is_dir() or info.flag_bits & 0x1:
        raise BundleError("bad_bundle", "APK base di dalam paket berupa folder atau terenkripsi; tidak bisa dianalisis.")
    return plan


# ---------------------------------------------------------------------------------------------- mengekstrak base
def extract_member(src: Path, member: str, dest: Path, max_bytes: int, progress: Callable[[], None] | None = None) -> int:
    """Salin SATU entri ke `dest` secara streaming. Ukuran yang dideklarasikan arsip tidak dipercaya: yang dibatasi adalah byte yang
    sungguh ditulis. CRC diperiksa zipfile di akhir pembacaan. Menulis ke `dest.part` lalu rename (tidak ada berkas setengah jadi)."""
    part = dest.with_name(dest.name + ".part")
    for stale in (part, dest):
        stale.unlink(missing_ok=True)                  # unlink pada symlink menghapus tautannya, bukan targetnya
    try:
        with zipfile.ZipFile(src) as zf:
            found = [i for i in zf.infolist() if i.filename == member]
            if len(found) != 1:
                raise BundleError("bundle_no_base", "APK base tidak ditemukan (atau ganda) di dalam paket.")
            info = found[0]
            if info.is_dir() or info.flag_bits & 0x1:
                raise BundleError("bad_bundle", "APK base berupa folder atau terenkripsi.")
            if info.file_size > max_bytes:
                raise BundleError("base_too_large", f"APK base melebihi batas {max_bytes // MIB} MB.")
            fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            written = 0
            with os.fdopen(fd, "wb") as out, zf.open(info) as fh:
                while True:
                    chunk = fh.read(MIB)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_bytes:
                        raise BundleError("base_too_large", f"APK base melebihi batas {max_bytes // MIB} MB setelah diekstrak.")
                    out.write(chunk)
                    if progress:
                        progress()
        with part.open("rb") as fh:
            if fh.read(4) != ZIP_MAGIC:
                raise BundleError("bad_bundle", "APK base di dalam paket bukan arsip APK yang valid.")
        os.replace(part, dest)
        return written
    except BundleError:
        part.unlink(missing_ok=True)
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, EOFError, RuntimeError, OSError) as exc:
        part.unlink(missing_ok=True)
        raise BundleError("bad_bundle", f"Paket tidak dapat dibaca ({type(exc).__name__}).") from exc
    except BaseException:
        part.unlink(missing_ok=True)
        raise


@contextlib.contextmanager
def prepared_apk(src: Path, work: Path, max_bytes: int, progress: Callable[[], None] | None = None) -> Iterator[Path]:
    """APK yang akan diberikan ke tool. APK biasa: `src` apa adanya. Paket: base hasil ekstraksi di work/<id>/base.apk (dihapus saat keluar,
    juga saat galat, supaya tidak menggandakan pemakaian disk). Keputusan diambil dari ISI berkas, bukan ekstensi atau opsi dari web."""
    try:
        with zipfile.ZipFile(src) as zf:
            plain = "AndroidManifest.xml" in zf.namelist()
            plan = None if plain else plan_bundle(zf)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, EOFError, OSError) as exc:
        raise BundleError("bad_zip", f"Arsip tidak dapat dibaca ({type(exc).__name__}).") from exc
    if plan is None:
        yield src
        return
    dest = work / BASE_NAME
    extract_member(src, plan.base, dest, max_bytes, progress)
    try:
        yield dest
    finally:
        dest.unlink(missing_ok=True)
        dest.with_name(dest.name + ".part").unlink(missing_ok=True)
