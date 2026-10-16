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
import hashlib
import json
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

MIB = 1024 * 1024
MAX_MANIFEST_BYTES = 1 * MIB          # manifest.json XAPK yang wajar hanya beberapa KB
MAX_LISTED = 20                       # nama split yang dicatat di opsi analisis (sisanya hanya dihitung)
BASE_NAME = "base.apk"                # nama sementara di work/<id>/
ZIP_MAGIC = b"PK\x03\x04"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


# Batas zip: bawaan dan nama env SAMA dengan services/web/app/config.py (tes menjaga kesamaan). Compose hari ini tidak meneruskan ZIP_MAX_*
# ke web, runner, maupun worker; menaikkan batas berarti mengubah compose di KETIGA layanan (docs/deploy.md).
ZIP_MAX_ENTRIES = _env_int("ZIP_MAX_ENTRIES", 100_000)
ZIP_MAX_TOTAL_BYTES = _env_int("ZIP_MAX_UNCOMPRESSED_MB", 3072) * MIB
ZIP_MAX_ENTRY_BYTES = _env_int("ZIP_MAX_ENTRY_MB", 512) * MIB
ZIP_MAX_RATIO = _env_int("ZIP_MAX_RATIO", 100)
BOMB_ENTRY_MIN = 8 * MIB              # rasio per entri hanya dinilai untuk entri >= 8 MiB (sama dengan apkcheck)
MAX_BUNDLE_APKS = 200                 # FR-9.3: base + 199 split
MAX_ALIAS_CANDIDATES = 8
MAX_NAME_BYTES = 255
UPLOAD_COPY_MAX_RUNNER_MB = 512       # batas salinan memfd upload; runner jauh dari 3 GiB karena salinan diambil sesudah apktool
UPLOAD_COPY_MAX_WORKER_MB = 256       # worker mem_limit 512m: memfd dihitung ke memori kontainer (ASUMSI, diukur di e2e)
DROPPED_DIRS = ("standalones/", "instant/", "system/")
SAI_MARKERS = ("meta.sai_v1.json", "meta.sai_v2.json")

_ALIAS_RE = re.compile(r"^splits/base-master_([0-9]+)\.apk$")
_GLOB_CHARS = frozenset("*?[]")
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


def _xapk_base(manifest: object, names: list[str], apks: list[str]) -> str:
    """Pilih base XAPK dari manifest.json yang sudah di-parse (dipakai `plan_bundle` dan `plan_split_set`: satu keputusan)."""
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
    return base


def _plan_xapk(zf: zipfile.ZipFile, names: list[str], apks: list[str]) -> BundlePlan:
    manifest = _read_json_member(zf, "manifest.json")
    return BundlePlan(format="xapk", base=_xapk_base(manifest, names, apks), apks=tuple(apks))


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
    for info in infos:
        _check_entry(info)
    if len(apks) > MAX_BUNDLE_APKS:
        raise BundleError("bundle_too_many_apks", f"Paket berisi {len(apks)} APK; batasnya {MAX_BUNDLE_APKS} (base + {MAX_BUNDLE_APKS - 1} split).")
    if "toc.pb" in names or "universal.apk" in names or any(_MASTER_RE.match(n) for n in names):
        plan = _plan_apks(names, apks)
    elif "manifest.json" in names:
        plan = _plan_xapk(zf, names, apks)
    elif "info.json" in names:
        raise BundleError("unsupported_bundle", "Ini tampak seperti paket APKM. Format itu belum didukung karena belum pernah diuji pada berkas "
                                                "asli; unggah base APK, XAPK, atau APKS.")
    elif any(n in names for n in SAI_MARKERS):
        raise BundleError("unsupported_bundle", "Ini tampak seperti paket SAI (Split APKs Installer). Format itu tidak didukung; "
                                                "unggah base APK, XAPK, atau APKS.")
    else:
        raise BundleError("unsupported_bundle", "Ini paket multi-APK dengan susunan yang tidak dikenal (bukan XAPK maupun APKS). "
                                                "Unggah base APK saja.")
    info = zf.getinfo(plan.base)
    if info.is_dir() or info.flag_bits & 0x1:
        raise BundleError("bad_bundle", "APK base di dalam paket berupa folder atau terenkripsi; tidak bisa dianalisis.")
    return plan


# ---------------------------------------------------------------------------------------------- keselamatan entri
def _check_entry(info: zipfile.ZipInfo) -> None:
    """Tolak entri yang tidak pernah boleh ada di paket: bukan berkas biasa/folder (symlink, perangkat, FIFO, soket), nama berisi kontrol atau `\\`,
    komponen kosong/`.`/`..`, nama > 255 byte UTF-8. Nama tidak pernah menjadi path di sistem ini, tetapi disalin ke paket akhir yang diekstrak
    alat lain di perangkat pemilik. Mode Unix 0 (zip buatan Windows/Java) diterima sebagai berkas biasa."""
    name = info.filename
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise BundleError("bundle_unsafe_entry", f"Paket berisi entri yang bukan berkas biasa (symlink/perangkat/FIFO): {_clean(name)!r}.")
    if _CONTROL_RE.search(name) or "\\" in name:
        raise BundleError("bundle_unsafe_entry", f"Paket berisi nama entri dengan karakter kontrol atau garis miring terbalik: {_clean(name)!r}.")
    if len(name.encode("utf-8", "surrogatepass")) > MAX_NAME_BYTES:
        raise BundleError("bundle_unsafe_entry", "Paket berisi nama entri yang terlalu panjang (> 255 byte).")
    parts = name[:-1].split("/") if name.endswith("/") else name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise BundleError("bundle_unsafe_entry", f"Paket berisi nama entri dengan komponen kosong atau titik: {_clean(name)!r}.")


# ---------------------------------------------------------------------------------------------- rencana set split
@dataclass(frozen=True)
class SplitSet:
    """Hasil `plan_split_set`. Posisi APK = indeks dalam `apk_order` (mulai 0). Murni dari central directory luar."""
    format: str                           # "xapk" | "apks"
    base: str                             # nama entri base
    apk_order: tuple[str, ...]            # semua *.apk kecuali base dan `dropped`, urut central directory
    alias_candidates: tuple[str, ...]     # APKS: splits/base-master_<n>.apk (n>=2), <= MAX_ALIAS_CANDIDATES; tetap ada di apk_order
    dropped: tuple[str, ...]              # APKS: *.apk di standalones/|instant/|system/ selain base (tidak ditandatangani, tidak ada di hasil)
    extras: tuple[str, ...]               # semua entri bukan-.apk (ikon, manifest.json, toc.pb, .obb, folder)
    plan_sha256: str                      # SHA-256 atas baris "nama\tCRC\tukuran\n" seluruh entri; mendeteksi beda aturan antar kontainer
    warnings: tuple[str, ...] = ()        # kode peringatan (mis. alias_terlalu_banyak)


def plan_split_set(infos: list[zipfile.ZipInfo], manifest_bytes: bytes | None) -> SplitSet:
    """Rencana set split dari central directory paket LUAR dan manifest.json kecil (<= 1 MiB). Murni: tidak membuka APK bersarang.

    Dipakai runner dan worker atas salinan memfd yang sama (`plan_sha256` harus sama). Lebih ketat dari `plan_bundle` (jalur build, bukan analisis):
    nama .apk/.obb berglob, duplikat huruf-sama (`casefold`) -> `bundle_unsafe_entry`; XAPK yang menyebut split yang tidak ada -> `split_missing`.
    """
    names = [i.filename for i in infos]
    if len(set(names)) != len(names):
        raise BundleError("duplicate_entry", "Arsip berisi entri dengan nama ganda, ditolak.")
    folded = {n.casefold() for n in names}
    if len(folded) != len(names):
        raise BundleError("bundle_unsafe_entry", "Paket berisi nama entri yang hanya berbeda huruf besar/kecil; ditolak.")
    if len(infos) > ZIP_MAX_ENTRIES:
        raise BundleError("bundle_too_large", "Paket berisi terlalu banyak entri.")
    for info in infos:
        _check_entry(info)
        low = info.filename.lower()
        if (low.endswith(".apk") or low.endswith(".obb")) and _GLOB_CHARS & set(info.filename):
            raise BundleError("bundle_unsafe_entry", f"Nama entri .apk/.obb berisi karakter glob (* ? [ ]): {_clean(info.filename)!r}.")
    apks = [n for n in names if n.lower().endswith(".apk")]
    if not apks:
        raise BundleError("bundle_invalid", "Bukan paket multi-APK: tidak ada entri .apk.")
    if len(apks) > MAX_BUNDLE_APKS:
        raise BundleError("bundle_too_many_apks", f"Paket berisi {len(apks)} APK; batasnya {MAX_BUNDLE_APKS} (base + {MAX_BUNDLE_APKS - 1} split).")
    if "AndroidManifest.xml" in names:
        raise BundleError("bundle_invalid", "Berkas ini APK biasa, bukan paket multi-APK.")
    warnings: list[str] = []
    dropped: tuple[str, ...] = ()
    candidates: tuple[str, ...] = ()
    if "toc.pb" in names or "universal.apk" in names or any(_MASTER_RE.match(n) for n in names):
        fmt = "apks"
        base = _plan_apks(names, apks).base
        dropped = tuple(n for n in apks if n != base and n.casefold().startswith(DROPPED_DIRS))
        if base == "splits/base-master.apk":
            found = [n for n in names if (m := _ALIAS_RE.match(n)) and int(m.group(1)) >= 2]
            if len(found) > MAX_ALIAS_CANDIDATES:
                warnings.append("alias_terlalu_banyak")
            candidates = tuple(found[:MAX_ALIAS_CANDIDATES])
    elif "manifest.json" in names:
        fmt = "xapk"
        if manifest_bytes is None:
            raise BundleError("bundle_invalid", "manifest.json XAPK tidak diberikan ke perencana.")
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise BundleError("bad_bundle", "manifest.json terlalu besar untuk manifest paket.")
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8-sig"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise BundleError("bad_bundle", "manifest.json bukan JSON yang valid.") from exc
        base = _xapk_base(manifest, names, apks)
        declared = manifest.get("split_apks") if isinstance(manifest, dict) else None
        if isinstance(declared, list):
            nameset = set(names)
            for d in declared:
                f = d.get("file") if isinstance(d, dict) else None
                if isinstance(f, str) and f not in nameset:
                    raise BundleError("split_missing", f"manifest.json menyebut split yang tidak ada di paket: {_clean(f)!r}.")
    elif "info.json" in names:
        raise BundleError("unsupported_bundle", "Ini tampak seperti paket APKM; belum didukung.")
    else:
        raise BundleError("unsupported_bundle", "Susunan paket multi-APK tidak dikenal (bukan XAPK maupun APKS).")
    skip = set(dropped) | {base}
    order = tuple(n for n in apks if n not in skip)
    extras = tuple(n for n in names if not n.lower().endswith(".apk"))
    digest = hashlib.sha256()
    for i in infos:
        digest.update(f"{i.filename}\t{i.CRC}\t{i.file_size}\n".encode("utf-8", "surrogatepass"))
    return SplitSet(fmt, base, order, candidates, dropped, extras, digest.hexdigest(), tuple(warnings))


def plan_from_zip(zf: zipfile.ZipFile) -> SplitSet:
    """`plan_split_set` atas sebuah ZipFile (runner: lintasan 1 dan memfd; worker: memfd), membaca `manifest.json` <= 1 MiB bila ada.
    Satu fungsi untuk semua pemanggil supaya `plan_sha256` sama bila isinya sama."""
    infos = zf.infolist()
    first = next((i for i in infos if i.filename == "manifest.json"), None)
    raw: bytes | None = None
    if first is not None:
        try:
            with zf.open(first) as fh:
                raw = fh.read(MAX_MANIFEST_BYTES + 1)
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError, EOFError) as exc:
            raise BundleError("bad_bundle", f"manifest.json tidak dapat dibaca ({type(exc).__name__}).") from exc
    return plan_split_set(infos, raw)


# ---------------------------------------------------------------------------------------------- upload TOCTOU-aman
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class UploadCopy:
    """Salinan memfd upload yang sudah diverifikasi. `.zip` = SATU ZipFile untuk semua pembacaan (daftar entri, ekstraksi split, extras).
    Memfd anonim: tidak ada di filesystem mana pun, sehingga tak dapat ditulis web/runner lain; penulisan-di-tempat pada upload asli tak berpengaruh."""

    def __init__(self, memfd: int, size: int, sha256: str) -> None:
        self.size = size
        self.sha256 = sha256
        self._memfd = memfd
        self.zip: zipfile.ZipFile | None = None
        try:
            self.zip = zipfile.ZipFile(os.fdopen(os.dup(memfd), "rb"))
        except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, EOFError, OSError) as exc:
            self.close()
            raise BundleError("bundle_invalid", f"Upload bukan arsip ZIP yang valid ({type(exc).__name__}).") from exc

    def close(self) -> None:
        if self.zip is not None:
            with contextlib.suppress(Exception):
                self.zip.close()
            self.zip = None
        if self._memfd >= 0:
            with contextlib.suppress(OSError):
                os.close(self._memfd)
            self._memfd = -1

    def __enter__(self) -> "UploadCopy":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class UploadHandle:
    """Upload yang sudah DIBUKA SEKALI (nofollow/nonblock, S_ISREG, nlink==1, ukuran <= cap) dan lolos lintasan 1 (hash dari fd == sha).
    `zipfile()` membaca central directory dari fd itu (gagal-cepat, hanya baca). `copy()` = lintasan 2: salin ke memfd sambil hash ulang."""

    def __init__(self, fd: int, size: int, sha: str, cap: int, on_tick: Callable[[], None] | None) -> None:
        self._fd, self.size, self.sha256, self._cap, self._tick = fd, size, sha, cap, on_tick

    def _chunks(self) -> Iterator[bytes]:
        os.lseek(self._fd, 0, os.SEEK_SET)
        total = 0
        while True:
            chunk = os.read(self._fd, MIB)
            if not chunk:
                return
            total += len(chunk)
            if total > self._cap:
                raise BundleError("bundle_too_large", f"Upload melebihi batas salinan {self._cap // MIB} MB.")
            if self._tick:
                self._tick()
            yield chunk

    def zipfile(self) -> zipfile.ZipFile:
        """ZipFile atas duplikat fd lintasan 1 (hanya untuk membaca central directory). Pemanggil menutupnya."""
        try:
            return zipfile.ZipFile(os.fdopen(os.dup(self._fd), "rb"))
        except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, EOFError, OSError) as exc:
            raise BundleError("bundle_invalid", f"Upload bukan arsip ZIP yang valid ({type(exc).__name__}).") from exc

    def copy(self) -> UploadCopy:
        if not hasattr(os, "memfd_create"):
            raise BundleError("memfd_unavailable", "memfd_create tidak tersedia; tanpa cadangan ke berkas biasa (gagal-tertutup).")
        try:
            mfd = os.memfd_create("upload", getattr(os, "MFD_CLOEXEC", 0))
        except OSError as exc:
            raise BundleError("memfd_unavailable", f"memfd_create gagal ({type(exc).__name__}); tanpa cadangan ke berkas biasa.") from exc
        try:
            h = hashlib.sha256()
            size = 0
            for chunk in self._chunks():
                h.update(chunk)
                size += len(chunk)
                view = memoryview(chunk)
                while view:
                    view = view[os.write(mfd, view):]
            if h.hexdigest() != self.sha256:
                raise BundleError("bundle_changed", "Isi upload berubah sejak diverifikasi.")
            os.lseek(mfd, 0, os.SEEK_SET)
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(mfd)
            raise
        return UploadCopy(mfd, size, self.sha256)        # dari sini UploadCopy pemilik memfd (menutupnya sendiri bila ZIP tak valid)

    def close(self) -> None:
        if self._fd >= 0:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> "UploadHandle":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def begin_upload(uploads_dirfd: int, sha: str, cap_bytes: int, on_tick: Callable[[], None] | None = None) -> UploadHandle:
    """Buka `<sha>.apk` SEKALI lewat `dir_fd` (O_NOFOLLOW|O_NONBLOCK), pastikan berkas reguler, nlink==1, 0 < ukuran <= cap, lalu LINTASAN 1:
    hash seluruh isi dari fd itu harus == `sha` (gagal-cepat, tidak menulis apa pun). Galat: `bundle_changed` (hilang/hash beda),
    `bundle_invalid` (sha tak valid, bukan reguler/symlink/FIFO, nlink>1, kosong), `bundle_too_large`."""
    if not isinstance(sha, str) or not _SHA_RE.match(sha):
        raise BundleError("bundle_invalid", "Hash upload tidak valid.")
    try:
        fd = os.open(f"{sha}.apk", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=uploads_dirfd)
    except FileNotFoundError as exc:
        raise BundleError("bundle_changed", "Upload tidak ada lagi di penyimpanan.") from exc
    except OSError as exc:
        raise BundleError("bundle_invalid", f"Upload tidak dapat dibuka dengan aman ({type(exc).__name__}).") from exc
    handle = UploadHandle(fd, 0, sha, cap_bytes, on_tick)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise BundleError("bundle_invalid", "Upload bukan berkas biasa dengan satu tautan.")
        if st.st_size <= 0:
            raise BundleError("bundle_invalid", "Upload kosong.")
        if st.st_size > cap_bytes:
            raise BundleError("bundle_too_large", f"Upload melebihi batas salinan {cap_bytes // MIB} MB.")
        h = hashlib.sha256()
        size = 0
        for chunk in handle._chunks():
            h.update(chunk)
            size += len(chunk)
        if h.hexdigest() != sha:
            raise BundleError("bundle_changed", "Isi upload tidak sama dengan hash yang diminta.")
        handle.size = size
        return handle
    except BaseException:
        handle.close()
        raise


def open_upload(uploads_dirfd: int, sha: str, cap_bytes: int, on_tick: Callable[[], None] | None = None) -> UploadCopy:
    """Lintasan 1 + lintasan 2 berurutan dari satu pembukaan; mengembalikan salinan memfd (`UploadCopy`). Dipakai worker (awal perakitan).
    Runner memakai `begin_upload` lalu `.copy()` tepat sebelum isi dipakai (setelah apktool)."""
    with begin_upload(uploads_dirfd, sha, cap_bytes, on_tick) as handle:
        return handle.copy()


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
