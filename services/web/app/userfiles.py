"""Penyimpanan berkas per analisis: lampiran pengguna (kind 'upload') dan berkas buatan AI (kind 'ai').

Tata letak di disk (volume `files`, hanya dipasang di web; runner tidak punya akses):

    /data/files/<analysis_id>/up/<token-acak>     lampiran pengguna. NAMA ASLI TIDAK PERNAH jadi path; hanya disimpan di DB.
    /data/files/<analysis_id>/ai/<path/relatif>   buatan AI. Path datang dari model (TIDAK TEPERCAYA) -> `clean_ai_path`.
    /data/files/.tmp/                             tempat tulis sementara (satu filesystem dengan tujuan agar os.replace atomik)

Prinsip keamanan:
  * Path buatan AI diperiksa ketat (allowlist karakter & ekstensi teks, tanpa '..', tanpa titik di awal, kedalaman terbatas) dan
    setiap akses ke disk memakai resolve_under + O_NOFOLLOW + S_ISREG.
  * Jenis berkas ditentukan dari ISI (magic bytes), bukan dari ekstensi/Content-Type kiriman klien.
  * Isi tidak pernah dijalankan; gambar hanya disajikan inline bila lolos sniffing PNG/JPEG/GIF/WebP. Selain itu selalu unduhan.
  * Kuota ukuran & jumlah per analisis ditegakkan di DB dalam satu transaksi (lihat store.add_upload/upsert_ai_file).
"""

from __future__ import annotations

import codecs
import hashlib
import io
import mimetypes
import os
import re
import secrets
import stat
import time
import zipfile
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from rvcore import store
from rvcore.fsutil import resolve_under, safe_rmtree

MB = 1024 * 1024
SNIFF_BYTES = 8192
PENDING_TTL = 6 * 3600           # unggahan yang tidak pernah dikirim dibersihkan setelah ini (detik)
AI_PREFIX = "hasil_ai/"          # awalan yang dipakai model untuk menyebut berkas buatannya
UPLOAD_PREFIX = "lampiran/"      # awalan untuk lampiran pengguna

# Ekstensi yang boleh DITULIS AI (semuanya teks; AI tidak membuat biner). Daftar sengaja lebar: py, js, md, dan bahasa lain.
AI_TEXT_EXTS = frozenset("""
py pyi js mjs cjs ts tsx jsx md markdown txt rst json jsonl yaml yml toml ini cfg conf env properties xml html htm css scss
csv tsv log sql sh bash zsh fish ps1 bat cmd java kt kts smali c h cc cpp hpp cs go rs rb php pl lua swift dart gradle
proto graphql gql diff patch frida hook dockerfile makefile cmake
""".split())
AI_BARE_NAMES = frozenset({"Dockerfile", "Makefile", "Procfile", "LICENSE", "README", "Gemfile", "CMakeLists.txt"})
_SEG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+\-]{0,99}$")
MAX_PATH_LEN = 200
MAX_DEPTH = 5

_IMAGE_MIME = {"png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}


class FileError(Exception):
    """Galat berkas yang aman ditampilkan ke pengguna/model (tanpa path internal)."""


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int      # satu berkas (unggahan & buatan AI)
    quota_bytes: int         # total per analisis (0 = tanpa batas)
    max_count: int           # jumlah berkas per analisis (0 = tanpa batas)


def _env_int(name: str, default: int, lo: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return max(lo, int(raw)) if raw else default
    except ValueError:
        return default


def limits_from_env() -> Limits:
    return Limits(max_file_bytes=_env_int("ATTACH_MAX_MB", 25, 1) * MB,
                  quota_bytes=_env_int("FILES_QUOTA_MB", 1024) * MB,
                  max_count=_env_int("FILES_MAX_COUNT", 2000))


# ---------------------------------------------------------------- jenis berkas dari isi
def sniff_image(head: bytes) -> str | None:
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


def looks_text(head: bytes) -> bool:
    """Teks bila tanpa NUL dan (UTF-8 valid atau hampir tanpa karakter kontrol). Awalan terpotong di tengah karakter ditoleransi."""
    if not head:
        return True
    if b"\x00" in head:
        return False
    try:
        codecs.getincrementaldecoder("utf-8")("strict").decode(head, final=False)
        return True
    except UnicodeDecodeError:
        pass
    ctrl = sum(1 for b in head if b < 9 or 13 < b < 32 or b == 127)
    return ctrl * 100 < len(head)          # < 1% karakter kontrol: kemungkinan teks 8-bit (mis. latin-1)


def sniff(head: bytes, name: str = "") -> tuple[str, str]:
    """(media, mime) dari isi: 'image' | 'text' | 'binary'."""
    img = sniff_image(head)
    if img:
        return "image", _IMAGE_MIME[img]
    if looks_text(head):
        guessed = mimetypes.guess_type(name)[0] or "text/plain"
        return "text", guessed if guessed.startswith("text/") or guessed in ("application/json", "application/xml") else "text/plain"
    return "binary", "application/octet-stream"


# ---------------------------------------------------------------- path buatan AI
def clean_ai_path(raw: str) -> str:
    """Path relatif aman di folder ai/. Menerima awalan 'hasil_ai/'. Melempar FileError dengan alasan yang bisa dipahami model."""
    p = (raw or "").strip().replace("\\", "/")
    if p.startswith(AI_PREFIX):
        p = p[len(AI_PREFIX):]
    if not p:
        raise FileError("path kosong")
    if "\x00" in p or len(p) > MAX_PATH_LEN:
        raise FileError(f"path tidak valid atau lebih dari {MAX_PATH_LEN} karakter")
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        raise FileError("path harus relatif (tanpa awalan /), mis. frida/hook_login.js")
    parts = p.split("/")
    if len(parts) > MAX_DEPTH:
        raise FileError(f"folder terlalu dalam (maksimum {MAX_DEPTH} tingkat)")
    for seg in parts:
        if seg in ("", ".", ".."):
            raise FileError("path tidak boleh memuat '..', '.', atau segmen kosong")
        if not _SEG_RE.match(seg):
            raise FileError("nama berkas/folder hanya boleh huruf, angka, '_', '-', '.', '+' (tanpa spasi, tanpa titik di awal, maks 100 "
                            f"karakter per segmen): {seg[:40]!r}")
        if seg.endswith("."):
            raise FileError("nama tidak boleh diakhiri titik")
    last = parts[-1]
    ext = last.rsplit(".", 1)[-1].lower() if "." in last else ""
    if last not in AI_BARE_NAMES and ext not in AI_TEXT_EXTS:
        raise FileError("ekstensi tidak diizinkan: AI hanya membuat berkas teks/kode (py, js, md, txt, json, yaml, sh, java, kt, smali, "
                        f"html, sql, ...). Nama: {last[:40]!r}")
    return "/".join(parts)


def display_name_for_header(name: str) -> tuple[str, str]:
    """(fallback_ascii, encoded_utf8) untuk Content-Disposition. Nama sudah dibersihkan dari kontrol oleh pemanggil."""
    from urllib.parse import quote

    ascii_name = re.sub(r"[^A-Za-z0-9._\- ]", "_", name)[:120] or "berkas"
    return ascii_name.replace('"', "_"), quote(name, safe="")


# ---------------------------------------------------------------- penyimpanan
def open_regular(path: Path):
    """Buka berkas biasa (bukan symlink/direktori/khusus) untuk baca biner. FileError bila tidak bisa."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise FileError("berkas tidak ditemukan di penyimpanan") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise FileError("bukan berkas biasa")
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb")


class FileStore:
    def __init__(self, root: Path, tmp: Path, limits: Limits, db: Callable[[], Any]) -> None:
        self.root, self.tmp, self.limits, self.db = Path(root), Path(tmp), limits, db

    # --- lokasi
    def base(self, analysis_id: int) -> Path:
        return self.root / str(int(analysis_id))

    def _kind_dir(self, analysis_id: int, kind: str) -> Path:
        return self.base(analysis_id) / ("up" if kind == "upload" else "ai")

    def abs_path(self, row: Any) -> Path | None:
        """Lokasi di disk untuk baris DB (aman terhadap symlink), atau None."""
        kind_dir = self._kind_dir(row["analysis_id"], row["kind"])
        return resolve_under(kind_dir, *str(row["path"]).split("/"))

    # --- baca
    def read_bytes(self, row: Any, max_bytes: int | None = None) -> bytes:
        path = self.abs_path(row)
        if path is None:
            raise FileError("berkas tidak ditemukan di penyimpanan")
        with open_regular(path) as fh:
            return fh.read() if max_bytes is None else fh.read(max_bytes)

    def read_text(self, row: Any, max_bytes: int | None = None) -> str:
        return self.read_bytes(row, max_bytes).decode("utf-8", errors="replace")

    # --- unggahan pengguna
    def save_upload(self, analysis_id: int, received: Path, name: str, size: int, sha256: str) -> dict[str, Any]:
        """Pindahkan hasil unggahan (di .tmp) ke up/ dan catat di DB. `received` dihapus bila gagal."""
        try:
            with open(received, "rb") as fh:
                head = fh.read(SNIFF_BYTES)
            media, mime = sniff(head, name)
            dest_dir = self._kind_dir(analysis_id, "upload")
            dest_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
            token = secrets.token_hex(12)
            dest = dest_dir / token
            os.replace(received, dest)
            os.chmod(dest, 0o600)
        except OSError as exc:
            received.unlink(missing_ok=True)
            raise FileError("gagal menyimpan lampiran (disk penuh atau tidak bisa ditulis)") from exc
        try:
            with closing(self.db()) as conn:
                fid = store.add_upload(conn, analysis_id, path=token, name=name, media=media, mime=mime, size=size, sha256=sha256,
                                       quota_bytes=self.limits.quota_bytes, max_count=self.limits.max_count)
        except BaseException:
            dest.unlink(missing_ok=True)
            raise
        return {"id": fid, "name": name, "media": media, "mime": mime, "size": size, "kind": "upload"}

    # --- buatan AI
    def _ai_target(self, analysis_id: int, rel: str) -> Path:
        base = self._kind_dir(analysis_id, "ai")
        target = base.joinpath(*rel.split("/"))
        # Tidak ada komponen yang boleh berupa symlink (kita sendiri tidak pernah membuatnya; ini pertahanan berlapis).
        probe = base
        for part in rel.split("/"):
            probe = probe / part
            if probe.is_symlink():
                raise FileError("path bertabrakan dengan entri tidak valid")
        return target

    def write_ai(self, analysis_id: int, path: str, content: str, mode: str = "overwrite") -> dict[str, Any]:
        """Tulis/ganti/tambah berkas buatan AI. mode: overwrite | append | create. Mengembalikan metadata (id, revisi, ukuran, ...)."""
        rel = clean_ai_path(path)
        if mode not in ("overwrite", "append", "create"):
            raise FileError("mode harus overwrite, append, atau create")
        if not isinstance(content, str):
            raise FileError("content harus berupa teks")
        if "\x00" in content:
            raise FileError("content memuat karakter NUL (bukan teks)")
        target = self._ai_target(analysis_id, rel)
        existed = target.is_file()
        if target.is_dir():
            raise FileError(f"{rel} adalah folder; pilih nama berkas lain")
        if existed and mode == "create":
            raise FileError(f"{rel} sudah ada. Pakai mode overwrite/append atau nama lain.")
        data = content.encode("utf-8")
        if existed and mode == "append":
            with open_regular(target) as fh:          # penyambungan apa adanya; model yang mengatur baris baru
                data = fh.read() + data
        if len(data) > self.limits.max_file_bytes:
            raise FileError(f"berkas {len(data) // 1024} KB melebihi batas {self.limits.max_file_bytes // MB} MB per berkas")
        if not data:
            raise FileError("isi kosong")
        # Pra-cek kuota sebelum menyentuh disk (pemeriksaan yang mengikat ada di transaksi DB di bawah).
        with closing(self.db()) as conn:
            used, count = store.files_usage(conn, analysis_id)
        if self.limits.quota_bytes and used + len(data) > self.limits.quota_bytes + (target.stat().st_size if existed else 0):
            raise FileError("kuota berkas analisis ini penuh; minta pengguna menghapus berkas lama di tab Berkas")
        try:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        except (FileExistsError, NotADirectoryError) as exc:
            raise FileError("salah satu folder pada path bertabrakan dengan berkas yang sudah ada") from exc
        self.tmp.mkdir(parents=True, exist_ok=True, mode=0o750)
        tmp = self.tmp / f".w{secrets.token_hex(8)}"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
        except OSError as exc:
            tmp.unlink(missing_ok=True)
            raise FileError("gagal menulis berkas (disk penuh atau tidak bisa ditulis)") from exc
        guessed = mimetypes.guess_type(rel)[0] or "text/plain"
        try:
            with closing(self.db()) as conn:
                fid, revision, created = store.upsert_ai_file(
                    conn, analysis_id, path=rel, media="text", mime=guessed if guessed.startswith("text/") else "text/plain",
                    size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                    quota_bytes=self.limits.quota_bytes, max_count=self.limits.max_count)
        except store.FileQuotaError as exc:
            if not existed:
                target.unlink(missing_ok=True)
            raise FileError(str(exc)) from exc
        return {"id": fid, "path": rel, "name": rel.rsplit("/", 1)[-1], "size": len(data), "revision": revision,
                "created": created, "lines": data.count(b"\n") + (0 if data.endswith(b"\n") else 1)}

    def edit_ai(self, analysis_id: int, path: str, old: str, new: str) -> dict[str, Any]:
        """Ganti SATU kemunculan `old` dengan `new`. Gagal bila `old` tidak ada atau muncul lebih dari sekali."""
        rel = clean_ai_path(path)
        with closing(self.db()) as conn:
            row = store.find_file(conn, analysis_id, "ai", rel)
        if row is None:
            raise FileError(f"{rel} belum ada. Buat dulu dengan write_file.")
        if not old:
            raise FileError("old_string wajib diisi")
        text = self.read_text(row)
        count = text.count(old)
        if count == 0:
            raise FileError("old_string tidak ditemukan persis (perhatikan spasi/indentasi). Baca ulang berkasnya dengan read_file.")
        if count > 1:
            raise FileError(f"old_string muncul {count} kali; perluas dengan baris di sekitarnya agar unik")
        res = self.write_ai(analysis_id, rel, text.replace(old, new, 1), "overwrite")
        res["diganti"] = 1
        return res

    # --- hapus & bersih-bersih
    def delete(self, analysis_id: int, file_id: int) -> bool:
        with closing(self.db()) as conn:
            row = store.delete_file_row(conn, analysis_id, file_id)
        if row is None:
            return False
        path = self.abs_path(row)
        if path is not None:
            try:
                path.unlink()
            except OSError:
                pass
            # Rapikan folder kosong di bawah ai/ (tidak pernah menghapus folder akar).
            if row["kind"] == "ai":
                stop = self._kind_dir(analysis_id, "ai")
                cur = path.parent
                while cur != stop and stop in cur.parents:
                    try:
                        cur.rmdir()
                    except OSError:
                        break
                    cur = cur.parent
        return True

    def purge_stale_uploads(self, analysis_id: int) -> int:
        """Hapus unggahan yang tidak pernah dikirim bersama pesan (pengguna membatalkan/menutup halaman)."""
        with closing(self.db()) as conn:
            rows = store.stale_pending_uploads(conn, analysis_id, time.time() - PENDING_TTL)
        n = 0
        for r in rows:
            n += 1 if self.delete(analysis_id, r["id"]) else 0
        return n

    def remove_all(self, analysis_id: int) -> None:
        safe_rmtree(self.base(analysis_id))


# ---------------------------------------------------------------- ZIP streaming
class _Sink(io.RawIOBase):
    """Tujuan tulis yang tidak bisa di-seek: zipfile memakai data descriptor, dan potongan diambil lewat `take()`."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._pos = 0

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:  # noqa: ANN001
        self._buf += b
        self._pos += len(b)
        return len(b)

    def tell(self) -> int:
        return self._pos

    def take(self) -> bytes:
        out = bytes(self._buf)
        self._buf.clear()
        return out


def iter_zip(entries: list[tuple[str, Path, float]]) -> Iterator[bytes]:
    """ZIP dialirkan potong demi potong (memori konstan, berapa pun ukuran berkas). entries = [(nama_di_zip, path_disk, mtime)]."""
    sink = _Sink()
    with zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, path, mtime in entries:
            try:
                src = open_regular(path)
            except FileError:
                continue
            with src:
                info = zipfile.ZipInfo(arcname, date_time=time.localtime(max(mtime, 315532800))[:6])
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                with zf.open(info, "w", force_zip64=True) as dst:
                    while True:
                        chunk = src.read(256 * 1024)
                        if not chunk:
                            break
                        dst.write(chunk)
                        if len(sink._buf) >= 256 * 1024:
                            yield sink.take()
            if sink._buf:
                yield sink.take()
    tail = sink.take()
    if tail:
        yield tail
