"""Penerimaan unggahan besar secara streaming ke disk (NFR-1.1).

Kenapa bukan `request.form()`: Starlette menampung bagian multipart besar di berkas sementara di /tmp,
yang di container ini adalah tmpfs (RAM, dihitung ke mem_limit). Unggahan 200 MB akan membunuh container.
Karena itu klien mengirim BADAN MENTAH (octet-stream) dan metadata lewat header; server menulis tiap
potongan langsung ke volume uploads sambil menghitung SHA-256 dan MD5.
"""

from __future__ import annotations

import hashlib
import os
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from fastapi import Request
from fastapi.concurrency import run_in_threadpool

FLUSH_BYTES = 1024 * 1024  # kumpulkan 1 MiB sebelum pindah ke thread (hash + tulis)


class UploadError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Received:
    path: Path
    sha256: str
    md5: str
    size: int


def clean_display_name(raw: str | None) -> str:
    """Nama untuk TAMPILAN saja. Membuang path, karakter kontrol, dan kontrol arah teks (spoofing RLO)."""
    name = unquote(raw or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(
        ch for ch in name
        if unicodedata.category(ch) not in {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}
    ).strip()
    return name[:255]


def _write_chunk(fh, sha, md, data: bytes) -> None:  # noqa: ANN001
    sha.update(data)
    md.update(data)
    fh.write(data)


async def receive_to_tmp(request: Request, tmp_dir: Path, max_bytes: int) -> Received:
    """Tulis badan request ke tmp_dir/<acak>.part. Berkas dihapus bila terjadi galat apa pun."""
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = tmp_dir / f"{uuid.uuid4().hex}.part"
    sha = hashlib.sha256()
    md = hashlib.md5(usedforsecurity=False)  # MD5 hanya sebagai pengenal tambahan (FR-1.3)
    size = 0
    buf = bytearray()

    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    fh = os.fdopen(fd, "wb")
    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            size += len(chunk)
            if size > max_bytes:
                raise UploadError(413, "too_large", f"Berkas melebihi batas {max_bytes // (1024 * 1024)} MB.")
            buf += chunk
            if len(buf) >= FLUSH_BYTES:
                data = bytes(buf)
                buf.clear()
                await run_in_threadpool(_write_chunk, fh, sha, md, data)
        if buf:
            await run_in_threadpool(_write_chunk, fh, sha, md, bytes(buf))
            buf.clear()
        await run_in_threadpool(fh.flush)
        await run_in_threadpool(os.fsync, fh.fileno())
    except BaseException:
        fh.close()
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise
    fh.close()

    if size == 0:
        tmp_path.unlink(missing_ok=True)
        raise UploadError(422, "empty", "Berkas kosong.")
    return Received(path=tmp_path, sha256=sha.hexdigest(), md5=md.hexdigest(), size=size)
