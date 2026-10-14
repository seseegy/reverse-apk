"""Tata letak direktori data. Satu-satunya tempat yang tahu di mana berkas disimpan.

    /data/uploads/<sha256>.apk        berkas unggahan asli (read-only setelah tervalidasi). Nama internal TETAP .apk walau isinya paket
                                      XAPK/APKS: halaman Penyimpanan, pembersihan, dan penjelajah semua memakai pola ini (lihat bundle.py)
    /data/uploads/.tmp/               unggahan yang sedang berjalan
    /data/work/<analysis_id>/         hasil: apktool/ jadx/ logs/ manifest.json (+ base.apk sementara, hanya selama tool berjalan, untuk paket)
    /data/files/<analysis_id>/up/     lampiran pengguna di chat (nama disimpan acak; nama asli hanya di DB)
    /data/files/<analysis_id>/ai/     berkas buatan AI (py, js, md, ...); hanya web yang menulis di sini
    /data/builds/<analysis_id>/<build_id>/   artefak build (Tahap 2: hasil bertanda tangan). Path HANYA dihitung dari id bilangan bulat positif
    /data/db/app.sqlite               basis data (SQLite, mode WAL)
    /data/spool/                      antrean berkas worker -> runner (lihat spool.py)

Nama berkas asli dari pengguna TIDAK PERNAH dipakai sebagai path (NFR-1.2).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _positive_id(name: str, value: object) -> int:
    """Hanya bilangan bulat positif murni. Menolak bool, str (mis. '../x'), float, bytes, None: id jadi segmen path."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} harus bilangan bulat positif")
    return value


class Layout:
    def __init__(self, data_dir: str | os.PathLike[str] = "/data") -> None:
        root = Path(data_dir)
        self.root = root
        self.uploads = root / "uploads"
        self.uploads_tmp = self.uploads / ".tmp"
        self.work = root / "work"
        # Volume terpisah dari `work`: "Analisis ulang" menghapus work/<id>, sedangkan berkas pengguna/AI harus bertahan.
        # Hanya web yang memasangnya (runner yang memproses APK tak tepercaya tidak punya akses).
        self.files = root / "files"
        self.files_tmp = self.files / ".tmp"
        self.db_dir = root / "db"
        self.db_path = self.db_dir / "app.sqlite"
        self.spool = root / "spool"
        # Artefak build (Tahap 2). Folder BELUM dibuat dan BELUM dipasang di compose pada Tahap 1.
        self.builds = root / "builds"

    def upload_path(self, sha256: str) -> Path:
        if not SHA256_RE.match(sha256):
            raise ValueError("sha256 tidak valid")
        return self.uploads / f"{sha256}.apk"

    def work_dir(self, analysis_id: int) -> Path:
        # int() menolak string berisi '/' atau '..' sebelum menjadi bagian path.
        return self.work / str(int(analysis_id))

    def files_dir(self, analysis_id: int) -> Path:
        return self.files / str(int(analysis_id))

    def builds_dir(self, analysis_id: int) -> Path:
        # Lebih ketat dari work_dir: tanpa int() sehingga '12' atau 12.0 ditolak, bukan dikonversi.
        return self.builds / str(_positive_id("analysis_id", analysis_id))

    def build_dir(self, analysis_id: int, build_id: int) -> Path:
        return self.builds / str(_positive_id("analysis_id", analysis_id)) / str(_positive_id("build_id", build_id))
