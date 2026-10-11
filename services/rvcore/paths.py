"""Tata letak direktori data. Satu-satunya tempat yang tahu di mana berkas disimpan.

    /data/uploads/<sha256>.apk        APK asli (read-only setelah tervalidasi)
    /data/uploads/.tmp/               unggahan yang sedang berjalan
    /data/work/<analysis_id>/         hasil: apktool/ jadx/ logs/ manifest.json
    /data/files/<analysis_id>/up/     lampiran pengguna di chat (nama disimpan acak; nama asli hanya di DB)
    /data/files/<analysis_id>/ai/     berkas buatan AI (py, js, md, ...); hanya web yang menulis di sini
    /data/db/app.sqlite               basis data (SQLite, mode WAL)
    /data/spool/                      antrean berkas worker -> runner (lihat spool.py)

Nama berkas asli dari pengguna TIDAK PERNAH dipakai sebagai path (NFR-1.2).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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

    def upload_path(self, sha256: str) -> Path:
        if not SHA256_RE.match(sha256):
            raise ValueError("sha256 tidak valid")
        return self.uploads / f"{sha256}.apk"

    def work_dir(self, analysis_id: int) -> Path:
        # int() menolak string berisi '/' atau '..' sebelum menjadi bagian path.
        return self.work / str(int(analysis_id))

    def files_dir(self, analysis_id: int) -> Path:
        return self.files / str(int(analysis_id))
