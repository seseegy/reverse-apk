"""Kebijakan akses perintah AI: apa yang boleh dibaca/ditulis. DAFTAR PUTIH; semua yang tidak disebut ditolak oleh Landlock.

Yang boleh DIBACA  : sistem (/usr, /bin, /lib, /etc, /opt), hasil analisis yang SEDANG DIBUKA saja (work/<id>/apktool, jadx, logs, manifest.json),
                     dan APK-nya sendiri (uploads/<sha>.apk, satu berkas).
Yang boleh DITULIS : ruang kerja analisis itu (bench/<id>/) dan folder sementara job (/tmp/...).
DITOLAK            : work/<id>/index (nilai rahasia MENTAH; sama dengan penjelajah folder), analisis lain, db, files, spool, daftar isi /data.
Semua path dihitung di sini dari `analysis_id` (angka) dan `sha256` (heksa 64): tidak ada path dari web yang dipercaya.

Pohon yang DIBANGUN dan di-diff adalah `$WS/project` (= bench/<id>/project, disalin dari baseline work/<id>/apktool oleh op `init`). `$WS` tetap seluruh
bench/<id>; aturan RW pada `$WS` sudah mencakup `project/` (Landlock berlaku untuk seluruh pohon di bawahnya), jadi `rules_for` tidak berubah.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from rvcore.paths import check_proto_id

from .landlock import DEV, RO, RW, Rule

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
WORK_VISIBLE_DIRS = ("apktool", "jadx", "logs")        # index/ SENGAJA tidak ada
WORK_VISIBLE_FILES = ("manifest.json",)
SYSTEM_RO = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc", "/opt")
DEVICES = ("/dev/null", "/dev/zero", "/dev/full", "/dev/urandom", "/dev/random")


@dataclass(frozen=True)
class Dirs:
    data: Path = Path("/data")

    @property
    def work(self) -> Path:
        return self.data / "work"

    @property
    def uploads(self) -> Path:
        return self.data / "uploads"

    @property
    def bench(self) -> Path:
        return self.data / "bench"


def workspace(dirs: Dirs, analysis_id: int) -> Path:
    return dirs.bench / str(int(analysis_id))              # int() menolak '/' dan '..'


def project_dir(dirs: Dirs, analysis_id: int) -> Path:
    """Pohon yang dibangun/di-diff: bench/<id>/project. Ketat: hanya int murni 1..MAX_PROTO_ID (op init/diff tidak menerima string atau bool)."""
    return dirs.bench / str(check_proto_id("analysis_id", analysis_id)) / "project"


def base_tree(dirs: Dirs, analysis_id: int) -> Path:
    """Baseline hasil apktool: work/<id>/apktool (dibaca saja; bench memasang `work` read-only)."""
    return dirs.work / str(check_proto_id("analysis_id", analysis_id)) / "apktool"


def rules_for(dirs: Dirs, analysis_id: int, sha256: str | None, scratch: Path) -> list[Rule]:
    aid = int(analysis_id)
    rules = [Rule(p, RO, optional=True) for p in SYSTEM_RO]
    rules += [Rule(p, DEV, optional=True) for p in DEVICES]
    w = dirs.work / str(aid)
    rules += [Rule(str(w / d), RO, optional=True) for d in WORK_VISIBLE_DIRS]
    rules += [Rule(str(w / f), RO, optional=True) for f in WORK_VISIBLE_FILES]
    if sha256 is not None and SHA256_RE.match(sha256):
        rules.append(Rule(str(dirs.uploads / f"{sha256}.apk"), RO, optional=True))
    rules.append(Rule(str(workspace(dirs, aid)), RW))      # wajib ada
    rules.append(Rule(str(scratch), RW))                   # wajib ada
    return rules


def canary_path(dirs: Dirs, analysis_id: int) -> str:
    """Folder yang SETELAH pengurungan harus tidak bisa didaftar. Bila bisa, pengurungan tidak efektif -> perintah tidak dijalankan."""
    return str(dirs.bench)


def env_for(dirs: Dirs, analysis_id: int, sha256: str | None, scratch: Path, job_id: str, proxy: str | None = None) -> dict[str, str]:
    aid = int(analysis_id)
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(scratch), "TMPDIR": str(scratch), "LANG": "C.UTF-8", "TERM": "dumb",
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1", "PWD": str(workspace(dirs, aid)),
        "WS": str(workspace(dirs, aid)), "WORK": str(dirs.work / str(aid)), "BENCH_JOB": job_id,
    }
    if sha256 is not None and SHA256_RE.match(sha256):
        env["APK"] = str(dirs.uploads / f"{sha256}.apk")
    if proxy:
        # Satu-satunya jalan keluar: proxy `egress` (hanya CONNECT/HTTPS). Klien yang mengabaikan variabel ini tidak punya rute lain (jaringan internal + Landlock TCP).
        for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "ALL_PROXY", "all_proxy"):
            env[k] = proxy
        env["NO_PROXY"] = env["no_proxy"] = ""
    return env
