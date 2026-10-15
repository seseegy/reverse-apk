"""Op bench `init` dan `diff` (Tahap 2b): baseline apktool -> `$WS/project`, dan diff kanonik `project/` terhadap baseline. Logika murni, tanpa spool/Docker.

Kontrak ruang kerja: `$WS` = bench/<id> (tidak berubah; tempat perintah shell AI bekerja dan Landlock memberi RW). Pohon yang DIBANGUN dan di-diff adalah
`$WS/project`; berkas lain di `$WS` (catatan, skrip) bebas dan diabaikan. Sebelum `init`, `project/` tidak ada dan `diff` ditolak (`belum_init`).

Semua jalur dihitung dari `analysis_id` (int) lewat `policy`; tidak ada jalur, nama, atau hash dari web yang dipakai. Daemon pemanggil TIDAK dikurung Landlock
dan membaca pohon yang ditulis AI, jadi semua pembacaan lewat `rvcore.treediff` (tanpa mengikuti symlink, FIFO tidak menggantung, batas jumlah/ukuran/kedalaman).
Satu job sekali jalan dan proses latar perintah AI dibunuh setelah tiap perintah, jadi tidak ada penulis AI selama op ini berjalan.

`init` tidak pernah menimpa pekerjaan AI tanpa perintah eksplisit:
  * tanpa `force`, `project` yang sudah ada (direktori, symlink, atau berkas) dibiarkan: `ok created=false reason=exists`, nol perubahan;
  * `force=True` menyalin baseline ke `.project.tmp` DULU (galat -> `project` lama utuh), baru menghapus `project` lama (tanpa mengikuti symlink) lalu `rename`.
    `force` hanya dikirim `buildctl init --force` (pemilik di shell VPS); tidak ada tool AI yang membangun permintaan `init`.
"""

from __future__ import annotations

import errno
import os
import stat
import time
from pathlib import Path
from typing import Any, Callable

from rvcore import shellspool as SP
from rvcore import treediff
from rvcore.fsutil import safe_rmtree
from rvcore.paths import check_proto_id

from . import executor, policy

PROJECT = "project"
PROJECT_TMP = ".project.tmp"
BASE_MARKER = "AndroidManifest.xml"
QUOTA_COPY_FRACTION = (3, 4)             # batas total byte isi salinan: 3/4 kuota ruang kerja (ukuran nyata; blok disk dicek terpisah)
QUOTA_AFTER_FRACTION = (9, 10)           # init yang sukses tidak boleh membuat perintah shell pertama ditolak kuota: ruang kerja (blok disk) <= 90%
FREE_RESERVE_BYTES = 64 * 1024 * 1024    # cadangan ruang bebas di atas ukuran sumber (A-15)
BEAT_EVERY = 5.0


def _refused(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"status": SP.STATUS_REFUSED, "code": code, "message": message, **extra}


def _ticker(cancel: Callable[[], bool], heartbeat: Callable[[], None], timeout: int, clock: Callable[[], float] = time.monotonic) -> Callable[[], None]:
    """`on_tick` untuk treediff: detak jantung paling jarang tiap BEAT_EVERY, pembatalan, dan tenggat."""
    deadline = clock() + timeout
    state = {"beat": 0.0}

    def tick() -> None:
        now = clock()
        if now - state["beat"] >= BEAT_EVERY:
            state["beat"] = now
            heartbeat()
        if cancel():
            raise treediff.TreeLimitError("cancelled", "dibatalkan")
        if now > deadline:
            raise treediff.TreeLimitError("timeout", f"melebihi batas waktu {timeout} detik")

    return tick


def _from_limit_error(exc: treediff.TreeLimitError) -> dict[str, Any]:
    if exc.code == "cancelled":
        return {"status": SP.STATUS_CANCELLED, "message": "dibatalkan"}
    if exc.code == "timeout":
        return {"status": SP.STATUS_TIMEOUT, "message": exc.message}
    return _refused(exc.code, exc.message)


def _oserror(what: str, exc: OSError) -> dict[str, Any]:
    return {"status": SP.STATUS_FAILED, "message": f"{what} ({type(exc).__name__}, {errno.errorcode.get(exc.errno or 0, 'EIO')})"}


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _base_ok(base: Path) -> bool:
    """Baseline = direktori nyata (bukan symlink) berisi AndroidManifest.xml berkas biasa (bukan symlink)."""
    st, mf = _lstat(base), _lstat(base / BASE_MARKER)
    return bool(st and stat.S_ISDIR(st.st_mode) and mf and stat.S_ISREG(mf.st_mode))


def _size_of(path: Path) -> int:
    """Ukuran blok disk entri: direktori nyata -> seluruh pohon, berkas biasa -> bloknya, selain itu (symlink/khusus/tak ada) 0. Tidak mengikuti symlink."""
    st = _lstat(path)
    if st is None:
        return 0
    if stat.S_ISDIR(st.st_mode):
        return executor.tree_bytes(path)
    return st.st_blocks * 512 if stat.S_ISREG(st.st_mode) else 0


def _remove(path: Path) -> None:
    """Hapus entri apa pun tanpa mengikuti symlink."""
    st = _lstat(path)
    if st is None:
        return
    if stat.S_ISDIR(st.st_mode):
        safe_rmtree(path)
    else:
        os.unlink(path)


def _prepare_ws(dirs: policy.Dirs, aid: int) -> tuple[Path | None, dict[str, Any] | None]:
    ws = policy.workspace(dirs, aid)
    try:
        ws.mkdir(parents=True, mode=0o700, exist_ok=True)
        if ws.is_symlink() or not ws.is_dir():
            return None, {"status": SP.STATUS_REFUSED, "message": "ruang kerja tidak valid"}
    except OSError as exc:
        return None, _oserror("ruang kerja tidak bisa disiapkan", exc)
    return ws, None


def op_init(dirs: policy.Dirs, workspace_bytes: int, aid: int, force: bool, *, timeout: int, cancel: Callable[[], bool] = lambda: False,
            heartbeat: Callable[[], None] = lambda: None, statvfs: Callable[[Any], Any] = os.statvfs) -> dict[str, Any]:
    """Salin baseline ke `bench/<aid>/project`. Hasil siap ditulis ke spool; TIDAK PERNAH melempar untuk kegagalan operasi.
    `ValueError` hanya untuk id yang bukan int murni 1..MAX_PROTO_ID (pemanggil daemon sudah memvalidasi; ini lapis kedua)."""
    check_proto_id("analysis_id", aid)
    ws, bad = _prepare_ws(dirs, aid)
    if bad is not None:
        return bad
    assert ws is not None
    project, tmp, base = ws / PROJECT, ws / PROJECT_TMP, policy.base_tree(dirs, aid)
    executor.touch_activity(ws)
    try:
        _remove(tmp)                                           # sisa daemon yang mati di tengah salinan (atau umpan symlink dari AI)
        existed = _lstat(project) is not None
    except OSError as exc:
        return _oserror("ruang kerja tidak bisa diperiksa", exc)
    if existed and not force:
        return {"status": SP.STATUS_OK, "created": False, "reason": "exists",
                "message": "project sudah ada; isinya TIDAK dibandingkan dengan baseline (lihat `diff`; `init --force` mengulang dari baseline)"}
    if not _base_ok(base):
        return _refused("baseline_tidak_ada", "hasil dekompilasi (apktool) analisis ini tidak ada atau tidak lengkap")

    try:
        src_bytes = executor.tree_bytes(base)
        others = max(0, executor.tree_bytes(ws) - _size_of(project))        # pekerjaan lain di ruang kerja; `project` lama akan diganti
        vfs = statvfs(ws)
        free = vfs.f_bavail * vfs.f_frsize
    except OSError as exc:
        return _oserror("ruang kerja tidak bisa diperiksa", exc)
    if free < src_bytes + FREE_RESERVE_BYTES:
        return _refused("kuota", "ruang disk bebas tidak cukup untuk menyalin baseline; kosongkan ruang dulu")

    limits = treediff.Limits(max_total_bytes=workspace_bytes * QUOTA_COPY_FRACTION[0] // QUOTA_COPY_FRACTION[1])
    try:
        stats = treediff.copy_tree_safe(base, tmp, limits, on_tick=_ticker(cancel, heartbeat, timeout))
        used = others + executor.tree_bytes(tmp)
        if used > workspace_bytes * QUOTA_AFTER_FRACTION[0] // QUOTA_AFTER_FRACTION[1]:
            _remove(tmp)
            return _refused("kuota", f"baseline ({used // (1024 * 1024)} MB) terlalu besar untuk kuota ruang kerja {workspace_bytes // (1024 * 1024)} MB")
        if existed:
            _remove(project)
        os.rename(tmp, project)
    except treediff.TreeLimitError as exc:
        _cleanup(tmp)
        return _from_limit_error(exc)
    except OSError as exc:
        _cleanup(tmp)
        return _oserror("menyalin baseline gagal", exc)
    return {"status": SP.STATUS_OK, "created": True, "reason": "reset" if existed else "created", "files": stats.files, "dirs": stats.dirs, "bytes": stats.bytes,
            "skipped": {"symlink": stats.skipped_symlink, "special": stats.skipped_special, "root_ignored": stats.root_ignored, "vanished": stats.vanished},
            "message": "project disalin dari baseline" + (" (diulang dari awal)" if existed else "")}


def _cleanup(tmp: Path) -> None:
    try:
        _remove(tmp)
    except OSError:
        pass


def op_diff(dirs: policy.Dirs, aid: int, *, timeout: int, cancel: Callable[[], bool] = lambda: False,
            heartbeat: Callable[[], None] = lambda: None) -> dict[str, Any]:
    """Diff kanonik `bench/<aid>/project` terhadap baseline + ringkasan (`treediff.DiffResult`). Tidak pernah melempar untuk kegagalan operasi."""
    check_proto_id("analysis_id", aid)
    ws = policy.workspace(dirs, aid)
    project, base = ws / PROJECT, policy.base_tree(dirs, aid)
    try:
        wst = _lstat(ws)
        st = _lstat(project) if wst is not None and stat.S_ISDIR(wst.st_mode) else None
        if st is None:
            return _refused("belum_init", "project belum dibuat; jalankan `init` dulu")
        if not stat.S_ISDIR(st.st_mode):
            return _refused("project_tidak_valid", "project bukan direktori biasa; `init --force` mengulang dari baseline")
        if not _base_ok(base):
            return _refused("baseline_tidak_ada", "hasil dekompilasi (apktool) analisis ini tidak ada atau tidak lengkap")
        executor.touch_activity(ws)
        res = treediff.compute_diff(base, project, treediff.Limits(), on_tick=_ticker(cancel, heartbeat, timeout))
    except treediff.TreeLimitError as exc:
        return _from_limit_error(exc)
    except OSError as exc:
        return _oserror("menghitung diff gagal", exc)
    return {"status": SP.STATUS_OK, "diff_sha256": res.diff_sha256, "counts": res.counts, "entries_total": res.entries_total, "base_entries": res.base_entries,
            "bytes": res.byte_totals, "kinds": res.kinds, "lines": res.lines, "skipped": res.skipped, "top": res.top, "truncated": res.truncated, "message": ""}
