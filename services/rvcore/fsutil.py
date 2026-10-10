"""Utilitas berkas yang aman terhadap isi yang tidak tepercaya (symlink, izin aneh, pohon raksasa)."""

from __future__ import annotations

import json
import os
import shutil
import stat
import uuid
from pathlib import Path
from typing import Any


def safe_rmtree(path: str | os.PathLike[str]) -> None:
    """Hapus pohon direktori tanpa pernah mengikuti symlink.

    Hasil dekompilasi bisa berisi direktori tanpa bit tulis; izin diperbaiki lalu dicoba ulang.
    """
    p = Path(path)
    try:
        if p.is_symlink():
            p.unlink()
            return
        if not p.exists():
            return
    except OSError:
        return

    def _onexc(func, failed_path, exc):  # noqa: ANN001
        if isinstance(exc, FileNotFoundError):
            return
        try:
            os.chmod(os.path.dirname(failed_path) or ".", 0o700)
            os.chmod(failed_path, 0o700)
        except OSError:
            pass
        func(failed_path)  # bila masih gagal, biarkan exception naik

    shutil.rmtree(p, onexc=_onexc)


def tree_stats(root: str | os.PathLike[str], max_bytes: int | None = None,
               max_files: int | None = None) -> tuple[int, int, bool]:
    """(total_byte, jumlah_berkas, melebihi_batas). Tidak mengikuti symlink; berhenti dini bila melebihi."""
    total = files = 0
    stack = [str(root)]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            files += 1
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
                    if (max_bytes is not None and total > max_bytes) or (
                        max_files is not None and files > max_files
                    ):
                        return total, files, True
        except OSError:
            continue
    return total, files, False


def remove_unsafe_entries(root: str | os.PathLike[str]) -> int:
    """Hapus symlink dan berkas khusus (socket, fifo, device) dari pohon hasil. Mengembalikan jumlahnya."""
    removed = 0
    stack = [str(root)]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except OSError:
            continue
        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode) or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                    os.unlink(entry.path)
                    removed += 1
                elif stat.S_ISDIR(st.st_mode):
                    stack.append(entry.path)
            except OSError:
                continue
    return removed


def resolve_under(root: str | os.PathLike[str], *parts: str) -> Path | None:
    """Path absolut dari root/parts bila (setelah menyelesaikan symlink) tetap berada di dalam root; selain itu None.

    Dipakai setiap kali web membaca isi yang bisa ditulis runner: runner yang dikompromikan tidak boleh
    bisa mengarahkan pembacaan ke berkas lain lewat symlink.
    """
    try:
        base = Path(os.path.realpath(root))
        target = Path(os.path.realpath(base.joinpath(*parts)))
    except (OSError, ValueError):
        return None
    if target == base or base not in target.parents:
        return None
    return target


def read_json_under(root: str | os.PathLike[str], *parts: str, max_bytes: int = 8 * 1024 * 1024) -> Any | None:
    """Baca berkas JSON kecil di bawah root secara aman. None bila tidak ada/tidak valid/terlalu besar."""
    target = resolve_under(root, *parts)
    if target is None:
        return None
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            if os.fstat(fh.fileno()).st_size > max_bytes or not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None
            return json.loads(fh.read(max_bytes + 1))
    except (OSError, ValueError):
        return None


def atomic_write_json(dest: Path, tmp_dir: Path, obj: Any, mode: int = 0o644) -> None:
    """Tulis JSON ke tmp_dir lalu os.replace ke dest (satu filesystem) agar pembaca tak melihat setengah berkas."""
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp = tmp_dir / f".{dest.name}.{uuid.uuid4().hex[:8]}.tmp"
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
