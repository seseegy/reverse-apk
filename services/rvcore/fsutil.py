"""Utilitas berkas yang aman terhadap isi yang tidak tepercaya (symlink, izin aneh, pohon raksasa)."""

from __future__ import annotations

import errno
import functools
import json
import os
import re
import shutil
import stat
import uuid
from pathlib import Path
from typing import Any, Sequence


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

    tried: set[str] = set()

    def _onexc(func, failed_path, exc):  # noqa: ANN001
        if isinstance(exc, FileNotFoundError):
            return
        try:
            os.chmod(os.path.dirname(failed_path) or ".", 0o700)
            os.chmod(failed_path, 0o700)
        except OSError:
            pass
        if func in (os.open, os.scandir, os.listdir):
            # Direktori tanpa bit baca (mode 000): rmtree berbasis fd memanggil handler dengan `os.open(nama, flags, dir_fd=)`, jadi `func(failed_path)` di bawah
            # akan TypeError. Setelah izin diperbaiki, ulangi penghapusan direktori itu dari awal; `tried` mencegah rekursi tak berujung bila chmod tidak berhasil.
            if failed_path in tried:
                raise exc
            tried.add(failed_path)
            shutil.rmtree(failed_path, onexc=_onexc)
            return
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


# ---------------------------------------------------------------------------------------------------- rantai-dirfd (volume `builds`)
# Runner (memproses pohon tak tepercaya) menulis akar `builds`, dan semua kontainer memakai uid 10001. Komponen perantara `builds/<aid>` yang ditukar
# jadi symlink akan diikuti oleh jalur string (`Path.mkdir`, `safe_rmtree` yang hanya memeriksa komponen TERAKHIR). Karena itu semua konsumen `builds/`
# selain runner memakai dua fungsi di bawah: tiap komponen dibuka relatif ke fd induknya dengan O_NOFOLLOW|O_DIRECTORY.
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _chain_name(name: object) -> str:
    """Komponen rantai = string bilangan bulat positif kanonik ('12'); '..', '', '1/2', '01', ' 1' ditolak (ValueError)."""
    if not isinstance(name, str) or not (name.isascii() and name.isdigit()) or str(int(name)) != name or int(name) <= 0:
        raise ValueError("komponen jalur harus string bilangan bulat positif")
    return name


def open_dir_chain(root: str | os.PathLike[str], *names: str, create: bool = False, mode: int = 0o755) -> int:
    """fd direktori `root/names...`: `root` lalu tiap nama dibuka relatif ke fd induk dengan O_RDONLY|O_DIRECTORY|O_NOFOLLOW. Symlink di komponen mana
    pun menghasilkan OSError (ELOOP/ENOTDIR), tidak pernah diikuti. `create=True` membuat komponen yang belum ada (`mkdir` relatif fd; yang sudah ada dipakai).
    OSError naik apa adanya (ENOENT = tak ada). Pemanggil menutup fd hasil."""
    parts = [_chain_name(n) for n in names]
    fd = os.open(root, DIR_FLAGS)
    for name in parts:
        try:
            if create:
                try:
                    os.mkdir(name, mode, dir_fd=fd)
                except FileExistsError:
                    pass
            nxt = os.open(name, DIR_FLAGS, dir_fd=fd)
        except BaseException:
            os.close(fd)
            raise
        os.close(fd)
        fd = nxt
    return fd


def _open_dir_fixing(parent_fd: int, name: str) -> int:
    """Buka subdirektori tanpa mengikuti symlink; bila izin baca ditolak (mode 000) pada direktori yang terbukti direktori, pulihkan 0700 lewat fd O_PATH
    (chmod pada /proc/self/fd/N tidak mengikuti symlink karena fd sudah terkunci ke inode) dan coba sekali lagi."""
    try:
        return os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    except PermissionError:
        pfd = os.open(name, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)   # symlink/bukan direktori -> OSError
        try:
            os.chmod(f"/proc/self/fd/{pfd}", 0o700)
        finally:
            os.close(pfd)
        return os.open(name, DIR_FLAGS, dir_fd=parent_fd)


def _with_fix(fd: int, func, *args, **kwargs):  # noqa: ANN001, ANN202
    """Jalankan `func`; EACCES/EPERM sekali -> fchmod 0700 pada direktori `fd` lalu ulangi."""
    try:
        return func(*args, **kwargs)
    except PermissionError:
        os.fchmod(fd, 0o700)
        return func(*args, **kwargs)


def _ident(fd: int) -> tuple[int, int]:
    st = os.fstat(fd)
    return st.st_dev, st.st_ino


def rmtree_at(dirfd: int, name: str) -> None:
    """Hapus entri `name` di bawah `dirfd` TANPA mengikuti symlink: bukan direktori (berkas, symlink, FIFO, soket) -> `unlink`; direktori -> isinya dihapus
    ITERATIF (pohon 5000 tingkat tidak memicu RecursionError) lalu `rmdir`. Hanya SATU fd direktori yang dipegang (naik lewat '..' dan memeriksa
    (dev, inode) induk), jadi kedalaman tidak menghabiskan batas fd. Direktori tanpa izin diperbaiki 0700 lewat fd. Yang sudah tak ada diabaikan."""
    try:
        st = os.lstat(name, dir_fd=dirfd)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(st.st_mode):
        try:
            os.unlink(name, dir_fd=dirfd)
        except FileNotFoundError:
            pass
        return
    fd = _open_dir_fixing(dirfd, name)
    try:
        # level: (ident direktori, nama sisa yang belum diproses, nama direktori ini di induknya)
        levels: list[tuple[tuple[int, int], list[str], str]] = [(_ident(fd), _with_fix(fd, os.listdir, fd), name)]
        while levels:
            ident, pending, own_name = levels[-1]
            if pending:
                child = pending.pop()
                try:
                    cst = os.lstat(child, dir_fd=fd)
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(cst.st_mode):
                    nfd = _open_dir_fixing(fd, child)
                    os.close(fd)
                    fd = nfd
                    levels.append((_ident(fd), _with_fix(fd, os.listdir, fd), child))
                else:
                    try:
                        _with_fix(fd, os.unlink, child, dir_fd=fd)
                    except FileNotFoundError:
                        pass
                continue
            levels.pop()
            if not levels:
                break
            parent = os.open("..", DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = parent
            if _ident(fd) != levels[-1][0]:
                raise OSError(errno.EBUSY, "pohon dipindahkan saat dihapus")
            _with_fix(fd, os.rmdir, own_name, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=dirfd)


# ---------------------------------------------------------------------------------------------------- penyaring jalur
# Path internal (kontainer) absolut yang tidak boleh sampai ke layar/AI: /data/work/12/..., /tmp/x, /opt/...
INTERNAL_PATH_RE = re.compile(
    r"(?<![\w<])/(?:data|tmp|opt|app|run|home|work|out|in|w|usr|var|etc|proc|root|mnt|srv|lib|bin|sbin|dev|sys)(?![\w-])"
    r"(?:/[^\s'\"`]*)?"
)
# Nama volume sebagai jalur RELATIF (apktool memantulkan jalur relatif terhadap cwd): `work/12/apktool/x`, `builds/3/7/...`. Lookbehind menolak awalan
# huruf/angka, '/', '.', '<', '>' dan '-': `smali/com/x/work/Foo.smali` dan `res/raw/builds/x` (bukan awal token) TIDAK disentuh.
_REL_PATH = r"(?<![\w./<>-])(?:work|builds|bench|uploads|spool|files|db|signwork|signspool|benchspool)/[^\s'\"`]*"
_BIDI_CHARS = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


@functools.lru_cache(maxsize=64)
def _scrub_re(roots: tuple[tuple[str, str], ...]) -> "re.Pattern[str]":
    """SATU regex alternasi (akar dikenal -> absolut -> relatif): yang paling kiri menang di posisi yang sama dan hasil penggantian TIDAK dipindai ulang."""
    # `keep`: label hasil saringan sebelumnya (`<proyek>/lib/x.so`) dibiarkan utuh, supaya menyaring dua kali (runner lalu worker/store) tidak merusak sisa jalur proyek.
    alts = [r"(?P<keep><(?:proyek|build|dasar|home)>(?:/[^\s'\"`]*)?)"]
    if roots:
        escaped = "|".join(re.escape(r) for r, _ in sorted(roots, key=lambda t: -len(t[0])))
        alts.append(rf"(?<![\w<])(?P<root>{escaped})(?![\w-])(?P<rest>(?:/[^\s'\"`]*)?)")
    alts.append(rf"(?P<abs>{INTERNAL_PATH_RE.pattern})")
    alts.append(rf"(?P<rel>{_REL_PATH})")
    return re.compile("|".join(alts))


def scrub_paths(text: object, roots: Sequence[tuple[str, str]] = ()) -> str:
    """Samarkan jalur internal di `text` (keluaran alat/AI; tak tepercaya). Karakter kontrol (kecuali \\n dan \\t) dan pengendali arah dibuang LEBIH DULU
    (supaya tak bisa menyisip di tengah jalur untuk lolos), lalu SATU lintasan `re.sub`:
      * `roots` = pasangan (jalur absolut, label), mis. (".../builds/3/7/src", "<proyek>"): akar dikenal diganti labelnya dan SISA jalur dipertahankan
        (`<proyek>/res/values/strings.xml` tetap berguna bagi AI);
      * jalur absolut lain (/data, /tmp, /opt, ...) -> `<path>`;
      * jalur relatif berawalan nama volume (`work/12/apktool/x`) -> `<path>`. Jalur proyek relatif (`res/...`, `smali/...`) sengaja dipertahankan."""
    clean = "".join(ch for ch in ("" if text is None else str(text))
                    if ch in "\n\t" or (ch not in _BIDI_CHARS and ch.isprintable()))
    pattern = _scrub_re(tuple((str(r), str(label)) for r, label in roots))

    def repl(m: "re.Match[str]") -> str:
        if m.group("keep") is not None:
            return m.group("keep")
        if m.groupdict().get("root") is not None:
            label = next(label for r, label in roots if str(r) == m.group("root"))
            return label + m.group("rest")
        return "<path>"

    return pattern.sub(repl, clean)
