"""Pengurungan Landlock untuk perintah yang disusun AI (PRD 09, Bagian C; keputusan isolasi: opsi 2, hasil `scripts/bench-probe.sh` di VPS pemilik).

Landlock membatasi proses ANAK ke daftar folder/berkas yang eksplisit; semua yang lain ditolak (baca, tulis, daftar folder, buat, hapus, ganti nama,
tautan keras). Tidak butuh kapabilitas tambahan. Aturan berlaku atas inode hasil resolusi, jadi symlink ke luar tidak membantu.

GAGAL TERTUTUP. Bila Landlock tidak tersedia atau pengurungan tidak bisa dipasang, `Confinement` melempar LandlockError dan pemanggil WAJIB tidak
menjalankan perintah. Tidak ada jalur "lanjut tanpa pengurungan".

Hak yang ditangani (di-deny kecuali diberi aturan): semua hak berkas ABI 1, REFER (ABI 2: tautan keras/rename lintas folder), TRUNCATE (ABI 3),
dan, bila ABI >= 4, TCP bind/connect tanpa aturan apa pun (kontainer ada di jaringan internal tanpa rute keluar; ini lapis kedua, dan memungkinkan satu port saja: proxy). Yang tidak bisa dibatasi Landlock
pada ABI < 6: sinyal/ptrace antar proses sepemilik (ditutup dengan PR_SET_DUMPABLE=0 pada daemon) dan socket UNIX abstrak.
"""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import struct
from dataclasses import dataclass

SYS_CREATE, SYS_ADD, SYS_RESTRICT = 444, 445, 446      # sama di x86_64 dan arm64
CREATE_VERSION = 1 << 0
RULE_PATH_BENEATH = 1
RULE_NET_PORT = 2
PR_SET_NO_NEW_PRIVS = 38
PR_SET_DUMPABLE = 4

EXECUTE, WRITE_FILE, READ_FILE, READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
REMOVE_DIR, REMOVE_FILE, MAKE_CHAR, MAKE_DIR = 1 << 4, 1 << 5, 1 << 6, 1 << 7
MAKE_REG, MAKE_SOCK, MAKE_FIFO, MAKE_BLOCK, MAKE_SYM = 1 << 8, 1 << 9, 1 << 10, 1 << 11, 1 << 12
REFER, TRUNCATE = 1 << 13, 1 << 14
NET_BIND_TCP, NET_CONNECT_TCP = 1 << 0, 1 << 1

FS_V1 = (1 << 13) - 1
FS_BY_ABI = {1: FS_V1, 2: FS_V1 | REFER, 3: FS_V1 | REFER | TRUNCATE}     # ABI >= 3 memakai nilai terakhir; hak lebih baru sengaja tidak ditangani
FILE_RIGHTS = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE                  # hak yang sah untuk aturan pada BERKAS (bukan folder)

RO = EXECUTE | READ_FILE | READ_DIR                                       # baca + jalankan
RW = FS_V1 | REFER | TRUNCATE                                             # penuh (dipotong ke yang ditangani)
DEV = READ_FILE | WRITE_FILE | TRUNCATE                                   # /dev/null dll.

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


class LandlockError(Exception):
    """Pengurungan tidak tersedia / gagal dipasang. Perintah TIDAK boleh dijalankan."""


def _sys(num: int, *args: int) -> int:
    return _libc.syscall(num, *[ctypes.c_long(a) for a in args])


def abi_version() -> int:
    """Versi ABI Landlock kernel (>= 1), atau 0 bila tidak tersedia (kernel lama, nonaktif, atau syscall diblokir seccomp)."""
    r = _sys(SYS_CREATE, 0, 0, CREATE_VERSION)
    return r if r >= 1 else 0


def handled_fs(abi: int) -> int:
    return FS_BY_ABI[min(abi, 3)] if abi >= 1 else 0


@dataclass(frozen=True)
class Rule:
    path: str
    rights: int
    optional: bool = False        # path tidak ada -> dilewati (mis. /lib64 di image tertentu); False -> LandlockError


class Confinement:
    """Dibangun di PROSES INDUK (membuka fd), dipasang di ANAK lewat `apply()` (dipanggil dari preexec_fn), lalu `close()` di induk."""

    def __init__(self, rules: list[Rule], connect_ports: tuple[int, ...] = ()) -> None:
        """`connect_ports`: port TCP tujuan `connect()` yang DIIZINKAN (mis. port proxy). Semua TCP lain ditolak. Hanya berlaku pada ABI >= 4; pada ABI lebih
        rendah kernel tidak bisa membatasi TCP, dan `net_enforced` bernilai False agar pemanggil tahu pembatasan ini TIDAK ada (jangan berpura-pura)."""
        self.abi = abi_version()
        if self.abi < 1:
            raise LandlockError("Landlock tidak tersedia di kernel/kontainer ini")
        self.handled = handled_fs(self.abi)
        net = (NET_BIND_TCP | NET_CONNECT_TCP) if self.abi >= 4 else 0
        attr = struct.pack("<QQ", self.handled, net) if self.abi >= 4 else struct.pack("<Q", self.handled)
        buf = ctypes.create_string_buffer(attr, len(attr))       # variabel: harus hidup sampai syscall selesai
        fd = _sys(SYS_CREATE, ctypes.addressof(buf), len(attr), 0)
        if fd < 0:
            raise LandlockError(f"membuat ruleset gagal: {errno.errorcode.get(ctypes.get_errno(), ctypes.get_errno())}")
        self.fd = fd
        self.net_enforced = self.abi >= 4
        try:
            for r in rules:
                self._add(r)
            if self.net_enforced:
                for port in connect_ports:
                    self._add_port(port)
        except BaseException:
            self.close()
            raise

    def _add_port(self, port: int) -> None:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise LandlockError(f"port tidak valid: {port!r}")
        buf = ctypes.create_string_buffer(struct.pack("<QQ", NET_CONNECT_TCP, port), 16)
        if _sys(SYS_ADD, self.fd, RULE_NET_PORT, ctypes.addressof(buf), 0) != 0:
            raise LandlockError(f"menambah aturan port {port} gagal: {errno.errorcode.get(ctypes.get_errno(), ctypes.get_errno())}")

    def _add(self, rule: Rule) -> None:
        try:
            pfd = os.open(rule.path, os.O_PATH | os.O_CLOEXEC)
        except FileNotFoundError:
            if rule.optional:
                return
            raise LandlockError(f"folder wajib tidak ada: {rule.path}") from None
        except OSError as exc:
            raise LandlockError(f"tidak bisa membuka {rule.path}: {exc.strerror}") from exc
        try:
            st = os.fstat(pfd)
            rights = rule.rights & self.handled
            if not stat.S_ISDIR(st.st_mode):
                rights &= FILE_RIGHTS                              # aturan pada berkas dengan hak folder -> EINVAL
            if not rights:
                return
            buf = ctypes.create_string_buffer(struct.pack("<Qi", rights, pfd), 12)
            if _sys(SYS_ADD, self.fd, RULE_PATH_BENEATH, ctypes.addressof(buf), 0) != 0:
                raise LandlockError(f"menambah aturan {rule.path} gagal: {errno.errorcode.get(ctypes.get_errno(), ctypes.get_errno())}")
        finally:
            os.close(pfd)

    def apply(self) -> None:
        """Pasang pengurungan pada proses INI (tidak bisa dicabut). Lempar LandlockError bila gagal -> pemanggil tidak boleh exec."""
        if _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise LandlockError("prctl(NO_NEW_PRIVS) gagal")
        if _sys(SYS_RESTRICT, self.fd, 0) != 0:
            raise LandlockError(f"restrict_self gagal: {errno.errorcode.get(ctypes.get_errno(), ctypes.get_errno())}")

    def close(self) -> None:
        if getattr(self, "fd", -1) >= 0:
            os.close(self.fd)
            self.fd = -1


def make_non_dumpable() -> bool:
    """Daemon tidak boleh bisa di-ptrace / dibaca lewat /proc oleh anaknya yang sepemilik (tanpa ini perintah AI bisa menyuntik kode ke daemon
    yang TIDAK dikurung dan keluar dari Landlock). Efektif untuk non-root; root punya CAP_SYS_PTRACE."""
    return _libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
