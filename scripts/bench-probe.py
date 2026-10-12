#!/usr/bin/env python3
"""Uji kemampuan isolasi untuk kontainer `bench` (docs/prd/09, "Isolasi antar analisis").

Menjawab dua pertanyaan, DI DALAM kontainer berpengaturan sama dengan `bench`:
  1. Landlock: bisakah sebuah proses mengunci dirinya hanya ke satu folder?   (opsi 2)
  2. User namespace: bisakah proses membuat namespace tanpa hak?              (opsi 3, dipakai bwrap)

Aman dijalankan: hanya membuat folder sementara di /tmp, membaca berkas buatan sendiri, dan keluar. Tidak menyentuh data aplikasi,
tidak memakai jaringan. Dijalankan lewat `scripts/bench-probe.sh` (kontainer) atau langsung `python3 scripts/bench-probe.py`.
Kode keluar 0 = Landlock berfungsi penuh. Hanya memakai pustaka standar (jalan di Python 3.9+).
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import struct
import sys
import tempfile

# Nomor syscall Landlock sama di x86_64 dan arm64 (kernel >= 5.13).
SYS_CREATE, SYS_ADD, SYS_RESTRICT = 444, 445, 446
CREATE_VERSION = 1 << 0
RULE_PATH_BENEATH = 1
# Hak berkas yang ditangani (ABI 1); semua yang tidak diberi aturan menjadi DITOLAK.
FS_EXECUTE, FS_WRITE_FILE, FS_READ_FILE, FS_READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
FS_REMOVE_DIR, FS_REMOVE_FILE, FS_MAKE_CHAR, FS_MAKE_DIR = 1 << 4, 1 << 5, 1 << 6, 1 << 7
FS_MAKE_REG, FS_MAKE_SOCK, FS_MAKE_FIFO, FS_MAKE_BLOCK, FS_MAKE_SYM = 1 << 8, 1 << 9, 1 << 10, 1 << 11, 1 << 12
ALL_FS = (1 << 13) - 1
PR_SET_NO_NEW_PRIVS = 38
CLONE_NEWUSER = 0x10000000

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def sysc(num: int, *args: int) -> int:
    return libc.syscall(num, *[ctypes.c_long(a) for a in args])


def errname(code: int) -> str:
    return errno.errorcode.get(code, str(code))


def landlock_abi() -> tuple[int | None, str]:
    r = sysc(SYS_CREATE, 0, 0, CREATE_VERSION)
    if r >= 0:
        return r, "ok"
    e = ctypes.get_errno()
    return None, {errno.ENOSYS: "ENOSYS (syscall diblokir seccomp atau kernel tanpa Landlock)",
                  errno.EOPNOTSUPP: "EOPNOTSUPP (Landlock tidak aktif di kernel)"}.get(e, errname(e))


def child_confined(allowed: str) -> int:
    """Dipanggil di proses anak: kunci ke `allowed` (baca+tulis) saja, lalu coba keluar. Kembali 0 bila terkunci benar."""
    attr = struct.pack("<Q", ALL_FS)                     # handled_access_fs
    attr_buf = ctypes.create_string_buffer(attr, len(attr))   # variabel, bukan sementara: buffer harus hidup sampai syscall selesai
    fd = sysc(SYS_CREATE, ctypes.addressof(attr_buf), len(attr), 0)
    if fd < 0:
        return 100 + min(ctypes.get_errno(), 99)          # 1xx = errno dari pembuatan ruleset
    dirfd = os.open(allowed, os.O_PATH | os.O_DIRECTORY)
    rule = struct.pack("<Qi", FS_READ_FILE | FS_READ_DIR | FS_WRITE_FILE | FS_MAKE_REG | FS_REMOVE_FILE, dirfd)
    rule_buf = ctypes.create_string_buffer(rule, len(rule))
    if sysc(SYS_ADD, fd, RULE_PATH_BENEATH, ctypes.addressof(rule_buf), 0) != 0:
        return 200 + min(ctypes.get_errno(), 99)          # 2xx = errno dari penambahan aturan
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        return 12
    if sysc(SYS_RESTRICT, fd, 0) != 0:
        return 13
    inside = os.path.join(allowed, "boleh.txt")
    with open(inside) as fh:                               # 1) berkas di dalam folder yang diizinkan: HARUS bisa
        if fh.read() != "ok":
            return 20
    try:                                                   # 2) berkas di luar folder: HARUS ditolak
        open(os.path.join(os.path.dirname(allowed), "rahasia.txt")).read()
        return 21
    except PermissionError:
        pass
    try:                                                   # 3) menulis di luar folder: HARUS ditolak
        open(os.path.join(os.path.dirname(allowed), "tulis.txt"), "w").write("x")
        return 22
    except PermissionError:
        pass
    try:                                                   # 4) daftar folder di luar: HARUS ditolak
        os.listdir(os.path.dirname(allowed))
        return 23
    except PermissionError:
        pass
    return 0


def probe_landlock() -> bool:
    abi, why = landlock_abi()
    if abi is None:
        print(f"  [GAGAL] Landlock tidak tersedia: {why}")
        return False
    print(f"  [OK   ] syscall Landlock tersedia, ABI v{abi}")
    with tempfile.TemporaryDirectory(prefix="bench-probe-") as root:
        allowed = os.path.join(root, "ws")
        os.mkdir(allowed)
        open(os.path.join(allowed, "boleh.txt"), "w").write("ok")
        open(os.path.join(root, "rahasia.txt"), "w").write("rahasia")
        pid = os.fork()
        if pid == 0:
            try:
                os._exit(child_confined(allowed))
            except BaseException:
                os._exit(99)
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (status >> 8)
    meaning = {0: "terkunci benar: berkas di dalam terbaca, di luar ditolak (baca, tulis, daftar folder)",
               12: "gagal prctl(NO_NEW_PRIVS)", 13: "gagal restrict_self",
               20: "berkas di dalam folder yang diizinkan tidak terbaca", 21: "BOCOR: berkas di luar folder masih terbaca",
               22: "BOCOR: menulis di luar folder berhasil", 23: "BOCOR: daftar folder di luar masih terbaca", 99: "galat tak terduga"}
    ok = code == 0
    if code not in meaning and 100 <= code < 300:
        step = "membuat ruleset" if code < 200 else "menambah aturan"
        meaning[code] = f"gagal {step}: {errname(code % 100)}"
    print(f"  [{'OK   ' if ok else 'GAGAL'}] pengurungan ke satu folder: {meaning.get(code, f'kode {code}')}")
    return ok


def probe_userns() -> bool:
    pid = os.fork()
    if pid == 0:
        r = libc.unshare(CLONE_NEWUSER)
        os._exit(0 if r == 0 else (ctypes.get_errno() or 1))
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (status >> 8)
    if code == 0:
        print("  [OK   ] user namespace tanpa hak bisa dibuat (bwrap kemungkinan jalan)")
        return True
    print(f"  [GAGAL] user namespace diblokir: {errname(code)} (bwrap tidak bisa dipakai di kontainer ini)")
    return False


def main() -> int:
    print(f"Uji isolasi bench | kernel {platform.release()} {platform.machine()} | uid={os.getuid()} | python {platform.python_version()}")
    print("\n[1] Landlock (opsi 2)")
    ll = probe_landlock()
    print("\n[2] User namespace tanpa hak (opsi 3, bwrap)")
    un = probe_userns()
    print("\nKESIMPULAN:")
    if ll:
        print("  Opsi 2 (Landlock) BISA dipakai di kontainer ini. Opsi 1 (salin per sesi + uid terpisah) tidak diperlukan.")
    elif un:
        print("  Landlock tidak jalan, tetapi bwrap (opsi 3) mungkin. Opsi 1 tetap cadangan.")
    else:
        print("  Landlock dan bwrap tidak jalan di sini. Gunakan opsi 1 (salin per sesi + uid terpisah).")
    return 0 if ll else 1


if __name__ == "__main__":
    sys.exit(main())
