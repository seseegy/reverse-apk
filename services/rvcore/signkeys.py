"""Pustaka kunci penandatangan (Tahap 2a): membaca berkas kunci dan masukan tak tepercaya dengan aman, dan menilai keadaan keystore pemilik.

Dipakai bersama oleh `signer-daemon`, `signer-selftest`, `rvcore.signspool` dan `worker/signcheck.py`. Hanya stdlib; tidak pernah mencetak atau
menyimpan isi kata sandi (hanya bentuknya yang diperiksa).

Satu konstanta, `OPEN_FLAGS`, dipakai untuk SEMUA pembukaan berkas tak tepercaya (request, hasil, detak jantung, kunci, masukan APK):
  * O_NOFOLLOW  - symlink ditolak (mis. requests/x.json -> /dev/zero);
  * O_NONBLOCK  - membuka FIFO tidak menggantung selamanya (open() tanpa flag ini memblokir sampai ada penulis);
  * O_CLOEXEC   - fd tidak bocor ke alat yang dijalankan.
Setelah dibuka, `fstat` HARUS memastikan berkas biasa SEBELUM membaca; jangan pernah memakai Path.read_text/open() pada masukan tak tepercaya.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import time
from typing import Any, Callable, NamedTuple

# Harus sama dengan KS_ALIAS di scripts/keystore.sh (dijaga tes).
ALIAS = "reverse-apk"
OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
MAX_P12_BYTES = 1024 * 1024
MAX_PASS_BYTES = 256
DER_MIN_BYTES = 200
DER_MAX_BYTES = 4096
KEYTOOL_TIMEOUT = 30.0
DETAIL_MAX = 300

MISSING_TEXT = ("/run/secrets tidak berisi kunci. Jika secrets/signing_keystore.p12 sudah ada di host, jalankan lewat 'make up' "
                "(memuat docker-compose.keystore.yml); jika belum, 'make keystore' lalu 'make up'.")
STALE_TEXT = ("berkas kunci di kontainer sudah tidak sama dengan berkas di host (diganti setelah kontainer dimulai). "
              "Jalankan: make restart")


class KeyStatus(NamedTuple):
    state: str          # ok | missing | unreadable | invalid | stale
    detail: str


class ToolResult(NamedTuple):
    """Hasil `run` yang disuntik ke owner_fingerprint: kode keluar (None bila tidak selesai), stdout (biner), stderr (teks)."""
    rc: int | None
    out: bytes
    err: str


def read_small(path: Any, limit: int, *, dir_fd: int | None = None, open_fn: Callable[..., int] | None = None) -> bytes | None:
    """Baca berkas biasa <= `limit` byte dengan aman; None bila bukan berkas biasa, terlalu besar, atau galat apa pun. Tidak pernah menggantung.

    Tidak pernah membaca lebih dari limit+1 byte. `dir_fd` untuk membuka relatif terhadap direktori yang sudah dipegang."""
    opener = open_fn or os.open               # dicari saat dipanggil (bukan saat definisi) agar penukar os.open di tes terlihat
    try:
        fd = opener(path, OPEN_FLAGS) if dir_fd is None else opener(path, OPEN_FLAGS, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        return _read_open_fd(fd, limit)
    except OSError:
        return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _read_open_fd(fd: int, limit: int, fstat_fn: Callable[[int], os.stat_result] = os.fstat) -> bytes | None:
    st = fstat_fn(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
        return None
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    return None if len(data) > limit else data


def _password_ok(data: bytes) -> bool:
    """Bentuk sandi: 1-256 byte setelah \\r\\n akhir dibuang; tanpa NUL/kontrol (alat hanya membaca BARIS pertama)."""
    pw = data.rstrip(b"\r\n")
    if not 1 <= len(pw) <= MAX_PASS_BYTES:
        return False
    return not any(b < 0x20 or b == 0x7F for b in pw)


def read_password_line(path: Any, *, open_fn: Callable[..., int] | None = None) -> bool:
    """True bila berkas sandi berbentuk benar. HANYA validasi bentuk: nilai sandi tidak dikembalikan dan tidak disimpan."""
    data = read_small(path, MAX_PASS_BYTES + 2, open_fn=open_fn)
    return data is not None and _password_ok(data)


def describe_unreadable(path: Any, euid: int, st: Any) -> str:
    """Pesan diagnosis 'terbaca di host tetapi tidak oleh proses ini'. `st` = hasil stat berkas (atau None bila tak bisa di-stat)."""
    if st is None:
        text = (f"{path} tidak bisa dibaca proses uid {euid} (izin tidak bisa dibaca). Kontainer signer berjalan sebagai uid {euid}. "
                "Di host jalankan: make keystore-access")
    else:
        mode = stat.S_IMODE(st.st_mode)
        text = (f"{path}: mode {mode:o} milik uid {st.st_uid} (gid {st.st_gid}). Kontainer signer berjalan sebagai uid {euid} dan TIDAK bisa "
                "membacanya. Di host jalankan: make keystore-access")
    return text[:DETAIL_MAX]


def inspect_key_file(path: Any, *, kind: str, open_fn: Callable[..., int] | None = None, fstat_fn: Callable[[int], os.stat_result] | None = None,
                     stat_fn: Callable[..., os.stat_result] | None = None, euid: int | None = None) -> KeyStatus:
    """Nilai satu berkas kunci (`kind` = 'p12' atau 'pass'). TIDAK PERNAH melempar; tidak pernah menggantung (FIFO/symlink ditolak)."""
    me = os.geteuid() if euid is None else euid
    opener = open_fn or os.open
    do_fstat = fstat_fn or os.fstat
    do_stat = stat_fn or os.stat
    try:
        try:
            fd = opener(path, OPEN_FLAGS)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EPERM):
                try:
                    st = do_stat(path)
                except OSError:
                    st = None
                return KeyStatus("unreadable", describe_unreadable(path, me, st))
            if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                return KeyStatus("missing", MISSING_TEXT)
            if exc.errno == errno.ELOOP:
                return KeyStatus("invalid", f"{path} adalah symlink; kunci harus berkas biasa.")
            return KeyStatus("unreadable", f"{path} tidak bisa dibuka ({errno.errorcode.get(exc.errno or 0, 'galat')}).")
        try:
            st = do_fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return KeyStatus("invalid", f"{path} bukan berkas biasa.")
            if st.st_nlink == 0:
                return KeyStatus("stale", STALE_TEXT)
            if kind == "pass":
                if st.st_size < 1 or st.st_size > MAX_PASS_BYTES + 2:
                    return KeyStatus("invalid", f"{path}: ukuran kata sandi harus 1-{MAX_PASS_BYTES} byte.")
                data = _read_open_fd(fd, MAX_PASS_BYTES + 2, do_fstat)
                if data is None or not _password_ok(data):
                    return KeyStatus("invalid", f"{path}: bentuk kata sandi tidak valid (kosong, terlalu panjang, atau berisi karakter kontrol).")
            else:
                if st.st_size < 1 or st.st_size > MAX_P12_BYTES:
                    return KeyStatus("invalid", f"{path}: ukuran keystore di luar batas (1 B - {MAX_P12_BYTES // 1024 // 1024} MiB).")
            return KeyStatus("ok", "")
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
    except Exception as exc:  # noqa: BLE001 - kontrak: tidak pernah melempar
        return KeyStatus("unreadable", f"{path} tidak bisa diperiksa ({type(exc).__name__}).")


def owner_fingerprint(p12: Any, passfile: Any, run: Callable[..., Any], *, home: str = "/tmp/home/_key",
                      timeout: float = KEYTOOL_TIMEOUT) -> tuple[str, str]:
    """SHA-256 (heks kecil 64) sertifikat pemilik di keystore, lewat `keytool -exportcert`. Mengembalikan (state, nilai):
      ('ok', hex64) | ('invalid', detail) | ('transient', detail)  - 'transient' = tenggat/EIO/dihentikan: JANGAN di-cache sebagai invalid.
    `run(argv, *, deadline, home, stderr)` disuntik: daemon memberi run_tool-nya, selftest memberi adaptor subprocess. `deadline` = waktu
    time.monotonic() absolut; hasilnya `ToolResult` (atau yang punya atribut rc/out). Kata sandi hanya lewat -storepass:file (tidak di argv)."""
    argv = ["keytool", "-exportcert", "-alias", ALIAS, "-keystore", str(p12), "-storetype", "PKCS12",
            "-storepass:file", str(passfile), "-J-Xmx128m", f"-J-Duser.home={home}"]
    try:
        res = run(argv, deadline=time.monotonic() + timeout, home=home, stderr="separate")
    except (TimeoutError, InterruptedError, OSError) as exc:
        return "transient", f"keytool tidak selesai ({type(exc).__name__})."
    rc = getattr(res, "rc", None)
    if rc is None:
        return "transient", "keytool tidak selesai (tenggat atau dihentikan)."
    if rc != 0:
        return "invalid", f"keytool gagal (kode {rc}): sandi salah, alias '{ALIAS}' tidak ada, atau keystore rusak."
    der = getattr(res, "out", b"")
    if not isinstance(der, (bytes, bytearray)) or not (DER_MIN_BYTES <= len(der) <= DER_MAX_BYTES) or der[:1] != b"\x30":
        return "invalid", "keluaran keytool bukan sertifikat DER yang masuk akal."
    return "ok", hashlib.sha256(bytes(der)).hexdigest()
