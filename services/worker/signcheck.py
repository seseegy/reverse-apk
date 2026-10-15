"""Alat bantu `make signer-verify`: satu-satunya pintu antara skrip bash dan `rvcore.signspool` / `Layout` (bash TIDAK pernah mem-parse JSON).

Dijalankan di kontainer worker: `python signcheck.py <subperintah> ...`. Bukan bagian produk (tidak dipanggil worker.py).

Kode keluar (seragam):
  0   perintah berjalan dan, bila ada `--expect-*`, harapan terpenuhi
  2   galat operasional (izin, IO, ruang, signer tidak tersedia): satu baris `GALAT: <teks>`
  3   hanya `sign` / `bad-request`: harapan TIDAK terpenuhi: baris `HASIL ...` lalu satu baris `ALASAN: <teks>`
  64  salah pakai, subperintah diagnostik tanpa SIGNCHECK_DIAG=1, atau id di luar sentinel (satu baris `GALAT: <teks>`)

Pengaman: SEMUA subperintah menolak analysis_id < 2147000000 (id analisis nyata autoincrement kecil, jadi tak mungkin menyentuh data nyata)
dan build_id di luar 1..7. Subperintah diagnostik (put-garbage, put-symlink, put-big, bad-request) hanya aktif bila env SIGNCHECK_DIAG=1.

Keluaran `kunci=nilai` atau satu baris `HASIL ok=1|0 code=<kode>|- cert=<hex64>|- sha=<hex64>|- size=<n> v1=1|0|- v2=1|0 v3=1|0 signers=<n>|- elapsed=<detik>`.
Kata sandi tidak pernah disentuh di sini; sertifikat/sha penuh (64 heks) bukan rahasia.

Semua akses ke `builds/<aid>/<bid>` memakai rantai-dirfd (`fsutil.open_dir_chain` + operasi relatif `dir_fd`; hapus lewat `rmtree_at`): runner kini bisa menulis akar
`builds`, jadi komponen perantara yang ditukar jadi symlink tidak boleh diikuti (A-03). `sign` mengirim `expect_sha256` = hash `unsigned.apk` yang dibaca dari folder
itu (atau `--expect-sha256`; berkas tak ada/bukan berkas biasa -> hash nol supaya signer sendiri yang menjawab input_missing/input_unsafe).
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import os
import re
import secrets
import stat
import sys
import time
import zipfile
from io import BytesIO
from typing import Any, Iterator

from rvcore.fsutil import open_dir_chain, rmtree_at
from rvcore.paths import Layout
from rvcore.signspool import (ERROR_CODES, JOB_ID_RE, SignerUnavailable, make_spool, new_job_id, read_result, signer_status,
                              submit_and_wait)

MIB = 1024 * 1024
SENTINEL_MIN_AID = 2147000000
MAX_AID = 2**31
BUILD_IDS = range(1, 8)
MAX_PUT_BYTES = 64 * MIB
MAX_BASE_BYTES = 16 * MIB          # APK dasar untuk put-big dibaca ke memori (stdin tidak bisa di-seek)
MAX_BIG_MB = 1100
MAX_ENTRIES = 70000                # batas entri APK ±65535; sedikit di atasnya untuk uji batas
CHUNK = MIB
DISK_MARGIN_MIB = 64
OWNER_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
EXPECT_RE = re.compile(r"[0-9a-f]{64}\Z")
DEFAULT_SIGN_TIMEOUT = 300
BAD_REQUEST_WAIT = 60.0
UNSIGNED = "unsigned.apk"
JAR_META = (
    ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n"),
    ("META-INF/CERT.SF", b"Signature-Version: 1.0\r\n\r\n"),
    ("META-INF/CERT.RSA", b"\x30\x00"),
)


class Usage(Exception):
    """Salah pakai -> kode 64."""


class Operational(Exception):
    """Galat operasional -> kode 2."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # argparse bawaan keluar dengan kode 2, yang di sini berarti galat operasional
        raise Usage(message)


def _parser() -> argparse.ArgumentParser:
    p = _Parser(prog="signcheck.py", add_help=False)
    sub = p.add_subparsers(dest="cmd", parser_class=_Parser)

    def ids(sp: argparse.ArgumentParser, with_bid: bool = True, bid_optional: bool = False) -> None:
        sp.add_argument("aid")
        if with_bid:
            sp.add_argument("bid", nargs="?" if bid_optional else None)

    sub.add_parser("status")
    ids(sub.add_parser("put"))
    sp = sub.add_parser("sign")
    ids(sp)
    sp.add_argument("--timeout", type=int, default=DEFAULT_SIGN_TIMEOUT)
    sp.add_argument("--expect-ok", action="store_true")
    sp.add_argument("--owner-sha256")
    sp.add_argument("--expect-error")
    sp.add_argument("--expect-sha256")
    ids(sub.add_parser("ls"))
    sub.add_parser("df")
    ids(sub.add_parser("clean"), bid_optional=True)
    ids(sub.add_parser("put-garbage"))
    ids(sub.add_parser("put-symlink"))
    sp = sub.add_parser("put-big")
    ids(sp)
    sp.add_argument("--size-mb", type=int, required=True)
    sp.add_argument("--entries", type=int, required=True)
    sp.add_argument("--jar-meta", action="store_true")
    sp = sub.add_parser("bad-request")
    ids(sp)
    sp.add_argument("--kind", required=True)
    sp.add_argument("--expect-error")
    return p


DIAG_COMMANDS = ("put-garbage", "put-symlink", "put-big", "bad-request")


def parse_ids(aid: str, bid: str | None) -> tuple[int, int | None]:
    """analysis_id sentinel (>= 2147000000) dan build_id 1..7; selain itu Usage (kode 64)."""
    if not (aid.isascii() and aid.isdigit()) or not SENTINEL_MIN_AID <= int(aid) < MAX_AID:
        raise Usage(f"analysis_id harus bilangan bulat sentinel {SENTINEL_MIN_AID}..{MAX_AID - 1} (id analisis nyata ditolak)")
    build: int | None = None
    if bid is not None:
        if not (bid.isascii() and bid.isdigit()) or int(bid) not in BUILD_IDS:
            raise Usage(f"build_id harus bilangan bulat {BUILD_IDS.start}..{BUILD_IDS.stop - 1}")
        build = int(bid)
    return int(aid), build


def _line(text: object) -> str:
    """Satu baris aman dicetak: karakter kontrol dibuang."""
    return "".join(ch if ch.isprintable() else " " for ch in str(text)).strip()


def hasil_line(res: dict[str, Any]) -> str:
    v = res["verify"]
    v1 = "-" if v.get("v1") is None else int(bool(v["v1"]))
    signers = "-" if res.get("signer_count") is None else res["signer_count"]
    return (f"HASIL ok={int(bool(res['ok']))} code={res.get('error_code') or '-'} cert={res.get('cert_sha256') or '-'} "
            f"sha={res.get('output_sha256') or '-'} size={res.get('output_size', 0)} v1={v1} v2={int(bool(v['v2']))} v3={int(bool(v['v3']))} "
            f"signers={signers} elapsed={res.get('elapsed', 0.0):.1f}")


ZERO_SHA = "0" * 64
OPEN_RD = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


@contextlib.contextmanager
def build_fd(layout: Layout, aid: int, bid: int, *, create: bool) -> Iterator[int]:
    """fd folder `builds/<aid>/<bid>` lewat rantai nofollow (A-03). Symlink/bukan direktori di komponen mana pun -> Operational (sasaran tak disentuh)."""
    try:
        fd = open_dir_chain(layout.builds, str(aid), str(bid), create=create)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise Operational(f"builds/{aid}/{bid} bukan direktori biasa (symlink atau jenis lain); ditolak") from exc
        raise Operational(f"folder build tidak bisa dibuka: {exc.strerror or exc}") from exc
    try:
        yield fd
    finally:
        os.close(fd)


class Tmp:
    """Berkas `.put-*.tmp` di folder build (relatif `bfd`); dihapus bila tidak diterbitkan (galat atau KeyboardInterrupt)."""

    def __init__(self, bfd: int) -> None:
        self.bfd = bfd
        self.name = f".put-{secrets.token_hex(6)}.tmp"
        self.published = False

    def __enter__(self) -> "Tmp":
        return self

    def publish(self, dest: str) -> None:
        os.replace(self.name, dest, src_dir_fd=self.bfd, dst_dir_fd=self.bfd)
        self.published = True

    def size(self) -> int:
        return os.stat(self.name, dir_fd=self.bfd, follow_symlinks=False).st_size

    def __exit__(self, *exc: object) -> None:
        if not self.published:
            try:
                os.unlink(self.name, dir_fd=self.bfd)
            except OSError:
                pass


def _open_tmp(tmp: Tmp) -> int:
    try:
        return os.open(tmp.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=tmp.bfd)
    except OSError as exc:
        raise Operational(f"tidak bisa menulis berkas sementara: {exc.strerror or exc}") from exc


def unsigned_sha256(layout: Layout, aid: int, bid: int) -> str:
    """sha256 `unsigned.apk` dibaca lewat rantai nofollow; tak ada / bukan berkas biasa / tak terbaca -> hash nol (signer yang menjawab input_missing/input_unsafe)."""
    try:
        with build_fd(layout, aid, bid, create=False) as bfd:
            fd = os.open(UNSIGNED, OPEN_RD, dir_fd=bfd)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    return ZERO_SHA
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(fd, CHUNK)
                    if not chunk:
                        return digest.hexdigest()
                    digest.update(chunk)
            finally:
                os.close(fd)
    except (OSError, Operational):
        return ZERO_SHA


def cmd_put(layout: Layout, aid: int, bid: int, stdin: Any) -> None:
    digest, total = hashlib.sha256(), 0
    with build_fd(layout, aid, bid, create=True) as bfd, Tmp(bfd) as tmp:
        fd = _open_tmp(tmp)
        try:
            with os.fdopen(fd, "wb") as out:
                while True:
                    chunk = stdin.read(CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_PUT_BYTES:
                        raise Operational(f"masukan melebihi {MAX_PUT_BYTES // MIB} MiB")
                    digest.update(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
        except OSError as exc:
            raise Operational(f"gagal menulis unsigned.apk: {exc.strerror or exc}") from exc
        try:
            tmp.publish(UNSIGNED)
        except OSError as exc:
            raise Operational(f"gagal menerbitkan unsigned.apk: {exc.strerror or exc}") from exc
    print(f"ditulis={total}")
    print(f"sha256={digest.hexdigest()}")


def cmd_put_garbage(layout: Layout, aid: int, bid: int) -> None:
    data = b"bukan zip\n"
    with build_fd(layout, aid, bid, create=True) as bfd, Tmp(bfd) as tmp:
        fd = _open_tmp(tmp)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        try:
            tmp.publish(UNSIGNED)
        except OSError as exc:
            raise Operational(f"gagal menerbitkan unsigned.apk: {exc.strerror or exc}") from exc
    print(f"ditulis={len(data)}")


def cmd_put_symlink(layout: Layout, aid: int, bid: int) -> None:
    with build_fd(layout, aid, bid, create=True) as bfd:
        try:
            try:
                os.unlink(UNSIGNED, dir_fd=bfd)
            except FileNotFoundError:
                pass
            os.symlink("/etc/hostname", UNSIGNED, dir_fd=bfd)
        except OSError as exc:
            raise Operational(f"gagal membuat symlink: {exc.strerror or exc}") from exc
    print("dibuat=symlink")


def free_mib(path: Any) -> int:
    try:
        st = os.statvfs(path)
    except OSError as exc:
        raise Operational(f"tidak bisa membaca ruang disk: {exc.strerror or exc}") from exc
    return st.f_bavail * st.f_frsize // MIB


def _copy_entry(zin: zipfile.ZipFile, zi: zipfile.ZipInfo, zout: zipfile.ZipFile) -> None:
    new = zipfile.ZipInfo(zi.filename, zi.date_time)
    new.compress_type, new.file_size, new.external_attr = zi.compress_type, zi.file_size, zi.external_attr
    with zin.open(zi) as src, zout.open(new, "w") as dst:
        while True:
            chunk = src.read(CHUNK)
            if not chunk:
                break
            dst.write(chunk)


def build_big_zip(dest: Any, base: Any, size_mb: int, entries: int, jar_meta: bool) -> int:
    """Tulis APK besar STREAMING ke `dest`: salin entri `base`, tambah `entries` entri assets/f%06d.bin (STORED) bertotal `size_mb` MiB dari os.urandom
    dalam potongan <= 1 MiB (tidak pernah satu blob), dan bila `jar_meta` tiga entri META-INF kecil (menyalakan v1). Mengembalikan jumlah entri."""
    total = size_mb * MIB
    per, rem = divmod(total, entries)
    with zipfile.ZipFile(base) as zin, zipfile.ZipFile(dest, "w", zipfile.ZIP_STORED) as zout:
        for zi in zin.infolist():
            if zi.is_dir():
                continue
            _copy_entry(zin, zi, zout)
        for i in range(entries):
            size = per + (rem if i == 0 else 0)
            zi = zipfile.ZipInfo("assets/f%06d.bin" % i, (2024, 1, 1, 0, 0, 0))
            zi.compress_type, zi.file_size = zipfile.ZIP_STORED, size
            with zout.open(zi, "w") as out:
                left = size
                while left > 0:
                    step = min(left, CHUNK)
                    out.write(os.urandom(step))
                    left -= step
        if jar_meta:
            for name, content in JAR_META:
                zout.writestr(zipfile.ZipInfo(name, (2024, 1, 1, 0, 0, 0)), content, compress_type=zipfile.ZIP_STORED)
        return len(zout.infolist())


def cmd_put_big(layout: Layout, aid: int, bid: int, args: argparse.Namespace, stdin: Any) -> None:
    if not 1 <= args.size_mb <= MAX_BIG_MB:
        raise Usage(f"--size-mb harus 1..{MAX_BIG_MB}")
    if not 1 <= args.entries <= MAX_ENTRIES:
        raise Usage(f"--entries harus 1..{MAX_ENTRIES}")
    base = stdin.read(MAX_BASE_BYTES + 1)
    if not base or len(base) > MAX_BASE_BYTES:
        raise Operational(f"APK dasar dari stdin harus 1 B..{MAX_BASE_BYTES // MIB} MiB")
    with build_fd(layout, aid, bid, create=True) as bfd:
        bebas = free_mib(bfd)
        if bebas < args.size_mb + DISK_MARGIN_MIB:
            raise Operational(f"ruang disk tidak cukup: butuh {args.size_mb + DISK_MARGIN_MIB} MiB, bebas {bebas} MiB")
        try:
            with Tmp(bfd) as tmp:
                fd = _open_tmp(tmp)
                try:
                    with os.fdopen(fd, "wb") as out:
                        count = build_big_zip(out, BytesIO(base), args.size_mb, args.entries, args.jar_meta)
                        out.flush()
                        os.fsync(out.fileno())
                except (OSError, zipfile.BadZipFile) as exc:
                    raise Operational(f"gagal membuat APK besar: {getattr(exc, 'strerror', None) or exc}") from exc
                written = tmp.size()
                try:
                    tmp.publish(UNSIGNED)
                except OSError as exc:
                    raise Operational(f"gagal menerbitkan unsigned.apk: {exc.strerror or exc}") from exc
        except KeyboardInterrupt:
            raise Operational("dihentikan; berkas sementara dihapus") from None
    print(f"ditulis={written}")
    print(f"entri={count}")


def cmd_status(layout: Layout) -> None:
    st = signer_status(make_spool(layout.signspool))
    ks = st["keystore"]
    print(f"hidup={int(st['hidup'])}")
    print(f"umur_hb={'-' if st['umur'] is None else format(st['umur'], '.1f')}")
    print(f"keystore={ks['state'] or '-'}")
    print(f"cert_sha256={ks['cert_sha256'] or '-'}")
    print(f"detail={_line(ks['detail'])}")


def cmd_ls(layout: Layout, aid: int, bid: int) -> None:
    try:
        with build_fd(layout, aid, bid, create=False) as bfd:
            names = sorted(os.listdir(bfd))
    except (OSError, Operational):
        names = []
    for name in names:
        print(_line(name))


def cmd_df(layout: Layout) -> None:
    print(f"bebas_mib={free_mib(layout.builds)}")


def _unlink_or_rmtree(folder: Any, name: str) -> bool:
    """Hapus satu entri spool (berkas atau direktori yang menyamar) tanpa mengikuti symlink. True bila ada yang dihapus."""
    try:
        dfd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        if not os.path.lexists(os.path.join(folder, name)):
            return False
        rmtree_at(dfd, name)
    except OSError:
        return False
    finally:
        os.close(dfd)
    return True


def cmd_clean(layout: Layout, aid: int, bid: int | None) -> None:
    """Hapus folder build sentinel (aid atau aid/bid) dan sisa berkas job sentinel di signspool. Hanya id sentinel yang sampai ke sini.
    Semua lewat rantai-dirfd: `builds/<aid>` yang ternyata symlink TIDAK diikuti (`clean AID` hanya meng-unlink symlinknya; `clean AID BID` menolak dengan GALAT)."""
    removed = False
    try:
        if bid is not None:
            try:
                afd = open_dir_chain(layout.builds, str(aid))
            except FileNotFoundError:
                afd = -1
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise Operational(f"builds/{aid} bukan direktori biasa (symlink atau jenis lain); ditolak, sasarannya tidak disentuh") from exc
                raise
            if afd >= 0:
                try:
                    present = os.path.lexists(os.path.join(layout.builds, str(aid), str(bid)))
                    rmtree_at(afd, str(bid))
                    removed = present
                finally:
                    os.close(afd)
        else:
            rfd = open_dir_chain(layout.builds)
            try:
                present = os.path.lexists(os.path.join(layout.builds, str(aid)))
                rmtree_at(rfd, str(aid))
                removed = present
            finally:
                os.close(rfd)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise Operational(f"gagal menghapus build {aid}: {exc.strerror or exc}") from exc
    spool = make_spool(layout.signspool)
    for folder, suffix in ((spool.requests, ".json"), (spool.running, ".json"), (spool.results, ".json"), (spool.cancel, "")):
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for name in names:
            stem = name[:-len(suffix)] if suffix and name.endswith(suffix) else name
            m = JOB_ID_RE.match(stem)
            if m is None or int(m.group(1)) != aid or (bid is not None and int(m.group(2)) != bid):
                continue
            removed = _unlink_or_rmtree(folder, name) or removed
    print(f"dibersihkan={int(removed)}")


def _verdict(res: dict[str, Any], expect_ok: bool, owner: str | None, expect_error: str | None) -> str | None:
    """None bila harapan terpenuhi, selain itu alasan (satu baris Indonesia)."""
    if expect_ok:
        if not res["ok"]:
            return f"diharapkan sukses tetapi job gagal ({res.get('error_code') or 'tanpa kode'}): {_line(res.get('error_text'))}"
        if res.get("signer_count") != 1 or not (res["verify"]["v2"] and res["verify"]["v3"]):
            return "hasil sukses tetapi tidak tepat satu penanda tangan dengan v2 dan v3"
        if not res.get("output_size", 0) > 0:
            return "hasil sukses tetapi ukuran signed.apk nol"
        if res.get("cert_sha256") != (owner or "").lower():
            return "sertifikat penanda tangan BUKAN sertifikat pemilik (sidik jari berbeda)"
        return None
    if expect_error:
        if res["ok"]:
            return f"diharapkan gagal dengan kode {expect_error} tetapi job berhasil"
        if res.get("error_code") != expect_error:
            return f"diharapkan kode {expect_error} tetapi kode hasil {res.get('error_code') or '-'}"
    return None


def _report(res: dict[str, Any], expect_ok: bool, owner: str | None, expect_error: str | None) -> int:
    print(hasil_line(res))
    reason = _verdict(res, expect_ok, owner, expect_error)
    if reason is not None:
        print(f"ALASAN: {reason}")
        return 3
    return 0


def cmd_sign(layout: Layout, aid: int, bid: int, args: argparse.Namespace) -> int:
    if args.expect_ok and args.expect_error:
        raise Usage("--expect-ok dan --expect-error tidak boleh bersamaan")
    owner = args.owner_sha256
    if args.expect_ok and (owner is None or not OWNER_RE.match(owner)):
        raise Usage("--expect-ok butuh --owner-sha256 berisi 64 karakter heks")
    if args.expect_error and args.expect_error not in ERROR_CODES:
        raise Usage("--expect-error harus salah satu kode galat signer")
    expect = args.expect_sha256
    if expect is not None and not EXPECT_RE.match(expect):
        raise Usage("--expect-sha256 harus 64 karakter heks huruf kecil")
    if expect is None:
        expect = unsigned_sha256(layout, aid, bid)
    try:
        res = submit_and_wait(make_spool(layout.signspool), aid, bid, timeout=args.timeout, expect_sha256=expect)
    except SignerUnavailable as exc:
        raise Operational(_line(exc.message)) from exc
    return _report(res, args.expect_ok, owner, args.expect_error)


def cmd_bad_request(layout: Layout, aid: int, bid: int, args: argparse.Namespace) -> int:
    if args.kind != "traversal":
        raise Usage("--kind yang dikenal hanya: traversal")
    if args.expect_error and args.expect_error not in ERROR_CODES:
        raise Usage("--expect-error harus salah satu kode galat signer")
    spool = make_spool(layout.signspool)
    if not signer_status(spool)["hidup"]:
        raise Operational("signer tidak aktif; request mentah tidak akan dijawab")
    job_id = new_job_id(aid, bid)
    # Nama berkas id sah; ISI memakai analysis_id traversal dan bidang path yang TIDAK boleh dipercaya signer.
    spool.submit({"job_id": job_id, "op": "sign", "analysis_id": "../etc", "build_id": bid, "timeout": 30, "path": "/etc/passwd",
                  "input": "/etc/passwd", "created": time.time()})
    try:
        end = time.monotonic() + BAD_REQUEST_WAIT
        res = read_result(spool, job_id)
        while res is None and time.monotonic() < end:
            time.sleep(0.1)
            res = read_result(spool, job_id)
        if res is None:
            spool.withdraw(job_id)
            raise Operational("signer tidak menjawab request mentah dalam batas waktu")
    finally:
        spool.forget(job_id)
    return _report(res, False, None, args.expect_error)


def main(argv: list[str] | None = None, *, layout: Layout | None = None, stdin: Any = None) -> int:
    args_list = sys.argv[1:] if argv is None else argv
    try:
        try:
            args = _parser().parse_args(args_list)
            if not args.cmd:
                raise Usage("subperintah wajib: status put sign ls df clean (+ diagnostik: put-garbage put-symlink put-big bad-request)")
            if args.cmd in DIAG_COMMANDS and os.environ.get("SIGNCHECK_DIAG") != "1":
                raise Usage(f"subperintah diagnostik '{args.cmd}' hanya aktif dengan SIGNCHECK_DIAG=1")
            lay = layout or Layout(os.environ.get("DATA_DIR", "/data"))
            inp = stdin if stdin is not None else sys.stdin.buffer
            if args.cmd == "status":
                cmd_status(lay)
                return 0
            if args.cmd == "df":
                cmd_df(lay)
                return 0
            aid, bid = parse_ids(args.aid, args.bid)
            if args.cmd == "clean":
                cmd_clean(lay, aid, bid)
            elif bid is None:
                raise Usage("build_id wajib")
            elif args.cmd == "put":
                cmd_put(lay, aid, bid, inp)
            elif args.cmd == "ls":
                cmd_ls(lay, aid, bid)
            elif args.cmd == "put-garbage":
                cmd_put_garbage(lay, aid, bid)
            elif args.cmd == "put-symlink":
                cmd_put_symlink(lay, aid, bid)
            elif args.cmd == "put-big":
                cmd_put_big(lay, aid, bid, args, inp)
            elif args.cmd == "sign":
                return cmd_sign(lay, aid, bid, args)
            elif args.cmd == "bad-request":
                return cmd_bad_request(lay, aid, bid, args)
            return 0
        except Usage as exc:
            print(f"GALAT: {_line(exc)}")
            return 64
        except Operational as exc:
            print(f"GALAT: {_line(exc)}")
            return 2
        except OSError as exc:
            print(f"GALAT: {_line(exc.strerror or exc)}")
            return 2
    except KeyboardInterrupt:
        print("GALAT: dihentikan")
        return 2


if __name__ == "__main__":
    sys.exit(main())
