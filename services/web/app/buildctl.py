"""CLI pemilik untuk pipeline build (Tahap 2b): `docker compose exec -T web python -m app.buildctl <perintah>`.

Perintah: analyze, init, shell, diff, request, approve, status, wait, cancel, artifact-info, delete. Persetujuan build HANYA terjadi di sini (`approve`, tercatat `via=cli`
di audit) dan di `store.approve_build` yang terikat hash diff; tidak ada rute web dan tidak ada tool AI untuk menyetujui, menandatangani, atau mengunduh.

Format keluaran (untuk skrip bash tanpa JSON): HANYA baris `kunci=nilai` (kunci `[a-z_0-9.]+`, nilai satu baris, karakter cetak, <= 500; kontrol dan pengendali arah tulisan diganti
spasi) dan blok teks bebas berawalan `o| ` (stdout shell), `e| ` (stderr shell), `l| ` (log). Penanda blok tidak mungkin berupa `kunci=`, jadi nama berkas buatan AI tidak bisa
memalsukan baris seperti `persetujuan=...`. Kode keluar: 0 harapan terpenuhi; 3 harapan TIDAK terpenuhi atau galat operasional (selalu `kode=<stabil>`); 64 salah pakai
(pesan ke stderr). Pengecualian tak terduga -> `kode=internal galat=<NamaGalat>`, kode 3, tanpa traceback di stdout.

`shell` memanggil `shellspool.run_command` LANGSUNG: CLI ini tidak mengimpor `ai.tools` dan tidak membaca `AI_SHELL_ENABLED`. Catatan jujur (A-14): modul `ai.tools` TETAP terimpor secara
transitif (lewat `routes_apk`/`app.context`, karena CLI hanya berjalan di kontainer web berenv lengkap) dan itu DITERIMA; jaminannya bukan "tidak terimpor" melainkan perilaku:
tes mem-patch `ai.tools.shell_run` agar melempar lalu menjalankan semua perintah dengan AI_SHELL_ENABLED=0 -> tidak pernah terpicu.

Impor privat dari `routes_apk` (`_store_upload`, `_limits`, `_delete`, `_reject_audit`, `_mark_enqueue_failed`) dijaga tes: nama/parameter berubah = tes gagal.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import sys
import time
import uuid
import zipfile
from contextlib import closing
from pathlib import Path
from typing import Any, BinaryIO, Callable, Sequence

import redis

from rvcore import shellspool, store
from rvcore.paths import MAX_PROTO_ID

from . import builds, jobs

log = logging.getLogger("reverse-apk.buildctl")

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 3, 64
CHUNK = 1024 * 1024                  # stdin dibaca per blok 1 MiB (tidak pernah memuat seluruh APK ke memori)
POLL = 1.0                           # jeda polling bawaan (Deps.poll); tes memperkecil lewat Deps
VALUE_MAX = 500
BLOCK_LINES_MAX = 400
KEY_RE = re.compile(r"[a-z_0-9.]+")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
TIMEOUT_DEFAULTS = {"analyze": 900, "wait": 1800, "shell": 60}
APPROVAL_LABEL = "pemilik-lewat-CLI"
_BIDI = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


# ---------------------------------------------------------------------------------------------------- keluaran
def clean_value(value: Any) -> str:
    """Satu baris teks aman: bool -> 1/0, None -> '', karakter tak-cetak/kontrol/pengendali arah -> spasi, dipotong ke VALUE_MAX."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    text = "".join(" " if (ch in _BIDI or not ch.isprintable()) else ch for ch in str(value))
    return text.strip()[:VALUE_MAX]


def format_kv(key: str, value: Any) -> str:
    if not isinstance(key, str) or not KEY_RE.fullmatch(key):
        raise ValueError(f"kunci keluaran tidak valid: {key!r}")
    return f"{key}={clean_value(value)}"


def format_block(prefix: str, text: Any) -> list[str]:
    """Teks bebas bergaris banyak -> baris berawalan `o| `/`e| `/`l| ` (tidak mungkin `kunci=`), tiap baris dibersihkan."""
    lines = str(text or "").splitlines()
    out = [f"{prefix}| {clean_value(ln)}" for ln in lines[:BLOCK_LINES_MAX]]
    if len(lines) > BLOCK_LINES_MAX:
        out.append(f"{prefix}| ... ({len(lines) - BLOCK_LINES_MAX} baris lagi dipotong)")
    return out


def _emit(*lines: str) -> None:
    sys.stdout.write("".join(ln + "\n" for ln in lines))
    sys.stdout.flush()


def emit(**pairs: Any) -> None:
    _emit(*(format_kv(k, v) for k, v in pairs.items()))


def emit_block(prefix: str, text: Any) -> None:
    _emit(*format_block(prefix, text))


# ---------------------------------------------------------------------------------------------------- argumen
class _Usage(Exception):
    pass


class _Help(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    """argparse yang tidak pernah keluar sendiri: salah pakai -> _Usage (kode 64, pesan ke stderr), --help -> _Help (kode 0, teks ke stderr)."""

    def error(self, message: str) -> Any:
        raise _Usage(message)

    def exit(self, status: int = 0, message: str | None = None) -> Any:
        if status == 0:
            raise _Help()
        raise _Usage(message or "")

    def _print_message(self, message: str, file: Any = None) -> None:       # keluaran stdout dijaga hanya kunci=nilai
        if message:
            sys.stderr.write(message)


def _id(text: str) -> int:
    if not (text.isascii() and text.isdigit()) or not 1 <= int(text) <= MAX_PROTO_ID:
        raise argparse.ArgumentTypeError(f"id harus bilangan bulat 1..{MAX_PROTO_ID}")
    return int(text)


def _sha(text: str) -> str:
    if not HEX64_RE.fullmatch(text):
        raise argparse.ArgumentTypeError("harus 64 karakter heksadesimal huruf kecil")
    return text


def _timeout(text: str) -> int:
    if not (text.isascii() and text.isdigit()) or not 1 <= int(text) <= 86400:
        raise argparse.ArgumentTypeError("timeout harus bilangan bulat 1..86400 (detik)")
    return int(text)


def _command(text: str) -> str:
    if not text.strip() or "\x00" in text or len(text) > shellspool.MAX_COMMAND_CHARS:
        raise argparse.ArgumentTypeError(f"perintah tidak boleh kosong, tanpa NUL, maksimum {shellspool.MAX_COMMAND_CHARS} karakter")
    return text


def _parser() -> _Parser:
    p = _Parser(prog="python -m app.buildctl", description="CLI pemilik pipeline build APK (tanpa AI, tanpa UI).")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="perintah")

    a = sub.add_parser("analyze", help="unggah APK (`-` = stdin) dan jalankan analisis")
    a.add_argument("source", help="`-` (stdin) atau path berkas APK di dalam kontainer")
    a.add_argument("--timeout", type=_timeout, default=TIMEOUT_DEFAULTS["analyze"], help="batas tunggu analisis (detik)")
    a.add_argument("--uniq", action="store_true", help="tambah satu entri ZIP acak agar sha256 unik tiap run (tidak dedup)")
    a.add_argument("--no-wait", dest="no_wait", action="store_true", help="jangan menunggu analisis selesai")
    a.add_argument("--name", default="", help="nama tampilan (bawaan cli-<sha8>.apk)")

    i = sub.add_parser("init", help="salin baseline apktool ke bench/<id>/project")
    i.add_argument("analysis_id", type=_id)
    i.add_argument("--force", action="store_true", help="reset project dari baseline (ditolak bila ada build aktif)")

    s = sub.add_parser("shell", help="jalankan satu perintah di ruang kerja bench (kurungan Landlock yang sama dengan tool AI)")
    s.add_argument("analysis_id", type=_id)
    s.add_argument("command", type=_command)
    s.add_argument("--timeout", type=_timeout, default=TIMEOUT_DEFAULTS["shell"])

    d = sub.add_parser("diff", help="diff kanonik project terhadap baseline")
    d.add_argument("analysis_id", type=_id)

    r = sub.add_parser("request", help="ajukan build dari diff saat ini (menunggu persetujuan)")
    r.add_argument("analysis_id", type=_id)
    r.add_argument("--note", default="")

    ap = sub.add_parser("approve", help="setujui build (terikat hash diff)")
    ap.add_argument("build_id", type=_id)
    ap.add_argument("--diff-sha256", dest="diff_sha256", type=_sha, required=True)
    ap.add_argument("--hold", action="store_true", help="setujui + queued TANPA mengantre ke worker (penahan uji)")

    st = sub.add_parser("status", help="keadaan satu build, atau ringkasan satu analisis (--analysis)")
    st.add_argument("build_id", type=_id, nargs="?")
    st.add_argument("--analysis", dest="analysis", type=_id)

    w = sub.add_parser("wait", help="tunggu build mencapai status final")
    w.add_argument("build_id", type=_id)
    w.add_argument("--timeout", type=_timeout, default=TIMEOUT_DEFAULTS["wait"])
    w.add_argument("--trace", action="store_true", help="cetak tiap perubahan status (trace.N=status@detik)")

    c = sub.add_parser("cancel", help="batalkan build")
    c.add_argument("build_id", type=_id)

    ai = sub.add_parser("artifact-info", help="hash ulang artefak di disk dan cocokkan dengan DB")
    ai.add_argument("build_id", type=_id)

    de = sub.add_parser("delete", help="hapus APK beserta semua analisis, builds/, dan bench/ (ditolak selama ada build aktif)")
    de.add_argument("analysis_id", type=_id)
    return p


# ---------------------------------------------------------------------------------------------------- konteks aplikasi (lambat: app.context membaca env saat diimpor)
def _default_deps() -> builds.Deps:
    from . import context
    return builds.Deps(layout=context.layout, db=context.db, redis=context.redis_conn, bench_spool=shellspool.make_spool(context.layout.root / "benchspool"), poll=POLL)


def max_upload_bytes() -> int:
    from . import context
    return context.settings.max_upload_bytes


def _analysis_job_timeout() -> int:
    from . import context
    return context.settings.job_timeout


# ---------------------------------------------------------------------------------------------------- perintah
def _fail(exc: builds.BuildsError) -> int:
    emit(kode=exc.kode, alasan=exc.pesan)
    for key, value in exc.extra.items():
        emit(**{key: value})
    return EXIT_FAIL


def _append_unique(path: Path, limit: int) -> tuple[str, str, int]:
    """Tambah entri ZIP acak `assets/uniq-<hex>.txt` ke berkas (zipfile mode `a`, di disk) lalu hitung ulang sha256/md5/ukuran."""
    with zipfile.ZipFile(path, "a") as zf:
        zf.writestr(f"assets/uniq-{uuid.uuid4().hex}.txt", b"reverse-apk verify-build\n")
    return _hash_file(path, limit)


def _hash_file(path: Path, limit: int) -> tuple[str, str, int]:
    sha, md5, size = hashlib.sha256(), hashlib.md5(usedforsecurity=False), 0
    with path.open("rb") as fh:
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            size += len(block)
            if size > limit:
                raise builds.BuildsError("terlalu_besar", f"Berkas melebihi batas {limit // (1024 * 1024)} MB.")
            sha.update(block)
            md5.update(block)
    return sha.hexdigest(), md5.hexdigest(), size


def _receive(source: BinaryIO, part: Path, limit: int) -> tuple[str, str, int]:
    """Alirkan `source` ke `part` per blok CHUNK sambil menghitung sha256/md5/ukuran; berhenti begitu melebihi batas (sisa aliran tidak dibaca)."""
    sha, md5, size = hashlib.sha256(), hashlib.md5(usedforsecurity=False), 0
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        while True:
            block = source.read(CHUNK)
            if not block:
                break
            size += len(block)
            if size > limit:
                raise builds.BuildsError("terlalu_besar", f"Berkas melebihi batas {limit // (1024 * 1024)} MB.")
            sha.update(block)
            md5.update(block)
            fh.write(block)
    return sha.hexdigest(), md5.hexdigest(), size


def cmd_analyze(d: builds.Deps, args: argparse.Namespace, stdin: BinaryIO | None) -> int:
    from . import routes_apk
    from .apkcheck import ApkRejected, validate_apk
    from .uploads import Received, clean_display_name

    started = time.monotonic()
    limit = max_upload_bytes()
    part = d.layout.uploads_tmp / f"{uuid.uuid4().hex}.part"
    d.layout.uploads_tmp.mkdir(parents=True, exist_ok=True)
    opened = None
    try:
        if args.source == "-":
            source = stdin if stdin is not None else sys.stdin.buffer
        else:
            opened = source = open(args.source, "rb")
        try:
            sha256, md5, size = _receive(source, part, limit)
        finally:
            if opened is not None:
                opened.close()
        if args.uniq:
            sha256, md5, size = _append_unique(part, limit)
        name = clean_display_name(args.name) if args.name else ""
        name = name or f"cli-{sha256[:8]}.apk"
        try:
            info = validate_apk(part, routes_apk._limits())
        except ApkRejected as exc:
            routes_apk._reject_audit(exc.code, name, "cli", sha256)
            raise builds.BuildsError(exc.code, exc.message) from None
        options: dict[str, Any] = {"deobf": False}
        if info.bundle is not None:
            options["bundle"] = info.bundle.to_options()               # A-08: supaya `request` menolak paket (paket_belum_didukung)
        result = routes_apk._store_upload(Received(path=part, sha256=sha256, md5=md5, size=size), name, options, "cli")
    finally:
        part.unlink(missing_ok=True)
    analysis_id = result["analysis_id"]
    emit(duplicate=result["duplicate"], apk_id=result["apk_id"], analysis_id=analysis_id, sha256=result["sha256"])
    if result["duplicate"]:
        emit(status=result.get("status") or "", elapsed=f"{time.monotonic() - started:.1f}")
        return EXIT_OK
    try:
        jobs.enqueue_analysis(d.redis, analysis_id, _analysis_job_timeout())
    except redis.RedisError as exc:
        log.warning("gagal mengantrekan analisis %s: %s", analysis_id, type(exc).__name__)
        routes_apk._mark_enqueue_failed(analysis_id)
        emit(status=store.FAILED)
        raise builds.BuildsError("antrean_mati", "APK tersimpan, tetapi antrean (Redis) tidak tersedia; analisis ditandai gagal.") from None
    if args.no_wait:
        emit(status=store.QUEUED, elapsed=f"{time.monotonic() - started:.1f}")
        return EXIT_OK
    while True:
        with closing(d.db()) as conn:
            row = store.get_analysis(conn, analysis_id)
        status = row["status"] if row is not None else "hilang"
        elapsed = time.monotonic() - started
        if status in store.TERMINAL or row is None:
            break
        if elapsed >= args.timeout:
            emit(status=status, elapsed=f"{elapsed:.1f}")
            raise builds.BuildsError("waktu_habis", f"Analisis #{analysis_id} belum selesai dalam {args.timeout} detik (status: {status}).")
        time.sleep(d.poll)
    emit(status=status, elapsed=f"{elapsed:.1f}")
    if status != store.DONE:
        raise builds.BuildsError("analisis_gagal", (row["error"] if row is not None else "") or f"Analisis berakhir dengan status {status}.")
    return EXIT_OK


def cmd_init(d: builds.Deps, args: argparse.Namespace, stdin: BinaryIO | None) -> int:
    res = builds.init_workspace(d, args.analysis_id, force=args.force)
    emit(created=res["created"], reason=res["reason"], files=res["files"], dirs=res["dirs"], bytes=res["bytes"], skipped_symlink=res["skipped"]["symlink"],
         skipped_special=res["skipped"]["special"], skipped_root_ignored=res["skipped"]["root_ignored"])
    if res["message"]:
        emit(pesan=res["message"])
    return EXIT_OK


def cmd_shell(d: builds.Deps, args: argparse.Namespace, stdin: BinaryIO | None) -> int:
    res = builds.run_shell(d, args.analysis_id, args.command, args.timeout)
    emit(status=res["status"], exit_code="" if res["exit_code"] is None else res["exit_code"], duration_ms=res["duration_ms"], truncated=res["truncated"])
    if res["signal"]:
        emit(signal=res["signal"])
    if res["message"]:
        emit(pesan=res["message"])
    emit_block("o", res["stdout"])
    emit_block("e", res["stderr"])
    return EXIT_OK if res["status"] == shellspool.STATUS_OK and res["exit_code"] == 0 else EXIT_FAIL


def _emit_diff(res: dict[str, Any]) -> None:
    c, b, ln, sk = res["counts"], res["bytes"], res["lines"], res["skipped"]
    emit(diff_sha256=res["diff_sha256"], added=c["added"], modified=c["modified"], removed=c["removed"], entries_total=res["entries_total"], bytes_added=b["added"],
         bytes_modified=b["modified"], bytes_removed=b["removed"], lines_plus=ln["plus"], lines_minus=ln["minus"], skipped_symlink=sk["symlink"],
         skipped_special=sk["special"], skipped_root_ignored=sk["root_ignored"], skipped_vanished=sk["vanished"], truncated=res["truncated"])
    if res["peringatan"]:
        emit(peringatan=res["peringatan"])
    emit(jejak_sistem=res["jejak_sistem"])
    for n, item in enumerate(res["top"], 1):
        delta = f" +{item['plus']} -{item['minus']}" if item["plus"] is not None and item["minus"] is not None else ""
        emit(**{f"file.{n}": f"{item['op']} {item['path']}{delta}"})


def cmd_diff(d: builds.Deps, args: argparse.Namespace, stdin: BinaryIO | None) -> int:
    _emit_diff(builds.workspace_diff(d, args.analysis_id))
    return EXIT_OK


def cmd_request(d: builds.Deps, args: argparse.Namespace, stdin: BinaryIO | None) -> int:
    res = builds.request_build(d, args.analysis_id, "user", args.note)
    c = res["counts"]
    emit(build_id=res["build_id"], diff_sha256=res["diff_sha256"], status=res["status"], added=c["added"], modified=c["modified"], removed=c["removed"])
    if res["peringatan"]:
        emit(peringatan=res["peringatan"])
    emit(jejak_sistem=res["jejak_sistem"])
    return EXIT_OK


def cmd_approve(d: builds.Deps, args: argparse.Namespace, stdin: BinaryIO | None) -> int:
    res = builds.approve_build(d, args.build_id, args.diff_sha256, hold=args.hold, via="cli")
    emit(build_id=res["build_id"], status=res["status"], enqueued=res["enqueued"], hold=res["hold"], persetujuan=APPROVAL_LABEL,
         pernyataan_versi=res["pernyataan_versi"], pernyataan_sha256=res["pernyataan_sha256"])
    if not args.hold and not res["enqueued"]:
        emit(kode="antrean_mati", galat=res["galat"] or "build tidak terkirim ke antrean")
        return EXIT_FAIL
    return EXIT_OK


STATUS_KEYS = ("build_id", "analysis_id", "status", "alasan", "diff_sha256", "error_code", "error_text", "cancel_requested", "output_name", "output_size", "output_sha256",
               "cert_sha256", "verify_ok", "approved_at", "started_at", "signing_mulai", "finished_at", "waktu_antre", "waktu_build", "waktu_tanda_tangan")


def cmd_status(d: builds.Deps, args: argparse.Namespace, stdin: BinaryIO | None) -> int:
    if (args.build_id is None) == (args.analysis is None):
        raise _Usage("beri tepat salah satu: <build_id> atau --analysis <analysis_id>")
    if args.analysis is not None:
        res = builds.get_status(d, analysis_id=args.analysis)
        emit(analysis_id=res["analysis_id"], builds=",".join(f"{b['build_id']}:{b['status']}" for b in res["builds"]),
             build_dirs=",".join(str(i) for i in res["build_dirs"]), build_dirs_n=len(res["build_dirs"]))
        return EXIT_OK
    res = builds.get_status(d, build_id=args.build_id)
    emit(**{k: (f"{res[k]:.3f}" if isinstance(res[k], float) else res[k]) for k in STATUS_KEYS})
    emit_block("l", res["stage_log"])
    return EXIT_OK


def cmd_wait(d: builds.Deps, args: argparse.Namespace, stdin: BinaryIO | None) -> int:
    counter = [0]

    def on_change(status: str, elapsed: float) -> None:
        if args.trace:
            counter[0] += 1
            emit(**{f"trace.{counter[0]}": f"{status}@{elapsed:.1f}"})
    res = builds.wait_build(d, args.build_id, args.timeout, on_change)
    emit(status=res["status"], elapsed=res["elapsed"])
    if res["status"] != store.B_DONE:
        emit(error_code=res["error_code"], error_text=res["error_text"], kode="tidak_selesai")
        return EXIT_FAIL
    return EXIT_OK


def cmd_cancel(d: builds.Deps, args: argparse.Namespace, stdin: BinaryIO | None) -> int:
    res = builds.cancel_build(d, args.build_id)
    emit(build_id=res["build_id"], hasil=res["hasil"])
    return EXIT_OK


def cmd_artifact_info(d: builds.Deps, args: argparse.Namespace, stdin: BinaryIO | None) -> int:
    res = builds.artifact_info(d, args.build_id)
    emit(build_id=res["build_id"], output_name=res["output_name"], output_size=res["output_size"], output_sha256=res["output_sha256"], cert_sha256=res["cert_sha256"],
         disk_sha256=res["disk_sha256"], cocok=res["cocok"])
    return EXIT_OK


def cmd_delete(d: builds.Deps, args: argparse.Namespace, stdin: BinaryIO | None) -> int:
    from . import routes_apk
    with closing(d.db()) as conn:
        row = conn.execute("SELECT apk_id FROM analysis WHERE id = ?", (args.analysis_id,)).fetchone()
    if row is None:
        raise builds.BuildsError("analisis_tidak_ada", f"Analisis #{args.analysis_id} tidak ditemukan.")
    result = routes_apk._delete(row["apk_id"], "cli")
    left = {"builds_ada": d.layout.builds / str(args.analysis_id), "bench_ada": d.layout.bench / str(args.analysis_id), "work_ada": d.layout.work_dir(args.analysis_id)}
    emit(hasil=result, **{k: os.path.lexists(p) for k, p in left.items()})
    if result == "busy":
        raise builds.BuildsError("busy", "Ada build/analisis aktif; batalkan dan tunggu selesai dulu (NB-2).")
    if result != "deleted":
        raise builds.BuildsError("analisis_tidak_ada", "Analisis tidak ditemukan.")
    if any(os.path.lexists(p) for p in left.values()):
        raise builds.BuildsError("sisa_direktori", "Sebagian direktori masih ada setelah dihapus (yatim); bersihkan lewat kontainer web.")
    return EXIT_OK


COMMANDS: dict[str, Callable[[builds.Deps, argparse.Namespace, Any], int]] = {
    "analyze": cmd_analyze, "init": cmd_init, "shell": cmd_shell, "diff": cmd_diff, "request": cmd_request, "approve": cmd_approve, "status": cmd_status,
    "wait": cmd_wait, "cancel": cmd_cancel, "artifact-info": cmd_artifact_info, "delete": cmd_delete,
}


def main(argv: Sequence[str] | None = None, *, deps: builds.Deps | None = None, stdin: BinaryIO | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except _Help:
        return EXIT_OK
    except _Usage as exc:
        sys.stderr.write(f"buildctl: {exc}\n")
        return EXIT_USAGE
    try:
        if args.cmd == "analyze" and args.source != "-":
            path = Path(args.source)
            if not path.is_file() or not os.access(path, os.R_OK):
                raise _Usage(f"{args.source}: bukan berkas biasa yang dapat dibaca")
        return COMMANDS[args.cmd](deps or _default_deps(), args, stdin)
    except _Usage as exc:
        sys.stderr.write(f"buildctl: {exc}\n")
        return EXIT_USAGE
    except builds.BuildsError as exc:
        return _fail(exc)
    except Exception as exc:  # noqa: BLE001 - CLI tidak boleh menumpahkan traceback ke stdout; jenis galat saja yang dicetak
        log.exception("galat tak terduga di buildctl %s", args.cmd)
        emit(kode="internal", galat=type(exc).__name__)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
