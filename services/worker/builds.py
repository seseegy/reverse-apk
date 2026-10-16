"""Worker: tugas `run_build` (Tahap 2b, FEAT D) — claim -> runner -> signer -> verifikasi -> nama artefak buatan sistem -> finish_build -> prune -> pemulihan.

Worker mengorkestrasi dua kontainer yang memproses masukan tak tepercaya (runner: pohon proyek; signer: APK hasil build) lewat spool berkas; ia TIDAK mempercayai
satu pun hasil mereka. Urutan (desain §2.1/§8; tiap langkah punya tes di tests/test_worker_builds.py):

  0 status harus `queued` (selain itu dilewati)        5 mark_signing (CAS; menulis `signing_mulai=<epoch>` ke stage_log, A-04)
  1 pra-cek signer: hidup dan keystore ok (gagal CEPAT)   6 tanda tangan (submit_and_wait + utas pemantau pembatalan DB)
  2 klaim CAS queued -> building                        7 verifikasi hasil signer (`_check_sign_result`)
  3 siapkan folder lewat rantai-dirfd                   8 penamaan: rantai dibuka ULANG, hash ulang dari fd, os.rename (A-17)
  4 build di runner (tunggu, detak, tenggat, batal)     9 finish_build  10 bersih (src/, unsigned.apk, .sign-*) + prune BUILD_KEEP

Folder `builds/<aid>/<bid>` ditulis runner (uid sama, bisa dikompromikan): SEMUA akses worker ke `builds/` memakai `fsutil.open_dir_chain` (tiap komponen O_NOFOLLOW) dan
operasi relatif fd (`rmtree_at`, `os.rename(src_dir_fd=, dst_dir_fd=)`, `os.unlink(dir_fd=)`); tidak ada `Path.mkdir`/`safe_rmtree`/`shutil.rmtree` pada `builds` (dijaga tes AST).
Komponen yang ditanam symlink tidak pernah diikuti: pembersihan gagal-tertutup, sasaran symlink utuh.
Sisa risiko jujur: runner terkompromi masih bisa mengubah isi `signed.apk` SESUDAH terbit; unduhan Tahap 5 wajib salin-lalu-hash.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import logging
import math
import os
import re
import stat
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rvcore import buildproto, bundle, bundleout, installscript, signspool, store
from rvcore.db import connect
from rvcore.fsutil import open_dir_chain, rmtree_at
from rvcore.paths import MAX_PROTO_ID, Layout
from rvcore.signkeys import read_small
from rvcore.spool import Spool

log = logging.getLogger("reverse-apk.builds")

POLL_INTERVAL = 1.0
RUNNER_STALE_AFTER = 45.0              # detik tanpa detak jantung runner setelah job diambil = runner mati
GRACE = 60.0                           # runner seharusnya sudah berhenti pada timeout + GRACE; +GRACE lagi -> menyerah
JOB_TIMEOUT_MARGIN = 600               # job_timeout RQ = TIMEOUT_BUILD + TIMEOUT_SIGN + ini (APK tunggal; tidak berubah dari 2b)
BUNDLE_JOB_MARGIN = 3800               # paket: 600 + SIGN_PER_FILE_S x 199 + ASSEMBLE_TIMEOUT (1200) dibulatkan; WAJIB sama dengan web.app.builds (tes paritas)
ASSEMBLE_TIMEOUT = 1200                # tenggat perakitan paket akhir (ASUMSI: laju rekompresi belum diukur)
ASSEMBLE_RESERVE = 1024 * 1024 * 1024  # cadangan disk di atas ukuran upload saat merakit
BUNDLE_KINDS = ("xapk", "apks")
QUEUE_NAME = "jobs"                    # sama dengan worker.QUEUE_NAME (dijaga tes main)
RESULT_LIMIT = 64 * 1024               # signkeys.read_small MENOLAK (tidak memotong) hasil runner yang lebih besar
HEARTBEAT_LIMIT = 16 * 1024
UNSIGNED, SIGNED, SRC = "unsigned.apk", "signed.apk", "src"
SCRATCH = frozenset({SRC, UNSIGNED, SIGNED})
SIGN_TMP_PREFIX = ".sign-"
# Sisa sementara paket (Tahap 3): masukan/keluaran per split, berkas antara runner, dan tmp perakitan. Paket akhir/skrip (`*-modified-<id>*`) TIDAK cocok.
SCRATCH_RE = re.compile(r"(?:split|signed)-\d{3}\.apk(?:\.part)?\Z")
SCRATCH_PREFIXES = (SIGN_TMP_PREFIX, ".split-", ".alias-", ".bundle-", ".install-")
STAGE_TAIL = 1500
NAME_BASE_MAX = 80
HASH_BLOCK = 1024 * 1024
OPEN_ARTIFACT = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_NO_RESULT = object()

SIGN_TEXT = {
    "sign_cert_mismatch": "Sertifikat penanda tangan tidak sama dengan sertifikat keystore pemilik (atau tidak bisa dipastikan); hasil dibuang.",
    "sign_bad_result": "Hasil penandatanganan tidak koheren atau tidak memenuhi syarat (v2 dan v3, tepat satu penanda tangan); hasil dibuang.",
    "artifact_changed": "APK berubah di antara build, penandatanganan, dan penamaan (hash tidak sama atau berkas tidak aman); hasil dibuang.",
    "bundle_changed": "Paket unggahan atau rencana split berubah di antara build dan perakitan; hasil dibuang.",
    "assemble_failed": "Perakitan paket akhir gagal (berkas sementara, ruang disk, atau verifikasi); hasil dibuang.",
    "assemble_timeout": "Perakitan paket akhir melewati batas waktu; hasil dibuang.",
    "no_space": "Ruang disk tidak cukup untuk merakit paket akhir; hasil dibuang.",
}


def job_margin(source_kind: str) -> int:
    """Margin `job_timeout` RQ: paket (xapk/apks) memakai margin besar, APK tunggal tetap 600 (2b)."""
    return BUNDLE_JOB_MARGIN if source_kind in BUNDLE_KINDS else JOB_TIMEOUT_MARGIN


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(lo, min(hi, value))


@dataclass(frozen=True)
class BuildConfig:
    layout: Layout
    timeout_build: int
    timeout_sign: int
    pickup_timeout: int
    keep: int | None = None

    @classmethod
    def from_env(cls) -> "BuildConfig":
        return cls(
            layout=Layout(os.environ.get("DATA_DIR", "/data")),
            timeout_build=_env_int("TIMEOUT_BUILD", 1800, 10, 3600),
            timeout_sign=_env_int("TIMEOUT_SIGN", 900, 10, 3600),
            pickup_timeout=_env_int("RUNNER_PICKUP_TIMEOUT", 120, 1, 3600),
            keep=store.build_keep(),
        )

    @property
    def job_timeout(self) -> int:
        return self.job_timeout_for("apk")

    def job_timeout_for(self, source_kind: str) -> int:
        return self.timeout_build + self.timeout_sign + job_margin(source_kind)


class _Fail(Exception):
    """Build berakhir `failed`. `extra` = baris tambahan untuk stage_log."""

    def __init__(self, code: str, text: str, extra: str = "") -> None:
        super().__init__(text)
        self.code, self.text, self.extra = code, text, extra


class _Cancel(Exception):
    """Pembatalan pengguna menang."""


@dataclass
class _Run:
    conn: Any
    cfg: BuildConfig
    row: Any
    analysis: Any
    lines: list[str] = field(default_factory=list)      # stage_log yang sudah terkumpul (ringkasan build, signing_mulai)
    published: list[str] = field(default_factory=list)  # nama artefak yang sudah diterbitkan (SEMUA dihapus bila build tidak berakhir `done`)
    done: bool = False

    @property
    def aid(self) -> int:
        return self.row["analysis_id"]

    @property
    def bid(self) -> int:
        return self.row["id"]


# ====================================================================== titik masuk
def run_build(build_id: Any, cfg: BuildConfig | None = None) -> None:
    """Jalankan satu build yang berstatus `queued`. Tidak pernah melempar `Exception` ke RQ; `BaseException` (timeout RQ/SIGTERM) menandai build gagal lalu naik lagi."""
    if type(build_id) is not int or not 1 <= build_id <= MAX_PROTO_ID:
        log.warning("run_build: id tidak valid ditolak (%s)", type(build_id).__name__)
        return
    cfg = cfg or BuildConfig.from_env()
    conn = connect(cfg.layout.db_path)
    try:
        _run(conn, cfg, build_id)
    finally:
        conn.close()


def _run(conn: Any, cfg: BuildConfig, build_id: int) -> None:
    row = store.get_build(conn, build_id)
    if row is None:
        log.warning("build %s tidak ada di basis data; dilewati", build_id)
        return
    if row["status"] != store.B_QUEUED:
        log.info("build %s dilewati (status %s)", build_id, row["status"])
        return
    analysis = store.get_analysis(conn, row["analysis_id"])
    if analysis is None:
        log.warning("build %s: analisis %s tidak ada; dilewati", build_id, row["analysis_id"])
        return
    run = _Run(conn, cfg, row, analysis)

    problem = _signer_problem(cfg)
    if problem is not None:                                   # gagal cepat dari `queued`; tidak ada runner/folder yang terbuang
        _finish_fail(run, _Fail("signer_unavailable", problem))
        _prune(run)
        return
    if not store.claim_build(conn, build_id):
        log.info("build %s dilewati (kalah balapan klaim atau dibatalkan)", build_id)
        return
    started = time.monotonic()
    try:
        _build(run)
    except _Cancel:
        _finish_cancel(run)
    except _Fail as fail:
        _finish_fail(run, fail)
    except BaseException as exc:  # noqa: BLE001 - termasuk timeout RQ/SIGTERM: build tidak boleh menggantung di building/signing
        log.exception("galat tak terduga pada build %s", build_id)
        _finish_fail(run, _Fail("internal", f"Galat internal: {type(exc).__name__}"))
        if not isinstance(exc, Exception):
            raise
    else:
        log.info("build %s selesai dalam %.1fs", build_id, time.monotonic() - started)
    finally:
        _cleanup(run)
        _prune(run)


# ====================================================================== langkah
def _signer_problem(cfg: BuildConfig) -> str | None:
    status = signspool.signer_status(signspool.make_spool(cfg.layout.signspool))
    if not status["hidup"]:
        return "Signer tidak aktif, jadi tidak ada yang ditandatangani. Jalankan 'make up' (profil build)."
    ks = status["keystore"]
    if ks["state"] != "ok":
        return f"Keystore signer belum siap (status: {ks['state'] or 'tidak diketahui'}). {ks['detail']}".strip()
    return None


def _owner_cert(cfg: BuildConfig) -> str | None:
    """Sertifikat pemilik menurut signer SEKARANG (kunci diganti di tengah jalan = beda). None bila signer tidak hidup / keystore tidak ok."""
    status = signspool.signer_status(signspool.make_spool(cfg.layout.signspool))
    ks = status["keystore"]
    return ks["cert_sha256"] if status["hidup"] and ks["state"] == "ok" else None


def _build(run: _Run) -> None:
    cfg = run.cfg
    try:
        _prepare_dir(cfg.layout, run.aid, run.bid)
    except OSError as exc:
        log.warning("build %s: folder build tidak bisa disiapkan (%s)", run.bid, errno.errorcode.get(exc.errno or 0, "OSError"))
        raise _Fail("internal", "Folder build tidak aman atau tidak bisa disiapkan; build dibatalkan.") from None

    result = _run_runner(run)
    kind = run.row["source_kind"]
    if result["source_kind"] != kind:                           # runner melaporkan format lain dari yang diminta: tidak dipercaya
        raise _Fail("bundle_changed", SIGN_TEXT["bundle_changed"])
    run.lines.append(_summary(result))
    t_sign = store.now()
    run.lines.append(f"signing_mulai={t_sign:.6f}")
    try:
        store.mark_signing(run.conn, run.bid, stage_log="\n".join(run.lines))
    except store.BuildStateError:                              # pembatalan menang (CAS cancel_requested = 0), atau baris sudah final
        raise _Cancel() from None

    if kind != "apk":
        _precheck_bundle(run, result)                           # upload ditukar/rencana beda: gagal SEBELUM signer dipanggil
    signed = _sign(run, result)
    problem = _check_sign_result(signed, _owner_cert(cfg), result["output_sha256"], result["splits"])
    if problem is not None:
        raise _Fail(problem[0], problem[1])
    if kind == "apk":
        name, out_sha, out_size = _publish(run, signed), signed["output_sha256"], signed["output_size"]
        run.lines.append(f"tanda_tangan: {signed['elapsed']:.1f} dtk (v2 dan v3, 1 penanda tangan)")
    else:
        pub = _assemble_publish(run, result, signed)
        name, out_sha, out_size = pub["name"], pub["sha256"], pub["size"]
        run.lines.append(f"tanda_tangan: {signed['elapsed']:.1f} dtk ({1 + len(result['splits'])} berkas, v2 dan v3, 1 penanda tangan, satu sertifikat)")
        run.lines.extend(pub["lines"])
    try:
        store.finish_build(run.conn, run.bid, output_name=name, output_sha256=out_sha, output_size=out_size,
                           output_format=kind, cert_sha256=signed["cert_sha256"], verify_ok=1, stage_log="\n".join(run.lines))
    except store.BuildStateError:                              # pembatalan terlambat (atau baris sudah `failed` oleh pemulihan)
        raise _Cancel() from None
    run.done = True


def _prepare_dir(layout: Layout, aid: int, bid: int) -> None:
    """Pastikan `builds/<aid>/<bid>` direktori kosong yang NYATA. Komponen yang ditanam (symlink/berkas) dihapus pada induknya (symlink hanya di-unlink, sasaran
    tidak disentuh); sisa lama di `<bid>` dihapus. OSError naik: pemanggil menjadikannya `internal`."""
    try:
        afd = open_dir_chain(layout.builds, str(aid), create=True)
    except OSError as exc:
        if exc.errno not in (errno.ELOOP, errno.ENOTDIR):
            raise
        rfd = open_dir_chain(layout.builds)
        try:
            rmtree_at(rfd, str(aid))
        finally:
            os.close(rfd)
        afd = open_dir_chain(layout.builds, str(aid), create=True)
    try:
        rmtree_at(afd, str(bid))
    finally:
        os.close(afd)
    os.close(open_dir_chain(layout.builds, str(aid), str(bid), create=True))


# ------------------------------------------------------------------ runner
def _run_runner(run: _Run) -> dict[str, Any]:
    cfg = run.cfg
    spool = Spool(cfg.layout.spool)
    spool.ensure_dirs()
    try:
        job = buildproto.build_build_request(run.aid, run.bid, run.row["diff_sha256"], run.analysis["sha256"], cfg.timeout_build, run.row["source_kind"])
    except ValueError as exc:
        raise _Fail("internal", f"Permintaan ke runner tidak valid: {exc}") from None
    job_id = job["job_id"]
    spool.submit(job)
    try:
        raw = _wait_runner(run, spool, job_id)
    finally:
        spool.forget(job_id)
    result = buildproto.parse_build_result(raw)
    if result["ok"]:
        return result
    code = result["error_code"]
    text = buildproto.ERROR_TEXT[code]
    if code == "build_failed" and result["error_text"] and result["error_text"] != text:
        text = f"{text} {result['error_text']}"
    extra = f"build: {result['elapsed']:.1f} dtk, gagal ({code})"
    if result["apktool_log_tail"]:
        extra += "\n" + result["apktool_log_tail"][-STAGE_TAIL:]
    if code == "cancelled":
        _cancel_or_fail(run, code, text, extra)
    raise _Fail(code, text, extra)


def _cancel_or_fail(run: _Run, code: str, text: str, extra: str = "") -> None:
    """Pelaksana melapor `cancelled`: hanya sah bila pengguna memintanya (store menolak `cancel_build` tanpa permintaan); selain itu build gagal."""
    if store.is_build_cancel_requested(run.conn, run.bid):
        raise _Cancel()
    raise _Fail(code, text, extra)


def _read_json_small(path: Path, limit: int) -> Any:
    """`_NO_RESULT` bila berkas tidak ada; None bila ada tetapi rusak/besar/bukan berkas biasa/FIFO (tidak pernah menggantung); selain itu hasil parse."""
    if not os.path.lexists(path):
        return _NO_RESULT
    raw = read_small(path, limit)
    if raw is None:
        return _NO_RESULT if not os.path.lexists(path) else None
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        return None


def _runner_beat_age(spool: Spool) -> float | None:
    data = _read_json_small(spool.heartbeat_file, HEARTBEAT_LIMIT)
    ts = data.get("ts") if isinstance(data, dict) else None
    if type(ts) not in (int, float) or not math.isfinite(ts):
        return None
    return max(0.0, time.time() - float(ts))


def _wait_runner(run: _Run, spool: Spool, job_id: str) -> Any:
    """Tunggu hasil runner (poll). Hasil DIBACA lewat read_small (runner memproses masukan hostile). Melempar _Fail / _Cancel; mengembalikan JSON mentah (atau None = rusak)."""
    cfg = run.cfg
    results = spool.results / f"{job_id}.json"
    submitted = time.monotonic()
    claimed_at: float | None = None
    cancel_sent = grace_sent = False
    while True:
        raw = _read_json_small(results, RESULT_LIMIT)
        if raw is not _NO_RESULT:
            return raw
        now = time.monotonic()
        if not cancel_sent and store.is_build_cancel_requested(run.conn, run.bid):
            spool.request_cancel(job_id)
            cancel_sent = True
            if claimed_at is None and spool.withdraw(job_id):          # belum diambil runner: tarik saja
                raise _Cancel()
        if claimed_at is None:
            if spool.is_waiting(job_id):
                if now - submitted > cfg.pickup_timeout:
                    if spool.withdraw(job_id):
                        raise _Fail("runner_unavailable", f"Runner tidak mengambil job dalam {cfg.pickup_timeout} detik (runner mati atau terlalu sibuk).")
                    claimed_at = now                                  # terambil persis sekarang
            else:
                claimed_at = now                                      # sudah pindah ke running/ (atau selesai: hasil dibaca di putaran berikut)
        else:
            age = _runner_beat_age(spool)
            if age is None or age > RUNNER_STALE_AFTER:
                time.sleep(0.5)                                       # kesempatan terakhir membaca hasil yang baru ditulis
                late = _read_json_small(results, RESULT_LIMIT)
                if late is not _NO_RESULT:
                    return late
                raise _Fail("runner_unavailable", "Runner berhenti merespons saat build berjalan.")
            if now - claimed_at > cfg.timeout_build + GRACE and not grace_sent:
                spool.request_cancel(job_id)                          # sabuk pengaman bila runner gagal menegakkan timeout
                grace_sent = True
            if now - claimed_at > cfg.timeout_build + 2 * GRACE:
                raise _Fail("timeout", "Build tidak selesai meski sudah melewati batas waktu.")
        time.sleep(POLL_INTERVAL)


def _summary(result: dict[str, Any]) -> str:
    line = f"build: {result['elapsed']:.1f} dtk, {result['output_size']} B"
    if result["peak_mem_mib"] is not None:
        line += f", puncak memori {result['peak_mem_mib']} MiB"
    if result["source_kind"] != "apk":
        line += f"\nsplit_n={len(result['splits'])}"
        if result["warnings"]:
            line += "\nperingatan=" + ",".join(result["warnings"])
    return line


# ------------------------------------------------------------------ signer
def _sign(run: _Run, result: dict[str, Any]) -> dict[str, Any]:
    """Kirim job tanda tangan dan tunggu. Utas pemantau (koneksi DB sendiri) menurunkan permintaan pembatalan ke `submit_and_wait`."""
    cfg = run.cfg
    cancel, stop = threading.Event(), threading.Event()

    def watch() -> None:
        conn = connect(cfg.layout.db_path)
        try:
            while not stop.wait(POLL_INTERVAL):
                if store.is_build_cancel_requested(conn, run.bid):
                    cancel.set()
                    return
        except Exception:  # noqa: BLE001 - pemantau tidak boleh mematikan tugas
            log.exception("pemantau pembatalan build %s gagal", run.bid)
        finally:
            conn.close()

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        res = signspool.submit_and_wait(signspool.make_spool(cfg.layout.signspool), run.aid, run.bid,
                                        timeout=signspool.sign_timeout(cfg.timeout_sign, len(result["splits"])),
                                        expect_sha256=result["output_sha256"], splits=[sp["sha256"] for sp in result["splits"]], cancel=cancel)
    except signspool.SignerUnavailable as exc:
        raise _Fail("signer_unavailable", exc.message) from None
    finally:
        stop.set()
        watcher.join(5)
    if not res["ok"]:
        code = res["error_code"] or "bad_result"
        if code == "cancelled":
            _cancel_or_fail(run, f"sign_{code}", res["error_text"])
        raise _Fail(f"sign_{code}", res["error_text"])
    return res


def _check_sign_result(res: dict[str, Any], owner: str | None, runner_sha: str, runner_splits: Any = ()) -> tuple[str, str] | None:
    """Semua syarat WAJIB (desain §8.3), tidak bergantung pada `parse_result`: None bila lolos, selain itu (kode, teks)."""
    def bad(code: str) -> tuple[str, str]:
        return code, SIGN_TEXT[code]

    if res.get("ok") is not True:
        return bad("sign_bad_result")
    if owner is None or res.get("cert_sha256") != owner:
        return bad("sign_cert_mismatch")
    verify = res.get("verify")
    if not isinstance(verify, dict) or verify.get("v2") is not True or verify.get("v3") is not True:
        return bad("sign_bad_result")
    if type(res.get("signer_count")) is not int or res["signer_count"] != 1:
        return bad("sign_bad_result")
    size, out_sha = res.get("output_size"), res.get("output_sha256")
    if type(size) is not int or size <= 0 or not isinstance(out_sha, str) or buildproto.HEX64_RE.match(out_sha) is None:
        return bad("sign_bad_result")
    if res.get("input_sha256") != runner_sha:
        return bad("artifact_changed")
    rows = res.get("splits", [])
    if not isinstance(rows, list) or len(rows) != len(runner_splits):
        return bad("sign_bad_result")                           # signer bergaya 2b yang mengabaikan `splits` berakhir di sini (gagal-tertutup)
    for position, (row, sent) in enumerate(zip(rows, runner_splits), 1):
        if not isinstance(row, dict) or row.get("index") != position or type(row.get("index")) is not int:
            return bad("sign_bad_result")
        size, out_sha = row.get("output_size"), row.get("output_sha256")
        if type(size) is not int or size <= 0 or not isinstance(out_sha, str) or buildproto.HEX64_RE.match(out_sha) is None:
            return bad("sign_bad_result")
        if row.get("v2") is not True or row.get("v3") is not True or type(row.get("signer_count")) is not int or row["signer_count"] != 1:
            return bad("sign_bad_result")
        if row.get("input_sha256") != sent["sha256"]:
            return bad("artifact_changed")
        if row.get("cert_sha256") != owner:
            return bad("sign_cert_mismatch")
    return None


# ------------------------------------------------------------------ penamaan dan terbit
def _sanitise(value: Any) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]", "_", value if isinstance(value, str) else "")
    return re.sub(r"_+", "_", text).lstrip("._-")[:NAME_BASE_MAX]


def _base_name(package: Any, filename_display: Any) -> str:
    stem = Path(filename_display).stem if isinstance(filename_display, str) and filename_display else ""
    return _sanitise(package) or _sanitise(stem) or "app"


def artifact_name(package: Any, filename_display: Any, build_id: int, fmt: str = "apk") -> str:
    """`<base>-modified-<build_id>.<apk|xapk|apks>` — turunan SISTEM saja: paket dari manifes, atau stem nama berkas, atau `app`. TIDAK dari catatan/AI/`requested_by`."""
    ext = fmt if fmt in ("apk", *BUNDLE_KINDS) else "apk"
    name = f"{_base_name(package, filename_display)}-modified-{build_id}.{ext}"
    return name if store._OUTPUT_NAME_RE.fullmatch(name) else f"app-modified-{build_id}.{ext}"


def install_script_name(package: Any, filename_display: Any, build_id: int) -> str:
    """Skrip pasang bersaudara dengan paket: `<base>-modified-<build_id>-install.sh` (<= 111 karakter < batas 120)."""
    name = f"{_base_name(package, filename_display)}-modified-{build_id}-install.sh"
    return name if store._OUTPUT_NAME_RE.fullmatch(name) else f"app-modified-{build_id}-install.sh"


def _bundle_fail(exc: Exception) -> _Fail:
    """BundleError/AssembleError -> _Fail dengan kode yang diterima store (<= 40 karakter) dan teks Indonesia tertutup."""
    code = getattr(exc, "code", "")
    if code in ("bundle_changed", "artifact_changed", "assemble_failed", "assemble_timeout", "no_space"):
        return _Fail(code, SIGN_TEXT[code])
    if code in buildproto.BUILD_ERROR_CODES:
        return _Fail(code, buildproto.ERROR_TEXT[code])
    return _Fail("bundle_invalid", buildproto.ERROR_TEXT["bundle_invalid"])


def _plan_matches(plan: bundle.SplitSet, kind: str, result: dict[str, Any]) -> bool:
    """Rencana yang dihitung worker sendiri dari upload == laporan runner (format, plan_sha256, alias ⊆ kandidat, jumlah split)."""
    aliases = result["aliases"]
    candidates = {plan.apk_order.index(n) for n in plan.alias_candidates}
    return (plan.format == kind and plan.plan_sha256 == result["plan_sha256"] and set(aliases) <= candidates
            and len(bundleout.final_split_names(plan, aliases)) == len(result["splits"]))


def _precheck_bundle(run: _Run, result: dict[str, Any]) -> None:
    """Lintasan 1 saja (tanpa salinan memfd) sebelum menandatangani: hemat bila upload sudah berubah. Pemeriksaan sebenarnya diulang di `_assemble_publish`."""
    try:
        ufd = open_dir_chain(run.cfg.layout.uploads)
    except OSError:
        raise _Fail("bundle_changed", SIGN_TEXT["bundle_changed"]) from None
    try:
        with bundle.begin_upload(ufd, run.analysis["sha256"], bundle.UPLOAD_COPY_MAX_WORKER_MB * 1024 * 1024) as handle, handle.zipfile() as zf:
            plan = bundle.plan_from_zip(zf)
    except bundle.BundleError as exc:
        raise _bundle_fail(exc) from None
    finally:
        os.close(ufd)
    if not _plan_matches(plan, run.row["source_kind"], result):
        raise _Fail("bundle_changed", SIGN_TEXT["bundle_changed"])


def _assemble_check(run: _Run, started: float, last: list[float]) -> Any:
    """`check()` untuk perakit: tenggat `ASSEMBLE_TIMEOUT` dan pembatalan DB (dibatasi 2x per detik agar tidak membebani SQLite)."""
    def check() -> None:
        now = time.monotonic()
        if now - started > ASSEMBLE_TIMEOUT:
            raise _Fail("assemble_timeout", SIGN_TEXT["assemble_timeout"])
        if now - last[0] >= 0.5:
            last[0] = now
            if store.is_build_cancel_requested(run.conn, run.bid):
                raise _Cancel()
    return check


def _assemble_publish(run: _Run, result: dict[str, Any], signed: dict[str, Any]) -> dict[str, Any]:
    """Perakitan format asal (design 3.6). Urutan TETAP: salinan upload (hash ulang) -> rencana == laporan runner -> skrip tmp -> paket tmp (hash saat disalin,
    verifikasi ulang) -> rename skrip lalu paket (A-17) -> cek inode -> hash skrip dibaca ulang. Nama dan urutan entri SELALU dari upload, tak pernah dari runner."""
    cfg, kind = run.cfg, run.row["source_kind"]
    started = time.monotonic()
    check = _assemble_check(run, started, [started])
    try:
        bfd = open_dir_chain(cfg.layout.builds, str(run.aid), str(run.bid))
    except OSError:
        raise _changed() from None
    try:
        try:
            ufd = open_dir_chain(cfg.layout.uploads)
        except OSError:
            raise _Fail("bundle_changed", SIGN_TEXT["bundle_changed"]) from None
        try:
            copy = bundle.open_upload(ufd, run.analysis["sha256"], bundle.UPLOAD_COPY_MAX_WORKER_MB * 1024 * 1024, check)
        except bundle.BundleError as exc:
            raise _bundle_fail(exc) from None
        finally:
            os.close(ufd)
        with copy:
            try:
                plan = bundle.plan_from_zip(copy.zip)
            except bundle.BundleError as exc:
                raise _bundle_fail(exc) from None
            aliases = result["aliases"]
            final = bundleout.final_split_names(plan, aliases)
            if not _plan_matches(plan, kind, result) or len(final) != len(signed["splits"]):
                raise _Fail("bundle_changed", SIGN_TEXT["bundle_changed"])
            st = os.statvfs(bfd)
            if st.f_bavail * st.f_frsize < copy.size + ASSEMBLE_RESERVE:
                raise _Fail("no_space", SIGN_TEXT["no_space"])
            token = uuid.uuid4().hex[:12]
            tmp_pkg, tmp_script = f".bundle-{token}.tmp", f".install-{token}.tmp"
            pkg_name = artifact_name(run.analysis["package"], run.analysis["filename_display"], run.bid, kind)
            script_name = install_script_name(run.analysis["package"], run.analysis["filename_display"], run.bid)
            obb = [i.filename for i in copy.zip.infolist() if kind == "xapk" and not i.is_dir() and i.filename.lower().endswith(".obb")]
            try:
                text = installscript.render(kind, pkg_name, run.analysis["package"] or "", plan.base, final, obb)
            except ValueError:
                raise _Fail("assemble_failed", SIGN_TEXT["assemble_failed"]) from None
            if installscript.lint(text):
                raise _Fail("assemble_failed", SIGN_TEXT["assemble_failed"])
            base = bundleout.SignedFile(SIGNED, signed["output_sha256"], signed["output_size"])
            parts = [bundleout.SignedFile(signspool.split_output_name(r["index"]), r["output_sha256"], r["output_size"]) for r in signed["splits"]]
            try:
                bundleout.write_new_file(bfd, tmp_script, text.encode("utf-8"))
                built = bundleout.assemble(bfd, tmp_pkg, copy.zip, plan, aliases, base, parts, check)
                ident_pkg, ident_script = os.lstat(tmp_pkg, dir_fd=bfd), os.lstat(tmp_script, dir_fd=bfd)
            except (bundleout.AssembleError, OSError) as exc:
                raise _bundle_fail(exc if isinstance(exc, bundleout.AssembleError) else bundleout.AssembleError("assemble_failed", "")) from None
        check()
        _rename_over(bfd, tmp_script, script_name)
        run.published.append(script_name)
        check()                                                  # batal/tenggat di antara dua rename: _cleanup menghapus skrip yang sudah terbit
        _rename_over(bfd, tmp_pkg, pkg_name)
        run.published.append(pkg_name)
        for name, ident in ((script_name, ident_script), (pkg_name, ident_pkg)):
            try:
                after = os.lstat(name, dir_fd=bfd)
            except OSError:
                raise _changed() from None
            if (after.st_dev, after.st_ino) != (ident.st_dev, ident.st_ino) or not stat.S_ISREG(after.st_mode):
                raise _changed()
        try:
            script_sha, _size = bundleout.hash_file_at(bfd, script_name)
        except bundleout.AssembleError as exc:
            raise _bundle_fail(exc) from None
        lines = [f"install_script={script_name} sha256={script_sha}", *built.notes]
        return {"name": pkg_name, "sha256": built.sha256, "size": built.size, "lines": lines}
    finally:
        os.close(bfd)


def _changed(detail: str = "") -> _Fail:
    return _Fail("artifact_changed", SIGN_TEXT["artifact_changed"], detail)


def _publish(run: _Run, signed: dict[str, Any]) -> str:
    """Tahap 8: rantai dibuka ULANG (bukan fd tahap 3); `signed.apk` dibuka nofollow, hash dihitung ulang DARI FD yang sama; rename relatif fd; unsigned.apk dihapus."""
    try:
        bfd = open_dir_chain(run.cfg.layout.builds, str(run.aid), str(run.bid))
    except OSError:
        raise _changed() from None
    try:
        try:
            fd = os.open(SIGNED, OPEN_ARTIFACT, dir_fd=bfd)
        except OSError:
            raise _changed() from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size != signed["output_size"]:
                raise _changed()
            digest = hashlib.sha256()
            while True:
                block = os.read(fd, HASH_BLOCK)
                if not block:
                    break
                digest.update(block)
            if not hmac.compare_digest(digest.hexdigest(), signed["output_sha256"]):
                raise _changed()
            ident = (st.st_dev, st.st_ino)
        except OSError:
            raise _changed() from None
        finally:
            os.close(fd)
        name = artifact_name(run.analysis["package"], run.analysis["filename_display"], run.bid)
        _rename_over(bfd, SIGNED, name)
        run.published.append(name)
        try:
            after = os.lstat(name, dir_fd=bfd)
        except OSError:
            raise _changed() from None
        if (after.st_dev, after.st_ino) != ident or not stat.S_ISREG(after.st_mode):      # yang terbit bukan berkas yang di-hash
            raise _changed()
        try:
            os.unlink(UNSIGNED, dir_fd=bfd)
        except FileNotFoundError:
            pass
        except OSError:
            raise _changed() from None
        return name
    finally:
        os.close(bfd)


def _rename_over(bfd: int, src: str, dst: str) -> None:
    """os.rename (menimpa berkas); tujuan berupa direktori -> rmtree_at lalu rename. Gagal -> artifact_changed (tidak pernah EISDIR tak tertangani)."""
    try:
        os.rename(src, dst, src_dir_fd=bfd, dst_dir_fd=bfd)
        return
    except OSError as exc:
        if exc.errno not in (errno.EISDIR, errno.ENOTEMPTY, errno.EEXIST):
            raise _changed() from None
    try:
        rmtree_at(bfd, dst)
        os.rename(src, dst, src_dir_fd=bfd, dst_dir_fd=bfd)
    except OSError:
        raise _changed() from None


# ====================================================================== penutup
def _finish_fail(run: _Run, fail: _Fail) -> None:
    stage_log = "\n".join([*run.lines, *([fail.extra] if fail.extra else [])]) or None
    try:
        store.fail_build(run.conn, run.bid, error_code=fail.code, error_text=fail.text, stage_log=stage_log)
    except store.BuildInputError:
        log.warning("build %s: kode/teks galat ditolak store (%s); dicatat sebagai internal", run.bid, fail.code)
        _safe_fail_internal(run)
    except store.BuildStateError as exc:
        log.warning("build %s tidak bisa ditandai gagal (%s): %s", run.bid, fail.code, exc)


def _safe_fail_internal(run: _Run) -> None:
    try:
        store.fail_build(run.conn, run.bid, error_code="internal", error_text="Galat internal pada worker.")
    except store.BuildError as exc:
        log.warning("build %s tidak bisa ditandai gagal: %s", run.bid, exc)


def _finish_cancel(run: _Run) -> None:
    try:
        store.cancel_build(run.conn, run.bid)
    except store.BuildStateError as exc:                        # mis. baris sudah `failed` oleh pemulihan di worker yang baru restart
        log.warning("build %s tidak bisa ditandai dibatalkan: %s", run.bid, exc)


def _scrub_build_dir(layout: Layout, aid: int, bid: int, also: Any = None) -> None:
    """Hapus sisa sementara di `builds/<aid>/<bid>` lewat rantai-dirfd (src/, unsigned.apk, signed.apk, .sign-*, sisa paket `split-NNN.apk`/`signed-NNN.apk`/`.split-*`/
    `.alias-*`/`.bundle-*`/`.install-*`, dan nama-nama `also`: str atau daftar). Idempoten; rantai yang ditanam symlink
    DITOLAK (gagal-tertutup: tidak ada yang dihapus lewat symlink). Galat hanya di-log."""
    try:
        bfd = open_dir_chain(layout.builds, str(aid), str(bid))
    except FileNotFoundError:
        return
    except OSError as exc:
        log.warning("build %s: pembersihan dilewati, jalur builds tidak aman (%s)", bid, errno.errorcode.get(exc.errno or 0, "OSError"))
        return
    extra = {also} if isinstance(also, str) else set(also or ())
    try:
        for name in os.listdir(bfd):
            if name in SCRATCH or name.startswith(SCRATCH_PREFIXES) or SCRATCH_RE.match(name) or name in extra:
                try:
                    rmtree_at(bfd, name)
                except OSError as exc:
                    log.warning("build %s: gagal menghapus %s (%s)", bid, name if name in SCRATCH else "sisa", errno.errorcode.get(exc.errno or 0, "OSError"))
    except OSError as exc:
        log.warning("build %s: folder tidak bisa dipindai (%s)", bid, errno.errorcode.get(exc.errno or 0, "OSError"))
    finally:
        os.close(bfd)


def _cleanup(run: _Run) -> None:
    try:
        _scrub_build_dir(run.cfg.layout, run.aid, run.bid, also=() if run.done else tuple(run.published))
    except Exception:  # noqa: BLE001 - pembersihan tidak boleh menutupi hasil build
        log.exception("pembersihan build %s gagal", run.bid)


def _prune(run: _Run) -> None:
    try:
        prune_analysis(run.conn, run.cfg.layout, run.aid, run.cfg.keep)
    except Exception:  # noqa: BLE001 - galat prune hanya di-log (tidak mengubah status build)
        log.exception("prune analisis %s gagal", run.aid)


# ====================================================================== retensi
def prune_analysis(conn: Any, layout: Layout, aid: int, keep: int | None = None) -> list[int]:
    """Hapus build final lama melebihi BUILD_KEEP: DIREKTORI dulu (rantai-dirfd), baru baris (tak ada yatim DB<->disk yang tak terlacak). `OSError` -> baris
    DIPERTAHANKAN + WARNING, dicoba lagi pada prune berikut. `builds/<aid>` ditanam symlink -> entri itu di-unlink dan HANYA baris yang ditargetkan prune dihapus (A-17).
    Mengembalikan id yang dihapus."""
    ids = store.prune_builds(conn, aid, keep)
    if not ids:
        return []
    afd: int | None = None
    try:
        afd = open_dir_chain(layout.builds, str(aid))
    except FileNotFoundError:
        pass                                                      # tidak ada folder: cukup hapus baris
    except OSError as exc:
        if exc.errno not in (errno.ELOOP, errno.ENOTDIR):
            log.warning("prune analisis %s dilewati: %s", aid, errno.errorcode.get(exc.errno or 0, "OSError"))
            return []
        try:
            rfd = open_dir_chain(layout.builds)
            try:
                rmtree_at(rfd, str(aid))                          # symlink hanya di-unlink; sasarannya tidak disentuh
            finally:
                os.close(rfd)
        except OSError as exc2:
            log.warning("prune analisis %s: entri tertanam tidak bisa dihapus: %s", aid, errno.errorcode.get(exc2.errno or 0, "OSError"))
            return []
    removed: list[int] = []
    try:
        for bid in ids:
            if afd is not None:
                try:
                    rmtree_at(afd, str(bid))
                except OSError as exc:
                    log.warning("prune build %s: direktori tidak bisa dihapus (%s); baris dipertahankan", bid, errno.errorcode.get(exc.errno or 0, "OSError"))
                    continue
            if store.delete_build(conn, bid):
                removed.append(bid)
    finally:
        if afd is not None:
            os.close(afd)
    return removed


def prune_for(analysis_id: int) -> None:
    """Pembungkus uji (verify-build langkah 11): koneksi sendiri, mencetak `pruned=<id,...>`."""
    cfg = BuildConfig.from_env()
    conn = connect(cfg.layout.db_path)
    try:
        ids = prune_analysis(conn, cfg.layout, analysis_id, cfg.keep)
    finally:
        conn.close()
    print("pruned=" + ",".join(str(i) for i in ids))


# ====================================================================== pemulihan (dipanggil worker.main)
def reconcile(layout: Layout | None = None) -> list[int]:
    """`building|signing` yang yatim setelah restart -> `failed/interrupted`, lalu hapus sisa sementaranya. TANPA sapu yatim (folder tanpa baris DB dibersihkan pemilik)."""
    layout = layout or Layout(os.environ.get("DATA_DIR", "/data"))
    conn = connect(layout.db_path)
    try:
        ids = store.recover_stuck_builds(conn)
        targets = []
        for build_id in ids:
            row = store.get_build(conn, build_id)
            if row is not None:
                targets.append((row["analysis_id"], build_id))
    finally:
        conn.close()
    for aid, bid in targets:
        _scrub_build_dir(layout, aid, bid)
    return ids


def requeue_orphans(redis_conn: Any, queue_name: str = QUEUE_NAME) -> list[int]:
    """Build `queued` (dan `approved`) tanpa job RQ berawalan `build-<id>-` dikirim ulang (approved -> queued lebih dulu). Aman terhadap duplikat (CAS klaim).
    Redis galat -> WARNING, worker tetap naik; build tetap `queued` dan dipulihkan pada start/approve berikutnya."""
    import redis
    from rq import Queue

    cfg = BuildConfig.from_env()
    requeued: list[int] = []
    try:
        queue = Queue(queue_name, connection=redis_conn)
        waiting = set(queue.job_ids)
        db = connect(cfg.layout.db_path)
        try:
            for build_id in sorted(store.build_ids_by_status(db, store.B_APPROVED, store.B_QUEUED)):
                if any(job_id.startswith(f"build-{build_id}-") for job_id in waiting):
                    continue
                row = store.get_build(db, build_id)
                if row is None:
                    continue
                if row["status"] == store.B_APPROVED:
                    try:
                        store.queue_build(db, build_id)
                    except store.BuildStateError:
                        continue
                queue.enqueue("tasks.run_build", build_id, job_id=f"build-{build_id}-{uuid.uuid4().hex[:8]}", job_timeout=cfg.job_timeout_for(row["source_kind"]),
                              result_ttl=300, failure_ttl=86400)
                requeued.append(build_id)
        finally:
            db.close()
    except (redis.RedisError, OSError) as exc:
        log.warning("requeue build gagal (%s); dicoba lagi pada start/approve berikutnya", type(exc).__name__)
    return requeued
