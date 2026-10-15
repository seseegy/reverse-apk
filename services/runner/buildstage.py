"""Tahap runner `build` (Tahap 2b): `apktool b` atas SNAPSHOT ruang kerja yang hash-nya dihitung ulang dan dicocokkan dengan yang disetujui.

Logika murni modul ini dipanggil `runner-daemon`; modul TIDAK mengimpor daemon (skrip tanpa ekstensi). Ketergantungan proses (grup proses, penguras keluaran,
detak jantung, pembatalan) disuntik lewat `Env`, jadi `_run_tool` dan tahap lama TIDAK disentuh sama sekali (loop pengawas di sini milik tahap build sendiri).

Urutan (design.md 6.2 + adendum A-07; setiap langkah menghormati SATU tenggat `started + timeout` dan menulis detak jantung <= 5 dtk):
  1. prasyarat   : folder build (rantai nofollow), `bench/<aid>/project`, dan `work/<aid>/apktool` ada
  2. cek disk    : ukuran pohon proyek -> butuh 2x + cadangan 1 GiB, sebelum menyalin
  3. snapshot    : `treediff.copy_tree_safe(bench/<aid>/project -> builds/<aid>/<bid>/src)` (AI boleh menulis ke ruang kerja selama build berjalan)
  4. hash ulang  : `treediff.compute_diff(work/<aid>/apktool, src)` (fungsi SAMA dengan bench) == `diff_sha256` yang disetujui, kalau tidak
                   `workspace_changed` dan apktool TIDAK dijalankan. Yang dinilai SNAPSHOT, bukan pohon hidup
  5. jejak       : tulis `src/assets/reverse-apk-modified.txt` SETELAH hash cocok (FR-9.23; ditambahkan sistem, di luar diff yang disetujui)
  6. apktool b   : lewat wrapper produksi (`b` argumen pertama), argv dari allowlist, grup proses sendiri
  7. hasil       : `unsigned.apk` dibuka O_NOFOLLOW|O_NONBLOCK, harus berkas biasa, hash + ukuran dari fd itu
  8. pembersihan : (di `finally`, SEBELUM `Spool.finish`) `src/`, HOME job, dan `unsigned.apk` bila hasilnya bukan ok. `build.log` (<= 64 KiB) tinggal.
Runner satu domain kepercayaan dengan penulis `builds/<aid>/<bid>/` (uid sama); pemeriksaan folder di langkah 1 hanya untuk pesan galat yang jelas.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import os
import re
import stat
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from rvcore import treediff
from rvcore.buildproto import ERROR_TEXT, ERROR_TEXT_MAX, LOG_TAIL_MAX, BuildRequest, dump_result
from rvcore.fsutil import DIR_FLAGS, open_dir_chain, rmtree_at, safe_rmtree, scrub_paths, tree_stats
from rvcore.paths import Layout
from rvcore.spool import Spool
from rvcore.treediff import Limits, TreeLimitError

MIB = 1024 * 1024
RESERVE = 1024 * MIB                      # cadangan disk di atas 2x ukuran pohon (salinan + build/ antara + unsigned.apk; angka konservatif, belum diukur)
LOG_MAX = 64 * 1024
LOG_MARK = "\n[dipotong]\n"
LOG_HEAD = 8 * 1024
LOG_TAIL = LOG_MAX - LOG_HEAD - len(LOG_MARK)       # kepala + penanda + ekor == tepat 64 KiB
TRACE_DIR, TRACE_NAME = "assets", "reverse-apk-modified.txt"
SRC, UNSIGNED, LOG = "src", "unsigned.apk", "build.log"
OPEN_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_ERROR_LINE = re.compile(r"(?i)(exception|error|fatal|failed|cannot|unable)")
# Kode TreeLimitError -> kode galat build.
_TREE_CODE = {
    "too_many_entries": "tree_too_large", "too_large": "tree_too_large", "file_too_large": "tree_too_large", "too_deep": "tree_too_large",
    "name_too_long": "tree_too_large", "unreadable": "tree_unreadable", "timeout": "timeout", "cancelled": "cancelled",
}


def apktool_argv(src: Any, out: Any) -> list[str]:
    """argv apktool dari ALLOWLIST (bukan dari request). `b` HARUS argumen pertama (wrapper hanya memeriksa argumen pertama untuk menyisipkan `--aapt`).
    `-f` wajib: tanpa itu apktool memakai ulang `build/apk/classes.dex` yang sudah ada (D1). Tanpa `--copy-original`, `--debuggable`, `--net-sec-conf`, `-p`, `-l`."""
    return ["apktool", "b", "-f", "-j", "2", str(src), "-o", str(out)]


@dataclass
class Env:
    """Ketergantungan proses dari runner-daemon (tes menyuntik versi palsu)."""
    layout: Layout
    spool: Spool
    stop: threading.Event
    home_root: Path
    kill_group: Callable[[subprocess.Popen], None]
    sweep_group: Callable[[subprocess.Popen], None]
    pump_output: Callable[..., None]                 # (proc, log_fd, state, strip_frames) -> None
    max_output_bytes: int
    max_output_files: int
    say: Callable[[str], None] = lambda msg: None
    clock: Callable[[], float] = time.monotonic
    path_env: str = field(default_factory=lambda: os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"))
    heartbeat_every: float = 5.0
    tick: float = 0.5
    output_check_every: float = 5.0
    cgroup_peak: str = "/sys/fs/cgroup/memory.peak"


class _Ticker:
    """`on_tick` untuk treediff: detak jantung, pembatalan/penghentian, dan tenggat bersama. Melempar TreeLimitError('cancelled'|'timeout')."""

    def __init__(self, env: Env, job_id: str, deadline: float) -> None:
        self.env, self.job_id, self.deadline = env, job_id, deadline
        self.last_beat = -1e9

    def __call__(self) -> None:
        now = self.env.clock()
        if now - self.last_beat >= self.env.heartbeat_every:
            self.env.spool.write_heartbeat("busy", self.job_id)
            self.last_beat = now
        if self.env.stop.is_set():
            raise TreeLimitError("cancelled", "runner dihentikan saat build berjalan")
        if self.env.spool.cancel_requested(self.job_id):
            raise TreeLimitError("cancelled", "dibatalkan")
        if now > self.deadline:
            raise TreeLimitError("timeout", "melebihi batas waktu build")


class _Finish(Exception):
    """Hasil akhir yang sudah pasti (bukan galat): dipakai untuk keluar dari urutan langkah."""

    def __init__(self, result: dict[str, Any]) -> None:
        super().__init__(result.get("error_code") or "ok")
        self.result = result


def _failed(code: str, text: str = "", status: str = "failed") -> _Finish:
    return _Finish({"status": status, "error_code": code, "error_text": scrub_paths(text)[:ERROR_TEXT_MAX] if text else ERROR_TEXT[code]})


def _errno(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno or 0, "EIO")


def _hash_fd(fd: int) -> tuple[str, int]:
    h, total = hashlib.sha256(), 0
    while True:
        chunk = os.read(fd, MIB)
        if not chunk:
            return h.hexdigest(), total
        h.update(chunk)
        total += len(chunk)


# ------------------------------------------------------------------ log
def _cut_head(head: bytes) -> bytes:
    cut = head.rfind(b"\n")
    return head[:cut + 1] if cut >= 0 else head


def _cut_tail(tail: bytes) -> bytes:
    nl = tail.find(b"\n")
    return tail[nl + 1:] if nl >= 0 else tail


def _fit(text: str) -> str:
    """Paling banyak LOG_MAX byte; yang dibuang ujung AWAL (bagian akhir log paling berguna). Penyaringan jalur bisa sedikit memanjangkan teks."""
    data = text.encode("utf-8")
    return text if len(data) <= LOG_MAX else data[-LOG_MAX:].decode("utf-8", errors="ignore")


def _read_log(path: Path, roots: list[tuple[str, str]]) -> str:
    """Log apktool mentah (<= 5 MiB, ditulis `pump_output` di HOME job) disaring `scrub_paths` dan dibatasi 64 KiB: bila lebih besar, kepala 8 KiB +
    penanda + ekor, dipotong di batas baris. Tak ada / bukan berkas biasa -> kosong."""
    try:
        fd = os.open(path, OPEN_FILE)
    except OSError:
        return ""
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size <= 0:
            return ""
        size = st.st_size
        if size <= LOG_MAX:
            return _fit(scrub_paths(os.pread(fd, size, 0).decode("utf-8", errors="replace"), roots))
        head = scrub_paths(_cut_head(os.pread(fd, LOG_HEAD, 0)).decode("utf-8", errors="replace"), roots)
        tail = scrub_paths(_cut_tail(os.pread(fd, LOG_TAIL, size - LOG_TAIL)).decode("utf-8", errors="replace"), roots)
        room = LOG_MAX - len(head.encode("utf-8")) - len(LOG_MARK)
        if len(tail.encode("utf-8")) > room:                  # penyaringan memanjangkan teks: kepala dan penanda dipertahankan, ujung AWAL ekor yang dibuang
            tail = tail.encode("utf-8")[-max(room, 0):].decode("utf-8", errors="ignore")
        return head + LOG_MARK + tail
    finally:
        os.close(fd)


def _write_log(bfd: int, text: str) -> None:
    """`build.log` di folder build: `unlink` dulu lalu O_CREAT|O_EXCL|O_NOFOLLOW (nama yang ditanam penyerang tidak diikuti/ditimpa). Batas 64 KiB."""
    data = _fit(text).encode("utf-8")
    rmtree_at(bfd, LOG)
    fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=bfd)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
    finally:
        os.close(fd)


def _last_error_line(text: str) -> str | None:
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line and _ERROR_LINE.search(line) and not line.startswith("at "):
            return line[:ERROR_TEXT_MAX]
    return None


# ------------------------------------------------------------------ langkah-langkah
def _open_project(layout: Layout, aid: int) -> None:
    """`bench/<aid>/project` harus direktori sungguhan (rantai O_NOFOLLOW). Tiada/symlink -> no_workspace."""
    fd = -1
    try:
        for name in (str(layout.bench), str(aid), "project"):
            nxt = os.open(name, DIR_FLAGS, **({} if fd < 0 else {"dir_fd": fd}))
            if fd >= 0:
                os.close(fd)
            fd = nxt
    except OSError as exc:
        raise _failed("no_workspace") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _check_base(layout: Layout, aid: int) -> None:
    """Pohon dasar = direktori sungguhan dengan `AndroidManifest.xml` berkas biasa."""
    fd = -1
    try:
        fd = open_dir_chain(layout.work, str(aid))
        base_fd = os.open("apktool", DIR_FLAGS, dir_fd=fd)
        try:
            st = os.stat("AndroidManifest.xml", dir_fd=base_fd, follow_symlinks=False)
        finally:
            os.close(base_fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.ENOENT, "bukan berkas biasa")
    except OSError as exc:
        raise _failed("baseline_missing") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _check_disk(env: Env, project: Path, build_dir: Path) -> None:
    size, _files, over = tree_stats(project, Limits().max_total_bytes)
    if over:
        raise _failed("tree_too_large", f"{ERROR_TEXT['tree_too_large']} (lebih dari {Limits().max_total_bytes // MIB} MiB)")
    st = os.statvfs(build_dir)
    free = st.f_bavail * st.f_frsize
    need = 2 * size + RESERVE
    if free < need:
        raise _failed("no_space", f"Ruang disk tidak cukup: butuh {need // MIB} MiB (2x pohon {size // MIB} MiB + cadangan), bebas {free // MIB} MiB.")


def _tree_finish(env: Env, exc: TreeLimitError) -> _Finish:
    """Hasil akhir untuk TreeLimitError: batas pohon -> tree_too_large, tak terbaca -> tree_unreadable (jalur proyek RELATIF di pesan), tenggat -> timeout,
    pembatalan -> cancelled, dan penghentian runner (STOP) -> aborted."""
    if exc.code == "cancelled" and env.stop.is_set():
        return _failed("aborted", "", "aborted")
    code = _TREE_CODE[exc.code]
    return _failed(code, exc.message if exc.code == "unreadable" else "", code if code in ("timeout", "cancelled") else "failed")


def _snapshot(env: Env, project: Path, src: Path, ticker: _Ticker) -> treediff.CopyStats:
    try:
        return treediff.copy_tree_safe(project, src, Limits(), on_tick=ticker)
    except TreeLimitError as exc:
        raise _tree_finish(env, exc) from exc
    except OSError as exc:
        if exc.errno == errno.ENOSPC:
            raise _failed("no_space") from exc
        raise _failed("snapshot_failed", f"{ERROR_TEXT['snapshot_failed']} ({_errno(exc)})") from exc


def _recompute(env: Env, base: Path, src: Path, expect: str, ticker: _Ticker) -> None:
    """Hitung ulang hash atas SNAPSHOT (dan dasar HIDUP). Beda -> workspace_changed (apktool tidak dijalankan)."""
    try:
        got = treediff.compute_diff(base, src, Limits(), on_tick=ticker, text_stats=False).diff_sha256
    except TreeLimitError as exc:
        raise _tree_finish(env, exc) from exc
    except OSError as exc:
        raise _failed("snapshot_failed", f"{ERROR_TEXT['snapshot_failed']} ({_errno(exc)})") from exc
    if not hmac.compare_digest(got, expect):
        raise _failed("workspace_changed")


def _write_trace(src: Path, req: BuildRequest) -> None:
    """Jejak FR-9.23 di `src/assets/reverse-apk-modified.txt`. Ditulis SETELAH hash cocok, jadi tidak memengaruhi hash. `src/assets` yang bukan direktori
    atau penulisan gagal -> snapshot_failed. Berkas bernama sama milik AI ditimpa ("ditambahkan sistem, bukan AI")."""
    try:
        sfd = os.open(src, DIR_FLAGS)
        try:
            try:
                st = os.stat(TRACE_DIR, dir_fd=sfd, follow_symlinks=False)
            except FileNotFoundError:
                os.mkdir(TRACE_DIR, 0o755, dir_fd=sfd)
            else:
                if not stat.S_ISDIR(st.st_mode):
                    raise OSError(errno.ENOTDIR, "assets bukan direktori")
            afd = os.open(TRACE_DIR, DIR_FLAGS, dir_fd=sfd)
            try:
                rmtree_at(afd, TRACE_NAME)
                body = (f"APK ini HASIL MODIFIKASI: dibangun ulang oleh reverse-apk setelah persetujuan pemilik; berkas ini ditambahkan sistem.\n"
                        f"asal_sha256={req.sha256}\ndiff_sha256={req.diff_sha256}\nbuild={req.build_id}\n"
                        f"waktu_utc={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n").encode("ascii")
                fd = os.open(TRACE_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=afd)
                try:
                    os.write(fd, body)
                finally:
                    os.close(fd)
            finally:
                os.close(afd)
        finally:
            os.close(sfd)
    except OSError as exc:
        raise _failed("snapshot_failed", f"{ERROR_TEXT['snapshot_failed']} ({_errno(exc)})") from exc


def _run_apktool(env: Env, job_id: str, src: Path, unsigned: Path, home: Path, raw_log: Path, deadline: float) -> tuple[int | None, str | None, str]:
    """Jalankan apktool dan awasi. Mengembalikan (rc, hasil_henti|None, rincian). hasil_henti: timeout|cancelled|aborted|output_limit|spawn_failed."""
    cmd = apktool_argv(src, unsigned)
    run_env = {"PATH": env.path_env, "HOME": str(home), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
    log_fd = os.open(raw_log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    proc: subprocess.Popen | None = None
    outcome: str | None = None
    detail = ""
    try:
        env.say(f"[{job_id}] mulai: apktool b -f -j 2 <src> -o <unsigned> (batas {int(deadline - env.clock())}s)")
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=home, env=run_env,
                                    start_new_session=True, close_fds=True)
        except OSError as exc:
            return None, "spawn_failed", f"apktool tidak dapat dijalankan ({_errno(exc)})"
        state: dict[str, Any] = {}
        reader = threading.Thread(target=env.pump_output, args=(proc, log_fd, state, True), daemon=True)
        reader.start()
        last_hb = last_check = -1e9
        while proc.poll() is None:
            now = env.clock()
            if now - last_hb >= env.heartbeat_every:
                env.spool.write_heartbeat("busy", job_id)
                last_hb = now
            if env.stop.is_set():
                outcome, detail = "aborted", "runner dihentikan saat build berjalan"
            elif env.spool.cancel_requested(job_id):
                outcome, detail = "cancelled", "dibatalkan"
            elif now > deadline:
                outcome, detail = "timeout", "melebihi batas waktu build"
            elif now - last_check >= env.output_check_every:
                last_check = now
                # HANYA keluaran (src/build + unsigned.apk) yang diukur: snapshot src/ sudah dibatasi treediff dan tidak boleh membuat pohon sah gagal.
                size, files, over = tree_stats(src / "build", env.max_output_bytes, env.max_output_files)
                try:
                    size += os.lstat(unsigned).st_size
                except OSError:
                    pass
                if over or size > env.max_output_bytes:
                    outcome, detail = "output_limit", f"keluaran melebihi batas ({size // MIB} MiB atau {files} berkas); kemungkinan arsip berbahaya"
            if outcome:
                env.say(f"[{job_id}] dihentikan: {outcome}")
                env.kill_group(proc)
                break
            time.sleep(env.tick)
        proc.wait()
        env.sweep_group(proc)
        reader.join(timeout=10)
        return proc.returncode, outcome, detail
    finally:
        os.close(log_fd)
        if proc is not None and proc.poll() is None:
            env.kill_group(proc)


def _open_unsigned(bfd: int) -> tuple[str, int]:
    try:
        fd = os.open(UNSIGNED, OPEN_FILE, dir_fd=bfd)
    except OSError as exc:
        raise _failed("no_output") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size <= 0:
            raise _failed("no_output")
        sha, size = _hash_fd(fd)
        if size <= 0:
            raise _failed("no_output")
        return sha, size
    finally:
        os.close(fd)


def _peak_mem_mib(path: str) -> int | None:
    """`memory.peak` cgroup v2 (runner didaur ulang per job, jadi mendekati puncak job). Tak terbaca -> None."""
    try:
        with open(path, "rb") as fh:
            return int(fh.read(64).strip()) // MIB
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------------ titik masuk
def run(env: Env, job_id: str, req: BuildRequest) -> dict[str, Any]:
    """Jalankan satu build. Tidak pernah melempar (kecuali KeyboardInterrupt); hasil sudah lolos `dump_result` (<= 8 KiB)."""
    started = env.clock()
    deadline = started + req.timeout
    layout = env.layout
    aid, bid = req.analysis_id, req.build_id
    build_dir = layout.build_dir(aid, bid)
    project, base = layout.project_dir(aid), layout.base_tree(aid)
    src, unsigned = build_dir / SRC, build_dir / UNSIGNED
    home = env.home_root / job_id
    raw_log = home / "apktool.raw"
    roots = [(str(src), "<proyek>"), (str(project), "<proyek>"), (str(build_dir), "<build>"), (str(base), "<dasar>"), (str(home), "<home>")]
    ticker = _Ticker(env, job_id, deadline)
    stats: treediff.CopyStats | None = None
    bfd = -1
    log_text = ""
    result: dict[str, Any] = {"status": "failed", "error_code": "internal", "error_text": ERROR_TEXT["internal"]}
    try:
        try:
            try:
                bfd = open_dir_chain(layout.builds, str(aid), str(bid))
            except OSError as exc:
                raise _failed("internal", "Folder build tidak siap (tidak ada atau bukan direktori biasa).") from exc
            _open_project(layout, aid)
            _check_base(layout, aid)
            ticker()
            _check_disk(env, project, build_dir)
            os.makedirs(home, mode=0o700, exist_ok=True)
            rmtree_at(bfd, SRC)
            rmtree_at(bfd, UNSIGNED)
            stats = _snapshot(env, project, src, ticker)
            _recompute(env, base, src, req.diff_sha256, ticker)
            _write_trace(src, req)
            ticker()
            rc, outcome, detail = _run_apktool(env, job_id, src, unsigned, home, raw_log, deadline)
            log_text = _read_log(raw_log, roots)
            if outcome in ("timeout", "cancelled", "aborted"):
                raise _failed(outcome, detail, outcome)
            if outcome == "output_limit":
                raise _failed("output_limit", detail)
            if outcome == "spawn_failed":
                raise _failed("internal", detail)
            if rc != 0:
                reason = _last_error_line(log_text)
                raise _failed("build_failed", reason if reason else f"apktool keluar dengan kode {rc}")
            sha, size = _open_unsigned(bfd)
            result = {"status": "ok", "output_size": size, "output_sha256": sha, "apktool_log_tail": log_text[-LOG_TAIL_MAX:]}
        except _Finish as fin:
            result = fin.result
            result["apktool_log_tail"] = log_text[-LOG_TAIL_MAX:]
        except TreeLimitError as exc:                       # dari ticker() di luar copy/compute
            result = _tree_finish(env, exc).result
        except OSError as exc:
            code = "no_space" if exc.errno == errno.ENOSPC else "internal"
            result = {"status": "failed", "error_code": code, "error_text": ERROR_TEXT[code]}
            env.say(f"[{job_id}] WARN galat I/O build ({_errno(exc)})")
    finally:
        # Pembersihan SEBELUM Spool.finish (disk penuh tidak boleh membuat hasil hilang); idempoten, tidak pernah melempar.
        if bfd >= 0:
            try:
                _write_log(bfd, log_text or str(result.get("error_text") or ""))
            except OSError as exc:
                env.say(f"[{job_id}] WARN build.log tidak dapat ditulis ({_errno(exc)})")
            try:
                rmtree_at(bfd, SRC)
            except OSError as exc:
                env.say(f"[{job_id}] WARN pembersihan {SRC} gagal ({_errno(exc)})")
        try:
            safe_rmtree(home)
        except OSError:
            pass
    if result.get("status") != "ok" and bfd >= 0:
        try:
            rmtree_at(bfd, UNSIGNED)                         # hasil parsial/lengkap pada build yang gagal tidak boleh tinggal (bisa ~1 GiB)
        except OSError as exc:
            env.say(f"[{job_id}] WARN pembersihan {UNSIGNED} gagal ({_errno(exc)})")
    if bfd >= 0:
        os.close(bfd)
    result["elapsed"] = round(env.clock() - started, 2)
    result["peak_mem_mib"] = _peak_mem_mib(env.cgroup_peak)
    if stats is not None:
        result["files"], result["bytes"] = stats.files, stats.bytes
    return dump_result(result)
