"""Menjalankan SATU perintah AI di dalam pengurungan. Dipisah dari daemon agar bisa diuji tanpa spool/Docker.

Tanggung jawab: susun spesifikasi dari kebijakan (bukan dari web), jalankan `bench.confined_exec` di grup proses sendiri, tangkap keluaran
dengan batas, tegakkan batas waktu/pembatalan, dan bunuh SELURUH keturunan (termasuk yang melepaskan diri dengan setsid) saat selesai.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import policy
from .confined_exec import EXIT_BAD_SPEC, EXIT_CANARY, EXIT_LANDLOCK

# Folder yang berisi paket `bench` (diturunkan dari lokasi berkas ini, BUKAN dari $PYTHONPATH lingkungan): proses pembantu harus selalu menemukan paketnya.
PKG_ROOT = str(Path(__file__).resolve().parent.parent)
STATUS_OK, STATUS_TIMEOUT, STATUS_CANCELLED, STATUS_FAILED, STATUS_REFUSED = "ok", "timeout", "cancelled", "failed", "refused"
PR_SET_CHILD_SUBREAPER = 36
_libc = None


@dataclass(frozen=True)
class Limits:
    max_timeout: int = 120
    output_bytes: int = 64 * 1024              # per aliran (stdout, stderr); kepala + ekor disimpan, tengah dihilangkan
    workspace_bytes: int = 4096 * 1024 * 1024
    file_bytes: int = 1024 * 1024 * 1024
    nofile: int = 512
    # RLIMIT_NPROC dihitung per UID di seluruh host (terukur): proses runner/worker/web dengan uid yang sama ikut terhitung, jadi nilai kecil membuat perintah
    # SAH gagal secara acak. Pembatas proses yang tepat per kontainer adalah `pids_limit` (cgroup) di docker-compose.yml; ini hanya lapis kedua.
    nproc: int = 2048
    term_grace: float = 2.0


@dataclass(frozen=True)
class NetConfig:
    """Jaringan untuk perintah AI lewat proxy. `port` adalah satu-satunya port TCP yang boleh di-connect (Landlock ABI >= 4)."""
    host: str
    port: int

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


class Capture:
    """Simpan KEPALA dan EKOR keluaran (error biasanya di ujung), hitung yang dihilangkan. Memori selalu <= head+tail."""

    def __init__(self, limit: int) -> None:
        self.head_max = limit * 2 // 3
        self.tail_max = limit - self.head_max
        self.head = bytearray()
        self.tail = bytearray()
        self.omitted = 0

    def feed(self, data: bytes) -> None:
        room = self.head_max - len(self.head)
        if room > 0:
            self.head += data[:room]
            data = data[room:]
        if data:
            self.tail += data
            over = len(self.tail) - self.tail_max
            if over > 0:
                self.omitted += over
                del self.tail[:over]

    def text(self) -> str:
        raw = bytes(self.head) + (f"\n…[{self.omitted} byte dihilangkan]…\n".encode() if self.omitted else b"") + bytes(self.tail)
        return raw.decode("utf-8", errors="replace")


ACTIVITY_MARK = ".last-used"
MAX_SCAN_ENTRIES = 200_000      # batas pemindaian aktivitas; lebih dari ini dianggap aktif (jangan menghapus yang tak sempat dinilai)


def touch_activity(ws: Path) -> None:
    """Tanda 'ruang kerja ini dipakai' (disentuh di awal dan akhir tiap perintah). Penyapu yatim memakainya: mtime FOLDER AKAR tidak berubah saat berkas
    di dalam subfolder diedit, jadi tidak bisa dipakai sebagai petunjuk aktivitas (terbukti: penyapu menghapus ruang kerja yang baru diedit)."""
    try:
        (ws / ACTIVITY_MARK).touch()
    except OSError:
        pass


def latest_activity(root: Path) -> float:
    """mtime TERBARU di seluruh pohon (berkas, folder, dan penanda). Tidak mengikuti symlink. Batas jumlah entri agar pohon raksasa tidak menahan penyapu."""
    newest, seen = 0.0, 0
    stack = [root]
    while stack and seen < MAX_SCAN_ENTRIES:
        d = stack.pop()
        try:
            newest = max(newest, d.lstat().st_mtime)
            with os.scandir(d) as it:
                for e in it:
                    seen += 1
                    try:
                        newest = max(newest, e.stat(follow_symlinks=False).st_mtime)
                        if e.is_dir(follow_symlinks=False):
                            stack.append(Path(e.path))
                    except OSError:
                        continue
        except OSError:
            continue
    return newest if seen < MAX_SCAN_ENTRIES else time.time()        # pohon terlalu besar untuk diperiksa penuh: anggap aktif (jangan menghapus)


def enable_subreaper() -> bool:
    """Keturunan yatim (double-fork, setsid) dialihkan ke daemon, bukan ke init, sehingga bisa dimatikan setelah tiap perintah."""
    global _libc
    import ctypes
    _libc = _libc or ctypes.CDLL(None, use_errno=True)
    return _libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0


def _children_of(pid: int) -> list[int]:
    out = []
    try:
        names = os.listdir("/proc")
    except OSError:
        return out
    for n in names:
        if not n.isdigit():
            continue
        try:
            with open(f"/proc/{n}/stat", "rb") as fh:
                stat = fh.read().decode("utf-8", "replace")
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        if ppid == pid:
            out.append(int(n))
    return out


def reap_descendants(protect: set[int] = frozenset()) -> int:
    """Bunuh semua anak langsung daemon (yatim yang diwarisi lewat subreaper) selain yang dilindungi. Mengembalikan jumlah yang dibunuh."""
    killed = 0
    for _ in range(5):                                      # keturunan bisa melahirkan lagi saat dibunuh; ulangi sampai bersih
        kids = [p for p in _children_of(os.getpid()) if p not in protect]
        if not kids:
            break
        for p in kids:
            try:
                os.kill(p, signal.SIGKILL)
                killed += 1
            except ProcessLookupError:
                pass
            except PermissionError:
                pass
        for p in kids:
            try:
                os.waitpid(p, 0)
            except (ChildProcessError, OSError):
                pass
    return killed


def tree_bytes(root: Path, stop_over: int | None = None) -> int:
    total = 0
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(Path(e.path))
                        else:
                            total += e.stat(follow_symlinks=False).st_blocks * 512
                    except OSError:
                        continue
        except OSError:
            continue
        if stop_over is not None and total > stop_over:
            return total
    return total


def run_confined(dirs: policy.Dirs, limits: Limits, *, analysis_id: int, command: str, timeout: int, sha256: str | None, job_id: str,
                 cancel: Callable[[], bool] = lambda: False, heartbeat: Callable[[], None] = lambda: None,
                 python: str = sys.executable, net: NetConfig | None = None) -> dict:
    """Jalankan perintah. TIDAK PERNAH melempar untuk kegagalan perintah; hasilnya dict siap ditulis ke spool."""
    started = time.monotonic()
    timeout = max(1, min(int(timeout), limits.max_timeout))
    ws = policy.workspace(dirs, analysis_id)
    try:
        ws.mkdir(parents=True, mode=0o700, exist_ok=True)
        if ws.is_symlink() or not ws.is_dir():
            return {"status": STATUS_REFUSED, "message": "ruang kerja tidak valid"}
        used = tree_bytes(ws, limits.workspace_bytes)
    except OSError as exc:
        return {"status": STATUS_FAILED, "message": f"ruang kerja tidak bisa disiapkan ({type(exc).__name__})"}
    if used > limits.workspace_bytes:
        return {"status": STATUS_REFUSED, "workspace_bytes": used,
                "message": f"Ruang kerja melebihi kuota {limits.workspace_bytes // (1024 * 1024)} MB; hapus berkas yang tidak perlu dulu."}

    touch_activity(ws)
    scratch = Path(tempfile.mkdtemp(prefix=f"job-{job_id[:16]}-", dir=os.environ.get("TMPDIR", "/tmp")))
    os.chmod(scratch, 0o700)
    out, err = Capture(limits.output_bytes), Capture(limits.output_bytes)
    rfd, wfd = os.pipe()
    proc = None
    outcome = None
    try:
        rules = policy.rules_for(dirs, analysis_id, sha256, scratch)
        spec = {"rules": [{"path": r.path, "rights": r.rights, "optional": r.optional} for r in rules], "command": command, "cwd": str(ws),
                "env": policy.env_for(dirs, analysis_id, sha256, scratch, job_id, proxy=net.url if net else None),
                "net_ports": [net.port] if net else [], "canary": policy.canary_path(dirs, analysis_id),
                "nofile": limits.nofile, "nproc": limits.nproc, "fsize": limits.file_bytes, "cpu_seconds": timeout + 5, "marker_fd": wfd}
        try:
            proc = subprocess.Popen([python, "-m", "bench.confined_exec", json.dumps(spec)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, cwd=str(ws), start_new_session=True, close_fds=True, pass_fds=(wfd,),
                                    env={"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONPATH": PKG_ROOT,
                                         "PYTHONDONTWRITEBYTECODE": "1"})
        except OSError as exc:
            return {"status": STATUS_FAILED, "message": f"tidak bisa memulai proses ({type(exc).__name__})"}
        os.close(wfd)
        wfd = -1

        def pump(stream, cap: Capture) -> None:
            fd = stream.fileno()
            while True:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    return
                if not chunk:
                    return
                cap.feed(chunk)

        threads = [threading.Thread(target=pump, args=(proc.stdout, out), daemon=True),
                   threading.Thread(target=pump, args=(proc.stderr, err), daemon=True)]
        for t in threads:
            t.start()
        deadline = time.monotonic() + timeout
        last_beat = 0.0
        while proc.poll() is None:
            now = time.monotonic()
            if now - last_beat >= 5.0:
                heartbeat()
                last_beat = now
            if cancel():
                outcome = STATUS_CANCELLED
            elif now > deadline:
                outcome = STATUS_TIMEOUT
            elif now - started > 2 and int(now) % 3 == 0 and tree_bytes(ws, limits.workspace_bytes) > limits.workspace_bytes * 2:
                outcome = STATUS_FAILED                       # menulis tanpa henti: hentikan sebelum disk penuh
            if outcome:
                _kill_group(proc, limits.term_grace)
                break
            time.sleep(0.05)
        proc.wait()
        # Sapu SEBELUM menunggu pompa: keturunan yang melepaskan diri (setsid / double-fork) masih memegang ujung pipa keluaran, sehingga join akan
        # menunggu sampai habis waktu. Setelah bash selesai tidak ada alasan membiarkan apa pun dari perintah itu tetap hidup.
        _kill_group(proc, 0.0, term=False)
        reap_descendants()
        for t in threads:
            t.join(timeout=3)
        marker = os.read(rfd, 1) if _readable(rfd) else b""
        rc = proc.returncode
        sig = -rc if rc < 0 else None
        res = {"exit_code": rc if rc >= 0 else None, "signal": sig, "stdout": out.text(), "stderr": err.text(), "truncated": bool(out.omitted or err.omitted),
               "omitted_bytes": out.omitted + err.omitted, "duration_ms": int((time.monotonic() - started) * 1000)}
        if marker != b"1":                                    # bash tidak pernah dijalankan
            why = {EXIT_LANDLOCK: "pengurungan keamanan tidak bisa dipasang (Landlock tidak tersedia atau gagal)",
                   EXIT_CANARY: "pengurungan keamanan tidak efektif pada uji kenari", EXIT_BAD_SPEC: "spesifikasi perintah tidak valid"}.get(
                       rc, f"proses pembantu berhenti sebelum menjalankan perintah (kode {rc})")
            return {**res, "status": STATUS_REFUSED, "exit_code": None, "message": f"Perintah TIDAK dijalankan: {why}."}
        res["status"] = outcome or STATUS_OK
        if outcome == STATUS_TIMEOUT:
            res["message"] = f"melebihi batas waktu {timeout} detik; proses dihentikan"
        elif outcome == STATUS_CANCELLED:
            res["message"] = "dibatalkan oleh pengguna"
        elif outcome == STATUS_FAILED:
            res["message"] = "dihentikan: ruang kerja tumbuh melewati batas"
        res["workspace_bytes"] = tree_bytes(ws)
        touch_activity(ws)
        return res
    finally:
        if wfd >= 0:
            os.close(wfd)
        os.close(rfd)
        if proc is not None:
            _kill_group(proc, 0.5, term=False)
        reap_descendants()
        shutil.rmtree(scratch, ignore_errors=True)


def _readable(fd: int) -> bool:
    import select
    return bool(select.select([fd], [], [], 0)[0])


def _kill_group(proc: subprocess.Popen, grace: float, term: bool = True) -> None:
    for sig, wait in (((signal.SIGTERM, grace),) if term else ()) + ((signal.SIGKILL, 1.0),):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        end = time.monotonic() + wait
        while time.monotonic() < end:
            if proc.poll() is not None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)       # sapu sisa grup
                except (ProcessLookupError, PermissionError):
                    pass
                return
            time.sleep(0.05)
