"""Protokol web <-> bench untuk tool AI `shell_run` (PRD 09, Bagian C).

Sama dengan spool.py (rename atomik; request/running/results/cancel), tetapi di VOLUME TERPISAH (`benchspool`) yang hanya dipasang di web
dan bench, dengan pola id dan batas ukuran sendiri. Jangan pernah berbagi direktori dengan spool worker<->runner: `claim_next` mengklaim
apa saja yang lolos pola id di `requests/`.

Kepercayaan:
  * bench TIDAK mempercayai path dari web. Ia hanya menerima `analysis_id` (angka), `sha256` (heksa 64) dan teks perintah; semua path dihitung sendiri.
  * web TIDAK mempercayai hasil dari bench. Bench memproses isi APK dan menjalankan perintah yang disusun AI; kontainernya bisa saja terkompromi.
    Ukuran berkas hasil diperiksa SEBELUM dibaca, di-parse sebagai JSON ketat, dan setiap bidang dinormalkan (jenis, panjang) di `parse_result`.

Operasi (`op`): `run` (satu perintah shell AI, dikurung Landlock), `init` (salin baseline `work/<id>/apktool` ke `bench/<id>/project/`, hanya bila belum
ada kecuali `force`) dan `diff` (diff kanonik `project/` terhadap baseline, `rvcore.treediff`). `init`/`diff` hanya membawa `analysis_id` (int) dan angka/bool;
jalur dihitung bench. Hasil keduanya dinormalkan di `parse_init_result`/`parse_diff_result` dengan pola yang sama dengan `parse_result`.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from .paths import SHA256_RE, check_proto_id
from .signkeys import read_small
from .spool import RESULT_CANCELLED, RESULT_FAILED, RESULT_OK, RESULT_TIMEOUT, Spool

JOB_ID_RE = re.compile(r"^s(\d{1,9})-[0-9a-f]{12}$")
MAX_COMMAND_CHARS = 8000
MAX_REQUEST_BYTES = 64 * 1024            # perintah 8000 karakter UTF-8 <= 32 KB + bidang lain
MAX_RESULT_BYTES = 1024 * 1024           # diperiksa SEBELUM membaca berkas hasil
MAX_STREAM_CHARS = 200_000               # batas mutlak per aliran setelah dibaca web (bench membatasi lebih ketat)
HEARTBEAT_STALE_AFTER = 20.0             # detik; bench menulis detak jantung tiap 5 detik

OP_RUN = "run"
OP_INIT = "init"
OP_DIFF = "diff"
OPS = (OP_RUN, OP_INIT, OP_DIFF)
OP_MAX_TIMEOUT = 600                     # detik; batas op init/diff (mengalir lewat pohon besar, bukan perintah shell 120 dtk)
OP_PICKUP_TIMEOUT = 120.0                # bench mungkin sedang menjalankan perintah AI sampai batas waktunya

# Status hasil yang dikenal web. Selain ini dianggap rusak.
STATUS_OK = RESULT_OK                    # perintah selesai (apa pun kode keluarnya)
STATUS_TIMEOUT = RESULT_TIMEOUT
STATUS_CANCELLED = RESULT_CANCELLED
STATUS_FAILED = RESULT_FAILED            # bench gagal menjalankan (bukan kegagalan perintah)
STATUS_REFUSED = "refused"               # ditolak sebelum jalan: kuota ruang kerja, permintaan tidak valid, pengurungan tidak bisa dipasang
STATUSES = frozenset({STATUS_OK, STATUS_TIMEOUT, STATUS_CANCELLED, STATUS_FAILED, STATUS_REFUSED})


class BenchUnavailable(Exception):
    """Bench tidak bisa dipakai (mati, sibuk, atau hasilnya rusak). `message` aman ditampilkan ke AI."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def new_job_id(analysis_id: int) -> str:
    return f"s{int(analysis_id)}-{uuid.uuid4().hex[:12]}"


def make_spool(root: str | os.PathLike[str]) -> Spool:
    return Spool(root, id_re=JOB_ID_RE, max_request=MAX_REQUEST_BYTES)


def build_run_request(analysis_id: int, command: str, timeout: int, sha256: str | None) -> dict[str, Any]:
    if not isinstance(command, str) or not command.strip() or "\x00" in command or len(command) > MAX_COMMAND_CHARS:
        raise ValueError("perintah tidak valid")
    if sha256 is not None and not SHA256_RE.match(sha256):
        raise ValueError("sha256 tidak valid")
    return {"job_id": new_job_id(analysis_id), "op": OP_RUN, "analysis_id": int(analysis_id), "command": command, "timeout": int(timeout),
            "sha256": sha256, "created": time.time()}


def _op_timeout(timeout: int) -> int:
    if type(timeout) is not int or timeout < 1:
        raise ValueError("timeout tidak valid")
    return min(timeout, OP_MAX_TIMEOUT)


def build_init_request(analysis_id: int, force: bool = False, timeout: int = OP_MAX_TIMEOUT) -> dict[str, Any]:
    """Permintaan `init`. Hanya angka dan bool: tidak ada path. `force=True` mereset `project/` dari baseline (pemilik/kode saja, tidak pernah AI)."""
    check_proto_id("analysis_id", analysis_id)
    if type(force) is not bool:
        raise ValueError("force harus bool")
    return {"job_id": new_job_id(analysis_id), "op": OP_INIT, "analysis_id": analysis_id, "force": force, "timeout": _op_timeout(timeout),
            "created": time.time()}


def build_diff_request(analysis_id: int, timeout: int = OP_MAX_TIMEOUT) -> dict[str, Any]:
    check_proto_id("analysis_id", analysis_id)
    return {"job_id": new_job_id(analysis_id), "op": OP_DIFF, "analysis_id": analysis_id, "timeout": _op_timeout(timeout), "created": time.time()}


def _int(v: Any, lo: int, hi: int, default: int | None = None) -> int | None:
    if isinstance(v, bool) or not isinstance(v, int):
        return default
    return max(lo, min(hi, v))


def _text(v: Any, limit: int) -> str:
    return v[:limit] if isinstance(v, str) else ""


def _status(v: Any) -> str:
    """Status yang dikenal, selain itu `failed`. `isinstance` dulu: nilai tak-hashable (list/dict) dari bench tak boleh memicu TypeError."""
    return v if isinstance(v, str) and v in STATUSES else STATUS_FAILED


_BIDI = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def _printable(v: Any, limit: int) -> str:
    """Teks satu baris yang aman ditampilkan: karakter kontrol, pengendali arah, dan surrogate sisa diganti '?'. Nama berkas buatan AI bisa memuat '\\n'."""
    if not isinstance(v, str):
        return ""
    return "".join(c if c.isprintable() and c not in _BIDI else "?" for c in v[:limit])


def parse_result(raw: Any) -> dict[str, Any]:
    """Normalkan hasil dari bench (TIDAK TEPERCAYA). Bidang tak dikenal dibuang, jenis dan panjang dipaksa. Tidak pernah melempar."""
    if not isinstance(raw, dict):
        raw = {}                                  # tetap lewat jalur normalisasi di bawah: pemanggil membaca SEMUA kunci tanpa `.get`
        message = "hasil bench rusak"
    else:
        message = _text(raw.get("message"), 600)
    status = _status(raw.get("status"))
    return {
        "status": status,
        "exit_code": _int(raw.get("exit_code"), -255, 255),
        "signal": _int(raw.get("signal"), 1, 64),
        "stdout": _text(raw.get("stdout"), MAX_STREAM_CHARS),
        "stderr": _text(raw.get("stderr"), MAX_STREAM_CHARS),
        "truncated": bool(raw.get("truncated")),
        "omitted_bytes": _int(raw.get("omitted_bytes"), 0, 1 << 40, 0),
        "duration_ms": _int(raw.get("duration_ms"), 0, 10**9, 0),
        "message": message,
        "workspace_bytes": _int(raw.get("workspace_bytes"), 0, 1 << 50),
    }


COUNT_MAX = 1 << 50
HEX64_RE = re.compile(r"[0-9a-f]{64}")   # dipakai dengan fullmatch: `$` pada SHA256_RE juga cocok sebelum '\n' akhir
INIT_REASONS = frozenset({"created", "exists", "reset"})
SKIPPED_KEYS = ("symlink", "special", "root_ignored", "vanished")
DIFF_KINDS = ("smali", "res", "manifest", "aset", "lib", "lain")
TOP_MAX = 40                             # sama dengan treediff.TOP_MAX
TOP_PATH_MAX = 300


def _counts(raw: Any, keys: tuple[str, ...]) -> dict[str, int]:
    src = raw if isinstance(raw, dict) else {}
    return {k: _int(src.get(k), 0, COUNT_MAX, 0) for k in keys}


def _code(v: Any) -> str:
    return v if isinstance(v, str) and re.fullmatch(r"[a-z_]{1,40}", v) else ""


def parse_init_result(raw: Any) -> dict[str, Any]:
    """Normalkan hasil `init` dari bench (TIDAK TEPERCAYA). Bidang tak dikenal dibuang, jenis dan panjang dipaksa. Tidak pernah melempar."""
    if not isinstance(raw, dict):
        raw = {}
        message = "hasil bench rusak"
    else:
        message = _printable(raw.get("message"), 600)
    reason = raw.get("reason")
    return {
        "status": _status(raw.get("status")),
        "created": raw.get("created") is True,
        "reason": reason if isinstance(reason, str) and reason in INIT_REASONS else "",
        "code": _code(raw.get("code")),
        "files": _int(raw.get("files"), 0, COUNT_MAX, 0),
        "dirs": _int(raw.get("dirs"), 0, COUNT_MAX, 0),
        "bytes": _int(raw.get("bytes"), 0, COUNT_MAX, 0),
        "skipped": _counts(raw.get("skipped"), SKIPPED_KEYS),
        "message": message,
    }


def _top_item(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict) or raw.get("op") not in ("A", "M", "R") or raw.get("kind") not in ("f", "d"):
        return None
    return {"op": raw["op"], "kind": raw["kind"], "path": _printable(raw.get("path"), TOP_PATH_MAX), "size": _int(raw.get("size"), 0, COUNT_MAX, 0),
            "plus": _int(raw.get("plus"), 0, COUNT_MAX), "minus": _int(raw.get("minus"), 0, COUNT_MAX)}


def parse_diff_result(raw: Any) -> dict[str, Any]:
    """Normalkan hasil `diff` dari bench (TIDAK TEPERCAYA). `status=ok` tanpa `diff_sha256` heksa-64 yang sah dianggap `failed`. Tidak pernah melempar."""
    if not isinstance(raw, dict):
        raw = {}
        message = "hasil bench rusak"
    else:
        message = _printable(raw.get("message"), 600)
    status = _status(raw.get("status"))
    sha = raw.get("diff_sha256")
    sha = sha if isinstance(sha, str) and HEX64_RE.fullmatch(sha) else ""
    if status == STATUS_OK and not sha:
        status, message = STATUS_FAILED, message or "hasil diff bench tidak memuat hash yang sah"
    tops = raw.get("top")
    top = [t for t in (_top_item(x) for x in (tops[:TOP_MAX] if isinstance(tops, list) else [])) if t is not None]
    return {
        "status": status,
        "diff_sha256": sha,
        "counts": _counts(raw.get("counts"), ("added", "modified", "removed")),
        "entries_total": _int(raw.get("entries_total"), 0, COUNT_MAX, 0),
        "base_entries": _int(raw.get("base_entries"), 0, COUNT_MAX, 0),
        "bytes": _counts(raw.get("bytes"), ("added", "modified", "removed")),
        "kinds": _counts(raw.get("kinds"), DIFF_KINDS),
        "lines": _counts(raw.get("lines"), ("plus", "minus", "files", "skipped_files")),
        "skipped": _counts(raw.get("skipped"), SKIPPED_KEYS),
        "top": top,
        "truncated": raw.get("truncated") is True,
        "code": _code(raw.get("code")),
        "message": message,
    }


def read_result(spool: Spool, job_id: str, parser: Callable[[Any], dict[str, Any]] = parse_result) -> dict[str, Any] | None:
    """Hasil job, atau None bila belum ada. Ukuran dibatasi SEBELUM dibaca; berkas bukan-biasa (symlink/FIFO) atau JSON rusak -> status failed.

    Dibaca lewat `read_small` (O_NOFOLLOW|O_NONBLOCK + fstat berkas biasa): bench bisa menanam FIFO/symlink di `results/` dan web tidak boleh menggantung."""
    path = spool.results / f"{job_id}.json"
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return parser({"status": STATUS_FAILED, "message": "hasil bench tidak bisa dibaca"})
    if st.st_size > MAX_RESULT_BYTES:
        return parser({"status": STATUS_FAILED, "message": "hasil bench terlalu besar"})
    data = read_small(path, MAX_RESULT_BYTES)
    if data is None:
        return parser({"status": STATUS_FAILED, "message": "hasil bench bukan berkas biasa atau tidak bisa dibaca"})
    try:
        return parser(json.loads(data.decode("utf-8")))
    except (ValueError, RecursionError):
        return parser({"status": STATUS_FAILED, "message": "hasil bench rusak"})


def _fail_fast_if_dead(spool: Spool) -> None:
    age = spool.heartbeat_age()
    if age is None or age > HEARTBEAT_STALE_AFTER:
        raise BenchUnavailable("Bench (kontainer shell) tidak aktif, jadi tidak ada perintah yang dijalankan.")


def run_command(spool: Spool, analysis_id: int, command: str, *, timeout: int, sha256: str | None = None, cancel: threading.Event | None = None,
                pickup_timeout: float = 30.0, grace: float = 15.0, poll: float = 0.1) -> dict[str, Any]:
    """Kirim satu perintah ke bench dan tunggu hasilnya. Memblokir. Melempar BenchUnavailable bila bench mati/sibuk/rusak.

    Ketahanan: bench mati -> gagal CEPAT (sebelum mengirim); tidak diambil dalam `pickup_timeout` -> ditarik; melewati batas waktu + `grace` -> minta
    batal lalu menyerah; `cancel` (pengguna menekan Batal) -> minta batal dan kembali segera. Berkas job selalu dibersihkan."""
    _fail_fast_if_dead(spool)
    try:
        job = build_run_request(analysis_id, command, timeout, sha256)
    except ValueError as exc:
        raise BenchUnavailable(f"Permintaan tidak valid: {exc}.") from exc
    return _submit_and_wait(spool, job, parse_result, timeout=timeout, cancel=cancel, pickup_timeout=pickup_timeout, grace=grace, poll=poll)


def run_op(spool: Spool, request: dict[str, Any], parser: Callable[[Any], dict[str, Any]], *, cancel: threading.Event | None = None,
           pickup_timeout: float = OP_PICKUP_TIMEOUT, grace: float = 15.0, poll: float = 0.1) -> dict[str, Any]:
    """Kirim op `init`/`diff` (dari `build_init_request`/`build_diff_request`) dan tunggu hasil yang SUDAH dinormalkan oleh `parser`
    (`parse_init_result`/`parse_diff_result`). Ketahanan dan pembersihan sama dengan `run_command`."""
    if request.get("op") not in (OP_INIT, OP_DIFF):
        raise ValueError("op bukan init/diff")
    _fail_fast_if_dead(spool)
    return _submit_and_wait(spool, request, parser, timeout=request["timeout"], cancel=cancel, pickup_timeout=pickup_timeout, grace=grace, poll=poll)


def _submit_and_wait(spool: Spool, job: dict[str, Any], parser: Callable[[Any], dict[str, Any]], *, timeout: int, cancel: threading.Event | None,
                     pickup_timeout: float, grace: float, poll: float) -> dict[str, Any]:
    job_id = job["job_id"]
    spool.submit(job)
    submitted = time.monotonic()
    started: float | None = None
    try:
        while True:
            res = read_result(spool, job_id, parser)
            if res is not None:
                return res
            now = time.monotonic()
            if cancel is not None and cancel.is_set():
                spool.request_cancel(job_id)
                if spool.withdraw(job_id):
                    return {**parser({"status": STATUS_CANCELLED}), "message": "dibatalkan sebelum berjalan"}
                started = started or now
                deadline = min(started + timeout + grace, now + 5.0)         # beri bench waktu singkat untuk menutup rapi
                while time.monotonic() < deadline:
                    res = read_result(spool, job_id, parser)
                    if res is not None:
                        return res
                    time.sleep(poll)
                return {**parser({"status": STATUS_CANCELLED}), "message": "dibatalkan"}
            if started is None:
                if spool.is_waiting(job_id):
                    if now - submitted > pickup_timeout:
                        if spool.withdraw(job_id):
                            raise BenchUnavailable("Bench sibuk atau tidak mengambil perintah dalam batas waktu; coba lagi sebentar lagi.")
                else:
                    started = now
            elif now - started > timeout + grace:
                spool.request_cancel(job_id)
                time.sleep(min(2.0, grace))
                res = read_result(spool, job_id, parser)
                if res is not None:
                    return res
                raise BenchUnavailable("Bench tidak menjawab setelah batas waktu perintah; hasilnya dibuang.")
            hb = spool.heartbeat_age()
            if started is not None and (hb is None or hb > HEARTBEAT_STALE_AFTER * 2):
                raise BenchUnavailable("Bench berhenti merespons saat perintah berjalan.")
            time.sleep(poll)
    finally:
        spool.forget(job_id)


def workspace_dir(bench_root: str | os.PathLike[str], analysis_id: int) -> Path:
    """Ruang kerja per analisis. int() menolak '/' dan '..' sebelum menjadi bagian path."""
    return Path(bench_root) / str(int(analysis_id))
