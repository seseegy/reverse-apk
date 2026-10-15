"""Protokol worker <-> signer untuk menandatangani APK hasil build (Tahap 2a; PRD 09).

Turunan `Spool` (rename atomik requests/ -> running/ -> results/), di VOLUME TERPISAH (`signspool`) yang hanya dipasang di worker dan signer.
Jangan pernah berbagi direktori dengan spool lain: `claim_next` mengklaim apa saja yang lolos `JOB_ID_RE` di requests/.

Kepercayaan:
  * signer TIDAK mempercayai path dari worker. Request hanya memuat id bilangan bulat (analysis_id, build_id) dan `expect_sha256` (hash `unsigned.apk` yang
    dilaporkan runner); path dihitung signer sendiri lewat `Layout.build_dir`. Bidang lain di request (mis. `path`, `input`, `out`) tidak pernah dibaca.
  * MULTI-BERKAS (Tahap 3; XAPK/APKS): SATU request = base + 0..199 split (BATCH, bukan satu job per berkas). `splits` = daftar `expect_sha256` per split, urutannya
    = indeks 1..n; nama berkas (`unsigned.apk`, `split-NNN.apk`, `signed.apk`, `signed-NNN.apk`) dihitung SIGNER dari indeks, TIDAK PERNAH dari request. Hasil
    semua-atau-tidak-sama-sekali: satu berkas gagal -> tidak ada `signed*.apk`. Semua berkas ditandatangani kunci pemilik yang SAMA (sertifikat tiap berkas dicek).
    Tanpa `splits` seluruh perilaku 2b tidak berubah.
  * signer menyalin `unsigned.apk` SEKALI dari satu fd ke ruang kerja privatnya (`signwork`), menghitung `input_sha256` dari byte yang disalin, dan MENOLAK
    (`input_unsafe`) sebelum menjalankan alat apa pun bila `input_sha256 != expect_sha256` (berkas ditukar sejak runner selesai). Hasil `ok` memuat `input_sha256`.
  * worker TIDAK mempercayai hasil dari signer (kontainernya memproses APK tak tepercaya). Hasil dibaca dengan `read_small`
    (O_NOFOLLOW|O_NONBLOCK, batas ukuran) lalu dinormalkan ketat oleh `parse_result`; `ok` benar hanya bila `ok is True` DAN koheren.
  * Semua pembukaan berkas tak tepercaya (request, hasil, detak jantung) memakai `signkeys.OPEN_FLAGS` lewat `read_small`. `Spool.read_heartbeat`,
    `Spool.result`, `Path.read_text` dan `claim_next` induk TIDAK dipakai: open() tanpa O_NONBLOCK menggantung pada FIFO, read_text membaca
    tanpa batas dan mengikuti symlink ke /dev/zero.
"""

from __future__ import annotations

import json
import math
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .fsutil import atomic_write_json, safe_rmtree
from .signkeys import OPEN_FLAGS, read_small
from .spool import Spool

# OPEN_FLAGS diekspor ulang: tes menjaga bahwa signspool memakai SATU konstanta yang sama dengan signkeys untuk semua pembukaan tak tepercaya.
__all__ = ["OPEN_FLAGS", "read_small", "JOB_ID_RE", "ERROR_CODES", "ERROR_TEXT", "SignerUnavailable", "SignSpool", "make_spool", "new_job_id",
           "build_sign_request", "validate_request", "parse_result", "read_result", "signer_status", "submit_and_wait", "MAX_SPLITS", "SIGN_PER_FILE_S",
           "sign_timeout", "split_input_name", "split_output_name"]

# Spool memanggil `.match(stem)`: awal terkunci oleh match, akhir oleh \Z. Bukan \d (cocok digit Unicode) dan bukan $ (cocok sebelum '\n').
JOB_ID_RE = re.compile(r"g([0-9]{1,10})-([0-9]{1,10})-[0-9a-f]{8}\Z")
MAX_REQUEST_BYTES = 16 * 1024            # 199 x 67 B (hash heks-64 + tanda baca) ~ 13,3 KiB + ~0,3 KiB bidang lain
MAX_RESULT_BYTES = 128 * 1024            # hasil 199 split ~ 60 KiB
MAX_HEARTBEAT_BYTES = 16 * 1024
HEARTBEAT_STALE_AFTER = 20.0             # detik; signer menulis detak jantung tiap 5 detik
MAX_ID = 2**31
MIN_TIMEOUT, MAX_TIMEOUT = 10, 3600
TEXT_MAX = 300
OP_SIGN = "sign"
OUTPUT_NAME = "signed.apk"
MAX_SPLITS = 199                         # base + 199 split = 200 APK (FR-9.3); WAJIB sama dengan `bundle.MAX_BUNDLE_APKS - 1` (dijaga tes)
SIGN_PER_FILE_S = 10                     # tambahan tenggat per split; worker dan signer memakai konstanta ini (jangan disalin)
HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")

ERROR_CODES = frozenset({
    "bad_request", "keystore_missing", "keystore_unreadable", "keystore_invalid", "keystore_stale",
    "input_missing", "input_unsafe", "input_too_large", "no_space", "align_failed", "sign_failed", "verify_failed",
    "cert_mismatch", "timeout", "cancelled", "aborted", "output_limit", "internal", "stale_signature",
})
# Satu kalimat per kode; 'bad_result' hanya dibuat pembaca (hasil tidak bisa dipercaya). Aman ditampilkan: tanpa path rahasia.
ERROR_TEXT: dict[str, str] = {
    "bad_request": "Permintaan tanda tangan tidak valid.",
    "keystore_missing": "Keystore pemilik tidak ada di signer; jalankan 'make keystore' lalu 'make up'.",
    "keystore_unreadable": "Keystore pemilik tidak bisa dibaca signer (izin berkas); jalankan 'make keystore-access' di host.",
    "keystore_invalid": "Keystore pemilik atau berkas kata sandinya tidak valid.",
    "keystore_stale": "Berkas keystore di signer sudah usang (diganti di host); jalankan 'make restart'.",
    "input_missing": "APK yang belum ditandatangani (unsigned.apk) tidak ditemukan untuk build ini.",
    "input_unsafe": "unsigned.apk bukan berkas biasa yang aman (symlink, tautan keras, atau jenis lain) sehingga ditolak.",
    "input_too_large": "unsigned.apk melebihi batas ukuran yang boleh ditandatangani.",
    "no_space": "Ruang disk tidak cukup untuk menandatangani APK ini.",
    "align_failed": "Perataan APK (zipalign) gagal; berkas mungkin bukan APK yang valid.",
    "sign_failed": "Penandatanganan APK (apksigner sign) gagal.",
    "verify_failed": "Verifikasi tanda tangan (apksigner verify) gagal.",
    "cert_mismatch": "Sertifikat penanda tangan tidak sama dengan sertifikat keystore pemilik, sehingga hasil dibuang.",
    "timeout": "Penandatanganan melewati batas waktu dan dihentikan.",
    "cancelled": "Penandatanganan dibatalkan.",
    "aborted": "Signer dimulai ulang saat penandatanganan berjalan; coba lagi.",
    "output_limit": "Keluaran alat penandatangan melebihi batas dan dihentikan.",
    "internal": "Terjadi galat internal pada signer.",
    "stale_signature": "Sisa tanda tangan lama (META-INF/*.SF, *.RSA, *.DSA, *.EC, atau MANIFEST.MF) ditemukan pada salah satu split; seluruh set dibuang.",
    "bad_result": "hasil signer rusak",
}


class SignerUnavailable(Exception):
    """Signer tidak bisa dipakai (mati, keystore bermasalah, sibuk, atau diam). `message` aman ditampilkan ke pengguna."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _clean_id(name: str, value: object) -> int:
    if type(value) is not int or not 1 <= value < MAX_ID:
        raise ValueError(f"{name} harus bilangan bulat 1 sampai {MAX_ID - 1}")
    return value


def new_job_id(analysis_id: int, build_id: int) -> str:
    return f"g{_clean_id('analysis_id', analysis_id)}-{_clean_id('build_id', build_id)}-{uuid.uuid4().hex[:8]}"


def _expect_sha(value: Any) -> str:
    if not isinstance(value, str) or HEX64_RE.match(value) is None:
        raise ValueError("expect_sha256 harus 64 karakter heks huruf kecil")
    return value


def _splits(value: Any) -> list[str]:
    """Daftar `expect_sha256` split (urutan = indeks 1..n): list/tuple berisi heks-64 huruf kecil, paling banyak MAX_SPLITS. Duplikat BOLEH (isi dua split bisa sama)."""
    if type(value) not in (list, tuple):
        raise ValueError("splits harus berupa daftar")
    if len(value) > MAX_SPLITS:
        raise ValueError(f"splits melebihi {MAX_SPLITS} berkas")
    return [_expect_sha(item) for item in value]


def sign_timeout(base: int, n_splits: int) -> int:
    """Tenggat tanda tangan satu set: `base` + SIGN_PER_FILE_S per split, dijepit ke MAX_TIMEOUT. Dipakai worker (kirim) dan signer (batas sendiri)."""
    return min(MAX_TIMEOUT, base + SIGN_PER_FILE_S * n_splits)


def _index(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= MAX_SPLITS:
        raise ValueError(f"indeks split harus bilangan bulat 1..{MAX_SPLITS}")
    return value


def split_input_name(index: int) -> str:
    """Nama masukan split di folder build: dihitung dari indeks, tidak pernah dari request."""
    return f"split-{_index(index):03d}.apk"


def split_output_name(index: int) -> str:
    """Nama keluaran split bertanda tangan di folder build: dihitung dari indeks."""
    return f"signed-{_index(index):03d}.apk"


def build_sign_request(analysis_id: int, build_id: int, timeout: int, expect_sha256: str, splits: Any = ()) -> dict[str, Any]:
    """Request (sisi pengirim). ValueError untuk str/float/bool/<=0/>=2**31 dan `expect_sha256` selain heks-64 huruf kecil; path TIDAK ikut dikirim.
    `splits` (opsional): `expect_sha256` tiap split berurutan indeks 1..n (<= MAX_SPLITS); kosong -> bidangnya tidak ada (bentuk 2b)."""
    job = {"job_id": new_job_id(analysis_id, build_id), "op": OP_SIGN, "analysis_id": analysis_id, "build_id": build_id,
           "timeout": _clean_id("timeout", timeout), "expect_sha256": _expect_sha(expect_sha256), "created": time.time()}
    items = _splits(splits)
    if items:
        job["splits"] = items
    return job


def validate_request(job: Any, job_id: str) -> tuple[int, int, int, str, list[str]]:
    """Validasi request (sisi signer) -> (analysis_id, build_id, timeout, expect_sha256, splits). ValueError bila tidak valid. Bidang lain DIABAIKAN
    (termasuk nama/path berkas: nama dihitung signer dari indeks). `splits` ada tetapi bukan daftar heks-64 (<= MAX_SPLITS) -> ValueError; tidak ada -> `[]`."""
    if not isinstance(job, dict) or job.get("job_id") != job_id:
        raise ValueError("job_id tidak cocok")
    m = JOB_ID_RE.match(job_id)
    if m is None:
        raise ValueError("job_id tidak valid")
    if job.get("op") != OP_SIGN:
        raise ValueError("op harus 'sign'")
    aid = _clean_id("analysis_id", job.get("analysis_id"))
    bid = _clean_id("build_id", job.get("build_id"))
    if aid != int(m.group(1)) or bid != int(m.group(2)):
        raise ValueError("id di isi request tidak sama dengan id di nama")
    timeout = job.get("timeout")
    if type(timeout) is not int:
        raise ValueError("timeout harus bilangan bulat")
    expect = _expect_sha(job.get("expect_sha256"))
    splits = _splits(job["splits"]) if "splits" in job else []
    return aid, bid, max(MIN_TIMEOUT, min(MAX_TIMEOUT, timeout)), expect, splits


class SignSpool(Spool):
    def __init__(self, root: str | os.PathLike[str]) -> None:
        super().__init__(root, id_re=JOB_ID_RE, max_request=MAX_REQUEST_BYTES)
        self.heartbeat_file = self.root / "signer.hb"

    def claim_next(self) -> tuple[str, dict[str, Any]] | None:
        """Ambil request tertua tanpa pernah mengikuti symlink atau membuka FIFO secara memblokir. Request rusak dijawab `bad_request`."""
        self.ensure_dirs()
        found: list[tuple[float, str]] = []
        try:
            with os.scandir(self.requests) as it:
                for entry in it:
                    try:
                        found.append((entry.stat(follow_symlinks=False).st_mtime, entry.name))
                    except OSError:
                        continue
        except OSError:
            return None
        found.sort()
        for _, name in found:
            stem, ext = os.path.splitext(name)
            path = self.requests / name
            if ext != ".json" or not self.id_re.match(stem):
                self._discard(path)
                continue
            target = self.running / name
            try:
                os.rename(path, target)  # klaim atomik
            except OSError:
                continue
            raw = read_small(target, self.max_request)
            job: Any = None
            if raw is not None:
                try:
                    job = json.loads(raw)
                except (ValueError, RecursionError):
                    job = None
            if not isinstance(job, dict) or job.get("job_id") != stem:
                self.finish(stem, {"status": "failed", "error_code": "bad_request", "message": "request tidak valid"})
                self._remove_leftover(target)
                continue
            return stem, job
        return None

    @staticmethod
    def _remove_leftover(target: Path) -> None:
        """`finish` hanya unlink: direktori yang menyamar jadi request tertinggal di running/ dan akan dianggap yatim selamanya."""
        try:
            target.unlink()
        except IsADirectoryError:
            try:
                safe_rmtree(target)
            except OSError:
                pass
        except OSError:
            pass

    def write_signer_heartbeat(self, state: str, job: str | None, keystore: dict[str, Any]) -> None:
        """Skema signer.hb: {ts,pid,state,job,keystore:{state,detail,cert_sha256}}."""
        self.ensure_dirs()
        ks = keystore or {}
        atomic_write_json(self.heartbeat_file, self.tmp, {
            "ts": time.time(), "pid": os.getpid(), "state": state, "job": job,
            "keystore": {"state": ks.get("state"), "detail": str(ks.get("detail") or "")[:TEXT_MAX], "cert_sha256": ks.get("cert_sha256")},
        })


def make_spool(root: str | os.PathLike[str]) -> SignSpool:
    return SignSpool(root)


# ------------------------------------------------------------------------------------------------ hasil
def _text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(ch for ch in value if ch.isprintable())[:TEXT_MAX].strip()


def _hex64(value: Any) -> str | None:
    return value if isinstance(value, str) and HEX64_RE.match(value) else None


def _int_or_none(value: Any) -> int | None:
    return value if type(value) is int else None


def _parse_splits(raw: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Elemen `splits` hasil signer, dinormalkan; `None` bila tidak koheren. Tanpa bidang `splits` (signer gaya 2b / tanpa split) -> `[]`.
    Koheren: daftar <= MAX_SPLITS, `index` berurutan 1..n (int murni), tiga hash heks-64, ukuran > 0, v2 dan v3 True, tepat satu penanda tangan (butir #13)."""
    if "splits" not in raw:
        return []
    rows = raw["splits"]
    if type(rows) is not list or len(rows) > MAX_SPLITS:
        return None
    out: list[dict[str, Any]] = []
    for position, row in enumerate(rows, 1):
        if not isinstance(row, dict) or type(row.get("index")) is not int or row["index"] != position:
            return None
        size = _int_or_none(row.get("output_size"))
        item = {"index": position, "input_sha256": _hex64(row.get("input_sha256")), "output_sha256": _hex64(row.get("output_sha256")),
                "output_size": size if size is not None else 0, "cert_sha256": _hex64(row.get("cert_sha256")),
                "v2": row.get("v2") is True, "v3": row.get("v3") is True, "signer_count": _int_or_none(row.get("signer_count"))}
        if (None in (item["input_sha256"], item["output_sha256"], item["cert_sha256"]) or item["output_size"] <= 0 or not (item["v2"] and item["v3"])
                or item["signer_count"] != 1):
            return None
        out.append(item)
    return out


def parse_result(raw: Any) -> dict[str, Any]:
    """Normalkan hasil dari signer (TIDAK TEPERCAYA). Tidak pernah melempar. `ok` benar hanya bila `raw["ok"] is True` DAN koheren
    (termasuk tiap elemen `splits` bila ada). Hasil selalu memuat `splits` (daftar; `[]` bila tidak ok / tanpa split)."""
    if not isinstance(raw, dict):
        raw = {}
    verify_raw = raw.get("verify") if isinstance(raw.get("verify"), dict) else {}
    v1 = verify_raw.get("v1")
    verify = {"v1": v1 if isinstance(v1, bool) else None, "v2": verify_raw.get("v2") is True, "v3": verify_raw.get("v3") is True}
    size = _int_or_none(raw.get("output_size"))
    elapsed = raw.get("elapsed")
    out_sha = _hex64(raw.get("output_sha256"))
    cert = _hex64(raw.get("cert_sha256"))
    signers = _int_or_none(raw.get("signer_count"))
    result: dict[str, Any] = {
        "ok": False, "error_code": None, "error_text": "", "output_name": OUTPUT_NAME,
        "output_size": size if size is not None and size > 0 else 0, "output_sha256": out_sha, "input_sha256": _hex64(raw.get("input_sha256")),
        "cert_sha256": cert,
        "verify": verify, "signer_count": signers, "splits": [],
        "elapsed": float(elapsed) if type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 1e7 else 0.0,
    }
    coherent = (out_sha is not None and cert is not None and result["input_sha256"] is not None and result["output_size"] > 0 and signers == 1
                and verify["v2"] and verify["v3"])
    splits = _parse_splits(raw) if raw.get("ok") is True and coherent else None
    if raw.get("ok") is True and coherent and splits is not None:
        result["ok"] = True
        result["splits"] = splits
        return result
    code = raw.get("error_code") if isinstance(raw.get("error_code"), str) else None
    if raw.get("ok") is True or code not in ERROR_CODES:      # klaim sukses yang tak koheren / kode di luar daftar -> hasil tak bisa dipercaya
        code = "bad_result"
    result["error_code"] = code
    text = _text(raw.get("error_text")) or _text(raw.get("message"))
    result["error_text"] = text if code != "bad_result" and text else ERROR_TEXT[code]
    return result


def read_result(spool: Spool, job_id: str) -> dict[str, Any] | None:
    """Hasil job (sudah dinormalkan), atau None bila belum ada. Hasil rusak/ditukar -> ok:false bad_result. Tidak pernah melempar/menggantung."""
    path = spool.results / f"{job_id}.json"
    if not os.path.lexists(path):
        return None
    raw = read_small(path, MAX_RESULT_BYTES)
    if raw is None:
        if not os.path.lexists(path):         # dihapus di antara pemeriksaan dan buka: belum ada hasil
            return None
        return parse_result(None)
    try:
        return parse_result(json.loads(raw))
    except (ValueError, RecursionError):
        return parse_result(None)


def signer_status(spool: Spool) -> dict[str, Any]:
    """Keadaan signer dari signer.hb, dinormalkan: hidup(bool), umur(detik|None), state, job, pid, keystore{state,detail,cert_sha256}.
    Umur dari hb['ts'] (bukan mtime). Heartbeat FIFO/symlink/terlalu besar/rusak -> hidup False."""
    out: dict[str, Any] = {"hidup": False, "umur": None, "state": None, "job": None, "pid": None,
                           "keystore": {"state": None, "detail": "", "cert_sha256": None}}
    raw = read_small(spool.root / "signer.hb", MAX_HEARTBEAT_BYTES)
    if raw is None:
        return out
    try:
        hb = json.loads(raw)
    except (ValueError, RecursionError):
        return out
    if not isinstance(hb, dict):
        return out
    ts = hb.get("ts")
    if type(ts) not in (int, float) or not math.isfinite(ts):
        return out
    age = max(0.0, time.time() - float(ts))
    out["umur"] = age
    out["hidup"] = age <= HEARTBEAT_STALE_AFTER
    out["state"] = hb.get("state") if hb.get("state") in ("idle", "busy") else None
    job = hb.get("job")
    out["job"] = job if isinstance(job, str) and JOB_ID_RE.match(job) else None
    out["pid"] = _int_or_none(hb.get("pid"))
    ks = hb.get("keystore") if isinstance(hb.get("keystore"), dict) else {}
    state = ks.get("state")
    out["keystore"] = {"state": state if state in ("ok", "missing", "unreadable", "invalid", "stale") else None,
                       "detail": _text(ks.get("detail")), "cert_sha256": _hex64(ks.get("cert_sha256"))}
    return out


def _cancelled(text: str) -> dict[str, Any]:
    return parse_result({"ok": False, "error_code": "cancelled", "error_text": text})


def submit_and_wait(spool: Spool, analysis_id: int, build_id: int, *, timeout: int, expect_sha256: str, splits: Any = (), cancel: threading.Event | None = None,
                    pickup_timeout: float = 30.0, grace: float = 15.0, poll: float = 0.1) -> dict[str, Any]:
    """Kirim satu job tanda tangan (base + `splits` opsional, satu set) dan tunggu hasilnya (dinormalkan). Memblokir. Melempar SignerUnavailable bila
    signer mati/keystore bermasalah/diam.

    Ketahanan (meniru shellspool.run_command): signer mati atau keystore != ok -> gagal CEPAT sebelum mengirim; tidak diambil dalam
    `pickup_timeout` -> ditarik; melewati batas waktu + `grace` -> minta batal lalu menyerah; `cancel` -> batal. Berkas job selalu dibersihkan."""
    status = signer_status(spool)
    if not status["hidup"]:
        raise SignerUnavailable("Signer tidak aktif, jadi tidak ada yang ditandatangani. Jalankan 'make up' (profil build).")
    ks = status["keystore"]
    if ks["state"] != "ok":
        raise SignerUnavailable(f"Keystore signer belum siap (status: {ks['state'] or 'tidak diketahui'}). {ks['detail']}".strip())
    try:
        job = build_sign_request(analysis_id, build_id, timeout, expect_sha256, splits)
    except ValueError as exc:
        raise SignerUnavailable(f"Permintaan tidak valid: {exc}.") from exc
    wait_timeout = max(MIN_TIMEOUT, min(MAX_TIMEOUT, timeout))          # signer menjepit timeout ke rentang yang sama
    job_id = job["job_id"]
    spool.submit(job)
    submitted = time.monotonic()
    started: float | None = None
    try:
        while True:
            res = read_result(spool, job_id)
            if res is not None:
                return res
            now = time.monotonic()
            if cancel is not None and cancel.is_set():
                spool.request_cancel(job_id)
                if spool.withdraw(job_id):
                    return _cancelled("dibatalkan sebelum berjalan")
                started = started or now
                deadline = min(started + wait_timeout + grace, now + 5.0)
                while time.monotonic() < deadline:
                    res = read_result(spool, job_id)
                    if res is not None:
                        return res
                    time.sleep(poll)
                return _cancelled("dibatalkan")
            if started is None:
                if spool.is_waiting(job_id):
                    if now - submitted > pickup_timeout and spool.withdraw(job_id):
                        raise SignerUnavailable("Signer sibuk atau tidak mengambil pekerjaan dalam batas waktu; coba lagi sebentar lagi.")
                else:
                    started = now
            elif now - started > wait_timeout + grace:
                spool.request_cancel(job_id)
                time.sleep(min(2.0, grace))
                res = read_result(spool, job_id)
                if res is not None:
                    return res
                raise SignerUnavailable("Signer tidak menjawab setelah batas waktu penandatanganan; hasilnya dibuang.")
            if started is not None:
                umur = signer_status(spool)["umur"]
                if umur is None or umur > HEARTBEAT_STALE_AFTER * 2:
                    raise SignerUnavailable("Signer berhenti merespons saat penandatanganan berjalan.")
            time.sleep(poll)
    finally:
        spool.forget(job_id)
