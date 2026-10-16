"""Perkakas bersama tes worker `run_build` (FEAT D): runner dan signer PALSU berupa utas daemon di atas spool tmp, plus DB sementara.

Sengaja TANPA pytest dan tanpa `conftest` supaya bisa diimpor proses uid 10001 (setpriv; interpreter dasar tanpa venv) yang meniru kontainer worker:
modul ini hanya butuh stdlib + `rvcore` + `services/worker` (modul `builds` diimpor MALAS lewat `bm()`, jadi tes yang tidak butuh `builds` tetap berjalan).
Daemon palsu memakai protokol NYATA (`Spool.claim_next/finish`, `SignSpool.claim_next/finish`, detak jantung nyata), bukan tiruan fungsi.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
for _sub in ("services", "services/worker"):
    if str(ROOT / _sub) not in sys.path:
        sys.path.insert(0, str(ROOT / _sub))

from rvcore import signspool, store  # noqa: E402
from rvcore.db import connect, migrate, tx  # noqa: E402
from rvcore.paths import Layout  # noqa: E402
from rvcore.spool import Spool  # noqa: E402

OWNER = hashlib.sha256(b"sertifikat pemilik").hexdigest()
OTHER = hashlib.sha256(b"sertifikat lain").hexdigest()
BADGING = {"package": "com.contoh.app", "version_code": 7, "version_name": "1.2.3", "min_sdk": 21, "target_sdk": 34}      # badging palsu hasil runner (Tahap 5)
HANG = object()        # `behave` mengembalikan ini = daemon mengambil job tetapi tidak pernah menjawab


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bm():
    """Modul `builds` (diimpor malas: sebelum FEAT D belum ada -> ModuleNotFoundError di tes yang memakainya, bukan di seluruh berkas)."""
    return importlib.import_module("builds")


class FakeRunner:
    """Runner palsu: detak jantung (utas sendiri, bisa dimatikan) + Spool.claim_next/finish nyata. `behave(runner, job_id, job)` -> dict hasil | HANG."""

    def __init__(self, layout: Layout, behave: Callable | None = None, beat: float = 0.1) -> None:
        self.layout = layout
        self.spool = Spool(layout.spool)
        self.spool.ensure_dirs()
        self.behave = behave or self.default
        self.beat = beat
        self.beating = True
        self.jobs: list[dict] = []
        self.stop = threading.Event()
        self.threads = [threading.Thread(target=self._loop, daemon=True), threading.Thread(target=self._heart, daemon=True)]

    # ------------------------------------------------------------------ perilaku bawaan: apktool "berhasil"
    @staticmethod
    def default(runner: "FakeRunner", job_id: str, job: dict) -> dict:
        bdir = runner.layout.build_dir(job["analysis_id"], job["build_id"])
        (bdir / "src" / "res").mkdir(parents=True, exist_ok=True)
        (bdir / "src" / "res" / "x.xml").write_text("<x/>")
        (bdir / "build.log").write_text("I: Building apk file...\n")
        data = b"PK-unsigned-" + job_id.encode()
        (bdir / "unsigned.apk").write_bytes(data)
        res = {"status": "ok", "output_size": len(data), "output_sha256": sha(data), "elapsed": 1.5, "peak_mem_mib": 123,
               "apktool_log_tail": "I: Building apk file...", "files": 10, "bytes": 100, "badging": dict(BADGING)}
        kind = job.get("source_kind", "apk")
        if kind != "apk":
            res.update(FakeRunner.bundle_fields(runner.layout, job, bdir, kind))
        return res

    @staticmethod
    def bundle_fields(layout: Layout, job: dict, bdir: Path, kind: str) -> dict:
        """Bidang paket seperti runner nyata: rencana dari upload, alias = semua kandidat, `split-NNN.apk` tanpa nama."""
        import zipfile
        from rvcore import bundle
        with zipfile.ZipFile(layout.upload_path(job["sha256"])) as zf:
            plan = bundle.plan_from_zip(zf)
        aliases = [plan.apk_order.index(n) for n in plan.alias_candidates]
        splits = []
        for k, name in enumerate([n for i, n in enumerate(plan.apk_order) if i not in aliases], 1):
            body = b"PK-split-" + name.encode()
            (bdir / f"split-{k:03d}.apk").write_bytes(body)
            splits.append({"index": k, "sha256": sha(body), "size": len(body)})
        return {"source_kind": kind, "plan_sha256": plan.plan_sha256, "aliases": aliases, "splits": splits, "warnings": []}

    def wait_cancel(self, job_id: str, seconds: float = 10.0) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.spool.cancel_requested(job_id):
                return True
            time.sleep(0.02)
        return False

    def _heart(self) -> None:
        while not self.stop.is_set():
            if self.beating:
                self.spool.write_heartbeat("idle")
            time.sleep(self.beat)

    def _loop(self) -> None:
        while not self.stop.is_set():
            claimed = self.spool.claim_next()
            if claimed is None:
                time.sleep(0.02)
                continue
            job_id, job = claimed
            self.jobs.append(job)
            result = self.behave(self, job_id, job)
            if result is not HANG:
                self.spool.finish(job_id, result)

    def __enter__(self) -> "FakeRunner":
        self.spool.write_heartbeat("idle")
        for t in self.threads:
            t.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop.set()
        for t in self.threads:
            t.join(5)


def signed_result(input_sha: str, output: bytes, **over: Any) -> dict:
    res = {"ok": True, "error_code": None, "error_text": "", "output_name": "signed.apk", "output_size": len(output), "output_sha256": sha(output),
           "input_sha256": input_sha, "cert_sha256": OWNER, "verify": {"v1": False, "v2": True, "v3": True}, "signer_count": 1, "elapsed": 0.5}
    res.update(over)
    return res


def failure_result(code: str) -> dict:
    return {"ok": False, "error_code": code, "error_text": signspool.ERROR_TEXT[code], "output_name": "signed.apk", "output_size": 0, "output_sha256": None,
            "cert_sha256": None, "verify": {"v1": None, "v2": False, "v3": False}, "signer_count": None, "elapsed": 0.2}


class FakeSigner:
    """Signer palsu: signer.hb nyata + SignSpool.claim_next/finish nyata. `behave(signer, job_id, job)` -> dict hasil | HANG."""

    def __init__(self, layout: Layout, behave: Callable | None = None, keystore_state: str = "ok", beat: float = 0.1) -> None:
        self.layout = layout
        self.spool = signspool.make_spool(layout.signspool)
        self.spool.ensure_dirs()
        self.behave = behave or self.default
        self.beat = beat
        self.beating = True
        self.keystore = {"state": keystore_state, "detail": "", "cert_sha256": OWNER if keystore_state == "ok" else None}
        self.jobs: list[dict] = []
        self.stop = threading.Event()
        self.threads = [threading.Thread(target=self._loop, daemon=True), threading.Thread(target=self._heart, daemon=True)]

    @staticmethod
    def default(signer: "FakeSigner", job_id: str, job: dict) -> dict:
        bdir = signer.layout.build_dir(job["analysis_id"], job["build_id"])
        data = (bdir / "unsigned.apk").read_bytes()
        out = data + b"+SIGNED"
        (bdir / "signed.apk").write_bytes(out)
        rows = []
        for k, want in enumerate(job.get("splits") or [], 1):
            body = (bdir / f"split-{k:03d}.apk").read_bytes()
            signed = body + b"+SIGNED"
            (bdir / f"signed-{k:03d}.apk").write_bytes(signed)
            rows.append({"index": k, "input_sha256": sha(body), "output_sha256": sha(signed), "output_size": len(signed), "cert_sha256": OWNER,
                         "v2": True, "v3": True, "signer_count": 1})
        return signed_result(sha(data), out, **({"splits": rows} if rows or job.get("splits") is not None else {}))

    def wait_cancel(self, job_id: str, seconds: float = 10.0) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.spool.cancel_requested(job_id):
                return True
            time.sleep(0.02)
        return False

    def _heart(self) -> None:
        while not self.stop.is_set():
            if self.beating:
                self.spool.write_signer_heartbeat("idle", None, self.keystore)
            time.sleep(self.beat)

    def _loop(self) -> None:
        while not self.stop.is_set():
            claimed = self.spool.claim_next()
            if claimed is None:
                time.sleep(0.02)
                continue
            job_id, job = claimed
            self.jobs.append(job)
            try:
                signspool.validate_request(job, job_id)
            except ValueError:
                self.spool.finish(job_id, failure_result("bad_request"))
                continue
            result = self.behave(self, job_id, job)
            if result is not HANG:
                self.spool.finish(job_id, result)

    def __enter__(self) -> "FakeSigner":
        self.spool.write_signer_heartbeat("idle", None, self.keystore)
        for t in self.threads:
            t.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop.set()
        for t in self.threads:
            t.join(5)


class Rig:
    """Data dir sementara + DB + pembantu pembuat analisis/build. Satu Rig per tes."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.layout = Layout(self.root / "data")
        for d in (self.layout.builds, self.layout.signspool, self.layout.spool, self.layout.work, self.layout.uploads):
            d.mkdir(parents=True, exist_ok=True)
        migrate(self.layout.db_path)
        self._n = 0
        self.runner: FakeRunner | None = None
        self.signer: FakeSigner | None = None

    # ------------------------------------------------------------------ DB
    def conn(self):
        return connect(self.layout.db_path)

    def analysis(self, package: str | None = "com.contoh.app", filename: str = "contoh.apk") -> int:
        self._n += 1
        digest = sha(f"apk-{self.root}-{self._n}".encode())
        conn = self.conn()
        try:
            with tx(conn):
                apk_id, aid = store.create_apk_with_analysis(conn, sha256=digest, md5=digest[:32], filename=filename, size=1, options={})
            if package is not None:
                store.update_apk_meta(conn, apk_id, package=package)
            store.set_stage(conn, aid, "apktool", store.OK)
            assert store.finish_analysis(conn, aid, store.DONE)
        finally:
            conn.close()
        return aid

    def bundle_analysis(self, data: bytes, fmt: str, package: str | None = "com.contoh.app", filename: str = "contoh.xapk") -> int:
        """Analisis dari paket XAPK/APKS: upload `<sha>.apk` ditulis di `uploads/` (hash = sha256 analisis), `options.bundle.format` terisi."""
        digest = sha(data)
        self.layout.uploads.mkdir(parents=True, exist_ok=True)
        (self.layout.uploads / f"{digest}.apk").write_bytes(data)
        conn = self.conn()
        try:
            with tx(conn):
                apk_id, aid = store.create_apk_with_analysis(conn, sha256=digest, md5=digest[:32], filename=filename, size=len(data), options={"bundle": {"format": fmt}})
            if package is not None:
                store.update_apk_meta(conn, apk_id, package=package)
            store.set_stage(conn, aid, "apktool", store.OK)
            assert store.finish_analysis(conn, aid, store.DONE)
        finally:
            conn.close()
        return aid

    def build(self, aid: int, *, note: str = "", requested_by: str = "user", upto: str = "queued", source_kind: str = "apk") -> int:
        """Build baru sampai status `upto` (awaiting_approval | approved | queued)."""
        self._n += 1
        diff = sha(f"diff-{self._n}".encode())
        conn = self.conn()
        try:
            bid = store.create_build(conn, aid, requested_by=requested_by, source_kind=source_kind, diff_sha256=diff, diff_summary={"n": 1}, note=note)
            if upto != "awaiting_approval":
                store.approve_build(conn, bid, diff_sha256=diff, statement_sha256=store.approval_statement_sha256(), statement_version=1)
            if upto == "queued":
                store.queue_build(conn, bid)
        finally:
            conn.close()
        return bid

    def final_build(self, aid: int, status: str, *, make_dir: bool = True) -> int:
        """Build FINAL (done | failed | cancelled) beserta folder berisi `build.log`/artefak."""
        bid = self.build(aid, upto="queued")
        conn = self.conn()
        try:
            if status == "done":
                assert store.claim_build(conn, bid)
                store.mark_signing(conn, bid)
                store.finish_build(conn, bid, output_name=f"x-modified-{bid}.apk", output_sha256=sha(b"a"), output_size=1, output_format="apk",
                                   cert_sha256=OWNER, verify_ok=1)
            elif status == "failed":
                store.fail_build(conn, bid, error_code="build_failed", error_text="x")
            elif status == "cancelled":
                assert store.request_cancel_build(conn, bid) == "cancelled"
            else:
                raise AssertionError(status)
        finally:
            conn.close()
        if make_dir:
            d = self.layout.build_dir(aid, bid)
            d.mkdir(parents=True)
            (d / "build.log").write_text("log")
            (d / f"x-modified-{bid}.apk").write_bytes(b"a")
        return bid

    def row(self, bid: int):
        conn = self.conn()
        try:
            return store.get_build(conn, bid)
        finally:
            conn.close()

    def exists(self, bid: int) -> bool:
        return self.row(bid) is not None

    def bdir(self, aid: int, bid: int) -> Path:
        return self.layout.build_dir(aid, bid)

    def listing(self, aid: int, bid: int) -> list[str]:
        d = self.bdir(aid, bid)
        return sorted(p.name for p in d.iterdir()) if d.is_dir() else []

    # ------------------------------------------------------------------ konfigurasi dan daemon palsu
    def cfg(self, **over: Any):
        values = dict(layout=self.layout, timeout_build=30, timeout_sign=30, pickup_timeout=5, keep=None)
        values.update(over)
        return bm().BuildConfig(**values)

    def start(self, *, runner: Callable | bool = True, signer: Callable | bool = True, keystore_state: str = "ok") -> "Rig":
        if runner is not False:
            self.runner = FakeRunner(self.layout, None if runner is True else runner).__enter__()
        if signer is not False:
            self.signer = FakeSigner(self.layout, None if signer is True else signer, keystore_state=keystore_state).__enter__()
        return self

    def stop(self) -> None:
        for d in (self.runner, self.signer):
            if d is not None:
                d.__exit__(None, None, None)

    def run(self, bid: int, **cfg_over: Any) -> None:
        bm().run_build(bid, self.cfg(**cfg_over))

    def stage_log_field(self, bid: int, key: str) -> float | None:
        for line in (self.row(bid)["stage_log"] or "").splitlines():
            if line.startswith(key + "="):
                return float(line.split("=", 1)[1])
        return None


def plant_symlink(path: Path, target: Path) -> None:
    """Ganti `path` (direktori/berkas/symlink) dengan symlink ke `target` seperti runner yang terkompromi."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        path.rename(path.with_name(path.name + ".dipindah"))
    path.symlink_to(target)


def victim(base: Path, name: str = "korban") -> Path:
    v = base / name
    (v / "5").mkdir(parents=True)
    (v / "5" / "penting").write_text("jangan disentuh")
    (v / "marker").write_text("jangan disentuh")
    return v


def victim_intact(v: Path) -> bool:
    return (v / "5" / "penting").read_text() == "jangan disentuh" and (v / "marker").read_text() == "jangan disentuh"


__all__ = ["Rig", "FakeRunner", "FakeSigner", "BADGING", "HANG", "OWNER", "OTHER", "sha", "bm", "signed_result", "failure_result", "plant_symlink", "victim",
           "victim_intact"]
