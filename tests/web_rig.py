"""Perkakas bersama tes lapisan web build (FEAT E): bench PALSU berupa utas daemon di atas `benchspool` tmp, Redis palsu (`fakeredis`), Redis mati,
dan pembuat analisis/build di DB sementara (memakai `Rig` dari build_rig).

Bench palsu memakai protokol NYATA (`shellspool.make_spool`, `Spool.claim_next/finish`, detak jantung nyata): yang dipalsukan hanya isi hasilnya. Tidak ada klaim tentang
bench-daemon nyata di sini (op `init`/`diff` nyata dibuktikan di test_bench_workspace.py)."""

from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

import fakeredis
import redis

from build_rig import Rig, sha
from rvcore import shellspool, store

ROOT = Path(__file__).resolve().parent.parent
for _sub in ("services", "services/web"):
    if str(ROOT / _sub) not in sys.path:
        sys.path.insert(0, str(ROOT / _sub))

DIFF_SHA = hashlib.sha256(b"diff-bench").hexdigest()


def diff_result(*, added: int = 0, modified: int = 1, removed: int = 0, sha256: str = DIFF_SHA, base_entries: int = 1000, top: list | None = None,
                **over: Any) -> dict:
    """Hasil op `diff` bentuk bench (belum dinormalkan; web yang menormalkan)."""
    if top is None:
        top = [{"op": "M", "kind": "f", "path": "res/values/strings.xml", "size": 120, "plus": 1, "minus": 1}][:modified]
    res = {"status": "ok", "diff_sha256": sha256, "counts": {"added": added, "modified": modified, "removed": removed}, "entries_total": added + modified + removed,
           "base_entries": base_entries, "bytes": {"added": 0, "modified": 120, "removed": 0},
           "kinds": {"smali": 0, "res": modified, "manifest": 0, "aset": 0, "lib": 0, "lain": 0}, "lines": {"plus": 1, "minus": 1, "files": 1, "skipped_files": 0},
           "skipped": {"symlink": 0, "special": 0, "root_ignored": 0, "vanished": 0}, "top": top, "truncated": False, "message": ""}
    res.update(over)
    return res


def init_result(**over: Any) -> dict:
    res = {"status": "ok", "created": True, "reason": "created", "files": 3, "dirs": 1, "bytes": 30, "skipped": {"symlink": 0, "special": 0, "root_ignored": 0},
           "message": "project dibuat dari baseline"}
    res.update(over)
    return res


class FakeBench:
    """Bench palsu: detak jantung + `Spool.claim_next/finish` nyata di `<root>/benchspool`. `behave(bench, job)` -> dict hasil bench (belum dinormalkan)."""

    def __init__(self, root: Path, behave: Callable | None = None, beat: float = 0.1) -> None:
        self.spool = shellspool.make_spool(Path(root) / "benchspool")
        self.spool.ensure_dirs()
        self.behave = behave or self.default
        self.beat = beat
        self.beating = True
        self.jobs: list[dict] = []
        self.diff = diff_result()
        self.init = init_result()
        self.stop_ev = threading.Event()
        self.threads = [threading.Thread(target=self._loop, daemon=True), threading.Thread(target=self._heart, daemon=True)]

    @staticmethod
    def default(bench: "FakeBench", job: dict) -> dict:
        if job["op"] == "init":
            return bench.init
        if job["op"] == "diff":
            return bench.diff
        return {"status": "ok", "exit_code": 0, "stdout": "ok\n", "stderr": "", "duration_ms": 5}

    def _heart(self) -> None:
        while not self.stop_ev.is_set():
            if self.beating:
                self.spool.write_heartbeat("idle")
            time.sleep(self.beat)

    def _loop(self) -> None:
        while not self.stop_ev.is_set():
            claimed = self.spool.claim_next()
            if claimed is None:
                time.sleep(0.02)
                continue
            job_id, job = claimed
            self.jobs.append(job)
            self.spool.finish(job_id, self.behave(self, job))

    def __enter__(self) -> "FakeBench":
        self.spool.write_heartbeat("idle")
        for t in self.threads:
            t.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop_ev.set()
        for t in self.threads:
            t.join(5)


def dead_redis() -> redis.Redis:
    """Klien Redis ke port yang menolak koneksi seketika (jalur 'Redis mati' yang NYATA, bukan tiruan)."""
    return redis.Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.3, socket_timeout=0.3)


def live_redis() -> "fakeredis.FakeStrictRedis":
    return fakeredis.FakeStrictRedis()


class WebRig(Rig):
    """`Rig` + bench palsu + Redis palsu + `Deps` web. Satu per tes."""

    def __init__(self, root: str | Path, *, redis_conn: Any = None, bench: bool = True) -> None:
        super().__init__(root)
        for d in (self.layout.bench, self.layout.root / "benchspool"):
            d.mkdir(parents=True, exist_ok=True)
        self.redis = redis_conn if redis_conn is not None else live_redis()
        self.bench = FakeBench(self.layout.root).__enter__() if bench else None
        self._bench_spool = shellspool.make_spool(self.layout.root / "benchspool")

    def deps(self, **over: Any):
        import app.builds as wb
        values = dict(layout=self.layout, db=self.conn, redis=self.redis, bench_spool=self._bench_spool, now=time.time, job_timeout=3300,
                      op_pickup_timeout=3.0, poll=0.02)
        values.update(over)
        return wb.Deps(**values)

    def stop(self) -> None:
        super().stop()
        if self.bench is not None:
            self.bench.__exit__(None, None, None)

    # ------------------------------------------------------------------ pembuat data
    def analysis_with(self, *, options: dict | None = None, apktool: str = store.OK, status: str = store.DONE, package: str = "com.contoh.app") -> int:
        self._n += 1
        digest = sha(f"web-apk-{self.root}-{self._n}".encode())
        conn = self.conn()
        try:
            from rvcore.db import tx
            with tx(conn):
                apk_id, aid = store.create_apk_with_analysis(conn, sha256=digest, md5=digest[:32], filename="contoh.apk", size=1, options=options or {})
            store.update_apk_meta(conn, apk_id, package=package)
            store.set_stage(conn, aid, "apktool", apktool)
            if status == store.DONE:
                assert store.finish_analysis(conn, aid, store.DONE)
        finally:
            conn.close()
        return aid

    def request(self, aid: int, **kw: Any) -> dict:
        import app.builds as wb
        return wb.request_build(self.deps(), aid, **kw)

    def audit(self, action: str) -> list[dict]:
        conn = self.conn()
        try:
            return [json.loads(r["detail"]) for r in conn.execute("SELECT detail FROM audit_log WHERE action = ? ORDER BY id", (action,))]
        finally:
            conn.close()

    def queue_ids(self) -> list[str]:
        from rq import Queue
        return list(Queue("jobs", connection=self.redis).job_ids)


# ---------------------------------------------------------------- konteks `conftest` (DB + layout bersama, dipakai tes rute/CLI)
def ctx_analysis(tag: str, *, jadx: bool = True) -> tuple[int, int]:
    """(apk_id, analysis_id) dengan analisis `done` (apktool dan jadx ok) dan berkas unggahan ada, di DB/layout konteks `conftest`. `tag` harus unik per tes."""
    from contextlib import closing

    from app import context
    from conftest import new_analysis
    aid = new_analysis(tag)
    with closing(context.db()) as conn:
        store.set_stage(conn, aid, "apktool", store.OK)
        if jadx:
            store.set_stage(conn, aid, "jadx", store.OK)
        assert store.finish_analysis(conn, aid, store.DONE)
        row = store.get_analysis(conn, aid)
    context.layout.upload_path(row["sha256"]).parent.mkdir(parents=True, exist_ok=True)
    context.layout.upload_path(row["sha256"]).write_bytes(b"PK")
    return row["apk_id"], aid


def ctx_build(aid: int, status: str = "awaiting_approval") -> int:
    """Build di DB konteks dengan status tepat `status` (awaiting_approval | approved | queued | building | signing)."""
    from contextlib import closing

    from app import context
    with closing(context.db()) as conn:
        h = sha(f"ctx-{aid}-{status}".encode())
        bid = store.create_build(conn, aid, requested_by="user", source_kind="apk", diff_sha256=h, diff_summary={"v": 1})
        if status in ("approved", "queued", "building", "signing"):
            store.approve_build(conn, bid, diff_sha256=h, statement_sha256=store.approval_statement_sha256(), statement_version=1)
        if status in ("queued", "building", "signing"):
            store.queue_build(conn, bid)
        if status in ("building", "signing"):
            assert store.claim_build(conn, bid)
        if status == "signing":
            store.mark_signing(conn, bid)
    return bid
