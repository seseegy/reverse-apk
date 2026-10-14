"""Tabel `build` + state machine di `rvcore.store` (Tahap 1: fondasi data; belum ada worker/runner/signer/UI/AI).

Mengapa ketat: persetujuan manual adalah satu-satunya pagar antara AI dan tanda tangan. Karena itu yang diuji bukan hanya jalur
normal, tetapi (1) setiap pasangan status dari/ke, (2) balapan dua koneksi nyata, (3) persetujuan atas diff yang berubah, (4) tidak adanya
jalan lain ke 'approved'/'done', dan (5) audit yang tidak membocorkan isi. Tes memakai DB sendiri di `tmp_path` (migrasi nyata) sehingga
tidak menyentuh DB bersama dari conftest dan tidak perlu pembersihan.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import itertools
import json
import re
import sqlite3
import threading
from pathlib import Path

import pytest

from rvcore import db as rvdb
from rvcore import store
from rvcore.db import tx

ROOT = Path(__file__).resolve().parent.parent
DIFF = "d" * 64
OTHER_DIFF = "d" * 63 + "e"
SHA_A, SHA_B, CERT = "a" * 64, "b" * 64, "c" * 64
SECRET = "RAHASIA-123"
_seq = itertools.count(1)

# Literal (bukan dari store) agar berkas ini tetap bisa DIKUMPULKAN di kode lama dan gagal per tes, bukan satu galat impor.
STATUSES = ("awaiting_approval", "approved", "queued", "building", "signing", "done", "rejected", "failed", "cancelled")
(AWAITING, APPROVED, QUEUED, BUILDING, SIGNING, DONE, REJECTED, FAILED, CANCELLED) = STATUSES
ACTIVE = (AWAITING, APPROVED, QUEUED, BUILDING, SIGNING)
FINAL = (DONE, REJECTED, FAILED, CANCELLED)


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "t.sqlite"
    rvdb.migrate(path)
    return path


@pytest.fixture
def conn(db_path):
    c = rvdb.connect(db_path)
    yield c
    c.close()


# ---------------------------------------------------------------- pembantu
def make_done_analysis(conn, *, apktool=store.OK, analysis_status=store.DONE) -> int:
    """apk + analysis + 4 tahap; semua tahap ok kecuali apktool=`apktool`; analisis berakhir di `analysis_status`."""
    n = next(_seq)
    sha = hashlib.sha256(f"apk-{n}".encode()).hexdigest()
    with tx(conn):
        _apk, aid = store.create_apk_with_analysis(conn, sha256=sha, md5=sha[:32], filename=f"a{n}.apk", size=1, options={})
    for name, _label in store.PIPELINE_STAGES:
        store.set_stage(conn, aid, name, apktool if name == "apktool" else store.OK)
    if analysis_status == store.QUEUED:
        return aid
    assert store.claim_analysis(conn, aid)
    if analysis_status != store.RUNNING:
        assert store.finish_analysis(conn, aid, analysis_status)
    return aid


def approve(conn, bid, diff=DIFF):
    store.approve_build(conn, bid, diff_sha256=diff, statement_sha256=store.approval_statement_sha256(), statement_version=1)


def finish(conn, bid, source_kind="apk"):
    store.finish_build(conn, bid, output_name=f"hasil.{source_kind}", output_sha256=SHA_A, output_size=123,
                       output_format=source_kind, cert_sha256=CERT, verify_ok=1)


def new_build(conn, aid, *, source_kind="apk", diff=DIFF, requested_by="ai:7", summary=None, note="") -> int:
    return store.create_build(conn, aid, requested_by=requested_by, source_kind=source_kind, diff_sha256=diff,
                              diff_summary=summary if summary is not None else {"files": 1}, note=note)


def build_in(conn, status, *, aid=None, source_kind="apk") -> int:
    """Build di `status`, dicapai HANYA lewat fungsi store (tidak ada jalan pintas SQL)."""
    aid = aid or make_done_analysis(conn)
    bid = new_build(conn, aid, source_kind=source_kind)
    if status == AWAITING:
        return bid
    if status == REJECTED:
        store.reject_build(conn, bid, "tidak")
        return bid
    if status == CANCELLED:
        assert store.request_cancel_build(conn, bid) == "cancelled"
        return bid
    approve(conn, bid)
    if status == APPROVED:
        return bid
    if status == FAILED:
        store.fail_build(conn, bid, error_code="tool_error", error_text="gagal")
        return bid
    store.queue_build(conn, bid)
    if status == QUEUED:
        return bid
    assert store.claim_build(conn, bid)
    if status == BUILDING:
        return bid
    store.mark_signing(conn, bid)
    if status == SIGNING:
        return bid
    assert status == DONE
    finish(conn, bid, source_kind)
    return bid


def row(conn, bid) -> dict:
    r = store.get_build(conn, bid)
    return dict(r) if r else {}


def audit_rows(conn, action=None):
    sql, args = "SELECT action, detail FROM audit_log WHERE action LIKE 'build_%'", ()
    if action:
        sql, args = sql + " AND action = ?", (action,)
    return [(r["action"], json.loads(r["detail"])) for r in conn.execute(sql + " ORDER BY id", args)]


def race(db_path, *fns):
    """Jalankan fns serentak, masing-masing di koneksi + thread sendiri; kembalikan [('ok', hasil) | ('err', exc)]."""
    barrier = threading.Barrier(len(fns))
    out = [None] * len(fns)

    def run(i, fn):
        c = rvdb.connect(db_path)
        try:
            barrier.wait(10)
            try:
                out[i] = ("ok", fn(c))
            except Exception as exc:     # noqa: BLE001 - hasil dibandingkan di tes
                out[i] = ("err", exc)
        finally:
            c.close()

    threads = [threading.Thread(target=run, args=(i, fn)) for i, fn in enumerate(fns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert all(o is not None for o in out), "thread tidak selesai"
    return out


# ================================================================ 1. konstanta
def test_status_constants_are_consistent():
    assert store.BUILD_STATUSES == STATUSES
    assert set(store.BUILD_ACTIVE) | set(store.BUILD_FINAL) == set(store.BUILD_STATUSES)
    assert not set(store.BUILD_ACTIVE) & set(store.BUILD_FINAL)
    assert set(store.BUILD_TRANSITIONS) == set(store.BUILD_STATUSES)
    assert all(not store.BUILD_TRANSITIONS[s] for s in store.BUILD_FINAL), "status final tidak boleh punya jalan keluar"
    assert all(to in store.BUILD_STATUSES for tos in store.BUILD_TRANSITIONS.values() for to in tos)
    assert set(store.BUILD_STATUS_LABEL) == set(store.BUILD_STATUSES)


def test_active_set_matches_the_database_index():
    """Predikat indeks unik parsial di db.py dan BUILD_ACTIVE di store harus sama persis."""
    sql = rvdb._MIGRATIONS[4]
    where = re.search(r"build_one_open_per_analysis.*?WHERE status IN \(([^)]*)\)", sql, re.S).group(1)
    assert tuple(re.findall(r"'([a-z_]+)'", where)) == store.BUILD_ACTIVE


# ================================================================ 2. tabel transisi (semua fungsi x semua status)
ACTIONS = {
    # nama: (pemanggil, {status_asal: status_tujuan}) - sah hanya untuk status_asal yang tercantum
    "approve": (lambda c, b: approve(c, b), {AWAITING: APPROVED}),
    "reject": (lambda c, b: store.reject_build(c, b, "x"), {AWAITING: REJECTED}),
    "queue": (lambda c, b: store.queue_build(c, b), {APPROVED: QUEUED}),
    "claim": (lambda c, b: store.claim_build(c, b), {QUEUED: BUILDING}),
    "mark_signing": (lambda c, b: store.mark_signing(c, b), {BUILDING: SIGNING}),
    "finish": (lambda c, b: finish(c, b), {SIGNING: DONE}),
    "fail": (lambda c, b: store.fail_build(c, b, error_code="tool_error", error_text="x"),
             {APPROVED: FAILED, QUEUED: FAILED, BUILDING: FAILED, SIGNING: FAILED}),
    "cancel_request": (lambda c, b: store.request_cancel_build(c, b),
                       {AWAITING: CANCELLED, APPROVED: CANCELLED, QUEUED: CANCELLED}),     # building/signing: hanya menandai permintaan
    "cancel_executor": (lambda c, b: store.cancel_build(c, b), {BUILDING: CANCELLED, SIGNING: CANCELLED}),     # butuh cancel_requested=1
    "recover": (lambda c, b: store.recover_stuck_builds(c), {BUILDING: FAILED, SIGNING: FAILED}),
}


def test_action_table_covers_exactly_the_documented_transitions():
    """Tabel tes diturunkan dari fungsi, BUILD_TRANSITIONS dari kode: keduanya harus identik (tidak ada transisi gelap/yatim)."""
    pairs = {(frm, to) for _fn, moves in ACTIONS.values() for frm, to in moves.items()}
    documented = {(frm, to) for frm, tos in store.BUILD_TRANSITIONS.items() for to in tos}
    assert pairs == documented


@pytest.mark.parametrize("action", sorted(ACTIONS))
@pytest.mark.parametrize("status", STATUSES)
def test_every_function_from_every_status(conn, action, status):
    fn, moves = ACTIONS[action]
    bid = build_in(conn, status)
    if action == "cancel_executor" and status in moves:
        assert store.request_cancel_build(conn, bid) == "requested"      # prasyarat: pembatalan sudah diminta
    before = row(conn, bid)
    audits_before = len(audit_rows(conn))
    if status in moves:
        fn(conn, bid)
        now = row(conn, bid)
        assert now["status"] == moves[status]
        assert now["updated_at"] >= before["updated_at"]
        return
    if action == "claim":
        assert fn(conn, bid) is False
    elif action == "recover":
        assert fn(conn, bid) == []
    elif action == "cancel_request":
        if status in (BUILDING, SIGNING):
            assert fn(conn, bid) == "requested"
            assert row(conn, bid)["status"] == status and row(conn, bid)["cancel_requested"] == 1
            return
        assert fn(conn, bid) == "noop"
    else:
        with pytest.raises(store.BuildStateError):
            fn(conn, bid)
    assert row(conn, bid) == before, "transisi tak sah tidak boleh mengubah baris"
    assert len(audit_rows(conn)) == audits_before, "transisi tak sah tidak boleh menulis audit"


@pytest.mark.parametrize("status,action", [
    (AWAITING, "queue"), (AWAITING, "claim"), (AWAITING, "finish"), (AWAITING, "fail"), (APPROVED, "claim"), (APPROVED, "mark_signing"),
    (QUEUED, "mark_signing"), (QUEUED, "finish"), (BUILDING, "finish"), (BUILDING, "queue"), (DONE, "queue"), (DONE, "fail"),
    (DONE, "approve"), (DONE, "cancel_request"), (FAILED, "queue"), (FAILED, "approve"), (CANCELLED, "approve"),
    (CANCELLED, "queue"), (REJECTED, "approve"), (REJECTED, "queue"),
])
def test_jumps_and_returns_from_final_are_refused(conn, status, action):
    fn, _moves = ACTIONS[action]
    bid = build_in(conn, status)
    before = row(conn, bid)
    try:
        result = fn(conn, bid)
    except store.BuildStateError:
        result = None
    assert result in (None, False, "noop", [])
    assert row(conn, bid) == before


def test_double_approve_is_refused_and_keeps_first_approval(conn):
    bid = new_build(conn, make_done_analysis(conn))
    approve(conn, bid)
    first = row(conn, bid)
    with pytest.raises(store.BuildStateError):
        approve(conn, bid)
    assert row(conn, bid) == first


def test_unknown_build_is_a_clear_error(conn):
    with pytest.raises(store.BuildStateError, match="tidak ditemukan"):
        store.queue_build(conn, 9999)
    with pytest.raises(store.BuildStateError, match="tidak ditemukan"):
        approve(conn, 9999)
    assert store.claim_build(conn, 9999) is False
    assert store.get_build(conn, 9999) is None


# ================================================================ 5. approve
def test_approve_with_different_diff_is_refused(conn):
    bid = new_build(conn, make_done_analysis(conn))
    with pytest.raises(store.BuildDiffMismatchError, match="Diff berubah"):
        approve(conn, bid, OTHER_DIFF)
    r = row(conn, bid)
    assert r["status"] == AWAITING and r["approved_at"] is None and r["approval_statement_sha256"] is None
    assert issubclass(store.BuildDiffMismatchError, store.BuildStateError)


@pytest.mark.parametrize("bad", ["D" * 64, "d" * 63, "d" * 65, "", None, b"d" * 64, 5, "d" * 63 + "g"])
def test_approve_rejects_malformed_diff(conn, bad):
    bid = new_build(conn, make_done_analysis(conn))
    with pytest.raises(store.BuildInputError):
        approve(conn, bid, bad)
    assert row(conn, bid)["status"] == AWAITING


def test_approve_requires_a_known_statement(conn):
    bid = new_build(conn, make_done_analysis(conn))
    good = store.approval_statement_sha256()
    for kwargs in (
        dict(statement_sha256=good, statement_version=99),
        dict(statement_sha256=good, statement_version=0),
        dict(statement_sha256=good, statement_version="1"),
        dict(statement_sha256=hashlib.sha256(b"teks lain").hexdigest(), statement_version=1),
        dict(statement_sha256=good.upper(), statement_version=1),
    ):
        with pytest.raises(store.BuildInputError):
            store.approve_build(conn, bid, diff_sha256=DIFF, **kwargs)
        assert row(conn, bid)["status"] == AWAITING


def test_approve_records_evidence(conn):
    bid = new_build(conn, make_done_analysis(conn))
    approve(conn, bid)
    r = row(conn, bid)
    assert r["status"] == APPROVED and r["approved_at"] is not None
    assert r["approval_statement_sha256"] == store.approval_statement_sha256() and r["approval_statement_version"] == 1
    assert r["diff_sha256"] == DIFF


def test_approval_statement_v1_is_pinned():
    assert store.APPROVAL_STATEMENT_VERSION == 1
    assert store.approval_statement() == "Saya berwenang memodifikasi APK ini dan hasilnya hanya untuk riset pribadi di perangkat saya."
    # Golden: mengubah teks v1 memutus bukti persetujuan lama. Ubah teks = tambah versi baru, jangan ubah v1.
    assert store.approval_statement_sha256() == "8b96c9b8b2f2f3cb153e2f9fbfbfb1c4580d6cfee7886bd5fb83601d9c3714bb"
    assert store.approval_statement_sha256() == store.approval_statement_sha256(1)
    assert store.approval_statement_sha256() == hashlib.sha256(store.APPROVAL_STATEMENTS[1].encode("utf-8")).hexdigest()
    for bad in (99, 0, "1", None):
        with pytest.raises(store.BuildInputError):
            store.approval_statement(bad)


# ================================================================ 6. CAS balapan (dua koneksi nyata)
ROUNDS = 25


def test_race_claim_build_has_exactly_one_winner(db_path, conn):
    for _ in range(ROUNDS):
        bid = build_in(conn, QUEUED)
        out = race(db_path, lambda c: store.claim_build(c, bid), lambda c: store.claim_build(c, bid))
        assert sorted(v for _k, v in out) == [False, True], out
        assert row(conn, bid)["status"] == BUILDING


def test_race_approve_build_has_exactly_one_winner(db_path, conn):
    for _ in range(ROUNDS):
        bid = new_build(conn, make_done_analysis(conn))
        out = race(db_path, lambda c: approve(c, bid), lambda c: approve(c, bid))
        kinds = sorted(k for k, _v in out)
        assert kinds == ["err", "ok"], out
        assert isinstance(next(v for k, v in out if k == "err"), store.BuildStateError)
        assert row(conn, bid)["status"] == APPROVED
        assert len(audit_rows(conn, "build_approved")) >= 1


def test_race_approve_with_stale_diff_never_wins_against_good_diff(db_path, conn):
    for _ in range(ROUNDS):
        bid = new_build(conn, make_done_analysis(conn))
        out = race(db_path, lambda c: approve(c, bid), lambda c: approve(c, bid, OTHER_DIFF))
        assert out[0][0] == "ok" and out[1][0] == "err"
        assert row(conn, bid)["status"] == APPROVED


def test_race_cancel_vs_claim_is_consistent(db_path, conn):
    outcomes = set()
    for _ in range(ROUNDS):
        bid = build_in(conn, QUEUED)
        out = race(db_path, lambda c: store.claim_build(c, bid), lambda c: store.request_cancel_build(c, bid))
        r = row(conn, bid)
        claimed, cancel = out[0][1], out[1][1]
        if r["status"] == CANCELLED:
            assert claimed is False and cancel == "cancelled"
        else:
            assert r["status"] == BUILDING and claimed is True and cancel == "requested" and r["cancel_requested"] == 1
        outcomes.add(r["status"])
    assert outcomes <= {CANCELLED, BUILDING}


def test_race_two_creates_for_the_same_analysis(db_path, conn):
    for _ in range(ROUNDS):
        aid = make_done_analysis(conn)
        out = race(db_path, lambda c: new_build(c, aid), lambda c: new_build(c, aid))
        assert sorted(k for k, _v in out) == ["err", "ok"], out
        assert isinstance(next(v for k, v in out if k == "err"), store.BuildStateError)
        assert len(store.list_builds(conn, aid)) == 1


# ================================================================ 7. create_build
def test_create_build_stores_the_request(conn):
    aid = make_done_analysis(conn)
    bid = store.create_build(conn, aid, requested_by="user", source_kind="xapk", diff_sha256=DIFF,
                             diff_summary={"files": 3, "plus": 10, "minus": 2}, note="Catatan")
    r = row(conn, bid)
    assert r["status"] == AWAITING and r["analysis_id"] == aid and r["requested_by"] == "user" and r["source_kind"] == "xapk"
    assert r["diff_sha256"] == DIFF and r["note"] == "Catatan" and r["cancel_requested"] == 0
    assert json.loads(r["diff_summary"]) == {"files": 3, "plus": 10, "minus": 2}
    assert r["created_at"] == r["updated_at"] and r["approved_at"] is None and r["verify_ok"] is None
    assert store.get_build(conn, bid, analysis_id=aid)["id"] == bid
    assert store.get_build(conn, bid, analysis_id=aid + 1) is None, "cakupan per analisis (cegah IDOR)"
    assert new_build(conn, make_done_analysis(conn), requested_by="ai:12") > bid


def test_create_refuses_missing_analysis(conn):
    with pytest.raises(store.BuildStateError, match="Analisis tidak ditemukan"):
        new_build(conn, 424242)


@pytest.mark.parametrize("bad", [0, -1, "1", None, True, 1.0])
def test_create_refuses_malformed_analysis_id(conn, bad):
    with pytest.raises(store.BuildInputError):
        new_build(conn, bad)


@pytest.mark.parametrize("status", [store.QUEUED, store.RUNNING, store.FAILED, store.CANCELLED])
def test_create_refuses_analysis_that_is_not_done(conn, status):
    aid = make_done_analysis(conn, analysis_status=status)
    with pytest.raises(store.BuildStateError, match="belum siap") as exc:
        new_build(conn, aid)
    assert store.STATUS_LABEL[status] in str(exc.value)
    assert conn.execute("SELECT COUNT(*) FROM build").fetchone()[0] == 0


def test_create_needs_a_usable_apktool_result(conn):
    """Pipeline menandai 'done' walau apktool gagal bila jadx masih berhasil; tanpa hasil apktool tidak ada yang bisa dibangun."""
    for stage_status in (store.FAILED, store.SKIPPED, store.PENDING):
        aid = make_done_analysis(conn, apktool=stage_status)
        with pytest.raises(store.BuildStateError, match="apktool"):
            new_build(conn, aid)
    assert new_build(conn, make_done_analysis(conn, apktool=store.WARN))


@pytest.mark.parametrize("status", ACTIVE)
def test_second_active_build_is_refused_for_every_active_status(conn, status):
    aid = make_done_analysis(conn)
    first = build_in(conn, status, aid=aid)
    with pytest.raises(store.BuildStateError, match=rf"build aktif \(#{first},"):
        new_build(conn, aid)
    assert len(store.list_builds(conn, aid)) == 1
    assert store.active_build(conn, aid)["id"] == first


@pytest.mark.parametrize("status", FINAL)
def test_new_build_allowed_after_previous_is_final(conn, status):
    aid = make_done_analysis(conn)
    first = build_in(conn, status, aid=aid)
    second = new_build(conn, aid)
    assert second > first and store.active_build(conn, aid)["id"] == second
    assert [r["id"] for r in store.list_builds(conn, aid)] == [second, first]


def test_other_analysis_is_not_blocked(conn):
    build_in(conn, BUILDING)
    assert build_in(conn, AWAITING)


@pytest.mark.parametrize("bad", ["root", "ai:", "ai:abc", "user; DROP TABLE build", "ai:1" + "0" * 30, "", None, "USER", "ai:-1", "ai:1\n"])
def test_create_validates_requested_by(conn, bad):
    with pytest.raises(store.BuildInputError):
        new_build(conn, make_done_analysis(conn), requested_by=bad)


@pytest.mark.parametrize("bad", ["zip", "", "APK", None, "apk "])
def test_create_validates_source_kind(conn, bad):
    with pytest.raises(store.BuildInputError):
        new_build(conn, make_done_analysis(conn), source_kind=bad)


@pytest.mark.parametrize("bad", ["D" * 64, "d" * 63, "d" * 64 + "\n", "", None, b"d" * 64])
def test_create_validates_diff_hash(conn, bad):
    with pytest.raises(store.BuildInputError):
        new_build(conn, make_done_analysis(conn), diff=bad)


def test_create_validates_diff_summary(conn):
    aid = make_done_analysis(conn)
    for bad in ([], "x", None, {"x": "y" * 9000}, {"x": object()}):
        with pytest.raises(store.BuildInputError):
            store.create_build(conn, aid, requested_by="user", source_kind="apk", diff_sha256=DIFF, diff_summary=bad)
    ok = new_build(conn, aid, summary={})
    assert row(conn, ok)["diff_summary"] == "{}"


# ================================================================ 8. teks bebas
def test_note_is_cleaned_and_truncated(conn):
    aid = make_done_analysis(conn)
    bid = new_build(conn, aid, note="x" * 5000)
    assert len(row(conn, bid)["note"]) == store.BUILD_NOTE_MAX == 2000
    store.request_cancel_build(conn, bid)
    messy = "a\x00b\x07c\r\nd\r\n\r\n\r\n\r\ne\u202efgh\ttab"
    bid = new_build(conn, aid, note=messy)
    note = row(conn, bid)["note"]
    assert note == "abc\nd\n\ne" + "fgh\ttab"
    assert "\x00" not in note and "\r" not in note and "\u202e" not in note


def test_fail_error_text_is_one_line_scrubbed_and_short(conn):
    bid = build_in(conn, BUILDING)
    store.fail_build(conn, bid, error_code="tool_error", error_text=(
        "apktool gagal di /data/work/12/apktool/foo.smali\nlalu /tmp/x dan /opt/aapt-exec/aapt2 " + "z" * 900))
    text = row(conn, bid)["error_text"]
    assert len(text) <= store.BUILD_ERROR_MAX == 500 and "\n" not in text
    for fragment in ("/data", "/tmp", "/opt"):
        assert fragment not in text
    assert text.startswith("apktool gagal di <path> lalu <path> dan <path>")


def test_error_text_keeps_ordinary_slashes(conn):
    bid = build_in(conn, BUILDING)
    store.fail_build(conn, bid, error_code="tool_error", error_text="gagal membaca dan/atau menulis, rasio 1/2 di /database")
    assert row(conn, bid)["error_text"] == "gagal membaca dan/atau menulis, rasio 1/2 di /database"


def test_reject_reason_is_cleaned_and_defaulted(conn):
    aid = make_done_analysis(conn)
    bid = new_build(conn, aid)
    store.reject_build(conn, bid, "r\x00" + "y" * 900 + "\nbaris")
    r = row(conn, bid)
    assert r["status"] == REJECTED and len(r["rejected_reason"]) <= store.BUILD_REASON_MAX == 500 and "\n" not in r["rejected_reason"]
    assert r["finished_at"] is not None
    bid2 = new_build(conn, aid)
    store.reject_build(conn, bid2)
    assert row(conn, bid2)["rejected_reason"] == "Ditolak pengguna."


def test_stage_log_is_truncated(conn):
    bid = build_in(conn, BUILDING)
    store.mark_signing(conn, bid, stage_log="l" * 9000)
    assert len(row(conn, bid)["stage_log"]) == store.BUILD_STAGE_LOG_MAX == 4000


# ================================================================ 9. pembatalan
@pytest.mark.parametrize("status", [AWAITING, APPROVED, QUEUED])
def test_cancel_before_running_is_immediate(conn, status):
    bid = build_in(conn, status)
    assert store.request_cancel_build(conn, bid) == "cancelled"
    r = row(conn, bid)
    assert r["status"] == CANCELLED and r["finished_at"] is not None and r["error_code"] == "cancelled" and r["cancel_requested"] == 1
    assert store.request_cancel_build(conn, bid) == "noop"


@pytest.mark.parametrize("status", [BUILDING, SIGNING])
def test_cancel_while_running_only_requests(conn, status):
    bid = build_in(conn, status)
    assert store.is_build_cancel_requested(conn, bid) is False
    assert store.request_cancel_build(conn, bid) == "requested"
    assert store.request_cancel_build(conn, bid) == "requested", "idempoten"
    r = row(conn, bid)
    assert r["status"] == status and r["cancel_requested"] == 1 and r["finished_at"] is None
    assert store.is_build_cancel_requested(conn, bid) is True
    store.cancel_build(conn, bid)
    r = row(conn, bid)
    assert r["status"] == CANCELLED and r["finished_at"] is not None and r["error_code"] == "cancelled"


@pytest.mark.parametrize("status", FINAL)
def test_cancel_final_is_noop(conn, status):
    bid = build_in(conn, status)
    before = row(conn, bid)
    assert store.request_cancel_build(conn, bid) == "noop"
    assert row(conn, bid) == before


@pytest.mark.parametrize("status", [BUILDING, SIGNING])
def test_cancel_build_needs_a_request(conn, status):
    bid = build_in(conn, status)
    with pytest.raises(store.BuildStateError):
        store.cancel_build(conn, bid)
    assert row(conn, bid)["status"] == status


def test_cancel_request_blocks_progress_but_not_failure(conn):
    building = build_in(conn, BUILDING)
    store.request_cancel_build(conn, building)
    with pytest.raises(store.BuildStateError, match="pembatalan sudah diminta"):
        store.mark_signing(conn, building)
    assert row(conn, building)["status"] == BUILDING
    store.fail_build(conn, building, error_code="tool_error", error_text="gagal nyata")      # kegagalan nyata tetap tercatat
    assert row(conn, building)["status"] == FAILED

    signing = build_in(conn, SIGNING)
    store.request_cancel_build(conn, signing)
    with pytest.raises(store.BuildStateError, match="pembatalan sudah diminta"):
        finish(conn, signing)
    r = row(conn, signing)
    assert r["status"] == SIGNING and r["output_name"] is None


def test_claim_refuses_when_cancel_was_requested(conn):
    """Status 'queued' tidak bisa membawa cancel_requested lewat API (batal langsung), jadi diset mentah: penjaga di klausa CAS."""
    bid = build_in(conn, QUEUED)
    conn.execute("UPDATE build SET cancel_requested = 1 WHERE id = ?", (bid,))
    assert store.claim_build(conn, bid) is False
    assert row(conn, bid)["status"] == QUEUED


# ================================================================ 10. finish_build
def test_finish_stores_every_output_column(conn):
    bid = build_in(conn, SIGNING, source_kind="xapk")
    store.finish_build(conn, bid, output_name="app-mod_1.0.xapk", output_sha256=SHA_A, output_size=4096,
                       output_format="xapk", cert_sha256=CERT, verify_ok=True, stage_log="zipalign ok; apksigner verify ok")
    r = row(conn, bid)
    assert r["status"] == DONE and r["verify_ok"] == 1 and r["output_name"] == "app-mod_1.0.xapk" and r["output_sha256"] == SHA_A
    assert r["output_size"] == 4096 and r["output_format"] == "xapk" and r["cert_sha256"] == CERT and r["finished_at"] is not None
    assert r["stage_log"] == "zipalign ok; apksigner verify ok"


@pytest.mark.parametrize("bad", [0, None, 2, -1, "1", 1.5, "true", b"1", [1]])
def test_finish_refuses_unverified_signature(conn, bad):
    bid = build_in(conn, SIGNING)
    with pytest.raises(store.BuildInputError):
        store.finish_build(conn, bid, output_name="a.apk", output_sha256=SHA_A, output_size=1, output_format="apk",
                           cert_sha256=CERT, verify_ok=bad)
    r = row(conn, bid)
    assert r["status"] == SIGNING and r["verify_ok"] is None and r["output_name"] is None


def test_finish_refuses_wrong_format_name_size_and_hex(conn):
    bid = build_in(conn, SIGNING, source_kind="apks")
    good = dict(output_name="a.apks", output_sha256=SHA_A, output_size=1, output_format="apks", cert_sha256=CERT, verify_ok=1)
    for override in (
        dict(output_format="apk"), dict(output_format="xapk"), dict(output_format="zip"),
        dict(output_name="../x.apks"), dict(output_name="a/b.apks"), dict(output_name=".hidden"), dict(output_name=""),
        dict(output_name="n" * 121), dict(output_name="a b.apks"), dict(output_name=None),
        dict(output_size=0), dict(output_size=-5), dict(output_size="9"), dict(output_size=True), dict(output_size=1.5),
        dict(output_sha256="A" * 64), dict(output_sha256="a" * 63), dict(cert_sha256="z" * 64), dict(cert_sha256=None),
    ):
        with pytest.raises(store.BuildInputError):
            store.finish_build(conn, bid, **{**good, **override})
        assert row(conn, bid)["status"] == SIGNING, override
    store.finish_build(conn, bid, **good)
    assert row(conn, bid)["status"] == DONE


# ================================================================ 11. fail_build
@pytest.mark.parametrize("status", [APPROVED, QUEUED, BUILDING, SIGNING])
def test_fail_from_every_executable_status(conn, status):
    bid = build_in(conn, status)
    store.fail_build(conn, bid, error_code="sign_failed", error_text="x", verify_ok=0, stage_log="langkah 3")
    r = row(conn, bid)
    assert r["status"] == FAILED and r["error_code"] == "sign_failed" and r["verify_ok"] == 0 and r["finished_at"] is not None
    assert r["stage_log"] == "langkah 3"


@pytest.mark.parametrize("bad", ["Besar", "", "a b", "k" * 41, "1abc", None, "a-b", "a\n"])
def test_fail_validates_error_code(conn, bad):
    bid = build_in(conn, BUILDING)
    with pytest.raises(store.BuildInputError):
        store.fail_build(conn, bid, error_code=bad, error_text="x")
    assert row(conn, bid)["status"] == BUILDING


@pytest.mark.parametrize("bad", [2, "1", 1.5, -1])
def test_fail_validates_verify_ok(conn, bad):
    bid = build_in(conn, BUILDING)
    with pytest.raises(store.BuildInputError):
        store.fail_build(conn, bid, error_code="tool_error", error_text="x", verify_ok=bad)


# ================================================================ 12. recover_stuck_builds
def test_recover_marks_orphans_interrupted_and_leaves_the_rest(conn):
    b1, s1 = build_in(conn, BUILDING), build_in(conn, SIGNING)
    others = {s: build_in(conn, s) for s in (AWAITING, APPROVED, QUEUED, DONE, FAILED, CANCELLED, REJECTED)}
    before = {s: row(conn, b) for s, b in others.items()}
    assert store.recover_stuck_builds(conn) == sorted([b1, s1])
    for bid in (b1, s1):
        r = row(conn, bid)
        assert r["status"] == FAILED and r["error_code"] == store.E_INTERRUPTED == "interrupted" and r["finished_at"] is not None
        assert "dimulai ulang" in r["error_text"]
    assert {s: row(conn, b) for s, b in others.items()} == before
    interrupted = [d["build_id"] for _a, d in audit_rows(conn, "build_failed") if d["error_code"] == "interrupted"]
    assert interrupted == sorted([b1, s1])
    assert store.recover_stuck_builds(conn) == []


# ================================================================ 13. prune_builds / delete_build
def _done_builds(conn, aid, n, status=DONE):
    ids = []
    for _ in range(n):
        ids.append(build_in(conn, status, aid=aid))
    return ids


def test_prune_respects_keep_and_never_touches_active(conn):
    aid = make_done_analysis(conn)
    done = _done_builds(conn, aid, 14)
    active = new_build(conn, aid)
    assert store.prune_builds(conn, aid, 10) == done[:4]
    assert store.prune_builds(conn, aid, 1) == done[:13]
    assert active not in store.prune_builds(conn, aid, 1)
    assert store.prune_builds(conn, aid, 14) == []
    assert row(conn, active)["status"] == AWAITING
    assert conn.execute("SELECT COUNT(*) FROM build WHERE analysis_id = ?", (aid,)).fetchone()[0] == 15, "prune tidak menghapus baris"


@pytest.mark.parametrize("status", ACTIVE)
def test_prune_never_returns_any_active_status(conn, status):
    aid = make_done_analysis(conn)
    _done_builds(conn, aid, 3)
    active = build_in(conn, status, aid=aid)
    assert active not in store.prune_builds(conn, aid, 1)


@pytest.mark.parametrize("status", ACTIVE)
def test_prune_never_returns_an_active_build_even_when_older_than_final_ones(conn, status):
    """Lewat API, build aktif selalu yang terbaru, sehingga tes di atas tidak bisa membedakan 'dikecualikan' dari 'kebetulan terbaru'.
    Di sini baris aktif SENGAJA lebih tua (id kecil, lewat SQL mentah) daripada deretan build final: ia tetap tidak boleh disebut."""
    aid = make_done_analysis(conn)
    evidence = dict(approved_at=1.0, approval_statement_sha256=SHA_A, approval_statement_version=1) if status != AWAITING else {}
    raw_insert(conn, aid, id=5, status=status, **evidence)
    final = dict(approved_at=1.0, approval_statement_sha256=SHA_A, approval_statement_version=1, verify_ok=1, output_name="a.apk",
                 output_sha256=SHA_A, output_size=1, output_format="apk", cert_sha256=CERT)
    for i in range(6, 9):
        raw_insert(conn, aid, id=i, status="done", **final)
        raw_insert(conn, aid, id=i + 10, status="failed")
    pruned = store.prune_builds(conn, aid, 1)
    assert 5 not in pruned
    assert pruned == [6, 7, 16, 17]


def test_prune_default_follows_build_keep_env(conn, monkeypatch):
    aid = make_done_analysis(conn)
    done = _done_builds(conn, aid, 14)
    monkeypatch.delenv("BUILD_KEEP", raising=False)
    assert store.prune_builds(conn, aid) == done[:4]
    monkeypatch.setenv("BUILD_KEEP", "3")
    assert store.prune_builds(conn, aid) == done[:11]
    monkeypatch.setenv("BUILD_KEEP", "3")
    assert store.prune_builds(conn, aid, keep=12) == done[:2], "argumen eksplisit mengalahkan env"


def test_prune_clamps_keep(conn):
    aid = make_done_analysis(conn)
    done = _done_builds(conn, aid, 3)
    assert store.prune_builds(conn, aid, 0) == done[:2] == store.prune_builds(conn, aid, 1)
    assert store.prune_builds(conn, aid, -7) == done[:2]
    assert store.prune_builds(conn, aid, 500) == []
    for bad in ("3", 2.0, True):
        with pytest.raises(store.BuildInputError):
            store.prune_builds(conn, aid, bad)


def test_prune_counts_nondone_separately_from_done(conn):
    """Deretan build gagal tidak boleh menggusur artefak `done` yang berharga (dan sebaliknya)."""
    aid = make_done_analysis(conn)
    done = _done_builds(conn, aid, 3)
    failed = _done_builds(conn, aid, 12, FAILED)
    assert store.prune_builds(conn, aid, 10) == failed[:2]
    assert not set(done) & set(store.prune_builds(conn, aid, 10))


def test_prune_is_scoped_to_one_analysis(conn):
    a, b = make_done_analysis(conn), make_done_analysis(conn)
    ids_a, ids_b = _done_builds(conn, a, 4), _done_builds(conn, b, 4)
    assert store.prune_builds(conn, a, 2) == ids_a[:2]
    assert store.prune_builds(conn, b, 2) == ids_b[:2]


def test_delete_build_only_removes_final_rows(conn):
    aid = make_done_analysis(conn)
    old = build_in(conn, DONE, aid=aid)
    assert store.delete_build(conn, old) is True and store.get_build(conn, old) is None
    assert store.delete_build(conn, old) is False
    active = build_in(conn, BUILDING, aid=aid)
    assert store.delete_build(conn, active) is False and row(conn, active)["status"] == BUILDING
    assert store.delete_build(conn, 99999) is False


# ================================================================ 14. build_keep()
@pytest.mark.parametrize("raw,expected", [
    (None, 10), ("", 10), (" ", 10), ("abc", 10), ("3", 3), (" 7 ", 7), ("0", 1), ("-5", 1), ("1", 1), ("100", 100), ("999", 100), ("2.5", 10),
])
def test_build_keep_parsing(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("BUILD_KEEP", raising=False)
    else:
        monkeypatch.setenv("BUILD_KEEP", raw)
    assert store.build_keep() == expected


# ================================================================ 15-16. audit
def test_audit_records_each_action_without_content(conn):
    aid = make_done_analysis(conn)
    summary = {"catatan": SECRET}
    b1 = new_build(conn, aid, summary=summary, note=SECRET)           # build_requested
    approve(conn, b1)                                                   # build_approved
    store.fail_build(conn, b1, error_code="tool_error", error_text=SECRET)   # build_failed
    b2 = new_build(conn, aid, summary=summary, note=SECRET)
    store.reject_build(conn, b2, SECRET)                                # build_rejected
    b3 = new_build(conn, aid, summary=summary, note=SECRET)
    assert store.request_cancel_build(conn, b3) == "cancelled"          # build_cancelled
    b4 = build_in(conn, SIGNING, aid=aid)
    finish(conn, b4)                                                    # build_done

    rows = audit_rows(conn)
    names = [a for a, _d in rows]
    for action in ("build_requested", "build_approved", "build_rejected", "build_cancelled", "build_failed", "build_done"):
        assert action in names, action
    assert names.count("build_requested") == 4 and names.count("build_failed") == 1 and names.count("build_rejected") == 1
    everything = " ".join(r[0] for r in conn.execute("SELECT detail FROM audit_log"))
    assert SECRET not in everything, "audit tidak boleh memuat note, diff_summary, error_text, atau alasan"
    for _a, d in rows:
        assert set(d) <= {"build_id", "analysis_id", "requested_by", "source_kind", "diff_sha256", "statement_version", "statement_sha256",
                          "error_code", "from_status", "by", "output_sha256", "output_size", "output_format", "cert_sha256"}
        assert d["build_id"] > 0 and d["analysis_id"] == aid
    approved = dict(rows)["build_approved"]
    assert approved["diff_sha256"] == DIFF and approved["statement_version"] == 1


def test_cancel_audit_distinguishes_request_and_executor(conn):
    store.request_cancel_build(conn, build_in(conn, QUEUED))
    running = build_in(conn, BUILDING)
    store.request_cancel_build(conn, running)
    store.cancel_build(conn, running)
    assert [(d["by"], d["from_status"]) for _a, d in audit_rows(conn, "build_cancelled")] == [("request", QUEUED), ("executor", BUILDING)]


def test_audit_failure_rolls_the_transition_back(conn, monkeypatch):
    """Status berubah <=> audit tercatat: bila audit gagal, tidak ada perubahan setengah jalan."""
    bid = new_build(conn, make_done_analysis(conn))

    def boom(*_a, **_k):
        raise RuntimeError("audit rusak")

    monkeypatch.setattr(store, "audit", boom)
    with pytest.raises(RuntimeError):
        approve(conn, bid)
    r = row(conn, bid)
    assert r["status"] == AWAITING and r["approved_at"] is None
    with pytest.raises(RuntimeError):
        store.reject_build(conn, bid, "x")
    assert row(conn, bid)["status"] == AWAITING


# ================================================================ 17. FK cascade
def test_deleting_the_analysis_removes_its_builds(conn):
    aid = make_done_analysis(conn)
    other = make_done_analysis(conn)
    build_in(conn, DONE, aid=aid)
    build_in(conn, BUILDING, aid=other)
    apk_id = conn.execute("SELECT apk_id FROM analysis WHERE id = ?", (aid,)).fetchone()[0]
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert store.delete_apk(conn, apk_id) == [aid]
    assert conn.execute("SELECT COUNT(*) FROM build WHERE analysis_id = ?", (aid,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM build WHERE analysis_id = ?", (other,)).fetchone()[0] == 1
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_insert_for_unknown_analysis_is_refused_by_the_database(conn):
    with pytest.raises(sqlite3.IntegrityError):
        raw_insert(conn, 31337)


# ================================================================ 18. penjaga CHECK (SQL mentah = pertahanan berlapis)
def raw_insert(conn, aid, **over):
    cols = dict(analysis_id=aid, requested_by="user", source_kind="apk", diff_sha256=DIFF, created_at=1.0, updated_at=1.0)
    cols.update(over)
    names = ", ".join(cols)
    conn.execute(f"INSERT INTO build ({names}) VALUES ({', '.join('?' for _ in cols)})", list(cols.values()))


def test_database_refuses_approved_without_evidence(conn):
    aid = make_done_analysis(conn)
    for status in ("approved", "queued", "building", "signing"):
        with pytest.raises(sqlite3.IntegrityError):
            raw_insert(conn, aid, status=status)
    with pytest.raises(sqlite3.IntegrityError):
        raw_insert(conn, aid, status="approved", approved_at=1.0, approval_statement_sha256=SHA_A)       # tanpa versi
    raw_insert(conn, aid, status="approved", approved_at=1.0, approval_statement_sha256=SHA_A, approval_statement_version=1)


def test_database_refuses_done_without_verification(conn):
    aid = make_done_analysis(conn)
    bid = build_in(conn, SIGNING, aid=aid)
    base = dict(output_name="a.apk", output_sha256=SHA_A, output_size=1, output_format="apk", cert_sha256=CERT)
    for bad in (dict(verify_ok=0), dict(verify_ok=None), dict(verify_ok=1, cert_sha256=None), dict(verify_ok=1, output_name=None)):
        sets = {**base, "status": "done", **bad}
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE build SET " + ", ".join(f"{k} = ?" for k in sets) + " WHERE id = ?", [*sets.values(), bid])
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE build SET output_format = 'xapk' WHERE id = ?", (bid,))        # beda dari source_kind


@pytest.mark.parametrize("over", [
    dict(diff_sha256="D" * 64), dict(diff_sha256="d" * 63), dict(diff_sha256="d" * 63 + "g"), dict(status="ngawur"),
    dict(source_kind="zip"), dict(requested_by="root"), dict(requested_by="ai:x"), dict(cancel_requested=2),
    dict(note="n" * 2001), dict(diff_summary="s" * 8193), dict(verify_ok=2), dict(output_size=-1), dict(error_text="e" * 501),
])
def test_database_refuses_malformed_rows(conn, over):
    with pytest.raises(sqlite3.IntegrityError):
        raw_insert(conn, make_done_analysis(conn), **over)


def test_database_allows_one_active_and_many_final_only(conn):
    aid = make_done_analysis(conn)
    for _ in range(3):
        raw_insert(conn, aid, status="cancelled")
    raw_insert(conn, aid, status="awaiting_approval")
    evidence = dict(approved_at=1.0, approval_statement_sha256=SHA_A, approval_statement_version=1)
    for status in ACTIVE:
        with pytest.raises(sqlite3.IntegrityError):
            raw_insert(conn, aid, status=status, **(evidence if status != AWAITING else {}))


# ================================================================ 19. tidak ada jalur persetujuan palsu
def _public_names():
    return [n for n in dir(store) if not n.startswith("_")]


def test_no_generic_status_setter_exists():
    for name in _public_names():
        assert not re.search(r"set_build_status|force|update_build|build_status_set|override", name, re.I), name


def test_ai_package_cannot_reach_lifecycle_functions():
    """Penjaga SADAR (Tahap 4 hanya boleh memanggil create_build): AI tidak punya tool setujui/antre/ambil/selesaikan/tanda tangan."""
    banned = ("approve_build", "queue_build", "claim_build", "finish_build", "mark_signing", "fail_build", "reject_build",
              "cancel_build", "request_cancel_build", "recover_stuck_builds", "delete_build", "prune_builds")
    offenders = []
    for path in (ROOT / "services/web/app/ai").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        offenders += [(path.name, n) for n in banned if n in text]
    assert offenders == []


def test_only_approve_build_targets_approved():
    """Secara struktur: dari semua fungsi store, hanya approve_build yang memanggil _build_cas dengan tujuan B_APPROVED."""
    tree = ast.parse(inspect.getsource(store))
    targets: dict[str, set[str]] = {}
    for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        for call in (c for c in ast.walk(fn) if isinstance(c, ast.Call) and getattr(c.func, "id", "") == "_build_cas"):
            dest = call.args[3]
            if isinstance(dest, ast.Name):
                targets.setdefault(dest.id, set()).add(fn.name)
    assert targets["B_APPROVED"] == {"approve_build"}
    assert targets["B_DONE"] == {"finish_build"}
    assert targets["B_BUILDING"] == {"claim_build"}
    # UPDATE mentah hanya dua: _build_cas (CAS umum) dan penandaan cancel_requested (status tidak berubah).
    updates = re.findall(r"UPDATE build SET ([\w{}]+)", inspect.getsource(store))
    assert sorted(updates) == ["cancel_requested", "{assignments}"]


# ================================================================ 21. env / compose (pelajaran OP-01)
def _block(name: str) -> str:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    block = compose.split(f"\n  {name}:\n", 1)[1].split("\nnetworks:\n", 1)[0].split("\n  # ", 1)[0]
    return "\n".join(ln for ln in block.splitlines() if not ln.lstrip().startswith("#"))


def test_build_keep_is_forwarded_to_web_and_worker_only():
    for service in ("web", "worker"):
        assert "      BUILD_KEEP: ${BUILD_KEEP:-10}" in _block(service), service
    for service in ("runner", "bench", "egress", "redis", "caddy"):
        assert "BUILD_KEEP" not in _block(service), service


def test_every_build_env_read_by_store_is_forwarded_by_compose():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    src = (ROOT / "services/rvcore/store.py").read_text(encoding="utf-8")
    names = set(re.findall(r'environ(?:\.get)?[\[(]\s*"(BUILD_[A-Z_]+)"', src))
    assert names == {"BUILD_KEEP"}
    for n in names:
        assert n in compose, f"{n} dibaca store.py tetapi tidak diteruskan docker-compose.yml"
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"^#BUILD_KEEP=10$", example, re.M)


def test_compose_gains_no_volume_or_secret_and_stays_clean_for_signing_guard():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    vols = set(re.findall(r"^  ([A-Za-z0-9_]+):", compose.split("\nvolumes:\n", 1)[1].split("\nsecrets:\n", 1)[0], re.M))
    assert vols == {"uploads", "work", "files", "db", "spool", "bench", "benchspool", "redisdata", "caddy_data", "caddy_config"}
    secrets = set(re.findall(r"^  ([A-Za-z0-9_]+):", compose.split("\nsecrets:\n", 1)[1], re.M))
    assert secrets == {"admin_password_hash"}
    # Jaga test_signer_toolchain: web/worker tidak boleh menyebut keystore/signer (komentar sudah dibuang oleh _block).
    for service in ("web", "worker"):
        assert not re.search(r"keystore|signer|SIGNER_", _block(service), re.I), service
