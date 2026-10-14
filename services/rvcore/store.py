"""Operasi basis data tingkat domain (apk, analysis, tahap, log). Dipakai web dan worker.

Aturan: setiap perubahan status memakai UPDATE bersyarat (compare-and-set) sehingga dua proses
yang berlomba (mis. pembatalan vs. worker) tidak saling menimpa status akhir.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import unicodedata
from typing import Any

from .db import tx

# --- status analisis
QUEUED, RUNNING, DONE, FAILED, CANCELLED = "queued", "running", "done", "failed", "cancelled"
ACTIVE = (QUEUED, RUNNING)
TERMINAL = (DONE, FAILED, CANCELLED)

# --- status tahap
PENDING, OK, WARN, SKIPPED = "pending", "ok", "warn", "skipped"
# RUNNING / FAILED / CANCELLED dipakai bersama dengan status analisis.

# Tahap pipeline M1 (urutan = posisi). "Antre" dan "Selesai" diturunkan dari status analisis.
PIPELINE_STAGES: list[tuple[str, str]] = [
    ("validating", "Validasi"),
    ("apktool", "apktool"),
    ("jadx", "jadx"),
    ("analyzing", "Analisis statis"),
]

# Kategori & tingkat temuan yang diterima dari runner (isi berkas tak tepercaya -> divalidasi saat impor).
FINDING_CATEGORIES = (
    "manifest", "signing", "network", "secret", "crypto", "webview", "storage", "native", "obfuscation", "library",
)
FINDING_SEVERITIES = ("info", "low", "medium", "high")
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
STAGE_LABELS = dict(PIPELINE_STAGES)

# Teks UI (satu sumber untuk server-render dan pembaruan live).
STATUS_LABEL = {QUEUED: "Antre", RUNNING: "Berjalan", DONE: "Selesai", FAILED: "Gagal", CANCELLED: "Dibatalkan"}
STATE_LABEL = {
    PENDING: "menunggu", RUNNING: "berjalan", OK: "selesai", WARN: "peringatan",
    FAILED: "gagal", SKIPPED: "dilewati", CANCELLED: "dibatalkan",
}

# Kode galat (error_code) yang dipakai UI.
E_TIMEOUT = "timeout"
E_INTERRUPTED = "interrupted"
E_TOOL = "tool_error"
E_RUNNER = "runner_unavailable"
E_VALIDATION = "validation"
E_OUTPUT_LIMIT = "output_limit"
E_INTERNAL = "internal"
E_CANCELLED = "cancelled"

MAX_LOG_MESSAGE = 500

_APK_META_FIELDS = {"package", "app_label", "version_name", "version_code", "min_sdk", "target_sdk"}


def now() -> float:
    return time.time()


def _text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    s = str(value).replace("\x00", "")
    return s[:limit]


# ------------------------------------------------------------------ pembuatan
def find_apk_by_sha(conn: sqlite3.Connection, sha256: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM apk WHERE sha256 = ?", (sha256,)).fetchone()


def _insert_analysis(conn: sqlite3.Connection, apk_id: int, options: dict[str, Any],
                     ai_enabled: bool) -> int:
    ts = now()
    cur = conn.execute(
        "INSERT INTO analysis (apk_id, status, options, ai_enabled, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (apk_id, QUEUED, json.dumps(options, sort_keys=True), int(ai_enabled), ts, ts),
    )
    analysis_id = int(cur.lastrowid)
    conn.executemany(
        "INSERT INTO analysis_stage (analysis_id, name, position, status) VALUES (?, ?, ?, ?)",
        [(analysis_id, name, pos, PENDING) for pos, (name, _label) in enumerate(PIPELINE_STAGES)],
    )
    return analysis_id


def create_apk_with_analysis(conn: sqlite3.Connection, *, sha256: str, md5: str, filename: str,
                             size: int, options: dict[str, Any]) -> tuple[int, int]:
    """Buat baris apk + analysis (antre). Harus dipanggil di dalam `tx`."""
    cur = conn.execute(
        "INSERT INTO apk (sha256, md5, filename_display, size, created_at) VALUES (?, ?, ?, ?, ?)",
        (sha256, md5, _text(filename, 255) or "unnamed.apk", int(size), now()),
    )
    apk_id = int(cur.lastrowid)
    return apk_id, _insert_analysis(conn, apk_id, options, ai_enabled=False)


def audit(conn: sqlite3.Connection, action: str, detail: dict[str, Any] | None = None) -> None:
    conn.execute(
        "INSERT INTO audit_log (ts, action, detail) VALUES (?, ?, ?)",
        (now(), action, json.dumps(detail or {}, ensure_ascii=False, default=str)),
    )


# ------------------------------------------------------------------ pembacaan
def latest_analysis_id(conn: sqlite3.Connection, apk_id: int) -> int | None:
    row = conn.execute("SELECT MAX(id) FROM analysis WHERE apk_id = ?", (apk_id,)).fetchone()
    return row[0] if row and row[0] is not None else None


def get_analysis(conn: sqlite3.Connection, analysis_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT an.*, a.sha256, a.md5, a.filename_display, a.size, a.package, a.app_label, "
        "       a.version_name, a.version_code, a.min_sdk, a.target_sdk, a.created_at AS apk_created_at "
        "FROM analysis an JOIN apk a ON a.id = an.apk_id WHERE an.id = ?",
        (analysis_id,),
    ).fetchone()


def get_stages(conn: sqlite3.Connection, analysis_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM analysis_stage WHERE analysis_id = ? ORDER BY position", (analysis_id,)
    ).fetchall()


def get_logs(conn: sqlite3.Connection, analysis_id: int, limit: int = 200) -> list[sqlite3.Row]:
    rows = conn.execute(
        "SELECT * FROM analysis_log WHERE analysis_id = ? ORDER BY id DESC LIMIT ?",
        (analysis_id, limit),
    ).fetchall()
    return list(reversed(rows))


def get_artifacts(conn: sqlite3.Connection, analysis_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM artifact WHERE analysis_id = ? ORDER BY id", (analysis_id,)
    ).fetchall()


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_apks(conn: sqlite3.Connection, q: str | None = None, limit: int = 500) -> list[sqlite3.Row]:
    where, params = "", []
    if q:
        pattern = f"%{_like_escape(q.strip().lower())}%"
        where = (
            "WHERE lower(a.filename_display) LIKE ? ESCAPE '\\' OR lower(coalesce(a.package, '')) LIKE ? ESCAPE '\\' "
            "OR lower(coalesce(a.app_label, '')) LIKE ? ESCAPE '\\' OR a.sha256 LIKE ? ESCAPE '\\'"
        )
        params = [pattern, pattern, pattern, pattern]
    return conn.execute(
        "SELECT a.*, an.id AS analysis_id, an.status AS status, an.error_code AS error_code, "
        "       an.started_at AS started_at, an.finished_at AS finished_at, "
        "       (SELECT s.name FROM analysis_stage s WHERE s.analysis_id = an.id AND s.status = 'running' "
        "        LIMIT 1) AS current_stage, "
        "       (SELECT COUNT(*) FROM analysis_stage s WHERE s.analysis_id = an.id AND s.status = 'warn') "
        "        + (SELECT COUNT(*) FROM analysis_stage s WHERE s.analysis_id = an.id AND s.status = 'failed') "
        "        AS problem_stages "
        "FROM apk a LEFT JOIN analysis an ON an.id = (SELECT MAX(id) FROM analysis WHERE apk_id = a.id) "
        f"{where} ORDER BY a.created_at DESC, a.id DESC LIMIT ?",
        [*params, limit],
    ).fetchall()


def queued_analysis_ids(conn: sqlite3.Connection) -> list[int]:
    return [r[0] for r in conn.execute("SELECT id FROM analysis WHERE status = ? ORDER BY id", (QUEUED,))]


def is_cancel_requested(conn: sqlite3.Connection, analysis_id: int) -> bool:
    row = conn.execute("SELECT cancel_requested, status FROM analysis WHERE id = ?", (analysis_id,)).fetchone()
    return bool(row and (row["cancel_requested"] or row["status"] == CANCELLED))


# ------------------------------------------------------------------ siklus hidup (worker)
def claim_analysis(conn: sqlite3.Connection, analysis_id: int) -> bool:
    """queued -> running. False bila sudah dibatalkan/diambil job lain (duplikat di antrean RQ)."""
    ts = now()
    with tx(conn):
        cur = conn.execute(
            "UPDATE analysis SET status = ?, started_at = ?, updated_at = ? "
            "WHERE id = ? AND status = ? AND cancel_requested = 0",
            (RUNNING, ts, ts, analysis_id, QUEUED),
        )
        return cur.rowcount == 1


def set_stage(conn: sqlite3.Connection, analysis_id: int, name: str, status: str,
              detail: str | None = None) -> None:
    ts = now()
    terminal = status not in (PENDING, RUNNING)
    with tx(conn):
        conn.execute(
            "UPDATE analysis_stage SET status = ?, detail = ?, "
            "  started_at = CASE WHEN ? = 'running' THEN ? ELSE started_at END, "
            "  finished_at = CASE WHEN ? THEN ? ELSE NULL END "
            "WHERE analysis_id = ? AND name = ?",
            (status, _text(detail, 300), status, ts, int(terminal), ts, analysis_id, name),
        )
        conn.execute("UPDATE analysis SET updated_at = ? WHERE id = ?", (ts, analysis_id))


def skip_pending_stages(conn: sqlite3.Connection, analysis_id: int, detail: str) -> None:
    with tx(conn):
        conn.execute(
            "UPDATE analysis_stage SET status = ?, detail = ?, finished_at = ? "
            "WHERE analysis_id = ? AND status = ?",
            (SKIPPED, _text(detail, 300), now(), analysis_id, PENDING),
        )


def add_log(conn: sqlite3.Connection, analysis_id: int, stage: str | None, level: str,
            message: str) -> None:
    ts = now()
    with tx(conn):
        conn.execute(
            "INSERT INTO analysis_log (analysis_id, ts, stage, level, message) VALUES (?, ?, ?, ?, ?)",
            (analysis_id, ts, stage, level, _text(message, MAX_LOG_MESSAGE) or ""),
        )
        conn.execute("UPDATE analysis SET updated_at = ? WHERE id = ?", (ts, analysis_id))


def finish_analysis(conn: sqlite3.Connection, analysis_id: int, status: str,
                    error_code: str | None = None, error: str | None = None) -> bool:
    """Set status akhir hanya bila analisis belum berakhir (CAS)."""
    ts = now()
    with tx(conn):
        cur = conn.execute(
            "UPDATE analysis SET status = ?, error_code = ?, error = ?, finished_at = ?, updated_at = ? "
            "WHERE id = ? AND status IN (?, ?)",
            (status, error_code, _text(error, 1000), ts, ts, analysis_id, QUEUED, RUNNING),
        )
        return cur.rowcount == 1


def set_tool_versions(conn: sqlite3.Connection, analysis_id: int, versions: dict[str, Any]) -> None:
    with tx(conn):
        conn.execute(
            "UPDATE analysis SET tool_versions = ?, updated_at = ? WHERE id = ?",
            (json.dumps(versions, ensure_ascii=False, sort_keys=True), now(), analysis_id),
        )


def update_apk_meta(conn: sqlite3.Connection, apk_id: int, **fields: Any) -> None:
    clean = {k: _text(v, 300) for k, v in fields.items() if k in _APK_META_FIELDS}
    if not clean:
        return
    assignments = ", ".join(f"{k} = ?" for k in clean)  # kunci dari allowlist, bukan input pengguna
    with tx(conn):
        conn.execute(f"UPDATE apk SET {assignments} WHERE id = ?", [*clean.values(), apk_id])


def replace_artifacts(conn: sqlite3.Connection, analysis_id: int,
                      items: list[tuple[str, str, int, int]]) -> None:
    """items: (kind, path_relatif, ukuran_byte, jumlah_berkas)."""
    with tx(conn):
        conn.execute("DELETE FROM artifact WHERE analysis_id = ?", (analysis_id,))
        conn.executemany(
            "INSERT INTO artifact (analysis_id, kind, path, size, files) VALUES (?, ?, ?, ?, ?)",
            [(analysis_id, k, p, s, f) for k, p, s, f in items],
        )


# ------------------------------------------------------------------ temuan
def replace_findings(conn: sqlite3.Connection, analysis_id: int, findings: list[dict[str, Any]],
                     source: str = "static") -> int:
    """Ganti seluruh temuan sumber `source`. Setiap temuan sudah divalidasi pemanggil. Mengembalikan jumlahnya."""
    ts = now()
    with tx(conn):
        conn.execute("DELETE FROM finding WHERE analysis_id = ? AND source = ?", (analysis_id, source))
        conn.executemany(
            "INSERT INTO finding (analysis_id, category, severity, rule_id, title, description, evidence, "
            "                     secret, occurrences, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (analysis_id, f["category"], f["severity"], f["rule_id"], f["title"], f.get("description", ""),
                 json.dumps(f.get("evidence", []), ensure_ascii=False), f.get("secret"),
                 int(f.get("occurrences", 1)), source, ts)
                for f in findings
            ],
        )
    return len(findings)


def list_findings(conn: sqlite3.Connection, analysis_id: int, category: str | None = None,
                  severity: str | None = None, q: str | None = None) -> list[sqlite3.Row]:
    where, params = ["analysis_id = ?"], [analysis_id]
    if category:
        where.append("category = ?")
        params.append(category)
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if q:
        where.append("(lower(title) LIKE ? ESCAPE '\\' OR lower(description) LIKE ? ESCAPE '\\' "
                     "OR lower(rule_id) LIKE ? ESCAPE '\\')")
        pat = f"%{_like_escape(q.strip().lower())}%"
        params += [pat, pat, pat]
    return conn.execute(
        "SELECT * FROM finding WHERE " + " AND ".join(where) + " ORDER BY CASE severity "
        "WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, category, id",
        params,
    ).fetchall()


def finding_counts(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any]:
    """{'total': n, 'by_severity': {...}, 'by_category': {...}} untuk ringkasan & filter."""
    by_sev = {r[0]: r[1] for r in conn.execute(
        "SELECT severity, COUNT(*) FROM finding WHERE analysis_id = ? GROUP BY severity", (analysis_id,))}
    by_cat = {r[0]: r[1] for r in conn.execute(
        "SELECT category, COUNT(*) FROM finding WHERE analysis_id = ? GROUP BY category", (analysis_id,))}
    return {"total": sum(by_sev.values()), "by_severity": by_sev, "by_category": by_cat}


def get_finding(conn: sqlite3.Connection, analysis_id: int, finding_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM finding WHERE id = ? AND analysis_id = ?", (finding_id, analysis_id)
    ).fetchone()


# ------------------------------------------------------------------ pencatatan panggilan AI
def record_ai_call(conn: sqlite3.Connection, *, purpose: str, model: str, prompt_tokens: int = 0,
                   completion_tokens: int = 0, cached_tokens: int = 0, cost_credits: float = 0.0,
                   estimated: bool = False, ok: bool = True, error: str | None = None,
                   analysis_id: int | None = None, session_id: int | None = None) -> int:
    with tx(conn):
        cur = conn.execute(
            "INSERT INTO ai_call (analysis_id, session_id, purpose, model, prompt_tokens, completion_tokens, "
            "                     cached_tokens, cost_credits, estimated, ok, error, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (analysis_id, session_id, _text(purpose, 40), _text(model, 120), int(prompt_tokens), int(completion_tokens),
             int(cached_tokens), float(cost_credits), int(estimated), int(ok), _text(error, 300), now()),
        )
        if session_id is not None and cost_credits:
            conn.execute("UPDATE chat_session SET cost_credits = cost_credits + ?, updated_at = ? WHERE id = ?",
                         (float(cost_credits), now(), session_id))
        return int(cur.lastrowid)


def ai_spent(conn: sqlite3.Connection, since: float | None = None, session_id: int | None = None) -> float:
    """Total kredit terpakai (sejak `since`, atau untuk satu sesi chat)."""
    where, params = [], []
    if since is not None:
        where.append("created_at >= ?")
        params.append(since)
    if session_id is not None:
        where.append("session_id = ?")
        params.append(session_id)
    sql = "SELECT COALESCE(SUM(cost_credits), 0) FROM ai_call" + (" WHERE " + " AND ".join(where) if where else "")
    return float(conn.execute(sql, params).fetchone()[0])


# ------------------------------------------------------------------ chat
def create_chat_session(conn: sqlite3.Connection, analysis_id: int, title: str | None = None) -> int:
    ts = now()
    with tx(conn):
        cur = conn.execute("INSERT INTO chat_session (analysis_id, title, created_at, updated_at) VALUES (?, ?, ?, ?)",
                           (analysis_id, _text(title, 120), ts, ts))
        return int(cur.lastrowid)


def get_chat_session(conn: sqlite3.Connection, analysis_id: int, session_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM chat_session WHERE id = ? AND analysis_id = ?", (session_id, analysis_id)).fetchone()


def list_chat_sessions(conn: sqlite3.Connection, analysis_id: int, limit: int = 30) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM chat_session WHERE analysis_id = ? ORDER BY id DESC LIMIT ?", (analysis_id, limit)).fetchall()


def add_chat_message(conn: sqlite3.Connection, session_id: int, role: str, content: str, *, tool_calls: Any = None,
                     citations: Any = None, model: str | None = None) -> int:
    ts = now()
    with tx(conn):
        cur = conn.execute(
            "INSERT INTO chat_message (session_id, role, content, tool_calls, citations, model, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id, role, content, json.dumps(tool_calls, ensure_ascii=False) if tool_calls else None,
             json.dumps(citations, ensure_ascii=False) if citations else None, _text(model, 120), ts))
        conn.execute("UPDATE chat_session SET updated_at = ? WHERE id = ?", (ts, session_id))
        return int(cur.lastrowid)


def get_chat_messages(conn: sqlite3.Connection, session_id: int, limit: int | None = None) -> list[sqlite3.Row]:
    """Semua pesan sesi (limit=None -> tanpa batas; SQLite: LIMIT -1)."""
    rows = conn.execute("SELECT * FROM chat_message WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                        (session_id, -1 if limit is None else limit)).fetchall()
    return list(reversed(rows))


def delete_chat_session(conn: sqlite3.Connection, analysis_id: int, session_id: int) -> bool:
    with tx(conn):
        return conn.execute("DELETE FROM chat_session WHERE id = ? AND analysis_id = ?", (session_id, analysis_id)).rowcount == 1


# ------------------------------------------------------------------ berkas: lampiran pengguna & buatan AI
class FileQuotaError(Exception):
    """Kuota berkas per analisis terlampaui (ukuran total atau jumlah). Pesan aman ditampilkan."""


_FILE_COLS = "id, analysis_id, kind, path, name, media, mime, size, sha256, revision, pending, created_at, updated_at"


def files_usage(conn: sqlite3.Connection, analysis_id: int) -> tuple[int, int]:
    """(total_byte, jumlah_berkas) milik analisis ini, termasuk unggahan yang belum dikirim."""
    row = conn.execute("SELECT COALESCE(SUM(size), 0), COUNT(*) FROM analysis_file WHERE analysis_id = ?", (analysis_id,)).fetchone()
    return int(row[0]), int(row[1])


def _check_quota(conn: sqlite3.Connection, analysis_id: int, add_bytes: int, add_count: int,
                 quota_bytes: int, max_count: int) -> None:
    used, count = files_usage(conn, analysis_id)
    if quota_bytes and used + add_bytes > quota_bytes:
        raise FileQuotaError(f"Kuota berkas analisis ini penuh ({used // (1024 * 1024)} dari {quota_bytes // (1024 * 1024)} MB). "
                             "Hapus berkas lama di tab Berkas, atau naikkan FILES_QUOTA_MB di .env.")
    if max_count and add_count > 0 and count + add_count > max_count:   # menimpa berkas yang ada tidak menambah jumlah
        raise FileQuotaError(f"Jumlah berkas analisis ini sudah {count} (batas {max_count}). Hapus yang tidak dipakai di tab Berkas.")


def add_upload(conn: sqlite3.Connection, analysis_id: int, *, path: str, name: str, media: str, mime: str, size: int,
               sha256: str, quota_bytes: int = 0, max_count: int = 0) -> int:
    """Catat lampiran pengguna (pending=1 sampai dikirim bersama pesan)."""
    ts = now()
    with tx(conn):
        _check_quota(conn, analysis_id, size, 1, quota_bytes, max_count)
        cur = conn.execute(
            "INSERT INTO analysis_file (analysis_id, kind, path, name, media, mime, size, sha256, pending, created_at, updated_at) "
            "VALUES (?, 'upload', ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (analysis_id, path, _text(name, 255) or "berkas", media, mime[:80], size, sha256, ts, ts))
        return int(cur.lastrowid)


def upsert_ai_file(conn: sqlite3.Connection, analysis_id: int, *, path: str, media: str, mime: str, size: int, sha256: str,
                   quota_bytes: int = 0, max_count: int = 0) -> tuple[int, int, bool]:
    """Catat berkas buatan AI. Path yang sama = revisi baru. Mengembalikan (id, revisi, baru?)."""
    ts = now()
    name = path.rsplit("/", 1)[-1]
    with tx(conn):
        old = conn.execute("SELECT id, size, revision FROM analysis_file WHERE analysis_id = ? AND kind = 'ai' AND path = ?",
                           (analysis_id, path)).fetchone()
        _check_quota(conn, analysis_id, size - (old["size"] if old else 0), 0 if old else 1, quota_bytes, max_count)
        if old:
            conn.execute("UPDATE analysis_file SET size = ?, sha256 = ?, media = ?, mime = ?, revision = revision + 1, updated_at = ? "
                         "WHERE id = ?", (size, sha256, media, mime[:80], ts, old["id"]))
            return int(old["id"]), int(old["revision"]) + 1, False
        cur = conn.execute(
            "INSERT INTO analysis_file (analysis_id, kind, path, name, media, mime, size, sha256, pending, created_at, updated_at) "
            "VALUES (?, 'ai', ?, ?, ?, ?, ?, ?, 0, ?, ?)", (analysis_id, path, name, media, mime[:80], size, sha256, ts, ts))
        return int(cur.lastrowid), 1, True


def get_file(conn: sqlite3.Connection, analysis_id: int, file_id: int) -> sqlite3.Row | None:
    return conn.execute(f"SELECT {_FILE_COLS} FROM analysis_file WHERE id = ? AND analysis_id = ?", (file_id, analysis_id)).fetchone()


def find_file(conn: sqlite3.Connection, analysis_id: int, kind: str, path: str) -> sqlite3.Row | None:
    return conn.execute(f"SELECT {_FILE_COLS} FROM analysis_file WHERE analysis_id = ? AND kind = ? AND path = ?",
                        (analysis_id, kind, path)).fetchone()


def list_files(conn: sqlite3.Connection, analysis_id: int, kind: str | None = None, *, include_pending: bool = False,
               limit: int | None = None, offset: int = 0) -> list[sqlite3.Row]:
    """Berkas satu analisis, urut id. `limit`/`offset` untuk paginasi halaman Berkas (limit=None -> semua, dipakai ZIP & tool AI)."""
    sql = f"SELECT {_FILE_COLS} FROM analysis_file WHERE analysis_id = ?"
    params: list[Any] = [analysis_id]
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    if not include_pending:
        sql += " AND pending = 0"
    sql += " ORDER BY id LIMIT ? OFFSET ?"
    params += [-1 if limit is None else limit, max(0, offset)]
    return conn.execute(sql, params).fetchall()


def count_files(conn: sqlite3.Connection, analysis_id: int, kind: str | None = None) -> int:
    sql = "SELECT COUNT(*) FROM analysis_file WHERE analysis_id = ? AND pending = 0"
    params: list[Any] = [analysis_id]
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    return int(conn.execute(sql, params).fetchone()[0])


def pending_uploads(conn: sqlite3.Connection, analysis_id: int, ids: list[int]) -> list[sqlite3.Row]:
    """Lampiran yang boleh dikirim sekarang: milik analisis ini, jenis upload, belum terkait pesan mana pun. Urutan = urutan `ids`."""
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    rows = conn.execute(f"SELECT {_FILE_COLS} FROM analysis_file WHERE analysis_id = ? AND kind = 'upload' AND pending = 1 "
                        f"AND id IN ({marks})", [analysis_id, *ids]).fetchall()
    by_id = {r["id"]: r for r in rows}
    return [by_id[i] for i in ids if i in by_id]


def attach_uploads(conn: sqlite3.Connection, message_id: int, analysis_id: int, ids: list[int]) -> list[sqlite3.Row]:
    """Kaitkan lampiran dengan pesan pengguna (pending -> 0). Hanya yang masih pending dan milik analisis ini."""
    rows = pending_uploads(conn, analysis_id, ids)
    claimed: list[sqlite3.Row] = []
    with tx(conn):
        for r in rows:
            # Compare-and-set: bila pengiriman lain sudah mengklaim lampiran ini, jangan ikut mengaitkannya.
            if conn.execute("UPDATE analysis_file SET pending = 0 WHERE id = ? AND pending = 1", (r["id"],)).rowcount == 1:
                conn.execute("INSERT OR IGNORE INTO message_file (message_id, file_id, role, revision) VALUES (?, ?, 'attachment', ?)",
                             (message_id, r["id"], r["revision"]))
                claimed.append(r)
    return claimed


def link_outputs(conn: sqlite3.Connection, message_id: int, items: list[tuple[int, int]]) -> None:
    """Kaitkan berkas buatan AI dengan jawaban yang membuatnya: [(file_id, revisi)]."""
    if not items:
        return
    with tx(conn):
        for file_id, revision in items:
            conn.execute("INSERT OR REPLACE INTO message_file (message_id, file_id, role, revision) "
                         "SELECT ?, id, 'output', ? FROM analysis_file WHERE id = ?", (message_id, revision, file_id))


def files_for_messages(conn: sqlite3.Connection, message_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
    """Berkas per pesan: {message_id: [{...kolom berkas, role, link_revision}]} urut id berkas."""
    if not message_ids:
        return {}
    marks = ",".join("?" * len(message_ids))
    rows = conn.execute(
        "SELECT mf.message_id, mf.role, mf.revision AS link_revision, f.id, f.analysis_id, f.kind, f.path, f.name, f.media, f.mime, f.size, f.revision "
        f"FROM message_file mf JOIN analysis_file f ON f.id = mf.file_id WHERE mf.message_id IN ({marks}) ORDER BY f.id", message_ids).fetchall()
    out: dict[int, list[dict[str, Any]]] = {}
    for r in rows:
        out.setdefault(int(r["message_id"]), []).append(dict(r))
    return out


def delete_file_row(conn: sqlite3.Connection, analysis_id: int, file_id: int) -> sqlite3.Row | None:
    """Hapus catatan berkas (isi di disk dihapus oleh pemanggil). Mengembalikan baris yang dihapus, atau None."""
    with tx(conn):
        row = conn.execute(f"SELECT {_FILE_COLS} FROM analysis_file WHERE id = ? AND analysis_id = ?", (file_id, analysis_id)).fetchone()
        if row is not None:
            conn.execute("DELETE FROM analysis_file WHERE id = ?", (file_id,))
        return row


def stale_pending_uploads(conn: sqlite3.Connection, analysis_id: int, older_than: float) -> list[sqlite3.Row]:
    return conn.execute(f"SELECT {_FILE_COLS} FROM analysis_file WHERE analysis_id = ? AND kind = 'upload' AND pending = 1 "
                        "AND created_at < ?", (analysis_id, older_than)).fetchall()


# ------------------------------------------------------------------ aksi pengguna (web)
def request_cancel(conn: sqlite3.Connection, analysis_id: int) -> str:
    """'cancelled' (antre, langsung batal) | 'requested' (sedang jalan) | 'noop'."""
    ts = now()
    with tx(conn):
        cur = conn.execute(
            "UPDATE analysis SET status = ?, error_code = ?, error = ?, finished_at = ?, updated_at = ?, "
            "  cancel_requested = 1 WHERE id = ? AND status = ?",
            (CANCELLED, E_CANCELLED, "Dibatalkan sebelum berjalan.", ts, ts, analysis_id, QUEUED),
        )
        if cur.rowcount == 1:
            conn.execute(
                "UPDATE analysis_stage SET status = ?, detail = ?, finished_at = ? "
                "WHERE analysis_id = ? AND status = ?",
                (SKIPPED, "dibatalkan", ts, analysis_id, PENDING),
            )
            return "cancelled"
        cur = conn.execute(
            "UPDATE analysis SET cancel_requested = 1, updated_at = ? WHERE id = ? AND status = ?",
            (ts, analysis_id, RUNNING),
        )
        return "requested" if cur.rowcount == 1 else "noop"


def reset_for_retry(conn: sqlite3.Connection, analysis_id: int, only_stage: str | None = None) -> bool:
    """Siapkan analisis yang sudah berakhir untuk dijalankan ulang. False bila masih aktif.

    only_stage: ulangi HANYA tahap itu (hasil apktool/jadx dipertahankan; FR-2.9). Tahap lain tidak disentuh.
    """
    ts = now()
    if only_stage is not None:
        if only_stage != "analyzing":
            raise ValueError("hanya tahap 'analyzing' yang bisa diulang sendiri")
        with tx(conn):
            cur = conn.execute(
                "UPDATE analysis SET status = ?, attempt = attempt + 1, cancel_requested = 0, "
                "  error_code = NULL, error = NULL, started_at = NULL, finished_at = NULL, "
                "  created_at = ?, updated_at = ? WHERE id = ? AND status IN (?, ?, ?)",
                (QUEUED, ts, ts, analysis_id, DONE, FAILED, CANCELLED),
            )
            if cur.rowcount != 1:
                return False
            conn.execute(
                "UPDATE analysis_stage SET status = ?, detail = NULL, started_at = NULL, finished_at = NULL "
                "WHERE analysis_id = ? AND name = ?",
                (PENDING, analysis_id, only_stage),
            )
            conn.execute("DELETE FROM finding WHERE analysis_id = ?", (analysis_id,))
            # Baris log TANPA tahap (ringkasan akhir seperti "Semua tahap selesai.") ikut dihapus: tanpa ini, tiap ulang statis
            # menambah satu baris duplikat yang tidak pernah dibersihkan.
            conn.execute("DELETE FROM analysis_log WHERE analysis_id = ? AND (stage = ? OR stage IS NULL)", (analysis_id, only_stage))
            return True
    with tx(conn):
        cur = conn.execute(
            "UPDATE analysis SET status = ?, attempt = attempt + 1, cancel_requested = 0, "
            "  error_code = NULL, error = NULL, tool_versions = NULL, started_at = NULL, "
            "  finished_at = NULL, created_at = ?, updated_at = ? "
            "WHERE id = ? AND status IN (?, ?, ?)",
            (QUEUED, ts, ts, analysis_id, DONE, FAILED, CANCELLED),
        )
        if cur.rowcount != 1:
            return False
        conn.execute(
            "UPDATE analysis_stage SET status = ?, detail = NULL, started_at = NULL, finished_at = NULL "
            "WHERE analysis_id = ?",
            (PENDING, analysis_id),
        )
        conn.execute("DELETE FROM analysis_log WHERE analysis_id = ?", (analysis_id,))
        conn.execute("DELETE FROM artifact WHERE analysis_id = ?", (analysis_id,))
        conn.execute("DELETE FROM finding WHERE analysis_id = ?", (analysis_id,))
        return True


def delete_apk(conn: sqlite3.Connection, apk_id: int) -> list[int] | None:
    """Hapus apk beserta analisisnya. None bila masih ada analisis aktif. Mengembalikan id analisis terhapus."""
    with tx(conn):
        active = conn.execute(
            "SELECT 1 FROM analysis WHERE apk_id = ? AND status IN (?, ?) LIMIT 1", (apk_id, QUEUED, RUNNING)
        ).fetchone()
        if active:
            return None
        ids = [r[0] for r in conn.execute("SELECT id FROM analysis WHERE apk_id = ?", (apk_id,))]
        conn.execute("DELETE FROM apk WHERE id = ?", (apk_id,))  # CASCADE ke analysis, tahap, log, artefak
        return ids


# ------------------------------------------------------------------ pemulihan setelah restart
def mark_interrupted(conn: sqlite3.Connection) -> list[int]:
    """Analisis 'running' yang ditinggal proses mati -> failed (NFR-2.3). Bisa di-retry dari UI."""
    ts = now()
    with tx(conn):
        ids = [r[0] for r in conn.execute("SELECT id FROM analysis WHERE status = ?", (RUNNING,))]
        for analysis_id in ids:
            conn.execute(
                "UPDATE analysis SET status = ?, error_code = ?, error = ?, finished_at = ?, updated_at = ? "
                "WHERE id = ?",
                (FAILED, E_INTERRUPTED,
                 "Terputus karena server/worker dimulai ulang saat job berjalan. Coba lagi.", ts, ts, analysis_id),
            )
            conn.execute(
                "UPDATE analysis_stage SET status = ?, detail = ?, finished_at = ? "
                "WHERE analysis_id = ? AND status = ?",
                (FAILED, "terputus", ts, analysis_id, RUNNING),
            )
            conn.execute(
                "UPDATE analysis_stage SET status = ?, detail = ?, finished_at = ? "
                "WHERE analysis_id = ? AND status = ?",
                (SKIPPED, "terputus", ts, analysis_id, PENDING),
            )
            conn.execute(
                "INSERT INTO analysis_log (analysis_id, ts, stage, level, message) VALUES (?, ?, NULL, 'error', ?)",
                (analysis_id, ts, "Job terputus karena restart; ditandai gagal. Gunakan “Coba lagi”."),
            )
    return ids


# ------------------------------------------------------------------ potret untuk UI / SSE
def build_steps(status: str, stages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    """Stepper (Antre -> tahap... -> Selesai) dan teks ringkasan untuk `role=status`.

    Dihitung di sini (bukan di JS/template) supaya tampilan awal dan pembaruan SSE identik.
    """
    steps: list[dict[str, Any]] = [
        {"key": "queued", "label": "Antre", "state": RUNNING if status == QUEUED else OK, "detail": None}
    ]
    for s in stages:
        steps.append({"key": s["name"], "label": s["label"], "state": s["status"], "detail": s["detail"]})
    final_state = {DONE: OK, CANCELLED: CANCELLED}.get(status, PENDING)
    steps.append({"key": "done", "label": "Selesai", "state": final_state, "detail": None})
    for step in steps:
        step["state_label"] = STATE_LABEL.get(step["state"], step["state"])

    total = len(steps)
    running = next((i for i, s in enumerate(steps) if s["state"] == RUNNING), None)
    if status == QUEUED:
        summary = f"Langkah 1 dari {total}: menunggu giliran di antrean"
    elif status == RUNNING and running is not None:
        summary = f"Langkah {running + 1} dari {total}: {steps[running]['label']} berjalan"
    elif status == RUNNING:
        summary = "Sedang diproses"
    elif status == DONE:
        problems = [s["label"] for s in steps if s["state"] in (WARN, FAILED)]
        summary = "Selesai" if not problems else "Selesai dengan peringatan: " + ", ".join(problems)
    elif status == CANCELLED:
        summary = "Dibatalkan"
    else:
        failed = next((s for s in steps if s["state"] == FAILED), None)
        summary = f"Gagal pada tahap {failed['label']}" if failed else "Gagal"
    return steps, summary


def analysis_snapshot(conn: sqlite3.Connection, analysis_id: int, log_limit: int = 120) -> dict[str, Any] | None:
    an = get_analysis(conn, analysis_id)
    if an is None:
        return None
    stages = [
        {"name": s["name"], "label": STAGE_LABELS.get(s["name"], s["name"]), "status": s["status"],
         "detail": s["detail"], "started_at": s["started_at"], "finished_at": s["finished_at"]}
        for s in get_stages(conn, analysis_id)
    ]
    logs = [
        {"id": r["id"], "ts": r["ts"], "stage": r["stage"], "level": r["level"], "message": r["message"]}
        for r in get_logs(conn, analysis_id, log_limit)
    ]
    problems = sum(1 for s in stages if s["status"] in (WARN, FAILED))
    steps, summary = build_steps(an["status"], stages)
    if an["status"] == RUNNING and an["cancel_requested"]:
        summary += " — pembatalan diminta, menghentikan…"
    return {
        "id": an["id"],
        "status": an["status"],
        "status_label": STATUS_LABEL.get(an["status"], an["status"]),
        "terminal": an["status"] in TERMINAL,
        "error_code": an["error_code"],
        "error": an["error"],
        "attempt": an["attempt"],
        "cancel_requested": bool(an["cancel_requested"]),
        "started_at": an["started_at"],
        "finished_at": an["finished_at"],
        "problem_stages": problems,
        "package": an["package"],
        "stages": stages,
        "steps": steps,
        "summary": summary,
        "logs": logs,
        "server_now": now(),
    }


# ================================================================== build APK (Tahap 1: tabel `build` + state machine)
# Aturan: SEMUA perubahan status lewat UPDATE ... WHERE id = ? AND status = ? (CAS) dan rowcount diperiksa; tabel transisi
# BUILD_TRANSITIONS adalah satu-satunya sumber kebenaran. Tidak ada fungsi "set status" generik. 'approved' HANYA bisa dicapai lewat
# approve_build (yang menuntut diff_sha256 sama persis dengan yang tercatat) -> AI/kode lain tidak punya jalan untuk memalsukan persetujuan.
# Setiap fungsi yang menulis membuka `tx` sendiri: pemanggil TIDAK boleh sedang berada di dalam `tx` (SQLite tak mengenal BEGIN bersarang).
# Penghapusan DIREKTORI artefak build (/data/builds/<analysis_id>/<build_id>/) baru dikerjakan Tahap 2; di sini hanya baris DB
# (hapus analisis -> baris build ikut hilang lewat ON DELETE CASCADE; prune_builds hanya MENYEBUTKAN id, tidak menghapus apa pun).
B_AWAITING, B_APPROVED, B_QUEUED, B_BUILDING, B_SIGNING = "awaiting_approval", "approved", "queued", "building", "signing"
B_DONE, B_REJECTED, B_FAILED, B_CANCELLED = "done", "rejected", "failed", "cancelled"
BUILD_STATUSES = (B_AWAITING, B_APPROVED, B_QUEUED, B_BUILDING, B_SIGNING, B_DONE, B_REJECTED, B_FAILED, B_CANCELLED)
BUILD_ACTIVE = (B_AWAITING, B_APPROVED, B_QUEUED, B_BUILDING, B_SIGNING)    # = predikat indeks unik parsial di db.py (v5)
BUILD_RUNNING = (B_BUILDING, B_SIGNING)
BUILD_FINAL = (B_DONE, B_REJECTED, B_FAILED, B_CANCELLED)

# dari -> himpunan tujuan yang SAH. Status final tidak punya jalan keluar.
BUILD_TRANSITIONS: dict[str, frozenset[str]] = {
    B_AWAITING: frozenset({B_APPROVED, B_REJECTED, B_CANCELLED}),
    B_APPROVED: frozenset({B_QUEUED, B_FAILED, B_CANCELLED}),
    B_QUEUED: frozenset({B_BUILDING, B_FAILED, B_CANCELLED}),
    B_BUILDING: frozenset({B_SIGNING, B_FAILED, B_CANCELLED}),
    B_SIGNING: frozenset({B_DONE, B_FAILED, B_CANCELLED}),
    B_DONE: frozenset(),
    B_REJECTED: frozenset(),
    B_FAILED: frozenset(),
    B_CANCELLED: frozenset(),
}

BUILD_STATUS_LABEL = {
    B_AWAITING: "Menunggu persetujuan", B_APPROVED: "Disetujui", B_QUEUED: "Antre", B_BUILDING: "Membangun",
    B_SIGNING: "Menandatangani", B_DONE: "Selesai", B_REJECTED: "Ditolak", B_FAILED: "Gagal", B_CANCELLED: "Dibatalkan",
}

BUILD_SOURCE_KINDS = ("apk", "xapk", "apks")
BUILD_NOTE_MAX, BUILD_SUMMARY_MAX, BUILD_ERROR_MAX, BUILD_REASON_MAX, BUILD_STAGE_LOG_MAX = 2000, 8192, 500, 500, 4000
BUILD_KEEP_DEFAULT, BUILD_KEEP_MIN, BUILD_KEEP_MAX = 10, 1, 100

# Pernyataan wewenang yang ditampilkan saat pengguna menyetujui build. SATU sumber kebenaran untuk UI (Tahap 5) dan store.
# Teks versi yang sudah dipakai TIDAK BOLEH diubah (hash-nya tersimpan di baris build): ubah teks = tambah versi baru.
APPROVAL_STATEMENT_VERSION = 1
APPROVAL_STATEMENTS: dict[int, str] = {
    1: "Saya berwenang memodifikasi APK ini dan hasilnya hanya untuk riset pribadi di perangkat saya.",
}

_REQUESTED_BY_RE = re.compile(r"(user|ai:[0-9]{1,18})")
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_OUTPUT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}")
_ERROR_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,39}")
# Path internal (kontainer) yang tidak boleh sampai ke layar: /data/work/12/..., /tmp/x, /opt/...
_INTERNAL_PATH_RE = re.compile(
    r"(?<![\w<])/(?:data|tmp|opt|app|run|home|work|out|in|w|usr|var|etc|proc|root|mnt|srv|lib|bin|sbin|dev|sys)(?![\w-])"
    r"(?:/[^\s'\"`]*)?"
)
# Pengendali arah tulisan (bisa memalsukan tampilan teks di layar persetujuan) dibuang bersama karakter kontrol.
_BIDI_CHARS = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


class BuildError(Exception):
    """Dasar galat build. Pesan berbahasa Indonesia dan aman ditampilkan ke pengguna."""


class BuildInputError(BuildError, ValueError):
    """Argumen tidak valid (heks, panjang, source_kind, nama berkas, ...)."""


class BuildStateError(BuildError):
    """Transisi tak sah, build tidak ada, kalah balapan, analisis belum siap, atau sudah ada build aktif."""


class BuildDiffMismatchError(BuildStateError):
    """Persetujuan ditolak: diff yang disetujui tidak sama dengan diff yang tercatat (diff berubah setelah diajukan)."""


# ------------------------------------------------------------------ pernyataan wewenang
def approval_statement(version: int = APPROVAL_STATEMENT_VERSION) -> str:
    if type(version) is not int or version not in APPROVAL_STATEMENTS:
        raise BuildInputError("Versi pernyataan wewenang tidak dikenal.")
    return APPROVAL_STATEMENTS[version]


def approval_statement_sha256(version: int = APPROVAL_STATEMENT_VERSION) -> str:
    return hashlib.sha256(approval_statement(version).encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ konfigurasi
def build_keep() -> int:
    """Jumlah build final yang disimpan per analisis (env BUILD_KEEP; bawaan 10, klem 1-100; nilai rusak -> bawaan)."""
    raw = os.environ.get("BUILD_KEEP", "").strip()
    try:
        value = int(raw)
    except ValueError:
        return BUILD_KEEP_DEFAULT
    return max(BUILD_KEEP_MIN, min(BUILD_KEEP_MAX, value))


# ------------------------------------------------------------------ pembantu privat
def _require_id(name: str, value: object) -> int:
    if type(value) is not int or value <= 0:
        raise BuildInputError(f"{name} harus bilangan bulat positif.")
    return value


def _require_hex64(name: str, value: object) -> str:
    if type(value) is not str or not _HEX64_RE.fullmatch(value):
        raise BuildInputError(f"{name} harus 64 karakter heksadesimal huruf kecil (SHA-256).")
    return value


def _clean_text(value: Any, limit: int, *, multiline: bool = False, scrub: bool = False) -> str:
    """Teks bebas (dari AI/pengguna, tak tepercaya): buang NUL/kontrol/pengendali arah, rapikan baris, potong ke `limit`."""
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    keep = "\n\t" if multiline else ""
    if not multiline:
        text = re.sub(r"\s+", " ", text)      # SEBELUM menyaring kontrol: '\n' juga karakter kontrol, jangan sampai menempelkan kata
    text = "".join(
        ch for ch in text
        if ch in keep or (ch not in _BIDI_CHARS and unicodedata.category(ch) not in ("Cc", "Cs"))
    )
    if multiline:
        text = re.sub(r"[ \t]+\n", "\n", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()
    if scrub:
        text = _INTERNAL_PATH_RE.sub("<path>", text)
    return text[:limit].rstrip()


def _build_cas(conn: sqlite3.Connection, build_id: int, from_statuses: tuple[str, ...], to_status: str, *,
               where: str = "", params: tuple = (), **cols: Any) -> bool:
    """UPDATE bersyarat (CAS): berhasil hanya bila status MASIH salah satu `from_statuses` (+ `where`). Harus di dalam `tx`.

    Menegaskan bahwa setiap (dari, ke) ada di BUILD_TRANSITIONS sebelum SQL dijalankan: salah tulis di kode = AssertionError,
    bukan transisi gelap. Nama kolom `cols` berasal dari kode (bukan input pengguna).
    """
    for frm in from_statuses:
        assert to_status in BUILD_TRANSITIONS[frm], f"transisi build {frm} -> {to_status} tidak ada di BUILD_TRANSITIONS"
    cols = {"status": to_status, "updated_at": now(), **cols}
    assignments = ", ".join(f"{k} = ?" for k in cols)
    marks = ", ".join("?" for _ in from_statuses)
    cur = conn.execute(
        f"UPDATE build SET {assignments} WHERE id = ? AND status IN ({marks})" + (f" AND {where}" if where else ""),
        [*cols.values(), build_id, *from_statuses, *params],
    )
    return cur.rowcount == 1


def _build_row(conn: sqlite3.Connection, build_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM build WHERE id = ?", (build_id,)).fetchone()
    if row is None:
        raise BuildStateError("Build tidak ditemukan.")
    return row


def _state_error(conn: sqlite3.Connection, build_id: int, verb: str) -> BuildStateError:
    """Galat untuk CAS yang gagal: jelaskan status saat ini (membaca ulang di dalam `tx` yang sama)."""
    row = conn.execute("SELECT status, cancel_requested FROM build WHERE id = ?", (build_id,)).fetchone()
    if row is None:
        return BuildStateError("Build tidak ditemukan.")
    label = BUILD_STATUS_LABEL.get(row["status"], row["status"])
    if row["status"] in BUILD_RUNNING and row["cancel_requested"]:
        return BuildStateError(f"Build #{build_id} berstatus “{label}” dan pembatalan sudah diminta; tidak bisa {verb}.")
    return BuildStateError(f"Build #{build_id} berstatus “{label}”; tidak bisa {verb}.")


def _audit_build(conn: sqlite3.Connection, action: str, row: sqlite3.Row, **extra: Any) -> None:
    """Audit ringkas: hanya id/hash/ukuran/kode. TIDAK PERNAH note, diff_summary, error_text, alasan, atau path."""
    audit(conn, action, {"build_id": row["id"], "analysis_id": row["analysis_id"], **extra})


def _bool01(name: str, value: Any, allowed: tuple = (0, 1)) -> int:
    if type(value) not in (int, bool) or int(value) not in allowed:
        raise BuildInputError(f"{name} tidak valid.")
    return int(value)


# ------------------------------------------------------------------ pembuatan & pembacaan
def create_build(conn: sqlite3.Connection, analysis_id: int, *, requested_by: str, source_kind: str, diff_sha256: str,
                 diff_summary: dict[str, Any], note: str = "") -> int:
    """Ajukan build baru (status awaiting_approval). Butuh analisis 'done' dengan hasil apktool; maksimum SATU build aktif per analisis."""
    _require_id("analysis_id", analysis_id)
    if type(requested_by) is not str or not _REQUESTED_BY_RE.fullmatch(requested_by):
        raise BuildInputError("requested_by harus 'user' atau 'ai:<id sesi chat>'.")
    if source_kind not in BUILD_SOURCE_KINDS:
        raise BuildInputError("Format asal harus apk, xapk, atau apks.")
    _require_hex64("diff_sha256", diff_sha256)
    if not isinstance(diff_summary, dict):
        raise BuildInputError("Ringkasan diff harus berupa objek.")
    try:
        summary = json.dumps(diff_summary, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        raise BuildInputError("Ringkasan diff tidak bisa diserialisasi.") from None
    if len(summary) > BUILD_SUMMARY_MAX:      # JSON terpotong = rusak, jadi ditolak, bukan dipotong
        raise BuildInputError(f"Ringkasan diff terlalu besar (maksimum {BUILD_SUMMARY_MAX} karakter).")
    note = _clean_text(note, BUILD_NOTE_MAX, multiline=True)
    ts = now()
    with tx(conn):
        an = conn.execute("SELECT status FROM analysis WHERE id = ?", (analysis_id,)).fetchone()
        if an is None:
            raise BuildStateError("Analisis tidak ditemukan.")
        if an["status"] != DONE:
            label = STATUS_LABEL.get(an["status"], an["status"])
            raise BuildStateError(f"Analisis belum siap (status: {label}). Tunggu sampai selesai.")
        stage = conn.execute(
            "SELECT status FROM analysis_stage WHERE analysis_id = ? AND name = 'apktool'", (analysis_id,)
        ).fetchone()
        if stage is None or stage["status"] not in (OK, WARN):
            raise BuildStateError("Hasil apktool tidak tersedia untuk analisis ini; tidak bisa dibangun.")
        marks = ", ".join("?" for _ in BUILD_ACTIVE)
        act = conn.execute(
            f"SELECT id, status FROM build WHERE analysis_id = ? AND status IN ({marks}) ORDER BY id DESC LIMIT 1",
            (analysis_id, *BUILD_ACTIVE),
        ).fetchone()
        if act is not None:
            raise _active_build_error(act)
        try:
            cur = conn.execute(
                "INSERT INTO build (analysis_id, status, requested_by, source_kind, diff_sha256, diff_summary, note, "
                "                   created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (analysis_id, B_AWAITING, requested_by, source_kind, diff_sha256, summary, note, ts, ts),
            )
        except sqlite3.IntegrityError as exc:       # jaring pengaman: indeks unik parsial (build aktif kedua)
            raise BuildStateError("Sudah ada build aktif untuk analisis ini. Batalkan atau tunggu sampai selesai.") from exc
        build_id = int(cur.lastrowid)
        audit(conn, "build_requested", {
            "build_id": build_id, "analysis_id": analysis_id, "requested_by": requested_by,
            "source_kind": source_kind, "diff_sha256": diff_sha256,
        })
    return build_id


def _active_build_error(row: sqlite3.Row) -> BuildStateError:
    label = BUILD_STATUS_LABEL.get(row["status"], row["status"])
    return BuildStateError(f"Sudah ada build aktif (#{row['id']}, {label}). Batalkan atau tunggu sampai selesai.")


def get_build(conn: sqlite3.Connection, build_id: int, *, analysis_id: int | None = None) -> sqlite3.Row | None:
    """analysis_id diberikan -> cakupan per analisis (rute tidak boleh membuka build milik analisis lain)."""
    if analysis_id is None:
        return conn.execute("SELECT * FROM build WHERE id = ?", (build_id,)).fetchone()
    return conn.execute("SELECT * FROM build WHERE id = ? AND analysis_id = ?", (build_id, analysis_id)).fetchone()


def list_builds(conn: sqlite3.Connection, analysis_id: int, limit: int = 50) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM build WHERE analysis_id = ? ORDER BY id DESC LIMIT ?", (analysis_id, limit)
    ).fetchall()


def active_build(conn: sqlite3.Connection, analysis_id: int) -> sqlite3.Row | None:
    marks = ", ".join("?" for _ in BUILD_ACTIVE)
    return conn.execute(
        f"SELECT * FROM build WHERE analysis_id = ? AND status IN ({marks}) ORDER BY id DESC LIMIT 1",
        (analysis_id, *BUILD_ACTIVE),
    ).fetchone()


def build_ids_by_status(conn: sqlite3.Connection, *statuses: str, limit: int = 1000) -> list[int]:
    bad = [s for s in statuses if s not in BUILD_STATUSES]
    if bad or not statuses:
        raise BuildInputError("Status build tidak dikenal.")
    marks = ", ".join("?" for _ in statuses)
    return [r[0] for r in conn.execute(
        f"SELECT id FROM build WHERE status IN ({marks}) ORDER BY id LIMIT ?", (*statuses, limit))]


def is_build_cancel_requested(conn: sqlite3.Connection, build_id: int) -> bool:
    row = conn.execute("SELECT cancel_requested, status FROM build WHERE id = ?", (build_id,)).fetchone()
    return bool(row and (row["cancel_requested"] or row["status"] == B_CANCELLED))


# ------------------------------------------------------------------ persetujuan (SATU-SATUNYA jalan ke 'approved')
def approve_build(conn: sqlite3.Connection, build_id: int, *, diff_sha256: str, statement_sha256: str,
                  statement_version: int) -> None:
    """awaiting_approval -> approved, HANYA bila diff_sha256 sama persis dengan yang tercatat saat diajukan.

    Hash diff ikut di klausa WHERE CAS (tanpa celah cek-lalu-ubah). statement_* = pernyataan wewenang yang ditampilkan; harus
    persis salah satu versi yang dikenal (UI tidak bisa menyetujui dengan teks yang tidak pernah ditampilkan).
    """
    _require_id("build_id", build_id)
    _require_hex64("diff_sha256", diff_sha256)
    _require_hex64("statement_sha256", statement_sha256)
    if type(statement_version) is not int or statement_version not in APPROVAL_STATEMENTS:
        raise BuildInputError("Versi pernyataan wewenang tidak dikenal.")
    if not hmac.compare_digest(statement_sha256, approval_statement_sha256(statement_version)):
        raise BuildInputError("Pernyataan wewenang tidak cocok dengan versi yang dikenal.")
    ts = now()
    with tx(conn):
        row = _build_row(conn, build_id)
        if row["status"] != B_AWAITING:
            raise _state_error(conn, build_id, "disetujui")
        if not hmac.compare_digest(diff_sha256, row["diff_sha256"]):
            raise BuildDiffMismatchError("Diff berubah sejak diajukan; muat ulang dan tinjau lagi.")
        if not _build_cas(conn, build_id, (B_AWAITING,), B_APPROVED, where="diff_sha256 = ?", params=(diff_sha256,),
                          approved_at=ts, approval_statement_sha256=statement_sha256,
                          approval_statement_version=statement_version):
            raise _state_error(conn, build_id, "disetujui")
        _audit_build(conn, "build_approved", row, diff_sha256=diff_sha256, statement_version=statement_version,
                     statement_sha256=statement_sha256)


def reject_build(conn: sqlite3.Connection, build_id: int, reason: str = "") -> None:
    """awaiting_approval -> rejected. Alasan dibersihkan; audit TANPA teks alasan."""
    _require_id("build_id", build_id)
    reason = _clean_text(reason, BUILD_REASON_MAX) or "Ditolak pengguna."
    ts = now()
    with tx(conn):
        row = _build_row(conn, build_id)
        if not _build_cas(conn, build_id, (B_AWAITING,), B_REJECTED, rejected_reason=reason, finished_at=ts):
            raise _state_error(conn, build_id, "ditolak")
        _audit_build(conn, "build_rejected", row, diff_sha256=row["diff_sha256"])


# ------------------------------------------------------------------ siklus hidup (worker/runner/signer; dipakai mulai Tahap 2)
def queue_build(conn: sqlite3.Connection, build_id: int) -> None:
    """approved -> queued."""
    _require_id("build_id", build_id)
    with tx(conn):
        _build_row(conn, build_id)
        if not _build_cas(conn, build_id, (B_APPROVED,), B_QUEUED):
            raise _state_error(conn, build_id, "diantrekan")


def claim_build(conn: sqlite3.Connection, build_id: int) -> bool:
    """queued -> building (atomik). False bila kalah balapan/sudah diambil/dibatalkan/tidak ada (pola claim_analysis)."""
    with tx(conn):
        return _build_cas(conn, build_id, (B_QUEUED,), B_BUILDING, where="cancel_requested = 0", started_at=now())


def mark_signing(conn: sqlite3.Connection, build_id: int, *, stage_log: str | None = None) -> None:
    """building -> signing. Ditolak bila pembatalan sudah diminta (pelaksana lalu memanggil cancel_build)."""
    _require_id("build_id", build_id)
    cols = {} if stage_log is None else {"stage_log": _clean_text(stage_log, BUILD_STAGE_LOG_MAX, multiline=True, scrub=True)}
    with tx(conn):
        _build_row(conn, build_id)
        if not _build_cas(conn, build_id, (B_BUILDING,), B_SIGNING, where="cancel_requested = 0", **cols):
            raise _state_error(conn, build_id, "masuk tahap tanda tangan")


def finish_build(conn: sqlite3.Connection, build_id: int, *, output_name: str, output_sha256: str, output_size: int,
                 output_format: str, cert_sha256: str, verify_ok: int | bool, stage_log: str | None = None) -> None:
    """signing -> done. verify_ok HARUS tepat 1/True: tidak ada jalan ke 'done' tanpa verifikasi tanda tangan yang lulus."""
    _require_id("build_id", build_id)
    if type(verify_ok) not in (int, bool) or verify_ok != 1:
        raise BuildInputError("Build hanya boleh selesai bila verifikasi tanda tangan lulus (verify_ok = 1).")
    if type(output_name) is not str or not _OUTPUT_NAME_RE.fullmatch(output_name):
        raise BuildInputError("Nama berkas keluaran tidak valid.")
    _require_hex64("output_sha256", output_sha256)
    _require_hex64("cert_sha256", cert_sha256)
    if type(output_size) is not int or output_size < 1:
        raise BuildInputError("Ukuran berkas keluaran harus bilangan bulat positif.")
    if output_format not in BUILD_SOURCE_KINDS:
        raise BuildInputError("Format keluaran harus apk, xapk, atau apks.")
    cols = {} if stage_log is None else {"stage_log": _clean_text(stage_log, BUILD_STAGE_LOG_MAX, multiline=True, scrub=True)}
    ts = now()
    with tx(conn):
        row = _build_row(conn, build_id)
        if output_format != row["source_kind"]:
            raise BuildInputError("Format keluaran harus sama dengan format asal.")
        if not _build_cas(conn, build_id, (B_SIGNING,), B_DONE, where="cancel_requested = 0", finished_at=ts,
                          output_name=output_name, output_sha256=output_sha256, output_size=output_size,
                          output_format=output_format, cert_sha256=cert_sha256, verify_ok=1, **cols):
            raise _state_error(conn, build_id, "diselesaikan")
        _audit_build(conn, "build_done", row, diff_sha256=row["diff_sha256"], output_sha256=output_sha256,
                     output_size=output_size, output_format=output_format, cert_sha256=cert_sha256)


def fail_build(conn: sqlite3.Connection, build_id: int, *, error_code: str, error_text: str, stage_log: str | None = None,
               verify_ok: int | bool | None = None) -> None:
    """approved/queued/building/signing -> failed. error_text dibersihkan dari path internal; audit TANPA error_text."""
    _require_id("build_id", build_id)
    if type(error_code) is not str or not _ERROR_CODE_RE.fullmatch(error_code):
        raise BuildInputError("Kode galat harus huruf kecil/angka/garis bawah (maksimum 40 karakter).")
    cols: dict[str, Any] = {"error_code": error_code, "error_text": _clean_text(error_text, BUILD_ERROR_MAX, scrub=True)}
    if verify_ok is not None:
        cols["verify_ok"] = _bool01("verify_ok", verify_ok)
    if stage_log is not None:
        cols["stage_log"] = _clean_text(stage_log, BUILD_STAGE_LOG_MAX, multiline=True, scrub=True)
    ts = now()
    with tx(conn):
        row = _build_row(conn, build_id)
        if not _build_cas(conn, build_id, (B_APPROVED, B_QUEUED, B_BUILDING, B_SIGNING), B_FAILED, finished_at=ts, **cols):
            raise _state_error(conn, build_id, "ditandai gagal")
        _audit_build(conn, "build_failed", row, error_code=error_code, from_status=row["status"])


# ------------------------------------------------------------------ pembatalan
def request_cancel_build(conn: sqlite3.Connection, build_id: int) -> str:
    """'cancelled' (belum berjalan: langsung batal) | 'requested' (building/signing: pelaksana yang menyelesaikan) | 'noop' (final)."""
    _require_id("build_id", build_id)
    ts = now()
    with tx(conn):
        row = _build_row(conn, build_id)
        if _build_cas(conn, build_id, (B_AWAITING, B_APPROVED, B_QUEUED), B_CANCELLED, cancel_requested=1,
                      error_code=E_CANCELLED, finished_at=ts):
            _audit_build(conn, "build_cancelled", row, from_status=row["status"], by="request")
            return "cancelled"
        cur = conn.execute(
            "UPDATE build SET cancel_requested = 1, updated_at = ? WHERE id = ? AND status IN (?, ?)",
            (ts, build_id, B_BUILDING, B_SIGNING),
        )
        return "requested" if cur.rowcount == 1 else "noop"


def cancel_build(conn: sqlite3.Connection, build_id: int) -> None:
    """PELAKSANA: building/signing dengan cancel_requested=1 -> cancelled. Selain itu BuildStateError."""
    _require_id("build_id", build_id)
    ts = now()
    with tx(conn):
        row = _build_row(conn, build_id)
        if not _build_cas(conn, build_id, BUILD_RUNNING, B_CANCELLED, where="cancel_requested = 1",
                          error_code=E_CANCELLED, finished_at=ts):
            raise BuildStateError(f"Build #{build_id} tidak sedang berjalan dengan permintaan pembatalan.")
        _audit_build(conn, "build_cancelled", row, from_status=row["status"], by="executor")


# ------------------------------------------------------------------ pemulihan & retensi
def recover_stuck_builds(conn: sqlite3.Connection) -> list[int]:
    """building/signing yang yatim setelah restart -> failed ('interrupted') (pola mark_interrupted). Mengembalikan id-nya."""
    ts = now()
    recovered: list[int] = []
    with tx(conn):
        rows = conn.execute(
            "SELECT * FROM build WHERE status IN (?, ?) ORDER BY id", BUILD_RUNNING).fetchall()
        for row in rows:
            if _build_cas(conn, row["id"], (row["status"],), B_FAILED, error_code=E_INTERRUPTED, finished_at=ts,
                          error_text="Terputus karena server/worker dimulai ulang saat build berjalan. Ajukan build baru."):
                _audit_build(conn, "build_failed", row, error_code=E_INTERRUPTED, from_status=row["status"])
                recovered.append(row["id"])
    return recovered


def prune_builds(conn: sqlite3.Connection, analysis_id: int, keep: int | None = None) -> list[int]:
    """Id build FINAL lama yang melebihi `keep` (urut naik). TIDAK menghapus baris/berkas dan TIDAK PERNAH menyebut build aktif.

    Dihitung terpisah: `done` terbaru sebanyak keep, dan (rejected/failed/cancelled) terbaru sebanyak keep -> deretan build gagal
    tidak menggusur artefak `done` yang berharga. Pemanggil (Tahap 2) menghapus direktori artefak lebih dulu, baru delete_build.
    """
    if keep is None:
        keep = build_keep()
    elif type(keep) is not int:
        raise BuildInputError("keep harus bilangan bulat.")
    keep = max(BUILD_KEEP_MIN, min(BUILD_KEEP_MAX, keep))
    old: list[int] = []
    for group in ((B_DONE,), (B_REJECTED, B_FAILED, B_CANCELLED)):
        marks = ", ".join("?" for _ in group)
        ids = [r[0] for r in conn.execute(
            f"SELECT id FROM build WHERE analysis_id = ? AND status IN ({marks}) ORDER BY id DESC", (analysis_id, *group))]
        old.extend(ids[keep:])
    return sorted(old)


def delete_build(conn: sqlite3.Connection, build_id: int) -> bool:
    """Hapus baris build FINAL (dipanggil setelah direktori artefaknya dihapus). False bila masih aktif atau tidak ada."""
    marks = ", ".join("?" for _ in BUILD_FINAL)
    with tx(conn):
        cur = conn.execute(f"DELETE FROM build WHERE id = ? AND status IN ({marks})", (build_id, *BUILD_FINAL))
        return cur.rowcount == 1
