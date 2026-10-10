"""Menyaring log mentah jadx/apktool (ditulis runner) menjadi baris ringkas untuk UI.

Log mentah bisa puluhan ribu baris dan memuat teks dari APK yang tidak tepercaya, jadi:
dibaca lewat path yang diverifikasi + O_NOFOLLOW, hanya baris penting yang disimpan ke DB,
dibatasi jumlahnya, dan UI selalu menampilkannya sebagai teks (escape).
"""

from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

from rvcore import store
from rvcore.fsutil import resolve_under

MAX_LINES_PER_STAGE = 60
READ_CHUNK = 64 * 1024
PROGRESS_STEP = 10  # catat tiap kelipatan 10%

_SPLIT = re.compile(r"[\r\n]+")
_ERROR = re.compile(r"(?i)\b(error|exception|fatal|failed|cannot|unable to|out ?of ?memory)\b|^E: |^ERROR\b")
_WARN = re.compile(r"(?i)\b(warn|warning|invalid|unsupported|dropping)\b|^W: |^WARN\b")
_APKTOOL_INFO = re.compile(r"^I: ")
_JADX_INFO = re.compile(r"INFO\s+-\s+(loading|processing|done)\b")
_PROGRESS = re.compile(r"progress:\s*(\d+)\s+of\s+(\d+)")


class LogTail:
    def __init__(self, conn: sqlite3.Connection, work_root: Path, analysis_id: int, stage: str,
                 log_name: str | None = None) -> None:
        self.log_name = log_name or stage
        self.conn = conn
        self.work_root = work_root
        self.analysis_id = analysis_id
        self.stage = stage
        self._offset = 0
        self._carry = ""
        self._emitted = 0
        self._last_line = ""
        self._last_pct = -PROGRESS_STEP
        self._truncated_noted = False
        self.dropped = 0

    def _read_new(self) -> str:
        target = resolve_under(self.work_root, str(self.analysis_id), "logs", f"{self.log_name}.log")
        if target is None:
            return ""
        try:
            fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return ""
        try:
            os.lseek(fd, self._offset, os.SEEK_SET)
            data = os.read(fd, READ_CHUNK)
        except OSError:
            return ""
        finally:
            os.close(fd)
        self._offset += len(data)
        return data.decode("utf-8", errors="replace")

    def _emit(self, level: str, message: str) -> None:
        if message == self._last_line:
            return
        if self._emitted >= MAX_LINES_PER_STAGE:
            self.dropped += 1
            if not self._truncated_noted:
                self._truncated_noted = True
                store.add_log(self.conn, self.analysis_id, self.stage, "warn",
                              f"Log {self.stage} dipotong di sini; lihat logs/{self.log_name}.log untuk selengkapnya.")
            return
        self._last_line = message
        self._emitted += 1
        store.add_log(self.conn, self.analysis_id, self.stage, level, message)

    def _handle(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        m = _PROGRESS.search(line)
        if m:
            done, total = int(m.group(1)), int(m.group(2))
            pct = (done * 100 // total) if total else 0
            if pct >= self._last_pct + PROGRESS_STEP or (pct == 100 and self._last_pct < 100):
                self._last_pct = pct
                # Progres tidak dihitung ke batas baris (tidak membanjiri), tetapi tetap dicatat.
                store.add_log(self.conn, self.analysis_id, self.stage, "info",
                              f"{self.stage}: {pct}% ({done}/{total})")
            return
        if _ERROR.search(line):
            self._emit("error", line)
        elif _WARN.search(line):
            self._emit("warn", line)
        elif _APKTOOL_INFO.search(line) or _JADX_INFO.search(line):
            self._emit("info", line)

    def pump(self) -> None:
        """Baca bagian log baru dan catat baris yang penting. Aman dipanggil berulang."""
        text = self._carry + self._read_new()
        if not text:
            return
        parts = _SPLIT.split(text)
        # Baris terakhir mungkin belum lengkap; simpan untuk putaran berikutnya.
        self._carry = parts.pop() if not text.endswith(("\n", "\r")) else ""
        for line in parts:
            self._handle(line)

    def flush(self) -> None:
        for _ in range(64):  # kosongkan sisa log (dibatasi agar tak berputar tanpa akhir)
            before = self._offset
            self.pump()
            if self._offset == before:
                break
        if self._carry:
            self._handle(self._carry)
            self._carry = ""
