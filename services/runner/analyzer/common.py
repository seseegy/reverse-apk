"""Utilitas bersama: penelusuran berkas aman, nomor baris, entropi, masking secret, dan agregator temuan."""

from __future__ import annotations

import bisect
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Iterator

MIB = 1024 * 1024
MAX_SCAN_BYTES = 4 * MIB       # berkas lebih besar dari ini dilewati saat pemindaian (dicatat)
MAX_SNIPPET = 240
MAX_EVIDENCE = 10
MAX_FINDINGS = 3000

SEVERITIES = ("info", "low", "medium", "high")
_SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Prefiks path (di bawah jadx/sources) yang dikenal sebagai pustaka pihak ketiga.
LIB_PREFIXES = (
    "androidx/", "android/support/", "com/google/android/", "com/google/firebase/", "com/google/gson/",
    "com/google/common/", "com/google/protobuf/", "com/google/crypto/", "kotlin/", "kotlinx/", "okhttp3/", "okio/",
    "retrofit2/", "com/squareup/", "org/apache/", "org/bouncycastle/", "com/facebook/", "io/reactivex/",
    "dagger/", "org/jetbrains/", "com/fasterxml/", "org/slf4j/", "com/bumptech/", "org/json/", "org/intellij/",
    "javax/", "j$/", "com/android/", "org/threeten/", "io/grpc/", "io/netty/", "org/checkerframework/",
)


def is_library(rel_path: str) -> bool:
    """rel_path relatif terhadap work/ (mis. 'jadx/sources/androidx/core/A.java')."""
    for marker in ("jadx/sources/", "apktool/smali/"):
        if rel_path.startswith(marker):
            return rel_path[len(marker):].startswith(LIB_PREFIXES)
    # apktool/smali_classesN/...
    m = re.match(r"apktool/smali_classes\d+/(.*)", rel_path)
    return bool(m and m.group(1).startswith(LIB_PREFIXES))


def iter_files(root: Path, suffixes: tuple[str, ...] | None = None) -> Iterator[Path]:
    """Berkas biasa di bawah root, terurut (deterministik). Tidak mengikuti symlink."""
    if not root.is_dir() or root.is_symlink():
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            if suffixes and not name.endswith(suffixes):
                continue
            p = Path(dirpath) / name
            try:
                if p.is_symlink() or not p.is_file():
                    continue
            except OSError:
                continue
            yield p


def read_text(path: Path, limit: int = MAX_SCAN_BYTES) -> str | None:
    """Baca teks UTF-8 (rusak diganti). None bila terlalu besar, biner, atau tak terbaca."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError:
        return None
    if len(data) > limit or b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


class Lines:
    """Pemetaan offset -> nomor baris (1-based) dengan pencarian biner; dibangun malas sekali per berkas."""

    __slots__ = ("_text", "_starts")

    def __init__(self, text: str) -> None:
        self._text = text
        self._starts: list[int] | None = None

    def line_of(self, pos: int) -> int:
        if self._starts is None:
            self._starts = [0] + [m.end() for m in re.finditer("\n", self._text)]
        return bisect.bisect_right(self._starts, pos)

    def text_of(self, line: int) -> str:
        self.line_of(0)
        starts = self._starts
        assert starts is not None
        if line < 1 or line > len(starts):
            return ""
        begin = starts[line - 1]
        end = starts[line] - 1 if line < len(starts) else len(self._text)
        return self._text[begin:end]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def mask_secret(value: str) -> str:
    """Tampilkan sebagian kecil saja: cukup untuk dikenali, tidak cukup untuk dipakai."""
    n = len(value)
    if n <= 8:
        return value[:1] + "•" * (n - 1)
    if n < 16:
        return value[:2] + "•" * (n - 4) + value[-2:]
    return value[:4] + "•" * 6 + value[-4:]


def clip(s: str, n: int = MAX_SNIPPET) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


class Findings:
    """Mengelompokkan temuan per (rule_id, key). Kemunculan berulang menambah `occurrences` dan evidence."""

    def __init__(self) -> None:
        self._groups: dict[tuple[str, str], dict] = {}
        self.dropped = 0

    def add(self, *, category: str, severity: str, rule_id: str, title: str, description: str = "",
            key: str = "", file: str | None = None, line: int | None = None, snippet: str | None = None,
            secret: str | None = None) -> None:
        gk = (rule_id, key)
        g = self._groups.get(gk)
        if g is None:
            if len(self._groups) >= MAX_FINDINGS:
                self.dropped += 1
                return
            g = {"category": category, "severity": severity, "rule_id": rule_id, "title": title,
                 "description": description, "evidence": [], "secret": secret, "occurrences": 0}
            self._groups[gk] = g
        g["occurrences"] += 1
        # Severity tertinggi di antara kemunculan menang (mis. kode aplikasi vs pustaka).
        if _SEV_RANK[severity] < _SEV_RANK[g["severity"]]:
            g["severity"] = severity
        if file is not None and len(g["evidence"]) < MAX_EVIDENCE:
            item = {"file": file, "line": line, "snippet": clip(snippet or "")}
            if item not in g["evidence"]:
                g["evidence"].append(item)

    def items(self) -> list[dict]:
        return sorted(self._groups.values(),
                      key=lambda g: (_SEV_RANK[g["severity"]], g["category"], g["rule_id"], g["title"]))

    def __len__(self) -> int:
        return len(self._groups)
