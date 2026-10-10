"""Redaksi secret SEBELUM data APK dikirim ke provider AI (FR-4.9).

Memakai ulang pola penyedia dari analyzer.rules (satu sumber kebenaran): AWS, Google, kunci privat, token, JWT, dll.
Nilai yang sama selalu mendapat placeholder yang sama, jadi model tetap bisa bernalar ("kunci yang sama dipakai di dua
tempat") tanpa melihat nilainya. Heuristik generik (nama + entropi) sengaja TIDAK dipakai di sini: terlalu kabur untuk
mengubah kode yang dikirim; temuan jenis itu sudah dimasking oleh analyzer.

Batas yang diakui: ini bukan jaminan. String rahasia tanpa pola dikenal (mis. password biasa) tetap bisa lolos.
"""

from __future__ import annotations

import re

try:
    from analyzer.rules import SECRET_PATTERNS
except ImportError as exc:  # pragma: no cover - hanya terjadi bila Dockerfile web lupa menyalin paket analyzer
    raise ImportError(
        "paket 'analyzer' tidak ditemukan. Image web harus menyalin services/runner/analyzer (lihat web/Dockerfile); "
        "tanpa itu redaksi secret tidak bisa bekerja dan AI TIDAK boleh dipakai."
    ) from exc

# user:password@ di dalam URL: hanya bagian kredensial yang diganti, skema + host tetap terbaca model.
_URL_CRED = re.compile(r"(\b[a-z][a-z0-9+.\-]{1,10}://)([^/\s:@\"'<>\\]{1,64}):([^/\s@\"'<>\\]{3,64})@")
_PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z ]*PRIVATE KEY(?: BLOCK)?)-----[\s\S]{0,8000}?-----END \1-----")


class Redactor:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._seen: dict[str, str] = {}
        self.count = 0

    def _placeholder(self, rule: str, value: str) -> str:
        key = f"{rule}|{value}"
        if key not in self._seen:
            self._seen[key] = f"‹REDACTED:{rule.split('.')[-1]}#{len(self._seen) + 1}›"
        self.count += 1
        return self._seen[key]

    def text(self, s: str) -> str:
        if not self.enabled or not s:
            return s
        if "PRIVATE KEY" in s:
            s = _PEM_BLOCK.sub(lambda m: self._placeholder("secret.private_key", m.group(0)), s)
        if "://" in s and "@" in s:
            s = _URL_CRED.sub(lambda m: f"{m.group(1)}{m.group(2)}:{self._placeholder('secret.url_password', m.group(3))}@", s)
        for pat in SECRET_PATTERNS:
            if pat.rule_id == "secret.url_credentials":
                continue                                  # ditangani di atas (lebih presisi)
            if pat.needle in s:
                s = pat.rx.sub(lambda m, p=pat: self._placeholder(p.rule_id, m.group(p.value_group)), s)
        return s
