"""Konfigurasi AI dari environment. Kunci API hanya dibaca di server; tidak pernah dikirim ke browser atau dicatat."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class ConfigError(ValueError):
    """Konfigurasi AI tidak valid. Pesan aman ditampilkan (tidak memuat kunci)."""


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw.replace(",", "."))
    except ValueError as exc:
        raise ConfigError(f"{name} harus berupa angka (nilai: {raw!r})") from exc
    if value < 0:
        raise ConfigError(f"{name} tidak boleh negatif")
    return value


def _int(name: str, default: int, lo: int = 1, hi: int = 10**6) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} harus berupa bilangan bulat (nilai: {raw!r})") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} harus antara {lo} dan {hi}")
    return value


# Batas TOTAL hasil tool per giliran. 0 = TANPA BATAS (bawaan). Isi AI_MAX_TURN_TOOL_CHARS bila ingin membatasi: tiap langkah agent
# mengirim ulang SEMUA hasil sebelumnya, jadi total yang besar membuat permintaan makin besar dan bisa melewati konteks model.
DEFAULT_TURN_TOOL_CHARS = 0


@dataclass(frozen=True)
class AIConfig:
    base_url: str
    api_key: str
    model: str
    model_pro: str
    fallback_model: str
    credit_idr: float            # nilai 1 kredit dalam Rupiah (hanya untuk tampilan)
    daily_budget: float          # kredit per hari (0 = tanpa batas)
    session_budget: float        # kredit per sesi chat (0 = tanpa batas)
    max_steps: int
    max_output_tokens: int
    connect_timeout: float
    read_timeout: float
    models_file: str
    day_offset_hours: int        # batas "hari" untuk anggaran harian (7 = WIB)
    redact_secrets: bool = True  # redaksi secret SEBELUM data APK dikirim ke provider (FR-4.9)
    max_tool_chars: int = 14000  # batas ukuran satu hasil tool (karakter)
    max_turn_tool_chars: int = DEFAULT_TURN_TOOL_CHARS  # batas total hasil tool dalam satu giliran (0 = tanpa batas)
    tool_timeout_s: float = 60.0  # batas WAKTU satu kueri/pencarian tool (detik; 0 = tanpa batas)
    # Lampiran. Ini bukan batas kemampuan AI: gambar > max_image_bytes tetap tersimpan & bisa diunduh, hanya tidak dikirim ke model
    # (permintaan HTTP ke provider punya batas ukuran sendiri). Teks lampiran <= inline_attach_chars langsung disertakan di pesan
    # (hemat satu putaran tool); yang lebih besar dibaca model lewat read_file secara bertahap.
    max_image_bytes: int = 10 * 1024 * 1024
    inline_attach_chars: int = 16000
    # Shell untuk AI (tool shell_run; PRD 09 Bagian C). MATI secara bawaan: perintah berjalan di kontainer `bench` terpisah (tanpa jaringan, tanpa
    # rahasia, tiap perintah dikurung Landlock). Nyalakan hanya setelah `make bench-selftest` lulus di server Anda.
    shell_enabled: bool = False
    shell_timeout_s: int = 60                 # batas waktu bawaan satu perintah (AI boleh meminta lebih kecil; bench membatasi dari atas)
    shell_max_timeout_s: int = 120            # batas atas yang boleh diminta AI
    shell_max_calls_per_turn: int = 40        # jumlah perintah per giliran (0 = tanpa batas)
    shell_max_output_chars: int = 12000       # keluaran per perintah yang dikirim kembali ke model (setelah redaksi)
    shell_spool_dir: str = "/data/benchspool"

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.api_key and self.model)

    def missing(self) -> list[str]:
        out = []
        if not self.base_url:
            out.append("AI_BASE_URL")
        if not self.api_key:
            out.append("AI_API_KEY")
        if not self.model:
            out.append("AI_MODEL")
        return out

    def idr(self, credits: float) -> float:
        return credits * self.credit_idr

    def redact(self, text: str) -> str:
        """Hapus kunci API dari teks apa pun yang akan ditampilkan atau dicatat."""
        if self.api_key and self.api_key in text:
            text = text.replace(self.api_key, "[kunci-disembunyikan]")
        return text


def load_ai_config() -> AIConfig:
    base = os.environ.get("AI_BASE_URL", "").strip().rstrip("/")
    if base:
        parts = urlsplit(base)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ConfigError("AI_BASE_URL harus berupa URL lengkap, mis. https://host/v1")
        if parts.scheme == "http" and parts.hostname not in LOOPBACK:
            # Kunci API dan potongan kode APK tidak boleh melintas tanpa enkripsi.
            raise ConfigError("AI_BASE_URL memakai http:// ke host publik; gunakan https://")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConfigError("AI_BASE_URL tidak boleh memuat kredensial, query, atau fragment")
    return AIConfig(
        base_url=base,
        api_key=os.environ.get("AI_API_KEY", "").strip(),
        model=os.environ.get("AI_MODEL", "").strip(),
        model_pro=os.environ.get("AI_MODEL_PRO", "").strip(),
        fallback_model=os.environ.get("AI_FALLBACK_MODEL", "").strip(),
        credit_idr=_float("AI_CREDIT_IDR", 300.0),
        daily_budget=_float("AI_DAILY_BUDGET_CREDITS", 5.0),
        session_budget=_float("AI_SESSION_BUDGET_CREDITS", 1.0),
        max_steps=_int("AI_MAX_STEPS", 100, 1, 100_000),
        max_output_tokens=_int("AI_MAX_OUTPUT_TOKENS", 4096, 64, 10_000_000),
        connect_timeout=_float("AI_CONNECT_TIMEOUT", 10.0),
        read_timeout=_float("AI_READ_TIMEOUT", 120.0),
        models_file=os.environ.get("AI_MODELS_FILE", "/config/ai_models.json"),
        day_offset_hours=_int("AI_DAY_OFFSET_HOURS", 7, -12, 14),
        redact_secrets=os.environ.get("AI_REDACT_SECRETS", "1").strip().lower() not in {"0", "false", "no", "off"},
        max_tool_chars=_int("AI_MAX_TOOL_CHARS", 14000, 1000, 100_000_000),
        max_turn_tool_chars=_int("AI_MAX_TURN_TOOL_CHARS", DEFAULT_TURN_TOOL_CHARS, 0, 1_000_000_000),
        tool_timeout_s=_float("AI_TOOL_TIMEOUT", 60.0),
        max_image_bytes=int(_float("AI_MAX_IMAGE_MB", 10.0) * 1024 * 1024),
        inline_attach_chars=_int("AI_INLINE_ATTACH_CHARS", 16000, 0, 100_000_000),
        shell_enabled=os.environ.get("AI_SHELL_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"},     # beda dengan redaksi: SALAH-nya = mati
        shell_timeout_s=_int("AI_SHELL_TIMEOUT", 60, 1, 3600),
        shell_max_timeout_s=_int("AI_SHELL_MAX_TIMEOUT", 120, 1, 3600),
        shell_max_calls_per_turn=_int("AI_SHELL_MAX_CALLS_PER_TURN", 40, 0, 100_000),
        shell_max_output_chars=_int("AI_SHELL_MAX_OUTPUT_CHARS", 12000, 500, 1_000_000),
        shell_spool_dir=os.environ.get("AI_SHELL_SPOOL", "/data/benchspool").strip() or "/data/benchspool",
    )
