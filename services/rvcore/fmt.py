"""Format angka untuk tampilan: satu gaya (Indonesia, sama dengan `toLocaleString("id-ID")` di app.js).

Ribuan dipisah titik, desimal koma: 1.234 · 1.234,5 · 0,123 · 1,5 MB. Dipakai web (filter Jinja `num`/`bytes`), worker, dan runner
(pesan log/tahap yang tampil di UI). Hanya stdlib. Teks untuk model AI dan keluaran CLI sengaja tidak memakai ini.
"""

from __future__ import annotations

from typing import Any

DASH = "–"


def _swap(text: str) -> str:
    """'1,234.5' (gaya Python) -> '1.234,5'."""
    return text.replace(",", "\x00").replace(".", ",").replace("\x00", ".")


def num(value: Any, decimals: int | None = 0) -> str:
    """Angka dengan pemisah Indonesia. decimals=None: tanpa nol berlebih (seperti '%g', mis. 0,5 · 5 · 1,25). None -> '–'."""
    if value is None or isinstance(value, bool):
        return DASH
    try:
        if decimals is None:
            text = f"{float(value):,.6f}".rstrip("0").rstrip(".")
        elif decimals == 0 and isinstance(value, int):
            text = f"{value:,}"                                    # int besar tetap tepat (tanpa lewat float)
        else:
            text = f"{float(value):,.{int(decimals)}f}"
    except (TypeError, ValueError):
        return str(value)
    if text in ("-0", "-0.0", "-0.00", "-0.000"):
        text = text[1:]
    return _swap(text)


def size(n: Any) -> str:
    """Ukuran berkas: 512 B · 1,5 KB · 12,3 GB. None -> '–'."""
    if n is None or isinstance(n, bool):
        return DASH
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{num(value, 0)} {unit}" if unit == "B" else f"{num(value, 1)} {unit}"
        value /= 1024
    return f"{num(n)} B"
