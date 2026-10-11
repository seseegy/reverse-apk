"""Logger paket AI (`reverse-apk.ai`) dan perangkum galat yang aman untuk dicatat.

Sebelumnya paket ini tidak punya logging sama sekali: galat di thread chat hanya sampai ke pengguna sebagai "Galat internal (TipeError)",
sehingga operator tidak punya jejak untuk mendiagnosis. Aturan yang dijaga di sini:
  * kunci API disamarkan (`cfg.redact`) di setiap pesan galat;
  * isi pesan pengguna / hasil tool / kode APK TIDAK dicatat; hanya id (session, analysis), model, tipe galat, dan lokasi kode;
  * satu baris per kejadian (mudah di-grep), tanpa `exc_info` agar pesan galat tidak tercetak ulang tanpa penyamaran.
"""

from __future__ import annotations

import logging
import os
import traceback
from typing import Any

log = logging.getLogger("reverse-apk.ai")

MAX_MESSAGE = 300
MAX_FRAMES = 4


def describe(exc: BaseException, cfg: Any = None) -> str:
    """'TipeGalat: pesan @ berkas.py:12(fungsi) > lain.py:34(fungsi)'. Pesan dipotong dan, bila `cfg` diberikan, kunci API disamarkan."""
    msg = str(exc)
    if cfg is not None:
        msg = cfg.redact(msg)
    msg = " ".join(msg.split())[:MAX_MESSAGE]
    try:
        frames = traceback.extract_tb(exc.__traceback__)[-MAX_FRAMES:]
        where = " > ".join(f"{os.path.basename(f.filename)}:{f.lineno}({f.name})" for f in frames)
    except Exception:  # noqa: BLE001 - perangkum tidak boleh menjadi sumber galat baru
        where = "?"
    return f"{type(exc).__name__}: {msg}" + (f" @ {where}" if where else "")
