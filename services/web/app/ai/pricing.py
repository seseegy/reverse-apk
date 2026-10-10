"""Tabel harga model (kredit per 1 juta token) dan penghitungan biaya.

Harga berasal dari berkas konfigurasi yang bisa diedit (config/ai_models.json), tidak di-hard-code: harga router
bisa berubah kapan saja. Model yang tidak ada di tabel dihitung dengan tarif `default` (sengaja mahal) dan ditandai
perkiraan, supaya anggaran tidak jebol hanya karena slug salah ketik.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Rate:
    in_per_m: float
    out_per_m: float
    known: bool = True


class PriceTable:
    def __init__(self, models: dict[str, dict], default: Rate, labels: dict[str, str], chat: list[str]) -> None:
        self._models, self._default, self.labels, self.chat_models = models, default, labels, chat

    @classmethod
    def load(cls, path: str | Path) -> "PriceTable":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        d = data.get("default") if isinstance(data, dict) else None
        default = Rate(_num(d, "in", 4.0), _num(d, "out", 4.0), known=False)
        models, labels, chat = {}, {}, []
        raw = data.get("models") if isinstance(data, dict) else None
        for slug, spec in (raw or {}).items():
            if not isinstance(spec, dict) or not isinstance(slug, str):
                continue
            models[slug] = {"in": _num(spec, "in", default.in_per_m), "out": _num(spec, "out", default.out_per_m)}
            labels[slug] = str(spec.get("label") or slug)[:80]
            if spec.get("chat", True):
                chat.append(slug)
        return cls(models, default, labels, chat)

    def rate(self, model: str) -> Rate:
        m = self._models.get(model)
        return Rate(m["in"], m["out"], True) if m else self._default

    def cost(self, model: str, prompt_tokens: int, completion_tokens: int) -> float:
        """Biaya dalam kredit. Token cache tidak didiskon (konservatif: harga diskon router tidak diketahui)."""
        r = self.rate(model)
        return (max(prompt_tokens, 0) * r.in_per_m + max(completion_tokens, 0) * r.out_per_m) / 1_000_000


def _num(spec: object, key: str, default: float) -> float:
    try:
        v = float(spec[key])  # type: ignore[index]
        return v if v >= 0 else default
    except (KeyError, TypeError, ValueError):
        return default
