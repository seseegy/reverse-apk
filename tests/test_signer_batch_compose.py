"""Isolasi signer TIDAK longgar oleh protokol multi-berkas (Tahap 3, sub-area C): tidak ada volume/jaringan/secret/cap baru; hanya env `SIGN_MAX_TOTAL_MB`.

Batas total byte satu permintaan (base + split) diteruskan compose ke signer SAJA dan dijaga bersama bawaan kode dan `.env.example`.
Signer tetap hanya di volume privat `signwork` (+ builds + signspool), tanpa `uploads`, tanpa jaringan; runner tetap tanpa signspool/signwork/keystore;
worker tetap tanpa signwork. Pagar "AI tanpa tool setujui/tanda tangan" dijaga test_build_nb.py (G-AI) dan tidak diubah.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from test_build_compose import block, list_items

ROOT = Path(__file__).resolve().parent.parent


def test_sign_max_total_mb_diteruskan_compose_ke_signer_saja():
    assert re.search(r"(?m)^      SIGN_MAX_TOTAL_MB: \$\{SIGN_MAX_TOTAL_MB:-3072\}$", block("signer"))
    for other in ("web", "worker", "runner", "bench", "redis", "caddy", "egress"):
        assert "SIGN_MAX_TOTAL_MB" not in block(other), other


def test_sign_max_total_mb_ada_di_env_example_dengan_bawaan_sama():
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"(?m)^#SIGN_MAX_TOTAL_MB=3072$", example)
    src = (ROOT / "services/signer/signer-daemon").read_text(encoding="utf-8")
    assert '_int_env("SIGN_MAX_TOTAL_MB", 3072, 1, 16384)' in src


def test_signer_tanpa_uploads_tanpa_jaringan_hanya_tiga_volume():
    b = block("signer")
    vols = [v.split(":")[0] for v in list_items(b, "volumes")]
    assert vols == ["builds", "signspool", "signwork"], "signer tidak memasang uploads: ekstras paket tidak pernah lewat signer"
    assert re.search(r"(?m)^    network_mode: none$", b)
    assert not re.search(r"(?m)^    (ports|networks|secrets|cap_add|privileged|devices):", b)
    assert "cap_drop: [ALL]" in b and "read_only: true" in b and 'user: "10001:10001"' in b


def test_runner_dan_worker_tidak_mendapat_akses_signwork_atau_keystore():
    runner, worker = block("runner"), block("worker")
    for forbidden in ("signspool", "signwork", "secrets", "keystore"):
        assert forbidden not in runner, forbidden
    assert "signwork" not in worker and "keystore" not in worker
    assert re.search(r"(?m)^    network_mode: none$", runner)


def test_signwork_hanya_dipasang_signer():
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    users = [name for name, svc in doc["services"].items() if any(str(v).split(":")[0] == "signwork" for v in svc.get("volumes", []))]
    assert users == ["signer"]
