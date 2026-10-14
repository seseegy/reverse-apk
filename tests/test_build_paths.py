"""Jalur artefak build (`Layout.builds/builds_dir/build_dir`): dihitung HANYA dari bilangan bulat positif.

Mengapa ketat: id build/analisis menjadi segmen path di disk. `work_dir` memakai `int(x)` yang masih menerima '12' atau -3; untuk
folder artefak yang nanti dihapus/diunduh, string apa pun (mis. '../x', '1/2') tidak boleh pernah sampai ke path.
Folder TIDAK dibuat oleh `Layout`. Volume `builds`/`signspool` dipasang compose hanya ke `worker` dan `signer` (Tahap 2a).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from rvcore.paths import Layout

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def layout(tmp_path):
    return Layout(tmp_path)


def test_builds_root_and_paths(layout, tmp_path):
    assert layout.builds == tmp_path / "builds"
    assert layout.builds_dir(3) == tmp_path / "builds" / "3"
    assert layout.build_dir(3, 7) == tmp_path / "builds" / "3" / "7"
    assert layout.signspool == tmp_path / "signspool"


def test_paths_never_leave_the_root_even_for_huge_ids(layout):
    for a, b in ((1, 1), (2**63, 2**64), (10**30, 10**40)):
        p = layout.build_dir(a, b).resolve()
        assert p.is_relative_to(layout.builds.resolve())
        assert layout.builds_dir(a).resolve().is_relative_to(layout.builds.resolve())


@pytest.mark.parametrize("bad", [0, -1, "1", "../x", "1/2", "..", 1.0, True, False, None, b"1", [1], (1,)])
def test_only_positive_int_is_accepted(layout, bad):
    with pytest.raises(ValueError):
        layout.builds_dir(bad)
    with pytest.raises(ValueError):
        layout.build_dir(bad, 1)
    with pytest.raises(ValueError):
        layout.build_dir(1, bad)


def test_directories_are_not_created(layout):
    layout.build_dir(1, 1)
    layout.builds_dir(1)
    assert not layout.builds.exists()
    assert not layout.signspool.exists()


def test_existing_paths_unchanged(layout, tmp_path):
    """Regresi: akar lama tidak berubah perilakunya."""
    assert layout.work_dir(5) == tmp_path / "work" / "5"
    assert layout.files_dir(5) == tmp_path / "files" / "5"
    assert layout.upload_path("a" * 64) == tmp_path / "uploads" / ("a" * 64 + ".apk")


def _service_names(compose: str) -> list[str]:
    body = compose.split("\nservices:\n", 1)[1].split("\nnetworks:\n", 1)[0]
    return re.findall(r"(?m)^  ([\w-]+):[ \t]*$", body)


def _mounters(compose: str, volume: str) -> set[str]:
    """Layanan yang memasang volume bernama `volume` (baris `- volume:/jalur` di blok layanan, komentar dibuang)."""
    body = compose.split("\nservices:\n", 1)[1].split("\nnetworks:\n", 1)[0]
    code = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    parts = re.split(r"(?m)^  ([\w-]+):[ \t]*$", code)
    return {parts[i] for i in range(1, len(parts), 2) if re.search(rf"(?m)^\s+- {re.escape(volume)}:/", parts[i + 1])}


def test_compose_mounts_builds_and_signspool_only_for_worker_and_signer():
    """Penjaga SADAR (menggantikan 'belum ada volume builds' Tahap 1): `builds` dan `signspool` hanya untuk worker + signer; runner/bench/egress/caddy/web/redis TIDAK."""
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    vols = compose.split("\nvolumes:\n", 1)[1].split("\nsecrets:\n", 1)[0]
    names = set(re.findall(r"^  ([A-Za-z0-9_]+):", vols, re.M))
    assert {"builds", "signspool"} <= names
    assert _mounters(compose, "builds") == {"worker", "signer"}
    assert _mounters(compose, "signspool") == {"worker", "signer"}
    for service in ("runner", "bench", "egress", "caddy", "web", "redis"):
        assert service in _service_names(compose), service
        assert service not in _mounters(compose, "builds") | _mounters(compose, "signspool"), service
