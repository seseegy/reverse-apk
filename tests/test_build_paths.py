"""Jalur artefak build (`Layout.builds/builds_dir/build_dir`): dihitung HANYA dari bilangan bulat positif.

Mengapa ketat: id build/analisis menjadi segmen path di disk. `work_dir` memakai `int(x)` yang masih menerima '12' atau -3; untuk
folder artefak yang nanti dihapus/diunduh, string apa pun (mis. '../x', '1/2') tidak boleh pernah sampai ke path.
Folder TIDAK dibuat dan volume `builds` BELUM ada di compose pada Tahap 1 (dikerjakan Tahap 2).
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


def test_existing_paths_unchanged(layout, tmp_path):
    """Regresi: akar lama tidak berubah perilakunya."""
    assert layout.work_dir(5) == tmp_path / "work" / "5"
    assert layout.files_dir(5) == tmp_path / "files" / "5"
    assert layout.upload_path("a" * 64) == tmp_path / "uploads" / ("a" * 64 + ".apk")


def test_compose_has_no_builds_volume_yet():
    """Penjaga SADAR: volume `builds` dan mount-nya dikerjakan Tahap 2. Ubah tes ini bersama perubahan compose itu."""
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    vols = compose.split("\nvolumes:\n", 1)[1].split("\nsecrets:\n", 1)[0]
    names = set(re.findall(r"^  ([A-Za-z0-9_]+):", vols, re.M))
    assert "builds" not in names
    assert "/data/builds" not in compose
