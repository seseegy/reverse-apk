"""Halaman Berkas: daftar dibuat berhalaman agar HTML tidak tumbuh tanpa batas (audit BE-09).

Semua angka diturunkan dari PAGE_SIZE, jadi tes tetap benar bila nilainya diubah.
"""

from __future__ import annotations

import re
import time
from contextlib import closing

import pytest

from app import context
from app.routes_files import PAGE_SIZE
from rvcore import store

from conftest import BROWSER, new_analysis

N_AI = PAGE_SIZE * 2 + 30          # tiga halaman; yang terakhir sebagian
N_UP = PAGE_SIZE * 2 + 5           # tiga halaman juga, agar tautan "Berikutnya" kedua bagian bisa diuji
PAGES = 3


def ai_name(i: int) -> str:
    return f"berkas-{i:04d}.md"


def up_name(i: int) -> str:
    return f"lampiran-{i:04d}.txt"


@pytest.fixture(scope="module")
def many_files() -> int:
    aid = new_analysis("banyak-berkas")
    ts = time.time()
    with closing(context.db()) as conn:
        conn.executemany(
            "INSERT INTO analysis_file (analysis_id, kind, path, name, media, mime, size, sha256, revision, pending, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)",
            [(aid, "ai", f"laporan/{ai_name(i)}", ai_name(i), "text", "text/markdown", 1024 + i, "c" * 64, ts, ts) for i in range(N_AI)]
            + [(aid, "upload", f"tok{i}", up_name(i), "text", "text/plain", 10, "d" * 64, ts, ts) for i in range(N_UP)])
        conn.commit()
    return aid


def page(client, aid: int, query: str = "") -> str:
    r = client.get(f"/analyses/{aid}/files{query}", headers=BROWSER)
    assert r.status_code == 200, r.status_code
    return r.text


def test_first_page_shows_one_page_per_section(client, many_files):
    html = page(client, many_files)
    assert len(re.findall(r'data-frow="\d+"', html)) == 2 * PAGE_SIZE
    assert ai_name(0) in html and ai_name(PAGE_SIZE - 1) in html
    assert ai_name(PAGE_SIZE) not in html, "baris halaman berikutnya tidak boleh ikut terkirim"
    assert up_name(0) in html and up_name(PAGE_SIZE) not in html


def test_counts_are_honest_not_page_size(client, many_files):
    html = page(client, many_files)
    assert f'<span class="count-pill">{N_AI}</span>' in html, "lencana = jumlah SELURUH berkas, bukan isi halaman"
    assert f"1–{PAGE_SIZE} dari {N_AI} berkas" in html
    assert f"(halaman 1 dari {PAGES})" in html


def test_middle_and_last_page(client, many_files):
    html = page(client, many_files, "?ai=2")
    assert ai_name(PAGE_SIZE) in html and ai_name(0) not in html
    assert f"{PAGE_SIZE + 1}–{2 * PAGE_SIZE} dari {N_AI} berkas" in html

    html = page(client, many_files, f"?ai={PAGES}")
    assert ai_name(N_AI - 1) in html and ai_name(PAGE_SIZE) not in html
    assert f"{2 * PAGE_SIZE + 1}–{N_AI} dari {N_AI} berkas" in html
    ai_section = html.split("Lampiran Anda")[0]
    assert 'rel="next"' not in ai_section, "halaman terakhir tidak punya tautan Berikutnya"
    assert 'rel="prev"' in ai_section


def test_out_of_range_is_clamped_not_empty(client, many_files):
    html = page(client, many_files, "?ai=999999")
    assert ai_name(N_AI - 1) in html and f"(halaman {PAGES} dari {PAGES})" in html


@pytest.mark.parametrize("bad", ["?ai=0", "?ai=-1", "?ai=abc", "?up=0"])
def test_invalid_page_param(client, many_files, bad):
    """Nomor halaman tidak valid = parameter QUERY -> halaman galat 422 (redirect hanya untuk id di path; BE-12)."""
    r = client.get(f"/analyses/{many_files}/files{bad}", headers=BROWSER)
    assert r.status_code == 422 and "Permintaan tidak valid" in r.text


def test_two_sections_paginate_independently(client, many_files):
    html = page(client, many_files, "?ai=2&up=2")
    assert ai_name(PAGE_SIZE) in html and up_name(PAGE_SIZE) in html
    # Jinja meng-escape '&' menjadi '&amp;' di atribut href.
    assert 'href="?ai=3&amp;up=2"' in html, "tautan bagian AI harus mempertahankan halaman lampiran"
    assert 'href="?up=3&amp;ai=2"' in html, "tautan bagian lampiran harus mempertahankan halaman AI"


def test_html_stays_small(client, many_files):
    """Penjaga regresi: terukur ±2,9 KB per baris, jadi 2 x PAGE_SIZE baris ≈ 285 KB. Ambang memberi ruang, tetapi
    menangkap kembalinya daftar tanpa batas (1.500 berkas = 4,3 MB) atau baris yang jauh lebih berat."""
    size = len(page(client, many_files))
    assert size < 3_000 * 2 * PAGE_SIZE + 60_000, f"HTML {size} byte"


def test_quota_and_zip_cover_all_files(client, many_files):
    html = page(client, many_files)
    with closing(context.db()) as conn:
        used, count = store.files_usage(conn, many_files)
        assert len(store.list_files(conn, many_files, "ai")) == N_AI, "ZIP & tool AI tetap melihat seluruh berkas"
    assert count == N_AI + N_UP and used > 0
    assert f"{count} berkas" in html, "kuota dihitung dari seluruh berkas, bukan halaman ini"


def test_small_list_has_no_pager(client, seeded):
    assert "Halaman daftar" not in page(client, seeded.aid)
