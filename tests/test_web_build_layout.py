"""Perbaikan tata letak halaman Build (Fase 2a): aturan CSS anti-overflow dan markup baru di `build_detail.html`.

Dua jenis tes: (1) invarian CSS/templat dibaca sebagai teks (tanpa browser), (2) HTML hasil render lewat test client.
Tidak dibuktikan di sini: pengukuran piksel di browser nyata (itu dilakukan harness audit terpisah).
"""

from __future__ import annotations

import re
from contextlib import closing

import pytest
from conftest import BROWSER, ROOT
from rvcore import shellspool, store
from test_web_build_ui import mk_build, mk_done, new_analysis
from web_rig import FakeBench, live_redis

from app import builds, context, routes_build

CSS = (ROOT / "services/web/app/static/css/app.css").read_text(encoding="utf-8")
TEMPLATES = ROOT / "services/web/app/templates"
HEX = "e3feb" + "a1" * 29 + "c9"          # 64 hex tanpa spasi
LONG = "galat_" + "x" * 480               # galat panjang tanpa spasi


def rule(selector: str) -> str:
    """Isi blok aturan CSS pertama yang selektornya persis `selector` (di awal baris)."""
    m = re.search(r"^" + re.escape(selector) + r"\s*\{([^}]*)\}", CSS, re.M)
    assert m, f"aturan CSS {selector!r} tidak ada"
    return m.group(1)


@pytest.fixture
def env(monkeypatch):
    bench = FakeBench(context.layout.root).__enter__()
    deps = builds.Deps(layout=context.layout, db=context.db, redis=live_redis(), bench_spool=shellspool.make_spool(context.layout.root / "benchspool"),
                       op_pickup_timeout=3.0, poll=0.02, job_timeout=3300)
    monkeypatch.setattr(routes_build, "_deps", lambda: deps)
    yield
    bench.__exit__(None, None, None)


def page(client, aid: int, bid: int) -> str:
    r = client.get(f"/analyses/{aid}/build/{bid}", headers=BROWSER)
    assert r.status_code == 200
    return r.text


# ====================================================================================== invarian CSS
def test_the_tab_strip_is_a_positioned_scroll_box_so_sr_only_cannot_widen_the_document():
    body = rule(".tabs")
    assert "overflow-x: auto" in body and "position: relative" in body


def test_cards_use_a_shrinkable_grid_column_and_card_heads_wrap():
    assert "grid-template-columns: minmax(0, 1fr)" in rule(".card")
    assert "flex-wrap: wrap" in rule(".card-head")
    assert "min-width: 0" in rule(".card-head > *")
    assert "overflow-wrap: anywhere" in rule(".card-head h2")


def test_the_long_token_class_exists_and_wraps_anywhere():
    assert "overflow-wrap: anywhere" in rule(".token-panjang") and "min-width: 0" in rule(".token-panjang")
    assert "overflow-wrap: anywhere" in rule(".break")


def test_every_template_that_prints_untrusted_long_text_marks_it_wrappable():
    src = (TEMPLATES / "build_detail.html").read_text(encoding="utf-8")
    for needle in ("Ditolak. Alasan:", "b.error_code or", "b.hint }}"):
        line = next(ln for ln in src.splitlines() if needle in ln)
        assert 'class="break"' in line or 'class="muted break"' in line, needle


def test_no_build_template_uses_inline_style_or_inline_script():
    for name in ("build_detail.html", "build.html", "_build_parts.html"):
        src = (TEMPLATES / name).read_text(encoding="utf-8")
        assert not re.search(r"\sstyle\s*=", src) and not re.search(r"<script(?![^>]*\bsrc=)", src), name


# ====================================================================================== markup via test client
def test_long_error_and_rejection_texts_are_wrapped_in_break_paragraphs(client, seeded, env):
    aid = new_analysis("lay-err")
    bid = mk_build(aid, status="signing")
    with closing(context.db()) as conn:
        store.fail_build(conn, bid, error_code="build_failed", error_text=LONG, stage_log=None)
    html = page(client, aid, bid)
    assert re.search(r'<p class="break"><span class="mono">build_failed</span> · ' + LONG, html)
    rid = mk_build(new_analysis("lay-rej"), status="awaiting_approval")
    aid2 = query_analysis(rid)
    client.post(f"/analyses/{aid2}/build/{rid}/reject", data={"csrf": seeded.csrf, "reason": "a" * 150})
    assert re.search(r'<p class="muted break">Ditolak\. Alasan: a{150}', page(client, aid2, rid))


def query_analysis(bid: int) -> int:
    from conftest import query
    return query("SELECT analysis_id FROM build WHERE id = ?", bid)[0][0]


# ====================================================================================== invarian CSS: hasil build dan log
def test_hex_blocks_and_stage_log_have_wrap_rules_and_readable_size():
    h, log = rule(".build-hash"), rule(".build-log")
    assert "overflow-wrap: anywhere" in h and "word-break: break-all" in h and "display: block" in h
    assert "white-space: pre-wrap" in log and "overflow-wrap: anywhere" in log and "overflow: auto" in log
    for body in (h, log):
        assert float(re.search(r"font-size:\s*([\d.]+)rem", body).group(1)) >= 0.8125


def test_every_pre_in_the_stylesheet_wraps_or_scrolls_inside_its_own_box():
    for sel in (".build-log", ".browse-pre"):
        assert "overflow" in rule(sel), sel


def test_stage_log_summary_is_styled_and_touch_sized_with_focus_ring():
    assert "min-height: 44px" in rule(".build-fold > summary") and "cursor: pointer" in rule(".build-fold > summary")
    assert "outline" in rule(".build-fold > summary:focus-visible")
    assert ".build-fold[open] > summary::after" in CSS


def test_download_buttons_stack_full_width_on_narrow_screens():
    m = re.search(r"@media \(max-width: 640px\) \{\s*\.build-actions \{[^}]*\}\s*\.build-actions \.btn \{([^}]*)\}", CSS)
    assert m and "width: 100%" in m.group(1) and "min-height: 44px" in m.group(1)


# ====================================================================================== markup via test client: hasil build
def test_finished_build_marks_hashes_as_long_tokens_and_shows_verification_as_a_badge(client, seeded, env):
    aid = new_analysis("lay-done")
    bid, name, _p = mk_done(aid, script=b"#!/bin/sh\necho ok\n", kind="xapk")
    html = page(client, aid, bid)
    assert len(re.findall(r'<dd class="build-hash token-panjang">[0-9a-f]{64}</dd>', html)) == 3     # hash diff + artefak + sertifikat
    assert f'<dd class="mono break token-panjang">{name}</dd>' in html
    assert re.search(r'class="badge badge-done">.*?<span>Lulus</span>', html, re.S) and "satu penanda tangan" in html


def test_download_actions_put_the_primary_first_and_label_the_script_briefly(client, seeded, env):
    aid = new_analysis("lay-dl")
    bid, _n, _p = mk_done(aid, script=b"#!/bin/sh\necho ok\n", kind="xapk")
    html = page(client, aid, bid)
    row = re.search(r'<div class="btn-row build-actions">(.*?)</div>', html, re.S).group(1)
    assert row.index("btn-primary") < row.index("btn-ghost") and f"/build/{bid}/download" in row and f"/build/{bid}/script" in row
    assert "<span>Unduh XAPK</span>" in row and "<span>Unduh skrip adb</span>" in row and "install-multiple" not in row
    assert "adb install-multiple" in html           # penjelasan pindah ke keterangan di bawah tombol
    single = page(client, aid := new_analysis("lay-dl2"), (b := mk_done(aid))[0])
    assert f"/build/{b[0]}/script" not in single and "Skrip adb berisi" not in single


def test_stage_log_is_a_styled_fold_with_a_line_count_and_escaped_content(client, seeded, env):
    aid = new_analysis("lay-log")
    bid, _n, _p = mk_done(aid)
    with closing(context.db()) as conn:
        conn.execute("UPDATE build SET stage_log = ? WHERE id = ?", ("build: 23.2 dtk\nbadging: paket=a versionCode=3\n<b>x</b>", bid))
        conn.commit()
    html = page(client, aid, bid)
    assert '<details class="build-fold">' in html and '<summary id="bl-title">Catatan tahap build <span class="count-pill">3 baris</span></summary>' in html
    assert '<pre class="build-log">' in html and "&lt;b&gt;x&lt;/b&gt;" in html and "<b>x</b>" not in html
