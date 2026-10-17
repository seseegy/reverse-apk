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
from test_web_build_ui import mk_build, new_analysis
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
