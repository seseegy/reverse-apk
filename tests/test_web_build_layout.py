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
from test_web_build_ui import mk_build, mk_done, new_analysis, summary
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


# ====================================================================================== invarian CSS: ringkasan diff, filter, daftar batas
def test_stat_grid_has_two_shrinkable_columns_on_phones_and_numbers_never_break():
    assert "white-space: nowrap" in rule(".build-stats dd") and "min-width: 0" in rule(".build-stats > div")
    m = re.search(r"@media \(max-width: 640px\) \{\s*\.build-stats \{([^}]*)\}", CSS)
    assert m and "repeat(2, minmax(0, 1fr))" in m.group(1)


def test_filter_row_stacks_full_width_on_narrow_screens_and_buttons_are_44px():
    assert "min-height: 44px" in rule(".build-filters .btn")
    m = re.search(r"@media \(max-width: 640px\) \{[^@]*?\.build-filters \{([^}]*)\}\s*\.build-filters \.field, \.build-filters \.field-grow \{([^}]*)\}", CSS)
    assert m and "flex-direction: column" in m.group(1) and "width: 100%" in m.group(2) and "min-width: 0" in m.group(2)


def test_kind_chips_wrap_and_are_touch_sized_on_phones():
    assert "flex-wrap: wrap" in rule(".kind-chips")
    assert re.search(r"@media \(max-width: 640px\) \{[^@]*\.kind-chips \.chip \{ min-height: 44px", CSS)


def test_not_promised_list_has_a_readable_measure_and_item_spacing():
    body = rule(".build-limits")
    assert "max-width: 70ch" in body and "gap: var(--space-2)" in body and "line-height: 1.6" in body
    assert "border-top" in rule(".build-limits + .hint")


# ====================================================================================== markup via test client: ringkasan diff
def test_diff_summary_splits_sizes_into_separate_metrics_and_keeps_every_label(client, seeded, env):
    aid = new_analysis("lay-stats")
    bid = mk_build(aid)
    html = page(client, aid, bid)
    stats = re.search(r'<dl class="build-stats">(.*?)</dl>', html, re.S).group(1)
    labels = re.findall(r"<dt>(.*?)</dt>", stats)
    assert labels == ["Berkas baru", "Berkas diubah", "Berkas dihapus", "Baris ditambah", "Baris dihapus", "Ukuran baru", "Ukuran diubah", "Ukuran dihapus"]
    assert "/ 0 B /" not in stats and "−2" in stats and "+5" in stats


def test_kind_chips_and_filter_forms_use_the_responsive_classes_and_keep_their_fields(client, seeded, env):
    aid = new_analysis("lay-filter")
    bid = mk_build(aid, data=summary())
    html = page(client, aid, bid)
    chips = re.search(r'<div class="kind-chips" role="group" aria-label="Saring per jenis">(.*?)</div>', html, re.S).group(1)
    assert 'href="?kind=smali">Smali (kode): 1</a>' in chips
    assert html.count('class="filters build-filters"') == 2           # saringan diff + form tolak
    f = re.search(r'<form method="get" class="filters build-filters".*?</form>', html, re.S).group(0)
    assert 'name="kind"' in f and 'name="q"' in f and "Saring</span>" in f
    # form persetujuan tak berubah: CSRF, hash diff, versi pernyataan, kotak centang wajib
    assert 'name="csrf"' in html and 'name="diff_sha256"' in html and 'name="statement_version"' in html
    assert re.search(r'<input id="stmt" type="checkbox" name="statement" value="1" required>', html)


def test_skipped_files_note_is_its_own_paragraph(client, seeded, env):
    aid = new_analysis("lay-skip")
    bid = mk_build(aid, data=summary(lines={"plus": 5, "minus": 2, "files": 3, "skipped_files": 4}))
    assert '<p class="muted hint">4 berkas tidak dihitung barisnya (biner atau terlalu besar).</p>' in page(client, aid, bid)


def test_not_promised_section_renders_items_in_a_list_followed_by_the_notice(client, seeded, env):
    aid = new_analysis("lay-np")
    bid = mk_build(aid)
    html = page(client, aid, bid)
    m = re.search(r'<ul class="build-limits">(.*?)</ul>\s*<p class="muted hint">(.*?)</p>', html, re.S)
    assert m and m.group(1).count("<li>") >= 3 and builds.LIMIT_NOTICE in m.group(2)


def test_alert_text_wraps_long_codes_such_as_warning_identifiers():
    assert re.search(r"^\.alert > div, \.alert > span \{[^}]*overflow-wrap: anywhere", CSS, re.M)


# ---------- Area B: tabel diff responsif ----------
def test_diff_table_scrolls_in_its_wrapper_keeps_a_min_width_and_hints_the_scroll():
    assert "overflow-x: auto" in rule(".table-wrap")
    assert re.search(r"min-width:\s*\d+rem", rule(".build-table"))
    assert "background" in rule(".table-scroll") and "local" in rule(".table-scroll")
    assert "display: block" in re.search(r"@media \(max-width: 640px\) \{ \.scroll-hint \{([^}]*)\}", CSS).group(1)


def test_diff_path_wraps_at_slashes_not_at_every_character_and_numbers_are_compact_and_right_aligned():
    p = rule(".build-path")
    assert "overflow-wrap: anywhere" in p and "break-all" not in p
    assert "nowrap" in rule(".build-table th, .build-table td.num, .build-table td.col-op")
    assert "tabular-nums" in rule(".build-table td.num") and "text-align: right" in rule(".num")


def test_diff_table_renders_caption_scoped_headers_and_wbr_paths_escaped(client, seeded, env):
    aid = new_analysis("lay-table")
    top = [{"op": "M", "kind": "f", "path": f"smali_classes{n % 4 + 2}/ai/<b>c{n}</b>.smali", "size": 2000 + n, "plus": n, "minus": 1} for n in range(40)]
    bid = mk_build(aid, data=summary(top=top, kinds={"smali": 40, "res": 0, "manifest": 0, "aset": 0, "lib": 0, "lain": 0}))
    html = page(client, aid, bid)
    assert '<caption class="sr-only">Berkas Smali (kode)' in html
    assert html.count('scope="col"') >= 5
    assert "smali_classes2/<wbr>ai/<wbr>&lt;b&gt;c" in html and "<b>c" not in html
    assert 'class="table-wrap table-scroll" tabindex="0" role="region"' in html
    assert 'style="' not in html


def test_empty_diff_renders_no_table_but_the_empty_state(client, seeded, env):
    aid = new_analysis("lay-empty")
    bid = mk_build(aid, data=summary(top=[]))
    html = page(client, aid, bid)
    assert "Tidak ada berkas yang cocok dengan saringan." in html
    assert "build-table" not in html


# ====================================================================================== area C: daftar build, state, copy
def list_page(client, aid: int) -> str:
    r = client.get(f"/analyses/{aid}/build", headers=BROWSER)
    assert r.status_code == 200
    return r.text


def test_build_list_stacks_into_cards_on_phones_with_touch_sized_links():
    css = CSS[CSS.index("Daftar build (build.html)"):]
    assert "@media (max-width: 640px)" in css and "attr(data-label)" in css and "display: block" in css
    assert "min-height: 44px" in rule(".build-open")
    assert "overflow-wrap: anywhere" in css


def test_global_focus_ring_and_build_summary_focus_exist():
    assert re.search(r"^:focus-visible\s*\{[^}]*outline: 2px solid var\(--color-ring\)", CSS, re.M)
    assert ".build-fold > summary:focus-visible" in CSS


def test_build_list_renders_a_row_per_state_with_labels_and_long_outputs_wrapped(client, seeded, env):
    aid = new_analysis("lay-list")
    done, _, _ = mk_done(aid)
    done2, _, _ = mk_done(aid, kind="xapk")
    ids = {"awaiting_approval": mk_build(aid)}          # satu build aktif per analisis; yang lain sudah selesai
    html = list_page(client, aid)
    for bid in [*ids.values(), done, done2]:
        assert f'href="/analyses/{aid}/build/{bid}"' in html
    assert html.count('data-label="Status"') == 3 and html.count('data-label="Hasil"') == 3
    assert '<caption class="sr-only">' in html and html.count('scope="col"') == 6
    assert f'class="build-open" href="/analyses/{aid}/build/{ids["awaiting_approval"]}">Tinjau dan setujui' in html
    assert 'style="' not in html
    assert "Menampilkan 50 build terbaru" not in html


def test_build_list_empty_state_has_icon_and_guidance(client, seeded, env):
    aid = new_analysis("lay-list-empty")
    html = list_page(client, aid)
    assert "Belum ada build." in html and "files-empty" in html and "build-list" not in html


def test_approval_form_keeps_csrf_statement_and_diff_binding(client, seeded, env):
    aid = new_analysis("lay-approve")
    bid = mk_build(aid)
    html = page(client, aid, bid)
    form = html[html.index('class="approve-box"'):]
    for needle in ('name="csrf"', 'name="diff_sha256"', 'name="statement_version"', 'name="statement" value="1" required'):
        assert needle in form


def test_table_headers_and_filter_button_use_consistent_indonesian_copy(client, seeded, env):
    aid = new_analysis("lay-copy")
    html = page(client, aid, mk_build(aid))
    assert ">Aksi<" in html and ">+ Baris<" in html and ">− Baris<" in html and "Terapkan" not in html


def test_status_poll_script_restores_scroll_after_reload_without_new_dependencies():
    js = (ROOT / "services/web/app/static/js/build.js").read_text(encoding="utf-8")
    assert "sessionStorage" in js and "scrollTo" in js and "eval(" not in js


def test_build_list_badge_may_wrap_so_it_never_widens_the_card_at_320px():
    body = rule(".build-list .badge")
    assert "max-width: 100%" in body and "white-space: normal" in body
