"""UI-14: pagination sungguhan daftar build (`?halaman=N`), sisi server, tanpa JS.

Klien uji = TestClient atas aplikasi nyata (conftest). Build dibuat lewat fungsi store (dibuat lalu ditolak, supaya tidak ada build aktif)
sehingga ratusan baris murah. Tidak dibuktikan di sini: tampilan piksel di browser/ponsel nyata.
"""

from __future__ import annotations

import re
from contextlib import closing

import pytest
from conftest import BROWSER, ROOT
from rvcore import store
from test_web_build_ui import mk_build, new_analysis

from app import context, routes_build

TEMPLATES = ROOT / "services/web/app/templates"


def many(aid: int, n: int) -> list[int]:
    """n build final (ditolak) untuk analisis `aid`, id menaik."""
    ids = []
    with closing(context.db()) as conn:
        for i in range(n):
            bid = store.create_build(conn, aid, requested_by="user", source_kind="apk", diff_sha256=f"{aid:04x}{i:060x}", diff_summary={"files": 1})
            store.reject_build(conn, bid, "uji")
            ids.append(bid)
    return ids


def get(client, aid: int, qs: str = ""):
    return client.get(f"/analyses/{aid}/build{qs}", headers=BROWSER, follow_redirects=False)


def shown(html: str, aid: int) -> list[int]:
    return [int(x) for x in re.findall(rf'<th scope="row" class="build-id"><a class="build-open" href="/analyses/{aid}/build/(\d+)"', html)]


@pytest.fixture
def big(client, seeded):
    aid = new_analysis("pg-big")
    other = new_analysis("pg-other")
    other_ids = many(other, 7)
    ids = many(aid, 120)
    return aid, ids, other_ids


def test_page_one_shows_newest_fifty_and_label(client, big):
    aid, ids, other_ids = big
    r = get(client, aid)
    assert r.status_code == 200
    assert shown(r.text, aid) == sorted(ids, reverse=True)[:50]
    assert "Menampilkan 1–50 dari 120" in r.text
    assert 'rel="next"' in r.text and 'rel="prev"' not in r.text
    assert 'href="?halaman=2"' in r.text


def test_middle_and_last_page(client, big):
    aid, ids, _ = big
    newest = sorted(ids, reverse=True)
    r2 = get(client, aid, "?halaman=2")
    assert shown(r2.text, aid) == newest[50:100] and "Menampilkan 51–100 dari 120" in r2.text
    assert 'href="?halaman=1"' in r2.text and 'href="?halaman=3"' in r2.text
    assert "halaman 2 dari 3" in r2.text
    r3 = get(client, aid, "?halaman=3")
    assert shown(r3.text, aid) == newest[100:] and "Menampilkan 101–120 dari 120" in r3.text
    assert 'rel="next"' not in r3.text and 'rel="prev"' in r3.text


def test_pages_are_stable_newest_first_without_duplicates_or_gaps(client, big):
    aid, ids, _ = big
    seen: list[int] = []
    for p in (1, 2, 3):
        seen += shown(get(client, aid, f"?halaman={p}").text, aid)
    assert seen == sorted(ids, reverse=True) and len(set(seen)) == 120


def test_other_analysis_builds_neither_counted_nor_listed(client, big):
    aid, ids, other_ids = big
    html = "".join(get(client, aid, f"?halaman={p}").text for p in (1, 2, 3))
    assert not (set(other_ids) & set(shown(html, aid)))
    assert not re.search(rf"/build/({'|'.join(map(str, other_ids))})\"", html)
    assert "dari 127" not in html
    r = get(client, aid, "?halaman=3")
    assert "Menampilkan 101–120 dari 120" in r.text


def test_up_to_fifty_builds_has_no_pager_and_no_old_limit_note(client, seeded):
    aid = new_analysis("pg-small")
    many(aid, 50)
    html = get(client, aid).text
    assert len(shown(html, aid)) == 50 and 'class="pager"' not in html
    assert "Menampilkan 50 build terbaru" not in html


def test_empty_list_still_renders(client, seeded):
    aid = new_analysis("pg-empty")
    r = get(client, aid)
    assert r.status_code == 200 and "Belum ada build." in r.text and 'class="pager"' not in r.text


@pytest.mark.parametrize("raw", ["abc", "-1", "0", "1.5", "1e9", "%00", "", " 2", "+2", "٣", "2%20", "0x10"])
def test_garbage_page_redirects_to_first_page_without_500(client, big, raw):
    aid = big[0]
    r = get(client, aid, f"?halaman={raw}")
    assert r.status_code == 303 and r.headers["location"] == f"/analyses/{aid}/build"


@pytest.mark.parametrize("raw", ["4", "99", "99999999999999999999", "9" * 5000])
def test_out_of_range_page_redirects_to_last_page(client, big, raw):
    aid = big[0]
    r = get(client, aid, f"?halaman={raw}")
    assert r.status_code == 303 and r.headers["location"] == f"/analyses/{aid}/build?halaman=3"
    assert get(client, aid, "?halaman=3").status_code == 200


def test_repeated_parameter_does_not_crash(client, big):
    aid = big[0]
    r = get(client, aid, "?halaman=1&halaman=2")
    assert r.status_code in (200, 303) and "Traceback" not in r.text


def test_page_one_explicit_and_zero_padded_are_ok(client, big):
    aid = big[0]
    assert get(client, aid, "?halaman=1").status_code == 200
    assert get(client, aid, "?halaman=02").status_code == 200


def test_paging_needs_login(anon, seeded):
    aid = new_analysis("pg-anon")
    r = anon.get(f"/analyses/{aid}/build?halaman=2", headers=BROWSER, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_prev_next_are_plain_links_and_keep_no_transient_notice(client, big):
    aid = big[0]
    html = get(client, aid, "?halaman=2&notice=diminta").text
    nav = html[html.index('class="pager"'):]
    nav = nav[:nav.index("</nav>")]
    hrefs = re.findall(r'href="([^"]*)"', nav)
    assert hrefs == ["?halaman=1", "?halaman=3"]          # notice sekali-tampil tidak ikut; tidak ada parameter lain di daftar ini
    assert "<script" not in nav and "onclick" not in nav and "button" not in nav


def test_page_is_pure_html_without_inline_js_or_style(client, big):
    aid = big[0]
    html = get(client, aid, "?halaman=2").text
    assert 'style="' not in html and "onclick" not in html
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)


def test_active_build_alert_and_disabled_request_button_on_later_pages(client, seeded):
    aid = new_analysis("pg-active")
    many(aid, 60)
    active = mk_build(aid)                                   # awaiting_approval = aktif, id tertinggi (halaman 1)
    html = get(client, aid, "?halaman=2").text
    assert f"build #{active}" in html and f'href="/analyses/{aid}/build/{active}"' in html
    assert re.search(r'<button type="submit" class="btn btn-primary" disabled>', html)
    assert active not in shown(html, aid)


def test_page_size_constant_documented_and_is_fifty():
    assert routes_build.BUILD_PAGE_SIZE == 50
    src = (ROOT / "services/web/app/routes_build.py").read_text(encoding="utf-8")
    assert "BUILD_PAGE_SIZE = 50" in src and "store.list_builds(conn, analysis_id, 50)" not in src


def test_build_keep_semantics_untouched(client, big, monkeypatch):
    aid, ids, _ = big
    monkeypatch.delenv("BUILD_KEEP", raising=False)
    assert store.BUILD_KEEP_DEFAULT == 10 and (store.BUILD_KEEP_MIN, store.BUILD_KEEP_MAX) == (1, 100)
    with closing(context.db()) as conn:
        # prune hanya MENGUSULKAN id (retensi dipanggil worker); membuka halaman tidak menghapus apa pun
        assert len(store.prune_builds(conn, aid, 10)) == 110
        assert conn.execute("SELECT COUNT(*) FROM build WHERE analysis_id = ?", (aid,)).fetchone()[0] == 120
    get(client, aid, "?halaman=2")
    with closing(context.db()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM build WHERE analysis_id = ?", (aid,)).fetchone()[0] == 120


def test_list_query_uses_the_analysis_index(seeded):
    aid = new_analysis("pg-plan")
    many(aid, 3)
    with closing(context.db()) as conn:
        for sql in ("SELECT * FROM build WHERE analysis_id = ? ORDER BY id DESC LIMIT 50 OFFSET 50", "SELECT COUNT(*) FROM build WHERE analysis_id = ?"):
            plan = " ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + sql, (aid,)))
            assert "build_analysis" in plan and "SCAN" not in plan.replace("SCAN build USING", "") and "TEMP B-TREE" not in plan, plan
