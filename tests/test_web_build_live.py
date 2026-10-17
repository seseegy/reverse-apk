"""UI-16: polling parsial halaman detail build (endpoint fragmen `/live` + `build.js`), tanpa reload halaman selama build berjalan.

Klien uji = TestClient atas aplikasi nyata. Perilaku JS di browser tidak diuji di sini (tidak ada kerangka tes JS di repo): hanya kontrak
statis berkas JS dan markup. Tidak dibuktikan di sini: gulir/fokus/seleksi di browser nyata.
"""

from __future__ import annotations

import json
import re
from contextlib import closing

import pytest
from conftest import BROWSER, FETCH, ROOT
from rvcore import store
from test_web_build_ui import mk_build, mk_done, new_analysis

from app import context

JS = ROOT / "services/web/app/static/js/build.js"
CSS = ROOT / "services/web/app/static/css/app.css"
TEMPLATES = ROOT / "services/web/app/templates"
MARK = "RAHASIA-PENANDA-9f3"


def live(client, aid, bid, **kw):
    return client.get(f"/analyses/{aid}/build/{bid}/live", headers=FETCH, **kw)


def page(client, aid, bid) -> str:
    return client.get(f"/analyses/{aid}/build/{bid}", headers=BROWSER).text


# ====================================================================================== (a) wajib login
def test_live_without_a_session_is_401_json_no_store(anon, seeded):
    aid = new_analysis("lv-anon")
    bid = mk_build(aid, status="building")
    r = live(anon, aid, bid)
    assert r.status_code == 401 and r.headers["cache-control"] == "no-store" and "fragment" not in r.text


# ====================================================================================== (b) cakupan analisis
def test_live_of_another_analysis_build_or_missing_build_is_404(client, seeded):
    a1, a2 = new_analysis("lv-own-1"), new_analysis("lv-own-2")
    bid = mk_build(a1, status="building")
    r = live(client, a2, bid)
    assert live(client, a1, bid).status_code == 200, "kontrol: pemilik sah dilayani"
    assert r.status_code == 404 and "fragment" not in r.text and r.headers["cache-control"] == "no-store"
    assert live(client, a1, bid + 9999).status_code == 404
    assert live(client, a1 + 9999, bid).status_code == 404


# ====================================================================================== bentuk payload
@pytest.mark.parametrize("status,needle", [("queued", "Antre"), ("building", "Membangun"), ("signing", "Menandatangani")])
def test_live_payload_shape(client, seeded, status, needle):
    aid = new_analysis(f"lv-shape-{status}")
    bid = mk_build(aid, status=status)
    r = live(client, aid, bid)
    d = r.json()
    assert r.status_code == 200 and set(d) == {"status", "label", "final", "cancel_requested", "fragment"}
    assert d["status"] == status and d["final"] is False and d["cancel_requested"] is False
    assert needle in d["fragment"] and 'data-live-slot="badge"' in d["fragment"] and 'data-live-slot="text"' in d["fragment"]
    assert r.headers["cache-control"] == "no-store"


def test_live_final_status_is_flagged_final(client, seeded):
    aid = new_analysis("lv-final")
    bid, _n, _p = mk_done(aid)
    d = live(client, aid, bid).json()
    assert d["status"] == "done" and d["final"] is True


def test_cancel_requested_is_reflected(client, seeded):
    aid = new_analysis("lv-cancel")
    bid = mk_build(aid, status="building")
    with closing(context.db()) as conn:
        conn.execute("UPDATE build SET cancel_requested = 1 WHERE id = ?", (bid,))
        conn.commit()
    d = live(client, aid, bid).json()
    assert d["cancel_requested"] is True and "Pembatalan sudah diminta" in d["fragment"]


# ====================================================================================== (c) tanpa data sensitif
def test_live_payload_leaks_nothing_sensitive(client, seeded):
    aid = new_analysis("lv-leak")
    bid, name, payload = mk_done(aid)
    with closing(context.db()) as conn:
        conn.execute("UPDATE build SET error_text = ?, stage_log = ?, rejected_reason = ?, status = 'signing', finished_at = NULL WHERE id = ?",
                     (f"{MARK}-error " + "x" * 400, f"{MARK}-log\n/srv/data/rahasia/path", f"{MARK}-tolak", bid))
        conn.commit()
    with closing(context.db()) as conn:
        row = dict(store.get_build(conn, bid, analysis_id=aid))
    r = live(client, aid, bid)
    assert r.status_code == 200 and r.json()["status"] == "signing"
    text = r.text
    for secret in (MARK, name, row["output_sha256"], row["diff_sha256"], row["cert_sha256"], str(context.layout.build_dir(aid, bid)), "/srv/data", seeded.csrf):
        assert secret and secret not in text, secret
    for bad in ("/download", "/script", "csrf", "<form", "<script", "href=", "onclick", "style="):
        assert bad not in text.lower(), bad
    assert not re.search(r"[0-9a-f]{40,}", text), "tidak ada hash panjang"
    assert seeded.cookie not in text


# ====================================================================================== (d) ukuran terbatas
def test_live_fragment_is_small_even_with_huge_error_and_log(client, seeded):
    aid = new_analysis("lv-size")
    bid = mk_build(aid, status="building")
    with closing(context.db()) as conn:
        conn.execute("UPDATE build SET error_text = ?, stage_log = ? WHERE id = ?", ("E" * 500, "L" * 4000, bid))
        conn.commit()
    r = live(client, aid, bid)
    assert r.status_code == 200 and len(r.content) < 2048 and len(r.json()["fragment"]) < 2048


# ====================================================================================== (e) validasi parameter
@pytest.mark.parametrize("raw", ["abc", "0", "-1", "1.5", "%00", "1" * 400, "99999999999999999999", "0x10", "%20", "1e3"])
def test_live_rejects_bad_build_ids_without_500(client, seeded, raw):
    aid = new_analysis("lv-badid")
    assert live(client, aid, mk_build(aid, status="building")).status_code == 200, "kontrol: id valid dilayani"
    r = client.get(f"/analyses/{aid}/build/{raw}/live", headers=FETCH)
    assert r.status_code in (400, 404) and r.status_code != 500 and r.headers["cache-control"] == "no-store"
    assert "fragment" not in r.text


@pytest.mark.parametrize("raw", ["abc", "0", "-1", "1" * 400])
def test_live_rejects_bad_analysis_ids_without_500(client, seeded, raw):
    aid = new_analysis("lv-badaid")
    assert live(client, aid, mk_build(aid, status="building")).status_code == 200, "kontrol: id valid dilayani"
    r = client.get(f"/analyses/{raw}/build/1/live", headers=FETCH)
    assert r.status_code in (400, 404) and "fragment" not in r.text


def test_unknown_query_params_are_ignored(client, seeded):
    aid = new_analysis("lv-query")
    bid = mk_build(aid, status="queued")
    r = client.get(f"/analyses/{aid}/build/{bid}/live?status=done&kind=x&" + "q=" + "z" * 5000, headers=FETCH)
    assert r.status_code == 200 and r.json()["status"] == "queued"


# ====================================================================================== (f) hanya GET
@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_live_only_allows_get(client, seeded, method):
    aid = new_analysis(f"lv-method-{method}")
    bid = mk_build(aid, status="queued")
    r = getattr(client, method)(f"/analyses/{aid}/build/{bid}/live", headers={"X-CSRF-Token": seeded.csrf})
    assert r.status_code == 405
    assert store_status(bid) == "queued"


def store_status(bid: int) -> str:
    with closing(context.db()) as conn:
        return conn.execute("SELECT status FROM build WHERE id = ?", (bid,)).fetchone()[0]


def test_live_is_read_only(client, seeded):
    aid = new_analysis("lv-readonly")
    bid = mk_build(aid, status="building")
    with closing(context.db()) as conn:
        before = [tuple(r) for r in conn.execute("SELECT * FROM build WHERE id = ?", (bid,))]
        audit = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    for _ in range(3):
        live(client, aid, bid)
    with closing(context.db()) as conn:
        assert [tuple(r) for r in conn.execute("SELECT * FROM build WHERE id = ?", (bid,))] == before
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == audit


# ====================================================================================== fragmen = render awal
def test_initial_page_renders_the_same_fragment_as_the_endpoint(client, seeded):
    aid = new_analysis("lv-same")
    bid = mk_build(aid, status="building")
    html = page(client, aid, bid)
    frag = live(client, aid, bid).json()["fragment"]
    badge, text = re.findall(r'<(?:div|p)[^>]*data-live-slot="(?:badge|text)"[^>]*>(.*?)</(?:div|p)>', frag, re.S)
    assert badge.strip() in html and " ".join(text.split()) in " ".join(html.split())


# ====================================================================================== (g) markup halaman detail
def test_detail_page_has_live_url_external_js_and_noscript_fallback(client, seeded):
    aid = new_analysis("lv-markup")
    bid = mk_build(aid, status="queued")
    html = page(client, aid, bid)
    assert f'data-build-live="/analyses/{aid}/build/{bid}/live"' in html and f'data-build-poll="/analyses/{aid}/build/{bid}/status"' in html
    assert '<script src="/static/js/build.js" defer></script>' in html
    assert "<noscript>" in html and 'http-equiv="refresh"' in html and "Muat ulang status" in html
    assert 'data-live-slot="badge"' in html and 'data-live-slot="text"' in html
    assert 'data-live-meta' in html and "data-live-busy" in html and "data-live-updated" in html
    assert 'aria-live="polite"' in html
    assert not re.search(r"<script(?![^>]*\bsrc=)", html) and " style=" not in html and "onclick" not in html


def test_noscript_refresh_is_inside_noscript_in_head_only_while_polling(client, seeded):
    aid = new_analysis("lv-noscript")
    html = page(client, aid, mk_build(aid, status="building"))
    head = html.split("</head>")[0]
    assert re.search(r'<noscript>\s*<meta http-equiv="refresh" content="\d+">\s*</noscript>', head)
    done = page(client, (a2 := new_analysis("lv-noscript-done")), mk_done(a2)[0])
    assert 'http-equiv="refresh"' not in done and "data-build-live" not in done and "<noscript>" not in done
    waiting = page(client, (a3 := new_analysis("lv-noscript-wait")), mk_build(a3, status="awaiting_approval"))
    assert 'http-equiv="refresh"' not in waiting and "data-build-live" not in waiting


def test_list_page_also_has_noscript_fallback_while_active(client, seeded):
    aid = new_analysis("lv-list-noscript")
    mk_build(aid, status="building")
    html = client.get(f"/analyses/{aid}/build", headers=BROWSER).text
    assert 'http-equiv="refresh"' in html.split("</head>")[0] and "Muat ulang status" in html and "data-build-live" not in html


def test_forms_stay_outside_live_slots_and_keep_csrf(client, seeded):
    aid = new_analysis("lv-forms")
    bid = mk_build(aid, status="queued")
    html = page(client, aid, bid)
    assert html.count("<form method=\"post\" action=\"/analyses/%d/build/%d/requeue\"" % (aid, bid)) == 1
    assert 'data-live-show="approved queued"' in html and "data-live-cancel" in html
    for action in ("requeue", "cancel"):
        form = html[html.index(f"/build/{bid}/{action}"):].split("</form>")[0]
        assert 'name="csrf"' in form
    frag = live(client, aid, bid).json()["fragment"]
    assert "<form" not in frag and "csrf" not in frag


def test_live_fragment_uses_jinja_autoescape_macro_not_safe():
    macros = (TEMPLATES / "_build_parts.html").read_text(encoding="utf-8")
    assert "macro build_live" in macros
    for name in ("_build_parts.html", "build_detail.html", "build_live.html"):
        p = TEMPLATES / name
        if p.exists():
            assert "|safe" not in p.read_text(encoding="utf-8"), name


# ====================================================================================== (h) CSP
def test_csp_has_no_unsafe_inline_and_allows_same_origin_fetch(client, seeded):
    aid = new_analysis("lv-csp")
    r = client.get(f"/analyses/{aid}/build/{mk_build(aid, status='building')}", headers=BROWSER)
    csp = r.headers["content-security-policy"]
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp and "script-src 'self'" in csp and "connect-src 'self'" in csp
    assert "unsafe-inline" not in live(client, aid, 1).headers.get("content-security-policy", "")


# ====================================================================================== kontrak statis build.js
def test_js_state_machine_contract():
    js = JS.read_text(encoding="utf-8")
    assert "node --check" not in js
    for token in ("visibilitychange", "clearTimeout", "30000", "replaceChildren", "AbortController", "DOMParser", "data-build-live", "pagehide", "sessionStorage", "location.reload"):
        assert token in js, token
    for bad in ("eval(", "new Function", "setInterval", "document.write", "innerHTML", "outerHTML", "insertAdjacentHTML"):
        assert bad not in js, bad
    assert js.count("setTimeout(") == 1, "satu titik penjadwalan = satu timer"
    assert re.search(r"\bidle\b", js) and all(s in js for s in ("backoff", "paused", "final"))


def test_js_never_logs_or_exposes_csrf_and_only_fetches_data_attribute_urls():
    js = JS.read_text(encoding="utf-8")
    assert "csrf" not in js.lower() and "console." not in js and "XMLHttpRequest" not in js
    assert re.findall(r"fetch\(([^,)]+)", js) == ["url"], "fetch hanya ke URL dari atribut data halaman"


def test_js_node_syntax_is_valid():
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node tidak tersedia")
    r = subprocess.run([node, "--check", str(JS)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr


# ====================================================================================== CSS indikator
def test_live_meta_reserves_space_and_respects_reduced_motion():
    css = CSS.read_text(encoding="utf-8")
    m = re.search(r"\.build-live-meta\s*\{([^}]*)\}", css)
    assert m and "min-height" in m.group(1)
    busy = re.search(r"\.build-live-busy\s*\{([^}]*)\}", css)
    assert busy and "visibility" in busy.group(1) and "display: none" not in busy.group(1)
    assert "build-live-busy" in css.split("prefers-reduced-motion")[-1] or "animation" not in busy.group(1)


def test_live_endpoint_json_is_parseable_and_utf8(client, seeded):
    aid = new_analysis("lv-json")
    bid = mk_build(aid, status="building")
    r = live(client, aid, bid)
    assert json.loads(r.content.decode("utf-8"))["status"] == "building" and r.headers["content-type"].startswith("application/json")
