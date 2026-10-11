"""Uji asap: setiap halaman terbuka (200) untuk pengguna yang login, dan menolak yang belum login. Struktur dasar aksesibilitas ikut dicek."""

from __future__ import annotations

import re

import pytest

from conftest import BROWSER

ANALYSIS_TABS = ["", "/findings", "/network", "/code", "/chat", "/files", "/manifest"]


def pages(aid: int) -> list[str]:
    return ["/", "/upload"] + [f"/analyses/{aid}{t}" for t in ANALYSIS_TABS]


def test_pages_render_for_logged_in_user(client, seeded):
    for path in pages(seeded.aid):
        r = client.get(path, headers=BROWSER)
        assert r.status_code == 200, path
        html = r.text
        assert 'lang="id"' in html and len(re.findall(r"<h1\b", html)) == 1, path
        assert "<script>" not in html and " style=" not in html, f"{path}: skrip/gaya inline melanggar CSP"
        assert r.headers["cache-control"] == "no-store" and "content-security-policy" in r.headers, path


@pytest.mark.parametrize("tab", ANALYSIS_TABS)
def test_pages_redirect_anonymous_to_login(anon, seeded, tab):
    r = anon.get(f"/analyses/{seeded.aid}{tab}", headers=BROWSER)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_login_page(anon):
    r = anon.get("/login", headers=BROWSER)
    assert r.status_code == 200 and 'autocomplete="current-password"' in r.text and 'name="csrf"' in r.text
