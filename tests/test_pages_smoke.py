"""Uji asap: setiap halaman terbuka (200) untuk pengguna yang login, dan menolak yang belum login. Struktur dasar aksesibilitas ikut dicek."""

from __future__ import annotations

import re

import pytest

from conftest import BROWSER, new_analysis

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


def test_buttons_use_matching_icons(client, seeded):
    """Kirim = pesawat kertas, Buka Chat = gelembung pesan, Jalankan analisis = putar; bukan ikon 'activity' (denyut) (audit UI-07)."""
    pulse = '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>'
    chat = client.get(f"/analyses/{seeded.aid}/chat", headers=BROWSER).text
    send = re.search(r"<button[^>]*data-send>(.*?)</button>", chat, re.S).group(1)
    assert '<path d="M22 2 11 13"/>' in send and pulse not in send
    # Tombol "Buka Chat" hanya tampil pada keadaan kosong, jadi pakai analisis baru (tes lain sudah membuat berkas di analisis utama).
    files = client.get(f"/analyses/{new_analysis('ikon')}/files", headers=BROWSER).text
    open_chat = re.search(r'<a class="btn btn-primary btn-sm" href="/analyses/\d+/chat">(.*?)</a>', files, re.S).group(1)
    assert "M21 15a2 2 0 0 1-2 2H7l-4 4V5" in open_chat and pulse not in open_chat


def test_login_page(anon):
    r = anon.get("/login", headers=BROWSER)
    assert r.status_code == 200 and 'autocomplete="current-password"' in r.text and 'name="csrf"' in r.text
