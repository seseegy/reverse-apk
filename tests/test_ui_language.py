"""Bahasa antarmuka seragam Indonesia (audit UI-06): Dashboard -> Beranda, Upload -> Unggah, Chat -> Percakapan, Manifest -> Manifes.

Yang diperiksa HANYA teks yang terlihat pengguna. URL (/chat, /upload, /manifest), kelas CSS, id, atribut data-*, nama tool AI,
dan log operator sengaja tetap memakai istilah lama karena itu kode, bukan tampilan.
"""

from __future__ import annotations

import html as htmllib
import re

import pytest

from conftest import BROWSER

OLD_WORDS = re.compile(r"\b(dashboard|upload|chat|manifest)\b", re.IGNORECASE)


def visible_text(page: str) -> str:
    """Teks yang dilihat pengguna: tanpa <script>/<style>/komentar/tag, plus nilai atribut yang dibacakan (aria-label, title, placeholder)."""
    body = re.sub(r"<(script|style)\b.*?</\1>|<!--.*?-->", " ", page, flags=re.S | re.I)
    spoken = " ".join(re.findall(r'(?:aria-label|title|placeholder|alt)="([^"]*)"', body))
    confirm = " ".join(re.findall(r'data-confirm="([^"]*)"', body))
    text = re.sub(r"<[^>]+>", " ", body)
    return htmllib.unescape(re.sub(r"\s+", " ", f"{text} {spoken} {confirm}"))


def pages(aid: int) -> dict[str, str]:
    return {"Beranda": "/", "Unggah": "/upload", "Ringkasan": f"/analyses/{aid}", "Temuan": f"/analyses/{aid}/findings",
            "Jaringan": f"/analyses/{aid}/network", "Kode": f"/analyses/{aid}/code", "Percakapan": f"/analyses/{aid}/chat",
            "Berkas": f"/analyses/{aid}/files", "Manifes": f"/analyses/{aid}/manifest"}


def test_main_menu_labels(client):
    nav = re.search(r'<nav aria-label="Navigasi utama">(.*?)</nav>', client.get("/", headers=BROWSER).text, re.S).group(1)
    assert [re.sub(r"<[^>]+>|\s+", " ", t).strip() for t in re.findall(r"<a[^>]*>(.*?)</a>", nav, re.S)] == ["Beranda", "Unggah", "Penyimpanan", "Pengaturan AI"]


def test_analysis_tab_labels(client, seeded):
    html = client.get(f"/analyses/{seeded.aid}", headers=BROWSER).text
    nav = re.search(r'<nav class="tabs"[^>]*>(.*?)</nav>', html, re.S).group(1)
    # Tab bisa membawa lencana angka (Berkas 3) atau teks bantu pembaca layar (Percakapan "(asisten sedang bekerja)"):
    # yang diperiksa hanya nama tabnya, di awal teks.
    labels = [re.sub(r"<[^>]+>|\s+", " ", t).strip() for t in re.findall(r"<a[^>]*>(.*?)</a>", nav, re.S)]
    expected = ["Ringkasan", "Temuan", "Jaringan", "Kode", "Percakapan", "Berkas", "Manifes", "Build"]
    assert len(labels) == len(expected) and all(l == n or l.startswith(n + " ") for l, n in zip(labels, expected)), labels


def test_urls_are_unchanged(client, seeded):
    """Hanya tampilan yang berubah: alamat tetap, supaya tautan lama dan bookmark tidak putus."""
    html = client.get(f"/analyses/{seeded.aid}", headers=BROWSER).text
    for path in (f"/analyses/{seeded.aid}/chat", f"/analyses/{seeded.aid}/manifest"):
        assert f'href="{path}' in html
    assert 'href="/upload"' in client.get("/", headers=BROWSER).text


@pytest.mark.parametrize("name", ["Beranda", "Unggah", "Ringkasan", "Temuan", "Jaringan", "Kode", "Percakapan", "Berkas", "Manifes"])
def test_no_old_english_labels_in_visible_text(client, seeded, name):
    path = pages(seeded.aid)[name]
    r = client.get(path, headers=BROWSER)
    assert r.status_code == 200
    leftovers = sorted({m.group(0) for m in OLD_WORDS.finditer(visible_text(r.text))})
    assert not leftovers, f"{path}: masih ada {leftovers} di teks yang terlihat pengguna"


def test_page_titles(client, seeded):
    for name, path in pages(seeded.aid).items():
        if name in ("Ringkasan", "Temuan", "Jaringan", "Kode", "Berkas"):
            continue
        title = re.search(r"<title>(.*?)</title>", client.get(path, headers=BROWSER).text, re.S).group(1)
        assert title.startswith(name), f"{path}: judul tab browser '{title}'"


def test_error_page_back_button(client):
    text = visible_text(client.get("/nope", headers=BROWSER).text)
    assert "Kembali ke beranda" in text and "dashboard" not in text.lower()


def test_user_visible_server_messages(client, seeded, json_headers):
    r = client.post(f"/analyses/{seeded.aid}/chat/send", content='{"text":"x","session_id":999999}', headers=json_headers)
    assert r.status_code == 404 and "percakapan" in r.json()["error"].lower() and "chat" not in r.json()["error"].lower()
