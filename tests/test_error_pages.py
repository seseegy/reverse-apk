"""Halaman galat: halaman untuk browser, JSON {"error"} untuk JS, header keamanan pada 500 (audit BE-12; PR #27)."""

from __future__ import annotations

import re

import pytest

import app.main as main_mod
from app import routes_apk

from conftest import BROWSER, FETCH

SECURITY = {"content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy"}


def is_error_page(r, status: int, title: str) -> bool:
    t = r.text
    return (r.status_code == status and r.headers["content-type"].startswith("text/html") and title in t
            and len(re.findall(r"<h1\b", t)) == 1 and 'href="/"' in t and '"detail"' not in t and 'lang="id"' in t)


def json_error(r, status: int, message: str) -> bool:
    return r.status_code == status and r.headers["content-type"].startswith("application/json") and r.json() == {"error": message}


@pytest.fixture
def broken_dashboard(monkeypatch):
    monkeypatch.setattr(routes_apk, "_list_apks", lambda q: (_ for _ in ()).throw(RuntimeError("rahasia-internal-xyz")))


# ---------------------------------------------------------------- browser, sudah login
def test_unknown_page(client):
    r = client.get("/nope", headers=BROWSER)
    assert is_error_page(r, 404, "Halaman tidak ditemukan")
    assert 'action="/logout"' in r.text and SECURITY <= set(r.headers)


@pytest.mark.parametrize("method, path", [("GET", "/analyses/abc"), ("GET", "/analyses/0"), ("GET", f"/analyses/{2**31}"),
                                          ("GET", "/analyses/1/files/0/download"), ("POST", "/apks/abc/delete")])
def test_invalid_id_in_path_is_not_found(client, method, path):
    r = client.request(method, path, headers=BROWSER)
    assert r.status_code == 303 and r.headers["location"] == "/?notice=not_found"


def test_invalid_query(client):
    r = client.get("/?q=" + "a" * 101, headers=BROWSER)
    assert is_error_page(r, 422, "Permintaan tidak valid")
    assert "string_too_long" not in r.text and '"loc"' not in r.text


@pytest.mark.parametrize("method, path", [("POST", "/upload"), ("GET", "/logout")])
def test_wrong_method(client, method, path):
    r = client.request(method, path, headers=BROWSER)
    assert is_error_page(r, 405, "Aksi tidak tersedia") and r.headers.get("allow")


# ---------------------------------------------------------------- browser, belum login
@pytest.mark.parametrize("path", ["/nope", "/analyses/abc", "/logout", "/?q=" + "a" * 101])
def test_anonymous_goes_to_login(anon, path):
    r = anon.get(path, headers=BROWSER)
    assert r.status_code == 303 and r.headers["location"] == "/login"


# ---------------------------------------------------------------- JavaScript / skrip
def test_fetch_gets_json(client, anon, seeded):
    assert json_error(client.get("/nope", headers=FETCH), 404, "Tidak ditemukan.")
    assert json_error(client.get("/nope"), 404, "Tidak ditemukan.")                  # tanpa header Accept
    assert json_error(anon.get("/nope", headers=FETCH), 404, "Tidak ditemukan.")      # tanpa login: JSON, bukan redirect
    bad = "Parameter permintaan tidak valid."
    assert json_error(client.get(f"/analyses/{seeded.aid}/code/file?root=java&path=" + "a" * 601, headers=FETCH), 422, bad)
    assert json_error(client.get(f"/analyses/{seeded.aid}/files/0/text", headers=FETCH), 422, bad)
    assert json_error(client.get(f"/analyses/{seeded.aid}/chat/stream", headers={"Accept": "text/event-stream"}), 422, bad)
    r = client.post("/upload", headers=FETCH)
    assert json_error(r, 405, "Metode tidak diizinkan.") and r.headers["allow"] == "GET"


# ---------------------------------------------------------------- galat tak terduga
def test_server_error_page(client, broken_dashboard):
    r = client.get("/", headers=BROWSER)
    assert is_error_page(r, 500, "Terjadi galat di server")
    assert SECURITY <= set(r.headers) and r.headers["cache-control"] == "no-store"
    assert "rahasia-internal-xyz" not in r.text and "RuntimeError" not in r.text


def test_server_error_json(client, broken_dashboard):
    r = client.get("/", headers=FETCH)
    assert json_error(r, 500, "Galat internal server.") and SECURITY <= set(r.headers)


def test_server_error_when_error_template_also_breaks(client, anon, broken_dashboard, monkeypatch):
    def broken_render(*a, **k):
        raise RuntimeError("template rusak")

    monkeypatch.setattr(main_mod, "render", broken_render)
    r = client.get("/", headers=BROWSER)
    assert r.status_code == 500 and "Terjadi galat di server" in r.text and SECURITY <= set(r.headers)
    r = anon.get("/login", headers=BROWSER)              # halaman login rusak: 500, BUKAN redirect ke dirinya sendiri
    assert r.status_code == 500 and r.headers["content-type"].startswith("text/html")


# ---------------------------------------------------------------- yang tidak boleh berubah
def test_route_handled_errors_unchanged(client, anon, seeded):
    r = client.get("/analyses/999999", headers=BROWSER)
    assert r.status_code == 303 and r.headers["location"] == "/?notice=not_found"
    r = anon.get(f"/analyses/{seeded.aid}/status", headers=FETCH)
    assert r.status_code == 401 and r.json() == {"error": "auth"}
    assert json_error(client.get(f"/analyses/{seeded.aid}/files/99999/text", headers=FETCH), 404, "Berkas tidak ditemukan.")
    assert client.get("/upload/", headers=BROWSER).status_code == 307
    assert client.get("/static/css/app.css").status_code == 200
