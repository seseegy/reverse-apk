"""chat/send dan Last-Event-ID: input tidak wajar ditolak rapi, jalur normal tidak berubah (audit BE-01, BE-02, BE-03; PR #25)."""

from __future__ import annotations

import json
from contextlib import closing

import pytest

from app import context
from app.routes_apk import _resume_position
from rvcore import store

from conftest import query, wait_for


def url(seeded) -> str:
    return f"/analyses/{seeded.aid}/chat/send"


def post(client, seeded, headers, body):
    return client.post(url(seeded), content=body if isinstance(body, (str, bytes)) else json.dumps(body), headers=headers)


def max_message_id() -> int:
    return query("SELECT COALESCE(MAX(id), 0) FROM chat_message")[0][0]


@pytest.mark.parametrize("value, status", [
    (10**30, 422), (2**63, 422), (2**31, 422), (0, 422), (-5, 422), (True, 422), (1.5, 422), ("7", 422),
    (2**31 - 1, 404),                       # bentuknya valid, sesinya saja yang tidak ada
])
def test_session_id_validated(client, seeded, json_headers, value, status):
    assert post(client, seeded, json_headers, {"text": "x", "session_id": value}).status_code == status


@pytest.mark.parametrize("value", [None, 123, ["a"], {"a": 1}, True, "a\x00b"])
def test_text_must_be_plain_string(client, seeded, json_headers, value):
    before = max_message_id()
    r = post(client, seeded, json_headers, {"text": value})
    assert r.status_code == 422
    assert max_message_id() == before, "pesan yang ditolak tidak boleh tersimpan"


@pytest.mark.parametrize("body", [{}, {"text": "   "}])
def test_empty_message_rejected(client, seeded, json_headers, body):
    assert post(client, seeded, json_headers, body).status_code == 422


@pytest.mark.parametrize("value", [["a"], {"a": 1}, 123, 0, True, "tidak-ada"])
def test_model_must_be_allowed_string(client, seeded, json_headers, value):
    assert post(client, seeded, json_headers, {"text": "x", "model": value}).status_code == 422


@pytest.mark.parametrize("body, status", [
    ("[" * 100_000, 400),                                     # sebelumnya RecursionError -> 500
    ('{"text":"x","a":' + "[" * 100_000, 400),
    ('{"text":"x","session_id":' + "9" * 5000 + "}", 400),     # integer melebihi batas digit Python
    ("[]", 400), ("null", 400), ("bukan json", 400), (b'{"text":"\xff\xfe"}', 400),
    ('{"text":"x","attachment_ids":"x"}', 422), ('{"text":"x","attachment_ids":[1000000000000000000000000000000]}', 422),
])
def test_malformed_bodies(client, seeded, json_headers, body, status):
    assert post(client, seeded, json_headers, body).status_code == status


def test_normal_message_is_stored_trimmed(client, seeded, json_headers):
    before = max_message_id()
    r = post(client, seeded, json_headers, {"text": "  halo  "})
    assert r.status_code == 202
    assert r.json()["session_id"] and "stream" in r.json()
    rows = wait_for(lambda: query("SELECT content FROM chat_message WHERE id > ? AND role = 'user'", before))
    assert rows[0][0] == "halo"


@pytest.mark.parametrize("model", ["", None, "test-model"])
def test_model_default_or_configured(client, seeded, json_headers, model):
    assert post(client, seeded, json_headers, {"text": "x", "model": model}).status_code == 202


def test_existing_session_and_running_turn(client, seeded, json_headers, blocking_turns):
    with closing(context.db()) as conn:
        sid = store.create_chat_session(conn, seeded.aid, "uji")
    assert post(client, seeded, json_headers, {"text": "x", "session_id": sid}).status_code == 202
    assert post(client, seeded, json_headers, {"text": "y", "session_id": sid}).status_code == 409   # giliran masih berjalan


def test_csrf_required(client, seeded):
    assert client.post(url(seeded), content='{"text":"x"}', headers={"Content-Type": "application/json"}).status_code == 403


@pytest.mark.parametrize("header, expected", [
    ("", 0), ("5", 6), ("0", 1), ("abc", 0), ("-1", 0), (" 3", 0),
    ("\u00b2", 0), ("\u00b3", 0), ("\u0661\u0662", 0),        # digit Unicode: lolos str.isdigit() tetapi gagal int()
    ("9" * 12, 10**12), ("9" * 13, 0), ("9" * 40, 0),
])
def test_resume_position(header, expected):
    assert _resume_position(header) == expected
