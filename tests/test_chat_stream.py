"""Sambung ulang aliran chat (SSE): putar ulang dari awal tanpa header; Last-Event-ID melanjutkan tanpa duplikat (FR-5.15)."""

from __future__ import annotations

import re

from conftest import wait_turn_done


def events(client, seeded, sid, headers=None):
    r = client.get(f"/analyses/{seeded.aid}/chat/stream?s={sid}", headers=headers or {})
    return r.status_code, [(int(i), e) for i, e in re.findall(r"^id: (\d+)\nevent: (\w+)", r.text, re.M)]


def test_replay_and_resume(client, seeded, json_headers):
    r = client.post(f"/analyses/{seeded.aid}/chat/send", content='{"text":"halo"}', headers=json_headers)
    sid = r.json()["session_id"]
    wait_turn_done(sid)                  # provider uji menolak koneksi -> giliran selesai dengan galat

    status, full = events(client, seeded, sid)
    assert status == 200 and len(full) >= 2 and full[-1][1] == "end"
    ids = [i for i, _ in full]

    status, part = events(client, seeded, sid, {"Last-Event-ID": str(ids[0])})
    assert status == 200 and [i for i, _ in part] == [i for i in ids if i > ids[0]]

    assert events(client, seeded, sid, {"Last-Event-ID": str(ids[-1])}) == (200, [])
    assert events(client, seeded, sid, {"Last-Event-ID": "9" * 40}) == (200, full)     # nilai absurd -> dari awal, bukan 500


def test_stream_requires_existing_turn(client, seeded):
    assert client.get(f"/analyses/{seeded.aid}/chat/stream?s=999999").status_code == 404
