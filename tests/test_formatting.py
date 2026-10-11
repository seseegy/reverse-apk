"""Satu gaya angka di seluruh UI (Indonesia: 1.234,5), sama di server dan JS (audit UI-04; butir 10 daftar sisa)."""

from __future__ import annotations

import json
import re
import shutil
from contextlib import closing

import pytest

from app import context
from rvcore import fmt, store

from conftest import BROWSER, query


@pytest.mark.parametrize("value, decimals, expected", [
    (0, 0, "0"), (999, 0, "999"), (1234, 0, "1.234"), (1234567, 0, "1.234.567"), (10**21, 0, "1" + ".000" * 7),
    (1500.4, 0, "1.500"), (1234.5, 1, "1.234,5"), (0.1234, 3, "0,123"), (6, 2, "6,00"), (-0.0001, 2, "0,00"),
    (5.0, None, "5"), (0.5, None, "0,5"), (1.25, None, "1,25"), (None, 0, "–"), (True, 0, "–"), ("abc", 0, "abc"),
])
def test_num(value, decimals, expected):
    assert fmt.num(value, decimals) == expected


@pytest.mark.parametrize("n, expected", [(None, "–"), (0, "0 B"), (512, "512 B"), (1536, "1,5 KB"), (5 * 1024**3, "5,0 GB"),
                                         (3 * 1024**4, "3,0 TB")])
def test_size(n, expected):
    assert fmt.size(n) == expected


@pytest.fixture
def spent_5_credits(monkeypatch):
    """5 kredit hari ini = Rp1.500 (AI_CREDIT_IDR bawaan 300). Anggaran harian dinaikkan agar chat tetap boleh dipakai."""
    monkeypatch.setenv("AI_DAILY_BUDGET_CREDITS", "100")
    with closing(context.db()) as conn:
        call_id = store.record_ai_call(conn, purpose="chat", model="test-model", cost_credits=5.0)
    yield
    query("DELETE FROM ai_call WHERE id = ?", call_id)


def test_chat_budget_rendered_in_indonesian_format(client, seeded, spent_5_credits):
    html = client.get(f"/analyses/{seeded.aid}/chat", headers=BROWSER).text
    assert re.search(r"data-b-idr>1\.500<", html), "Rp harus 1.500 (sebelumnya 1,500, lalu berubah jadi 1.500 oleh JS)"
    assert re.search(r"data-b-today>5,000<", html)
    assert re.search(r"data-b-limit>100<", html)


def test_budget_error_message_in_indonesian_format(client, seeded, json_headers, spent_5_credits, monkeypatch):
    monkeypatch.setenv("AI_DAILY_BUDGET_CREDITS", "2.5")
    r = client.post(f"/analyses/{seeded.aid}/chat/send", content='{"text":"x"}', headers=json_headers)
    assert r.status_code == 402
    assert "5,000 dari 2,5 kredit ≈ Rp1.500" in r.json()["error"]


@pytest.fixture
def decompile_summary(seeded):
    index = context.layout.work_dir(seeded.aid) / "index"
    index.mkdir(parents=True, exist_ok=True)
    (index / "summary.json").write_text(json.dumps({
        "decompile": {"jadx_error_count": 12345, "jadx_units": 50000, "methods_listed": 1234, "failed_pct": 24.69, "verdict": "banyak",
                      "detail": True, "by_category": {"tipe": 1234}},
        "code": {"app_classes": 20000, "smali_only_files": 2500, "methods_not_decompiled": 4321}}))
    yield
    shutil.rmtree(context.layout.work_dir(seeded.aid), ignore_errors=True)


def test_analysis_numbers_in_indonesian_format(client, seeded, decompile_summary):
    html = client.get(f"/analyses/{seeded.aid}", headers=BROWSER).text
    for expected in ("12.345 error", "1.234 method", "24,69%", "50.000 unit", "2.500 class", ">4.321<"):
        assert expected in html, expected
    assert not re.search(r"\d,\d{3}\b", re.sub(r"<[^>]+>", " ", html)), "masih ada pemisah ribuan gaya Inggris (1,234)"


def test_dashboard_disk_size_in_indonesian_format(client):
    html = client.get("/", headers=BROWSER).text
    assert re.search(r"\d+,\d (?:B|KB|MB|GB|TB) bebas dari \d+,\d (?:KB|MB|GB|TB)", html)
