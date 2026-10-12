"""Tombol "Batalkan" analisis: minta konfirmasi HANYA saat analisis sedang berjalan (audit UI-08).

Saat antre, membatalkan tidak membuang apa pun. Saat berjalan, hasil sementara apktool/jadx langsung dihapus (pipeline._finish_cancelled)
dan harus diulang dari awal, jadi pengguna perlu ditanya dulu, seperti pada Hapus dan Analisis ulang.
"""

from __future__ import annotations

import re

import pytest

from conftest import BROWSER, new_analysis, query


def cancel_form(client, aid: int) -> str:
    html = client.get(f"/analyses/{aid}", headers=BROWSER).text
    m = re.search(rf'<form[^>]*action="/analyses/{aid}/cancel"[^>]*>', html)
    assert m, "form Batalkan tidak ditemukan"
    return m.group(0)


def set_status(aid: int, status: str, cancel_requested: int = 0) -> None:
    query("UPDATE analysis SET status = ?, cancel_requested = ? WHERE id = ?", status, cancel_requested, aid)


def test_running_asks_for_confirmation(client):
    aid = new_analysis("batal-berjalan")
    set_status(aid, "running")
    form = cancel_form(client, aid)
    assert "data-confirm=" in form
    msg = re.search(r'data-confirm="([^"]*)"', form).group(1)
    assert msg.strip(), "pesan konfirmasi tidak boleh kosong (kosong = tanpa konfirmasi)"
    assert "dihapus" in msg and "awal" in msg, "pengguna harus tahu apa yang hilang"
    assert "data-submit-lock" in form, "penguncian kirim ganda tetap ada"


def test_queued_does_not_ask(client):
    aid = new_analysis("batal-antre")              # status bawaan: queued
    form = cancel_form(client, aid)
    assert 'data-confirm=""' in form or "data-confirm=" not in form
    assert not re.search(r'data-confirm="[^"]+"', form), "membatalkan yang masih antre tidak membuang apa pun"


def test_cancel_already_requested_is_disabled(client):
    aid = new_analysis("batal-diminta")
    set_status(aid, "running", cancel_requested=1)
    html = client.get(f"/analyses/{aid}", headers=BROWSER).text
    form = re.search(rf'<form[^>]*action="/analyses/{aid}/cancel".*?</form>', html, re.S).group(0)
    assert "disabled" in form


@pytest.mark.parametrize("status", ["done", "failed", "cancelled"])
def test_finished_has_no_cancel_form(client, status):
    aid = new_analysis(f"batal-{status}")
    set_status(aid, status)
    html = client.get(f"/analyses/{aid}", headers=BROWSER).text
    assert f'action="/analyses/{aid}/cancel"' not in html


def test_existing_confirmations_unchanged(client):
    """Hapus dan Analisis ulang tetap bertanya (perilaku lama tidak boleh hilang)."""
    aid = new_analysis("konfirmasi-lama")
    set_status(aid, "done")
    html = client.get(f"/analyses/{aid}", headers=BROWSER).text
    retry = re.search(rf'<form[^>]*action="/analyses/{aid}/retry"[^>]*>', html).group(0)
    assert "Jalankan ulang analisis?" in retry
    delete = re.search(r'<form[^>]*action="/apks/\d+/delete"[^>]*>', html).group(0)
    assert "Hapus APK ini" in delete


def test_cancel_still_works_server_side(client, seeded):
    """Konfirmasi hanya di sisi klien; endpoint-nya sendiri tidak berubah."""
    aid = new_analysis("batal-endpoint")
    r = client.post(f"/analyses/{aid}/cancel", data={"csrf": seeded.csrf})
    assert r.status_code == 303 and r.headers["location"].startswith(f"/analyses/{aid}")
    assert query("SELECT status FROM analysis WHERE id = ?", aid)[0][0] == "cancelled"
