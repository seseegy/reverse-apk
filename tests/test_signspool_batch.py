"""Protokol signspool untuk permintaan tanda tangan MULTI-BERKAS (Tahap 3, sub-area C): satu request = base + 0..199 split, `expect_sha256` PER BERKAS.

Keputusan desain (design.md 4.1/4.2): BATCH satu request, hasil semua-atau-tidak-sama-sekali. Nama berkas dihitung signer, TIDAK PERNAH dari request.
Tanpa `splits` seluruh perilaku 2b tidak berubah (tes 2b lama di test_signspool.py tetap berlaku).
"""

from __future__ import annotations

import json
import time

import pytest

from rvcore import signspool as S

EXP = "e" * 64
H = [format(i, "x") * 64 for i in range(1, 10)]          # hash tiruan berbeda-beda
OWNER = "c" * 64


def jid(tail="abcdef12"):
    return f"g1-1-{tail}"


def req(**extra):
    return {"job_id": jid(), "op": "sign", "analysis_id": 1, "build_id": 1, "timeout": 60, "expect_sha256": EXP, "created": 1.0, **extra}


def split_row(i, **kw):
    row = {"index": i, "input_sha256": H[i % 9], "output_sha256": H[(i + 1) % 9], "output_size": 100 + i, "cert_sha256": OWNER, "v2": True, "v3": True, "signer_count": 1}
    row.update(kw)
    return row


def good(n=0, **extra):
    base = {"ok": True, "error_code": None, "error_text": "", "output_name": "signed.apk", "output_size": 1234, "output_sha256": "b" * 64, "input_sha256": EXP,
            "cert_sha256": OWNER, "verify": {"v1": False, "v2": True, "v3": True}, "signer_count": 1, "elapsed": 1.5}
    if n or "splits" in extra:
        base["splits"] = [split_row(i) for i in range(1, n + 1)]
    base.update(extra)
    return base


# ------------------------------------------------------------------------------------------------ konstanta bersama
def test_konstanta_batch():
    assert (S.MAX_SPLITS, S.SIGN_PER_FILE_S) == (199, 10)
    assert (S.MAX_REQUEST_BYTES, S.MAX_RESULT_BYTES) == (16 * 1024, 128 * 1024)


def test_batas_ukuran_request_cukup_untuk_199_split_terpanjang():
    job = S.build_sign_request(2**31 - 1, 2**31 - 1, 3600, EXP, splits=[H[1]] * S.MAX_SPLITS)
    assert len(json.dumps(job).encode()) < S.MAX_REQUEST_BYTES


def test_batas_ukuran_hasil_cukup_untuk_199_split():
    raw = good(S.MAX_SPLITS)
    assert len(json.dumps(raw).encode()) < S.MAX_RESULT_BYTES


@pytest.mark.parametrize("base,n,want", [(900, 0, 900), (900, 3, 930), (3600, 5, 3600), (30, 199, 30 + 1990), (3590, 2, 3600)])
def test_sign_timeout_diskalakan_per_berkas_dan_dijepit(base, n, want):
    assert S.sign_timeout(base, n) == want


def test_kode_galat_stale_signature_terdaftar_dan_punya_teks():
    assert "stale_signature" in S.ERROR_CODES and S.ERROR_TEXT["stale_signature"]
    assert len(S.ERROR_TEXT["stale_signature"]) <= 300 and "tanda tangan" in S.ERROR_TEXT["stale_signature"]
    assert set(S.ERROR_TEXT) == set(S.ERROR_CODES) | {"bad_result"}


# ------------------------------------------------------------------------------------------------ build_sign_request
def test_request_tanpa_splits_bentuk_2b_tak_berubah():
    r = S.build_sign_request(5, 6, 120, EXP)
    assert set(r) == {"job_id", "op", "analysis_id", "build_id", "timeout", "expect_sha256", "created"}


def test_request_dengan_splits_urutan_dipertahankan_dan_bidang_splits_saja():
    r = S.build_sign_request(5, 6, 120, EXP, splits=[H[3], H[1], H[2]])
    assert r["splits"] == [H[3], H[1], H[2]]
    assert set(r) == {"job_id", "op", "analysis_id", "build_id", "timeout", "expect_sha256", "created", "splits"}
    assert not any("name" in k or "path" in k for k in r), "nama/path berkas tidak pernah ikut dikirim"


def test_request_splits_kosong_tidak_menambah_bidang():
    assert "splits" not in S.build_sign_request(5, 6, 120, EXP, splits=())


def test_request_splits_duplikat_boleh():
    assert S.build_sign_request(1, 1, 60, EXP, splits=[H[1], H[1]])["splits"] == [H[1], H[1]]


@pytest.mark.parametrize("bad", [
    "x" * 64, "A" * 64, "a" * 63, "a" * 65, "", None, 5, ["a" * 64], {"a": "b"}, b"a" * 64, "a" * 63 + "\n", "../" + "a" * 61, "a" * 32 + "/" + "a" * 31,
])
def test_request_pengirim_menolak_elemen_splits_tak_valid(bad):
    with pytest.raises(ValueError):
        S.build_sign_request(1, 1, 60, EXP, splits=[bad])


def test_request_pengirim_menolak_lebih_199_split():
    S.build_sign_request(1, 1, 60, EXP, splits=[H[1]] * 199)
    with pytest.raises(ValueError):
        S.build_sign_request(1, 1, 60, EXP, splits=[H[1]] * 200)


@pytest.mark.parametrize("bad", ["a" * 64, {"0": "a" * 64}, 5, True])
def test_request_pengirim_menolak_splits_bukan_daftar(bad):
    with pytest.raises(ValueError):
        S.build_sign_request(1, 1, 60, EXP, splits=bad)


# ------------------------------------------------------------------------------------------------ validate_request
def test_validate_mengembalikan_lima_elemen_dengan_splits():
    assert S.validate_request(req(), jid()) == (1, 1, 60, EXP, [])
    got = S.validate_request(req(splits=[H[1], H[2]]), jid())
    assert got == (1, 1, 60, EXP, [H[1], H[2]])
    assert isinstance(got[4], list)


@pytest.mark.parametrize("splits", [
    "a" * 64, {"x": "a" * 64}, 5, True, None, [None], [5], ["x" * 64], ["A" * 64], ["a" * 63], ["a" * 64 + "\n"], [["a" * 64]], [{"sha": "a" * 64}], [b"a" * 64],
    ["a" * 64, 3], ["../etc/passwd"], [{"name": "../x.apk", "sha256": "a" * 64}],
])
def test_validate_menolak_splits_tak_valid(splits):
    with pytest.raises(ValueError):
        S.validate_request(req(splits=splits), jid())


def test_validate_menolak_lebih_199_split_dan_menerima_199():
    assert len(S.validate_request(req(splits=[H[1]] * 199), jid())[4]) == 199
    with pytest.raises(ValueError):
        S.validate_request(req(splits=[H[1]] * 200), jid())


def test_validate_bidang_nama_dan_path_diabaikan_tidak_pernah_dibaca():
    plain = S.validate_request(req(splits=[H[1]]), jid())
    evil = S.validate_request(req(splits=[H[1]], names=["../../etc/passwd"], paths=["/etc/shadow"], split_names={"1": "../x"}, out="/tmp/x"), jid())
    assert plain == evil


def test_validate_nama_berkas_hasil_hitung_signer_bukan_dari_request():
    assert S.split_input_name(1) == "split-001.apk" and S.split_input_name(199) == "split-199.apk"
    assert S.split_output_name(1) == "signed-001.apk" and S.split_output_name(199) == "signed-199.apk"
    for bad in (0, 200, -1, "1", 1.0, True, None):
        with pytest.raises(ValueError):
            S.split_input_name(bad)
        with pytest.raises(ValueError):
            S.split_output_name(bad)


# ------------------------------------------------------------------------------------------------ parse_result
def test_hasil_tanpa_splits_2b_dinormalkan_dengan_splits_kosong():
    r = S.parse_result(good())
    assert r["ok"] is True and r["splits"] == []


def test_hasil_dengan_splits_dinormalkan_lengkap():
    r = S.parse_result(good(3))
    assert r["ok"] is True and len(r["splits"]) == 3
    assert r["splits"][1] == {"index": 2, "input_sha256": H[2], "output_sha256": H[3], "output_size": 102, "cert_sha256": OWNER, "v2": True, "v3": True, "signer_count": 1}


def test_hasil_199_split_ok():
    assert S.parse_result(good(199))["ok"] is True


@pytest.mark.parametrize("mut", [
    {"splits": [split_row(1), split_row(3)]},                      # index tidak berurutan
    {"splits": [split_row(2), split_row(1)]},                      # urutan terbalik
    {"splits": [split_row(0)]},                                    # index mulai 0
    {"splits": [split_row(1), split_row(1)]},                      # index ganda
    {"splits": [split_row(1, index="1")]},                         # index bukan int
    {"splits": [split_row(1, index=True)]},                        # bool bukan int
    {"splits": [split_row(1, input_sha256="x")]},
    {"splits": [split_row(1, input_sha256=None)]},
    {"splits": [split_row(1, output_sha256="A" * 64)]},
    {"splits": [split_row(1, output_size=0)]},
    {"splits": [split_row(1, output_size=-5)]},
    {"splits": [split_row(1, output_size="9")]},
    {"splits": [split_row(1, output_size=True)]},
    {"splits": [split_row(1, cert_sha256=None)]},
    {"splits": [split_row(1, cert_sha256="zz")]},
    {"splits": [split_row(1, v2=False)]},                          # #13: v2/v3/signer_count per split diperiksa
    {"splits": [split_row(1, v3=False)]},
    {"splits": [split_row(1, v2="true")]},
    {"splits": [split_row(1, signer_count=2)]},
    {"splits": [split_row(1, signer_count=None)]},
    {"splits": [split_row(1, signer_count=True)]},
    {"splits": ["bukan dict"]},
    {"splits": [None]},
    {"splits": "x"},
    {"splits": {"1": split_row(1)}},
    {"splits": 5},
    {"splits": [split_row(i) for i in range(1, 201)]},             # > MAX_SPLITS
])
def test_hasil_ok_dengan_splits_tak_koheren_jadi_bad_result(mut):
    r = S.parse_result(good(**mut))
    assert r["ok"] is False and r["error_code"] == "bad_result" and r["error_text"] == "hasil signer rusak"
    assert r["splits"] == []


def test_hasil_gagal_tidak_membawa_splits():
    r = S.parse_result({"ok": False, "error_code": "input_unsafe", "error_text": "x", "splits": [split_row(1)]})
    assert r["ok"] is False and r["error_code"] == "input_unsafe" and r["splits"] == []


def test_hasil_bidang_tambahan_di_elemen_splits_dibuang():
    row = split_row(1, nama="../x.apk", path="/etc/passwd")
    r = S.parse_result(good(splits=[row]))
    assert r["ok"] is True and set(r["splits"][0]) == {"index", "input_sha256", "output_sha256", "output_size", "cert_sha256", "v2", "v3", "signer_count"}


def test_hasil_stale_signature_dikenal_bukan_bad_result():
    r = S.parse_result({"ok": False, "error_code": "stale_signature", "error_text": "sisa"})
    assert r["error_code"] == "stale_signature" and r["error_text"] == "sisa"


# ------------------------------------------------------------------------------------------------ submit_and_wait
def test_submit_and_wait_meneruskan_splits_ke_request(tmp_path):
    spool = S.make_spool(tmp_path / "sp")
    spool.ensure_dirs()
    spool.write_signer_heartbeat("idle", None, {"state": "ok", "detail": "", "cert_sha256": OWNER})
    seen = {}

    import threading

    def signer():
        end = time.monotonic() + 5
        while time.monotonic() < end:
            claimed = spool.claim_next()
            if claimed:
                seen["job"] = claimed[1]
                spool.finish(claimed[0], good(2))
                return
            time.sleep(0.02)

    th = threading.Thread(target=signer, daemon=True)
    th.start()
    res = S.submit_and_wait(spool, 1, 1, timeout=60, expect_sha256=EXP, splits=[H[1], H[2]], poll=0.02)
    th.join(5)
    assert res["ok"] is True and len(res["splits"]) == 2
    assert seen["job"]["splits"] == [H[1], H[2]] and seen["job"]["expect_sha256"] == EXP


def test_submit_and_wait_splits_tak_valid_gagal_sebelum_dikirim(tmp_path):
    spool = S.make_spool(tmp_path / "sp")
    spool.ensure_dirs()
    spool.write_signer_heartbeat("idle", None, {"state": "ok", "detail": "", "cert_sha256": OWNER})
    with pytest.raises(S.SignerUnavailable):
        S.submit_and_wait(spool, 1, 1, timeout=60, expect_sha256=EXP, splits=["x"], poll=0.02)
    assert list(spool.requests.iterdir()) == []
