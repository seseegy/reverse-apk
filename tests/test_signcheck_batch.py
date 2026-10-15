"""`signcheck.py` untuk permintaan MULTI-BERKAS (Tahap 3, sub-area C; design.md 4.4): `put-split AID BID N` dan `sign --splits HEX,HEX,...`.

Hanya dipakai skrip uji (verify-build negatif); semua akses `builds/<aid>/<bid>` lewat rantai dir_fd + `Tmp.publish` (tmp O_EXCL, rename atomik), id sentinel saja.
"""

from __future__ import annotations

import hashlib
import io
import re

import pytest
from rvcore import signspool
from rvcore.paths import Layout
from test_signcheck import AID, FakeDaemon, OTHER, OWNER, failure_result, load, success_result

H = [hashlib.sha256(b"split-%d" % i).hexdigest() for i in range(1, 6)]


@pytest.fixture
def sc():
    return load()


@pytest.fixture
def layout(tmp_path):
    lay = Layout(tmp_path / "data")
    lay.builds.mkdir(parents=True)
    return lay


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.delenv("SIGNCHECK_DIAG", raising=False)


def call(sc, layout, capsys, *argv, stdin: bytes | None = None):
    rc = sc.main([str(a) for a in argv], layout=layout, stdin=io.BytesIO(stdin if stdin is not None else b""))
    return rc, capsys.readouterr().out


def kv(out):
    return dict(ln.split("=", 1) for ln in out.splitlines() if "=" in ln)


def row(i, **kw):
    r = {"index": i, "input_sha256": H[(i - 1) % len(H)], "output_sha256": hashlib.sha256(b"out%d" % i).hexdigest(), "output_size": 100 + i, "cert_sha256": OWNER,
         "v2": True, "v3": True, "signer_count": 1}
    r.update(kw)
    return r


def ok_with(n, **over):
    res = success_result(splits=[row(i) for i in range(1, n + 1)])
    res.update(over)
    return res


# ================================================================================ put-split
def test_put_split_menulis_split_nnn_lewat_tmp_dan_mencetak_hash(sc, layout, capsys):
    data = b"PK\x03\x04" + b"isi" * 100
    rc, out = call(sc, layout, capsys, "put-split", AID, 1, 3, stdin=data)
    assert rc == 0, out
    bdir = layout.build_dir(AID, 1)
    assert sorted(p.name for p in bdir.iterdir()) == ["split-003.apk"]
    assert (bdir / "split-003.apk").read_bytes() == data
    assert kv(out) == {"ditulis": str(len(data)), "sha256": hashlib.sha256(data).hexdigest()}
    assert not [p for p in bdir.iterdir() if p.name.startswith(".put-")]


def test_put_split_menimpa_split_lama_secara_atomik(sc, layout, capsys):
    call(sc, layout, capsys, "put-split", AID, 1, 1, stdin=b"lama")
    rc, _ = call(sc, layout, capsys, "put-split", AID, 1, 1, stdin=b"baru")
    assert rc == 0 and (layout.build_dir(AID, 1) / "split-001.apk").read_bytes() == b"baru"


@pytest.mark.parametrize("n", ["0", "200", "-1", "1.5", "x", "", "٣", "0003", "042", "+3", " 3"])
def test_put_split_n_di_luar_1_199_salah_pakai(sc, layout, capsys, n):
    rc, out = call(sc, layout, capsys, "put-split", AID, 1, n, stdin=b"x")
    assert rc == 64 and out.startswith("GALAT:")
    assert not layout.build_dir(AID, 1).exists() or list(layout.build_dir(AID, 1).iterdir()) == []


@pytest.mark.parametrize("n", ["1", "199", "42"])
def test_put_split_n_batas_diterima(sc, layout, capsys, n):
    rc, _ = call(sc, layout, capsys, "put-split", AID, 1, n, stdin=b"x")
    assert rc == 0 and (layout.build_dir(AID, 1) / f"split-{int(n):03d}.apk").exists()


def test_put_split_menolak_id_non_sentinel(sc, layout, capsys):
    rc, out = call(sc, layout, capsys, "put-split", 5, 1, 1, stdin=b"x")
    assert rc == 64 and "sentinel" in out
    rc, out = call(sc, layout, capsys, "put-split", AID, 9, 1, stdin=b"x")
    assert rc == 64


def test_put_split_tanpa_n_salah_pakai(sc, layout, capsys):
    rc, out = call(sc, layout, capsys, "put-split", AID, 1, stdin=b"x")
    assert rc == 64


def test_put_split_tidak_mengikuti_symlink_akar_build(sc, layout, capsys, tmp_path):
    outside = tmp_path / "luar"
    (outside / "1").mkdir(parents=True)
    (layout.builds / str(AID)).symlink_to(outside)
    rc, out = call(sc, layout, capsys, "put-split", AID, 1, 1, stdin=b"x")
    assert rc == 2 and out.startswith("GALAT:")
    assert list((outside / "1").iterdir()) == []


def test_put_split_melebihi_batas_ukuran_galat_dan_tmp_dibuang(sc, layout, capsys, monkeypatch):
    monkeypatch.setattr(sc, "MAX_PUT_BYTES", 10)
    rc, out = call(sc, layout, capsys, "put-split", AID, 1, 1, stdin=b"x" * 11)
    assert rc == 2
    assert list(layout.build_dir(AID, 1).iterdir()) == []


def test_put_split_tmp_sudah_ada_gagal_tertutup_tanpa_menerbitkan(sc, layout, capsys, monkeypatch):
    bdir = layout.build_dir(AID, 1)
    bdir.mkdir(parents=True)
    monkeypatch.setattr(sc.secrets, "token_hex", lambda n=6: "abc")
    (bdir / ".put-abc.tmp").write_bytes(b"ditanam")
    rc, out = call(sc, layout, capsys, "put-split", AID, 1, 1, stdin=b"x")
    assert rc == 2 and out.startswith("GALAT:") and not (bdir / "split-001.apk").exists()


def test_ls_dan_clean_mencakup_split_dan_signed_nnn(sc, layout, capsys):
    call(sc, layout, capsys, "put-split", AID, 1, 2, stdin=b"x")
    (layout.build_dir(AID, 1) / "signed-002.apk").write_bytes(b"y")
    rc, out = call(sc, layout, capsys, "ls", AID, 1)
    assert out.split() == ["signed-002.apk", "split-002.apk"]
    rc, out = call(sc, layout, capsys, "clean", AID, 1)
    assert rc == 0 and out.strip() == "dibersihkan=1" and not layout.build_dir(AID, 1).exists()


# ================================================================================ sign --splits
def test_sign_tanpa_splits_request_2b_tak_berubah(sc, layout, capsys):
    call(sc, layout, capsys, "put", AID, 1, stdin=b"APK")
    with FakeDaemon(layout) as d:
        rc, out = call(sc, layout, capsys, "sign", AID, 1)
    assert rc == 0 and "splits" not in d.seen[0]
    assert not [ln for ln in out.splitlines() if ln.startswith("SPLIT ")]


def test_sign_splits_diteruskan_urut_dan_expect_base_dari_unsigned(sc, layout, capsys):
    call(sc, layout, capsys, "put", AID, 1, stdin=b"APK")
    with FakeDaemon(layout) as d:
        d.behave = lambda job_id, job: ok_with(2)
        rc, out = call(sc, layout, capsys, "sign", AID, 1, "--splits", f"{H[1]},{H[0]}", "--expect-ok", "--owner-sha256", OWNER)
    job = d.seen[0]
    assert rc == 0, out
    assert job["splits"] == [H[1], H[0]] and job["expect_sha256"] == hashlib.sha256(b"APK").hexdigest()


def test_sign_splits_mencetak_baris_split_per_berkas(sc, layout, capsys):
    call(sc, layout, capsys, "put", AID, 1, stdin=b"APK")
    with FakeDaemon(layout) as d:
        d.behave = lambda job_id, job: ok_with(2)
        rc, out = call(sc, layout, capsys, "sign", AID, 1, "--splits", f"{H[0]},{H[1]}")
    lines = [ln for ln in out.splitlines() if ln.startswith("SPLIT ")]
    assert rc == 0 and len(lines) == 2
    assert re.fullmatch(r"SPLIT index=1 sha=[0-9a-f]{64} size=101 cert=[0-9a-f]{64} v2=1 v3=1 signers=1", lines[0]), lines[0]
    assert out.splitlines()[0].startswith("HASIL ok=1 ")


def test_sign_splits_expect_ok_cert_split_beda_gagal_kode_3(sc, layout, capsys):
    call(sc, layout, capsys, "put", AID, 1, stdin=b"APK")
    with FakeDaemon(layout) as d:
        res = ok_with(2)
        res["splits"][1]["cert_sha256"] = OTHER
        d.behave = lambda job_id, job: res
        rc, out = call(sc, layout, capsys, "sign", AID, 1, "--splits", f"{H[0]},{H[1]}", "--expect-ok", "--owner-sha256", OWNER)
    assert rc == 3 and "ALASAN:" in out and "split" in out.split("ALASAN:")[1]


def test_sign_splits_expect_ok_jumlah_hasil_kurang_gagal(sc, layout, capsys):
    call(sc, layout, capsys, "put", AID, 1, stdin=b"APK")
    with FakeDaemon(layout) as d:
        d.behave = lambda job_id, job: success_result()          # signer gaya 2b: mengabaikan splits
        rc, out = call(sc, layout, capsys, "sign", AID, 1, "--splits", f"{H[0]},{H[1]}", "--expect-ok", "--owner-sha256", OWNER)
    assert rc == 3 and "ALASAN:" in out


def test_sign_splits_expect_error_stale_signature(sc, layout, capsys):
    call(sc, layout, capsys, "put", AID, 1, stdin=b"APK")
    with FakeDaemon(layout) as d:
        d.behave = lambda job_id, job: failure_result("stale_signature")
        rc, out = call(sc, layout, capsys, "sign", AID, 1, "--splits", H[0], "--expect-error", "stale_signature")
    assert rc == 0 and "code=stale_signature" in out


def test_sign_expect_sha256_dan_splits_bersama(sc, layout, capsys):
    call(sc, layout, capsys, "put", AID, 1, stdin=b"APK")
    with FakeDaemon(layout) as d:
        d.behave = lambda job_id, job: failure_result("input_unsafe")
        rc, out = call(sc, layout, capsys, "sign", AID, 1, "--splits", H[0], "--expect-sha256", "0" * 64, "--expect-error", "input_unsafe")
    assert rc == 0 and d.seen[0]["expect_sha256"] == "0" * 64 and d.seen[0]["splits"] == [H[0]]


@pytest.mark.parametrize("bad", ["", "x", H[0] + ",", "," + H[0], f"{H[0]},,{H[1]}", H[0][:-1], H[0].upper(), ",".join([H[0]] * 200), f"{H[0]};{H[1]}", "../" + H[0][3:]])
def test_sign_splits_tak_valid_salah_pakai_tanpa_mengirim(sc, layout, capsys, bad):
    call(sc, layout, capsys, "put", AID, 1, stdin=b"APK")
    rc, out = call(sc, layout, capsys, "sign", AID, 1, "--splits", bad)
    assert rc == 64 and out.startswith("GALAT:")
    requests = layout.signspool / "requests"
    assert not requests.exists() or list(requests.iterdir()) == []


def test_sign_splits_199_diterima(sc, layout, capsys):
    call(sc, layout, capsys, "put", AID, 1, stdin=b"APK")
    with FakeDaemon(layout) as d:
        d.behave = lambda job_id, job: ok_with(199)
        rc, out = call(sc, layout, capsys, "sign", AID, 1, "--splits", ",".join([H[0]] * 199), "--timeout", "60")
    assert rc == 0 and len(d.seen[0]["splits"]) == 199


def test_sign_splits_timeout_default_diskalakan_per_berkas(sc, layout, capsys):
    call(sc, layout, capsys, "put", AID, 1, stdin=b"APK")
    with FakeDaemon(layout) as d:
        d.behave = lambda job_id, job: ok_with(2)
        call(sc, layout, capsys, "sign", AID, 1, "--splits", f"{H[0]},{H[1]}")
    assert d.seen[0]["timeout"] == signspool.sign_timeout(sc.DEFAULT_SIGN_TIMEOUT, 2)


def test_signcheck_tidak_pernah_menyentuh_id_nyata_untuk_splits(sc, layout, capsys):
    rc, out = call(sc, layout, capsys, "sign", 5, 1, "--splits", H[0])
    assert rc == 64 and "sentinel" in out
