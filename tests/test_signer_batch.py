"""Tes signer-daemon untuk permintaan MULTI-BERKAS (Tahap 3, sub-area C; design.md 3.5/4.3/10.3): base + split dalam SATU job.

Wajib: `expect_sha256` PER BERKAS dipetakan per indeks; setiap berkas dibuka SEKALI (O_NOFOLLOW|O_NONBLOCK, S_ISREG, nlink==1) dan di-hash dari fd yang sama; SEMUA
berkas ditandatangani kunci pemilik yang SAMA; semua-atau-tidak-sama-sekali (satu gagal -> tidak ada `signed*.apk`); tanpa `splits` perilaku 2b identik.

Alat PALSU (pola test_signer_daemon.FAKE_TOOL) dengan perilaku per berkas (`by_k`, k dari subfolder `s<kkk>` di argv) dan perekaman isi ruang kerja saat alat dipanggil.
Split dibuat sebagai ZIP sungguhan karena daemon memindai nama entri `aligned.apk`/keluaran untuk k >= 1.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import threading
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from rvcore import signspool
from test_signer_daemon import FAKE_TOOL, OWNER, OTHER, PASSWORD, stored_result, within

BASE = b"APK-TIRUAN" * 100

_HELPERS = '''
import re as _re
def _tree(args):
    for a in args:
        m = _re.search(r"^(.*/g[0-9]+-[0-9]+-[0-9a-f]{8})(/|$)", a)
        if m:
            root = m.group(1)
            out = []
            for dp, dn, fn in os.walk(root):
                for f in fn + dn:
                    out.append(os.path.relpath(os.path.join(dp, f), root))
            return sorted(out)
    return None
_mk = _re.search(r"/s([0-9]{3})/", " ".join(sys.argv[1:]))
_k = str(int(_mk.group(1))) if _mk else "0"
'''
_INJECT = '''
    if b.get("garbage_out"):
        open(out, "wb").write(b"bukan zip")
    elif b.get("inject"):
        import zipfile as _z
        with _z.ZipFile(out, "a") as _zf:
            for _nm in b["inject"]:
                _zf.writestr(_nm, b"x")
'''
BATCH_TOOL = (FAKE_TOOL
              .replace("REC = @REC@", "REC = @REC@" + _HELPERS)
              .replace('"cwd": os.getcwd()}', '"cwd": os.getcwd(), "tree": _tree(args), "k": _k}')
              .replace('b = beh.get(key, {})', 'b = (beh.get("by_k", {}).get(_k, {}) or {}).get(key) or beh.get(key, {})')
              .replace('    shutil.copyfile(args[-1], out)\n    if b.get("noout"):', '    shutil.copyfile(args[-1], out)\n' + _INJECT + '    if b.get("noout"):'))
assert "_tree(args)" in BATCH_TOOL and "by_k" in BATCH_TOOL and "garbage_out" in BATCH_TOOL


def zbytes(entries: dict[str, bytes] | list[tuple[str, bytes]]) -> bytes:
    """ZIP sungguhan (STORED) dengan urutan entri dipertahankan; nama ganda dibolehkan lewat daftar pasangan."""
    buf = io.BytesIO()
    items = list(entries.items()) if isinstance(entries, dict) else entries
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, data in items:
            zf.writestr(name, data)
    return buf.getvalue()


def split_zip(i: int, extra: dict[str, bytes] | None = None) -> bytes:
    return zbytes({"AndroidManifest.xml": b"manifest-%d" % i, "classes.dex": b"SPLIT-%d" % i * 20, **(extra or {})})


@pytest.fixture
def d(monkeypatch, tmp_path):
    from test_signer_daemon import load_daemon
    return load_daemon(monkeypatch, tmp_path)


@pytest.fixture
def brig(d, tmp_path, monkeypatch):
    """Daemon + alat palsu per-berkas + kunci tiruan + folder build 1/2 berisi unsigned.apk (non-zip; k=0 tidak dipindai)."""
    rec, bindir, secrets = tmp_path / "rec", tmp_path / "bin", tmp_path / "run-secrets"
    for p in (rec, bindir, secrets):
        p.mkdir()
    text = BATCH_TOOL.replace("@PY@", sys.executable).replace("@REC@", repr(str(rec)))
    for tool in ("zipalign", "apksigner", "keytool"):
        (bindir / tool).write_text(text)
        (bindir / tool).chmod(0o755)
    (secrets / "signing_keystore").write_bytes(b"p12-tiruan")
    (secrets / "signing_keystore_pass").write_text(PASSWORD)
    for p in (secrets / "signing_keystore", secrets / "signing_keystore_pass"):
        p.chmod(0o644)
    bdir = d.LAYOUT.build_dir(1, 2)
    bdir.mkdir(parents=True)
    (bdir / "unsigned.apk").write_bytes(BASE)
    monkeypatch.setattr(d, "TOOL_PATH", f"{bindir}:/usr/bin:/bin")
    monkeypatch.setattr(d, "KEYTOOL_TIMEOUT", 10.0)
    r = SimpleNamespace(d=d, rec=rec, bin=bindir, secrets=secrets, bdir=bdir, home=tmp_path / "home", splits=[])
    r.behave = lambda **kw: (rec / "behavior.json").write_text(json.dumps({"owner": OWNER, **kw}))
    r.behave()

    def calls():
        path = rec / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def put(n, extra=None):
        """Tulis split-001..n sebagai ZIP sungguhan; kembalikan isi (bytes) tiap split."""
        r.splits = []
        for i in range(1, n + 1):
            data = split_zip(i, (extra or {}).get(i))
            (bdir / f"split-{i:03d}.apk").write_bytes(data)
            r.splits.append(data)
        return r.splits

    def hashes():
        return [hashlib.sha256((bdir / f"split-{i:03d}.apk").read_bytes()).hexdigest() for i in range(1, len(r.splits) + 1)]

    def request(timeout=60, splits=None, expect=None, aid=1, bid=2):
        base = hashlib.sha256((bdir / "unsigned.apk").read_bytes()).hexdigest() if (bdir / "unsigned.apk").is_file() else "0" * 64
        return signspool.build_sign_request(aid, bid, timeout, expect or base, splits=hashes() if splits is None else splits)

    def run(timeout=60, splits=None, expect=None, job=None):
        job = job or request(timeout, splits, expect)
        d.SPOOL.submit(job)
        claimed = d.SPOOL.claim_next()
        assert claimed is not None and claimed[0] == job["job_id"]
        return job["job_id"], d.run_job(*claimed)

    r.calls, r.put, r.hashes, r.request, r.run = calls, put, hashes, request, run
    r.tools = lambda: [(c["tool"], c["argv"][0] if c["argv"] else "", c["k"]) for c in calls() if c["tool"] != "keytool"]
    r.names = lambda: sorted(p.name for p in bdir.iterdir())
    return r


def signed_names(r):
    return [n for n in r.names() if n.startswith("signed")]


def assert_nothing_signed(r, job_id=None):
    assert signed_names(r) == [], r.names()
    assert not [n for n in r.names() if n.startswith(".sign-")], r.names()
    assert not r.d.LAYOUT.signwork.exists() or list(r.d.LAYOUT.signwork.iterdir()) == []
    if job_id:
        assert not (r.home / job_id).exists()


# ================================================================================ positif
def test_batch_semua_ok_menerbitkan_signed_nnn_dan_hasil_per_berkas(brig):
    d = brig.d
    brig.put(3)
    job_id, res = brig.run()
    assert res["ok"] is True, res
    assert brig.names() == sorted(["unsigned.apk", "split-001.apk", "split-002.apk", "split-003.apk", "signed.apk", "signed-001.apk", "signed-002.apk", "signed-003.apk"])
    base = (brig.bdir / "signed.apk").read_bytes()
    assert (res["output_size"], res["output_sha256"], res["cert_sha256"]) == (len(base), hashlib.sha256(base).hexdigest(), OWNER)
    assert res["input_sha256"] == hashlib.sha256(BASE).hexdigest()
    assert len(res["splits"]) == 3
    for i, row in enumerate(res["splits"], 1):
        data = (brig.bdir / f"signed-{i:03d}.apk").read_bytes()
        assert row == {"index": i, "input_sha256": hashlib.sha256(brig.splits[i - 1]).hexdigest(), "output_sha256": hashlib.sha256(data).hexdigest(),
                       "output_size": len(data), "cert_sha256": OWNER, "v2": True, "v3": True, "signer_count": 1}
    parsed = signspool.parse_result(stored_result(d, job_id))
    assert parsed["ok"] is True and len(parsed["splits"]) == 3
    assert list(d.LAYOUT.signwork.iterdir()) == [] and not (brig.home / job_id).exists()
    # masukan milik runner tidak disentuh
    assert (brig.bdir / "unsigned.apk").read_bytes() == BASE
    for i in range(1, 4):
        assert (brig.bdir / f"split-{i:03d}.apk").read_bytes() == brig.splits[i - 1]


def test_batch_urutan_alat_per_berkas_dan_semua_di_signwork_privat(brig):
    brig.put(2)
    job_id, res = brig.run()
    assert res["ok"] is True
    seq = [(t, a, k) for t, a, k in brig.tools()]
    one = lambda k: [("zipalign", "-P", k), ("zipalign", "-c", k), ("apksigner", "sign", k), ("apksigner", "verify", k)]   # noqa: E731
    assert seq == one("0") + one("1") + one("2")
    wdir = brig.d.LAYOUT.signwork / job_id
    for c in brig.calls():
        if c["tool"] == "keytool":
            continue
        assert all(str(brig.bdir) not in a for a in c["argv"]), "tidak ada alat yang menyentuh folder build"
    zips = [c for c in brig.calls() if c["key"] == "zipalign"]
    assert zips[0]["argv"] == ["-P", "16", "-f", "4", str(wdir / "in.apk"), str(wdir / "aligned.apk")]
    assert zips[1]["argv"] == ["-P", "16", "-f", "4", str(wdir / "s001" / "in.apk"), str(wdir / "s001" / "aligned.apk")]
    assert zips[2]["argv"] == ["-P", "16", "-f", "4", str(wdir / "s002" / "in.apk"), str(wdir / "s002" / "aligned.apk")]


def test_argv_zipalign_apksigner_split_sama_dengan_2b(brig):
    """k >= 1 memakai builder argv PERSIS 2b: tanpa --min-sdk-version dan tanpa --v1-signing-enabled (recon: keduanya merusak split tanpa uses-sdk)."""
    d = brig.d
    brig.put(1)
    job_id, res = brig.run()
    assert res["ok"]
    sub = d.LAYOUT.signwork / job_id / "s001"
    sign = [c for c in brig.calls() if c["key"] == "apksigner:sign"][1]["argv"]
    assert sign == d.build_sign_cmd(sub / "aligned.apk", sub / "signed.apk")[1:]
    assert not any(a in ("--min-sdk-version", "--v1-signing-enabled", "--key-pass") for a in sign)
    chk = [c for c in brig.calls() if c["key"] == "zipalign:check"][1]["argv"]
    assert chk == d.build_zipalign_check_cmd(sub / "aligned.apk")[1:]
    ver = [c for c in brig.calls() if c["key"] == "apksigner:verify"][1]["argv"]
    assert ver == d.build_verify_cmd(sub / "signed.apk")[1:]


def test_semua_berkas_ditandatangani_kunci_pemilik_yang_sama(brig):
    brig.put(3)
    _, res = brig.run()
    assert res["ok"]
    signs = [c["argv"] for c in brig.calls() if c["key"] == "apksigner:sign"]
    assert len(signs) == 4
    ks = {(a[a.index("--ks") + 1], a[a.index("--ks-key-alias") + 1], a[a.index("--ks-pass") + 1]) for a in signs}
    assert len(ks) == 1, "satu keystore, satu alias, satu berkas sandi untuk SEMUA berkas"
    assert {row["cert_sha256"] for row in res["splits"]} | {res["cert_sha256"]} == {OWNER}
    for c in brig.calls():
        assert PASSWORD not in json.dumps(c["argv"]) and PASSWORD not in json.dumps(c["env"])


def test_tanpa_splits_perilaku_2b_identik(brig):
    brig.put(2)                                    # split ada di disk tetapi TIDAK diminta
    job_id, res = brig.run(splits=[])
    assert res["ok"] is True and "splits" not in res
    assert brig.names() == sorted(["unsigned.apk", "split-001.apk", "split-002.apk", "signed.apk"])
    assert [(t, a) for t, a, _k in brig.tools()] == [("zipalign", "-P"), ("zipalign", "-c"), ("apksigner", "sign"), ("apksigner", "verify")]
    assert not any(c["tree"] and any(n.startswith("s0") for n in c["tree"]) for c in brig.calls() if c["tree"] is not None), "tanpa subfolder per berkas"
    assert signspool.parse_result(stored_result(brig.d, job_id))["splits"] == []


def test_split_di_disk_lebih_banyak_dari_diminta_hanya_yang_diminta_ditandatangani(brig):
    brig.put(3)
    _, res = brig.run(splits=brig.hashes()[:2])
    assert res["ok"] and len(res["splits"]) == 2
    assert "signed-003.apk" not in brig.names() and "signed-002.apk" in brig.names()


def test_batch_199_split_tertinggi_diterima(brig, monkeypatch):
    brig.put(2)
    # 199 elemen permintaan, tetapi hanya 2 berkas di disk -> split ke-3 hilang; batas jumlah sendiri diterima validator
    job = brig.request(splits=brig.hashes() + ["a" * 64] * 197)
    _, res = brig.run(job=job)
    assert res["error_code"] == "input_missing"


def test_batch_signwork_dibersihkan_antar_berkas(brig):
    brig.put(3)
    job_id, res = brig.run()
    assert res["ok"]
    signs = [c for c in brig.calls() if c["key"] == "apksigner:sign"]
    k2 = next(c for c in signs if c["k"] == "2")["tree"]
    assert not any(n.startswith("s001") for n in k2), k2                 # subfolder berkas sebelumnya sudah dihapus
    for top in ("in.apk", "aligned.apk", "signed.apk"):
        assert top not in k2, k2                                         # berkas kerja k=0 dibersihkan sebelum iterasi 1
    assert "s002" in k2


def test_batch_subfolder_per_berkas_0700_dibuat_dirfd(brig, monkeypatch):
    d = brig.d
    brig.put(1)
    modes = []
    real_mkdir = d.os.mkdir

    def spy(path, mode=0o777, *, dir_fd=None):
        modes.append((str(path), mode, dir_fd is not None))
        return real_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(d.os, "mkdir", spy)
    _, res = brig.run()
    assert res["ok"]
    assert [m for m in modes if m[0] == "s001"] == [("s001", 0o700, True)]


def test_batch_subfolder_dihapus_juga_saat_gagal(brig):
    brig.put(2)
    brig.behave(by_k={"1": {"apksigner:sign": {"mode": "fail", "partial": True}}})
    job_id, res = brig.run()
    assert res["error_code"] == "sign_failed"
    assert_nothing_signed(brig, job_id)


def test_batch_tanpa_splits_tidak_membuat_subfolder(brig, monkeypatch):
    made = []
    real = brig.d.os.mkdir
    monkeypatch.setattr(brig.d.os, "mkdir", lambda p, *a, **k: (made.append(str(p)), real(p, *a, **k))[1])
    _, res = brig.run(splits=[])
    assert res["ok"] and not [m for m in made if m.startswith("s0")]


# ================================================================================ expect PER BERKAS, fase 0
def test_batch_fase0_hash_beda_nol_panggilan_alat(brig):
    brig.put(3)
    bad = brig.hashes()
    bad[1] = "0" * 64
    job_id, res = brig.run(splits=bad)
    assert (res["ok"], res["error_code"]) == (False, "input_unsafe") and "split-002" in res["error_text"]
    assert brig.tools() == []
    assert_nothing_signed(brig, job_id)


def test_expect_dipetakan_per_indeks(brig):
    """Dua split berisi beda, hash TERTUKAR urutannya -> input_unsafe untuk tepat berkas yang salah, nol alat."""
    brig.put(2)
    h = brig.hashes()
    job_id, res = brig.run(splits=[h[1], h[0]])
    assert res["error_code"] == "input_unsafe" and "split-001" in res["error_text"]
    assert brig.tools() == []
    assert_nothing_signed(brig, job_id)


def test_expect_base_dipetakan_ke_unsigned_bukan_ke_split(brig):
    brig.put(1)
    job_id, res = brig.run(expect=brig.hashes()[0])         # hash split dipakai sebagai expect base
    assert res["error_code"] == "input_unsafe" and "unsigned.apk" in res["error_text"]
    assert brig.tools() == []


def test_batch_hash_base_beda_saja_cukup_menggagalkan_semuanya(brig):
    brig.put(2)
    job_id, res = brig.run(expect="1" * 64)
    assert res["error_code"] == "input_unsafe" and brig.tools() == []
    assert_nothing_signed(brig, job_id)


def test_batch_split_hilang_input_missing_nol_signed(brig):
    brig.put(3)
    h = brig.hashes()
    (brig.bdir / "split-002.apk").unlink()
    job_id, res = brig.run(splits=h)
    assert res["error_code"] == "input_missing" and "split-002" in res["error_text"]
    assert brig.tools() == []
    assert_nothing_signed(brig, job_id)


def test_permintaan_parsial_dua_dari_tiga_split_hilang_semua_ditolak(brig):
    """Permintaan menyebut 3 split, hanya split-001 yang ada: tidak ada satu pun berkas (juga base) ditandatangani."""
    brig.put(3)
    h = brig.hashes()
    for i in (2, 3):
        (brig.bdir / f"split-{i:03d}.apk").unlink()
    job_id, res = brig.run(splits=h)
    assert res["ok"] is False and res["error_code"] == "input_missing"
    assert brig.tools() == [] and "signed.apk" not in brig.names() and "signed-001.apk" not in brig.names()


def test_split_kosong_input_unsafe(brig):
    brig.put(2)
    h = brig.hashes()
    (brig.bdir / "split-002.apk").write_bytes(b"")
    _, res = brig.run(splits=h)
    assert res["error_code"] == "input_unsafe" and brig.tools() == []


# ================================================================================ masukan tak aman (open_input per berkas)
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "direktori"])
def test_batch_split_tak_aman_input_unsafe(brig, kind, tmp_path):
    brig.put(3)
    h = brig.hashes()
    target = brig.bdir / "split-002.apk"
    keep = target.read_bytes()
    target.unlink()
    if kind == "symlink":
        outside = tmp_path / "luar.apk"
        outside.write_bytes(keep)
        target.symlink_to(outside)
    elif kind == "hardlink":
        target.write_bytes(keep)
        os.link(target, brig.bdir / "tautan-lain")
    else:
        target.mkdir()
    job_id, res = brig.run(splits=h)
    assert res["error_code"] == "input_unsafe" and "split-002" in res["error_text"], res
    assert brig.tools() == []
    assert not [n for n in signed_names(brig)], brig.names()
    if kind == "symlink":
        assert (tmp_path / "luar.apk").read_bytes() == keep


def test_batch_split_fifo_tidak_menggantung(brig):
    brig.put(2)
    h = brig.hashes()
    (brig.bdir / "split-002.apk").unlink()
    os.mkfifo(brig.bdir / "split-002.apk")
    try:
        started = time.monotonic()
        (job_id, res), exc = within(8, lambda: brig.run(splits=h))
        assert exc is None and time.monotonic() - started < 5
    finally:
        try:
            os.close(os.open(brig.bdir / "split-002.apk", os.O_RDWR | os.O_NONBLOCK))
        except OSError:
            pass
    assert res["error_code"] == "input_unsafe" and brig.tools() == []


def test_batch_symlink_pada_base_juga_ditolak_dan_split_tidak_diproses(brig, tmp_path):
    brig.put(2)
    h = brig.hashes()
    (brig.bdir / "unsigned.apk").unlink()
    (brig.bdir / "unsigned.apk").symlink_to(tmp_path / "x")
    _, res = brig.run(splits=h, expect="2" * 64)
    assert res["error_code"] == "input_unsafe" and brig.tools() == []


# ================================================================================ batas jumlah / ukuran
def test_jumlah_split_melebihi_199_bad_request_nol_alat(brig):
    brig.put(1)
    job = brig.request(splits=brig.hashes())
    job["splits"] = ["a" * 64] * 200                 # dilewati validator pengirim (ditulis mentah)
    brig.d.SPOOL.submit(job)
    claimed = brig.d.SPOOL.claim_next()
    res = brig.d.run_job(*claimed)
    assert res["error_code"] == "bad_request" and brig.tools() == []
    assert_nothing_signed(brig)


def test_total_byte_melebihi_batas_input_too_large_nol_alat(brig, monkeypatch):
    monkeypatch.setattr(brig.d, "SIGN_MAX_TOTAL_MB", 1)
    brig.put(2, extra={1: {"assets/blob.bin": os.urandom(700 * 1024)}, 2: {"assets/blob.bin": os.urandom(700 * 1024)}})
    job_id, res = brig.run()
    assert res["error_code"] == "input_too_large" and "SIGN_MAX_TOTAL_MB" in res["error_text"]
    assert brig.tools() == []
    assert_nothing_signed(brig, job_id)


def test_total_tepat_di_batas_diterima(brig, monkeypatch):
    brig.put(2)
    total = sum(len(x) for x in [BASE, *brig.splits])
    monkeypatch.setattr(brig.d, "SIGN_MAX_TOTAL_MB", 1)
    assert total < 1024 * 1024
    _, res = brig.run()
    assert res["ok"] is True


def test_ukuran_satu_split_melebihi_batas_per_berkas(brig, monkeypatch):
    monkeypatch.setattr(brig.d, "SIGN_MAX_MB", 1)
    brig.put(2, extra={2: {"assets/blob.bin": os.urandom(1536 * 1024)}})
    job_id, res = brig.run()
    assert res["error_code"] == "input_too_large" and "split-002.apk" in res["error_text"] and "MiB" in res["error_text"]
    assert brig.tools() == []
    assert_nothing_signed(brig, job_id)


def test_sign_max_total_mb_env_default_dan_klem(monkeypatch, tmp_path):
    from test_signer_daemon import load_daemon
    monkeypatch.delenv("SIGN_MAX_TOTAL_MB", raising=False)
    assert load_daemon(monkeypatch, tmp_path).SIGN_MAX_TOTAL_MB == 3072
    for raw, want in (("abc", 3072), ("", 3072), ("0", 1), ("-4", 1), ("99999", 16384), ("2048", 2048), (" 5 ", 5)):
        assert load_daemon(monkeypatch, tmp_path, SIGN_MAX_TOTAL_MB=raw).SIGN_MAX_TOTAL_MB == want


def test_batch_disk_puncak_2x_terbesar_bukan_jumlah(brig, monkeypatch):
    """Ruang kerja dibersihkan antar berkas: 'bebas' dikurangi byte yang MASIH ada di signwork; cukup untuk 2x berkas terbesar, tidak untuk jumlahnya."""
    d = brig.d
    brig.put(3, extra={1: {"assets/b.bin": b"z" * 20000}, 2: {"assets/b.bin": b"z" * 20000}, 3: {"assets/b.bin": b"z" * 20000}})
    biggest = max(len(BASE), *[len(x) for x in brig.splits])
    need = 2 * biggest + d.SIG_SLACK + d.RESERVE

    def used():
        n = 0
        for dp, _dn, fn in os.walk(d.LAYOUT.signwork):
            n += sum(os.path.getsize(os.path.join(dp, f)) for f in fn)
        return n

    monkeypatch.setattr(d.os, "statvfs", lambda _t: SimpleNamespace(f_bavail=need - used(), f_frsize=1))
    job_id, res = brig.run()
    assert res["ok"] is True, res


def test_batas_disk_signwork_berkas_terbesar_no_space_tanpa_sisa(brig, monkeypatch):
    d = brig.d
    brig.put(2, extra={2: {"assets/b.bin": b"z" * 30000}})
    biggest = max(len(x) for x in brig.splits)
    need = 2 * biggest + d.SIG_SLACK + d.RESERVE
    monkeypatch.setattr(d.os, "statvfs", lambda _t: SimpleNamespace(f_bavail=need - 1, f_frsize=1))
    job_id, res = brig.run()
    assert res["error_code"] == "no_space"
    assert_nothing_signed(brig, job_id)


# ================================================================================ semua-atau-tidak-sama-sekali
def _spy_finish(d, bdir, box):
    real = d.SPOOL.finish

    def finish(job_id, result):
        box["at_finish"] = sorted(p.name for p in bdir.iterdir())
        return real(job_id, result)

    d.SPOOL.finish = finish


def test_batch_gagal_di_tengah_semua_signed_dibuang_sebelum_hasil(brig):
    d = brig.d
    brig.put(3)
    brig.behave(by_k={"3": {"apksigner:sign": {"mode": "fail", "partial": True}}})
    published = []
    real_pub = d.publish_signed
    d.publish_signed = lambda *a, **k: (real_pub(*a, **k), published.append(k.get("final", "signed.apk")))[0]
    box = {}
    _spy_finish(d, brig.bdir, box)
    job_id, res = brig.run()
    assert res["error_code"] == "sign_failed"
    assert published == ["signed.apk", "signed-001.apk", "signed-002.apk"], published       # sudah terbit 3, lalu k=3 gagal
    assert [n for n in box["at_finish"] if n.startswith("signed")] == [], box              # semuanya dibuang SEBELUM hasil ditulis
    assert_nothing_signed(brig, job_id)


@pytest.mark.parametrize("behavior,code", [
    ({"zipalign": {"mode": "fail", "partial": True, "text": "Unable to open 'x' as zip archive: Success"}}, "align_failed"),
    ({"zipalign:check": {"mode": "fail", "text": "Verification FAILED"}}, "align_failed"),
    ({"apksigner:sign": {"mode": "kill9"}}, "sign_failed"),
    ({"apksigner:verify": {"mode": "fail", "rc": 1, "text": "DOES NOT VERIFY\nERROR: boom"}}, "verify_failed"),
    ({"apksigner:verify": {"digests": [OTHER]}}, "cert_mismatch"),
    ({"apksigner:verify": {"v3": False}}, "verify_failed"),
    ({"apksigner:verify": {"v2": False}}, "verify_failed"),
    ({"apksigner:verify": {"signers": 2}}, "verify_failed"),
    ({"apksigner:verify": {"digests": []}}, "verify_failed"),
])
def test_batch_kegagalan_pada_split_terakhir_tidak_menyisakan_apa_pun(brig, behavior, code):
    brig.put(2)
    brig.behave(by_k={"2": behavior})
    job_id, res = brig.run()
    assert (res["ok"], res["error_code"]) == (False, code), res
    assert_nothing_signed(brig, job_id)
    stored = signspool.parse_result(stored_result(brig.d, job_id))
    assert stored["ok"] is False and stored["error_code"] == code and stored["splits"] == []


def test_batch_cert_beda_satu_berkas_seluruh_set_dibuang(brig):
    brig.put(3)
    brig.behave(by_k={"2": {"apksigner:verify": {"digests": [OTHER]}}})
    job_id, res = brig.run()
    assert res["error_code"] == "cert_mismatch" and OTHER[:12] in res["error_text"] and OWNER[:12] in res["error_text"]
    assert_nothing_signed(brig, job_id)


def test_batch_evaluate_verify_untuk_semua_k(brig):
    """Sertifikat beda HANYA pada k=3 (terakhir) tetap menjatuhkan seluruh set -> evaluate_verify tidak dilewati untuk k >= 1."""
    brig.put(3)
    brig.behave(by_k={"3": {"apksigner:verify": {"digests": [OWNER, OTHER]}}})
    _, res = brig.run()
    assert res["error_code"] == "cert_mismatch"


def test_batch_hasil_ok_hanya_bila_semua_sertifikat_identik_keystore(brig):
    brig.put(2)
    brig.behave(by_k={"1": {"apksigner:verify": {"digests": [OWNER]}}})
    _, res = brig.run()
    assert res["ok"] and {r["cert_sha256"] for r in res["splits"]} == {OWNER}


def test_batch_split_non_zip_setelah_zipalign_gagal_tertutup(brig):
    """Split bukan ZIP (zipalign palsu menyalin begitu saja): pindaian TIDAK dilewati -> input_unsafe, apksigner tidak dipanggil untuk berkas itu."""
    brig.put(2)
    h = brig.hashes()
    (brig.bdir / "split-002.apk").write_bytes(b"bukan zip sama sekali" * 10)
    h[1] = hashlib.sha256((brig.bdir / "split-002.apk").read_bytes()).hexdigest()
    job_id, res = brig.run(splits=h)
    assert res["error_code"] == "input_unsafe"
    assert not [t for t in brig.tools() if t[2] == "2" and t[0] == "apksigner"]
    assert_nothing_signed(brig, job_id)


def test_batch_stale_signature_terdeteksi_pada_aligned_apksigner_tidak_dipanggil(brig):
    brig.put(3, extra={2: {"META-INF/OLD.RSA": b"\x30\x00", "META-INF/OLD.SF": b"sf", "META-INF/MANIFEST.MF": b"mf"}})
    job_id, res = brig.run()
    assert res["error_code"] == "stale_signature" and "split-002" in res["error_text"]
    assert not [t for t in brig.tools() if t[2] == "2" and t[0] == "apksigner"]
    assert not [t for t in brig.tools() if t[2] == "3"], "berkas sesudahnya tidak pernah diproses"
    assert_nothing_signed(brig, job_id)


@pytest.mark.parametrize("stale", ["META-INF/X.RSA", "META-INF/X.DSA", "META-INF/X.EC", "META-INF/X.SF", "META-INF/MANIFEST.MF", "meta-inf/x.rsa", "META-INF/SIG-X"])
def test_batch_stale_signature_setiap_jenis(brig, stale):
    brig.put(1, extra={1: {stale: b"x"}})
    _, res = brig.run()
    assert res["error_code"] == "stale_signature"
    assert not [t for t in brig.tools() if t[2] == "1" and t[0] == "apksigner"]


def test_batch_meta_inf_bukan_tanda_tangan_selamat(brig):
    brig.put(1, extra={1: {"META-INF/services/demo": b"x", "META-INF/com.x.version": b"1", "META-INF/a.kotlin_module": b"k"}})
    _, res = brig.run()
    assert res["ok"] is True


def test_batch_nama_ganda_pasca_casefold_input_unsafe(brig):
    data = zbytes([("res/A.txt", b"1"), ("res/a.txt", b"2")])
    brig.put(1)
    (brig.bdir / "split-001.apk").write_bytes(data)
    brig.splits[0] = data
    job_id, res = brig.run(splits=brig.hashes())
    assert res["error_code"] == "input_unsafe" and "split-001" in res["error_text"]
    assert not [t for t in brig.tools() if t[0] == "apksigner" and t[2] == "1"]
    assert_nothing_signed(brig, job_id)


def test_batch_nama_ganda_persis_input_unsafe(brig):
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        data = zbytes([("classes.dex", b"1"), ("classes.dex", b"2")])
    brig.put(1)
    (brig.bdir / "split-001.apk").write_bytes(data)
    brig.splits[0] = data
    _, res = brig.run(splits=brig.hashes())
    assert res["error_code"] == "input_unsafe"


def test_batch_terlalu_banyak_entri_input_unsafe(brig, monkeypatch):
    monkeypatch.setattr(brig.d, "ZIP_MAX_ENTRIES", 3)
    brig.put(1, extra={1: {"a": b"1", "b": b"2", "c": b"3"}})
    _, res = brig.run()
    assert res["error_code"] == "input_unsafe" and not [t for t in brig.tools() if t[0] == "apksigner" and t[2] == "1"]


# ---- pindaian KELUARAN
def test_batch_stale_signature_keluaran(brig):
    brig.put(2)
    brig.behave(by_k={"2": {"apksigner:sign": {"inject": ["META-INF/OLD.RSA", "META-INF/OWNER.RSA", "META-INF/OWNER.SF"]}}})
    job_id, res = brig.run()
    assert res["error_code"] == "stale_signature" and "split-002" in res["error_text"]
    assert_nothing_signed(brig, job_id)


def test_pindai_keluaran_himpunan_boleh_sig_ditolak(brig):
    brig.put(1)
    brig.behave(by_k={"1": {"apksigner:sign": {"inject": ["META-INF/MANIFEST.MF", "META-INF/SIG-X.SF"]}}})
    _, res = brig.run()
    assert res["error_code"] == "stale_signature"


def test_pindai_keluaran_himpunan_boleh_diterima(brig):
    brig.put(2)
    brig.behave(by_k={"1": {"apksigner:sign": {"inject": ["META-INF/MANIFEST.MF", "META-INF/OWNER.SF", "META-INF/OWNER.RSA"]}},
                      "2": {"apksigner:sign": {"inject": ["META-INF/MANIFEST.MF", "META-INF/OWNER.SF", "META-INF/OWNER.EC"]}}})
    _, res = brig.run()
    assert res["ok"] is True


def test_pindai_keluaran_non_zip_verify_failed(brig):
    brig.put(1)
    brig.behave(by_k={"1": {"apksigner:sign": {"garbage_out": True}}})
    job_id, res = brig.run()
    assert res["error_code"] == "verify_failed"
    assert_nothing_signed(brig, job_id)


def test_pindai_tidak_dilakukan_untuk_base_k0_dan_apk_tunggal(brig):
    """k=0 (dan APK tunggal) mengikuti 2b: tidak dipindai, tidak ada kode galat baru -> base dengan META-INF/*.RSA di keluaran tetap lulus."""
    (brig.bdir / "unsigned.apk").write_bytes(zbytes({"classes.dex": b"d", "META-INF/X.RSA": b"\x30\x00", "META-INF/Y.RSA": b"\x30\x00"}))
    brig.put(1)
    brig.behave(by_k={"0": {"apksigner:sign": {"inject": ["META-INF/Z.RSA", "META-INF/SIG-Q"]}}})
    _, res = brig.run()
    assert res["ok"] is True, res
    # APK tunggal (tanpa splits)
    for n in brig.names():
        if n.startswith("signed"):
            (brig.bdir / n).unlink()
    _, res = brig.run(splits=[])
    assert res["ok"] is True and "splits" not in res


def test_base_dengan_meta_inf_sesuai_aturan(brig):
    (brig.bdir / "unsigned.apk").write_bytes(zbytes({"classes.dex": b"d", "META-INF/X.RSA": b"\x30\x00", "META-INF/X.SF": b"sf"}))
    brig.put(1)
    _, res = brig.run()
    assert res["ok"] is True


# ================================================================================ tmp ditanam, penerbitan
def test_batch_tmp_ditanam_eexist_gagal_tertutup(brig):
    d = brig.d
    brig.put(2)
    real = d.publish_signed

    def planted(*a, **kw):
        if kw.get("final") == "signed-001.apk":
            os.symlink("/etc/hostname", brig.bdir / ".sign-signed-001.tmp")
        return real(*a, **kw)

    d.publish_signed = planted
    job_id, res = brig.run()
    assert res["error_code"] == "internal" and ".sign-signed-001.tmp" in res["error_text"]
    assert_nothing_signed(brig, job_id)
    assert Path("/etc/hostname").exists()


def test_publish_signed_nama_tmp_dan_akhir_dapat_diatur_dan_2b_tetap_bawaan(d, tmp_path):
    bdir = tmp_path / "b"
    bdir.mkdir()
    src = tmp_path / "s.apk"
    src.write_bytes(b"hasil")
    sha = hashlib.sha256(b"hasil").hexdigest()
    bfd = os.open(bdir, os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open(src, os.O_RDONLY)
    try:
        d.publish_signed(bfd, fd, sha, 5, lambda: None, tmp=".sign-signed-007.tmp", final="signed-007.apk")
        d.publish_signed(bfd, fd, sha, 5, lambda: None)
    finally:
        os.close(fd)
        os.close(bfd)
    assert sorted(p.name for p in bdir.iterdir()) == ["signed-007.apk", "signed.apk"]
    assert (bdir / "signed-007.apk").read_bytes() == b"hasil"


def test_publish_signed_nnn_ditukar_setelah_terbit_terdeteksi_baca_ulang(d, tmp_path, monkeypatch):
    bdir = tmp_path / "b"
    bdir.mkdir()
    src = tmp_path / "s.apk"
    src.write_bytes(b"hasil")
    sha = hashlib.sha256(b"hasil").hexdigest()
    real = os.replace

    def replace_then_tamper(a, b, **kw):
        real(a, b, **kw)
        if b == "signed-001.apk":
            with open(bdir / "signed-001.apk", "r+b") as fh:
                fh.write(b"JAHAT")

    monkeypatch.setattr(d.os, "replace", replace_then_tamper)
    bfd = os.open(bdir, os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open(src, os.O_RDONLY)
    try:
        with pytest.raises(d.JobError) as ei:
            d.publish_signed(bfd, fd, sha, 5, lambda: None, tmp=".sign-signed-001.tmp", final="signed-001.apk")
    finally:
        os.close(fd)
        os.close(bfd)
    assert ei.value.code == "internal"
    assert not (bdir / "signed-001.apk").exists(), "berkas yang ditukar dihapus, bukan dibiarkan bernama signed-NNN.apk"


# ================================================================================ TOCTOU nyata antar-utas / sisipan
def test_tukar_path_split_setelah_fd_dipegang_tak_berpengaruh(brig):
    """Runner menukar JALUR split-002.apk (rename inode baru) SETELAH fase 0: yang disalin dan ditandatangani tetap inode yang sudah divalidasi."""
    d = brig.d
    brig.put(2)
    h = brig.hashes()
    original = brig.splits[1]
    real = d.copy_input
    calls = []

    def hooked(src_fd, wdfd, max_bytes, on_tick, *a, **kw):
        calls.append(1)
        if len(calls) == 3:
            evil = brig.bdir / ".evil"
            evil.write_bytes(split_zip(99))
            os.rename(evil, brig.bdir / "split-002.apk")
        return real(src_fd, wdfd, max_bytes, on_tick, *a, **kw)

    d.copy_input = hooked
    job_id, res = brig.run(splits=h)
    assert len(calls) == 3
    assert res["ok"] is True, res
    assert (brig.bdir / "signed-002.apk").read_bytes() == original
    assert b"SPLIT-99" not in (brig.bdir / "signed-002.apk").read_bytes()


def test_tukar_split_antara_fase0_dan_salin_ditolak(brig):
    """Isi inode split-002 diubah DI TEMPAT antara fase 0 dan penyalinan: hash ulang pada salinan != expect -> input_unsafe; k=0/1 yang sudah terbit dibuang."""
    d = brig.d
    brig.put(3)
    real = d.copy_input
    calls = []

    def hooked(src_fd, wdfd, max_bytes, on_tick, *a, **kw):
        calls.append(1)
        if len(calls) == 3:
            with open(brig.bdir / "split-002.apk", "r+b") as fh:
                fh.seek(10)
                fh.write(b"DIUBAH-RUNNER")
        return real(src_fd, wdfd, max_bytes, on_tick, *a, **kw)

    d.copy_input = hooked
    job_id, res = brig.run()
    assert res["error_code"] == "input_unsafe" and "split-002" in res["error_text"]
    assert not [t for t in brig.tools() if t[2] in ("2", "3")]
    assert_nothing_signed(brig, job_id)


def test_tukar_split_tumbuh_saat_disalin_input_too_large(brig, monkeypatch):
    d = brig.d
    brig.put(1)
    real = d.copy_input

    def hooked(src_fd, wdfd, max_bytes, on_tick, *a, **kw):
        return real(src_fd, wdfd, 10, on_tick, *a, **kw)         # batas per salinan diperkecil: simulasi berkas tumbuh

    d.copy_input = hooked
    _, res = brig.run()
    assert res["error_code"] == "input_too_large"


def test_fd_semua_masukan_dipegang_sejak_fase_0_dan_ditutup_semua(brig):
    brig.put(3)
    before = set(os.listdir("/proc/self/fd"))
    _, res = brig.run()
    assert res["ok"]
    after = set(os.listdir("/proc/self/fd"))
    assert len(after - before) <= 1, "tidak ada fd bocor (selisih 1 mungkin fd listdir itu sendiri)"


def test_fd_tidak_bocor_saat_gagal(brig):
    brig.put(3)
    brig.behave(by_k={"2": {"apksigner:verify": {"digests": [OTHER]}}})
    before = len(os.listdir("/proc/self/fd"))
    _, res = brig.run()
    assert res["error_code"] == "cert_mismatch"
    assert len(os.listdir("/proc/self/fd")) <= before + 1


# ================================================================================ tenggat, pembatalan, henti
def test_batch_tenggat_diskalakan_per_berkas(brig, monkeypatch):
    d = brig.d
    monkeypatch.setattr(d, "SIGN_TIMEOUT", 30)
    seen = []
    real = d.run_tool

    def spy(argv, *, deadline, **kw):
        if argv[0] in ("zipalign", "apksigner"):
            seen.append(deadline)
        return real(argv, deadline=deadline, **kw)

    monkeypatch.setattr(d, "run_tool", spy)
    brig.put(2)
    t0 = time.monotonic()
    _, res = brig.run(timeout=3600)
    assert res["ok"]
    assert len({round(x, 2) for x in seen}) == 1, "SATU tenggat tunggal untuk seluruh set"
    assert 45 < seen[0] - t0 <= 51, seen[0] - t0                # 30 + 10 x 2
    seen.clear()
    for n in brig.names():
        if n.startswith("signed"):
            (brig.bdir / n).unlink()
    t0 = time.monotonic()
    _, res = brig.run(timeout=3600, splits=[])
    assert 26 < seen[0] - t0 <= 31                              # tanpa split: 2b


def test_batch_tenggat_tunggal_membunuh_alat_di_tengah(brig, monkeypatch):
    d = brig.d
    monkeypatch.setattr(d, "SIGN_TIMEOUT", 1)
    monkeypatch.setattr(d, "SIGN_PER_FILE_S", 0)
    brig.put(2)
    brig.behave(by_k={"1": {"apksigner:sign": {"mode": "sleep"}}})
    started = time.monotonic()
    job_id, res = brig.run(timeout=3600)
    assert res["error_code"] == "timeout" and time.monotonic() - started < 15
    time.sleep(0.3)
    from test_signer_daemon import alive
    assert not alive(int((brig.rec / "gc.pid").read_text()))
    assert_nothing_signed(brig, job_id)


def test_batch_pembatalan_di_tengah_nol_sisa(brig):
    d = brig.d
    brig.put(2)
    brig.behave(by_k={"1": {"apksigner:sign": {"mode": "sleep"}}})
    job = brig.request()
    d.SPOOL.submit(job)
    job_id, request = d.SPOOL.claim_next()
    d.SPOOL.request_cancel(job_id)
    started = time.monotonic()
    res = d.run_job(job_id, request)
    assert res["error_code"] == "cancelled" and time.monotonic() - started < 10
    assert_nothing_signed(brig, job_id)


def test_batch_sigterm_di_tengah_aborted_nol_sisa(brig):
    d = brig.d
    brig.put(2)
    brig.behave(by_k={"2": {"apksigner:sign": {"mode": "sleep"}}})
    timer = threading.Timer(1.0, d.STOP.set)
    timer.start()
    try:
        job_id, res = brig.run()
    finally:
        timer.cancel()
    assert res["error_code"] == "aborted"
    assert_nothing_signed(brig, job_id)


# ================================================================================ sapu sisa, yatim
def test_sweep_leftovers_mengenali_signed_nnn_bukan_split_nnn(d, tmp_path):
    bdir = tmp_path / "b"
    bdir.mkdir()
    for n in ("signed.apk", "signed-001.apk", "signed-199.apk", ".sign-signed-001.tmp", ".sign-aligned.tmp", "x.idsig"):
        (bdir / n).write_bytes(b"x")
    for n in ("split-001.apk", "unsigned.apk", "signed-1.apk", "signed-0001.apk", "signed-001.apk.bak", "build.log", "signedXapk"):
        (bdir / n).write_bytes(b"x")
    bfd = os.open(bdir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert d.sweep_leftovers(bfd) == []
    finally:
        os.close(bfd)
    assert sorted(p.name for p in bdir.iterdir()) == sorted(["split-001.apk", "unsigned.apk", "signed-1.apk", "signed-0001.apk", "signed-001.apk.bak", "build.log", "signedXapk"])


def test_sisa_signed_dan_signed_nnn_lama_tidak_tersisa_saat_job_baru_gagal(brig):
    for n in ("signed.apk", "signed-001.apk", "signed-002.apk"):
        (brig.bdir / n).write_bytes(b"lama")
    brig.put(1)
    brig.behave(by_k={"1": {"zipalign": {"mode": "fail"}}})
    job_id, res = brig.run()
    assert res["error_code"] == "align_failed"
    assert_nothing_signed(brig, job_id)


def test_abort_orphans_membersihkan_signed_nnn(brig):
    d = brig.d
    brig.put(2)
    job = brig.request()
    d.SPOOL.ensure_dirs()
    (d.SPOOL.running / f"{job['job_id']}.json").write_text(json.dumps(job))
    for n in ("signed.apk", "signed-001.apk", "signed-002.apk", ".sign-signed-002.tmp"):
        (brig.bdir / n).write_bytes(b"sisa")
    d.abort_orphans()
    assert stored_result(d, job["job_id"])["error_code"] == "aborted"
    assert brig.names() == ["split-001.apk", "split-002.apk", "unsigned.apk"]


def test_sisa_signed_nnn_lama_dibuang_sebelum_job_baru(brig):
    (brig.bdir / "signed-005.apk").write_bytes(b"lama")
    brig.put(1)
    _, res = brig.run()
    assert res["ok"] and "signed-005.apk" not in brig.names()


# ================================================================================ konsistensi konstanta lintas modul
def test_konstanta_bersama_worker_dan_signer_sama(d):
    assert d.SIGN_PER_FILE_S == signspool.SIGN_PER_FILE_S == 10
    assert d.MAX_SPLITS == signspool.MAX_SPLITS == 199
    from rvcore import bundle
    assert signspool.MAX_SPLITS + 1 == bundle.MAX_BUNDLE_APKS, "base + 199 split = 200 APK (FR-9.3)"


def test_nama_berkas_hanya_dari_indeks_bukan_dari_request(brig):
    brig.put(1)
    job = brig.request()
    job["names"] = ["../../evil.apk"]
    job["splits_names"] = {"1": "../x"}
    _, res = brig.run(job=job)
    assert res["ok"] and brig.names() == sorted(["unsigned.apk", "split-001.apk", "signed.apk", "signed-001.apk"])
