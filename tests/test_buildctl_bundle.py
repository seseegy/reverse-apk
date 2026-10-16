"""Tahap 3, sub-area E: keluaran CLI `buildctl` untuk set artefak multi-berkas (XAPK/APKS).

Dibuktikan: `status` dan `artifact-info` menampilkan format asli, daftar split (hash/ukuran/verifikasi), kecocokan sertifikat (dari catatan worker), lokasi skrip
install-multiple, peringatan dan batas jujur; kegagalan per-split bernama jelas dan berkode keluar 3; keluaran build APK tunggal TIDAK berubah (kunci sama).
Tidak dibuktikan: apksigner nyata (CLI web tidak punya alat; sertifikat per split dicatat worker/signer, bukan diverifikasi ulang di sini).
"""

from __future__ import annotations

import io
import time
import zipfile
from contextlib import closing

import pytest
from build_rig import sha
from rvcore import installscript, store
from rvcore import shellspool
from test_buildctl import Out, assert_wellformed, requested
from test_bundle import zip_bytes
from web_rig import FakeBench, ctx_analysis, live_redis


@pytest.fixture
def ctl_mod():
    from app import buildctl
    return buildctl


@pytest.fixture
def env(monkeypatch, ctl_mod):
    import app.builds as wb
    from app import context
    monkeypatch.setenv("AI_SHELL_ENABLED", "0")
    monkeypatch.setattr(ctl_mod, "POLL", 0.02)
    bench = FakeBench(context.layout.root).__enter__()
    yield wb.Deps(layout=context.layout, db=context.db, redis=live_redis(), bench_spool=shellspool.make_spool(context.layout.root / "benchspool"),
                  now=time.time, job_timeout=3300, op_pickup_timeout=3.0, poll=0.02)
    bench.__exit__(None, None, None)


@pytest.fixture
def ctl(capsys, env, ctl_mod):
    def run(*argv: str, stdin: bytes = b"") -> Out:
        code = ctl_mod.main(list(argv), deps=env, stdin=io.BytesIO(stdin))
        cap = capsys.readouterr()
        return Out(code, cap.out, cap.err)
    return run


def _signed_apk(tag: str, extra: dict[str, bytes] | None = None) -> bytes:
    entries = {"AndroidManifest.xml": b"<manifest/>" + tag.encode(), "classes.dex": b"dex\n035\x00" + tag.encode(), "META-INF/services/x": b"s"}
    entries.update(extra or {})
    return zip_bytes(entries)


def _done_bundle(tag: str, fmt: str = "xapk", *, script: str | None = None, script_tamper: bytes | None = None, split_extra: dict[str, bytes] | None = None,
                 stage_extra: str = "") -> tuple[int, int, dict]:
    from app import context
    _apk, aid = ctx_analysis(tag)
    with closing(context.db()) as conn:
        h = sha(f"b-{tag}".encode())
        bid = store.create_build(conn, aid, requested_by="user", source_kind=fmt, diff_sha256=h, diff_summary={"v": 1})
        store.approve_build(conn, bid, diff_sha256=h, statement_sha256=store.approval_statement_sha256(), statement_version=1)
        store.queue_build(conn, bid)
        assert store.claim_build(conn, bid)
        store.mark_signing(conn, bid)
    d = context.layout.builds / str(aid) / str(bid)
    d.mkdir(parents=True)
    pkg_name = f"app-modified-{bid}.{fmt}"
    base, sp1, sp2 = ("com.example.app.apk", "config.arm64_v8a.apk", "config.en.apk") if fmt == "xapk" else ("splits/base-master.apk", "splits/base-arm64_v8a.apk", "splits/base-en.apk")
    pkg = zip_bytes({base: _signed_apk(tag + "b"), sp1: _signed_apk(tag + "1", split_extra), sp2: _signed_apk(tag + "2"), "manifest.json": b"{}"})
    (d / pkg_name).write_bytes(pkg)
    script_name = f"app-modified-{bid}-install.sh"
    text = script if script is not None else installscript.render(fmt, pkg_name, "com.example.app", base, [sp1, sp2])
    (d / script_name).write_bytes(text.encode())
    logged = sha(text.encode())
    if script_tamper is not None:
        (d / script_name).write_bytes(script_tamper)
    log = f"signing_mulai={time.time():.6f}\nsplit_n=2\n{stage_extra}install_script={script_name} sha256={logged}"
    with closing(context.db()) as conn:
        store.finish_build(conn, bid, output_name=pkg_name, output_sha256=sha(pkg), output_size=len(pkg), output_format=fmt, cert_sha256=sha(b"cert"), verify_ok=1,
                           stage_log=log)
    return aid, bid, {"pkg": pkg, "names": [base, sp1, sp2], "script_name": script_name, "pkg_name": pkg_name}


# ============================================================================================ artifact-info
def test_artifact_info_bundle_menampilkan_split_hash_ukuran_verifikasi_dan_skrip(ctl, env):
    aid, bid, meta = _done_bundle("ai-xapk")
    r = ctl("artifact-info", str(bid))
    assert r.code == 0 and r["cocok"] == "1" and r["format"] == "xapk" and r["split_n"] == "3", r.text
    assert_wellformed(r)
    with zipfile.ZipFile(io.BytesIO(meta["pkg"])) as zf:
        for n, name in enumerate(meta["names"], 1):
            data = zf.read(name)
            line = r[f"split.{n}"]
            assert line.startswith(name) and f"sha256={sha(data)}" in line and f"ukuran={len(data)}" in line and "verifikasi=ok" in line, line
    assert r["skrip"] == meta["script_name"] and r["skrip_cocok"] == "1" and r["skrip_lint"] == "ok"
    assert r["skrip_lokasi"] == f"builds/{aid}/{bid}/{meta['script_name']}"
    assert r["sertifikat"].startswith("sama") and r["cert_sha256"] == sha(b"cert")
    assert "100%" in r["batas"] and "Play Integrity" in r["batas"] and "anti-tamper" in r["batas"]
    assert "tautan" in r["unduh"]


def test_artifact_info_apks_nama_entri_dari_paket(ctl, env):
    _aid, bid, meta = _done_bundle("ai-apks", "apks")
    r = ctl("artifact-info", str(bid))
    assert r.code == 0 and r["format"] == "apks" and r["split_n"] == "3" and r["split.1"].startswith("splits/base-master.apk")


def test_artifact_info_skrip_diubah_gagal_dengan_kode_jelas(ctl, env):
    _aid, bid, _m = _done_bundle("ai-skrip-ubah", script_tamper=b"#!/bin/sh\nadb uninstall x\n")
    r = ctl("artifact-info", str(bid))
    assert r.code == 3 and r["kode"] == "skrip_tidak_cocok" and r["skrip_cocok"] == "0", r.text


def test_artifact_info_skrip_di_luar_allowlist_dilaporkan(ctl, env):
    text = installscript.render("xapk", "p.xapk", "com.example.app", "b.apk", ["c.apk"]) + "rm -rf /\n"
    _aid, bid, _m = _done_bundle("ai-skrip-lint", script=text)
    r = ctl("artifact-info", str(bid))
    assert r.code == 3 and r["kode"] == "skrip_tidak_lolos_lint" and r["skrip_cocok"] == "1", r.text


def test_artifact_info_split_bertanda_tangan_apksigner_sah_tidak_dianggap_sisa(ctl, env):
    """Regresi e2e fase 3: paket hasil signer NYATA membawa v1 milik apksigner (MANIFEST.MF + REVERSE-.SF + REVERSE-.RSA) di tiap split; itu bukan sisa tanda tangan
    lama (himpunan yang sama dipakai signer-daemon dan signer-selftest --check-bundle). Sebelumnya semua split dilaporkan `ttd_lama` dan buildctl keluar kode 3."""
    legit = {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "META-INF/REVERSE-.SF": b"sf", "META-INF/REVERSE-.RSA": b"rsa"}
    _aid, bid, _meta = _done_bundle("ai-legit-v1", split_extra=legit)
    r = ctl("artifact-info", str(bid))
    assert r.code == 0, r.text
    assert "verifikasi=ok" in r["split.2"] and "ttd_lama" not in r.text and r.kv.get("kode") in (None, "")


def test_artifact_info_split_dengan_sisa_tanda_tangan_lama_disebut_namanya(ctl, env):
    # Sisa lama + tanda tangan baru = dua nama dasar (CERT dan REVERSE-): di luar himpunan boleh apksigner. (Dahulu cukup satu CERT.RSA; lihat changed-tests.md.)
    _aid, bid, meta = _done_bundle("ai-stale", split_extra={"META-INF/CERT.RSA": b"x", "META-INF/REVERSE-.RSA": b"y"})
    r = ctl("artifact-info", str(bid))
    assert r.code == 3 and r["kode"] == "split_bermasalah", r.text
    assert "verifikasi=ttd_lama" in r["split.2"] and r["split.2"].startswith("config.arm64_v8a.apk")
    assert "config.arm64_v8a.apk" in r["alasan"] and "verifikasi=ok" in r["split.1"]


def test_artifact_info_skrip_hilang(ctl, env):
    from app import context
    aid, bid, meta = _done_bundle("ai-skrip-hilang")
    (context.layout.builds / str(aid) / str(bid) / meta["script_name"]).unlink()
    r = ctl("artifact-info", str(bid))
    assert r.code == 3 and r["kode"] == "skrip_tidak_ada", r.text


def test_artifact_info_apk_tunggal_tanpa_kunci_baru(ctl, env):
    from app import context
    _apk, aid = ctx_analysis("ai-apk")
    from web_rig import ctx_build
    bid = ctx_build(aid, "signing")
    name = f"x-modified-{bid}.apk"
    d = context.layout.builds / str(aid) / str(bid)
    d.mkdir(parents=True)
    (d / name).write_bytes(b"isi-apk")
    with closing(context.db()) as conn:
        store.finish_build(conn, bid, output_name=name, output_sha256=sha(b"isi-apk"), output_size=7, output_format="apk", cert_sha256=sha(b"c"), verify_ok=1,
                           stage_log="signing_mulai=1.0")
    r = ctl("artifact-info", str(bid))
    assert r.code == 0 and list(r.kv) == ["build_id", "output_name", "output_size", "output_sha256", "cert_sha256", "disk_sha256", "cocok"]


# ============================================================================================ status
def test_status_bundle_menampilkan_format_skrip_peringatan_dan_batas(ctl, env):
    aid, bid, meta = _done_bundle("st-xapk", stage_extra="peringatan=versi_split_beda,entri_dibuang=2\n")
    r = ctl("status", str(bid))
    assert r.code == 0 and r["source_kind"] == "xapk" and r["output_format"] == "xapk", r.text
    assert r["install_script"] == meta["script_name"] and r["install_script_lokasi"] == f"builds/{aid}/{bid}/{meta['script_name']}"
    assert r["peringatan"] == "versi_split_beda,entri_dibuang=2"
    assert "100%" in r["batas"] and "tautan" in r["unduh"]
    assert_wellformed(r)


def test_status_apk_tunggal_kunci_tidak_berubah(ctl, env):
    aid, bid, _h = requested(env, ctl, "st-apk")
    r = ctl("status", str(bid))
    assert "source_kind" not in r.kv and "batas" not in r.kv and "install_script" not in r.kv and "unduh" not in r.kv


@pytest.mark.parametrize("code,fragment", [("split_invalid", "split"), ("split_missing", "split"), ("bundle_changed", "ajukan build baru"),
                                           ("sign_cert_mismatch", "sertifikat"), ("bundle_too_large", "batas")])
def test_status_build_paket_gagal_memberi_petunjuk(ctl, env, code, fragment):
    from app import context
    _apk, aid = ctx_analysis("st-gagal-" + code)
    with closing(context.db()) as conn:
        h = sha(code.encode())
        bid = store.create_build(conn, aid, requested_by="user", source_kind="xapk", diff_sha256=h, diff_summary={"v": 1})
        store.approve_build(conn, bid, diff_sha256=h, statement_sha256=store.approval_statement_sha256(), statement_version=1)
        store.queue_build(conn, bid)
        assert store.claim_build(conn, bid)
        store.fail_build(conn, bid, error_code=code, error_text=f"galat {code} pada split config.en.apk", stage_log="x=1")
    r = ctl("status", str(bid))
    assert r.code == 0 and r["status"] == "failed" and r["error_code"] == code
    assert fragment in r["petunjuk"].lower() and "tidak ada set setengah jadi" in r["petunjuk"].lower(), r.text
    assert r["split_gagal"] == "config.en.apk"
    assert_wellformed(r)
