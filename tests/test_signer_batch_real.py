"""Tes signer-daemon NYATA untuk multi-berkas (Tahap 3, sub-area C): zipalign + apksigner Build-Tools 37 + JDK 21, bukan alat palsu. Dilewati bersih di CI.

Butuh: SIGNER_TEST_BUILD_TOOLS=<.../android-37.0> SIGNER_TEST_JAVA_HOME=<jdk21> SIGNER_TEST_APK=<base.apk> SIGNER_TEST_SPLITS=<split1.apk>:<split2.apk>
(split sungguhan keluaran bundletool, masih membawa META-INF/BNDLTOOL.*). Yang dibuktikan: DUGAAN "sisa v1 pada split" -> split mentah DITOLAK (`stale_signature`);
split yang sudah dibuang tanda tangannya (rvcore.splitzip.strip_signatures, seperti runner) ditandatangani, diverifikasi mandiri, SEMUA berbagi satu sertifikat
(= keystore pemilik), dan tidak menyisakan berkas tanda tangan selain milik apksigner.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from rvcore import signspool, splitzip
from test_signer_daemon import PASSWORD, WRAPPER, load_daemon, make_keystore

VARS = ("SIGNER_TEST_BUILD_TOOLS", "SIGNER_TEST_JAVA_HOME", "SIGNER_TEST_APK", "SIGNER_TEST_SPLITS")
real_only = pytest.mark.skipif(not all(os.environ.get(v) for v in VARS), reason="alat nyata tidak ada (set " + ", ".join(VARS) + ")")
assert PASSWORD


@pytest.fixture(scope="module")
def tools(tmp_path_factory):
    if not all(os.environ.get(v) for v in VARS):
        pytest.skip("alat nyata tidak ada")
    bt, jh = Path(os.environ["SIGNER_TEST_BUILD_TOOLS"]), Path(os.environ["SIGNER_TEST_JAVA_HOME"])
    root = tmp_path_factory.mktemp("realbatch")
    bindir = root / "bin"
    bindir.mkdir()
    (bindir / "apksigner").write_text(WRAPPER.format(bt=bt))
    (bindir / "apksigner").chmod(0o755)
    (bindir / "zipalign").symlink_to(bt / "zipalign")
    (bindir / "java").symlink_to(jh / "bin" / "java")
    (bindir / "keytool").symlink_to(jh / "bin" / "keytool")
    t = SimpleNamespace(root=root, bin=bindir, bt=bt, apk=Path(os.environ["SIGNER_TEST_APK"]), keytool=jh / "bin" / "keytool",
                        splits=[Path(p) for p in os.environ["SIGNER_TEST_SPLITS"].split(os.pathsep) if p])
    t.owner = make_keystore(t, "owner")
    return t


@pytest.fixture
def rig(tools, monkeypatch, tmp_path):
    d = load_daemon(monkeypatch, tmp_path)
    secrets = tmp_path / "run-secrets"
    secrets.mkdir()
    shutil.copy(tools.owner.p12, secrets / "signing_keystore")
    shutil.copy(tools.owner.pw, secrets / "signing_keystore_pass")
    bdir = d.LAYOUT.build_dir(1, 2)
    bdir.mkdir(parents=True)
    shutil.copy(tools.apk, bdir / "unsigned.apk")
    monkeypatch.setattr(d, "TOOL_PATH", str(tools.bin))
    monkeypatch.setattr(d, "KEYTOOL_TIMEOUT", 60.0)
    monkeypatch.setattr(d, "TICK", 0.25)

    def put(stripped: bool) -> list[str]:
        hashes = []
        bfd = os.open(bdir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for i, src in enumerate(tools.splits, 1):
                name = signspool.split_input_name(i)
                if stripped:
                    with zipfile.ZipFile(src) as zf:
                        splitzip.strip_signatures(zf, bfd, name, splitzip.ZipBudget())
                else:
                    shutil.copy(src, bdir / name)
                hashes.append(hashlib.sha256((bdir / name).read_bytes()).hexdigest())
        finally:
            os.close(bfd)
        return hashes

    def run(hashes, timeout=600):
        job = signspool.build_sign_request(1, 2, timeout, hashlib.sha256((bdir / "unsigned.apk").read_bytes()).hexdigest(), splits=hashes)
        d.SPOOL.submit(job)
        claimed = d.SPOOL.claim_next()
        return d.run_job(*claimed)

    return SimpleNamespace(d=d, bdir=bdir, put=put, run=run)


def verify(tools, path: Path):
    out = subprocess.run([str(tools.bin / "java"), "-jar", str(tools.bt / "lib" / "apksigner.jar"), "verify", "--verbose", "--print-certs", str(path)],
                         capture_output=True, text=True, timeout=180, env={"PATH": "/usr/bin:/bin", "HOME": str(tools.root)})
    return out.returncode, out.stdout


@real_only
def test_real_batch_xapk_semua_satu_sertifikat(rig, tools):
    res = rig.run(rig.put(stripped=True))
    assert res["ok"] is True, res
    assert len(res["splits"]) == len(tools.splits) >= 1
    names = ["signed.apk"] + [signspool.split_output_name(i) for i in range(1, len(tools.splits) + 1)]
    certs = set()
    for name in names:
        rc, text = verify(tools, rig.bdir / name)
        assert rc == 0, (name, text)
        assert "Verified using v2 scheme (APK Signature Scheme v2): true" in text and "Verified using v3 scheme (APK Signature Scheme v3): true" in text
        assert "Number of signers: 1" in text
        certs |= {ln.rsplit(": ", 1)[1].lower() for ln in text.splitlines() if "certificate SHA-256 digest" in ln}
    assert certs == {tools.owner.sha}, "SEMUA berkas ditandatangani kunci pemilik yang SAMA"
    assert {res["cert_sha256"], *[r["cert_sha256"] for r in res["splits"]]} == {tools.owner.sha}


@real_only
def test_real_stale_v1_dibuang_dan_dipindai_bersih(rig, tools):
    res = rig.run(rig.put(stripped=True))
    assert res["ok"] is True, res
    for i in range(1, len(tools.splits) + 1):
        with zipfile.ZipFile(rig.bdir / signspool.split_output_name(i)) as zf:
            names = zf.namelist()
        assert splitzip.unexpected_signature_entries(names) == [], names
        assert not [n for n in names if "BNDLTOOL" in n.upper()], "sisa tanda tangan bundletool tidak boleh lolos"


@real_only
def test_real_split_mentah_dengan_v1_lama_ditolak_stale_signature(rig, tools):
    hashes = rig.put(stripped=False)
    with zipfile.ZipFile(rig.bdir / "split-001.apk") as zf:
        assert any(splitzip.is_signature_entry(n) for n in zf.namelist()), "prasyarat: split uji memang membawa META-INF/*.RSA"
    res = rig.run(hashes)
    assert res["ok"] is False and res["error_code"] == "stale_signature", res
    assert not [p.name for p in rig.bdir.iterdir() if p.name.startswith("signed")]
    assert list(rig.d.LAYOUT.signwork.iterdir()) == []


@real_only
def test_real_satu_split_ditukar_semua_dibuang(rig, tools):
    hashes = rig.put(stripped=True)
    with open(rig.bdir / "split-001.apk", "r+b") as fh:
        fh.seek(20)
        fh.write(b"DIUBAH")
    res = rig.run(hashes)
    assert res["ok"] is False and res["error_code"] == "input_unsafe"
    assert not [p.name for p in rig.bdir.iterdir() if p.name.startswith("signed")]
