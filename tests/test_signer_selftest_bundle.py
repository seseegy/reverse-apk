"""`signer-selftest --check-bundle <aid> <bid> <nama>` (Tahap 3, sub-area C; design.md 4.4 + addendum #1): verifikasi independen PAKET XAPK/APKS hasil build.

Dipanggil hanya oleh `make verify-build`; selftest hanya MELAPORKAN (keputusan cert == keystore pemilik ada di skrip pemanggil), seperti `--check-apk`.
Pertahanan membongkar paket (addendum #1): paket sumber berkas biasa + nlink==1 lewat rantai dir_fd; nama keluaran dibuat sendiri (`e%03d.apk`, TIDAK dari nama entri)
di subfolder privat `signwork/.check-*` dibuka `O_EXCL|O_NOFOLLOW` lewat dir_fd; batas jumlah/entri/total memakai ZIP_MAX_*; nama ganda dan nama berbahaya ditolak.
Alat PALSU (skrip sh) membaca keluaran per entri dari berkas `verify.<e001.apk>`; yang dilaporkan harus berasal dari entri yang benar.
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import io
import os
import zipfile
from pathlib import Path

import pytest
from conftest import within_call

ROOT = Path(__file__).resolve().parent.parent
CERT_A = hashlib.sha256(b"cert-a").hexdigest()
CERT_B = hashlib.sha256(b"cert-b").hexdigest()
KEYS = ("signers", "v2", "v3", "cert", "zipalign", "sisa_ttd")

FAKE_APKSIGNER = """#!/bin/sh
for a; do last=$a; done
b=$(basename "$last")
echo "apksigner $* " >> "$FAKE_DIR/tools.log"
cp "$last" "$FAKE_DIR/seen.$b" 2>/dev/null
if [ -f "$FAKE_DIR/verify.$b" ]; then cat "$FAKE_DIR/verify.$b"; else cat "$FAKE_DIR/verify.default"; fi
[ -f "$FAKE_DIR/verify.rc.$b" ] && exit "$(cat "$FAKE_DIR/verify.rc.$b")"
exit 0
"""
FAKE_ZIPALIGN = """#!/bin/sh
for a; do last=$a; done
b=$(basename "$last")
echo "zipalign $* " >> "$FAKE_DIR/tools.log"
[ -f "$FAKE_DIR/zipalign.rc.$b" ] && exit "$(cat "$FAKE_DIR/zipalign.rc.$b")"
exit 0
"""


def verify_out(digests=(CERT_A,), v2=True, v3=True, signers=None) -> str:
    lines = ["Verifies", "Verified using v1 scheme (JAR signing): false", f"Verified using v2 scheme (APK Signature Scheme v2): {str(v2).lower()}",
             f"Verified using v3 scheme (APK Signature Scheme v3): {str(v3).lower()}", f"Number of signers: {len(digests) if signers is None else signers}"]
    for i, dig in enumerate(digests, 1):
        lines += [f"Signer #{i} certificate DN: CN=reverse-apk", f"Signer #{i} certificate SHA-256 digest: {dig.upper()}"]
    return "\n".join(lines) + "\n"


def zbytes(entries) -> bytes:
    buf = io.BytesIO()
    items = list(entries.items()) if isinstance(entries, dict) else entries
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, data in items:
            zf.writestr(name, data)
    return buf.getvalue()


def apk(tag: str, extra: dict | None = None) -> bytes:
    return zbytes({"AndroidManifest.xml": b"m-" + tag.encode(), "classes.dex": tag.encode() * 30, **(extra or {})})


@pytest.fixture
def st():
    loader = importlib.machinery.SourceFileLoader("signer_selftest_bundle", str(ROOT / "services/signer/signer-selftest"))
    spec = importlib.util.spec_from_loader("signer_selftest_bundle", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class Rig:
    def __init__(self, tmp_path, monkeypatch, st):
        self.st, self.mp, self.root = st, monkeypatch, tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.fake = tmp_path / "fake"
        self.fake.mkdir()
        for name, body in (("apksigner", FAKE_APKSIGNER), ("zipalign", FAKE_ZIPALIGN)):
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        self.builds = tmp_path / "data" / "builds"
        self.work = tmp_path / "data" / "signwork"
        self.dir = self.builds / "5" / "9"
        self.dir.mkdir(parents=True)
        self.work.mkdir(parents=True)
        self.name = "app-modified-9.xapk"
        self.entries: dict = {}
        (self.fake / "verify.default").write_text(verify_out())
        monkeypatch.setenv("PATH", f"{self.bin}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv("FAKE_DIR", str(self.fake))

    def package(self, entries=None, name=None):
        self.entries = entries if entries is not None else {
            "manifest.json": b'{"package_name":"x"}', "icon.png": b"PNG", "Android/obb/x/main.1.x.obb": b"OBB" * 50,
            "x.apk": apk("base"), "config.arm64_v8a.apk": apk("arm"), "config.xxhdpi.apk": apk("dpi"),
        }
        self.name = name or self.name
        (self.dir / self.name).write_bytes(zbytes(self.entries))
        return self

    def run(self, capsys, *argv, name=None, aid="5", bid="9"):
        rc = self.st.run_check_bundle([aid, bid, self.name if name is None else name, *argv], builds_root=str(self.builds), work_root=str(self.work))
        cap = capsys.readouterr()
        return rc, cap

    def tools(self) -> list[str]:
        p = self.fake / "tools.log"
        return p.read_text().splitlines() if p.exists() else []

    def seen(self, n: int) -> bytes:
        return (self.fake / f"seen.e{n:03d}.apk").read_bytes()

    def leftovers(self):
        return sorted(p.name for p in self.work.iterdir())


@pytest.fixture
def rg(tmp_path, monkeypatch, st):
    return Rig(tmp_path, monkeypatch, st)


def kvs(text: str) -> dict[str, str]:
    return dict(ln.split("=", 1) for ln in text.splitlines() if "=" in ln)


# ================================================================================ positif
def test_check_bundle_xapk_kunci_tepat_dan_berurutan(rg, capsys):
    rg.package()
    rc, cap = rg.run(capsys)
    assert rc == 0, cap.out + cap.err
    order = [ln.split("=", 1)[0] for ln in cap.out.strip().splitlines()]
    want = ["format", "entri_apk"]
    for n in (1, 2, 3):
        want += [f"entri.{n}.nama"] + [f"entri.{n}.{k}" for k in KEYS]
    want += ["cert_berbeda", "extras_n"]
    assert order == want
    got = kvs(cap.out)
    assert (got["format"], got["entri_apk"], got["cert_berbeda"], got["extras_n"]) == ("xapk", "3", "1", "3")
    assert [got[f"entri.{n}.nama"] for n in (1, 2, 3)] == ["x.apk", "config.arm64_v8a.apk", "config.xxhdpi.apk"]
    for n in (1, 2, 3):
        assert (got[f"entri.{n}.signers"], got[f"entri.{n}.v2"], got[f"entri.{n}.v3"], got[f"entri.{n}.cert"], got[f"entri.{n}.zipalign"],
                got[f"entri.{n}.sisa_ttd"]) == ("1", "1", "1", CERT_A, "ok", "0")
    assert cap.err == ""
    assert rg.leftovers() == [], "subfolder kerja dibuang"


def test_check_bundle_apks(rg, capsys):
    rg.package({"splits/base-master.apk": apk("b"), "splits/base-xxhdpi.apk": apk("d"), "toc.pb": b"\x0a\x01"}, name="app-modified-9.apks")
    rc, cap = rg.run(capsys)
    got = kvs(cap.out)
    assert rc == 0 and got["format"] == "apks" and got["entri_apk"] == "2" and got["extras_n"] == "1"


def test_check_bundle_isi_entri_sampai_ke_alat_persis_dan_nama_keluaran_buatan_sendiri(rg, capsys):
    rg.package()
    rc, _ = rg.run(capsys)
    assert rc == 0
    assert rg.seen(1) == rg.entries["x.apk"] and rg.seen(2) == rg.entries["config.arm64_v8a.apk"] and rg.seen(3) == rg.entries["config.xxhdpi.apk"]
    log = rg.tools()
    assert len(log) == 6
    for ln in log:
        path = ln.split()[-1]
        assert Path(path).parent.parent == rg.work and Path(path).parent.name.startswith(".check-")
        assert Path(path).name in ("e001.apk", "e002.apk", "e003.apk"), "nama dari urutan, bukan dari nama entri"
    assert log[0].startswith("zipalign -c -P 16 4 ") and log[1].startswith("apksigner verify --verbose --print-certs ")


def test_check_bundle_laporan_per_entri_dari_entri_yang_benar(rg, capsys):
    rg.package()
    (rg.fake / "verify.e002.apk").write_text(verify_out(digests=(CERT_B,), v3=False))
    rc, cap = rg.run(capsys)
    got = kvs(cap.out)
    assert rc == 0
    assert got["entri.2.cert"] == CERT_B and got["entri.2.v3"] == "0" and got["entri.1.cert"] == CERT_A and got["entri.3.cert"] == CERT_A
    assert got["cert_berbeda"] == "2"


def test_check_bundle_cert_berbeda_menghitung_sertifikat_unik_lintas_entri(rg, capsys):
    rg.package()
    (rg.fake / "verify.e001.apk").write_text(verify_out(digests=(CERT_A, CERT_B)))        # satu entri dengan dua penanda tangan
    rc, cap = rg.run(capsys)
    got = kvs(cap.out)
    assert got["cert_berbeda"] == "2" and got["entri.1.signers"] == "2" and got["entri.1.cert"] == ",".join(sorted([CERT_A, CERT_B]))


def test_check_bundle_sisa_ttd_menghitung_pelanggar_himpunan_boleh(rg, capsys):
    rg.package({"manifest.json": b"{}", "b.apk": apk("b", {"META-INF/MANIFEST.MF": b"m", "META-INF/OWNER.SF": b"s", "META-INF/OWNER.RSA": b"r"}),
                "c.apk": apk("c", {"META-INF/OLD.RSA": b"r", "META-INF/OWNER.SF": b"s", "META-INF/OWNER.RSA": b"r"}), "d.apk": apk("d", {"META-INF/services/x": b"x"})},
               name="p.xapk")
    rc, cap = rg.run(capsys, name="p.xapk")
    got = kvs(cap.out)
    assert rc == 0
    assert (got["entri.1.sisa_ttd"], got["entri.2.sisa_ttd"], got["entri.3.sisa_ttd"]) == ("0", "3", "0")


def test_check_bundle_tanpa_split_hanya_base(rg, capsys):
    rg.package({"manifest.json": b"{}", "base.apk": apk("b"), "Android/obb/p/main.obb": b"x"})
    rc, cap = rg.run(capsys)
    got = kvs(cap.out)
    assert rc == 0 and got["entri_apk"] == "1" and got["extras_n"] == "2"


def test_check_bundle_direktori_di_paket_tidak_dihitung_extras(rg, capsys):
    rg.package([("Android/", b""), ("Android/obb/", b""), ("b.apk", apk("b")), ("manifest.json", b"{}")])
    rc, cap = rg.run(capsys)
    assert rc == 0 and kvs(cap.out)["extras_n"] == "1"


# ================================================================================ pertahanan zip-slip / nama
@pytest.mark.parametrize("bad", ["../x.apk", "/abs.apk", "a/../b.apk", "a\\b.apk", "..\\x.apk", "a\nb.apk", "./x.apk", "a//b.apk"])
def test_check_bundle_zip_slip_nama_tidak_menjadi_path(rg, capsys, bad, tmp_path):
    rg.package([("ok.apk", apk("ok")), (bad, apk("jahat"))])
    rc, cap = rg.run(capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "bukan_paket"
    assert rg.tools() == [] and rg.leftovers() == []
    assert not list(tmp_path.rglob("x.apk")) and not (rg.work.parent / "x.apk").exists() and not (rg.root / "abs.apk").exists()


def test_check_bundle_nama_ganda_ditolak(rg, capsys):
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        rg.package([("a.apk", apk("1")), ("a.apk", apk("2"))])
    rc, cap = rg.run(capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "bukan_paket" and rg.tools() == []


def test_check_bundle_nama_ganda_beda_huruf_ditolak(rg, capsys):
    rg.package([("Split.apk", apk("1")), ("split.APK", apk("2"))])
    rc, cap = rg.run(capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "bukan_paket" and rg.tools() == []


def test_check_bundle_nama_entri_tidak_menentukan_nama_berkas_kerja(rg, capsys):
    rg.package([("splits/config.tr.apk", apk("tr")), ("deep/a/b/c.APK", apk("c"))])
    rc, cap = rg.run(capsys)
    assert rc == 0
    names = sorted(Path(ln.split()[-1]).name for ln in rg.tools())
    assert names == ["e001.apk", "e001.apk", "e002.apk", "e002.apk"]


def test_check_bundle_subfolder_kerja_0700_dan_berkas_0600_o_excl(rg, capsys, monkeypatch):
    rg.package()
    modes = []
    real_mkdir, real_open = os.mkdir, os.open

    def spy_mkdir(p, mode=0o777, *, dir_fd=None):
        modes.append(("mkdir", str(p), mode, dir_fd is not None))
        return real_mkdir(p, mode, dir_fd=dir_fd)

    def spy_open(p, flags, mode=0o777, *, dir_fd=None):
        if str(p).startswith("e0"):
            modes.append(("open", str(p), flags, dir_fd is not None, mode))
        return real_open(p, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", spy_mkdir)
    monkeypatch.setattr(os, "open", spy_open)
    rc, _ = rg.run(capsys)
    monkeypatch.undo()
    assert rc == 0
    mk = [m for m in modes if m[0] == "mkdir"]
    assert len(mk) == 1 and mk[0][1].startswith(".check-") and mk[0][2] == 0o700 and mk[0][3] is True
    ops = [m for m in modes if m[0] == "open" and m[2] & os.O_CREAT]
    assert [o[1] for o in ops] == ["e001.apk", "e002.apk", "e003.apk"]
    for o in ops:
        assert o[2] & os.O_EXCL and o[2] & os.O_NOFOLLOW and o[2] & os.O_CREAT and o[3] is True and o[4] == 0o600


def test_check_bundle_subfolder_kerja_yang_sudah_ada_ditolak_tidak_dipakai(rg, capsys, monkeypatch):
    rg.package()
    monkeypatch.setattr(rg.st.secrets, "token_hex", lambda n=8: "aaaa")
    planted = rg.work / ".check-aaaa"
    planted.mkdir()
    (planted / "milik-orang.txt").write_text("jangan sentuh")
    rc, cap = rg.run(capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "internal" and rg.tools() == []
    assert (planted / "milik-orang.txt").read_text() == "jangan sentuh"


def test_check_bundle_subfolder_kerja_symlink_tidak_diikuti(rg, capsys, monkeypatch, tmp_path):
    rg.package()
    outside = tmp_path / "luar"
    outside.mkdir()
    monkeypatch.setattr(rg.st.secrets, "token_hex", lambda n=8: "bbbb")
    (rg.work / ".check-bbbb").symlink_to(outside)
    rc, cap = rg.run(capsys)
    assert rc == 3 and rg.tools() == [] and list(outside.iterdir()) == []


def test_check_bundle_folder_kerja_tak_ada_internal(rg, capsys):
    rg.package()
    rg.work.rmdir()
    rc, cap = rg.run(capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "internal" and rg.tools() == []


# ================================================================================ batas jumlah / ukuran
def test_check_bundle_batas_jumlah_apk(rg, capsys, monkeypatch):
    monkeypatch.setattr(rg.st, "MAX_BUNDLE_APKS", 2)
    rg.package()
    rc, cap = rg.run(capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "bukan_paket" and rg.tools() == []


def test_check_bundle_batas_jumlah_apk_tepat_diterima(rg, capsys, monkeypatch):
    monkeypatch.setattr(rg.st, "MAX_BUNDLE_APKS", 3)
    rg.package()
    rc, _ = rg.run(capsys)
    assert rc == 0


def test_check_bundle_batas_jumlah_entri_total(rg, capsys, monkeypatch):
    monkeypatch.setattr(rg.st, "ZIP_MAX_ENTRIES", 5)
    rg.package()
    rc, cap = rg.run(capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "bukan_paket" and rg.tools() == []


def test_check_bundle_batas_ukuran_per_entri_apk(rg, capsys, monkeypatch):
    big = apk("g", {"assets/b.bin": os.urandom(5000)})
    rg.package({"manifest.json": b"{}", "a.apk": apk("a"), "b.apk": big})
    monkeypatch.setattr(rg.st, "ZIP_MAX_ENTRY_BYTES", len(big) - 1)
    rc, cap = rg.run(capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "bukan_paket" and rg.tools() == []


def test_check_bundle_batas_ukuran_total_apk(rg, capsys, monkeypatch):
    a, b = apk("a", {"x": os.urandom(3000)}), apk("b", {"x": os.urandom(3000)})
    rg.package({"manifest.json": b"{}", "a.apk": a, "b.apk": b})
    monkeypatch.setattr(rg.st, "ZIP_MAX_TOTAL_BYTES", len(a) + len(b) - 1)
    rc, cap = rg.run(capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "bukan_paket" and rg.tools() == []
    monkeypatch.setattr(rg.st, "ZIP_MAX_TOTAL_BYTES", len(a) + len(b))
    rc, _ = rg.run(capsys)
    assert rc == 0


def test_check_bundle_extras_besar_tidak_diekstrak_dan_tidak_dibatasi_total_apk(rg, capsys, monkeypatch):
    a = apk("a")
    rg.package({"manifest.json": b"{}", "a.apk": a, "Android/obb/p/main.obb": os.urandom(20000)})
    monkeypatch.setattr(rg.st, "ZIP_MAX_TOTAL_BYTES", len(a))
    rc, _ = rg.run(capsys)
    assert rc == 0


def test_check_bundle_paket_tanpa_apk_ditolak(rg, capsys):
    rg.package({"manifest.json": b"{}", "icon.png": b"x"})
    rc, cap = rg.run(capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "bukan_paket"


# ================================================================================ paket sumber
def test_check_bundle_sumber_symlink_ditolak(rg, capsys):
    rg.package()
    (rg.dir / "tautan.xapk").symlink_to(rg.name)
    rc, cap = rg.run(capsys, name="tautan.xapk")
    assert rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada" and rg.tools() == []


def test_check_bundle_sumber_nlink_lebih_dari_satu_ditolak(rg, capsys):
    rg.package()
    os.link(rg.dir / rg.name, rg.dir / "lain.xapk")
    rc, cap = rg.run(capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "bukan_paket" and rg.tools() == []


def test_check_bundle_sumber_fifo_tidak_menggantung(rg, capsys):
    os.mkfifo(rg.dir / "fifo.xapk")
    (rc, cap), exc = within_call(10, rg.run, capsys, name="fifo.xapk")
    assert exc is None and rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada"


@pytest.mark.parametrize("kind", ["dir", "empty"])
def test_check_bundle_sumber_direktori_atau_kosong_ditolak(rg, capsys, kind):
    if kind == "dir":
        (rg.dir / "d.xapk").mkdir()
    else:
        (rg.dir / "d.xapk").write_bytes(b"")
    rc, cap = rg.run(capsys, name="d.xapk")
    assert rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada" and rg.tools() == []


def test_check_bundle_bukan_zip_bukan_paket(rg, capsys):
    (rg.dir / "x.xapk").write_bytes(b"bukan zip" * 20)
    rc, cap = rg.run(capsys, name="x.xapk")
    assert rc == 3 and kvs(cap.out)["kode"] == "bukan_paket" and rg.tools() == []


@pytest.mark.parametrize("name", ["app.apk", "app.zip", "app", "app.XAPK.bak"])
def test_check_bundle_ekstensi_bukan_xapk_apks_ditolak(rg, capsys, name):
    rg.package(name=name)
    rc, cap = rg.run(capsys, name=name)
    assert rc == 3 and kvs(cap.out)["kode"] == "bukan_paket" and rg.tools() == []


def test_check_bundle_berkas_tak_ada_dan_folder_tak_ada(rg, capsys):
    rc, cap = rg.run(capsys, name="tidak-ada.xapk")
    assert rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada"
    rc, cap = rg.run(capsys, aid="6")
    assert rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada"


def test_check_bundle_tidak_mengikuti_folder_build_symlink(rg, capsys, tmp_path):
    rg.package()
    other = tmp_path / "lain"
    other.mkdir()
    (other / rg.name).write_bytes((rg.dir / rg.name).read_bytes())
    (rg.builds / "5" / "8").symlink_to(other)
    rc, cap = rg.run(capsys, bid="8")
    assert rc == 3 and kvs(cap.out)["kode"] == "berkas_tidak_ada" and rg.tools() == []


# ================================================================================ kegagalan alat tetap melaporkan
def test_check_bundle_zipalign_gagal_pada_satu_entri(rg, capsys):
    rg.package()
    (rg.fake / "zipalign.rc.e002.apk").write_text("1")
    rc, cap = rg.run(capsys)
    got = kvs(cap.out)
    assert rc == 3 and got["kode"] == "zipalign_gagal" and got["entri.2.zipalign"] == "gagal" and got["entri.1.zipalign"] == "ok"
    assert rg.leftovers() == []


def test_check_bundle_verify_gagal_pada_satu_entri(rg, capsys):
    rg.package()
    (rg.fake / "verify.rc.e003.apk").write_text("1")
    (rg.fake / "verify.e003.apk").write_text("DOES NOT VERIFY\n")
    rc, cap = rg.run(capsys)
    got = kvs(cap.out)
    assert rc == 3 and got["kode"] == "verify_gagal" and got["entri.3.v2"] == "0" and got["entri.3.cert"] == "-" and got["entri.3.signers"] == "-"
    assert rg.leftovers() == []


def test_check_bundle_keluaran_alat_tak_dikenal_bukan_lulus(rg, capsys):
    rg.package()
    (rg.fake / "verify.default").write_text("keluaran tak dikenal\n")
    rc, cap = rg.run(capsys)
    got = kvs(cap.out)
    assert got["entri.1.v2"] == "0" and got["entri.1.v3"] == "0" and got["entri.1.signers"] == "-" and got["entri.1.cert"] == "-"


def test_check_bundle_alat_tak_ada_alat_gagal(rg, capsys, monkeypatch):
    rg.package()
    monkeypatch.setenv("PATH", "/nonexistent")
    rc, cap = rg.run(capsys)
    assert rc == 3 and kvs(cap.out)["kode"] == "alat_gagal" and rg.leftovers() == []


# ================================================================================ penggunaan
def test_check_bundle_butuh_tiga_argumen(st, capsys):
    for args in ([], ["5"], ["5", "9"], ["5", "9", "a.xapk", "extra"]):
        assert st.main(["--check-bundle", *args]) == 64
        assert capsys.readouterr().out == ""


@pytest.mark.parametrize("bad", ["", "0", "-1", "+1", " 1", "1.0", "1000000000", "true", "١٢"])
def test_check_bundle_id_tak_valid_64(rg, capsys, bad):
    for aid, bid in ((bad, "9"), ("5", bad)):
        rc, cap = rg.run(capsys, aid=aid, bid=bid)
        assert rc == 64 and cap.out == "" and cap.err.startswith("GALAT:")
    assert rg.tools() == []


@pytest.mark.parametrize("bad", ["", "../x.xapk", ".t.xapk", "a/b.xapk", "a b.xapk", "a" * 121, "é.xapk", "x.xapk\n"])
def test_check_bundle_nama_harus_lolos_regex_nama_keluaran(rg, capsys, bad):
    rc, cap = rg.run(capsys, name=bad)
    assert rc == 64 and cap.out == "" and rg.tools() == []


def test_check_bundle_tidak_boleh_dipakai_bersama_mode_lain(st, capsys):
    assert st.main(["--check-bundle", "5", "9", "a.xapk", "--watch"]) == 64
    assert st.main(["--leak-scan", "--check-bundle", "5", "9", "a.xapk"]) == 64
    assert st.main(["--check-apk", "5", "9", "a.apk", "--check-bundle", "5", "9", "a.xapk"]) == 64


def test_check_bundle_dispatch_main_melewati_pemeriksaan_kontainer(rg, capsys, monkeypatch):
    rg.package()
    monkeypatch.setattr(rg.st, "DATA_DIR", str(rg.root / "data"))
    rc = rg.st.main(["--check-bundle", "5", "9", rg.name])
    out = capsys.readouterr().out
    assert rc == 0 and "ringkasan" not in out and "format=xapk" in out


def test_check_bundle_tidak_menumpahkan_traceback(rg, capsys, monkeypatch):
    rg.package()
    monkeypatch.setattr(rg.st.zipfile, "ZipFile", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    rc, cap = rg.run(capsys)
    assert rc == 3 and "Traceback" not in cap.out + cap.err and kvs(cap.out)["kode"] in ("internal", "bukan_paket")


def test_check_apk_lama_dan_selftest_27_pemeriksaan_tidak_berubah():
    src = (ROOT / "services/signer/signer-selftest").read_text()
    assert src.count("report(") >= 20 and "def run_check_apk(" in src and "def run_check_bundle(" in src
    assert 'CHECK_KEYS = ("signers", "v2", "v3", "cert", "zipalign", "sha", "size")' in src


def test_batas_selftest_sama_dengan_rvcore_bundle(st):
    from rvcore import bundle
    assert (st.MAX_BUNDLE_APKS, st.ZIP_MAX_ENTRIES, st.ZIP_MAX_ENTRY_BYTES, st.ZIP_MAX_TOTAL_BYTES) == (
        bundle.MAX_BUNDLE_APKS, bundle.ZIP_MAX_ENTRIES, bundle.ZIP_MAX_ENTRY_BYTES, bundle.ZIP_MAX_TOTAL_BYTES)
