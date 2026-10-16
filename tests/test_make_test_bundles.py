"""scripts/make-test-bundles.py: pembangkit sampel XAPK/APKS untuk `make verify-build` (Tahap 3, sub-area F).

Hanya pustaka standar; TANPA material kunci (sampel tidak ditandatangani: tanda tangan dibuat signer saat build). Yang dijaga di sini:
  * susunan XAPK (manifest.json v2, ikon, OBB, base + 3 split) dan APKS (toc.pb, base-master, alias `base-master_2` berbyte sama, config split);
  * manifest biner split (AXML) benar: package/versionCode sama dengan base `scripts/sample-apk/build.py`, `split`, `configForSplit`, fitur;
  * META-INF basi (BNDLTOOL.*) hanya di split dan bukan tanda tangan sungguhan, `META-INF/services/demo` ikut (harus selamat);
  * deterministik; tanpa PRIVATE KEY/PKCS12/berkas kunci; diterima ingest/rencana proyek (`plan_from_zip`, `validate_apk`).
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/make-test-bundles.py"
SAMPLE = ROOT / "scripts/sample-apk/build.py"

RES_XML, RES_STRING_POOL, RES_XML_RESOURCE_MAP = 0x0003, 0x0001, 0x0180
RES_START_NS, RES_END_NS, RES_START_EL, RES_END_EL = 0x0100, 0x0101, 0x0102, 0x0103


def load():
    spec = importlib.util.spec_from_file_location("make_test_bundles", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["make_test_bundles"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mtb():
    return load()


def base_apk() -> bytes:
    """APK dasar palsu yang lolos validasi ingest (manifest + dex di akar); isinya tidak dibaca generator."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("classes.dex", b"dex\n035\x00")
    return buf.getvalue()


def names(data: bytes) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return zf.namelist()


def member(data: bytes, name: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return zf.read(name)


# ------------------------------------------------------------------------------ pengurai AXML mini (independen dari generator)
def parse_axml(data: bytes) -> dict:
    """-> {'strings': [...], 'elements': [(nama, {atribut: nilai})], 'resmap': [...]}; atribut ber-namespace diberi awalan `@`."""
    kind, hsize, size = struct.unpack_from("<HHI", data, 0)
    assert (kind, hsize) == (RES_XML, 8) and size == len(data)
    pos, strings, resmap, elements = 8, [], [], []
    while pos < len(data):
        ctype, chsize, csize = struct.unpack_from("<HHI", data, pos)
        assert csize % 4 == 0 and csize >= chsize
        if ctype == RES_STRING_POOL:
            count, styles, flags, sstart, _ = struct.unpack_from("<IIIII", data, pos + 8)
            assert styles == 0 and flags & 0x100 == 0                       # UTF-16
            offs = struct.unpack_from(f"<{count}I", data, pos + chsize)
            for off in offs:
                at = pos + sstart + off
                (n,) = struct.unpack_from("<H", data, at)
                strings.append(data[at + 2:at + 2 + 2 * n].decode("utf-16-le"))
        elif ctype == RES_XML_RESOURCE_MAP:
            resmap = list(struct.unpack_from(f"<{(csize - chsize) // 4}I", data, pos + chsize))
        elif ctype == RES_START_EL:
            ns, name, astart, asize, acount = struct.unpack_from("<iiHHH", data, pos + 16)
            assert (astart, asize) == (20, 20)
            attrs = {}
            for i in range(acount):
                ans, aname, raw, vsize, _, vtype, vdata = struct.unpack_from("<iiiHBBI", data, pos + 16 + astart + i * 20)
                assert vsize == 8
                key = ("@" if ans >= 0 else "") + strings[aname]
                attrs[key] = strings[raw] if raw >= 0 else (vdata if vtype != 0x12 else bool(vdata))
            elements.append((strings[name], attrs))
        pos += csize
    assert pos == len(data)
    return {"strings": strings, "elements": elements, "resmap": resmap}


def sample_constants() -> tuple[str, int]:
    text = SAMPLE.read_text()
    pkg = re.search(r'package="([a-z0-9_.]+)"', text).group(1)
    vc = int(re.search(r"versionCode: (\d+)", text).group(1))
    return pkg, vc


# ================================================================================ konstanta dan AXML
def test_package_dan_versioncode_sama_dengan_sample_apk(mtb):
    pkg, vc = sample_constants()
    assert mtb.PACKAGE == pkg and mtb.VERSION_CODE == vc


def test_axml_diurai_pengurai_mini_package_split_versioncode(mtb):
    pkg, vc = sample_constants()
    parsed = parse_axml(mtb.axml_manifest(pkg, vc, split="config.arm64_v8a"))
    (name, attrs), (app, app_attrs) = parsed["elements"][0], parsed["elements"][1]
    assert name == "manifest" and app == "application"
    assert attrs["package"] == pkg and attrs["split"] == "config.arm64_v8a" and attrs["@versionCode"] == vc
    assert "configForSplit" not in attrs and "@isFeatureSplit" not in attrs
    assert app_attrs == {"@hasCode": False}


def test_axml_config_for_split_fitur_dan_uses_split_dan_uses_sdk(mtb):
    parsed = parse_axml(mtb.axml_manifest("com.example.vuln", 1, split="feat1", feature=True, uses_split="base", min_sdk=24))
    els = {n: a for n, a in parsed["elements"]}
    assert els["manifest"]["@isFeatureSplit"] is True and els["manifest"]["split"] == "feat1"
    assert els["uses-split"] == {"@name": "base"}
    assert els["uses-sdk"] == {"@minSdkVersion": 24}
    parsed2 = parse_axml(mtb.axml_manifest("com.example.vuln", 1, split="config.x", config_for_split="feat1"))
    assert parsed2["elements"][0][1]["configForSplit"] == "feat1"


def test_axml_peta_sumber_daya_selaras_dengan_string_awal(mtb):
    parsed = parse_axml(mtb.axml_manifest("com.example.vuln", 1, split="feat1", feature=True, uses_split="base", min_sdk=24))
    ids = {"versionCode": 0x0101021B, "versionName": 0x0101021C, "isFeatureSplit": 0x0101055B, "hasCode": 0x0101000C, "name": 0x01010003, "minSdkVersion": 0x0101020C}
    for idx, rid in enumerate(parsed["resmap"]):
        assert ids[parsed["strings"][idx]] == rid          # string ke-i pada peta = atribut ber-id (aapt2/Android mensyaratkan urutan ini)


def test_axml_deterministik(mtb):
    a = mtb.axml_manifest("com.example.vuln", 1, split="s")
    assert a == mtb.axml_manifest("com.example.vuln", 1, split="s")


# ================================================================================ XAPK
def test_xapk_susunan_dan_manifest_v2(mtb):
    base = base_apk()
    data = mtb.build_xapk(base)
    got = names(data)
    assert got == ["manifest.json", "icon.png", "Android/obb/com.example.vuln/main.1.com.example.vuln.obb", "com.example.vuln.apk",
                   "config.arm64_v8a.apk", "config.id.apk", "feat1.apk"]
    assert member(data, "com.example.vuln.apk") == base
    m = json.loads(member(data, "manifest.json"))
    assert m["xapk_version"] == 2 and m["package_name"] == "com.example.vuln" and m["icon"] == "icon.png"
    assert m["split_apks"] == [{"file": "com.example.vuln.apk", "id": "base"}, {"file": "config.arm64_v8a.apk", "id": "config.arm64_v8a"},
                               {"file": "config.id.apk", "id": "config.id"}, {"file": "feat1.apk", "id": "feat1"}]
    assert m["split_configs"] == ["config.arm64_v8a", "config.id"]
    assert m["expansions"][0]["file"] == "Android/obb/com.example.vuln/main.1.com.example.vuln.obb"
    # total_size = jumlah ukuran APK di paket: syarat agar worker boleh memperbaruinya (desain: hanya bila angka asli sama dengan jumlah ukuran asal)
    sizes = sum(len(member(data, n)) for n in got if n.endswith(".apk"))
    assert m["total_size"] == sizes


def test_xapk_obb_64kib_dan_ikon_png_valid(mtb):
    data = mtb.build_xapk(base_apk())
    obb = member(data, "Android/obb/com.example.vuln/main.1.com.example.vuln.obb")
    assert len(obb) == 64 * 1024 and len(set(obb)) > 16          # deterministik tetapi bukan nol berulang
    icon = member(data, "icon.png")
    assert icon[:8] == b"\x89PNG\r\n\x1a\n" and icon[12:16] == b"IHDR"


def test_xapk_split_memuat_manifest_biner_yang_cocok(mtb):
    pkg, vc = sample_constants()
    data = mtb.build_xapk(base_apk())
    for fname, split, cfg, feature in (("config.arm64_v8a.apk", "config.arm64_v8a", None, False), ("config.id.apk", "config.id", None, False),
                                       ("feat1.apk", "feat1", None, True)):
        inner = member(data, fname)
        attrs = parse_axml(member(inner, "AndroidManifest.xml"))["elements"][0][1]
        assert attrs["package"] == pkg and attrs["@versionCode"] == vc and attrs["split"] == split
        assert attrs.get("configForSplit") == cfg and attrs.get("@isFeatureSplit", False) is feature


def test_config_split_tanpa_uses_sdk_dan_fitur_dengan_uses_sdk(mtb):
    data = mtb.build_xapk(base_apk())
    cfg = parse_axml(member(member(data, "config.id.apk"), "AndroidManifest.xml"))["elements"]
    feat = parse_axml(member(member(data, "feat1.apk"), "AndroidManifest.xml"))["elements"]
    assert "uses-sdk" not in [n for n, _ in cfg]              # meniru bundletool (apksigner lalu membuat v1 juga)
    assert "uses-sdk" in [n for n, _ in feat] and "uses-split" in [n for n, _ in feat]


def test_split_arm64_memuat_lib_so_stored(mtb):
    inner = member(mtb.build_xapk(base_apk()), "config.arm64_v8a.apk")
    with zipfile.ZipFile(io.BytesIO(inner)) as zf:
        info = zf.getinfo("lib/arm64-v8a/libdemo.so")
        assert info.compress_type == zipfile.ZIP_STORED and info.file_size > 0


# ================================================================================ APKS
def test_apks_susunan_alias_identik(mtb):
    base = base_apk()
    data = mtb.build_apks(base)
    assert names(data) == ["toc.pb", "splits/base-master.apk", "splits/base-master_2.apk", "splits/base-arm64_v8a.apk", "splits/base-id.apk"]
    assert member(data, "splits/base-master.apk") == base
    assert member(data, "splits/base-master_2.apk") == base          # alias: byte sama dengan base
    pkg, vc = sample_constants()
    for fname, split in (("splits/base-arm64_v8a.apk", "config.arm64_v8a"), ("splits/base-id.apk", "config.id")):
        attrs = parse_axml(member(member(data, fname), "AndroidManifest.xml"))["elements"][0][1]
        assert attrs["package"] == pkg and attrs["@versionCode"] == vc and attrs["split"] == split
    assert member(data, "toc.pb")                                    # penanda tidak kosong


# ================================================================================ META-INF basi
def test_stale_meta_inf_ada_di_split_bukan_di_base_dan_services_selamat(mtb):
    base = base_apk()
    for data, splits in ((mtb.build_xapk(base), ["config.arm64_v8a.apk", "config.id.apk", "feat1.apk"]),
                         (mtb.build_apks(base), ["splits/base-arm64_v8a.apk", "splits/base-id.apk"])):
        for s in splits:
            inner = names(member(data, s))
            assert {"META-INF/BNDLTOOL.SF", "META-INF/BNDLTOOL.RSA", "META-INF/MANIFEST.MF"} <= set(inner), s
            assert "META-INF/services/demo" in inner, s
    xa = mtb.build_xapk(base)
    assert member(xa, "com.example.vuln.apk") == base and not any(n.startswith("META-INF/") for n in names(member(xa, "com.example.vuln.apk")))


def test_tanpa_stale_meta_inf_split_bersih(mtb):
    data = mtb.build_xapk(base_apk(), stale_meta_inf=False)
    for s in ("config.arm64_v8a.apk", "config.id.apk", "feat1.apk"):
        assert not any(n.startswith("META-INF/") for n in names(member(data, s)))


def test_isi_meta_inf_basi_bukan_tanda_tangan_sungguhan(mtb):
    inner = member(mtb.build_xapk(base_apk()), "config.id.apk")
    for n in ("META-INF/BNDLTOOL.SF", "META-INF/BNDLTOOL.RSA", "META-INF/MANIFEST.MF"):
        blob = member(inner, n)
        assert blob and blob[:1] != b"\x30", n                       # bukan struktur DER (PKCS#7) — tidak ada kunci/sertifikat
        assert b"BEGIN" not in blob and b"PRIVATE" not in blob


# ================================================================================ deterministik dan CLI
def test_deterministik(mtb):
    base = base_apk()
    assert mtb.build_xapk(base) == mtb.build_xapk(base)
    assert mtb.build_apks(base) == mtb.build_apks(base)
    assert hashlib.sha256(mtb.build_xapk(base)).hexdigest() != hashlib.sha256(mtb.build_apks(base)).hexdigest()


def test_cli_xapk_apks_dan_splits(tmp_path):
    base = tmp_path / "base.apk"
    base.write_bytes(base_apk())
    x, a, d = tmp_path / "s.xapk", tmp_path / "s.apks", tmp_path / "parts"
    for args in (["xapk", "--base", str(base), "-o", str(x)], ["apks", "--base", str(base), "-o", str(a)], ["splits", "--base", str(base), "-o", str(d)]):
        res = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, timeout=60)
        assert res.returncode == 0, res.stderr
    assert zipfile.is_zipfile(x) and zipfile.is_zipfile(a)
    assert sorted(p.name for p in d.iterdir()) == ["base.apk", "split-1.apk", "split-2.apk", "split-stale.apk"]
    assert (d / "base.apk").read_bytes() == base.read_bytes()
    assert not any(n.startswith("META-INF/") for n in names((d / "split-1.apk").read_bytes()))      # split-1/2 bersih
    assert "META-INF/OLD.RSA" in names((d / "split-stale.apk").read_bytes())                        # satu split bertanda tangan lama
    assert (d / "split-1.apk").read_bytes() != (d / "split-2.apk").read_bytes()


def test_cli_tanpa_base_gagal_dengan_pesan_jelas(tmp_path):
    res = subprocess.run([sys.executable, str(SCRIPT), "xapk", "--base", str(tmp_path / "tidak-ada.apk"), "-o", str(tmp_path / "x.xapk")], capture_output=True, text=True,
                         timeout=60)
    assert res.returncode != 0 and "tidak ditemukan" in (res.stderr + res.stdout)
    assert not (tmp_path / "x.xapk").exists()


def test_cli_menolak_base_bukan_zip(tmp_path):
    bad = tmp_path / "b.apk"
    bad.write_bytes(b"bukan zip")
    res = subprocess.run([sys.executable, str(SCRIPT), "apks", "--base", str(bad), "-o", str(tmp_path / "x.apks")], capture_output=True, text=True, timeout=60)
    assert res.returncode != 0 and not (tmp_path / "x.apks").exists()


# ================================================================================ ringkasan untuk verify-build (kunci=nilai)
def test_checks_for_xapk_dan_apks(mtb):
    base = base_apk()
    xa = mtb.checks_for(mtb.build_xapk(base), "xapk")
    obb = "Android/obb/com.example.vuln/main.1.com.example.vuln.obb"
    data = mtb.build_xapk(base)
    assert f"same:icon.png:{hashlib.sha256(member(data, 'icon.png')).hexdigest()}" in xa
    assert f"same:{obb}:{hashlib.sha256(member(data, obb)).hexdigest()}" in xa
    assert f"extras:icon.png,manifest.json,{obb}" in xa or any(c.startswith("extras:") and set(c[7:].split(",")) == {"icon.png", "manifest.json", obb} for c in xa)
    m = json.loads(member(data, "manifest.json"))
    m.pop("total_size")
    canon = hashlib.sha256(json.dumps(m, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert f"manifest:manifest.json:{canon}" in xa
    aps = mtb.checks_for(mtb.build_apks(base), "apks")
    assert "alias:splits/base-master_2.apk:splits/base-master.apk" in aps
    assert any(c.startswith("same:toc.pb:") for c in aps) and "extras:toc.pb" in aps


def test_cli_mencetak_ringkasan_kunci_nilai(tmp_path):
    base = tmp_path / "base.apk"
    base.write_bytes(base_apk())
    out = tmp_path / "s.xapk"
    res = subprocess.run([sys.executable, str(SCRIPT), "xapk", "--base", str(base), "-o", str(out)], capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    kv = [ln.split("=", 1) for ln in res.stdout.splitlines() if "=" in ln]
    d = {k: v for k, v in kv}
    assert d["format"] == "xapk" and int(d["entri_apk"]) == 4 and int(d["extras_n"]) == 3
    assert [v for k, v in kv if re.fullmatch(r"apk\.\d+", k)] == ["com.example.vuln.apk", "config.arm64_v8a.apk", "config.id.apk", "feat1.apk"]
    assert d["sha256"] == hashlib.sha256(out.read_bytes()).hexdigest()
    assert [v for k, v in kv if re.fullmatch(r"periksa\.\d+", k)] == mtb_checks(out)
    parts = tmp_path / "parts"
    res = subprocess.run([sys.executable, str(SCRIPT), "splits", "--base", str(base), "-o", str(parts)], capture_output=True, text=True, timeout=60)
    d2 = dict(ln.split("=", 1) for ln in res.stdout.splitlines() if "=" in ln)
    for n in ("base", "split-1", "split-2", "split-stale"):
        assert d2[f"{n}.sha256"] == hashlib.sha256((parts / f"{n}.apk").read_bytes()).hexdigest()


def mtb_checks(path: Path) -> list[str]:
    return load().checks_for(path.read_bytes(), "xapk")


# ================================================================================ tanpa material kunci
KEY_MARKERS = (b"PRIVATE KEY", b"BEGIN CERTIFICATE", b"BEGIN RSA", b"BEGIN EC", b"keytool", b"jarsigner")


def test_tanpa_material_kunci_di_keluaran_maupun_sumber(mtb):
    base = base_apk()
    outputs = [mtb.build_xapk(base), mtb.build_apks(base), mtb.build_xapk(base, stale_meta_inf=False)]

    def walk(data: bytes):
        yield data
        if zipfile.is_zipfile(io.BytesIO(data)):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for n in zf.namelist():
                    assert not re.search(r"\.(p12|pfx|jks|keystore|pem|key)$", n, re.I), n
                    yield from walk(zf.read(n))

    for out in outputs:
        for blob in walk(out):
            for marker in KEY_MARKERS:
                assert marker not in blob, marker
    src = SCRIPT.read_bytes()
    for marker in KEY_MARKERS:
        assert marker not in src, marker
    assert b"PKCS12" not in src and b"KeyStore" not in src


def test_repo_tidak_melacak_berkas_kunci():
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("bukan checkout git")
    files = subprocess.run(["git", "ls-files"], capture_output=True, text=True, cwd=ROOT, check=True).stdout.splitlines()
    bad = [f for f in files if re.search(r"\.(p12|pfx|jks|keystore|pem)$", f, re.I)]
    assert bad == []


def test_gitignore_menutup_keluaran_sampel():
    ignore = (ROOT / ".gitignore").read_text().split()
    for pat in ("testdata/", "*.apk", "*.xapk", "*.apks", "secrets/"):
        assert pat in ignore, pat


def test_skrip_tidak_menulis_di_luar_keluaran_yang_diminta():
    code = SCRIPT.read_text()
    assert "secrets" not in code and "keystore" not in code.lower()
    assert "subprocess" not in code and "socket" not in code      # murni stdlib tanpa proses/jaringan


# ================================================================================ diterima ingest proyek
def test_xapk_dan_apks_diterima_rencana_split_set(mtb):
    from rvcore.bundle import plan_from_zip
    base = base_apk()
    xa = zipfile.ZipFile(io.BytesIO(mtb.build_xapk(base)))
    plan = plan_from_zip(xa)
    assert plan.format == "xapk" and plan.base == "com.example.vuln.apk"
    assert plan.apk_order == ("config.arm64_v8a.apk", "config.id.apk", "feat1.apk")
    assert "Android/obb/com.example.vuln/main.1.com.example.vuln.obb" in plan.extras and "manifest.json" in plan.extras
    aps = zipfile.ZipFile(io.BytesIO(mtb.build_apks(base)))
    plan = plan_from_zip(aps)
    assert plan.format == "apks" and plan.base == "splits/base-master.apk"
    assert plan.alias_candidates == ("splits/base-master_2.apk",)
    assert plan.apk_order == ("splits/base-master_2.apk", "splits/base-arm64_v8a.apk", "splits/base-id.apk")


def test_satu_entri_uniq_tambahan_tetap_diterima(mtb):
    """`analyze - --uniq` menambah assets/uniq-*.txt ke paket; rencana tetap sah dan entri itu menjadi extras."""
    from rvcore.bundle import plan_from_zip
    for build in (mtb.build_xapk, mtb.build_apks):
        buf = io.BytesIO(build(base_apk()))
        with zipfile.ZipFile(buf, "a") as zf:
            zf.writestr("assets/uniq-abc123.txt", b"reverse-apk verify-build\n")
        plan = plan_from_zip(zipfile.ZipFile(io.BytesIO(buf.getvalue())))
        assert "assets/uniq-abc123.txt" in plan.extras


def test_validate_apk_mengenali_paket(mtb, tmp_path):
    from app.apkcheck import Limits, validate_apk
    limits = Limits(max_entries=100_000, max_total_uncompressed=3 << 30, max_entry_uncompressed=512 << 20, max_ratio=100)
    for name, data in (("s.xapk", mtb.build_xapk(base_apk())), ("s.apks", mtb.build_apks(base_apk()))):
        p = tmp_path / name
        p.write_bytes(data)
        info = validate_apk(p, limits)
        assert info.bundle is not None


# ================================================================================ alat nyata (hanya bila tersedia; bukan CI)
def _aapt2() -> str | None:
    return os.environ.get("AAPT2") or shutil.which("aapt2")


@pytest.mark.skipif(_aapt2() is None, reason="aapt2 tidak tersedia (set AAPT2=/jalur/aapt2)")
def test_real_aapt2_dump_xmltree(mtb, tmp_path):
    data = mtb.build_xapk(base_apk())
    for fname, split in (("config.arm64_v8a.apk", "config.arm64_v8a"), ("feat1.apk", "feat1")):
        p = tmp_path / fname
        p.write_bytes(member(data, fname))
        out = subprocess.run([_aapt2(), "dump", "xmltree", "--file", "AndroidManifest.xml", str(p)], capture_output=True, text=True, timeout=60)
        assert out.returncode == 0, out.stderr
        assert 'package="com.example.vuln"' in out.stdout and f'split="{split}"' in out.stdout
        assert "versionCode(0x0101021b)=1" in out.stdout
    assert "isFeatureSplit(0x0101055b)=true" in subprocess.run([_aapt2(), "dump", "xmltree", "--file", "AndroidManifest.xml", str(tmp_path / "feat1.apk")],
                                                              capture_output=True, text=True).stdout
