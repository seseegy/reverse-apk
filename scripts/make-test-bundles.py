#!/usr/bin/env python3
"""Membuat sampel XAPK dan APKS (set split) untuk `make verify-build` (Tahap 3). Hanya pustaka standar; berjalan di host (python3 apa pun >= 3.8).

    scripts/make-test-bundles.py xapk   [--base testdata/vulnsample.apk] [-o testdata/sample.xapk]  [--no-stale-meta-inf]
    scripts/make-test-bundles.py apks   [--base testdata/vulnsample.apk] [-o testdata/sample.apks]  [--no-stale-meta-inf]
    scripts/make-test-bundles.py splits [--base testdata/vulnsample.apk] [-o testdata/parts]

  xapk    manifest.json (bentuk XAPK v2), icon.png, satu OBB 64 KiB, APK dasar + tiga split (config.arm64_v8a, config.id, fitur feat1).
  apks    toc.pb (penanda), splits/base-master.apk (= APK dasar), splits/base-master_2.apk (byte sama = alias), dua split config.
  splits  berkas lepas untuk uji negatif penanda tangan: base.apk, split-1.apk, split-2.apk (bersih), split-stale.apk (membawa META-INF/OLD.* basi).

Sampel TIDAK ditandatangani dan tidak memuat material kunci apa pun: tanda tangan dibuat oleh signer saat build. "META-INF basi" di split hanyalah byte sampah bernama
BNDLTOOL.SF/.RSA dan MANIFEST.MF (meniru sisa bundletool) plus `META-INF/services/demo` yang HARUS selamat; pipeline wajib membuang sampah itu sebelum menandatangani.
Manifest tiap split adalah AXML biner minimal (package/versionCode sama dengan APK sampel `scripts/sample-apk/build.py`). Keluaran deterministik. Hasil ditulis ke testdata/
(di-ignore git; jangan commit). Stdout: baris `kunci=nilai` ringkasan (dibaca `verify-build.sh`; bash tidak mem-parse JSON).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import struct
import sys
import zipfile
import zlib
from pathlib import Path

PACKAGE = "com.example.vuln"
VERSION_CODE = 1
VERSION_NAME = "1.0-test"
DATE = (1980, 1, 1, 0, 0, 0)
OBB_NAME = "Android/obb/%s/main.1.%s.obb" % (PACKAGE, PACKAGE)

# ------------------------------------------------------------------------------------------------ AXML biner minimal
RES_IDS = {"versionCode": 0x0101021B, "versionName": 0x0101021C, "isFeatureSplit": 0x0101055B, "hasCode": 0x0101000C, "name": 0x01010003, "minSdkVersion": 0x0101020C}
NS_URI = "http://schemas.android.com/apk/res/android"
T_STRING, T_INT_DEC, T_BOOLEAN = 0x03, 0x10, 0x12


def _string_pool(strings):
    blob, offsets = b"", []
    for text in strings:
        raw = text.encode("utf-16-le")
        units = len(raw) // 2
        if units >= 0x8000:
            raise ValueError("string terlalu panjang untuk pool AXML minimal")
        offsets.append(len(blob))
        blob += struct.pack("<H", units) + raw + b"\x00\x00"
    blob += b"\x00" * (-len(blob) % 4)
    start = 28 + 4 * len(strings)
    head = struct.pack("<HHIIIIII", 0x0001, 28, start + len(blob), len(strings), 0, 0, start, 0)
    return head + b"".join(struct.pack("<I", o) for o in offsets) + blob


def axml_manifest(package, version_code, split=None, config_for_split=None, feature=False, uses_split=None, min_sdk=None, version_name=VERSION_NAME):
    """AndroidManifest.xml biner (AXML) untuk APK split. Atribut ber-namespace diurutkan menurut id sumber daya dan string-nya ditaruh PERTAMA di pool (syarat peta
    sumber daya); atribut tanpa namespace (`package`, `split`, `configForSplit`) menyusul. Tanpa `uses-sdk` bila `min_sdk` kosong (meniru split config bundletool)."""
    root = [(True, "versionCode", "int", version_code), (True, "versionName", "str", version_name)]
    if feature:
        root.append((True, "isFeatureSplit", "bool", True))
    root.append((False, "package", "str", package))
    if split:
        root.append((False, "split", "str", split))
    if config_for_split:
        root.append((False, "configForSplit", "str", config_for_split))
    children = []
    if min_sdk:
        children.append(("uses-sdk", [(True, "minSdkVersion", "int", int(min_sdk))], []))
    if uses_split:
        children.append(("uses-split", [(True, "name", "str", uses_split)], []))
    children.append(("application", [(True, "hasCode", "bool", False)], []))
    tree = ("manifest", root, children)

    def walk(node):
        yield node
        for child in node[2]:
            yield from walk(child)

    used_ids = sorted({a[1] for n in walk(tree) for a in n[1] if a[0]}, key=lambda k: RES_IDS[k])
    strings = list(used_ids)

    def idx(text):
        if text not in strings:
            strings.append(text)
        return strings.index(text)

    prefix, uri = idx("android"), idx(NS_URI)
    for n in walk(tree):
        idx(n[0])
        for a in n[1]:
            idx(a[1])
            if a[2] == "str":
                idx(a[3])
    line = [1]

    def attr_bytes(a):
        ns = uri if a[0] else -1
        name = strings.index(a[1])
        if a[2] == "str":
            sidx = strings.index(a[3])
            return struct.pack("<iiiHBBI", ns, name, sidx, 8, 0, T_STRING, sidx)
        if a[2] == "bool":
            return struct.pack("<iiiHBBI", ns, name, -1, 8, 0, T_BOOLEAN, 0xFFFFFFFF if a[3] else 0)
        return struct.pack("<iiiHBBI", ns, name, -1, 8, 0, T_INT_DEC, a[3] & 0xFFFFFFFF)

    def emit(node):
        name, attrs, kids = node
        ordered = sorted([a for a in attrs if a[0]], key=lambda a: RES_IDS[a[1]]) + [a for a in attrs if not a[0]]
        line[0] += 1
        body = b"".join(attr_bytes(a) for a in ordered)
        out = struct.pack("<HHIIi", 0x0102, 16, 36 + len(body), line[0], -1)
        out += struct.pack("<iiHHHHHH", -1, strings.index(name), 20, 20, len(ordered), 0, 0, 0) + body
        for kid in kids:
            out += emit(kid)
        line[0] += 1
        return out + struct.pack("<HHIIiii", 0x0103, 16, 24, line[0], -1, -1, strings.index(name))

    elements = emit(tree)
    pool = _string_pool(strings)
    resmap = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(used_ids)) + b"".join(struct.pack("<I", RES_IDS[k]) for k in used_ids)
    start_ns = struct.pack("<HHIIiII", 0x0100, 16, 24, 1, -1, prefix, uri)
    end_ns = struct.pack("<HHIIiII", 0x0101, 16, 24, line[0] + 1, -1, prefix, uri)
    body = pool + resmap + start_ns + elements + end_ns
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


# ------------------------------------------------------------------------------------------------ pembangun ZIP/APK
def _zip(entries):
    """entries = [(nama, byte)]; semua STORED, tanggal tetap, mode 0644 -> keluaran deterministik."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, data in entries:
            info = zipfile.ZipInfo(name, DATE)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return buf.getvalue()


def _bytes(tag, n):
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(("%s-%d" % (tag, i)).encode()).digest()
        i += 1
    return out[:n]


STALE_META_INF = (
    ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nCreated-By: sampel-uji (bukan tanda tangan sungguhan)\r\n\r\n"),
    ("META-INF/BNDLTOOL.SF", b"Signature-Version: 1.0\r\nCreated-By: sampel-uji\r\nX-Sampel: sampah\r\n\r\n"),
    ("META-INF/BNDLTOOL.RSA", b"SAMPAH-BUKAN-PKCS7" + _bytes("rsa", 200)),
    ("META-INF/services/demo", b"com.example.vuln.Demo\n"),
)
OLD_META_INF = (
    ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nCreated-By: sampel-uji (bukan tanda tangan sungguhan)\r\n\r\n"),
    ("META-INF/OLD.SF", b"Signature-Version: 1.0\r\nCreated-By: sampel-uji\r\n\r\n"),
    ("META-INF/OLD.RSA", b"SAMPAH-BUKAN-PKCS7" + _bytes("old", 120)),
)

# (id split, berkas di XAPK, berkas di APKS, fitur?, isi tambahan)
SPLITS = (
    ("config.arm64_v8a", "config.arm64_v8a.apk", "splits/base-arm64_v8a.apk", False, (("lib/arm64-v8a/libdemo.so", b"\x7fELF" + _bytes("so", 4096)),)),
    ("config.id", "config.id.apk", "splits/base-id.apk", False, (("assets/lang/id.txt", b"bahasa indonesia (sampel)\n"),)),
    ("feat1", "feat1.apk", None, True, (("assets/feat1.txt", b"fitur satu (sampel)\n"),)),
)


def build_split(split_id, feature=False, files=(), meta_inf=()):
    """APK split minimal: manifest biner + isi tambahan (+ META-INF basi bila diminta). Tanpa kode (hasCode=false), tanpa resources.arsc."""
    manifest = axml_manifest(PACKAGE, VERSION_CODE, split=split_id, feature=feature, uses_split="base" if feature else None, min_sdk=24 if feature else None)
    return _zip([("AndroidManifest.xml", manifest)] + list(files) + list(meta_inf))


def _splits(stale):
    return [(sid, xf, af, build_split(sid, feat, files, STALE_META_INF if stale else ())) for sid, xf, af, feat, files in SPLITS]


def _png():
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\x00\x20\x80\xc0", 9)) + chunk(b"IEND", b""))


def build_xapk(base, stale_meta_inf=True):
    splits = _splits(stale_meta_inf)
    apk_total = len(base) + sum(len(s[3]) for s in splits)
    manifest = {
        "xapk_version": 2, "package_name": PACKAGE, "name": "VulnSample", "version_code": str(VERSION_CODE), "version_name": VERSION_NAME,
        "min_sdk_version": "24", "target_sdk_version": "33", "permissions": ["android.permission.INTERNET"], "split_configs": [sid for sid, _, _, feat, _ in SPLITS if not feat],
        "total_size": apk_total, "icon": "icon.png",
        "split_apks": [{"file": PACKAGE + ".apk", "id": "base"}] + [{"file": s[1], "id": s[1][:-4]} for s in splits],
        "expansions": [{"file": OBB_NAME, "install_location": "EXTERNAL_STORAGE", "install_path": OBB_NAME}],
    }
    entries = [("manifest.json", (json.dumps(manifest, indent=2) + "\n").encode()), ("icon.png", _png()), (OBB_NAME, _bytes("obb", 64 * 1024)),
               (PACKAGE + ".apk", base)] + [(s[1], s[3]) for s in splits]
    return _zip(entries)


def build_apks(base, stale_meta_inf=True):
    splits = [s for s in _splits(stale_meta_inf) if s[2] is not None]
    entries = [("toc.pb", b"\x0a\x0dsampel-bundle\n"), ("splits/base-master.apk", base), ("splits/base-master_2.apk", base)] + [(s[2], s[3]) for s in splits]
    return _zip(entries)


def build_parts(base):
    """Berkas lepas untuk uji negatif penanda tangan: dua split bersih dan satu split yang membawa sisa tanda tangan lama (OLD.*)."""
    clean = _splits(False)
    stale = build_split("config.id", False, SPLITS[1][4], OLD_META_INF)
    return {"base.apk": base, "split-1.apk": clean[0][3], "split-2.apk": clean[1][3], "split-stale.apk": stale}


# ------------------------------------------------------------------------------------------------ ringkasan untuk verify-build
def _sha(data):
    return hashlib.sha256(data).hexdigest()


def checks_for(data, fmt):
    """Daftar pemeriksaan isi paket hasil build (dibaca tamu runner `PY_PAKET`): same:<anggota>:<sha256> | manifest:<anggota>:<sha256 kanonik tanpa total_size> |
    alias:<anggota>:<anggota lain> | extras:<nama,...> (semua entri bukan-APK; ditambah tepat satu assets/uniq-*.txt dari --uniq)."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = [i.filename for i in zf.infolist() if not i.is_dir()]
        extras = sorted(n for n in names if not n.endswith(".apk"))
        if fmt == "xapk":
            m = json.loads(zf.read("manifest.json"))
            m.pop("total_size", None)
            canon = _sha(json.dumps(m, sort_keys=True, separators=(",", ":")).encode())
            out = ["same:icon.png:" + _sha(zf.read("icon.png")), "same:%s:%s" % (OBB_NAME, _sha(zf.read(OBB_NAME))), "manifest:manifest.json:" + canon]
        else:
            out = ["same:toc.pb:" + _sha(zf.read("toc.pb")), "alias:splits/base-master_2.apk:splits/base-master.apk"]
    return out + ["extras:" + ",".join(extras)]


def summary_lines(data, fmt, path):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = [i.filename for i in zf.infolist() if not i.is_dir()]
    apks = [n for n in names if n.endswith(".apk")]
    lines = ["format=" + fmt, "arsip=" + str(path), "sha256=" + _sha(data), "ukuran=%d" % len(data), "entri_apk=%d" % len(apks)]
    lines += ["apk.%d=%s" % (n, name) for n, name in enumerate(apks, 1)]
    lines.append("extras_n=%d" % (len(names) - len(apks)))
    lines += ["periksa.%d=%s" % (n, c) for n, c in enumerate(checks_for(data, fmt), 1)]
    return lines


# ------------------------------------------------------------------------------------------------ CLI
def _write(dest, data):
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    part.write_bytes(data)
    os.replace(str(part), str(dest))


def _read_base(path):
    p = Path(path)
    if not p.is_file():
        sys.exit("APK dasar tidak ditemukan: %s (buat sekali: python3 scripts/sample-apk/build.py)" % p)
    data = p.read_bytes()
    if not zipfile.is_zipfile(io.BytesIO(data)):
        sys.exit("APK dasar bukan berkas ZIP/APK yang sah: %s" % p)
    return data


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=("xapk", "apks", "splits"))
    ap.add_argument("--base", default="testdata/vulnsample.apk")
    ap.add_argument("-o", "--output")
    ap.add_argument("--no-stale-meta-inf", dest="stale", action="store_false", help="split bersih tanpa META-INF basi (bawaan: basi, meniru sisa bundletool)")
    a = ap.parse_args(argv)
    base = _read_base(a.base)
    if a.cmd == "splits":
        dest = Path(a.output or "testdata/parts")
        dest.mkdir(parents=True, exist_ok=True)
        for name, data in build_parts(base).items():
            _write(dest / name, data)
            print("%s.sha256=%s" % (name[:-4], _sha(data)))
        return 0
    dest = Path(a.output or "testdata/sample.%s" % a.cmd)
    data = build_xapk(base, a.stale) if a.cmd == "xapk" else build_apks(base, a.stale)
    _write(dest, data)
    print("\n".join(summary_lines(data, a.cmd, dest)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
