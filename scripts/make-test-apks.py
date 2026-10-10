#!/usr/bin/env python3
"""Membuat berkas uji untuk pipeline upload/dekompilasi (roadmap: "Set APK uji"). Hanya pustaka standar.

    scripts/make-test-apks.py bomb  [-o testdata/bomb.apk]
    scripts/make-test-apks.py large BASE.apk [--mb 90] [-o testdata/large.apk]
    scripts/make-test-apks.py junk  [-o testdata/junk.apk]

  bomb   zip bomb sintetis: kecil di disk, ~300 MB saat diekstrak (rasio > 1000:1). Harus DITOLAK saat upload.
  large  APK asli + aset acak tak-terkompresi hingga >= --mb MB. Untuk uji performa & batas sumber daya.
         (Tanda tangan APK menjadi tidak valid; tidak masalah untuk analisis statis.)
  junk   struktur APK valid (manifest + dex) berisi sampah. Lolos validasi upload tetapi apktool/jadx gagal:
         menguji penanganan job gagal.

Hasil ditulis ke testdata/ (di-ignore git; jangan commit APK).
"""

from __future__ import annotations

import argparse
import os
import sys
import zipfile
from pathlib import Path

MIB = 1024 * 1024


def out_path(arg: str | None, default: str) -> Path:
    p = Path(arg or default)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def make_bomb(dest: Path, expand_mb: int = 300) -> None:
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"\x00manifest")
        z.writestr("classes.dex", b"dex\n035\x00")
        chunk = b"\0" * MIB
        with z.open("assets/zeros.bin", "w", force_zip64=True) as fh:
            for _ in range(expand_mb):
                fh.write(chunk)


def make_large(base: Path, dest: Path, target_mb: int) -> None:
    if not base.is_file():
        sys.exit(f"APK dasar tidak ditemukan: {base}")
    with zipfile.ZipFile(base) as src, zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for info in src.infolist():
            z.writestr(info, src.read(info.filename))
        # Acak = tak terkompresi, sehingga rasio kompresi tetap ~1:1 (bukan zip bomb).
        with z.open(zipfile.ZipInfo("assets/padding.bin"), "w", force_zip64=True) as fh:
            for _ in range(max(1, target_mb - base.stat().st_size // MIB)):
                fh.write(os.urandom(MIB))


def make_junk(dest: Path) -> None:
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"\x00garbage" * 50)
        z.writestr("classes.dex", b"dex\n035\x00" + b"\xff" * 200)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bomb")
    b.add_argument("-o", "--output")
    lg = sub.add_parser("large")
    lg.add_argument("base")
    lg.add_argument("--mb", type=int, default=90)
    lg.add_argument("-o", "--output")
    j = sub.add_parser("junk")
    j.add_argument("-o", "--output")
    a = ap.parse_args()

    if a.cmd == "bomb":
        dest = out_path(a.output, "testdata/bomb.apk")
        make_bomb(dest)
    elif a.cmd == "large":
        dest = out_path(a.output, "testdata/large.apk")
        make_large(Path(a.base), dest, a.mb)
    else:
        dest = out_path(a.output, "testdata/junk.apk")
        make_junk(dest)
    print(f"{dest}  ({dest.stat().st_size / MIB:.2f} MiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
