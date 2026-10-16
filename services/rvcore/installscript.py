"""Skrip `adb install-multiple` untuk paket XAPK/APKS hasil build (Tahap 3). TEKS shell saja: aplikasi tidak pernah menjalankannya dan tidak memanggil `adb`.

Dijalankan pemilik di PC-nya (sh POSIX + adb + unzip + tr + mktemp; Windows tidak didukung). Fungsi murni dan deterministik: templat LITERAL tetap; satu-satunya
baris yang berubah adalah baris data `BUNDLE=`, `PKG=`, `add '<nama>' '<abi>'`, dan `obb '<nama>' '<paket>'`, tiap nilai dikutip tunggal (`'` -> `'\\''`).
Nama entri tidak pernah menjadi path dan tidak pernah disisipkan tanpa kutip; nama yang mengandung kontrol, `\\`, `*?[]`, atau diawali `-` DITOLAK di sini
(`ValueError`) karena `unzip` memperlakukan argumennya sebagai pola/opsi.

`lint(text)` memakai ALLOWLIST: setiap baris harus sama persis dengan baris templat, cocok salah satu regex data, atau komentar/kosong. Tidak ada daftar larangan.
"""

from __future__ import annotations

import re

FORMATS = ("xapk", "apks")
# Token ABI persis (perbandingan string-sama, BUKAN startswith/endswith): `x86` tidak pernah cocok `x86_64`, `armeabi` tidak cocok `armeabi_v7a`.
ABI_TOKENS = frozenset({"arm64_v8a", "armeabi_v7a", "armeabi", "x86_64", "x86", "mips", "mips64", "riscv64"})
MAX_NAME_BYTES = 255

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_PKG_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*\Z")
_ABI_NAME_RE = re.compile(r"(?:base-|config\.)(.+)\Z")
_Q = r"'[^'\\]*(?:'\\''[^'\\]*)*'"
_DATA_RES = (re.compile(rf"add {_Q} '[a-z0-9_]*'\Z"), re.compile(rf"obb {_Q} {_Q}\Z"), re.compile(rf"BUNDLE={_Q}\Z"), re.compile(rf"PKG={_Q}\Z"))

# Baris templat tetap (urutan = urutan keluaran). `{DATA_*}` hanya penanda posisi dan bukan bagian keluaran.
_HEAD = (
    "#!/bin/sh",
    "# Dibuat otomatis oleh sistem reverse-apk (BUKAN oleh AI). Hanya teks shell: aplikasi tidak menjalankan adb.",
    "# Paket ini ditandatangani ulang dengan kunci PEMILIK. Aplikasi asli yang sudah terpasang HARUS di-'adb uninstall' lebih dulu",
    "# (data aplikasi hilang); skrip ini TIDAK melakukannya.",
    "# Tidak ada jaminan untuk aplikasi dengan anti-tamper, packer, Play Integrity, atau pemeriksaan hash .so.",
    "# Butuh: sh POSIX, adb, unzip, tr, mktemp. Windows tidak didukung. Pasang SEMUA ABI: ALL=1 sh <skrip>.",
    "set -eu",
)
_BODY = (
    'for c in adb unzip tr mktemp dirname basename; do',
    '  command -v "$c" >/dev/null 2>&1 || { echo "Perintah $c tidak ditemukan." >&2; exit 1; }',
    'done',
    'HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)',
    'ZIP="$HERE/$BUNDLE"',
    '[ -f "$ZIP" ] || { echo "Berkas paket tidak ada di samping skrip: $BUNDLE" >&2; exit 1; }',
    'ALL="${ALL:-0}"',
    "ABIS=\",$(adb shell getprop ro.product.cpu.abilist | tr -d '\\r' | tr '-' '_'),\"",
    'TMP=$(mktemp -d)',
    "trap 'rm -rf \"$TMP\"' EXIT",
    'LIST="$TMP/.daftar"',
    ': > "$LIST"',
    'want() {',
    '  [ -z "$1" ] && return 0',
    '  [ "$ALL" = 1 ] && return 0',
    '  [ "$ABIS" = ",," ] && { echo "Daftar ABI perangkat kosong (adb gagal?). Jalankan ulang, atau pakai ALL=1." >&2; exit 1; }',
    '  case "$ABIS" in *",$1,"*) return 0 ;; esac',
    '  return 1',
    '}',
    'add() {',
    '  want "$2" || return 0',
    '  unzip -q -o "$ZIP" "$1" -d "$TMP"',
    '  printf \'%s\\n\' "$TMP/$1" >> "$LIST"',
    '}',
    'install() {',
    '  set --',
    '  while IFS= read -r f; do set -- "$@" "$f"; done < "$LIST"',
    '  [ "$#" -gt 0 ] || { echo "Tidak ada APK yang cocok untuk dipasang." >&2; exit 1; }',
    '  adb install-multiple -r "$@"',
    '}',
    'obb() {',
    '  unzip -q -o "$ZIP" "$1" -d "$TMP"',
    '  adb shell mkdir -p "/sdcard/Android/obb/$2"',
    '  adb push "$TMP/$1" "/sdcard/Android/obb/$2/$(basename "$1")"',
    '  rm -f "$TMP/$1"',
    '}',
)
_INSTALL = ("install",)
_TAIL = ('echo "Selesai."',)
_TEMPLATE_LINES = frozenset(_HEAD + _BODY + _INSTALL + _TAIL)


def quote(value: str) -> str:
    """Kutip tunggal POSIX: `'` -> `'\\''`."""
    return "'" + value.replace("'", "'\\''") + "'"


def check_name(name: object) -> str:
    """Nama entri aman untuk disisipkan dan untuk argumen `unzip`; ValueError bila tidak."""
    if not isinstance(name, str) or not name or len(name.encode("utf-8", "surrogatepass")) > MAX_NAME_BYTES:
        raise ValueError("nama entri tidak valid")
    if _CONTROL_RE.search(name) or "\\" in name or any(c in name for c in "*?[]") or name.startswith("-") or name.startswith("/"):
        raise ValueError("nama entri mengandung karakter yang tidak boleh ada di skrip pasang")
    return name


def abi_of(name: str) -> str:
    """Token ABI split (`config.arm64_v8a.apk`, `splits/base-arm64_v8a.apk`) atau '' (bahasa, kerapatan, fitur, master). Persis sama dengan ABI_TOKENS."""
    stem = name.rsplit("/", 1)[-1]
    if stem.lower().endswith(".apk"):
        stem = stem[:-4]
    m = _ABI_NAME_RE.match(stem)
    token = m.group(1).replace("-", "_") if m else ""
    return token if token in ABI_TOKENS else ""


def render(fmt: str, bundle_name: str, package: str, base: str, splits: list[str] | tuple[str, ...], obb: list[str] | tuple[str, ...] = ()) -> str:
    """Teks skrip. `base` dipasang pertama (tanpa penyaringan ABI), lalu `splits` menurut urutan, lalu (XAPK) tiap `obb` di-push ke /sdcard/Android/obb/<paket>/.
    APKS tidak punya OBB (obb diabaikan bila diberikan = ValueError agar salah-pakai terlihat)."""
    if fmt not in FORMATS:
        raise ValueError("format harus xapk atau apks")
    if fmt == "apks" and obb:
        raise ValueError("APKS tidak membawa OBB")
    check_name(bundle_name)
    check_name(base)
    names = [check_name(n) for n in splits]
    obbs = [check_name(n) for n in obb]
    if obbs and not (isinstance(package, str) and _PKG_RE.match(package)):
        raise ValueError("nama paket tidak valid untuk jalur OBB")
    pkg = package if isinstance(package, str) and _PKG_RE.match(package) else ""
    if len({base, *names}) != len(names) + 1:
        raise ValueError("nama APK ganda")
    lines = [*_HEAD, f"BUNDLE={quote(bundle_name)}", f"PKG={quote(pkg)}", *_BODY, f"add {quote(base)} ''"]
    lines += [f"add {quote(n)} {quote(abi_of(n))}" for n in names]
    lines += list(_INSTALL)
    lines += [f"obb {quote(n)} {quote(pkg)}" for n in obbs]
    lines += list(_TAIL)
    return "\n".join(lines) + "\n"


def lint(text: str) -> list[str]:
    """Pelanggaran allowlist (kosong = bersih). Tiap baris: sama persis dengan baris templat, atau salah satu regex data, atau komentar `#`/kosong."""
    bad: list[str] = []
    if not text.endswith("\n") or "\r" in text:
        bad.append("akhir baris/CR tidak sah")
    for n, line in enumerate(text.split("\n")[:-1] if text.endswith("\n") else text.split("\n"), 1):
        if line == "" or line in _TEMPLATE_LINES or any(r.match(line) for r in _DATA_RES):
            continue
        if line.startswith("#") and (n > 1 or line == "#!/bin/sh"):
            continue
        bad.append(f"baris {n} di luar allowlist")
    return bad


__all__ = ["FORMATS", "ABI_TOKENS", "render", "lint", "abi_of", "quote", "check_name"]
