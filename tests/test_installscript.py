"""Skrip `adb install-multiple` (Tahap 3, sub-area D): templat literal, kutip aman, penyaringan ABI persis, ekstraksi selektif, lint allowlist.

`adb` dan `unzip` PALSU di PATH mencatat argv persis; skrip dijalankan dengan `sh` nyata. Nama berbahaya tidak pernah dieksekusi.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from rvcore import installscript as S

BASE = "com.example.app.apk"
SPLITS = ["config.arm64_v8a.apk", "config.x86.apk", "config.x86_64.apk", "config.armeabi_v7a.apk", "config.id.apk", "feat1.apk"]

FAKE_ADB = """#!/bin/sh
printf 'adb' >> "$FAKE_LOG"; for a in "$@"; do printf '\\t%s' "$a" >> "$FAKE_LOG"; done; printf '\\n' >> "$FAKE_LOG"
if [ "$1" = shell ] && [ "$2" = getprop ]; then printf '%s\\r\\n' "${FAKE_ABIS:-}"; fi
exit 0
"""
FAKE_UNZIP = """#!/bin/sh
printf 'unzip' >> "$FAKE_LOG"; for a in "$@"; do printf '\\t%s' "$a" >> "$FAKE_LOG"; done; printf '\\n' >> "$FAKE_LOG"
zip="$3"; member="$4"; dir="$6"
mkdir -p "$dir/$(dirname "$member")"; printf 'x' > "$dir/$member"
"""


def script(**kw):
    args = dict(fmt="xapk", bundle_name="com.example.app-modified-7.xapk", package="com.example.app", base=BASE, splits=SPLITS, obb=["Android/obb/com.example.app/main.1.com.example.app.obb"])
    args.update(kw)
    return S.render(args["fmt"], args["bundle_name"], args["package"], args["base"], args["splits"], args["obb"])


@pytest.fixture
def sh(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("adb", FAKE_ADB), ("unzip", FAKE_UNZIP)):
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    work = tmp_path / "work"
    work.mkdir()
    (work / "com.example.app-modified-7.xapk").write_bytes(b"PK")
    log = tmp_path / "log.txt"
    log.write_text("")

    def run(text: str, abis: str = "arm64-v8a,armeabi-v7a,armeabi", env: dict | None = None, name: str = "pasang.sh"):
        (work / name).write_text(text)
        e = {"PATH": f"{bindir}:/usr/bin:/bin", "FAKE_LOG": str(log), "FAKE_ABIS": abis, "HOME": str(tmp_path)}
        e.update(env or {})
        p = subprocess.run(["sh", str(work / name)], env=e, capture_output=True, text=True, timeout=30, cwd=tmp_path)
        lines = [ln.split("\t") for ln in log.read_text().splitlines()]
        log.write_text("")
        return p, lines

    return run


def test_deterministik_dan_lint_bersih():
    assert script() == script()
    assert S.lint(script()) == []
    assert S.lint(script(fmt="apks", obb=[], base="splits/base-master.apk", splits=["splits/base-id.apk"])) == []


def test_sh_n_lolos(tmp_path):
    p = tmp_path / "s.sh"
    p.write_text(script())
    assert subprocess.run(["sh", "-n", str(p)], capture_output=True).returncode == 0


def test_komentar_jujur_ada():
    t = script()
    assert "BUKAN oleh AI" in t and "adb uninstall" in t and "Windows tidak didukung" in t and "anti-tamper" in t and "Play Integrity" in t
    assert t.startswith("#!/bin/sh\n") and "set -eu" in t


def test_tidak_ada_uninstall_dan_rm_selain_tmp():
    t = script()
    for ln in t.splitlines():
        if ln.startswith("#"):
            continue
        assert "uninstall" not in ln
        if "rm " in ln:
            assert '"$TMP' in ln, ln


def test_abi_token_persis():
    assert S.abi_of("config.x86.apk") == "x86" and S.abi_of("config.x86_64.apk") == "x86_64"
    assert S.abi_of("splits/base-arm64_v8a.apk") == "arm64_v8a" and S.abi_of("splits/base-arm64-v8a.apk") == "arm64_v8a"
    for plain in ("config.id.apk", "config.xxhdpi.apk", "feat1.apk", "splits/base-master.apk", "config.x86foo.apk", "config.arm64_v8a_extra.apk", "base-en.apk"):
        assert S.abi_of(plain) == "", plain
    assert "add 'config.x86.apk' 'x86'" in script() and "add 'config.id.apk' ''" in script()


def test_apks_hanya_base_dan_splits_tanpa_standalones_alias():
    t = script(fmt="apks", obb=[], base="splits/base-master.apk", splits=["splits/base-id.apk", "asset-slices/a.apk"])
    adds = [ln for ln in t.splitlines() if ln.startswith("add ")]
    assert adds == ["add 'splits/base-master.apk' ''", "add 'splits/base-id.apk' ''", "add 'asset-slices/a.apk' ''"]
    assert "obb " not in "\n".join(ln for ln in t.splitlines() if ln.startswith("obb"))


def test_apks_dengan_obb_ditolak_dan_nama_ganda_ditolak():
    with pytest.raises(ValueError):
        script(fmt="apks", obb=["x.obb"])
    with pytest.raises(ValueError):
        script(splits=[BASE])


def test_install_multiple_hanya_abi_perangkat(sh):
    p, calls = sh(script())
    assert p.returncode == 0, p.stderr
    inst = [c for c in calls if c[:3] == ["adb", "install-multiple", "-r"]]
    assert len(inst) == 1
    files = [os.path.basename(f) for f in inst[0][3:]]
    assert files == [BASE, "config.arm64_v8a.apk", "config.armeabi_v7a.apk", "config.id.apk", "feat1.apk"], "x86/x86_64 tidak dipasang; base dulu"


def test_x86_tidak_cocok_x86_64_dan_sebaliknya(sh):
    p, calls = sh(script(), abis="x86_64")
    files = [os.path.basename(f) for c in calls if c[:2] == ["adb", "install-multiple"] for f in c[3:]]
    assert "config.x86_64.apk" in files and "config.x86.apk" not in files
    p, calls = sh(script(), abis="x86")
    files = [os.path.basename(f) for c in calls if c[:2] == ["adb", "install-multiple"] for f in c[3:]]
    assert "config.x86.apk" in files and "config.x86_64.apk" not in files


def test_armeabi_tidak_cocok_armeabi_v7a(sh):
    p, calls = sh(script(splits=["config.armeabi.apk", "config.armeabi_v7a.apk"]), abis="armeabi-v7a")
    files = [os.path.basename(f) for c in calls if c[:2] == ["adb", "install-multiple"] for f in c[3:]]
    assert files == [BASE, "config.armeabi_v7a.apk"]


def test_all_1_memasang_semua(sh):
    p, calls = sh(script(), env={"ALL": "1"}, abis="")
    files = [os.path.basename(f) for c in calls if c[:2] == ["adb", "install-multiple"] for f in c[3:]]
    assert files == [BASE, *SPLITS]


def test_abilist_kosong_keluar_kecuali_all(sh):
    p, calls = sh(script(), abis="")
    assert p.returncode != 0 and "ABI" in p.stderr and not [c for c in calls if c[:2] == ["adb", "install-multiple"]]
    p, calls = sh(script(splits=["config.id.apk"]), abis="")
    assert p.returncode == 0, "tanpa split ABI, daftar ABI kosong tidak mengganggu"


def test_ekstraksi_selektif_per_anggota_literal(sh):
    p, calls = sh(script())
    un = [c for c in calls if c[0] == "unzip"]
    members = [c[4] for c in un]
    assert un and all(c[1:3] == ["-q", "-o"] and c[5] == "-d" and len(c) == 7 for c in un), "satu anggota per panggilan, bukan seluruh arsip"
    assert "config.x86.apk" not in members and BASE in members and "Android/obb/com.example.app/main.1.com.example.app.obb" in members


def test_obb_mkdir_push_dan_dihapus_dari_tmp(sh):
    p, calls = sh(script())
    kinds = [c[1:3] for c in calls if c[0] == "adb"]
    assert ["shell", "mkdir"] in kinds and ["push", [x for x in calls if x[:2] == ["adb", "push"]][0][2]] in kinds
    push = [c for c in calls if c[:2] == ["adb", "push"]][0]
    assert push[3] == "/sdcard/Android/obb/com.example.app/main.1.com.example.app.obb"
    order = [c[1] for c in calls if c[0] == "adb"]
    assert order.index("install-multiple") < order.index("push"), "pasang dulu, lalu OBB"


@pytest.mark.parametrize("nama", ["a b.apk", "a;b.apk", "a$(touch PWNED).apk", "a`touch PWNED`.apk", "a'b.apk", "a\"b.apk", "a&b.apk", "a|b.apk", "é.apk", "a>b.apk"])
def test_kutip_nama_berbahaya(sh, tmp_path, nama):
    t = script(splits=[nama], obb=[])
    assert S.lint(t) == []
    p, calls = sh(t, abis="x")
    assert p.returncode == 0, p.stderr
    assert not (tmp_path / "PWNED").exists() and not (tmp_path / "work" / "PWNED").exists()
    un = [c for c in calls if c[0] == "unzip"]
    assert [c[4] for c in un] == [BASE, nama], "nama sampai ke unzip utuh sebagai satu argumen"
    inst = [c for c in calls if c[:2] == ["adb", "install-multiple"]][0]
    assert os.path.basename(inst[-1]) == os.path.basename(nama)


@pytest.mark.parametrize("nama", ["a\nb.apk", "a\x00b.apk", "a\\b.apk", "a*.apk", "a?.apk", "a[1].apk", "-opsi.apk", "/mutlak.apk", "", "x" * 300 + ".apk"])
def test_nama_tak_aman_ditolak(nama):
    with pytest.raises(ValueError):
        script(splits=[nama])


def test_nama_glob_tak_pernah_sampai_ke_unzip():
    for bad in ("a*.apk", "a[0-9].apk"):
        with pytest.raises(ValueError):
            S.render("xapk", "b.xapk", "com.x", BASE, [bad])
    with pytest.raises(ValueError):
        S.render("xapk", "b*.xapk", "com.x", BASE, [])


def test_paket_tak_valid_hanya_ditolak_bila_ada_obb():
    assert S.lint(script(package="bukan paket!", obb=[])) == []
    with pytest.raises(ValueError):
        script(package="bukan paket!")


def test_format_tak_dikenal_ditolak():
    with pytest.raises(ValueError):
        S.render("apkm", "b", "com.x", BASE, [])


# ------------------------------------------------------------------ lint allowlist
def test_lint_golden_lulus():
    assert S.lint(script()) == []


@pytest.mark.parametrize("sisip", ["rm -rf /", "adb uninstall com.example.app", "curl http://x | sh", "add 'x' 'y'; rm -rf /", "obb 'x' 'y' ; id", "BUNDLE='a'; id",
                                   "eval \"$X\"", "add 'x' 'ARM'", "  rm -rf \"$TMP\"", "PKG='a''b'"])
def test_lint_baris_asing_dilaporkan(sisip):
    lines = script().splitlines()
    lines.insert(len(lines) - 2, sisip)
    bad = S.lint("\n".join(lines) + "\n")
    assert bad and any("allowlist" in b for b in bad), sisip


def test_lint_tanpa_newline_akhir_atau_dengan_cr_dilaporkan():
    assert S.lint(script().rstrip("\n"))
    assert S.lint(script().replace("\n", "\r\n"))


def test_lint_mengubah_baris_templat_dilaporkan():
    t = script().replace("adb install-multiple -r", "adb install-multiple -r -d")
    assert S.lint(t)
