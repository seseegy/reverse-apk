"""Tool AI `list_dir`: menelusuri folder hasil dekompilasi (resource, smali, Java) tanpa harus menebak nama berkas.

Yang dijaga: path keluaran bisa langsung dipakai read_file, akar & folder yang tidak boleh dibaca tidak ditawarkan, path berbahaya/symlink
tidak bisa keluar dari folder analisis, folder besar bisa dibaca bertahap tanpa tumpang-tindih, dan UI penampil kode tidak berubah.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re

import pytest

from app import codeindex, context
from app.ai import tools as T
from app.ai.config import load_ai_config
from app.ai.redact import Redactor

from conftest import new_analysis

LAYOUT = '<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"><Button android:id="@+id/btn_login" android:text="Masuk"/></LinearLayout>'


def write(root, rel: str, text: str = "x") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


@pytest.fixture
def tree():
    """Analisis baru dengan pohon hasil dekompilasi kecil tetapi realistis (jadx + apktool)."""
    aid = new_analysis(f"list-dir-{os.urandom(4).hex()}")
    root = context.layout.work / str(aid)
    write(root, "jadx/sources/com/example/app/MainActivity.java", "class MainActivity {}")
    write(root, "jadx/resources/res/layout/jadx_only.xml", LAYOUT)
    write(root, "apktool/AndroidManifest.xml", "<manifest/>")
    write(root, "apktool/apktool.yml", "version: 3")                      # tidak boleh ditawarkan
    write(root, "apktool/original/META-INF/CERT.RSA", "rsa")              # tidak boleh ditawarkan
    write(root, "apktool/lib/arm64-v8a/libx.so", "so")                    # tidak boleh ditawarkan
    write(root, "apktool/smali/com/example/app/MainActivity.smali", ".class public Lcom/example/app/MainActivity;")
    for name in ("activity_login.xml", "activity_main.xml", "item_row.xml"):
        write(root, f"apktool/res/layout/{name}", LAYOUT)
    write(root, "apktool/res/layout-land/activity_login.xml", LAYOUT)
    write(root, "apktool/res/menu/main_menu.xml", "<menu/>")
    write(root, "apktool/res/navigation/nav_graph.xml", "<navigation/>")
    write(root, "apktool/res/values/strings.xml", "<resources/>")
    (root / "apktool/res/drawable-xxhdpi").mkdir(parents=True)
    (root / "apktool/res/drawable-xxhdpi/ic.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
    return type("Tree", (), {"aid": aid, "root": root})


def ctx_for(t, **cfg_overrides):
    cfg = dataclasses.replace(load_ai_config(), **cfg_overrides) if cfg_overrides else load_ai_config()
    return T.ToolContext(t.aid, context.layout.work, cfg, context.db, Redactor(True), files=context.file_store)


def call(ctx, name: str, **args):
    """(ok, isi). `isi` = JSON hasil tool bila ok, atau teks galat."""
    out, ok = T.run_tool(ctx, name, json.dumps(args))
    if not ok:
        msg = re.sub(r"<[^>]+>", "", out)
        # "tool tidak ada" juga sebuah penolakan; tanpa pagar ini tes penolakan lulus walau tool-nya sendiri hilang.
        assert f"tool '{name}' tidak ada" not in msg, f"{name} tidak terdaftar"
        return False, msg
    body = out.split("\n", 2)[2].rsplit("\n</hasil_tool>", 1)[0]
    return True, json.loads(body)


def listing(ctx, **args) -> dict:
    ok, data = call(ctx, "list_dir", **args)
    assert ok, data
    return data


# ---------------------------------------------------------------------------------------------- terdaftar
def test_tool_is_registered_with_strict_schema():
    assert "list_dir" in T.TOOLS
    schema = next(s for s in T.schemas() if s["function"]["name"] == "list_dir")
    params = schema["function"]["parameters"]
    assert params["additionalProperties"] is False and set(params["properties"]) == {"path", "filter", "limit", "offset"}
    assert not params.get("required")


# ---------------------------------------------------------------------------------------------- akar
def test_no_path_lists_the_roots(tree):
    data = listing(ctx_for(tree))
    assert [r["path"] for r in data["akar"]] == ["jadx/sources", "jadx/resources", "apktool"]
    assert "list_files" in data["catatan"]


def test_roots_missing_are_not_offered():
    aid = new_analysis(f"list-dir-kosong-{os.urandom(4).hex()}")
    ok, msg = call(T.ToolContext(aid, context.layout.work, load_ai_config(), context.db, Redactor(True)), "list_dir")
    assert not ok and "belum ada hasil dekompilasi" in msg


# ---------------------------------------------------------------------------------------------- isi folder
def test_res_listing_shows_every_ui_folder_with_full_paths(tree):
    data = listing(ctx_for(tree), path="apktool/res")
    assert data["folder"] == ["apktool/res/drawable-xxhdpi", "apktool/res/layout", "apktool/res/layout-land", "apktool/res/menu",
                              "apktool/res/navigation", "apktool/res/values"]
    assert data["berkas"] == [] and "layout*" in data["catatan"]


def test_listing_is_flat_not_merged_like_java_packages(tree):
    """Penampil kode menggabung com/example/app jadi satu entri; AI harus melihat satu tingkat saja, supaya path tidak melompat."""
    data = listing(ctx_for(tree), path="jadx/sources")
    assert data["folder"] == ["jadx/sources/com"]


def test_apktool_root_offers_only_what_read_file_can_open(tree):
    data = listing(ctx_for(tree), path="apktool")
    offered = data["folder"] + [b["path"] for b in data["berkas"]]
    assert "apktool/smali" in offered and "apktool/res" in offered and "apktool/AndroidManifest.xml" in offered
    assert not [p for p in offered if p.split("/")[1] in ("original", "lib", "apktool.yml")], offered
    # dan memang tidak bisa dibuka: penawaran tidak boleh lebih luas dari izin baca
    for hidden in ("apktool/original/META-INF/CERT.RSA", "apktool/apktool.yml"):
        ok, _ = call(ctx_for(tree), "read_file", path=hidden)
        assert not ok


def test_filter_is_case_insensitive_and_does_not_recurse(tree):
    data = listing(ctx_for(tree), path="apktool/res/layout", filter="LOGIN")
    assert [b["path"] for b in data["berkas"]] == ["apktool/res/layout/activity_login.xml"]
    assert listing(ctx_for(tree), path="apktool/res", filter="layout")["folder"] == ["apktool/res/layout", "apktool/res/layout-land"]


def test_unprefixed_path_means_apktool_like_read_file(tree):
    assert listing(ctx_for(tree), path="res/layout") == listing(ctx_for(tree), path="apktool/res/layout")


def test_slashes_and_backslashes_are_normalised(tree):
    base = listing(ctx_for(tree), path="apktool/res/layout")
    assert listing(ctx_for(tree), path="/apktool/res/layout/") == base
    assert listing(ctx_for(tree), path="apktool\\res\\layout") == base


def test_every_listed_file_can_be_read_with_read_file(tree):
    """Kontrak utama: path dari list_dir dipakai apa adanya oleh read_file."""
    ctx = ctx_for(tree)
    checked = 0
    for folder in ("jadx/resources/res/layout", "apktool/res/layout", "apktool/res/layout-land", "apktool/res/menu", "apktool/res/values",
                   "apktool/smali/com/example/app", "jadx/sources/com/example/app"):
        for f in listing(ctx, path=folder)["berkas"]:
            ok, data = call(ctx, "read_file", path=f["path"])
            assert ok and data["isi"], f"{f['path']}: {data}"
            checked += 1
    assert checked >= 8


def test_binary_files_are_listed_but_point_to_view_image(tree):
    data = listing(ctx_for(tree), path="apktool/res/drawable-xxhdpi")
    assert [b["path"] for b in data["berkas"]] == ["apktool/res/drawable-xxhdpi/ic.png"]
    assert "view_image" in data["catatan"]


# ---------------------------------------------------------------------------------------------- galat
@pytest.mark.parametrize("path", ["../x", "apktool/../../..", "apktool/res/../../../etc", "apktool/res/layout/../../../..", "a\x00b"])
def test_traversal_is_rejected(tree, path):
    ok, msg = call(ctx_for(tree), "list_dir", path=path)
    assert not ok and ("tidak ditemukan" in msg or "karakter tidak valid" in msg), msg


def test_absolute_path_cannot_reach_the_host(tree):
    ok, msg = call(ctx_for(tree), "list_dir", path="/etc")
    assert not ok and "tidak ditemukan" in msg


def test_symlinks_are_never_listed_or_followed(tree, tmp_path):
    (tmp_path / "rahasia.txt").write_text("host")
    os.symlink(tmp_path, tree.root / "apktool/res/tautan")
    os.symlink(tmp_path / "rahasia.txt", tree.root / "apktool/res/layout/tautan.xml")
    assert "tautan" not in " ".join(listing(ctx_for(tree), path="apktool/res")["folder"])
    assert "tautan.xml" not in json.dumps(listing(ctx_for(tree), path="apktool/res/layout"))
    ok, _ = call(ctx_for(tree), "list_dir", path="apktool/res/tautan")
    assert not ok


def test_a_file_path_gets_a_helpful_error(tree):
    ok, msg = call(ctx_for(tree), "list_dir", path="apktool/res/layout/activity_login.xml")
    assert not ok and "read_file" in msg


def test_user_attachments_point_to_list_files(tree):
    for p in ("lampiran/1", "hasil_ai/x.md"):
        ok, msg = call(ctx_for(tree), "list_dir", path=p)
        assert not ok and "list_files" in msg


def test_bad_argument_types_are_tool_errors_not_crashes(tree):
    for bad in ({"path": 5}, {"filter": ["a"]}, {"limit": "banyak"}, {"offset": {"x": 1}}):
        out, ok = T.run_tool(ctx_for(tree), "list_dir", json.dumps(bad))
        assert "tidak ada. Tool yang tersedia" not in out, "list_dir tidak terdaftar"
        assert not ok and "galat internal" not in out and "harus berupa" in out, (bad, out)


# ---------------------------------------------------------------------------------------------- folder besar
def test_big_folder_is_paged_without_overlap_or_loss(tree):
    big = tree.root / "apktool/res/drawable-xxhdpi"
    names = [f"gambar_{i:04d}_dengan_nama_yang_cukup_panjang.png" for i in range(300)]
    for n in names:
        (big / n).write_bytes(b"\x89PNG\r\n\x1a\n\x00")
    ctx = ctx_for(tree, max_tool_chars=3000)
    seen, offset, pages = [], 0, 0
    while True:
        data = listing(ctx, path="apktool/res/drawable-xxhdpi", offset=offset)
        got = [b["path"] for b in data["berkas"]]
        assert got, "halaman kosong sebelum selesai"
        assert len(json.dumps(data, ensure_ascii=False)) < 3000 + 2000
        seen += got
        pages += 1
        if "lanjut" not in data:
            break
        offset = int(re.search(r"offset=(\d+)", data["lanjut"]).group(1))
    expected = sorted(f"apktool/res/drawable-xxhdpi/{n}" for n in names + ["ic.png"])
    assert pages > 1 and seen == expected


def test_limit_and_offset(tree):
    ctx = ctx_for(tree)
    first = listing(ctx, path="apktool/res/layout", limit=2)
    assert [b["path"] for b in first["berkas"]] == ["apktool/res/layout/activity_login.xml", "apktool/res/layout/activity_main.xml"]
    rest = listing(ctx, path="apktool/res/layout", offset=2)
    assert [b["path"] for b in rest["berkas"]] == ["apktool/res/layout/item_row.xml"]
    ok, msg = call(ctx, "list_dir", path="apktool/res/layout", offset=99)
    assert not ok and "hanya berisi 3 entri" in msg


# ---------------------------------------------------------------------------------------------- penampil kode (UI) tidak berubah
def test_code_viewer_listing_is_unchanged(tree):
    """list_dir milik UI mendapat parameter baru, tetapi pemakaian lamanya harus persis sama.

    Penampil kode menggabung rantai folder tunggal (com/example/app -> "com.example.app", original/META-INF -> "original.META-INF")
    dan menampilkan SEMUA entri apktool, termasuk yang tidak bisa dibuka. Bagian itu tidak boleh ikut berubah oleh opsi khusus tool AI.
    """
    work = context.layout.work
    java = codeindex.list_dir(work, tree.aid, "java", "")
    assert [(e["name"], e["path"]) for e in java["entries"]] == [("com.example.app", "com/example/app")]
    root = codeindex.list_dir(work, tree.aid, "smali", "")
    names = {e["name"]: e["path"] for e in root["entries"]}
    assert names["original.META-INF"] == "original/META-INF"             # digabung
    assert names["lib.arm64-v8a"] == "lib/arm64-v8a"
    assert {"res", "apktool.yml", "AndroidManifest.xml"} <= set(names)    # entri yang tidak bisa dibuka read_file tetap tampil di UI
    # Opsi tool AI mengubah hasil; bawaan tidak.
    flat = codeindex.list_dir(work, tree.aid, "smali", "", merge_chains=False, readable_only=True)
    assert "original" not in {e["name"] for e in flat["entries"]} and "apktool.yml" not in {e["name"] for e in flat["entries"]}
