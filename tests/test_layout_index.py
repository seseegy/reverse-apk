"""Indeks pencarian memuat layout/menu/navigation (analyzer v3), tanpa mengubah temuan, string, atau jaringan yang sudah ada.

Layout hanya untuk DICARI (id tombol, teks layar, onClick). Mereka tidak ikut pemindaian secret/URL, supaya tab Temuan & Jaringan
tidak berubah isinya akibat perubahan ini.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import analyzer
from analyzer import scan as scan_mod
from analyzer.common import Findings
from analyzer.index import IndexWriter
from analyzer.scan import Scanner

from app import codeindex, context
from app.ai import tools as T
from app.ai.config import load_ai_config
from app.ai.redact import Redactor

from conftest import new_analysis

# Isi yang PASTI dipindai bila berada di folder yang dipindai (kontrol positif di bawah): URL tanpa TLS + kunci contoh dari dokumentasi AWS.
NOISY = '<resources><string name="api">http://insecure.example.com/v1/login</string><string name="aws_key">AKIAIOSFODNN7EXAMPLE</string></resources>'
LOGIN = ('<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android" android:orientation="vertical">'
         '<Button android:id="@+id/btn_login" android:onClick="onLoginClicked" android:text="Masuk"/></LinearLayout>')


def put(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def run_scan(work: Path, version: str | None = None):
    """Jalankan Scanner sungguhan pada pohon `work` (= work/<id>), tulis index.sqlite di work/index/. Kembalikan (scanner, findings)."""
    out = work / "index"
    out.mkdir(exist_ok=True)
    index = IndexWriter(out)
    findings = Findings()
    scanner = Scanner(work, index, findings, lambda msg: None)
    scanner.run()
    index.finish({"analyzer_version": version or str(analyzer.VERSION), "created": "0"})
    return scanner, findings


def indexed_paths(work: Path) -> set[str]:
    conn = sqlite3.connect(work / "index" / "index.sqlite")
    try:
        return {r[0] for r in conn.execute("SELECT path FROM code")}
    finally:
        conn.close()


def strings_table(work: Path) -> list[tuple]:
    conn = sqlite3.connect(work / "index" / "index.sqlite")
    try:
        return sorted(conn.execute("SELECT kind, value, file FROM strings"))
    finally:
        conn.close()


@pytest.fixture
def work(tmp_path):
    root = tmp_path / "w" / "1"
    put(root, "apktool/AndroidManifest.xml", '<manifest package="com.example.app"/>')
    put(root, "apktool/res/layout/activity_login.xml", LOGIN)
    put(root, "apktool/res/layout-land/activity_login.xml", LOGIN.replace("Masuk", "MasukLanskap"))
    put(root, "apktool/res/layout-v21/activity_v21.xml", LOGIN.replace("btn_login", "btn_v21"))
    put(root, "apktool/res/menu/main_menu.xml", '<menu><item android:id="@+id/action_settings" android:title="Pengaturan"/></menu>')
    put(root, "apktool/res/menu-sw600dp/main_menu.xml", '<menu><item android:id="@+id/action_tablet"/></menu>')
    put(root, "apktool/res/navigation/nav_graph.xml", '<navigation><fragment android:id="@+id/loginFragment" android:name="com.example.LoginFragment"/></navigation>')
    put(root, "apktool/res/values/strings.xml", '<resources><string name="app_name">Contoh</string></resources>')
    return root


def search(work_root: Path, aid: int, q: str) -> set[str]:
    r = codeindex.search_code(work_root, aid, q, "all")
    assert r["available"] and not r["error"], r
    return {h["path"] for h in r["hits"]}


# ---------------------------------------------------------------------------------------------- yang dicari
def test_layout_menu_and_navigation_are_searchable(work):
    scanner, _ = run_scan(work)
    root = work.parent
    assert search(root, 1, "btn_login") >= {"apktool/res/layout/activity_login.xml", "apktool/res/layout-land/activity_login.xml"}
    assert search(root, 1, "onLoginClicked")                                     # atribut onClick: petunjuk ke kode
    assert search(root, 1, "action_settings") == {"apktool/res/menu/main_menu.xml"}
    assert search(root, 1, "loginFragment") == {"apktool/res/navigation/nav_graph.xml"}
    assert scanner.stats.layout_files == 6


def test_qualifier_variants_are_included(work):
    run_scan(work)
    root = work.parent
    assert search(root, 1, "btn_v21") == {"apktool/res/layout-v21/activity_v21.xml"}
    assert search(root, 1, "action_tablet") == {"apktool/res/menu-sw600dp/main_menu.xml"}
    assert search(root, 1, "MasukLanskap") == {"apktool/res/layout-land/activity_login.xml"}


def test_only_layout_like_folders_are_added(work):
    """Cakupan sengaja sempit: folder XML lain (drawable, anim, color, ...) tidak diindeks, agar ukuran indeks terkendali."""
    for d in ("drawable", "anim", "color", "animator", "layoutx", "menuku"):
        put(work, f"apktool/res/{d}/f.xml", "<x>zzmarker_" + d + "</x>")
    run_scan(work)
    paths = indexed_paths(work)
    for d in ("drawable", "anim", "color", "animator", "layoutx", "menuku"):
        assert f"apktool/res/{d}/f.xml" not in paths, d
    assert "apktool/res/values/strings.xml" in paths                              # yang lama tetap ada


def test_non_xml_files_inside_layout_folders_are_skipped(work):
    put(work, "apktool/res/layout/catatan.txt", "zztxtmarker")
    (work / "apktool/res/layout/gambar.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00zzpng")
    run_scan(work)
    assert not {p for p in indexed_paths(work) if p.endswith((".txt", ".png")) and "layout" in p}


# ---------------------------------------------------------------------------------------------- tanpa efek samping
def test_layouts_do_not_change_findings_or_strings(work):
    """Kontrol positif: isi 'berisik' di folder yang DIPINDAI menghasilkan temuan/string. Isi yang sama di layout tidak boleh menambahnya."""
    put(work, "apktool/res/values/api.xml", NOISY)
    _, base_findings = run_scan(work)
    base_items, base_strings = base_findings.items(), strings_table(work)
    assert any("insecure.example.com" in json.dumps(i) for i in base_items) or any("insecure.example.com" in s[1] for s in base_strings), \
        "kontrol positif gagal: isi berisik tidak terpindai di folder values, jadi tes ini tidak membuktikan apa pun"

    put(work, "apktool/res/layout/berisik.xml", NOISY)
    put(work, "apktool/res/menu/berisik.xml", NOISY)
    put(work, "apktool/res/navigation/berisik.xml", NOISY)
    _, new_findings = run_scan(work)
    assert [i for i in new_findings.items() if "berisik" in json.dumps(i)] == [], "layout ikut dipindai sebagai temuan"
    assert [s for s in strings_table(work) if "berisik" in (s[2] or "")] == [], "layout ikut dipindai sebagai string"
    assert len(new_findings.items()) == len(base_items) and len(strings_table(work)) == len(base_strings)
    assert "apktool/res/layout/berisik.xml" in indexed_paths(work)                # tetapi tetap bisa dicari


# ---------------------------------------------------------------------------------------------- batas ukuran
def test_oversized_layout_file_is_skipped(work):
    put(work, "apktool/res/layout/raksasa.xml", "<a>" + "zzbig " * (scan_mod.MAX_RES_BYTES // 6 + 100) + "</a>")
    run_scan(work)
    assert "apktool/res/layout/raksasa.xml" not in indexed_paths(work)
    assert "apktool/res/layout/activity_login.xml" in indexed_paths(work)


def test_total_layout_budget_protects_index_size(work, monkeypatch):
    monkeypatch.setattr(scan_mod, "MAX_SEARCH_ONLY_BYTES", 2 * len(LOGIN))
    scanner, _ = run_scan(work)
    assert 1 <= scanner.stats.layout_files < 6


def test_symlinked_layout_dirs_and_files_are_ignored(work, tmp_path):
    outside = tmp_path / "luar"
    put(outside, "x.xml", "<a>zzoutside</a>")
    (work / "apktool/res/layout-link").symlink_to(outside, target_is_directory=True)
    (work / "apktool/res/layout/tautan.xml").symlink_to(outside / "x.xml")
    run_scan(work)
    assert not [p for p in indexed_paths(work) if "tautan" in p or "layout-link" in p or "zzoutside" in p]


def test_missing_res_folder_is_fine(tmp_path):
    root = tmp_path / "w" / "1"
    put(root, "apktool/AndroidManifest.xml", "<manifest/>")
    scanner, _ = run_scan(root)
    assert scanner.stats.layout_files == 0


# ---------------------------------------------------------------------------------------------- versi & tool AI
def test_analyzer_version_matches_the_constant_the_web_app_checks():
    """Dua angka di dua paket yang harus sama: kalau analyzer dinaikkan lagi tetapi konstanta web tidak, peringatan indeks-lama salah."""
    assert analyzer.VERSION == codeindex.LAYOUT_INDEX_VERSION


def tool_search(aid: int, q: str) -> dict:
    ctx = T.ToolContext(aid, context.layout.work, load_ai_config(), context.db, Redactor(True))
    out, ok = T.run_tool(ctx, "search_code", json.dumps({"query": q}))
    assert ok, out
    return json.loads(out.split("\n", 2)[2].rsplit("\n</hasil_tool>", 1)[0])


def seeded_work(tag: str, version: str | None) -> int:
    aid = new_analysis(tag)
    root = context.layout.work / str(aid)
    put(root, "apktool/res/layout/activity_login.xml", LOGIN)
    put(root, "apktool/AndroidManifest.xml", "<manifest/>")
    run_scan(root, version)
    return aid


def test_ai_search_finds_layout_ids_through_the_tool():
    aid = seeded_work("layout-tool-baru", None)
    data = tool_search(aid, "btn_login")
    assert [h["berkas"] for h in data["hasil"]] == ["apktool/res/layout/activity_login.xml"]
    assert "PERHATIAN" not in data["catatan"]


@pytest.mark.parametrize("version", ["2", "1", "abc", None])
def test_ai_is_warned_when_the_index_predates_layout_search(version):
    """Tanpa peringatan ini, 'tidak ada hasil' dari indeks lama terbaca AI sebagai 'tidak ada di layout manapun'."""
    aid = new_analysis(f"layout-tool-lama-{version}")
    root = context.layout.work / str(aid)
    put(root, "apktool/AndroidManifest.xml", "<manifest/>")
    out = root / "index"
    out.mkdir()
    index = IndexWriter(out)
    Scanner(root, index, Findings(), lambda m: None).run()
    index.finish({"created": "0", **({"analyzer_version": version} if version else {})})
    data = tool_search(aid, "manifest")
    assert "PERHATIAN" in data["catatan"] and "list_dir" in data["catatan"]
