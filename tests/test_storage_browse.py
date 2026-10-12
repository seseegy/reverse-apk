"""Penjelajah folder (PRD 10, tahap 3). Penyaji berkas dari disk lewat jalur pilihan pengguna: tes terpenting adalah yang MENOLAK.

Dua lapis diuji: logika (storage_browse, tanpa web) dan HTTP (rute /storage/jelajah*). Daftar putih diuji per lapisan supaya mutasi pada satu
lapisan tidak tertutup lapisan lain (pelajaran dari tahap 2).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from app import context, storage_browse as B
from rvcore.paths import Layout

from conftest import BROWSER

SHA = "a" * 64
SECRET = "AKIAIOSFODNN7EXAMPLE"      # kunci contoh dokumentasi AWS, bukan rahasia sungguhan


def put(path: Path, data: bytes | str = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return path


@pytest.fixture
def lay(tmp_path):
    lay = Layout(tmp_path)
    for d in (lay.uploads, lay.uploads_tmp, lay.work, lay.db_dir, lay.files, lay.files_tmp):
        d.mkdir(parents=True, exist_ok=True)
    put(lay.db_dir / "app.sqlite", b"SQLite format 3\x00rahasia-db")
    put(lay.uploads / f"{SHA}.apk", b"PK\x03\x04apk")
    put(lay.uploads_tmp / "putus", b"tmp")
    w = lay.work / "1"
    put(w / "jadx" / "sources" / "com" / "A.java", "class A {}")
    put(w / "jadx" / "resources" / "res" / "values" / "s.xml", "<resources/>")
    put(w / "apktool" / "AndroidManifest.xml", "<manifest/>")
    put(w / "logs" / "jadx.log", "log")
    put(w / "manifest.json", "{}")
    put(w / "index" / "findings.jsonl", f'{{"secret": "{SECRET}"}}\n')                  # TERTUTUP
    put(w / "index" / "index.sqlite", f"string {SECRET}".encode())                     # TERTUTUP
    put(lay.files / "1" / "ai" / "laporan.md", "# laporan")
    put(lay.files / "1" / "up" / "tok123", "lampiran")
    put(lay.files / "1" / "rahasia-lain.txt", "bukan up/ atau ai/")                    # TERTUTUP (bukan kategori yang dikenal)
    return lay


# ================================================================================ daftar putih (lapisan 1: allowed)
@pytest.mark.parametrize("root,path", [
    ("uploads", ""), ("uploads", f"{SHA}.apk"),
    ("work", ""), ("work", "1"), ("work", "1/jadx"), ("work", "1/jadx/sources/com/A.java"), ("work", "1/apktool"), ("work", "1/logs/jadx.log"), ("work", "1/manifest.json"),
    ("files", ""), ("files", "1"), ("files", "1/up"), ("files", "1/ai/laporan.md"),
])
def test_allowed_paths(root, path):
    assert B.allowed(root, B._parts(path))


@pytest.mark.parametrize("root,path", [
    ("work", "1/index"), ("work", "1/index/findings.jsonl"), ("work", "1/index/index.sqlite"),          # nilai rahasia mentah
    ("work", "1/jadx.log"), ("work", "1/lain.txt"), ("work", "1/manifest.json/x"), ("work", ".trash"), ("work", ".tmp"), ("work", "catatan.txt"),
    ("work", "abc"), ("work", "0"), ("work", "01"), ("work", "-1"), ("work", "1" * 11),
    ("files", ".tmp"), ("files", ".trash"), ("files", "1/rahasia-lain.txt"), ("files", "1/x"), ("files", "abc"),
    ("uploads", ".tmp"), ("uploads", ".tmp/putus"), ("uploads", ".trash"), ("uploads", "abc.apk"), ("uploads", SHA), ("uploads", f"{SHA}.apk/x"), ("uploads", "x/" + SHA + ".apk"),
    ("db", ""), ("db", "app.sqlite"), ("", ""), ("spool", ""), ("config", ""), ("..", ""),
])
def test_forbidden_paths(root, path):
    parts = B._parts(path)
    assert parts is not None and not B.allowed(root, parts), f"{root}/{path} seharusnya ditolak"


def test_index_is_closed_at_any_depth_even_with_allowed_sounding_names():
    for p in ("1/index", "1/index/a", "1/index/jadx", "1/index/../jadx"):
        parts = B._parts(p)
        assert parts is None or not B.allowed("work", parts), p


# ================================================================================ bentuk jalur (lapisan 2: _parts)
@pytest.mark.parametrize("path", ["../x", "a/../b", "..", "a/..", "/etc/passwd", "a\\b", "a\x00b", "a\nb", "a\tb", "a\x7fb", "x" * 601, "a/" + "b" * 256, "a\x1b[31m"])
def test_hostile_path_shapes_are_rejected(path):
    assert B._parts(path) is None


@pytest.mark.parametrize("path,expected", [("", []), ("a", ["a"]), ("a/b", ["a", "b"]), ("a//b", ["a", "b"]), ("./a/./b/", ["a", "b"]), ("é/ü", ["é", "ü"])])
def test_benign_path_shapes_are_normalised(path, expected):
    assert B._parts(path) == expected


def test_non_string_path_is_rejected():
    for bad in (None, 5, b"a", ["a"]):
        assert B._parts(bad) is None


# ================================================================================ resolve + symlink (lapisan 3)
def test_resolve_accepts_good_and_rejects_closed(lay):
    assert B.resolve(lay, "work", "1/jadx/sources/com/A.java") is not None
    assert B.resolve(lay, "work", "1/index/findings.jsonl") is None
    assert B.resolve(lay, "db", "") is None and B.resolve(lay, "db", "app.sqlite") is None


def test_symlink_inside_allowed_folder_to_closed_folder_is_rejected(lay):
    w = lay.work / "1"
    os.symlink(w / "index", w / "jadx" / "tautan_index")
    os.symlink(w / "index" / "findings.jsonl", w / "jadx" / "tautan.jsonl")
    for rel in ("1/jadx/tautan_index", "1/jadx/tautan_index/findings.jsonl", "1/jadx/tautan.jsonl"):
        assert B.resolve(lay, "work", rel) is None and B.open_file(lay, "work", rel) is None and B.read_text(lay, "work", rel) is None, rel


def test_allowed_folder_that_is_itself_a_symlink_is_rejected(lay):
    other = lay.work / "2"
    other.mkdir()
    os.symlink(lay.work / "1" / "index", other / "jadx")
    os.symlink(lay.db_dir, other / "logs")
    assert B.resolve(lay, "work", "2/jadx") is None and B.resolve(lay, "work", "2/logs") is None
    assert B.list_dir(lay, "work", "2/jadx") is None


def test_symlink_to_outside_the_root_is_rejected(lay, tmp_path_factory):
    outside = tmp_path_factory.mktemp("luar")
    put(outside / "host.txt", "rahasia host")
    os.symlink(outside / "host.txt", lay.work / "1" / "apktool" / "host.txt")
    os.symlink(outside, lay.work / "1" / "apktool" / "luar")
    for rel in ("1/apktool/host.txt", "1/apktool/luar", "1/apktool/luar/host.txt"):
        assert B.open_file(lay, "work", rel) is None, rel


def test_symlinks_are_never_offered_in_listings(lay, tmp_path_factory):
    outside = tmp_path_factory.mktemp("luar")
    os.symlink(outside, lay.work / "1" / "jadx" / "luar")
    os.symlink(lay.work / "1" / "index", lay.work / "1" / "jadx" / "ke_index")
    names = [e.name for e in B.list_dir(lay, "work", "1/jadx").entries]
    assert "luar" not in names and "ke_index" not in names and "sources" in names


def test_open_file_itself_refuses_a_symlink_even_if_resolve_were_fooled(lay, monkeypatch):
    """Lapisan terakhir (O_NOFOLLOW) diuji TERPISAH: resolve() diganti agar menyerahkan symlink, seperti bila berkas ditukar setelah dicek (race)."""
    link = lay.work / "1" / "jadx" / "tautan.txt"
    os.symlink(lay.work / "1" / "index" / "findings.jsonl", link)
    monkeypatch.setattr(B, "resolve", lambda *a, **k: (link, ["1", "jadx", "tautan.txt"]))
    assert B.open_file(lay, "work", "apa-saja") is None


def test_list_dir_itself_refuses_a_symlinked_folder_even_if_resolve_were_fooled(lay, monkeypatch):
    link = lay.work / "1" / "jadx" / "ke_index"
    os.symlink(lay.work / "1" / "index", link)
    monkeypatch.setattr(B, "resolve", lambda *a, **k: (link, ["1", "jadx", "ke_index"]))
    assert B.list_dir(lay, "work", "apa-saja") is None


def test_db_is_not_a_browsable_root_in_any_table(lay):
    assert "db" not in B.ROOTS and B._base(lay, "db") is None
    assert all(r["id"] != "db" for r in B.root_summary(lay))


def test_top_level_work_symlink_to_a_real_analysis_dir_is_not_followed(lay):
    os.symlink(lay.work / "1", lay.work / "9")
    assert B.resolve(lay, "work", "9") is None and "9" not in [e.name for e in B.list_dir(lay, "work", "").entries]


# ================================================================================ daftar isi
def test_listing_work_offers_only_analysis_folders(lay):
    put(lay.work / "catatan.txt", "liar")
    (lay.work / ".trash").mkdir()
    ls = B.list_dir(lay, "work", "")
    assert [e.name for e in ls.entries] == ["1"] and set(ls.hidden) == {"catatan.txt", ".trash"}


def test_listing_analysis_hides_index_but_says_it_is_hidden(lay):
    ls = B.list_dir(lay, "work", "1")
    assert [e.name for e in ls.entries] == ["apktool", "jadx", "logs", "manifest.json"]
    assert ls.hidden == ["index"]                          # pengguna diberi tahu: ada, sengaja disembunyikan


def test_listing_files_offers_only_up_and_ai(lay):
    ls = B.list_dir(lay, "files", "1")
    assert [e.name for e in ls.entries] == ["ai", "up"] and ls.hidden == ["rahasia-lain.txt"]


def test_listing_uploads_offers_only_apk_files(lay):
    ls = B.list_dir(lay, "uploads", "")
    assert [e.name for e in ls.entries] == [f"{SHA}.apk"] and ".tmp" in ls.hidden


def test_folders_sort_before_files_and_case_insensitively(lay):
    d = lay.work / "1" / "jadx"
    put(d / "b.txt"); put(d / "A.txt"); put(d / "zeta" / "f"); put(d / "Alpha" / "f")
    assert [(e.name, e.is_dir) for e in B.list_dir(lay, "work", "1/jadx").entries] == [("Alpha", True), ("resources", True), ("sources", True), ("zeta", True), ("A.txt", False), ("b.txt", False)]


def test_crumbs_and_paths_are_relative_to_the_root(lay):
    ls = B.list_dir(lay, "work", "1/jadx/sources")
    assert ls.crumbs == [("Hasil dekompilasi", ""), ("1", "1"), ("jadx", "1/jadx"), ("sources", "1/jadx/sources")]
    assert [e.path for e in ls.entries] == ["1/jadx/sources/com"]


def test_listing_a_file_or_missing_folder_returns_none(lay):
    assert B.list_dir(lay, "work", "1/manifest.json") is None and B.list_dir(lay, "work", "1/jadx/tidak-ada") is None and B.list_dir(lay, "nope", "") is None


def test_pagination_covers_every_entry_exactly_once(lay):
    d = lay.work / "1" / "jadx" / "banyak"
    for i in range(1234):
        put(d / f"f{i:05d}.txt", "x")
    first = B.list_dir(lay, "work", "1/jadx/banyak", 1)
    assert first.total == 1234 and first.pages == 7 and len(first.entries) == B.PAGE_SIZE
    seen = []
    for p in range(1, first.pages + 1):
        seen += [e.name for e in B.list_dir(lay, "work", "1/jadx/banyak", p).entries]
    assert seen == [f"f{i:05d}.txt" for i in range(1234)]


@pytest.mark.parametrize("page,expected", [(0, 1), (-5, 1), (999, 7), (None, 1), ("2", 2)])
def test_page_is_clamped_not_an_error(lay, page, expected):
    d = lay.work / "1" / "jadx" / "banyak"
    for i in range(1234):
        put(d / f"f{i:05d}.txt", "x")
    assert B.list_dir(lay, "work", "1/jadx/banyak", page).page == expected


def test_scan_cap_marks_truncation(lay, monkeypatch):
    monkeypatch.setattr(B, "MAX_ENTRIES_SCANNED", 50)
    d = lay.work / "1" / "jadx" / "besar"
    for i in range(200):
        put(d / f"f{i}.txt", "x")
    ls = B.list_dir(lay, "work", "1/jadx/besar")
    assert ls.truncated and ls.total < 200


def test_entries_with_control_characters_are_not_offered(lay):
    d = lay.work / "1" / "jadx"
    put(d / "baik.txt", "x"); put(d / "ada\nbaris.txt", "x"); put(d / "ada\x1b[31m.txt", "x")
    assert [e.name for e in B.list_dir(lay, "work", "1/jadx").entries if e.name.endswith(".txt")] == ["baik.txt"]


def test_non_utf8_filename_is_counted_not_offered(lay):
    d = lay.work / "1" / "jadx"
    with open(os.path.join(os.fsencode(str(d)), b"bad-\xff-name.txt"), "wb") as fh:
        fh.write(b"x")
    ls = B.list_dir(lay, "work", "1/jadx")
    assert ls.undecodable == 1 and not any("bad-" in e.name for e in ls.entries)
    assert all(e.path.encode("utf-8") for e in ls.entries)          # setiap jalur yang ditawarkan bisa dijadikan URL (surrogate akan melempar)


# ================================================================================ membuka berkas
def test_open_file_reads_exact_bytes_and_size(lay):
    fh, size, name = B.open_file(lay, "work", "1/jadx/sources/com/A.java")
    with fh:
        assert fh.read() == b"class A {}" and size == 10 and name == "A.java"


@pytest.mark.parametrize("root,path", [("work", "1/jadx"), ("work", ""), ("files", "1"), ("uploads", ""), ("work", "1/jadx/tidak-ada")])
def test_open_file_refuses_directories_root_and_missing(lay, root, path):
    assert B.open_file(lay, root, path) is None


def test_read_text_truncates_and_flags(lay):
    put(lay.work / "1" / "logs" / "besar.log", b"a" * 1000 + b"\n")
    r = B.read_text(lay, "work", "1/logs/besar.log", limit=100)
    assert r["truncated"] and len(r["text"]) == 100 and r["size"] == 1001 and not r["binary"]


def test_read_text_flags_binary_without_returning_content(lay):
    put(lay.work / "1" / "apktool" / "x.bin", b"\x00\x01\x02secret")
    r = B.read_text(lay, "work", "1/apktool/x.bin")
    assert r["binary"] and "text" not in r


def test_read_text_never_reveals_closed_content(lay):
    for rel in ("1/index/findings.jsonl", "1/index/index.sqlite"):
        assert B.read_text(lay, "work", rel) is None
    r = B.read_text(lay, "work", "1/jadx/sources/com/A.java")
    assert SECRET not in str(r)


def test_browse_module_has_no_write_or_delete_calls():
    """Penjelajah HANYA MEMBACA. Jaga dengan membaca sumbernya: tidak boleh ada pemanggilan yang mengubah disk."""
    src = (Path(B.__file__)).read_text(encoding="utf-8")
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    for banned in ("os.remove", "os.unlink", "os.rename", "os.replace", "shutil.", "rmtree", ".unlink(", ".write_", "os.makedirs", ".mkdir(", "O_WRONLY", "O_RDWR", "O_CREAT", "open(" + "'w", '"w"'):
        assert banned not in code, f"storage_browse tidak boleh memuat {banned!r}"


# ================================================================================ HTTP
def seed_http_tree():
    """Pohon uji di folder data bersama (DB uji ikut dipakai tes lain, jadi pakai id analisis yang jelas tidak bentrok)."""
    lay = context.layout
    base = lay.work / "7001"
    put(base / "jadx" / "sources" / "A.java", "class A {}\n" * 3)
    put(base / "logs" / "jadx.log", "baris log\n")
    put(base / "apktool" / "x.bin", b"\x00\x01biner")
    put(base / "index" / "findings.jsonl", f'{{"secret":"{SECRET}"}}')
    put(base / "index" / "index.sqlite", f"x {SECRET}".encode())
    return base


@pytest.fixture
def http_tree():
    base = seed_http_tree()
    yield base
    import shutil
    shutil.rmtree(base, ignore_errors=True)


def text_of(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def test_pages_require_login(anon):
    for url in ("/storage/jelajah", "/storage/jelajah?akar=work", "/storage/jelajah/lihat?akar=work&jalur=7001/logs/jadx.log", "/storage/jelajah/unduh?akar=work&jalur=7001/logs/jadx.log"):
        r = anon.get(url)
        assert r.status_code in (303, 401), url
        assert SECRET not in r.text and "baris log" not in r.text


def test_root_chooser_lists_roots_and_explains_db(client, seeded):
    r = client.get("/storage/jelajah", headers=BROWSER)
    t = text_of(r.text)
    assert r.status_code == 200 and "APK asli" in t and "Hasil dekompilasi" in t and "Lampiran" in t and "tidak dapat dijelajahi" in t
    assert "akar=db" not in r.text and "hanya melihat" in t.lower()


def test_browsing_works_and_shows_hidden_note(client, seeded, http_tree):
    r = client.get("/storage/jelajah?akar=work&jalur=7001", headers=BROWSER)
    t = text_of(r.text)
    assert r.status_code == 200 and "jadx/" in t and "apktool/" in t and "logs/" in t
    assert "sengaja tidak ditampilkan" in t and "index" in t                       # diberi tahu, bukan hilang diam-diam
    assert 'akar=work&amp;jalur=7001%2Findex' not in r.text and "findings.jsonl" not in r.text


@pytest.mark.parametrize("qs", [
    "akar=work&jalur=7001/index", "akar=work&jalur=7001/index/findings.jsonl", "akar=db", "akar=db&jalur=app.sqlite", "akar=work&jalur=../db",
    "akar=work&jalur=7001/../../db", "akar=work&jalur=%2e%2e%2fdb", "akar=work&jalur=/etc", "akar=work&jalur=7001\\index", "akar=work&jalur=7001/jadx/%00",
    "akar=sembarang", "akar=uploads&jalur=.tmp", "akar=files&jalur=.trash",
])
def test_browse_pages_reject_closed_or_hostile_paths(client, seeded, http_tree, qs):
    r = client.get("/storage/jelajah?" + qs, headers=BROWSER)
    assert r.status_code == 404 and "Folder tidak ditemukan" in text_of(r.text), qs
    assert SECRET not in r.text and "rahasia-db" not in r.text and "sqlite" not in r.text.lower().replace("storage", "")


def test_view_returns_text_json(client, seeded, http_tree):
    r = client.get("/storage/jelajah/lihat?akar=work&jalur=7001/logs/jadx.log")
    assert r.status_code == 200 and r.json()["text"] == "baris log\n" and r.headers["cache-control"] == "no-store"


def test_view_flags_binary_and_never_returns_its_bytes(client, seeded, http_tree):
    d = client.get("/storage/jelajah/lihat?akar=work&jalur=7001/apktool/x.bin").json()
    assert d["binary"] is True and "text" not in d and "biner" not in str(d)


@pytest.mark.parametrize("qs", ["akar=work&jalur=7001/index/findings.jsonl", "akar=work&jalur=7001/index/index.sqlite", "akar=db&jalur=app.sqlite", "akar=work&jalur=../db/app.sqlite",
                                "akar=work&jalur=7001/jadx", "akar=work&jalur=", "akar=files&jalur=7001"])
def test_view_and_download_reject_closed_paths_without_leaking(client, seeded, http_tree, qs):
    for ep in ("lihat", "unduh"):
        r = client.get(f"/storage/jelajah/{ep}?{qs}")
        assert r.status_code == 404, (ep, qs)
        assert SECRET not in r.text and "rahasia-db" not in r.text


def test_download_headers_are_safe(client, seeded, http_tree):
    r = client.get("/storage/jelajah/unduh?akar=work&jalur=7001/jadx/sources/A.java")
    assert r.status_code == 200 and r.content == b"class A {}\n" * 3
    h = r.headers
    assert h["content-type"] == "application/octet-stream" and h["content-disposition"].startswith("attachment;") and "A.java" in h["content-disposition"]
    assert h["x-content-type-options"] == "nosniff" and "sandbox" in h["content-security-policy"] and h["cache-control"] == "no-store"
    assert h["content-length"] == str(len(r.content))


def test_download_filename_cannot_inject_headers(client, seeded, http_tree):
    d = http_tree / "jadx" / "sources"
    put(d / 'a"b; filename=evil.html.txt', "x")
    r = client.get("/storage/jelajah/unduh?akar=work&jalur=" + "7001/jadx/sources/" + 'a"b; filename=evil.html.txt')
    assert r.status_code == 200
    disp = r.headers["content-disposition"]
    assert "\n" not in disp and "\r" not in disp and disp.count("attachment") == 1 and 'filename="a"b' not in disp


def test_html_file_is_only_ever_offered_as_download_never_inline(client, seeded, http_tree):
    put(http_tree / "jadx" / "sources" / "x.html", "<script>alert(1)</script>")
    r = client.get("/storage/jelajah/unduh?akar=work&jalur=7001/jadx/sources/x.html")
    assert r.headers["content-type"] == "application/octet-stream" and r.headers["content-disposition"].startswith("attachment")
    v = client.get("/storage/jelajah/lihat?akar=work&jalur=7001/jadx/sources/x.html")
    assert v.headers["content-type"].startswith("application/json")                  # teks dikirim sebagai JSON, dirender klien lewat textContent


def test_download_streams_exactly_the_announced_length_even_if_file_grows(client, seeded, http_tree, monkeypatch):
    """logs/ boleh dilihat dan berkasnya bisa tumbuh saat analisis berjalan: Content-Length harus tetap benar (tidak ada unduhan rusak)."""
    log = http_tree / "logs" / "jadx.log"
    real = B.open_file

    def growing(*a, **k):
        fh, size, name = real(*a, **k)
        with open(log, "ab") as w:
            w.write(b"TUMBUH" * 5000)                                              # berkas bertambah SESUDAH ukuran dibaca
        return fh, size, name
    monkeypatch.setattr(B, "open_file", growing)
    r = client.get("/storage/jelajah/unduh?akar=work&jalur=7001/logs/jadx.log")
    assert r.status_code == 200 and len(r.content) == int(r.headers["content-length"]) == len("baris log\n")


def test_pages_are_csp_safe_and_escape_hostile_names(client, seeded, http_tree):
    evil = "<img src=x onerror=alert(1)>.txt"
    put(http_tree / "jadx" / "sources" / evil, "x")
    r = client.get("/storage/jelajah?akar=work&jalur=7001/jadx/sources", headers=BROWSER)
    assert r.status_code == 200 and evil not in r.text and "&lt;img src=x onerror=alert(1)&gt;.txt" in r.text
    assert " style=" not in r.text and "<script" not in r.text.replace('<script src="/static/js/app.js" defer></script>', "")


def test_paging_param_is_validated(client, seeded, http_tree):
    for qs in ("hal=0", "hal=-1", "hal=abc", "hal=99999999999"):
        assert client.get("/storage/jelajah?akar=work&jalur=7001&" + qs, headers=BROWSER).status_code in (200, 422), qs
    assert client.get("/storage/jelajah?akar=work&jalur=" + "x" * 700, headers=BROWSER).status_code == 422


def test_storage_page_links_to_browser_and_nothing_else_in_it_writes(client, seeded):
    html = client.get("/storage", headers=BROWSER).text
    assert 'href="/storage/jelajah"' in html
    browse = client.get("/storage/jelajah", headers=BROWSER).text
    assert 'method="post"' not in browse.lower().replace('method="post" action="/logout"', "")            # satu-satunya form di halaman: Keluar


def test_page_with_a_non_utf8_filename_still_renders_and_says_so(client, seeded, http_tree):
    """Terukur sebelumnya: satu nama non-UTF-8 membuat SELURUH halaman folder galat 500 (urlencode gagal di template). Diuji sampai HTML."""
    with open(os.path.join(os.fsencode(str(http_tree / "jadx" / "sources")), b"bad-\xff-name.txt"), "wb") as fh:
        fh.write(b"x")
    r = client.get("/storage/jelajah?akar=work&jalur=7001/jadx/sources", headers=BROWSER)
    assert r.status_code == 200 and "A.java" in r.text and "1 entri tidak ditampilkan karena namanya bukan teks UTF-8" in text_of(r.text)
