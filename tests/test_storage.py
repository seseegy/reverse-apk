"""Halaman Penyimpanan (PRD 10, tahap 1): angka dari DB, pemindaian disk, pencocokan DB<->disk, dan halaman yang benar-benar dirender.

Halaman ini HANYA melihat. Tes juga menjaga bahwa tidak ada yang berubah di disk/DB oleh halaman atau pemindaian.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import pytest

from app import context, routes_storage, storage
from rvcore import store
from rvcore.db import tx
from rvcore.paths import Layout

from conftest import BROWSER, new_analysis, query

OLD = 3 * 86400


def put(path: Path, size: int = 1000, age: float = 0.0) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(os.urandom(size))
    if age:
        t = time.time() - age
        os.utime(path, (t, t))
    return path


def age_dir(path: Path, age: float) -> None:
    t = time.time() - age
    os.utime(path, (t, t))


@pytest.fixture
def world(tmp_path):
    """Layout + DB terpisah (bukan DB uji bersama), supaya angka bisa dipastikan persis."""
    from rvcore import db as rvdb

    lay = Layout(tmp_path)
    for d in (lay.uploads, lay.uploads_tmp, lay.work, lay.db_dir, lay.files, lay.files_tmp):
        d.mkdir(parents=True, exist_ok=True)
    rvdb.migrate(lay.db_path)
    conn = rvdb.connect(lay.db_path)
    yield lay, conn
    conn.close()


def add_apk(lay, conn, tag: str, apk_bytes: int = 2000, artifacts=(), on_disk: bool = True, status: str = "done"):
    sha = (tag.encode().hex() * 64)[:64]
    with tx(conn):
        apk_id, aid = store.create_apk_with_analysis(conn, sha256=sha, md5=sha[:32], filename=f"{tag}.apk", size=apk_bytes, options={})
        conn.execute("UPDATE analysis SET status = ? WHERE id = ?", (status, aid))
    if on_disk:
        put(lay.upload_path(sha), apk_bytes, OLD)
    if artifacts:
        store.replace_artifacts(conn, aid, list(artifacts))
    return apk_id, aid, sha


# ---------------------------------------------------------------------------------------------- ukuran di disk
def test_tree_size_counts_disk_blocks_not_just_bytes(tmp_path):
    """Ribuan berkas kecil memakai satu blok penuh masing-masing: ukuran di disk >= jumlah byte isi, dan selisihnya nyata."""
    for i in range(200):
        put(tmp_path / f"d{i % 5}" / f"f{i}.txt", 10)
    t = storage.tree_size(tmp_path)
    assert t.files == 200 and t.apparent == 2000
    assert t.disk >= t.apparent and t.disk >= 200 * 512          # tiap berkas memakai blok sendiri


def test_tree_size_ignores_symlinks_and_missing(tmp_path):
    put(tmp_path / "a" / "ok.bin", 1000)
    outside = tmp_path.parent / f"luar-{os.urandom(3).hex()}"
    put(outside / "besar.bin", 500_000)
    os.symlink(outside, tmp_path / "a" / "tautan")
    os.symlink(outside / "besar.bin", tmp_path / "a" / "tautan.bin")
    t = storage.tree_size(tmp_path)
    assert t.files == 1 and t.apparent == 1000
    assert storage.tree_size(tmp_path / "tidak-ada") == storage.TreeSize()


def test_budget_stops_early_and_marks_partial(tmp_path):
    for i in range(50):
        put(tmp_path / f"f{i}", 10)
    full = storage.tree_size(tmp_path)
    assert full.files == 50 and not full.partial                  # kontrol: tanpa anggaran semuanya terhitung
    t = storage.tree_size(tmp_path, storage.Budget(max_files=10))
    assert t.partial and 0 < t.files < 50                        # berhenti dini: sebagian terhitung, ditandai batas bawah
    fake = {"now": 0.0}
    b = storage.Budget(max_seconds=5, clock=lambda: fake["now"])
    assert not b.exhausted()
    fake["now"] = 6.0
    assert b.exhausted()


# ---------------------------------------------------------------------------------------------- dari DB
def test_from_db_sums_per_apk_and_total(world):
    lay, conn = world
    a1 = add_apk(lay, conn, "satu", 1000, artifacts=[("apktool", "apktool", 5000, 10), ("jadx", "jadx", 20000, 40), ("index", "index", 300, 1)])
    add_apk(lay, conn, "dua", 2000)
    with tx(conn):
        conn.execute("INSERT INTO analysis_file (analysis_id, kind, path, name, size, created_at, updated_at) VALUES (?, 'ai', 'a.md', 'a.md', 700, 1, 1)", (a1[1],))
    d = storage.from_db(conn)
    by = {i["file"]: i for i in d["items"]}
    assert by["satu.apk"]["decompile"] == 25300 and by["satu.apk"]["files"] == 700 and by["satu.apk"]["total"] == 1000 + 25300 + 700
    assert by["dua.apk"]["total"] == 2000
    assert d["totals"] == {"apk": 3000, "decompile": 25300, "files": 700} and d["count"] == 2
    assert [i["file"] for i in d["items"]] == ["satu.apk", "dua.apk"]       # terbesar dulu


def test_from_db_counts_every_analysis_of_an_apk(world):
    """Satu APK bisa punya lebih dari satu analisis; hasil dekompilasi semuanya ikut dijumlah, bukan hanya yang terbaru."""
    lay, conn = world
    apk_id, aid, _ = add_apk(lay, conn, "ganda", 100, artifacts=[("jadx", "jadx", 1000, 1)])
    with tx(conn):
        second = store._insert_analysis(conn, apk_id, {}, ai_enabled=False)
    store.replace_artifacts(conn, second, [("jadx", "jadx", 4000, 1)])
    assert storage.from_db(conn)["items"][0]["decompile"] == 5000


def test_from_db_flags_active_analysis(world):
    lay, conn = world
    add_apk(lay, conn, "jalan", status="running")
    add_apk(lay, conn, "selesai", status="done")
    by = {i["file"]: i for i in storage.from_db(conn)["items"]}
    assert by["jalan.apk"]["active"] and not by["selesai.apk"]["active"]


# ---------------------------------------------------------------------------------------------- pencocokan DB <-> disk
def scan(lay, conn, **kw):
    return storage.scan_disk(lay, conn, **kw)


def test_consistent_world_has_no_findings(world):
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "rapi", artifacts=[("jadx", "jadx", 100, 1)])
    put(lay.work_dir(aid) / "jadx" / "A.java", 500, OLD)
    s = scan(lay, conn)
    assert not (s.orphan_work or s.orphan_files or s.orphan_uploads or s.missing_uploads or s.missing_files or s.unknown_work or s.recent)
    assert s.work_by_analysis[aid].files == 1 and not s.partial


def test_finds_orphans_old_enough(world):
    lay, conn = world
    put(lay.work / "9001" / "sisa.bin", 4000, OLD); age_dir(lay.work / "9001", OLD)
    put(lay.files / "9002" / "ai" / "x.md", 300, OLD); age_dir(lay.files / "9002", OLD)
    put(lay.uploads / ("f" * 64 + ".apk"), 2000, OLD)
    s = scan(lay, conn)
    assert [o["name"] for o in s.orphan_work] == ["9001"] and s.orphan_work[0]["disk"] >= 4000
    assert [o["name"] for o in s.orphan_files] == ["9002"]
    assert [o["name"] for o in s.orphan_uploads] == [("f" * 64) + ".apk"]
    assert not s.recent


def test_recent_unowned_things_are_not_orphans(world):
    """Worker membuat work/<id> sesaat sebelum baris DB terlihat. Folder yang baru dibuat TIDAK boleh dilaporkan yatim
    (begitu ada tombol hapus, itu bisa menghapus pekerjaan yang sedang berjalan)."""
    lay, conn = world
    put(lay.work / "9003" / "baru.bin", 1000)                             # berkas baru, folder baru
    put(lay.uploads / ("e" * 64 + ".apk"), 1000)                          # APK yang baru ditulis
    s = scan(lay, conn)
    assert not (s.orphan_work or s.orphan_uploads)
    assert {r["where"] for r in s.recent} == {"work", "uploads"}


def test_folder_age_uses_newest_file_inside(world):
    """Folder induk lama, tetapi ada berkas yang baru ditulis di dalamnya: itu sedang dikerjakan, bukan yatim."""
    lay, conn = world
    put(lay.work / "9004" / "lama.bin", 1000, OLD)
    put(lay.work / "9004" / "baru.bin", 1000)
    age_dir(lay.work / "9004", OLD)
    s = scan(lay, conn)
    assert not s.orphan_work and [r["name"] for r in s.recent] == ["9004"]


def test_detects_missing_upload_and_file_rows(world):
    lay, conn = world
    apk_id, aid, _ = add_apk(lay, conn, "hilang", on_disk=False)
    add_apk(lay, conn, "ada", on_disk=True)
    with tx(conn):
        for kind, path in (("ai", "ada.md"), ("ai", "hilang.md"), ("upload", "u_1.txt")):
            conn.execute("INSERT INTO analysis_file (analysis_id, kind, path, name, size, created_at, updated_at) VALUES (?, ?, ?, ?, 10, 1, 1)", (aid, kind, path, path))
    put(lay.files_dir(aid) / "ai" / "ada.md", 10, OLD)
    s = scan(lay, conn)
    assert [m["apk_id"] for m in s.missing_uploads] == [apk_id]
    assert sorted(m["name"] for m in s.missing_files) == ["hilang.md", "u_1.txt"]


def test_missing_file_check_does_not_follow_symlinks(world, tmp_path_factory):
    """Baris yang menunjuk berkas lewat symlink ke luar folder analisis dianggap hilang (aturan yang sama dengan halaman Berkas)."""
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "tautan")
    outside = tmp_path_factory.mktemp("luar") / "rahasia.txt"
    outside.write_text("x")
    with tx(conn):
        conn.execute("INSERT INTO analysis_file (analysis_id, kind, path, name, size, created_at, updated_at) VALUES (?, 'ai', 'rahasia.txt', 'rahasia.txt', 1, 1, 1)", (aid,))
    (lay.files_dir(aid) / "ai").mkdir(parents=True)
    os.symlink(outside, lay.files_dir(aid) / "ai" / "rahasia.txt")
    assert [m["name"] for m in scan(lay, conn).missing_files] == ["rahasia.txt"]


def test_stray_file_in_work_and_tmp_are_reported(world):
    lay, conn = world
    put(lay.work / "catatan.txt", 10, OLD)
    put(lay.uploads_tmp / "putus", 5000, OLD)
    s = scan(lay, conn)
    assert [u["name"] for u in s.unknown_work] == ["catatan.txt"] and s.tmp.disk >= 5000


def test_scan_is_read_only(world):
    """Pemindaian tidak boleh mengubah apa pun: daftar berkas + isi + DB identik sebelum dan sesudah."""
    lay, conn = world
    add_apk(lay, conn, "baca", artifacts=[("jadx", "jadx", 1, 1)])
    put(lay.work / "9001" / "sisa.bin", 100, OLD); age_dir(lay.work / "9001", OLD)

    def snap():
        files = sorted((str(p.relative_to(lay.root)), p.stat().st_size, p.stat().st_mtime) for p in lay.root.rglob("*") if p.is_file() and p != lay.db_path
                       and not p.name.startswith("app.sqlite"))
        return files, [tuple(r) for r in conn.execute("SELECT * FROM apk")], [tuple(r) for r in conn.execute("SELECT * FROM audit_log")]
    before = snap()
    scan(lay, conn)
    assert snap() == before


def test_partial_scan_is_flagged_and_never_invents_findings(world):
    """Anggaran habis -> hasil ditandai partial (angka = batas bawah). Yang terlihat tetap benar; yang tak terpindai TIDAK dikarang.

    Anggaran dipakai bersama, dan folder kecil (db, .tmp) dipindai lebih dulu, jadi dengan anggaran sangat kecil folder work/ bisa tak
    tersentuh sama sekali. Itu jujur selama partial=True; yang tidak boleh: daftar yatim berisi sesuatu yang sebenarnya punya pemilik."""
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "pemilik")
    put(lay.work_dir(aid) / "jadx" / "A.java", 1000, OLD)                      # punya pemilik
    for i in range(1, 6):
        put(lay.work / str(8000 + i) / "x.bin", 1000, OLD); age_dir(lay.work / str(8000 + i), OLD)   # yatim sungguhan
    full = scan(lay, conn)
    assert not full.partial and sorted(o["name"] for o in full.orphan_work) == [str(8000 + i) for i in range(1, 6)]
    tiny = scan(lay, conn, budget=storage.Budget(max_files=3))
    assert tiny.partial
    assert str(aid) not in {o["name"] for o in tiny.orphan_work}               # yang punya pemilik tidak pernah dilaporkan yatim
    assert {o["name"] for o in tiny.orphan_work} <= {o["name"] for o in full.orphan_work}      # tidak ada temuan yang dikarang


def test_big_single_folder_cannot_blow_through_the_budget(world):
    """Regresi: anggaran dulu hanya dicek di awal tiap folder, sehingga satu folder berisi banyak berkas lolos sepenuhnya."""
    lay, conn = world
    for i in range(1200):
        put(lay.work / "9100" / f"f{i}.bin", 10, OLD)
    age_dir(lay.work / "9100", OLD)
    t = storage.tree_size(lay.work / "9100", storage.Budget(max_files=300))
    assert t.partial and t.files <= 300


# ---------------------------------------------------------------------------------------------- cache
def test_cache_reuses_fresh_scan_and_force_rescans():
    calls = []
    cache = storage.ScanCache(ttl=60)

    def run():
        calls.append(1)
        return storage.DiskScan(taken_at=time.time())
    a, busy = cache.get(run)
    b, _ = cache.get(run)
    assert a is b and len(calls) == 1 and not busy
    c, _ = cache.get(run, force=True)
    assert c is not a and len(calls) == 2


def test_cache_does_not_start_a_second_scan_while_busy():
    import threading
    cache, started, release, results = storage.ScanCache(ttl=60), threading.Event(), threading.Event(), []

    def slow():
        started.set()
        release.wait(5)
        return storage.DiskScan(taken_at=time.time())
    t = threading.Thread(target=lambda: results.append(cache.get(slow, force=True)))
    t.start()
    assert started.wait(5)
    other, busy = cache.get(lambda: pytest.fail("tidak boleh memulai pemindaian kedua"), force=True)
    assert busy and other is None
    release.set()
    t.join(5)
    assert results and not results[0][1]


def test_cache_survives_a_failing_scan():
    cache = storage.ScanCache(ttl=60)

    def boom():
        raise OSError("disk rusak")
    r, busy = cache.get(boom, force=True)
    assert r.error == "OSError" and not busy
    ok, _ = cache.get(lambda: storage.DiskScan(taken_at=time.time()), force=True)      # pemindaian berikutnya tetap bisa jalan
    assert ok.error is None


# ---------------------------------------------------------------------------------------------- tampilan
def usage(total=100 * 2**30, used=9 * 2**30, free=86 * 2**30):
    return type("U", (), {"total": total, "used": used, "free": free})()


def test_host_view_separates_reserved_blocks():
    """Angka sungguhan dari VPS pemilik: 99 GB total, 9,0 GB terpakai, 86 GB tersedia -> selisih ±4 GB adalah cadangan, bukan hilang."""
    h = storage.host_view(usage(99 * 2**30, 9 * 2**30, 86 * 2**30), 1 * 2**30)
    assert h["reserved"] == 4 * 2**30 and h["app"] == 2**30 and h["other"] == 8 * 2**30
    assert sum(s["bytes"] for s in h["segments"]) == h["total"]          # bilah menyusun 100% disk


def test_host_view_never_reports_more_app_than_used():
    h = storage.host_view(usage(), 50 * 2**30)
    assert h["app"] == h["used"] and h["other"] == 0
    assert storage.host_view(usage(), -5)["app"] == 0


def test_composition_marks_source_and_regenerable():
    totals = {"apk": 100, "decompile": 800, "files": 100}
    c = storage.composition(totals, None)
    assert c["source"] == "db" and [s["key"] for s in c["segments"]] == ["apk", "decompile", "files"] and c["known"] == 1000
    assert {s["key"]: s["regen"] for s in c["segments"]} == {"apk": False, "decompile": True, "files": False}
    s = storage.DiskScan(taken_at=time.time())
    s.roots = {"uploads": storage.TreeSize(disk=10), "work": storage.TreeSize(disk=70), "files": storage.TreeSize(disk=10), "db": storage.TreeSize(disk=5)}
    s.tmp = storage.TreeSize(disk=5)
    c = storage.composition(totals, s)
    assert c["source"] == "disk" and c["known"] == 100 and {x["key"] for x in c["segments"]} == {"apk", "decompile", "files", "db", "tmp"}
    assert abs(sum(x["pct"] for x in c["segments"]) - 100) < 0.2


# ---------------------------------------------------------------------------------------------- halaman (dirender sungguhan)
@pytest.fixture
def fresh_cache(monkeypatch):
    monkeypatch.setattr(routes_storage, "SCAN_CACHE", storage.ScanCache(ttl=60))
    return routes_storage.SCAN_CACHE


def text_of(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def test_requires_login(anon):
    assert anon.get("/storage").status_code == 303 and anon.get("/storage").headers["location"] == "/login"
    assert anon.post("/storage/scan", data={"csrf": "x"}).status_code == 303


def test_page_renders_without_a_scan(client, seeded, fresh_cache):
    r = client.get("/storage", headers=BROWSER)
    assert r.status_code == 200
    t = text_of(r.text)
    assert "<h1>Penyimpanan</h1>" in r.text and "Dari catatan database" in t and "Periksa disk" in t
    assert "perkiraan dari catatan database" in t                 # kartu disk server tidak berpura-pura tepat sebelum dipindai
    assert "Pemeriksaan konsistensi" in t and "Tekan Periksa disk" in t
    assert "docker builder prune --filter until=168h" in r.text and "docker system prune -a --volumes" in r.text
    assert 'aria-current="page">Penyimpanan' in r.text            # menu aktif
    assert " style=" not in r.text                                 # CSP style-src 'self': tidak boleh ada gaya inline


def test_page_never_scans_the_disk_on_get(client, seeded, fresh_cache, monkeypatch):
    monkeypatch.setattr(storage, "scan_disk", lambda *a, **k: pytest.fail("GET /storage tidak boleh memindai disk"))
    assert client.get("/storage", headers=BROWSER).status_code == 200
    assert fresh_cache.peek() is None


def test_scan_requires_csrf_and_does_not_scan_without_it(client, seeded, fresh_cache, monkeypatch):
    monkeypatch.setattr(storage, "scan_disk", lambda *a, **k: pytest.fail("tanpa CSRF tidak boleh memindai"))
    r = client.post("/storage/scan", data={"csrf": "salah"})
    assert r.status_code == 403 and fresh_cache.peek() is None


def test_scan_then_page_shows_results(client, seeded, fresh_cache):
    aid = new_analysis(f"simpan-{os.urandom(3).hex()}")
    put(context.layout.work / "7771" / "sisa.bin", 3000, OLD); age_dir(context.layout.work / "7771", OLD)
    r = client.post("/storage/scan", data={"csrf": seeded.csrf})
    assert r.status_code == 303 and r.headers["location"] == "/storage?notice=scanned"
    page = client.get("/storage?notice=scanned", headers=BROWSER)
    t = text_of(page.text)
    assert page.status_code == 200 and "Pemeriksaan disk selesai." in t and "Ukuran di disk" in t and "Periksa ulang disk" in t
    assert "tanpa catatan" in t and "7771" in page.text
    assert "Di disk" in t                                                 # kolom hasil pemindaian muncul di tabel Per APK
    assert aid                                                            # analisis uji ikut terdaftar tanpa merusak halaman


def test_scan_failure_is_reported_not_a_500(client, seeded, fresh_cache, monkeypatch):
    monkeypatch.setattr(storage, "scan_disk", lambda *a, **k: (_ for _ in ()).throw(OSError("rusak")))
    r = client.post("/storage/scan", data={"csrf": seeded.csrf})
    assert r.status_code == 303 and r.headers["location"] == "/storage?notice=failed"
    page = client.get("/storage", headers=BROWSER)
    assert page.status_code == 200 and "Pemeriksaan disk terakhir gagal" in text_of(page.text)


def test_sort_links_and_invalid_sort_fall_back(client, seeded, fresh_cache):
    for key in ("total", "dekompilasi", "nama"):
        r = client.get(f"/storage?urut={key}", headers=BROWSER)
        assert r.status_code == 200 and f'href="/storage?urut={key}"' in r.text
    assert client.get("/storage?urut=sembarang", headers=BROWSER).status_code == 200
    assert client.get("/storage?urut=" + "x" * 50, headers=BROWSER).status_code == 422       # batas panjang parameter
    # judul kolom yang sedang diurutkan diumumkan ke pembaca layar
    assert 'aria-sort="descending"' in client.get("/storage?urut=total", headers=BROWSER).text


def test_page_escapes_names_from_disk_and_db(client, seeded, fresh_cache):
    """Nama berkas liar di disk dan nama APK di DB berasal dari luar: tidak boleh menjadi HTML."""
    evil = "<img src=x onerror=alert(1)>"
    put(context.layout.work / evil, 10, OLD)                                       # berkas liar bernama jahat di work/
    new_analysis(f"jahat-{os.urandom(3).hex()}")
    query("UPDATE apk SET filename_display = ?, app_label = ? WHERE filename_display LIKE 'jahat-%'", evil, evil)
    client.post("/storage/scan", data={"csrf": seeded.csrf})
    html = client.get("/storage", headers=BROWSER).text
    assert evil not in html and "&lt;img src=x onerror=alert(1)&gt;" in html
    (context.layout.work / evil).unlink()
    query("UPDATE apk SET filename_display = 'dibersihkan.apk', app_label = NULL WHERE filename_display = ?", evil)


def test_beranda_links_to_storage_from_disk_card(client, seeded):
    html = client.get("/", headers=BROWSER).text
    assert 'href="/storage"' in html and "Lihat rincian penyimpanan" in html


# ================================================================================ tahap 2: rute pembersihan (HTTP)
# Tes logika penghapusan ada di test_storage_clean.py. Di sini yang diuji lapisan web: sesi, CSRF, validasi masukan, halaman konfirmasi,
# dan bahwa alur dari klik sampai disk benar-benar bekerja di aplikasi yang sesungguhnya (DB + folder data uji bersama).
def make_world_for_http(tag: str):
    """Analisis selesai dengan hasil dekompilasi nyata di DB uji bersama. Mengembalikan (analysis_id, folder work)."""
    aid = new_analysis(f"{tag}-{os.urandom(3).hex()}")
    query("UPDATE analysis SET status = 'done' WHERE id = ?", aid)
    w = context.layout.work_dir(aid)
    for name in ("apktool", "jadx"):
        put(w / name / "x" / "f.txt", 4000, OLD)
    put(w / "index" / "index.sqlite", 1000, OLD)
    with closing_db() as conn:                       # replace_artifacts membuka transaksinya sendiri; jangan dibungkus tx lagi
        store.replace_artifacts(conn, aid, [("apktool", "apktool", 4000, 1), ("jadx", "jadx", 4000, 1), ("index", "index", 1000, 1)])
    return aid, w


def closing_db():
    from contextlib import closing
    return closing(context.db())


def audit_rows(action="storage_clean"):
    return query("SELECT detail FROM audit_log WHERE action = ? ORDER BY id", action)


@pytest.fixture
def reaper_sync(monkeypatch):
    """Penghapus latar diganti versi sinkron supaya hasil akhir bisa diperiksa tanpa menunggu thread."""
    class Sync:
        def start(self):
            context.reaper.sweep()
            return True

        def __getattr__(self, name):
            return getattr(context.reaper, name)
    monkeypatch.setattr(routes_storage, "reaper", Sync())
    return Sync()


def test_clean_pages_require_login(anon):
    assert anon.get("/storage/bersihkan?aksi=sisa").status_code == 303
    assert anon.post("/storage/bersihkan", data={"aksi": "sisa", "csrf": "x"}).status_code == 303


def test_confirm_page_changes_nothing(client, seeded, fresh_cache):
    """GET konfirmasi boleh dibuka, di-refresh, atau di-prefetch tanpa efek apa pun."""
    aid, w = make_world_for_http("konfirmasi")
    before = sorted(p.relative_to(w).as_posix() for p in w.rglob("*") if p.is_file())
    n_audit = len(audit_rows())
    for _ in range(3):
        r = client.get(f"/storage/bersihkan?aksi=hasil&analisis={aid}", headers=BROWSER)
        assert r.status_code == 200
    t = text_of(r.text)
    assert "Bersihkan hasil dekompilasi" in t and "2 item akan dihapus" in t and "Bisa dibuat ulang" in t and "Batal" in t
    assert sorted(p.relative_to(w).as_posix() for p in w.rglob("*") if p.is_file()) == before and len(audit_rows()) == n_audit
    assert not (context.layout.work / ".trash").exists() or not any((context.layout.work / ".trash").iterdir())


def test_irreversible_action_shows_checkbox_and_reversible_does_not(client, seeded, fresh_cache):
    aid, _ = make_world_for_http("kotak")
    assert 'name="paham"' not in client.get(f"/storage/bersihkan?aksi=hasil&analisis={aid}", headers=BROWSER).text
    put(context.layout.work / "9501" / "s.bin", 100, OLD); age_dir(context.layout.work / "9501", OLD)
    page = client.get("/storage/bersihkan?aksi=sisa", headers=BROWSER).text
    assert 'name="paham"' in page and "required" in page and "Tidak bisa dibatalkan" in text_of(page) and 'value="work/9501"' in page
    (context.layout.work / "9501" / "s.bin").unlink(); (context.layout.work / "9501").rmdir()


@pytest.mark.parametrize("qs", ["", "?aksi=", "?aksi=hapus-semua", "?aksi=hasil", "?aksi=hasil&analisis=0", "?aksi=db", "?aksi=../x"])
def test_confirm_page_rejects_bad_requests(client, seeded, fresh_cache, qs):
    r = client.get("/storage/bersihkan" + qs, headers=BROWSER)
    assert r.status_code == 303 and r.headers["location"] == "/storage?notice=bad"


def test_confirm_page_for_unknown_or_active_analysis_offers_nothing(client, seeded, fresh_cache):
    page = client.get("/storage/bersihkan?aksi=hasil&analisis=999999", headers=BROWSER)
    # 'csrf' juga ada di form Keluar pada header, jadi yang diperiksa adalah FORM PENGHAPUSAN-nya.
    assert page.status_code == 200 and "Tidak ada yang perlu dihapus" in text_of(page.text) and 'action="/storage/bersihkan"' not in page.text
    aid, w = make_world_for_http("aktif-http")
    query("UPDATE analysis SET status = 'running' WHERE id = ?", aid)
    page = client.get(f"/storage/bersihkan?aksi=hasil&analisis={aid}", headers=BROWSER)
    assert "antre/berjalan" in text_of(page.text) and 'action="/storage/bersihkan"' not in page.text      # tidak ada tombol hapus sama sekali


def test_execute_requires_csrf_and_deletes_nothing_without_it(client, seeded, fresh_cache):
    aid, w = make_world_for_http("csrf")
    before = sorted(p.relative_to(w).as_posix() for p in w.rglob("*") if p.is_file())
    for bad in ("", "salah", "x" * 500):
        r = client.post("/storage/bersihkan", data={"aksi": "hasil", "analisis": str(aid), "csrf": bad})
        assert r.status_code == 403, bad
    assert sorted(p.relative_to(w).as_posix() for p in w.rglob("*") if p.is_file()) == before


@pytest.mark.parametrize("data", [
    {"aksi": "hapus"}, {"aksi": ""}, {"aksi": "hasil"}, {"aksi": "hasil", "analisis": "abc"}, {"aksi": "hasil", "analisis": "-1"},
    {"aksi": "hasil", "analisis": "1" * 40}, {"aksi": "sisa"}, {"aksi": "sisa", "paham": "1"},
    {"aksi": "sisa", "paham": "1", "kunci": "../db"}, {"aksi": "sisa", "paham": "1", "kunci": "work/a b"}, {"aksi": "sisa", "paham": "1", "kunci": "x" * 300},
    {"aksi": "sisa", "paham": "1", "kunci": "work/../db"}, {"aksi": "sisa", "paham": "1", "kunci": "/etc/passwd"}, {"aksi": "sisa", "paham": "1", "kunci": "work//9001"},
    {"aksi": "sisa", "paham": "1", "kunci": "work/"}, {"aksi": "sisa", "paham": "1", "kunci": ".."},
    {"aksi": "catatan", "paham": "1", "kunci": "abc"}, {"aksi": "catatan", "paham": "1", "kunci": "1; DROP TABLE apk"}, {"aksi": "catatan", "paham": "1"},
])
def test_execute_rejects_malformed_input_without_touching_anything(client, seeded, fresh_cache, data):
    aid, w = make_world_for_http("jahat")
    put(context.layout.work / "9502" / "s.bin", 100, OLD); age_dir(context.layout.work / "9502", OLD)
    before = (sorted(p.relative_to(context.layout.root).as_posix() for p in context.layout.root.rglob("*") if p.is_file() and "/db/" not in "/" + p.relative_to(context.layout.root).as_posix()))
    r = client.post("/storage/bersihkan", data={"csrf": seeded.csrf, **data})
    assert r.status_code == 303 and r.headers["location"] == "/storage?notice=bad"
    after = (sorted(p.relative_to(context.layout.root).as_posix() for p in context.layout.root.rglob("*") if p.is_file() and "/db/" not in "/" + p.relative_to(context.layout.root).as_posix()))
    assert after == before
    (context.layout.work / "9502" / "s.bin").unlink(); (context.layout.work / "9502").rmdir()


def test_irreversible_post_without_confirmation_checkbox_is_rejected(client, seeded, fresh_cache):
    put(context.layout.work / "9503" / "s.bin", 100, OLD); age_dir(context.layout.work / "9503", OLD)
    r = client.post("/storage/bersihkan", data={"csrf": seeded.csrf, "aksi": "sisa", "kunci": "work/9503"})        # tanpa 'paham'
    assert r.status_code == 303 and r.headers["location"] == "/storage?notice=bad" and (context.layout.work / "9503" / "s.bin").is_file()
    (context.layout.work / "9503" / "s.bin").unlink(); (context.layout.work / "9503").rmdir()


def test_too_many_keys_are_rejected(client, seeded, fresh_cache):
    data = {"csrf": seeded.csrf, "aksi": "sisa", "paham": "1", "kunci": [f"work/{9000 + i}" for i in range(routes_storage.MAX_KEYS + 1)]}
    r = client.post("/storage/bersihkan", data=data)
    assert r.status_code in (303, 400) and (r.status_code == 400 or r.headers["location"] == "/storage?notice=bad")


def test_full_flow_decompile_clean_end_to_end(client, seeded, fresh_cache, reaper_sync):
    """Alur nyata: pratinjau -> konfirmasi -> hasil. Cek disk, DB, audit, halaman sesudahnya, dan bahwa ukuran yang dilaporkan terukur."""
    aid, w = make_world_for_http("alur")
    n_audit = len(audit_rows())
    r = client.post("/storage/bersihkan", data={"csrf": seeded.csrf, "aksi": "hasil", "analisis": str(aid)})
    assert r.status_code == 303 and r.headers["location"] == "/storage?notice=cleaned"
    assert not (w / "apktool").exists() and not (w / "jadx").exists() and (w / "index" / "index.sqlite").is_file()   # index dipertahankan
    assert sorted(a[0] for a in query("SELECT kind FROM artifact WHERE analysis_id = ?", aid)) == ["index"]
    assert len(audit_rows()) == n_audit + 1 and str(aid) in audit_rows()[-1][0]
    page = client.get("/storage?notice=cleaned", headers=BROWSER)
    t = text_of(page.text)
    assert page.status_code == 200 and "2 item dibersihkan" in t and "belakang layar" in t
    # sesudah dibersihkan, tidak ada lagi hasil dekompilasi tercatat -> tombol untuk analisis ini hilang
    assert f"analisis={aid}\"" not in client.get("/storage", headers=BROWSER).text
    # hasil hanya tampil SEKALI (angka tidak lewat URL, tidak bisa dipalsukan)
    again = client.get("/storage?notice=cleaned", headers=BROWSER)
    assert "item dibersihkan" not in text_of(again.text)


def test_flow_orphans_removes_only_what_was_previewed(client, seeded, fresh_cache, reaper_sync):
    put(context.layout.work / "9601" / "a.bin", 500, OLD); age_dir(context.layout.work / "9601", OLD)
    put(context.layout.work / "9602" / "b.bin", 500, OLD); age_dir(context.layout.work / "9602", OLD)
    page = client.get("/storage/bersihkan?aksi=sisa", headers=BROWSER).text
    assert 'value="work/9601"' in page and 'value="work/9602"' in page
    put(context.layout.work / "9603" / "c.bin", 500, OLD); age_dir(context.layout.work / "9603", OLD)         # muncul SESUDAH pratinjau
    r = client.post("/storage/bersihkan", data={"csrf": seeded.csrf, "aksi": "sisa", "paham": "1", "kunci": ["work/9601", "work/9602"]})
    assert r.status_code == 303 and r.headers["location"] == "/storage?notice=cleaned"
    assert not (context.layout.work / "9601").exists() and not (context.layout.work / "9602").exists()
    assert (context.layout.work / "9603" / "c.bin").is_file()                    # tidak dipratinjau -> tidak dihapus
    (context.layout.work / "9603" / "c.bin").unlink(); (context.layout.work / "9603").rmdir()


def test_nothing_left_message_when_everything_already_gone(client, seeded, fresh_cache):
    r = client.post("/storage/bersihkan", data={"csrf": seeded.csrf, "aksi": "sementara", "paham": "1"})      # 'sementara' tak bisa dibatalkan -> wajib paham
    assert r.status_code == 303 and r.headers["location"] == "/storage?notice=nothing"
    assert "Tidak ada yang dihapus" in text_of(client.get("/storage?notice=nothing", headers=BROWSER).text)


def test_storage_page_offers_clean_buttons_only_where_meaningful(client, seeded, fresh_cache):
    aid, _ = make_world_for_http("tombol")
    html = client.get("/storage", headers=BROWSER).text
    assert f'href="/storage/bersihkan?aksi=hasil&amp;analisis={aid}"' in html           # punya hasil dekompilasi tercatat & tidak aktif
    empty = new_analysis(f"kosong-{os.urandom(3).hex()}")
    assert f"analisis={empty}\"" not in client.get("/storage", headers=BROWSER).text    # tidak ada yang bisa dibersihkan -> tidak ada tombol
    query("UPDATE analysis SET status = 'running' WHERE id = ?", aid)
    h2 = client.get("/storage", headers=BROWSER).text
    assert f"analisis={aid}\"" not in h2 and "sedang berjalan" in h2                     # aktif -> tombol diganti keterangan
    query("UPDATE analysis SET status = 'done' WHERE id = ?", aid)


def test_clean_pages_are_csp_safe(client, seeded, fresh_cache):
    aid, _ = make_world_for_http("csp")
    for url in (f"/storage/bersihkan?aksi=hasil&analisis={aid}", "/storage/bersihkan?aksi=sisa", "/storage/bersihkan?aksi=sementara", "/storage/bersihkan?aksi=catatan"):
        r = client.get(url, headers=BROWSER)
        assert r.status_code == 200 and " style=" not in r.text and "<script" not in r.text.replace('<script src="/static/js/app.js" defer></script>', ""), url


def test_clean_button_ignores_index_only_analyses(client, seeded, fresh_cache):
    """Regresi: 'hasil dekompilasi' di tabel menjumlah index/ juga, tetapi pembersihan hanya membuang apktool+jadx. Analisis yang hanya punya index/
    dulu tetap ditawari tombol yang tidak akan menemukan apa pun."""
    aid = new_analysis(f"hanya-index-{os.urandom(3).hex()}")
    query("UPDATE analysis SET status = 'done' WHERE id = ?", aid)
    put(context.layout.work_dir(aid) / "index" / "index.sqlite", 1000, OLD)
    with closing_db() as conn:
        store.replace_artifacts(conn, aid, [("index", "index", 1000, 1)])
    html = client.get("/storage", headers=BROWSER).text
    assert f"analisis={aid}\"" not in html
    row = next(i for i in storage_items() if i["analysis_id"] == aid)
    assert row["decompile"] == 1000 and row["cleanable"] == 0


def storage_items():
    with closing_db() as conn:
        return storage.from_db(conn)["items"]


def test_page_no_longer_claims_there_are_no_clean_buttons(client, seeded, fresh_cache):
    """Sisa teks tahap 1 ('tombol pembersihan belum ada') salah begitu tahap 2 ada."""
    client.post("/storage/scan", data={"csrf": seeded.csrf})
    t = text_of(client.get("/storage", headers=BROWSER).text)
    assert "tombol pembersihan belum ada" not in t and "hanya untuk melihat" not in t        # frasa lama tahap 1, tepat
    assert "pratinjau" in t.lower()


def test_tmp_button_only_when_old_leftovers_exist(client, seeded, fresh_cache):
    client.post("/storage/scan", data={"csrf": seeded.csrf})
    assert "aksi=sementara" not in client.get("/storage", headers=BROWSER).text
    put(context.layout.uploads_tmp / "putus-lama", 3000, OLD)
    put(context.layout.uploads_tmp / "sedang-jalan", 3000)                            # baru: tidak boleh dihitung
    client.post("/storage/scan", data={"csrf": seeded.csrf})
    page = client.get("/storage", headers=BROWSER).text
    assert "aksi=sementara" in page and "Hapus 1 sisa unggahan sementara" in text_of(page)
    (context.layout.uploads_tmp / "putus-lama").unlink(); (context.layout.uploads_tmp / "sedang-jalan").unlink()


def test_trash_in_progress_is_explained_not_reported_as_orphan(client, seeded, fresh_cache):
    put(context.layout.work / ".trash" / "abc-sisa" / "f", 5000, OLD)
    client.post("/storage/scan", data={"csrf": seeded.csrf})
    t = text_of(client.get("/storage", headers=BROWSER).text)
    assert "Sedang dihapus di belakang layar" in t and ".trash" not in t.split("Pemeriksaan konsistensi")[1].split("Panduan server")[0]
    context.reaper.sweep()
    assert not context.reaper.pending()


def test_row_action_exists_in_both_slots_for_cleanable_row(client, seeded, fresh_cache):
    """Dua salinan tombol (sel Nama untuk layar sempit, kolom Aksi untuk layar lebar); CSS menampilkan tepat satu. Verifikasi visual di tes browser."""
    aid, _ = make_world_for_http("dua-slot")
    html = client.get("/storage", headers=BROWSER).text
    assert html.count(f"aksi=hasil&amp;analisis={aid}\"") == 2 and 'class="row-action"' in html and 'class="cell-action"' in html
