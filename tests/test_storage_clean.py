"""Pembersihan penyimpanan (PRD 10, tahap 2). Lebih banyak tes untuk apa yang TIDAK boleh terhapus daripada yang boleh.

Pola tiap tes: bangun dunia kecil (DB + disk), lakukan aksi, lalu periksa (a) yang seharusnya hilang benar-benar hilang dan terukur, dan
(b) SEMUA yang lain identik. Ini yang menangkap penghapusan berlebih, yang tidak terlihat dari hasil aksi itu sendiri.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from app import storage, storage_clean as C
from rvcore import db as rvdb
from rvcore import store
from rvcore.db import tx
from rvcore.paths import Layout

OLD = 3 * 86400


def put(path: Path, size: int = 1000, age: float = 0.0) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(os.urandom(size))
    if age:
        t = time.time() - age
        os.utime(path, (t, t))
    return path


def age(path: Path, seconds: float) -> None:
    t = time.time() - seconds
    os.utime(path, (t, t))


@pytest.fixture
def world(tmp_path):
    lay = Layout(tmp_path)
    for d in (lay.uploads, lay.uploads_tmp, lay.work, lay.db_dir, lay.files, lay.files_tmp):
        d.mkdir(parents=True, exist_ok=True)
    rvdb.migrate(lay.db_path)
    conn = rvdb.connect(lay.db_path)
    yield lay, conn
    conn.close()


def add_apk(lay, conn, tag: str, status: str = "done", with_outputs: bool = True):
    sha = (tag.encode().hex() * 64)[:64]
    with tx(conn):
        apk_id, aid = store.create_apk_with_analysis(conn, sha256=sha, md5=sha[:32], filename=f"{tag}.apk", size=2000, options={})
        conn.execute("UPDATE analysis SET status = ? WHERE id = ?", (status, aid))
    put(lay.upload_path(sha), 2000, OLD)
    w = lay.work_dir(aid)
    if with_outputs:
        for name in ("apktool", "jadx"):
            for i in range(3):
                put(w / name / "sub" / f"f{i}.txt", 4000, OLD)
        put(w / "index" / "index.sqlite", 3000, OLD)
        put(w / "logs" / "jadx.log", 500, OLD)
        put(w / "manifest.json", 200, OLD)
        store.replace_artifacts(conn, aid, [("apktool", "apktool", 12000, 3), ("jadx", "jadx", 12000, 3), ("index", "index", 3000, 1)])
    return apk_id, aid, sha


def snapshot(lay: Layout, skip: tuple[str, ...] = ()) -> dict[str, tuple[int, float]]:
    """Semua berkas di bawah akar data (kecuali .trash dan db), dengan ukuran + mtime: untuk membuktikan 'yang lain tidak berubah'."""
    out = {}
    for p in sorted(lay.root.rglob("*")):
        rel = p.relative_to(lay.root).as_posix()
        if p.is_file() and not p.is_symlink() and not rel.startswith(("db/",)) and "/.trash/" not in "/" + rel and not any(rel.startswith(s) for s in skip):
            out[rel] = (p.stat().st_size, p.stat().st_mtime)
    return out


def audits(conn):
    return [dict(r) for r in conn.execute("SELECT action, detail FROM audit_log WHERE action = 'storage_clean' ORDER BY id")]


# ================================================================================ hasil dekompilasi
def test_decompile_clean_removes_only_apktool_and_jadx(world):
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "satu")
    _, other, _ = add_apk(lay, conn, "lain")
    before = snapshot(lay)
    res = C.execute(lay, conn, C.Kind.DECOMPILE, analysis_id=aid)
    after = snapshot(lay)
    gone = set(before) - set(after)
    assert gone == {p for p in before if p.startswith((f"work/{aid}/apktool/", f"work/{aid}/jadx/"))} and len(gone) == 6
    assert all(after[p] == before[p] for p in after)                        # yang tersisa identik (ukuran + mtime)
    assert (lay.work_dir(aid) / "index" / "index.sqlite").is_file() and (lay.work_dir(aid) / "logs" / "jadx.log").is_file() \
        and (lay.work_dir(aid) / "manifest.json").is_file()
    assert any(p.startswith(f"work/{other}/") for p in after)               # analisis lain utuh
    assert res.removed == 2 and res.freed > 0 and not res.skipped


def test_decompile_clean_updates_db_consistently(world):
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "db")
    C.execute(lay, conn, C.Kind.DECOMPILE, analysis_id=aid, ip="1.2.3.4")
    kinds = {r["kind"] for r in store.get_artifacts(conn, aid)}
    assert kinds == {"index"}                                               # artefak apktool/jadx hilang dari catatan, index tetap
    assert "dibersihkan" in conn.execute("SELECT message FROM analysis_log WHERE analysis_id = ?", (aid,)).fetchone()[0]
    a = audits(conn)
    assert len(a) == 1 and '"analysis_id": %d' % aid in a[0]["detail"] and "1.2.3.4" in a[0]["detail"]
    assert conn.execute("SELECT status FROM analysis WHERE id = ?", (aid,)).fetchone()[0] == "done"      # status analisis tidak diubah


@pytest.mark.parametrize("status", ["queued", "running"])
def test_active_analysis_is_never_touched(world, status):
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "aktif", status=status)
    before = snapshot(lay)
    res = C.execute(lay, conn, C.Kind.DECOMPILE, analysis_id=aid)
    assert snapshot(lay) == before and res.removed == 0 and res.skipped and "antre/berjalan" in res.skipped[0][1]
    assert not audits(conn) and len(store.get_artifacts(conn, aid)) == 3


def test_decompile_clean_is_idempotent_and_reports_nothing_to_do(world):
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "dua-kali")
    C.execute(lay, conn, C.Kind.DECOMPILE, analysis_id=aid)
    second = C.execute(lay, conn, C.Kind.DECOMPILE, analysis_id=aid)
    assert second.removed == 0 and "sudah bersih" in second.skipped[0][1] and len(audits(conn)) == 1


def test_unknown_analysis_and_bad_ids(world):
    lay, conn = world
    assert C.execute(lay, conn, C.Kind.DECOMPILE, analysis_id=999).skipped[0][1] == "tidak ditemukan"
    with pytest.raises(ValueError):
        C.execute(lay, conn, C.Kind.DECOMPILE)
    with pytest.raises(ValueError):
        C.execute(lay, conn, "hapus-semua")


def test_decompile_clean_ignores_symlinked_output(world, tmp_path_factory):
    """work/<id>/jadx berupa symlink ke luar: tidak boleh diikuti, dihapus, atau dipindah."""
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "tautan", with_outputs=False)
    outside = tmp_path_factory.mktemp("luar")
    put(outside / "penting.txt", 100)
    lay.work_dir(aid).mkdir(parents=True, exist_ok=True)
    os.symlink(outside, lay.work_dir(aid) / "jadx")
    put(lay.work_dir(aid) / "apktool" / "a.txt", 100, OLD)
    res = C.execute(lay, conn, C.Kind.DECOMPILE, analysis_id=aid)
    assert (outside / "penting.txt").is_file() and (lay.work_dir(aid) / "jadx").is_symlink()
    assert res.removed == 1 and not (lay.work_dir(aid) / "apktool").exists()


def test_failed_transaction_puts_folders_back(world, monkeypatch):
    """Bila audit/DB gagal SESUDAH rename, folder harus dikembalikan: DB menganggap hasil masih ada, jadi disk tidak boleh kosong."""
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "gagal")
    before = snapshot(lay)

    def boom(conn_, action, detail):
        raise RuntimeError("audit rusak")
    with pytest.raises(RuntimeError):
        C.execute(lay, conn, C.Kind.DECOMPILE, analysis_id=aid, audit=boom)
    assert snapshot(lay) == before                                         # semuanya kembali, termasuk mtime
    assert len(store.get_artifacts(conn, aid)) == 3                        # DB ikut dibatalkan
    assert not C.trash_dir(lay.work).exists() or not any(C.trash_dir(lay.work).iterdir())


# ================================================================================ sisa tanpa pemilik
def make_orphans(lay):
    put(lay.work / "9001" / "sisa.bin", 4000, OLD); age(lay.work / "9001", OLD)
    put(lay.files / "9002" / "ai" / "x.md", 300, OLD); age(lay.files / "9002", OLD)
    put(lay.uploads / ("f" * 64 + ".apk"), 2000, OLD)
    put(lay.work / "liar.txt", 50, OLD)


def test_orphans_removed_and_everything_else_untouched(world):
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "pemilik")
    put(lay.files_dir(aid) / "ai" / "milik.md", 100, OLD)
    make_orphans(lay)
    before = snapshot(lay)
    res = C.execute(lay, conn, C.Kind.ORPHAN, keys=None)
    after = snapshot(lay)
    assert set(before) - set(after) == {"work/9001/sisa.bin", "files/9002/ai/x.md", "uploads/" + "f" * 64 + ".apk", "work/liar.txt"}
    assert all(after[p] == before[p] for p in after)
    assert res.removed == 4 and res.freed >= 4000 + 300 + 2000 + 50
    assert any(p.startswith(f"work/{aid}/") for p in after) and (lay.files_dir(aid) / "ai" / "milik.md").is_file()


def test_orphan_selection_is_an_allowlist_not_a_wildcard(world):
    """Hanya yang dipilih yang dihapus, walau ada yatim lain yang juga memenuhi syarat."""
    lay, conn = world
    make_orphans(lay)
    res = C.execute(lay, conn, C.Kind.ORPHAN, keys=["work/9001"])
    assert res.removed == 1 and (lay.work / "9001" / "sisa.bin").exists() is False
    assert (lay.files / "9002" / "ai" / "x.md").is_file() and (lay.uploads / ("f" * 64 + ".apk")).is_file()


def test_selected_item_that_gained_an_owner_is_skipped(world):
    """Antara pratinjau dan konfirmasi, analisis 9001 didaftarkan di DB. Folder itu kini PUNYA pemilik dan tidak boleh dihapus."""
    lay, conn = world
    put(lay.work / "9001" / "hasil.bin", 4000, OLD); age(lay.work / "9001", OLD)
    preview = C.plan_orphans(lay, conn)
    assert [i.key for i in preview.items] == ["work/9001"]
    with tx(conn):
        conn.execute("INSERT INTO apk (id, sha256, md5, filename_display, size, created_at) VALUES (9, ?, ?, 'x.apk', 1, 1)", ("d" * 64, "d" * 32))
        conn.execute("INSERT INTO analysis (id, apk_id, status, created_at, updated_at) VALUES (9001, 9, 'queued', 1, 1)")
    res = C.execute(lay, conn, C.Kind.ORPHAN, keys=["work/9001"])
    assert res.removed == 0 and (lay.work / "9001" / "hasil.bin").is_file() and "kini punya pemilik" in res.skipped[0][1]


def test_recent_unowned_folder_is_never_deleted(world):
    lay, conn = world
    put(lay.work / "9003" / "baru.bin", 1000)                              # worker baru saja membuatnya
    put(lay.uploads / ("e" * 64 + ".apk"), 1000)
    assert C.plan_orphans(lay, conn).items == []
    res = C.execute(lay, conn, C.Kind.ORPHAN, keys=["work/9003", "uploads/" + "e" * 64 + ".apk"])
    assert res.removed == 0 and (lay.work / "9003" / "baru.bin").is_file() and len(res.skipped) == 2


@pytest.mark.parametrize("key", ["../db", "work/../db", "work/..", "/etc", "work/9001/../../db", "db/app.sqlite", "work/.trash", "work/.tmp",
                                 "work/a b", "work/\x00", "work/" + "x" * 300, "uploads/..", "tmp/x", "", "work/", "work//9001", "work\\9001"])
def test_hostile_keys_delete_nothing(world, key):
    """Kunci dari klien tidak dipercaya: tak satu pun kunci jahat boleh menghapus apa pun, apalagi folder database."""
    lay, conn = world
    add_apk(lay, conn, "aman")
    make_orphans(lay)
    before = snapshot(lay)
    db_before = lay.db_path.stat().st_size
    res = C.execute(lay, conn, C.Kind.ORPHAN, keys=[key])
    assert res.removed == 0 and snapshot(lay) == before and lay.db_path.is_file() and lay.db_path.stat().st_size >= db_before


def test_symlinks_in_roots_are_not_orphans_and_not_followed(world, tmp_path_factory):
    lay, conn = world
    outside = tmp_path_factory.mktemp("luar")
    put(outside / "rahasia.txt", 100)
    os.symlink(outside, lay.work / "7001")
    os.symlink(outside / "rahasia.txt", lay.uploads / ("c" * 64 + ".apk"))
    res = C.execute(lay, conn, C.Kind.ORPHAN, keys=["work/7001", "uploads/" + "c" * 64 + ".apk"])
    assert res.removed == 0 and (outside / "rahasia.txt").is_file() and (lay.work / "7001").is_symlink()


def test_orphan_deletion_never_touches_db_dir(world):
    lay, conn = world
    make_orphans(lay)
    C.execute(lay, conn, C.Kind.ORPHAN, keys=None)
    assert lay.db_path.is_file() and conn.execute("SELECT count(*) FROM audit_log").fetchone()[0] >= 1


def test_failed_orphan_transaction_restores(world):
    lay, conn = world
    make_orphans(lay)
    before = snapshot(lay)

    def boom(*a):
        raise RuntimeError("x")
    with pytest.raises(RuntimeError):
        C.execute(lay, conn, C.Kind.ORPHAN, keys=None, audit=boom)
    assert snapshot(lay) == before


# ================================================================================ sisa sementara
def test_tmp_only_removes_old_files_never_active_uploads(world):
    lay, conn = world
    put(lay.uploads_tmp / "putus-lama", 3000, OLD)
    put(lay.files_tmp / "putus-lama2", 1000, OLD)
    put(lay.uploads_tmp / "sedang-diunggah", 5000)                         # baru: mungkin unggahan yang sedang berjalan
    put(lay.uploads_tmp / "hampir", 1000, C.TMP_MIN_AGE - 60)
    res = C.execute(lay, conn, C.Kind.TMP)
    assert res.removed == 2 and not (lay.uploads_tmp / "putus-lama").exists() and not (lay.files_tmp / "putus-lama2").exists()
    assert (lay.uploads_tmp / "sedang-diunggah").is_file() and (lay.uploads_tmp / "hampir").is_file()


# ================================================================================ catatan tanpa berkas
def add_file_row(conn, aid, kind, path, size=10):
    with tx(conn):
        cur = conn.execute("INSERT INTO analysis_file (analysis_id, kind, path, name, size, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, 1)",
                           (aid, kind, path, path, size))
    return cur.lastrowid


def test_records_only_deletes_rows_whose_file_is_gone(world):
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "cat")
    ada = add_file_row(conn, aid, "ai", "ada.md"); hilang = add_file_row(conn, aid, "ai", "hilang.md"); up = add_file_row(conn, aid, "upload", "tok")
    put(lay.files_dir(aid) / "ai" / "ada.md", 10, OLD)
    before = snapshot(lay)
    res = C.execute(lay, conn, C.Kind.RECORDS, ids=None)
    ids = {r[0] for r in conn.execute("SELECT id FROM analysis_file")}
    assert ids == {ada} and res.removed == 2 and hilang not in ids and up not in ids
    assert snapshot(lay) == before                                         # tidak ada berkas yang disentuh


def test_record_whose_file_came_back_is_kept(world):
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "kembali")
    fid = add_file_row(conn, aid, "ai", "balik.md")
    assert [i.key for i in C.plan_records(lay, conn).items] == [str(fid)]
    put(lay.files_dir(aid) / "ai" / "balik.md", 10, OLD)                  # berkasnya muncul kembali sesudah pratinjau
    res = C.execute(lay, conn, C.Kind.RECORDS, ids=[fid])
    assert res.removed == 0 and conn.execute("SELECT count(*) FROM analysis_file").fetchone()[0] == 1


def test_records_of_running_analysis_are_skipped(world):
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "jalan", status="running")
    fid = add_file_row(conn, aid, "ai", "x.md")
    res = C.execute(lay, conn, C.Kind.RECORDS, ids=[fid])
    assert res.removed == 0 and "sedang berjalan" in res.skipped[0][1]


def test_record_ids_from_client_are_validated(world):
    lay, conn = world
    with pytest.raises((ValueError, TypeError)):
        C.plan_records(lay, conn, ["1; DROP TABLE apk"])
    assert conn.execute("SELECT count(*) FROM apk").fetchone()[0] == 0


# ================================================================================ trash + reaper
def test_reaper_empties_trash_and_is_idempotent(world):
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "sapu")
    reaper = C.Reaper(lay)
    C.execute(lay, conn, C.Kind.DECOMPILE, analysis_id=aid, reaper=None)
    assert reaper.pending() and C.trash_size(lay) > 0
    assert reaper.sweep() == 2 and not reaper.pending() and C.trash_size(lay) == 0
    assert reaper.sweep() == 0


def test_reaper_survives_a_failing_removal(world):
    lay, conn = world
    put(C.trash_dir(lay.work) / "abc-x" / "f", 100)
    calls = []

    def flaky(p):
        calls.append(p)
        raise PermissionError("tidak boleh")
    r = C.Reaper(lay, remover=flaky)
    assert r.sweep() == 0 and calls and r.pending()                       # gagal dicatat, tidak melempar; dicoba lagi sapuan berikutnya


def test_reaper_thread_runs_in_background_and_start_is_single(world):
    lay, conn = world
    put(C.trash_dir(lay.files) / "abc-1" / "f", 100)
    import threading
    gate, started = threading.Event(), threading.Event()

    def slow(p):
        started.set()
        gate.wait(5)
        from rvcore.fsutil import safe_rmtree
        safe_rmtree(p)
    r = C.Reaper(lay, remover=slow)
    assert r.start() and started.wait(5)
    assert not r.start()                                                   # sudah ada thread yang berjalan: tidak membuat yang kedua
    gate.set()
    r.join(5)
    assert not r.pending()


def test_scan_does_not_report_trash_as_orphan_and_counts_it(world):
    lay, conn = world
    _, aid, _ = add_apk(lay, conn, "trash")
    C.execute(lay, conn, C.Kind.DECOMPILE, analysis_id=aid)
    s = storage.scan_disk(lay, conn)
    assert s.trash.disk > 0 and not s.orphan_work and not s.unknown_work and ".trash" not in str(s.orphan_files)
    assert C.plan_orphans(lay, conn).items == []                           # .trash tidak bisa dipilih untuk dihapus lewat aksi yatim


def test_startup_resumes_trash_left_by_a_crash(world):
    lay, conn = world
    put(C.trash_dir(lay.work) / "dead-beef" / "x" / "f", 100)
    r = C.Reaper(lay)
    assert r.pending() and r.sweep() == 1 and not r.pending()


# ================================================================================ lapisan pertahanan, masing-masing diuji SENDIRI
# Penghapusan tidak boleh bergantung pada satu pemeriksaan. Tes di atas lewat pintu depan (`execute`), tempat lapisan pertama (daftar kandidat)
# sudah menolak hal jahat sehingga lapisan kedua tidak pernah terlihat bekerja. Di sini lapisan kedua dipanggil langsung dengan masukan jahat
# yang sengaja melewati lapisan pertama (mutasi: tanpa tes ini, menghapus pemeriksaan symlink/akar/nama di _move_item tidak terdeteksi).
def item_at(path: Path, key: str = "work/x") -> C.Item:
    return C.Item(key=key, label=key, path=path)


def test_move_item_refuses_symlink_even_if_caller_forgot(world, tmp_path_factory):
    lay, _ = world
    outside = tmp_path_factory.mktemp("luar")
    put(outside / "penting.txt", 100)
    os.symlink(outside, lay.work / "7777")
    assert C._move_item(item_at(lay.work / "7777"), lay.work) is None
    assert (outside / "penting.txt").is_file() and (lay.work / "7777").is_symlink() and not C.trash_dir(lay.work).exists()


def test_move_item_refuses_paths_outside_its_root(world):
    """Item yang path-nya ada di luar akar yang disebut (mis. db/ dengan akar work) ditolak, apa pun key-nya."""
    lay, _ = world
    victim = put(lay.db_dir / "jangan-hapus.sqlite", 100)
    assert C._move_item(item_at(lay.db_dir / "jangan-hapus.sqlite"), lay.work) is None
    assert C._move_item(item_at(lay.work.parent / "work-lain"), lay.work) is None
    assert C._move_item(item_at(lay.work / ".." / "db"), lay.work) is None          # naik lewat '..'
    assert victim.is_file()


@pytest.mark.parametrize("name", [".trash", ".", ".."])
def test_move_item_never_moves_trash_or_dots(world, name):
    lay, _ = world
    (lay.work / ".trash").mkdir(exist_ok=True)
    assert C._move_item(item_at(lay.work / name), lay.work) is None and (lay.work / ".trash").is_dir()


def test_move_item_with_no_path_or_missing_path(world):
    lay, _ = world
    assert C._move_item(C.Item(key="x", label="x", path=None), lay.work) is None
    assert C._move_item(item_at(lay.work / "tidak-ada"), lay.work) is None


@pytest.mark.parametrize("name", ["a b", "a/b", "a\\b", "a\nb", "a\x00b", "é", "x" * 201, "", "a;rm", "a$(x)", "*", "a'b"])
def test_orphan_name_pattern_rejects_hostile_names_on_its_own(name):
    """Pola nama diuji langsung, terpisah dari daftar kandidat."""
    assert C.ORPHAN_NAME_RE.match(name) is None


@pytest.mark.parametrize("name", ["9001", "abc.txt", "a-b_c.d", "f" * 64 + ".apk", "x" * 200])
def test_orphan_name_pattern_accepts_normal_names(name):
    assert C.ORPHAN_NAME_RE.match(name) is not None


def test_folder_with_hostile_name_on_disk_is_never_a_candidate(world):
    """Folder sungguhan bernama aneh (dibuat siapa pun yang bisa menulis ke volume) tidak masuk daftar kandidat sama sekali."""
    lay, conn = world
    for bad in ("a b", "x;y", "$(id)", "é"):
        put(lay.work / bad / "f", 100, OLD); age(lay.work / bad, OLD)
    assert C.plan_orphans(lay, conn).items == []


# ================================================================================ izin: hasil jadx/apktool berupa direktori r-x
# Sebagai root izin diabaikan, jadi bug ini TIDAK terlihat di tes biasa. Di produksi runner berjalan sebagai uid 10001 dan hasilnya berizin r-x:
# memindahkan direktori r-x ke .trash gagal dengan PermissionError (terukur), sehingga tombol Bersihkan hasil gagal di produksi.
# Tes di bawah menjalankan kode di SUBPROSES yang menjatuhkan hak ke 'nobody'. Bila lingkungan tidak mengizinkan (bukan root, tanpa setpriv),
# tes DILEWATI dengan alasan, bukan lulus semu.
import shutil
import subprocess
import sys
import textwrap

_SETPRIV = shutil.which("setpriv")


def _base_python() -> str | None:
    """Interpreter DASAR (di luar venv): venv biasanya tidak bisa dijalankan 'nobody'. Dipilih yang sama minor-nya dengan tes ini
    (kode memakai shutil.rmtree(onexc=...), Python >= 3.12), dan hanya dipakai bila 'nobody' benar-benar bisa menjalankannya."""
    candidates = [os.path.join(sys.base_prefix, "bin", f"python{sys.version_info.major}.{sys.version_info.minor}"),
                  os.path.join(sys.base_prefix, "bin", "python3")]
    for c in candidates:
        if os.path.exists(c):
            real = os.path.realpath(c)            # jalur NYATA: symlink lewat folder yang tak bisa dilintasi 'nobody' (mis. /root) gagal saat exec
            try:
                # Persis pemanggilan yang dipakai tes (setpriv -> env -i -> python): pemeriksaan yang berbeda dari pemakaian bisa lolos
                # padahal pemakaiannya gagal (terjadi di sini: pemanggilan langsung berhasil, lewat `env -i` gagal).
                ok = subprocess.run([_SETPRIV, "--reuid=65534", "--regid=65534", "--clear-groups", "env", "-i", "PATH=/usr/bin:/bin", real,
                                     "-c", "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)"], capture_output=True, timeout=20).returncode == 0
            except (OSError, subprocess.SubprocessError):
                ok = False
            if ok:
                return real
    return None


_CAN_DROP = os.geteuid() == 0 and _SETPRIV is not None and _base_python() is not None


def _run_as_nobody(code: str, tmp_path: Path) -> subprocess.CompletedProcess:
    # tmp_path milik pytest berizin 0700 (tidak bisa dilintasi 'nobody'), jadi pakai folder sementara tersendiri yang terbuka, dan hapus sesudahnya.
    import tempfile
    work = Path(tempfile.mkdtemp(prefix="rv-nobody-"))
    work.chmod(0o777)
    root = Path(__file__).resolve().parent.parent
    script = work / "t.py"
    script.write_text(textwrap.dedent(code))
    script.chmod(0o644)
    env = ["env", "-i", "PATH=/usr/bin:/bin", f"HOME={work}", "LANG=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1",
           f"PYTHONPATH={root / 'services'}:{root / 'services' / 'web'}"]
    try:
        return subprocess.run([_SETPRIV, "--reuid=65534", "--regid=65534", "--clear-groups", *env, _base_python(), str(script)],
                              capture_output=True, text=True, timeout=60)
    finally:
        _rmtree_as_root(work)


def _rmtree_as_root(path: Path) -> None:
    """Pohon uji berisi direktori r-x milik 'nobody'; root bisa menghapusnya, tetapi perbaiki izinnya dulu agar tidak bergantung pada itu."""
    for dirpath, dirnames, _files in os.walk(path):
        for d in dirnames:
            try:
                os.chmod(os.path.join(dirpath, d), 0o700)
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)


_BUILD = '''
import os, sys
from pathlib import Path
from rvcore.paths import Layout
import importlib
C = importlib.import_module("app.storage_clean")
lay = Layout(sys.argv[0].rsplit("/", 1)[0] + "/data")
for d in (lay.work, lay.files, lay.uploads): d.mkdir(parents=True, exist_ok=True)

def build_ro(name, root):
    """Pohon bersarang dengan direktori r-x dan berkas r--, seperti hasil jadx/apktool nyata."""
    top = root / name
    dirs = [top / "sources/com/ex/inner", top / "resources/res/values"]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        (d / "A.java").write_text("class A {}")
    allp = sorted({p for d in dirs for p in [d, *d.parents] if top in (p, *p.parents)}, key=lambda p: -len(p.parts))
    for p in allp:
        for f in p.glob("*.java"): os.chmod(f, 0o444)
    for p in allp: os.chmod(p, 0o555)
    return top
'''


@pytest.mark.skipif(not _CAN_DROP, reason="butuh root + setpriv + Python >= 3.12 di luar venv yang bisa dijalankan 'nobody' (izin diabaikan bagi root)")
def test_readonly_directories_can_be_moved_and_reaped_as_a_normal_user(tmp_path):
    code = _BUILD + '''
top = build_ro("jadx", lay.work / "7")
item = C.Item(key="7/jadx", label="jadx", path=top)
dest = C._move_item(item, lay.work)
assert dest is not None, "rename direktori r-x ke .trash GAGAL"
assert not top.exists()
r = C.Reaper(lay)
assert r.sweep() == 1 and not r.pending(), "penghapusan akhir gagal"
print("OK uid", os.getuid())
'''
    r = _run_as_nobody(code, tmp_path)
    assert r.returncode == 0 and "OK uid 65534" in r.stdout, (r.stdout + r.stderr)[-800:]


@pytest.mark.skipif(not _CAN_DROP, reason="butuh root + setpriv + Python >= 3.12 di luar venv yang bisa dijalankan 'nobody'")
def test_without_the_permission_fix_the_move_fails_for_a_normal_user(tmp_path):
    """Kontrol negatif: membuktikan tes di atas benar-benar menguji sesuatu (rename r-x memang gagal tanpa pemulihan izin)."""
    code = _BUILD + '''
top = build_ro("jadx", lay.work / "8")
try:
    os.rename(top, lay.work / "dipindah")
    print("RENAME_OK")
except PermissionError:
    print("RENAME_DITOLAK")
'''
    r = _run_as_nobody(code, tmp_path)
    assert "RENAME_DITOLAK" in r.stdout, (r.stdout + r.stderr)[-800:]
