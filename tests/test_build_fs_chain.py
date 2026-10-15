"""fsutil Tahap 2b: `open_dir_chain`, `rmtree_at`, `scrub_paths` (rantai-dirfd untuk `builds/`, penyaring jalur NB-3) dan `Layout` baru.

Alasan: runner (memproses pohon tak tepercaya) kini menulis akar `builds`, dan semua kontainer memakai uid 10001. `safe_rmtree`/`Path.mkdir` hanya memeriksa
komponen TERAKHIR, jadi `builds/<aid>` yang ditukar jadi symlink ke `/data/work` akan diikuti. Tes ini menjalankan kodenya sebagai uid 10001 sungguhan
(setpriv) pada pohon milik root/uid lain dengan mode 000/444/600 (pelajaran 3), bukan hanya pemilik-sama.
"""

from __future__ import annotations

import ast
import errno
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import textwrap
from pathlib import Path

import pytest
from conftest import AS_10001, ROOT, need_uid, open_to_10001, within_call
from rvcore import fsutil
from rvcore.paths import MAX_PROTO_ID, Layout

SERVICES = ROOT / "services"


@pytest.fixture
def builds(tmp_path):
    root = tmp_path / "builds"
    root.mkdir()
    return root


def marker_dir(base: Path, name: str = "korban") -> Path:
    victim = base / name
    (victim / "5").mkdir(parents=True)
    (victim / "5" / "penting").write_text("jangan disentuh")
    return victim


# ======================================================================================== Layout
def test_layout_has_bench_signwork_and_project_paths_without_creating_anything(tmp_path):
    lay = Layout(tmp_path / "d")
    assert lay.bench == tmp_path / "d" / "bench" and lay.signwork == tmp_path / "d" / "signwork"
    assert lay.project_dir(7) == tmp_path / "d" / "bench" / "7" / "project"
    assert lay.base_tree(7) == tmp_path / "d" / "work" / "7" / "apktool"
    assert not (tmp_path / "d").exists()


@pytest.mark.parametrize("bad", ["1", "../x", 1.0, True, None, 0, -1, MAX_PROTO_ID + 1, b"1"])
def test_layout_project_and_base_tree_accept_only_protocol_ids(tmp_path, bad):
    lay = Layout(tmp_path)
    for fn in (lay.project_dir, lay.base_tree):
        with pytest.raises(ValueError):
            fn(bad)
    assert lay.project_dir(MAX_PROTO_ID).name == "project"


# ======================================================================================== open_dir_chain
def test_open_dir_chain_opens_and_creates_components(builds):
    fd = fsutil.open_dir_chain(builds, "3", "7", create=True)
    try:
        assert stat.S_ISDIR(os.fstat(fd).st_mode) and (builds / "3" / "7").is_dir()
    finally:
        os.close(fd)
    os.close(fsutil.open_dir_chain(builds, "3", "7", create=True))                  # sudah ada: dipakai, tidak galat
    with pytest.raises(FileNotFoundError):
        fsutil.open_dir_chain(builds, "4", "1")
    assert not (builds / "4").exists(), "tanpa create tidak membuat apa pun"
    os.close(fsutil.open_dir_chain(builds))                                          # tanpa nama: akar saja


@pytest.mark.parametrize("name", ["", "..", "../x", "1/2", "0", "-1", "01", " 1", "1 ", "a", "٣", "1\n", ".", "1.0", "%2e"])
def test_open_dir_chain_rejects_non_canonical_components(builds, name):
    with pytest.raises(ValueError):
        fsutil.open_dir_chain(builds, name)
    with pytest.raises(ValueError):
        fsutil.open_dir_chain(builds, "1", name, create=True)
    assert not (builds / "1").exists()


@pytest.mark.parametrize("where", ["root", "aid", "bid"])
def test_open_dir_chain_never_follows_a_symlink_at_any_component(tmp_path, where):
    victim = marker_dir(tmp_path)
    real = tmp_path / "real"
    (real / "5" / "9").mkdir(parents=True)
    if where == "root":
        link = tmp_path / "builds-link"
        link.symlink_to(real)
        root, names = link, ("5", "9")
    elif where == "aid":
        root = tmp_path / "builds"
        root.mkdir()
        (root / "5").symlink_to(victim)
        names = ("5", "9")
    else:
        root = tmp_path / "builds"
        (root / "5").mkdir(parents=True)
        (root / "5" / "9").symlink_to(victim / "5")
        names = ("5", "9")
    for create in (False, True):
        with pytest.raises(OSError) as exc:
            fsutil.open_dir_chain(root, *names, create=create)
        assert exc.value.errno in (errno.ELOOP, errno.ENOTDIR)
    assert sorted(p.name for p in (victim / "5").iterdir()) == ["penting"], "sasaran symlink tidak disentuh (create=True tidak menulis ke sana)"


def test_open_dir_chain_component_that_is_a_regular_file_fails_with_enotdir(builds):
    (builds / "5").write_text("bukan direktori")
    with pytest.raises(OSError) as exc:
        fsutil.open_dir_chain(builds, "5", "1", create=True)
    assert exc.value.errno in (errno.ENOTDIR, errno.EEXIST)
    assert (builds / "5").read_text() == "bukan direktori"


def test_open_dir_chain_leaks_no_fd_on_failure(builds):
    before = set(os.listdir("/proc/self/fd"))
    for _ in range(20):
        with pytest.raises(OSError):
            fsutil.open_dir_chain(builds, "1", "2")
        with pytest.raises(ValueError):
            fsutil.open_dir_chain(builds, "1", "../x")
    assert set(os.listdir("/proc/self/fd")) <= before | {str(i) for i in range(0, 0)}


# ======================================================================================== rmtree_at
def test_rmtree_at_removes_a_tree_and_ignores_missing(builds):
    (builds / "1" / "2" / "src" / "res").mkdir(parents=True)
    (builds / "1" / "2" / "src" / "res" / "a.xml").write_text("x")
    (builds / "1" / "2" / "unsigned.apk").write_bytes(b"x")
    fd = fsutil.open_dir_chain(builds, "1")
    try:
        fsutil.rmtree_at(fd, "2")
        assert not (builds / "1" / "2").exists()
        fsutil.rmtree_at(fd, "2")                                                     # sudah tak ada: no-op
        fsutil.rmtree_at(fd, "tidak-ada")
    finally:
        os.close(fd)
    assert (builds / "1").is_dir()


def test_rmtree_at_unlinks_a_symlink_without_touching_its_target(builds, tmp_path):
    victim = marker_dir(tmp_path)
    (builds / "9").symlink_to(victim)
    fd = fsutil.open_dir_chain(builds)
    try:
        fsutil.rmtree_at(fd, "9")
    finally:
        os.close(fd)
    assert not os.path.lexists(builds / "9") and (victim / "5" / "penting").read_text() == "jangan disentuh"


def test_rmtree_at_does_not_follow_symlinks_inside_the_tree(builds, tmp_path):
    victim = marker_dir(tmp_path)
    (builds / "1" / "sub").mkdir(parents=True)
    (builds / "1" / "sub" / "ke-korban").symlink_to(victim)
    (builds / "1" / "ke-berkas").symlink_to(victim / "5" / "penting")
    fd = fsutil.open_dir_chain(builds)
    try:
        fsutil.rmtree_at(fd, "1")
    finally:
        os.close(fd)
    assert not (builds / "1").exists() and (victim / "5" / "penting").read_text() == "jangan disentuh"


def test_rmtree_at_deletes_fifo_socket_and_odd_entries_without_hanging(builds):
    d = builds / "1"
    d.mkdir()
    os.mkfifo(d / "pipa")
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(d / "soket"))
    sock.close()
    (d / "dir-kosong").mkdir()
    fd = fsutil.open_dir_chain(builds)
    try:
        _res, exc = within_call(5, fsutil.rmtree_at, fd, "1")
    finally:
        os.close(fd)
    assert exc is None and not d.exists()


def test_rmtree_at_handles_a_5000_level_tree_without_recursion_error_or_fd_exhaustion(builds):
    """Iteratif dan hanya SATU fd direktori yang dipegang (naik lewat '..'): pohon dalam buatan penyerang tidak menghabiskan batas fd (RLIMIT_NOFILE)."""
    fd = fsutil.open_dir_chain(builds, create=False)
    cur = os.open(builds, fsutil.DIR_FLAGS)
    os.mkdir("deep", 0o755, dir_fd=cur)
    nxt = os.open("deep", fsutil.DIR_FLAGS, dir_fd=cur)
    os.close(cur)
    cur = nxt
    for _ in range(5000):
        os.mkdir("d", 0o755, dir_fd=cur)
        nxt = os.open("d", fsutil.DIR_FLAGS, dir_fd=cur)
        os.close(cur)
        cur = nxt
    with os.fdopen(os.open("leaf.txt", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=cur), "w") as fh:
        fh.write("x")
    os.close(cur)
    try:
        _res, exc = within_call(60, fsutil.rmtree_at, fd, "deep")
    finally:
        os.close(fd)
    assert exc is None and not (builds / "deep").exists()


def test_rmtree_at_stops_and_reports_when_a_subdirectory_is_moved_elsewhere_while_being_deleted(builds, tmp_path, monkeypatch):
    """Penyerang memindahkan subdirektori `b` (tempat kita berada) ke induk lain di tengah penghapusan. Naik lewat '..' memeriksa (dev, inode) induk, jadi kita
    berhenti dengan OSError, bukan melanjutkan menghapus entri bernama sama (`a`, sisa daftar) di tempat lain."""
    other = tmp_path / "V"
    other.mkdir()
    (other / "penting").write_text("jangan disentuh")
    decoy = tmp_path / "a"                                    # akan terhapus bila kita naik ke induk yang salah lalu menghapus 'a'
    decoy.mkdir()
    (builds / "1" / "a" / "b").mkdir(parents=True)
    (builds / "1" / "a" / "b" / "f").write_text("x")
    fd = fsutil.open_dir_chain(builds)
    real = fsutil.os.listdir
    moved = []

    def listdir(arg):
        names = real(arg)
        if not moved and names == ["f"]:                     # sedang di builds/1/a/b
            moved.append(1)
            os.rename(builds / "1" / "a" / "b", other / "b")
        return names

    monkeypatch.setattr(fsutil.os, "listdir", listdir)
    try:
        with pytest.raises(OSError):
            fsutil.rmtree_at(fd, "1")
    finally:
        os.close(fd)
    assert moved and decoy.is_dir() and (other / "penting").read_text() == "jangan disentuh"


@need_uid
def test_uid10001_rmtree_at_removes_mode000_dirs_and_mode444_files_owned_by_itself(tmp_path):
    shared = open_to_10001(Path(tempfile.mkdtemp(prefix="rv-chain-")))
    try:
        data = shared / "builds"
        data.mkdir()
        os.chown(data, 10001, 10001)
        script = shared / "run.py"
        script.write_text(textwrap.dedent('''
            import os, sys
            from rvcore import fsutil
            root = sys.argv[1]
            os.makedirs(root + "/3/7/src/res/values")
            for p, m in (("/3/7/src/res/values/strings.xml", 0o444), ("/3/7/unsigned.apk", 0o444)):
                open(root + p, "w").write("x"); os.chmod(root + p, m)
            os.chmod(root + "/3/7/src/res/values", 0o000)      # direktori tanpa izin apa pun
            os.chmod(root + "/3/7/src/res", 0o500)             # tanpa izin tulis
            fd = fsutil.open_dir_chain(root, "3")
            try:
                fsutil.rmtree_at(fd, "7")
            finally:
                os.close(fd)
            print("ada" if os.path.exists(root + "/3/7") else "terhapus")
        '''))
        r = subprocess.run([*AS_10001, str(script), str(data)], capture_output=True, text=True, timeout=60)
        assert r.returncode == 0 and r.stdout.strip() == "terhapus", (r.stdout, r.stderr)
    finally:
        shutil.rmtree(shared, ignore_errors=True)


@need_uid
def test_uid10001_cannot_delete_through_a_dir_it_does_not_own_but_fails_closed_without_crashing(tmp_path):
    """Direktori milik root mode 000 (bukan milik 10001): perbaikan izin tidak mungkin -> OSError (bukan TypeError/loop), isi tidak hilang."""
    shared = open_to_10001(Path(tempfile.mkdtemp(prefix="rv-chain-")))
    try:
        (shared / "builds" / "3" / "7" / "dalam").mkdir(parents=True)
        (shared / "builds" / "3" / "7" / "dalam" / "f").write_text("x")
        os.chmod(shared / "builds" / "3" / "7" / "dalam", 0o000)
        os.chown(shared / "builds" / "3", 10001, 10001)
        script = shared / "run.py"
        script.write_text(textwrap.dedent('''
            import os, sys
            from rvcore import fsutil
            fd = fsutil.open_dir_chain(sys.argv[1], "3")
            try:
                fsutil.rmtree_at(fd, "7")
                print("terhapus")
            except OSError as exc:
                print("oserror", type(exc).__name__)
        '''))
        r = subprocess.run([*AS_10001, str(script), str(shared / "builds")], capture_output=True, text=True, timeout=60)
        assert r.returncode == 0 and r.stdout.startswith("oserror"), (r.stdout, r.stderr)
        assert (shared / "builds" / "3" / "7" / "dalam").exists()
    finally:
        os.chmod(shared / "builds" / "3" / "7" / "dalam", 0o755)
        shutil.rmtree(shared, ignore_errors=True)


# ======================================================================================== scrub_paths (NB-3)
SCRUB_CASES = [
    # (masukan, keluaran) tanpa akar dikenal
    ("smali/com/x/work/Foo.smali", "smali/com/x/work/Foo.smali"),                      # bukan awal token: utuh
    ("res/raw/builds/x", "res/raw/builds/x"),
    ("work/12/apktool/x", "<path>"),
    ("galat di work/12/apktool/res/x.xml lalu", "galat di <path> lalu"),
    (">/data/work/1/index", "><path>"),                                              # pesan apktool memantulkan nama berkas: tetap tersaring
    ("/data/builds/3/7/unsigned.apk", "<path>"),
    ("/tmp/home/a1-build-1234/x", "<path>"),
    ("lihat /opt/aapt-exec/aapt2 dan /usr/bin/java", "lihat <path> dan <path>"),
    ("<proyek>/lib/x.so", "<proyek>/lib/x.so"),                                       # label hasil saringan sebelumnya tidak disaring ulang
    ("<path>", "<path>"),
    ("bench/4/project/res", "<path>"),
    ("a\x00b\x07c\u202ed", "abcd"),
    ("baris1\nbaris2\tx", "baris1\nbaris2\tx"),
    ("tmp/x dan /home", "tmp/x dan <path>"),
]


@pytest.mark.parametrize("text,want", SCRUB_CASES)
def test_scrub_paths_table(text, want):
    assert fsutil.scrub_paths(text) == want


def test_scrub_paths_known_roots_keep_the_project_relative_rest():
    roots = [("/data/builds/3/7/src", "<proyek>"), ("/data/builds/3/7", "<build>"), ("/data/work/3/apktool", "<dasar>"), ("/tmp/home/a3-build-aaaaaaaa", "<home>")]
    f = lambda t: fsutil.scrub_paths(t, roots)  # noqa: E731
    assert f("/data/builds/3/7/src/res/values/strings.xml") == "<proyek>/res/values/strings.xml"
    assert f("W: /data/builds/3/7/src/lib/x.so gagal") == "W: <proyek>/lib/x.so gagal"
    assert f("/data/builds/3/7/unsigned.apk") == "<build>/unsigned.apk"
    assert f("/data/builds/3/7") == "<build>" and f("/data/builds/3/7/src") == "<proyek>"
    assert f("/data/work/3/apktool/AndroidManifest.xml") == "<dasar>/AndroidManifest.xml"
    assert f("HOME=/tmp/home/a3-build-aaaaaaaa/.local") == "HOME=<home>/.local"
    assert f("/data/builds/3/70/x") == "<path>", "id lain (70) bukan awalan akar (3/7)"
    assert f("/data/builds/9/9/src/x") == "<path>", "akar yang tak dikenal tetap disaring sebagai jalur absolut"
    assert f("/etc/passwd") == "<path>"
    assert f("smali/com/x/work/Foo") == "smali/com/x/work/Foo"


def test_scrub_paths_is_single_pass_and_idempotent():
    roots = [("/data/builds/3/7/src", "<proyek>")]
    once = fsutil.scrub_paths("/data/builds/3/7/src/res/x dan work/1/x dan /tmp/y", roots)
    assert once == "<proyek>/res/x dan <path> dan <path>"
    assert fsutil.scrub_paths(once, roots) == once


def test_scrub_paths_removes_controls_before_matching_so_they_cannot_hide_a_path():
    assert fsutil.scrub_paths("/da\u200bta/work/1") == "<path>"
    assert fsutil.scrub_paths("/da\x00ta/work/1") == "<path>"
    assert fsutil.scrub_paths("wo\u202erk/12/apktool/x") == "<path>"


def test_scrub_paths_accepts_non_str_and_none():
    assert fsutil.scrub_paths(None) == "" and fsutil.scrub_paths(12) == "12" and fsutil.scrub_paths(b"x") == "b'x'"


def test_store_clean_text_uses_the_shared_scrubber_for_relative_volume_paths():
    """NB-3: `store._clean_text(scrub=True)` kini menyaring jalur RELATIF volume (work/12/apktool/x) selain jalur absolut, dan membiarkan jalur proyek."""
    from rvcore import store
    out = store._clean_text("gagal: work/12/apktool/x.smali /data/work/1 smali/com/x/work/Foo.smali", 500, scrub=True)
    assert out == "gagal: <path> <path> smali/com/x/work/Foo.smali"
    assert store._clean_text("work/12/apktool/x", 500) == "work/12/apktool/x", "tanpa scrub=True tidak diubah"


# ======================================================================================== penjaga struktural konsumen builds/
CONSUMERS = ["services/worker/signcheck.py"]                    # FEAT D/E menambah worker/builds.py, web/app/builds.py, web/app/buildctl.py
PATH_BASED = {"safe_rmtree", "rmtree", "mkdir", "makedirs", "rename", "rmdir"}


def test_consumers_of_builds_do_not_mutate_it_by_path():
    for rel in CONSUMERS:
        tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert not names & PATH_BASED, (rel, names & PATH_BASED)


def test_signer_publishes_only_relative_to_the_opened_build_directory():
    """Tidak ada `os.replace`/`os.rename`/`os.unlink` berbasis jalur string di signer-daemon yang menyentuh folder build (semua `dir_fd`)."""
    tree = ast.parse((SERVICES / "signer/signer-daemon").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
            if node.func.attr in ("replace", "rename", "link", "symlink"):
                assert {k.arg for k in node.keywords} >= {"src_dir_fd", "dst_dir_fd"}, ast.unparse(node)
