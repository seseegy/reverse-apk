"""`rvcore.treediff` (Tahap 2b, FEAT A): manifes/diff kanonik pohon proyek dan salinan aman.

Mengapa ketat: `diff_sha256` adalah yang DISETUJUI pemilik, dan runner menghitung ulang hash itu atas snapshot pohon yang ditulis AI. Kalau hash
bisa digeser tanpa mengubah isi (urutan, inode, mtime), pemilik mendapat `workspace_changed` palsu; kalau isi bisa berubah tanpa menggeser hash (satu byte,
bit x, berkas dasar), AI menyelundupkan perubahan yang tak pernah disetujui. Pohon yang dibaca juga musuh: symlink, FIFO, soket, nama raksasa, pohon dalam.

Pembanding independen: `oracle_*` di bawah menghitung manifes/diff dengan `os.walk` dan `json.dumps` penuh, tanpa memakai kode treediff.
Tes yang menjalankan kode sebagai uid 10001 (bukan root: izin berlaku), termasuk dari bind `ro` dan tujuan tmpfs `noexec`, DILEWATI dengan alasan
bila lingkungan tidak mengizinkan (bukan root, tanpa setpriv/unshare), bukan lulus semu.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import random
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import traceback
import unicodedata
from contextlib import contextmanager
from pathlib import Path

import pytest

from rvcore import store
from rvcore import treediff as T

ROOT = Path(__file__).resolve().parent.parent
SERVICES = ROOT / "services"


# ------------------------------------------------------------------ pembantu
@contextmanager
def within(seconds: int):
    """Gagal (bukan menggantung) bila blok berjalan lebih lama dari `seconds`: open() FIFO tanpa O_NONBLOCK akan menunggu selamanya."""
    def _boom(_sig, _frame):
        raise TimeoutError(f"menggantung lebih dari {seconds} dtk")
    old = signal.signal(signal.SIGALRM, _boom)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def open_fds() -> int:
    return len(os.listdir("/proc/self/fd"))


def put(root: Path, rel: str, data: bytes | str = b"", mode: int = 0o644) -> Path:
    p = Path(os.fsdecode(os.fsencode(root) + b"/" + os.fsencode(rel)))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data.encode() if isinstance(data, str) else data)
    os.chmod(p, mode)
    return p


def mktree(root: Path, files: dict[str, bytes | str], empty_dirs: tuple[str, ...] = ()) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for rel, data in files.items():
        put(root, rel, data)
    for rel in empty_dirs:
        (root / rel).mkdir(parents=True, exist_ok=True)
    return root


def diff(base: Path, work: Path, limits: T.Limits = T.Limits(), **kw) -> T.DiffResult:
    return T.compute_diff(base, work, limits, **kw)


def h(base: Path, work: Path, limits: T.Limits = T.Limits()) -> str:
    return diff(base, work, limits).diff_sha256


def entries_of(base: Path, work: Path) -> list[list]:
    got: list[list] = []
    T.compute_diff(base, work, collect=got)
    return got


def key_of(path: str) -> tuple[bytes, ...]:
    return tuple(os.fsencode(c) for c in path.split("/"))


# ------------------------------------------------------------------ pembanding independen (tanpa treediff)
def oracle_manifest(root: Path) -> dict[str, tuple]:
    out: dict[str, tuple] = {}
    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        rel_dir = os.path.relpath(dirpath, str(root))
        at_root = rel_dir == "."
        if at_root:
            dirnames[:] = [d for d in dirnames if d not in ("build", "dist")]
            filenames[:] = [f for f in filenames if f not in ("build", "dist")]
        if not dirnames and not filenames and not at_root:
            out[rel_dir] = ("d", 0, "", 0)
        for f in filenames:
            p = os.path.join(dirpath, f)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            data = Path(p).read_bytes()
            rel = f if at_root else os.path.join(rel_dir, f)
            out[rel] = ("f", len(data), hashlib.sha256(data).hexdigest(), 1 if os.stat(p).st_mode & 0o111 else 0)
    return out


def oracle_diff(base: Path, work: Path) -> tuple[list[list], str, str]:
    """(entri diff berurutan, base_hex, diff_sha256) dihitung dengan gabungan dict + json.dumps PENUH."""
    b, w = oracle_manifest(base), oracle_manifest(work)
    base_hex = hashlib.sha256("".join(
        json.dumps([p, *b[p]], separators=(",", ":"), ensure_ascii=True) + "\n" for p in sorted(b, key=key_of)).encode()).hexdigest()
    events: list[tuple[tuple, int, list]] = []
    for p in set(b) | set(w):
        old, new = b.get(p), w.get(p)
        if old and new and old[0] == new[0] == "f" and old != new:
            events.append((key_of(p), 0, ["M", p, "f", new[1], new[2], new[3], old[1], old[2], old[3]]))
        elif old and new and old[0] != new[0]:
            events.append((key_of(p), 0, ["R", p, *old]))
            events.append((key_of(p), 1, ["A", p, *new]))
        elif old and not new:
            events.append((key_of(p), 0, ["R", p, *old]))
        elif new and not old:
            events.append((key_of(p), 0, ["A", p, *new]))
    entries = [e for _k, _o, e in sorted(events, key=lambda t: (t[0], t[1]))]
    payload = json.dumps({"v": 2, "e": entries, "base": base_hex}, separators=(",", ":"), ensure_ascii=True).encode()
    return entries, base_hex, hashlib.sha256(payload).hexdigest()


# ------------------------------------------------------------------ pohon acak berbiji
NAME_PARTS = ["values", "values-v21", "values.x", "values x", "layout", "layout-land", "a", "A", "a-b", "a.b", "smali", "smali_classes2", "é", "lib"]
LEAF_PARTS = ["strings.xml", "styles.xml", "a.txt", "A.txt", "a b.txt", "x-1", "x.1", "x", "Foo.smali", "é.txt"]


def rand_spec(rng: random.Random) -> tuple[dict[str, tuple[bytes, int]], list[str]]:
    files: dict[str, tuple[bytes, int]] = {}
    dirs: list[str] = []
    for _ in range(rng.randint(0, 40)):
        depth = rng.randint(0, 3)
        parts = [rng.choice(NAME_PARTS) for _ in range(depth)] + [rng.choice(LEAF_PARTS)]
        files["/".join(parts)] = (bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 24))), rng.randint(0, 1))
    for _ in range(rng.randint(0, 4)):
        dirs.append("/".join(rng.choice(NAME_PARTS) for _ in range(rng.randint(1, 3))))
    return files, dirs


def materialize(root: Path, spec, rng: random.Random, noise: bool = True) -> None:
    """Tulis `spec` ke disk dalam urutan acak dengan mode, mtime, dan inode acak (selain bit x). Entri yang bentrok jenis dilewati."""
    files, dirs = spec
    root.mkdir(parents=True, exist_ok=True)
    order = sorted(files)
    rng.shuffle(order)
    junk = root.parent / (root.name + "-junk")
    junk.mkdir(exist_ok=True)
    for rel in order:
        data, x = files[rel]
        target = root / rel
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_dir():
                continue
            target.write_bytes(data)
        except (NotADirectoryError, FileExistsError, IsADirectoryError):
            continue
        os.chmod(target, rng.choice([0o755, 0o711, 0o700]) if x else rng.choice([0o644, 0o600, 0o664, 0o640]))
        if noise:
            os.utime(target, (rng.randint(10**8, 2 * 10**9), rng.randint(10**8, 2 * 10**9)))
            for k in range(rng.randint(0, 2)):                    # menggeser nomor inode berikutnya
                (junk / f"j{rng.getrandbits(32)}-{k}").write_bytes(b"x")
    for rel in dirs:
        try:
            (root / rel).mkdir(parents=True, exist_ok=True)
        except (NotADirectoryError, FileExistsError):
            pass
    shutil.rmtree(junk, ignore_errors=True)


def mutate(work: Path, rng: random.Random) -> None:
    files = sorted(p for p in work.rglob("*") if p.is_file() and not p.is_symlink())
    for _ in range(rng.randint(1, 6)):
        op = rng.choice(["del", "mod", "x", "add", "adddir", "deldir", "swapdir"])
        if op == "del" and files:
            p = files.pop(rng.randrange(len(files)))
            if p.is_file():
                p.unlink()
        elif op == "mod" and files:
            p = rng.choice(files)
            if p.is_file():
                p.write_bytes(p.read_bytes() + bytes([rng.getrandbits(8)]))
        elif op == "x" and files:
            p = rng.choice(files)
            if p.is_file():
                os.chmod(p, (p.stat().st_mode ^ 0o111) & 0o777)
        elif op == "add":
            parts = [rng.choice(NAME_PARTS) for _ in range(rng.randint(0, 2))] + [rng.choice(LEAF_PARTS) + "-new"]
            try:
                put(work, "/".join(parts), bytes([rng.getrandbits(8)]) * rng.randint(0, 9))
            except (NotADirectoryError, FileExistsError, IsADirectoryError):
                pass
        elif op == "adddir":
            try:
                (work / rng.choice(NAME_PARTS) / (rng.choice(NAME_PARTS) + "-emptynew")).mkdir(parents=True, exist_ok=True)
            except (NotADirectoryError, FileExistsError):
                pass
        elif op == "deldir":
            empties = [p for p in work.rglob("*") if p.is_dir() and not any(p.iterdir())]
            if empties:
                rng.choice(empties).rmdir()
        elif op == "swapdir" and files:                           # berkas diganti direktori kosong dengan nama sama
            p = rng.choice(files)
            if p.is_file():
                p.unlink()
                p.mkdir()


# ================================================================ 1. kesetaraan byte payload dan pembanding independen
@pytest.mark.parametrize("seed", range(40))
def test_matches_independent_oracle_and_payload_bytes_equal_json_dumps(tmp_path, seed):
    """A-01: entri, urutan, `base`, dan hash == perhitungan independen (os.walk + json.dumps PENUH, dict berurutan, tanpa sort_keys)."""
    rng = random.Random(seed)
    base, work = tmp_path / "base", tmp_path / "work"
    materialize(base, rand_spec(rng), rng)
    shutil.copytree(base, work, symlinks=True)
    mutate(work, rng)
    got: list[list] = []
    res = T.compute_diff(base, work, collect=got)
    entries, base_hex, digest = oracle_diff(base, work)
    assert got == entries
    assert res.base_sha256 == base_hex == T.manifest_hash(base)
    assert res.diff_sha256 == digest
    payload = json.dumps({"v": 2, "e": got, "base": res.base_sha256}, separators=(",", ":"), ensure_ascii=True).encode()
    assert hashlib.sha256(payload).hexdigest() == res.diff_sha256
    assert res.entries_total == len(got) == sum(res.counts.values())
    assert [e[1] for e in got] == [e[1] for e in sorted(got, key=lambda e: (key_of(e[1]), e[0] == "A"))], "urutan harus urutan kunci komponen-byte"


def test_empty_trees_and_identical_trees(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    got: list[list] = []
    res = T.compute_diff(a, b, collect=got)
    assert got == [] and res.entries_total == 0 and res.base_entries == 0
    assert res.diff_sha256 == hashlib.sha256(b'{"v":2,"e":[],"base":"' + hashlib.sha256(b"").hexdigest().encode() + b'"}').hexdigest()
    mktree(a, {"x/y": "1", "z": "2"}), mktree(b, {"x/y": "1", "z": "2"})
    assert diff(a, b).entries_total == 0
    assert h(a, b) == h(a, a)


def test_non_ascii_and_non_utf8_names_serialize_deterministically(tmp_path):
    base, work = tmp_path / "base", tmp_path / "work"
    mktree(base, {"res/ok.txt": "1"})
    mktree(work, {"res/ok.txt": "1", "res/日本語.xml": "x", "res/emoji-😀.txt": "y"})
    put(work, "res/\udcff\udcfe.bin", b"z")                      # nama bukan UTF-8 (byte \xff\xfe) lewat surrogateescape
    got: list[list] = []
    res = T.compute_diff(base, work, collect=got)
    entries, _b, digest = oracle_diff(base, work)
    assert got == entries and res.diff_sha256 == digest and len(got) == 3
    assert all(m.isascii() for m in [json.dumps(e, ensure_ascii=True) for e in got])
    # ringkasan memakai nama yang bisa disimpan: tidak ada surrogate sisa (sqlite menolak teks itu)
    json.dumps(res.summary(), ensure_ascii=False).encode("utf-8")


# ================================================================ 2. properti hash
@pytest.mark.parametrize("seed", range(15))
def test_order_inode_mtime_and_non_x_modes_do_not_change_hash(tmp_path, seed):
    rng = random.Random(1000 + seed)
    spec = rand_spec(rng)
    base = tmp_path / "base"
    materialize(base, spec, random.Random(1))
    seen = set()
    for k in range(3):                                          # tiga materialisasi: urutan, inode, mtime, mode berbeda
        work = tmp_path / f"w{k}"
        materialize(work, spec, random.Random(100 + k))
        seen.add(h(base, work))
    assert len(seen) == 1
    seen_manifest = {T.manifest_hash(tmp_path / f"w{k}") for k in range(3)}
    assert len(seen_manifest) == 1


def test_one_byte_x_bit_extra_file_extra_empty_dir_each_change_hash(tmp_path):
    base = mktree(tmp_path / "base", {"a/f": "hello", "b": "x"})
    ref = mktree(tmp_path / "ref", {"a/f": "hello", "b": "x"})
    ref_hash = h(base, ref)
    assert ref_hash == h(base, ref)

    def variant(name, fn):
        w = mktree(tmp_path / name, {"a/f": "hello", "b": "x"})
        fn(w)
        return h(base, w)

    results = {
        "byte": variant("v1", lambda w: (w / "a/f").write_bytes(b"hellp")),
        "len": variant("v2", lambda w: (w / "a/f").write_bytes(b"hello!")),
        "x": variant("v3", lambda w: os.chmod(w / "a/f", 0o755)),
        "more": variant("v4", lambda w: put(w, "c", "")),
        "less": variant("v5", lambda w: (w / "b").unlink()),
        "emptydir": variant("v6", lambda w: (w / "e").mkdir()),
        "nested_emptydir": variant("v7", lambda w: (w / "a/e").mkdir()),
        "rename": variant("v8", lambda w: (w / "b").rename(w / "bb")),
    }
    assert ref_hash not in results.values()
    assert len(set(results.values())) == len(results), "setiap perubahan harus menghasilkan hash tersendiri"


def test_changing_only_a_base_file_changes_the_hash(tmp_path):
    """F-01: delta saja tidak cukup. Dua pasangan dengan diff IDENTIK (hanya A z) tetapi berkas dasar `a` berbeda harus berhash beda."""
    def pair(tag, a_content):
        base = mktree(tmp_path / f"base{tag}", {"a": a_content, "b": "2"})
        work = mktree(tmp_path / f"work{tag}", {"a": a_content, "b": "2", "z": "new"})
        return base, work

    (b1, w1), (b2, w2), (b3, w3) = pair(1, "1"), pair(2, "CHANGED-BASE"), pair(3, "1")
    assert entries_of(b1, w1) == entries_of(b2, w2) != []
    assert h(b1, w1) != h(b2, w2)
    assert h(b1, w1) == h(b3, w3), "kontrol: isi yang sama -> hash sama"


def test_mutation_in_place_with_same_size_and_mtime_changes_hash_and_revert_restores(tmp_path):
    base = mktree(tmp_path / "base", {"a": "aaaa"})
    work = mktree(tmp_path / "work", {"a": "aaaa", "f": "12345678"})
    before = h(base, work)
    st = (work / "f").stat()
    (work / "f").write_bytes(b"12345679")                       # ukuran sama
    os.utime(work / "f", ns=(st.st_atime_ns, st.st_mtime_ns))   # mtime sama
    mutated = h(base, work)
    assert mutated != before
    (work / "f").write_bytes(b"12345678")
    assert h(base, work) == before


def test_case_and_unicode_normalization_distinguish_entries(tmp_path):
    base = mktree(tmp_path / "base", {})
    work = mktree(tmp_path / "work", {"A.txt": "1", "a.txt": "1"})
    got = entries_of(base, work)
    assert [e[1] for e in got] == ["A.txt", "a.txt"]
    nfc, nfd = unicodedata.normalize("NFC", "é.txt"), unicodedata.normalize("NFD", "é.txt")
    assert nfc != nfd
    w2 = mktree(tmp_path / "w2", {nfc: "1", nfd: "1"})
    assert [e[1] for e in entries_of(base, w2)] == sorted([nfc, nfd], key=lambda s: os.fsencode(s))
    assert h(base, w2) != h(base, mktree(tmp_path / "w3", {nfc: "1"}))


def test_walk_order_is_per_component_bytes_not_whole_path_string(tmp_path):
    """F-02: DFS memberi `res/values/x` < `res/values-v21/y` (kunci komponen), kebalikan urutan string karena '/' > '-'."""
    files = {"res/values/strings.xml": "a", "res/values/colors.xml": "e", "res/values-v21/styles.xml": "b", "res/layout/a.xml": "c",
             "res/layout/b.xml": "f", "res/layout-land/a.xml": "d"}
    base = mktree(tmp_path / "base", files)

    def run(name, change):
        w = mktree(tmp_path / name, files)
        change(w)
        return entries_of(base, w)

    assert run("w0", lambda w: None) == []
    only_r = run("w1", lambda w: (w / "res/values/strings.xml").unlink())
    assert [(e[0], e[1]) for e in only_r] == [("R", "res/values/strings.xml")]
    only_m = run("w2", lambda w: (w / "res/values-v21/styles.xml").write_text("B2"))
    assert [(e[0], e[1]) for e in only_m] == [("M", "res/values-v21/styles.xml")]
    only_a = run("w3", lambda w: put(w, "res/values/new.xml", "n"))
    assert [(e[0], e[1]) for e in only_a] == [("A", "res/values/new.xml")]
    many = run("w4", lambda w: [(w / "res/layout/a.xml").unlink(), put(w, "res/layout-land/b.xml", "x"), put(w, "res/layout/0", "y")])
    assert [(e[0], e[1]) for e in many] == [("A", "res/layout/0"), ("R", "res/layout/a.xml"), ("A", "res/layout-land/b.xml")]


@pytest.mark.parametrize("seed", range(10))
def test_shared_prefix_names_with_dash_dot_space_give_exactly_one_removal(tmp_path, seed):
    rng = random.Random(7000 + seed)
    stems = ["v", "v-1", "v.1", "v 1", "v_1", "v1", "V"]
    files = {f"{d}/{rng.choice(['a', 'b', 'a-b'])}{i}.xml": str(i) for i, d in enumerate(rng.choices(stems, k=25))}
    base = mktree(tmp_path / "base", files)
    for n, victim in enumerate(rng.sample(sorted(files), 5)):
        w = mktree(tmp_path / f"w{n}", files)
        (w / victim).unlink()
        parent = (w / victim).parent
        if not any(parent.iterdir()):
            parent.rmdir()                                       # direktori yang jadi kosong ikut hilang (di dasar ia berisi)
        got = entries_of(base, w)
        assert [(e[0], e[1]) for e in got] == [("R", victim)], got


# ================================================================ 3. entri khusus, direktori, penyaringan
def specials(root: Path) -> None:
    """symlink ke berkas/direktori/jalur luar/menggantung/berputar, FIFO, soket (+ perangkat bila mungkin)."""
    (root / "tgt").mkdir()
    (root / "tgt/secret").write_text("secret")
    os.symlink("tgt/secret", root / "ln-file")
    os.symlink("tgt", root / "ln-dir")
    os.symlink("/etc", root / "ln-etc")
    os.symlink("nowhere", root / "ln-dangling")
    os.symlink("ln-loop", root / "ln-loop")
    os.mkfifo(root / "fifo")
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(root / "sock"))
    s.close()
    try:
        os.mknod(root / "dev", stat.S_IFCHR | 0o600, os.makedev(1, 3))
    except OSError:
        pass


def test_special_entries_are_ignored_counted_and_never_hang(tmp_path):
    base = mktree(tmp_path / "base", {"tgt/secret": "secret"})
    work = mktree(tmp_path / "work", {"keep": "k"})
    specials(work)
    ref = mktree(tmp_path / "ref", {"keep": "k", "tgt/secret": "secret"})
    with within(10):
        res = diff(base, work)
        res_ref = diff(base, ref)
    got = entries_of(base, work)
    assert [e[1] for e in got] == ["keep"], "hanya berkas biasa; symlink ke sasaran tidak diikuti"
    assert res.skipped["symlink"] == 5 and res.skipped["special"] >= 2          # fifo + soket (+ perangkat)
    assert res_ref.skipped == {"symlink": 0, "special": 0, "root_ignored": 0, "vanished": 0}
    # tgt/secret ada di kerja juga (tidak diubah) sehingga diff hanya 'keep'; hash == pohon tanpa entri khusus
    clean = mktree(tmp_path / "clean", {"keep": "k", "tgt/secret": "secret"})
    assert res.diff_sha256 == h(base, clean)


def test_symlinked_dir_contents_are_not_read_even_when_link_replaces_a_tree(tmp_path):
    outside = mktree(tmp_path / "outside", {"leak.txt": "TOPSECRET"})
    base = mktree(tmp_path / "base", {"a": "1"})
    work = mktree(tmp_path / "work", {"a": "1"})
    os.symlink(outside, work / "res")
    assert entries_of(base, work) == []
    snap = tmp_path / "snap"
    T.copy_tree_safe(work, snap)
    assert sorted(p.name for p in snap.iterdir()) == ["a"] and not list(snap.rglob("leak.txt"))
    os.symlink(outside, tmp_path / "rootlink")                  # akar sendiri symlink -> ditolak (O_NOFOLLOW), tidak diikuti
    with pytest.raises(T.TreeLimitError) as ei:
        T.manifest_hash(tmp_path / "rootlink")
    assert ei.value.code == "unreadable"


def test_missing_root_is_unreadable_not_a_crash(tmp_path):
    with pytest.raises(T.TreeLimitError) as ei:
        diff(tmp_path / "nope", tmp_path)
    assert ei.value.code == "unreadable"
    assert str(tmp_path) not in ei.value.message, "pesan galat tidak membocorkan jalur absolut"


def test_fifo_named_x_does_not_hang_and_swapped_in_fifo_or_symlink_is_skipped(tmp_path, monkeypatch):
    base = mktree(tmp_path / "base", {})
    work = mktree(tmp_path / "work", {"ok": "1"})
    os.mkfifo(work / "x")
    with within(5):
        assert [e[1] for e in entries_of(base, work)] == ["ok"]
    os.unlink(work / "x")
    real_stat = os.stat

    def swap_after_stat(kind):
        done = []

        def fake(path, *a, **kw):
            res = real_stat(path, *a, **kw)
            if path == "victim" and kw.get("dir_fd") is not None and not done:
                done.append(1)
                os.unlink("victim", dir_fd=kw["dir_fd"])
                if kind == "fifo":
                    os.mkfifo("victim", dir_fd=kw["dir_fd"])
                elif kind == "symlink":
                    os.symlink("ok", "victim", dir_fd=kw["dir_fd"])
            return res
        return fake

    for kind, field in (("fifo", "special"), ("symlink", "vanished")):
        put(work, "victim", "data")
        monkeypatch.setattr(os, "stat", swap_after_stat(kind))
        try:
            with within(5):
                res = diff(base, work)
        finally:
            monkeypatch.setattr(os, "stat", real_stat)
        assert res.skipped[field] == 1 and [e[1] for e in entries_of(base, work)] == ["ok"], kind
        for p in (work / "victim",):
            if p.is_symlink() or p.exists():
                p.unlink()


def test_dir_swapped_for_symlink_between_stat_and_open_is_not_followed(tmp_path, monkeypatch):
    outside = mktree(tmp_path / "outside", {"leak.txt": "TOPSECRET"})
    base = mktree(tmp_path / "base", {})
    work = mktree(tmp_path / "work", {"ok": "1", "d/f": "2"})
    real_stat = os.stat
    done = []

    def fake(path, *a, **kw):
        res = real_stat(path, *a, **kw)
        if path == "d" and kw.get("dir_fd") is not None and not done:
            done.append(1)
            shutil.rmtree(work / "d")
            os.symlink(outside, work / "d")
        return res
    monkeypatch.setattr(os, "stat", fake)
    try:
        got: list[list] = []
        res = T.compute_diff(base, work, collect=got)
    finally:
        monkeypatch.setattr(os, "stat", real_stat)
    assert [e[1] for e in got] == ["ok"] and res.skipped["vanished"] == 1


def test_directory_empty_means_scandir_empty_and_filtered_dirs_are_not_emitted(tmp_path):
    """A-16: dir kosong dicatat; dir yang isinya habis difilter (symlink/FIFO/build akar) tidak dicatat dan tidak dibuat saat salin."""
    base = mktree(tmp_path / "base", {"k": "1"})
    work = mktree(tmp_path / "work", {"k": "1"}, empty_dirs=("empty", "nest/empty2"))
    (work / "onlylink").mkdir()
    os.symlink("k", work / "onlylink/l")
    (work / "onlyfifo/deeper").mkdir(parents=True)
    os.mkfifo(work / "onlyfifo/deeper/f")
    (work / "withbuild").mkdir()
    os.makedirs(work / "build/apk")
    (work / "build/apk/classes.dex").write_bytes(b"PLANTED")
    got = entries_of(base, work)
    assert [(e[0], e[1], e[2]) for e in got] == [("A", "empty", "d"), ("A", "nest/empty2", "d"), ("A", "withbuild", "d")]
    snap = tmp_path / "snap"
    stats = T.copy_tree_safe(work, snap)
    assert sorted(str(p.relative_to(snap)) for p in snap.rglob("*")) == ["empty", "k", "nest", "nest/empty2", "withbuild"]
    assert not (snap / "onlylink").exists() and not (snap / "onlyfifo").exists() and not (snap / "build").exists()
    assert stats.dirs == 4 and stats.files == 1 and stats.skipped_symlink == 1 and stats.skipped_special == 1 and stats.root_ignored == 1
    assert h(base, snap) == h(base, work), "hash pohon hidup == hash snapshot"


def test_root_build_and_dist_are_ignored_but_not_at_other_depths(tmp_path):
    base = mktree(tmp_path / "base", {"a": "1"})
    work = mktree(tmp_path / "work", {"a": "1", "build/apk/classes.dex": "PLANTED", "dist/x.apk": "y", "res/build/keep.txt": "k",
                                      "smali/dist/Foo.smali": "z"})
    got = entries_of(base, work)
    assert [e[1] for e in got] == ["res/build/keep.txt", "smali/dist/Foo.smali"]
    res = diff(base, work)
    assert res.skipped["root_ignored"] == 2
    base_with = mktree(tmp_path / "base2", {"a": "1", "build/old": "o"})
    assert entries_of(base_with, base) == [], "build/ juga diabaikan di pohon DASAR"
    assert h(base, work) == h(base, mktree(tmp_path / "w2", {"a": "1", "res/build/keep.txt": "k", "smali/dist/Foo.smali": "z"}))
    assert T.manifest_hash(mktree(tmp_path / "bx", {"a": "1", "Build/x": "1"})) != T.manifest_hash(mktree(tmp_path / "by", {"a": "1"})), "'Build' bukan 'build'"
    file_build = mktree(tmp_path / "fb", {"a": "1", "build": "i am a file"})
    assert T.manifest_hash(file_build) == T.manifest_hash(mktree(tmp_path / "fc", {"a": "1"}))


def test_live_tree_hash_equals_runner_snapshot_hash(tmp_path):
    """Bench menghitung atas pohon HIDUP, runner atas snapshot hasil copy_tree_safe: hash HARUS sama (termasuk entri khusus dan build/)."""
    rng = random.Random(42)
    base = tmp_path / "base"
    materialize(base, rand_spec(rng), rng)
    work = tmp_path / "work"
    shutil.copytree(base, work)
    mutate(work, rng)
    specials(work)
    os.makedirs(work / "build/apk")
    (work / "build/apk/classes.dex").write_bytes(b"PLANTED")
    os.chmod(work / "build", 0o700)
    live = diff(base, work)
    snap = tmp_path / "snap"
    stats = T.copy_tree_safe(work, snap)
    assert diff(base, snap).diff_sha256 == live.diff_sha256
    assert diff(base, snap).entries_total == live.entries_total
    assert stats.skipped_symlink == live.skipped["symlink"] and stats.skipped_special == live.skipped["special"] and stats.root_ignored == 1
    assert T.manifest_hash(snap) == T.manifest_hash(work)


# ================================================================ 4. batas
def test_default_limits_are_the_documented_ones():
    lim = T.Limits()
    assert (lim.max_entries, lim.max_total_bytes, lim.max_file_bytes, lim.max_depth, lim.max_name_bytes, lim.max_path_bytes) == (
        600_000, 3 * 1024 ** 3, 1024 ** 3, 64, 255, 1024)
    assert T.ROOT_IGNORE == ("build", "dist")
    assert set(T.ERROR_CODES) == {"too_many_entries", "too_large", "file_too_large", "too_deep", "name_too_long", "unreadable", "timeout", "cancelled"}


def code_of(fn, *a, **kw) -> str:
    before = open_fds()
    with pytest.raises(T.TreeLimitError) as ei:
        fn(*a, **kw)
    assert open_fds() == before, "fd bocor setelah galat"
    return ei.value.code


def test_entry_limit_counts_every_name_and_is_per_tree(tmp_path):
    files = {"f1": "1", "f2": "2", "f3": "3", "d/g1": "4", "d/g2": "5"}                 # f1 f2 f3 d g1 g2 = 6 entri
    a, b = mktree(tmp_path / "a", files), mktree(tmp_path / "b", files)
    assert diff(a, b, T.Limits(max_entries=6)).entries_total == 0, "dasar di batas + kerja di batas -> lolos (batas PER pohon)"
    assert code_of(diff, a, b, T.Limits(max_entries=5)) == "too_many_entries"
    ignored = mktree(tmp_path / "c", {"f1": "1", "build/x": "y"})
    assert code_of(T.manifest_hash, ignored, T.Limits(max_entries=1)) == "too_many_entries", "entri yang diabaikan tetap dihitung"
    big = tmp_path / "big"
    big.mkdir()
    for i in range(3000):
        (big / f"f{i}").write_bytes(b"")
    assert code_of(T.manifest_hash, big, T.Limits(max_entries=2999)) == "too_many_entries"
    assert code_of(T.copy_tree_safe, big, tmp_path / "bigcopy", T.Limits(max_entries=2999)) == "too_many_entries"


def test_total_and_per_file_byte_limits(tmp_path, monkeypatch):
    t = mktree(tmp_path / "t", {"a": "0123456789", "b": "0123456789", "c": "0123456789"})
    assert T.manifest_hash(t, T.Limits(max_total_bytes=30))
    assert code_of(T.manifest_hash, t, T.Limits(max_total_bytes=29)) == "too_large"
    assert T.manifest_hash(t, T.Limits(max_file_bytes=10))
    assert code_of(T.manifest_hash, t, T.Limits(max_file_bytes=9)) == "file_too_large"
    assert code_of(T.copy_tree_safe, t, tmp_path / "c1", T.Limits(max_total_bytes=29)) == "too_large"
    sparse = mktree(tmp_path / "s", {"small": "1"})
    with open(sparse / "huge", "wb") as fh:
        fh.truncate(2 * 1024 ** 3)                                                         # sparse: tidak boleh dibaca sampai habis
    def must_not_read(*a, **kw):
        raise AssertionError("berkas di atas batas tidak boleh dibaca")
    monkeypatch.setattr(T, "_read_chunk", must_not_read)
    with within(5):
        assert code_of(T.manifest_hash, sparse) == "file_too_large"
        assert code_of(T.copy_tree_safe, sparse, tmp_path / "sparse-copy") == "file_too_large"


def test_depth_name_and_path_length_limits_are_in_bytes(tmp_path):
    t = mktree(tmp_path / "t", {"a/b/c/f": "1"})
    assert T.manifest_hash(t, T.Limits(max_depth=3))
    assert code_of(T.manifest_hash, mktree(tmp_path / "t2", {"a/b/c/d/f": "1"}), T.Limits(max_depth=3)) == "too_deep"
    assert T.manifest_hash(mktree(tmp_path / "n1", {"x" * 10: "1"}), T.Limits(max_name_bytes=10))
    assert code_of(T.manifest_hash, mktree(tmp_path / "n2", {"x" * 11: "1"}), T.Limits(max_name_bytes=10)) == "name_too_long"
    assert T.manifest_hash(mktree(tmp_path / "n3", {"é" * 5: "1"}), T.Limits(max_name_bytes=10))
    assert code_of(T.manifest_hash, mktree(tmp_path / "n4", {"é" * 6: "1"}), T.Limits(max_name_bytes=10)) == "name_too_long", "byte, bukan karakter"
    assert T.manifest_hash(mktree(tmp_path / "n5", {"x" * 255: "1"})), "255 byte (NAME_MAX) lolos pada batas bawaan"
    assert code_of(T.manifest_hash, mktree(tmp_path / "p1", {"aaaaaaaaaa/bbbbbbbbbb.txt": "1"}), T.Limits(max_path_bytes=20)) == "name_too_long"
    assert T.manifest_hash(mktree(tmp_path / "p2", {"aaaaaaaaaa/bbbbbbbbbb.txt": "1"}), T.Limits(max_path_bytes=25))
    deep = tmp_path / "deep"
    deep.mkdir()
    cur = deep
    for _ in range(64):
        cur = cur / "d"
        cur.mkdir()
    (cur / "f").write_text("1")
    assert T.manifest_hash(deep), "kedalaman 64 (bawaan) lolos"
    (cur / "d").mkdir()
    (cur / "d/f").write_text("1")
    assert code_of(T.manifest_hash, deep) == "too_deep"


def test_large_tree_is_hashed_and_copied_within_limits_and_hashes_match(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    for i in range(30):
        for j in range(100):
            put(base, f"d{i:02d}/f{j:03d}.txt", f"{i}-{j}")
    work = tmp_path / "work"
    shutil.copytree(base, work)
    put(work, "d05/f007.txt", "changed")
    res = diff(base, work)
    assert res.entries_total == 1 and res.base_entries == 3000
    snap = tmp_path / "snap"
    assert T.copy_tree_safe(work, snap).files == 3000
    assert h(base, snap) == res.diff_sha256


# ================================================================ 5. salin aman
def test_copy_modes_are_deterministic_and_independent_of_umask_and_source_mode(tmp_path):
    src = tmp_path / "src"
    mktree(src, {"plain": "1", "ro": "2", "none": "3", "run": "4", "d/sub/f": "5"}, empty_dirs=("e",))
    os.chmod(src / "ro", 0o444), os.chmod(src / "none", 0o000 if os.geteuid() == 0 else 0o400), os.chmod(src / "run", 0o700), os.chmod(src / "d", 0o500)
    os.utime(src / "plain", (1_000_000_000, 1_000_000_000))
    old = os.umask(0o077)
    try:
        stats = T.copy_tree_safe(src, tmp_path / "dst")
    finally:
        os.umask(old)
        os.chmod(src / "d", 0o755)
    dst = tmp_path / "dst"
    modes = {str(p.relative_to(dst)): stat.S_IMODE(p.stat().st_mode) for p in [dst, *dst.rglob("*")]}
    assert modes["."] == 0o755 and modes["d"] == 0o755 and modes["d/sub"] == 0o755 and modes["e"] == 0o755
    assert modes["plain"] == modes["ro"] == modes["none"] == modes["d/sub/f"] == 0o644 and modes["run"] == 0o755
    assert (dst / "plain").stat().st_mtime > 1_500_000_000, "mtime tidak dipertahankan"
    assert (stats.files, stats.dirs, stats.bytes) == (5, 3, 5)
    assert (dst / "none").read_text() == "3"


def test_copy_refuses_existing_destination_and_leaves_it_untouched(tmp_path):
    src = mktree(tmp_path / "src", {"a": "1"})
    dst = mktree(tmp_path / "dst", {"keep": "k"})
    with pytest.raises(FileExistsError):
        T.copy_tree_safe(src, dst)
    assert sorted(p.name for p in dst.iterdir()) == ["keep"]
    os.symlink(tmp_path, tmp_path / "linkdst")
    with pytest.raises(FileExistsError):
        T.copy_tree_safe(src, tmp_path / "linkdst")


def test_copy_never_follows_symlinks_and_drops_special_entries(tmp_path):
    outside = mktree(tmp_path / "outside", {"leak.txt": "TOPSECRET"})
    src = mktree(tmp_path / "src", {"a": "1"})
    specials(src)
    os.symlink(outside, src / "linkdir")
    stats = T.copy_tree_safe(src, tmp_path / "dst")
    assert sorted(p.name for p in (tmp_path / "dst").rglob("*")) == ["a", "secret", "tgt"]
    assert not [p for p in (tmp_path / "dst").rglob("*") if p.is_symlink()]
    assert stats.skipped_symlink == 6 and stats.skipped_special >= 2


def test_copy_error_midway_leaves_partial_dst_for_the_caller_and_leaks_no_fd(tmp_path):
    src = mktree(tmp_path / "src", {"a/1": "1", "a/2": "2", "b/3": "3"})
    calls = []

    def cancel():
        calls.append(1)
        raise T.TreeLimitError("cancelled", "dibatalkan")
    big = tmp_path / "big"
    big.mkdir()
    for i in range(1500):
        (big / f"f{i}").write_bytes(b"x")
    before = open_fds()
    with pytest.raises(T.TreeLimitError) as ei:
        T.copy_tree_safe(big, tmp_path / "dst", on_tick=cancel)
    assert ei.value.code == "cancelled" and calls
    assert (tmp_path / "dst").is_dir() and 0 < len(os.listdir(tmp_path / "dst")) < 1500, "setengah jadi dibiarkan untuk pemanggil"
    assert open_fds() == before
    shutil.rmtree(tmp_path / "dst")
    assert T.copy_tree_safe(src, tmp_path / "dst2").files == 3


# ================================================================ 6. detak, tenggat, rekursi
def test_on_tick_fires_by_entries_and_by_time_and_may_abort(tmp_path, monkeypatch):
    big = tmp_path / "big"
    big.mkdir()
    for i in range(2500):
        (big / f"f{i}").write_bytes(b"")
    monkeypatch.setattr(T, "_clock", lambda: 0.0)               # tanpa waktu: hanya hitungan entri yang memicu
    ticks = []
    T.manifest_hash(big, on_tick=lambda: ticks.append(1))
    assert len(ticks) == 2, "tiap 1000 entri"
    small = mktree(tmp_path / "small", {f"f{i}": "x" for i in range(10)})
    clock = {"t": 0.0}

    def fake_clock():
        clock["t"] += 1.0                                       # tiap panggilan jam = 1 dtk berlalu
        return clock["t"]
    monkeypatch.setattr(T, "_clock", fake_clock)
    seen = []
    T.manifest_hash(small, on_tick=lambda: seen.append(clock["t"]))
    assert seen, "detak berdasarkan waktu walau entri sedikit"
    gaps = [b - a for a, b in zip([0.0, *seen], seen)]
    assert max(gaps) <= T.TICK_SECONDS + 2.0, "jeda antar-detak dibatasi (A-07: <= 5 dtk nyata)"


def test_on_tick_timeout_and_cancel_abort_diff_and_copy_without_leaking_fds(tmp_path):
    big = tmp_path / "big"
    big.mkdir()
    for i in range(1200):
        (big / f"f{i}").write_bytes(b"")
    other = mktree(tmp_path / "other", {})

    def stop(code):
        def tick():
            raise T.TreeLimitError(code, "stop")
        return tick
    for code in ("timeout", "cancelled"):
        assert code_of(T.compute_diff, other, big, T.Limits(), on_tick=stop(code)) == code
        assert code_of(T.compute_diff, big, other, T.Limits(), on_tick=stop(code)) == code
        assert code_of(T.copy_tree_safe, big, tmp_path / f"c-{code}", T.Limits(), on_tick=stop(code)) == code


def test_recursion_error_is_converted_not_leaked(tmp_path, monkeypatch):
    t = mktree(tmp_path / "t", {"a/b": "1"})

    def boom(*a, **kw):
        raise RecursionError("maximum recursion depth exceeded")
        yield  # pragma: no cover
    monkeypatch.setattr(T, "_walk_dir", boom)
    assert code_of(T.compute_diff, t, t) == "too_deep"
    assert code_of(T.copy_tree_safe, t, tmp_path / "dst") == "too_deep"
    assert code_of(T.manifest_hash, t) == "too_deep"


def test_really_deep_tree_hits_python_recursion_and_becomes_too_deep(tmp_path):
    deep = tmp_path / "deep"
    deep.mkdir()
    fd = os.open(deep, os.O_RDONLY | os.O_DIRECTORY)
    for _ in range(300):
        os.mkdir("d", dir_fd=fd)
        nfd = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
        os.close(fd)
        fd = nfd
    os.close(fd)
    lim = T.Limits(max_depth=10 ** 6, max_path_bytes=10 ** 9)
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(len(traceback.extract_stack()) + 150)
    try:
        assert code_of(T.manifest_hash, deep, lim) == "too_deep"
        assert code_of(T.compute_diff, deep, deep, lim) == "too_deep"
    finally:
        sys.setrecursionlimit(old)
    shutil.rmtree(deep, ignore_errors=True)


# ================================================================ 7. ringkasan
def depth_of(obj) -> int:
    if isinstance(obj, dict):
        return 1 + max((depth_of(v) for v in obj.values()), default=0)
    if isinstance(obj, list):
        return 1 + max((depth_of(v) for v in obj), default=0)
    return 0


def test_summary_counts_kinds_bytes_and_text_lines(tmp_path):
    base = mktree(tmp_path / "base", {
        "AndroidManifest.xml": "<m/>\n", "res/values/strings.xml": "a\nb\nc\n", "smali/A.smali": "1\n2\n", "smali_classes2/B.smali": "x\n",
        "assets/gone.txt": "g1\ng2\ng3\n", "lib/arm64/x.so": b"\x00\x01\x02", "other.txt": "o\n"})
    work = mktree(tmp_path / "work", {
        "AndroidManifest.xml": "<m/>\n", "res/values/strings.xml": "a\nB\nc\nd\n", "smali/A.smali": "1\n2\n", "smali_classes2/B.smali": "x\n",
        "lib/arm64/x.so": b"\x00\x09\x02\x03", "other.txt": "o\n", "assets/new.txt": "n1\nn2\n", "res/raw/blob.bin": b"\x00" * 50})
    res = diff(base, work)
    assert res.counts == {"added": 2, "modified": 2, "removed": 1}
    assert res.entries_total == 5 and res.base_entries == 7
    assert res.kinds == {"smali": 0, "res": 2, "manifest": 0, "aset": 2, "lib": 1, "lain": 0}
    assert res.byte_totals == {"added": 6 + 50, "modified": 8 + 4, "removed": 9}
    assert res.lines["plus"] == 2 + 2 and res.lines["minus"] == 1 + 3, "strings.xml +B +d -b; assets/new +2; gone -3"
    assert res.lines["files"] == 3 and res.lines["skipped_files"] == 2, "x.so dan blob.bin tampak biner"
    top = {t["path"]: t for t in res.top}
    assert top["res/values/strings.xml"]["plus"] == 2 and top["res/values/strings.xml"]["minus"] == 1
    assert top["lib/arm64/x.so"]["plus"] is None
    assert res.top[0]["path"] == "res/raw/blob.bin", "urut |delta ukuran| menurun"
    no_lines = T.compute_diff(base, work, text_stats=False)
    assert no_lines.lines == {"plus": 0, "minus": 0, "files": 0, "skipped_files": 0} and no_lines.diff_sha256 == res.diff_sha256, "baris di luar hash"


def test_summary_top_is_sorted_by_abs_delta_then_path_and_truncated(tmp_path):
    base = mktree(tmp_path / "base", {})
    work = mktree(tmp_path / "work", {f"f{i:02d}": "x" * (i % 7) for i in range(60)})
    res = diff(base, work)
    assert len(res.top) == T.TOP_MAX and res.truncated
    keyed = [(-t["size"], t["path"]) for t in res.top]
    assert keyed == sorted(keyed)
    assert res.top[0]["size"] == 6 and res.top[0]["path"] == "f06"
    assert not diff(base, mktree(tmp_path / "w2", {"a": "1"})).truncated


def test_summary_fits_the_store_limit_even_with_worst_case_paths(tmp_path):
    base = mktree(tmp_path / "base", {})
    w = tmp_path / "work"
    pieces = ["a" * 100, "b" * 100, "c" * 90]
    for i in range(70):
        put(w, "/".join([*pieces, f"{i:03d}.txt"]), "x" * (i + 1))
    res = diff(base, w)
    assert max(len(t["path"]) for t in res.top) == 300
    summary = res.summary()
    text = json.dumps(summary, sort_keys=True, ensure_ascii=False)
    assert len(text) <= T.SUMMARY_MAX_CHARS < store.BUILD_SUMMARY_MAX
    assert summary["truncated"] and 0 < len(summary["top"]) < T.TOP_MAX
    assert [t["size"] for t in summary["top"]] == [t["size"] for t in res.top[:len(summary["top"])]], "pemotongan menyisakan yang terbesar"
    assert depth_of(summary) <= 4
    assert res.summary(max_chars=400)["top"] == [] and res.summary(max_chars=400)["truncated"] is True
    with pytest.raises(ValueError):
        res.summary(max_chars=50)


def test_summary_is_flat_plain_json_and_safe_to_store(tmp_path):
    base = mktree(tmp_path / "base", {"a": "1"})
    work = mktree(tmp_path / "work", {"a": "2", "bad\nname\u202e.txt": "x"})
    put(work, "z\udcff.bin", b"1")
    summary = diff(base, work).summary()
    assert set(summary) == {"v", "counts", "bytes", "kinds", "lines", "skipped", "top", "truncated"} and summary["v"] == 1
    assert depth_of(summary) <= 4
    json.dumps(summary, ensure_ascii=False).encode("utf-8")
    shown = [t["path"] for t in summary["top"]]
    assert not [p for p in shown if "\n" in p or "\u202e" in p or "\udcff" in p], shown


# ================================================================ 8. dapat dimuat dari semua tempat rvcore dipakai
def test_module_is_stdlib_only_and_loads_without_site_packages():
    tree = ast.parse((SERVICES / "rvcore/treediff.py").read_text())
    mods = {n.names[0].name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)}
    mods |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module and n.level == 0}
    assert mods <= set(sys.stdlib_module_names), mods - set(sys.stdlib_module_names)
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level > 0], "tidak mengimpor modul rvcore lain"
    out = subprocess.run([sys.executable, "-S", "-c", f"import sys; sys.path.insert(0, {str(SERVICES)!r}); import rvcore.treediff as t; print(t.Limits().max_entries)"],
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0 and out.stdout.strip() == "600000", out.stderr


def test_every_image_that_uses_rvcore_copies_the_whole_package():
    """Tidak ada daftar COPY per berkas untuk rvcore: treediff.py ikut otomatis di image bench, runner, worker, web, dan signer."""
    users = {}
    for df in sorted((SERVICES).glob("*/Dockerfile")):
        lines = [ln.strip() for ln in df.read_text().splitlines() if re.match(r"\s*COPY\b.*rvcore", ln)]
        if lines:
            users[df.parent.name] = lines
    assert set(users) == {"bench", "runner", "signer", "web", "worker"}, users
    assert all(lines == ["COPY rvcore ./rvcore"] for lines in users.values()), users
    ignore = (SERVICES / ".dockerignore").read_text().split()
    assert not [p for p in ignore if p.endswith(".py") or "rvcore" in p or "treediff" in p], ignore
    compose = (ROOT / "docker-compose.yml").read_text()
    assert compose.count("context: ./services") >= 5


# ================================================================ 9. uid 10001 / non-pemilik / ro / tmpfs noexec
_SETPRIV, _UNSHARE = shutil.which("setpriv"), shutil.which("unshare")
_REAL_PY = os.path.realpath(os.path.join(sys.base_prefix, "bin", f"python{sys.version_info.major}.{sys.version_info.minor}"))
_LIB = os.path.join(os.path.dirname(os.path.dirname(_REAL_PY)), "lib")
_ENV = ["env", "-i", "PATH=/usr/bin:/bin", f"LD_LIBRARY_PATH={_LIB}", "PYTHONDONTWRITEBYTECODE=1", f"PYTHONPATH={SERVICES}"]
_AS_10001 = [_SETPRIV, "--reuid=10001", "--regid=10001", "--clear-groups", *_ENV, _REAL_PY] if _SETPRIV else []

_SCRIPT = textwrap.dedent('''
    import dataclasses, json, sys
    from rvcore import treediff as T
    mode, base, work, dst = sys.argv[1:5]
    out = {}
    try:
        if mode in ("diff", "both"):
            r = T.compute_diff(base, work)
            out["diff"], out["skipped"], out["entries"] = r.diff_sha256, r.skipped, r.entries_total
        if mode in ("copy", "both"):
            out["copy"] = dataclasses.asdict(T.copy_tree_safe(work, dst))
        if mode == "both":
            out["snap"] = T.compute_diff(base, dst).diff_sha256
    except T.TreeLimitError as e:
        out["error"], out["message"] = e.code, e.message
    except OSError as e:
        out["oserror"] = type(e).__name__
    print(json.dumps(out))
''')


def _can_drop() -> bool:
    if os.geteuid() != 0 or not _SETPRIV:
        return False
    try:
        r = subprocess.run([*_AS_10001, "-c", "import sys, rvcore.treediff; sys.exit(0 if sys.version_info >= (3, 12) and __import__('os').getuid() == 10001 else 1)"],
                           capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


_CAN_DROP = _can_drop()
need_uid = pytest.mark.skipif(not _CAN_DROP, reason="butuh root + setpriv + interpreter yang bisa dijalankan uid 10001 (izin diabaikan bagi root)")


@pytest.fixture
def shared():
    """Folder yang bisa dilintasi uid 10001 (tmp_path pytest berizin 0700), dibuat/dihapus root."""
    d = Path(tempfile.mkdtemp(prefix="rv-treediff-"))
    d.chmod(0o755)
    (d / "run.py").write_text(_SCRIPT)
    (d / "run.py").chmod(0o644)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def run_user(shared: Path, mode: str, base: Path, work: Path, dst: Path, *, wrap: list[str] | None = None, timeout: int = 60) -> dict:
    cmd = [*(wrap or []), *_AS_10001, str(shared / "run.py"), mode, str(base), str(work), str(dst)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    assert r.returncode == 0, (r.stdout, r.stderr)
    return json.loads(r.stdout.strip().splitlines()[-1])


def root_owned_pair(shared: Path) -> tuple[Path, Path]:
    base = mktree(shared / "base", {"res/values/strings.xml": "a\n", "smali/A.smali": "1\n"})
    work = mktree(shared / "work", {"res/values/strings.xml": "b\n", "smali/A.smali": "1\n", "assets/new.txt": "n\n"})
    os.chmod(work / "assets/new.txt", 0o755)
    os.mkfifo(work / "fifo", 0o666)
    os.symlink("/etc/passwd", work / "pw")
    os.makedirs(work / "build/apk")
    return base, work


@need_uid
def test_uid10001_reads_root_owned_tree_with_fifo_and_symlink_and_copies_into_its_own_dir(shared):
    base, work = root_owned_pair(shared)
    dstparent = shared / "dstp"
    dstparent.mkdir()
    os.chown(dstparent, 10001, 10001)
    with within(40):
        out = run_user(shared, "both", base, work, dstparent / "snap")
    assert out["skipped"] == {"symlink": 1, "special": 1, "root_ignored": 1, "vanished": 0}
    assert out["diff"] == out["snap"] == h(base, work), "hash identik untuk root dan uid 10001, hidup dan snapshot"
    assert out["copy"]["files"] == 3 and out["copy"]["skipped_special"] == 1
    snap = dstparent / "snap"
    st = {str(p.relative_to(snap)): (p.stat().st_uid, stat.S_IMODE(p.stat().st_mode)) for p in snap.rglob("*")}
    assert st["assets/new.txt"] == (10001, 0o755) and st["res/values/strings.xml"] == (10001, 0o644) and st["res"] == (10001, 0o755)


@need_uid
def test_uid10001_gets_fail_closed_unreadable_for_mode600_file_and_mode700_dir_owned_by_root(shared):
    base, work = root_owned_pair(shared)
    os.chmod(work / "res/values/strings.xml", 0o600)
    dstparent = shared / "dstp"
    dstparent.mkdir()
    os.chown(dstparent, 10001, 10001)
    out = run_user(shared, "diff", base, work, dstparent / "snap")
    assert out["error"] == "unreadable" and "res/values/strings.xml" in out["message"] and str(shared) not in out["message"]
    out = run_user(shared, "copy", base, work, dstparent / "snap")
    assert out["error"] == "unreadable"
    os.chmod(work / "res/values/strings.xml", 0o644)
    os.chmod(work / "smali", 0o700)
    assert run_user(shared, "diff", base, work, dstparent / "snap2")["error"] == "unreadable"
    os.chmod(work / "smali", 0o755)
    assert "error" not in run_user(shared, "diff", base, work, dstparent / "snap3")


@need_uid
def test_uid10001_copy_into_unwritable_parent_raises_oserror_and_creates_nothing(shared):
    base, work = root_owned_pair(shared)
    ro_parent = shared / "rootonly"
    ro_parent.mkdir()
    out = run_user(shared, "copy", base, work, ro_parent / "snap")
    assert out == {"oserror": "PermissionError"} and not (ro_parent / "snap").exists()


@need_uid
@pytest.mark.skipif(not _UNSHARE, reason="butuh unshare")
def test_uid10001_reads_from_readonly_bind_and_copies_to_noexec_tmpfs(shared):
    """Meniru runner: pohon bench di bind `ro` (EROFS bila ditulis), salinan ke tmpfs `noexec` (mode 0755 tetap bisa dibuat, tak bisa dieksekusi)."""
    base, work = root_owned_pair(shared)
    mnt, tmpfs = shared / "ro", shared / "tmp"
    mnt.mkdir(), tmpfs.mkdir()
    script = (f"set -e; mount --bind {work} {mnt}; mount -o remount,bind,ro {mnt}; mount -t tmpfs -o noexec,nosuid,size=8m,mode=1777 tmpfs {tmpfs}; "
              f"if (echo x > {mnt}/probe) 2>/dev/null; then echo RW; exit 9; fi; "
              f"exec {' '.join(_AS_10001)} {shared / 'run.py'} both {base} {mnt} {tmpfs}/snap")
    r = subprocess.run([_UNSHARE, "-m", "sh", "-c", script], capture_output=True, text=True, timeout=60)
    if "RW" in r.stdout or r.returncode == 9:
        pytest.fail("bind ro ternyata bisa ditulis")
    if r.returncode != 0 and ("mount" in r.stderr or "unshare" in r.stderr):
        pytest.skip(f"unshare/mount tidak diizinkan: {r.stderr.strip()[:120]}")
    assert r.returncode == 0, (r.stdout, r.stderr)
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["diff"] == out["snap"] == h(base, work) and out["copy"]["files"] == 3
