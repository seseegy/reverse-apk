"""Penutupan R3/R10 (Tahap 2b): balapan NYATA antara 'runner' (uid 10001 yang menulis `builds/<aid>/<bid>/`) dan signer saat signer bekerja.

Ancaman: semua kontainer uid 10001 dan signer adalah 'oracle penandatanganan'. Runner yang memproses pohon tak tepercaya, kini bisa menulis `builds/`, dapat menukar
`unsigned.apk` / `.sign-signed.tmp` / `signed.apk` / folder build saat signer bekerja, supaya berkas tak terverifikasi diterbitkan sebagai `ok:true`. Desain yang
dibuktikan di sini (design.md 7.2, adendum A-02): signer menyalin `unsigned.apk` SEKALI dari satu fd ke `signwork` privat, menolak bila hash salinan != `expect_sha256`
SEBELUM alat apa pun jalan, align/sign/verify di `signwork`, menerbitkan dengan O_EXCL + rename, lalu membaca ulang dan mencocokkan hash.

Cara: alat PALSU yang berhenti di GERBANG berkas (`started.<alat>` ditulis, menunggu `go.<alat>`), jadi 'runner' (utas uji ATAU proses uid 10001 terpisah) bertindak TEPAT
di jendela yang berbahaya. Bagian terakhir memakai alat NYATA (Build-Tools 37 + JDK 21) dengan 'runner' yang menghantam folder terus-menerus (dilewati bersih bila env tidak diset).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import AS_10001, ROOT, as_user, need_uid, open_to_10001, within_call
from rvcore import signspool
from test_signer_daemon import (
    FAKE_TOOL,
    OWNER,
    WRAPPER,
    independent_verify,
    load_daemon,
    make_keystore,
    real_only,
    sreq,
)

ORIGINAL = b"APK-TIRUAN" * 100
EVIL = b"EVIL-MARKER-PENYERANG" * 50
SCRIPT = ROOT / "services" / "signer" / "signer-daemon"

GATE = '''
gate = beh.get("gate") or {}
if key in gate:
    tag = key.replace(":", "_")
    open(os.path.join(REC, "started." + tag), "w").write("1")
    stop_at = time.time() + 60
    while time.time() < stop_at and not os.path.exists(os.path.join(REC, "go." + tag)):
        time.sleep(0.01)
'''


@pytest.fixture
def sd(monkeypatch, tmp_path):
    """Modul signer-daemon yang dimuat dengan DATA_DIR/SIGNER_SECRETS_DIR sementara."""
    return load_daemon(monkeypatch, tmp_path)


@pytest.fixture
def rig(sd, tmp_path, monkeypatch):
    """Daemon + alat palsu yang bisa berhenti di GERBANG + kunci tiruan + folder build 1/2 berisi unsigned.apk (pola `rig` di test_signer_daemon)."""
    rec, bindir, secrets = tmp_path / "rec", tmp_path / "bin", tmp_path / "run-secrets"
    for p in (rec, bindir, secrets):
        p.mkdir()
    text = FAKE_TOOL.replace("@PY@", sys.executable).replace("@REC@", repr(str(rec))).replace('mode = b.get("mode", "ok")', GATE + 'mode = b.get("mode", "ok")')
    for tool in ("zipalign", "apksigner", "keytool"):
        (bindir / tool).write_text(text)
        (bindir / tool).chmod(0o755)
    (secrets / "signing_keystore").write_bytes(b"p12-tiruan")
    (secrets / "signing_keystore_pass").write_text("0123456789abcdef" * 4)
    for p in (secrets / "signing_keystore", secrets / "signing_keystore_pass"):
        p.chmod(0o644)
    bdir = sd.LAYOUT.build_dir(1, 2)
    bdir.mkdir(parents=True)
    (bdir / "unsigned.apk").write_bytes(ORIGINAL)
    monkeypatch.setattr(sd, "TOOL_PATH", f"{bindir}:/usr/bin:/bin")
    monkeypatch.setattr(sd, "KEYTOOL_TIMEOUT", 10.0)
    r = SimpleNamespace(d=sd, rec=rec, bin=bindir, secrets=secrets, bdir=bdir, home=tmp_path / "home")
    r.behave = lambda **kw: (rec / "behavior.json").write_text(json.dumps({"owner": OWNER, **kw}))
    r.behave()
    r.calls = lambda: [json.loads(ln) for ln in (rec / "calls.jsonl").read_text().splitlines()] if (rec / "calls.jsonl").exists() else []

    def run(aid=1, bid=2, timeout=60):
        job = sreq(sd.LAYOUT, aid, bid, timeout)
        sd.SPOOL.submit(job)
        claimed = sd.SPOOL.claim_next()
        return job["job_id"], sd.run_job(*claimed)

    r.run = run
    return r


@pytest.fixture
def race(rig):
    """`rig` + `race.race(gate, attack)`: menjalankan satu job lalu 'runner' bertindak di jendela gerbang alat."""
    daemon = rig.d

    def run(gate: str | None, attack, aid=1, bid=2, job=None, **behave):
        rig.behave(**({"gate": {gate: True}} if gate else {}), **behave)
        job = job or sreq(daemon.LAYOUT, aid, bid)
        daemon.SPOOL.submit(job)
        claimed = daemon.SPOOL.claim_next()
        assert claimed is not None
        box: dict = {}
        th = threading.Thread(target=lambda: box.update(res=daemon.run_job(*claimed)), daemon=True)
        th.start()
        if gate:
            tag = gate.replace(":", "_")
            end = time.monotonic() + 30
            while time.monotonic() < end and not (rig.rec / f"started.{tag}").exists() and th.is_alive():
                time.sleep(0.01)
            assert (rig.rec / f"started.{tag}").exists(), "alat tidak sampai ke gerbang"
        attack()
        if gate:
            (rig.rec / f"go.{tag}").write_text("1")
        th.join(60)
        assert not th.is_alive(), "job signer menggantung"
        return box["res"], claimed[0]

    rig.race = run
    return rig


def tools_called(rig):
    return [c["key"] for c in rig.calls() if c["tool"] != "keytool"]


def assert_no_evil(rig):
    for p in rig.bdir.rglob("*"):
        if p.is_file() and not p.is_symlink():
            assert b"EVIL-MARKER" not in p.read_bytes() or p.name == "unsigned.apk" or p.name.startswith("unsigned"), p


def signwork_empty(rig):
    work = rig.d.LAYOUT.signwork
    return not work.exists() or list(work.iterdir()) == []


# ======================================================================================== 1. masukan ditukar SETELAH signer menyalinnya
def swap_content_in_place(rig):
    with open(rig.bdir / "unsigned.apk", "r+b") as fh:
        fh.write(EVIL)
        fh.truncate(len(EVIL))


def swap_by_rename(rig):
    (rig.bdir / "lain.apk").write_bytes(EVIL)
    os.replace(rig.bdir / "lain.apk", rig.bdir / "unsigned.apk")


def swap_for_symlink(rig):
    (rig.bdir / "unsigned.apk").unlink()
    (rig.bdir / "unsigned.apk").symlink_to("/etc/passwd")


def swap_for_fifo(rig):
    (rig.bdir / "unsigned.apk").unlink()
    os.mkfifo(rig.bdir / "unsigned.apk")


def swap_for_hardlink(rig):
    (rig.bdir / "unsigned.apk").unlink()
    (rig.bdir.parent / "lain-di-luar").write_bytes(EVIL)
    os.link(rig.bdir.parent / "lain-di-luar", rig.bdir / "unsigned.apk")


@pytest.mark.parametrize("attack", [swap_content_in_place, swap_by_rename, swap_for_symlink, swap_for_fifo, swap_for_hardlink])
def test_swapping_unsigned_apk_while_zipalign_runs_cannot_change_what_gets_signed(race, attack):
    """Gerbang di zipalign: salinan privat SUDAH diambil. Apa pun yang dilakukan 'runner' pada unsigned.apk sesudahnya tidak berpengaruh: hasil memuat byte ASLI."""
    res, job_id = race.race("zipalign", lambda: attack(race))
    assert res["ok"] is True, res
    signed = (race.bdir / "signed.apk").read_bytes()
    assert signed == ORIGINAL and b"EVIL-MARKER" not in signed
    assert res["input_sha256"] == hashlib.sha256(ORIGINAL).hexdigest() and res["output_sha256"] == hashlib.sha256(signed).hexdigest()
    zip_argv = next(c["argv"] for c in race.calls() if c["key"] == "zipalign")
    assert zip_argv[-2].startswith(str(race.d.LAYOUT.signwork)) and str(race.bdir) not in " ".join(zip_argv), "alat membaca salinan privat, bukan folder build"
    assert signwork_empty(race)


def test_every_tool_argument_points_into_signwork_never_into_the_runner_writable_folder(race):
    res, _ = race.race(None, lambda: None)
    assert res["ok"] is True
    for c in race.calls():
        if c["tool"] == "keytool":
            continue
        paths = [a for a in c["argv"] if a.startswith("/") or a.startswith("file:/")]
        assert all(str(race.bdir) not in p for p in paths), c["argv"]
        assert any(str(race.d.LAYOUT.signwork) in p for p in paths if "run-secrets" not in p), c["argv"]


# ======================================================================================== 2. masukan ditukar SEBELUM signer membuka (A-02)
@pytest.mark.parametrize("attack", [swap_content_in_place, swap_by_rename, swap_for_hardlink])
def test_a_unsigned_apk_swapped_after_the_runner_finished_is_refused_before_any_tool_runs(race, attack):
    """A-02: hash di request (`expect_sha256` = yang dilaporkan runner) != hash salinan -> `input_unsafe`, alat palsu 0 panggilan, tidak ada signed.apk."""
    job = sreq(race.d.LAYOUT, 1, 2)                                  # hash ASLI
    attack(race)                                                     # 'runner' menukar sebelum signer sempat membuka
    res, _ = race.race(None, lambda: None, job=job)
    assert (res["ok"], res["error_code"]) == (False, "input_unsafe")
    assert "hash tak cocok" in res["error_text"] or attack is swap_for_hardlink, "tautan keras ditolak lebih dulu oleh nlink"
    assert tools_called(race) == [] and not (race.bdir / "signed.apk").exists() and signwork_empty(race)
    assert res["output_sha256"] is None


def test_wrong_expect_sha256_is_refused_even_when_the_file_is_untouched(race):
    res, _ = race.race(None, lambda: None, job=sreq(race.d.LAYOUT, 1, 2, expect="0" * 64))
    assert res["error_code"] == "input_unsafe" and tools_called(race) == [] and not (race.bdir / "signed.apk").exists()


def test_the_expect_sha256_comparison_happens_before_zipalign_not_after(race, monkeypatch):
    order = []
    d = race.d
    real_cmp = d.hmac.compare_digest
    monkeypatch.setattr(d, "build_zipalign_cmd", lambda *a: (order.append("zipalign"), ["zipalign", "-P", "16", "-f", "4", str(a[0]), str(a[1])])[1])
    monkeypatch.setattr(d.hmac, "compare_digest", lambda a, b: (order.append("cmp"), real_cmp(a, b))[1])
    race.race(None, lambda: None, job=sreq(d.LAYOUT, 1, 2, expect="0" * 64))
    assert order[:1] == ["cmp"] and "zipalign" not in order


# ======================================================================================== 3. penerbitan tahan balapan
def plant_regular(rig):
    (rig.bdir / ".sign-signed.tmp").write_bytes(EVIL)


def plant_fifo(rig):
    os.mkfifo(rig.bdir / ".sign-signed.tmp")


def plant_symlink(rig):
    (rig.bdir.parent / "korban.txt").write_text("jangan ditimpa")
    (rig.bdir / ".sign-signed.tmp").symlink_to(rig.bdir.parent / "korban.txt")


def plant_dir(rig):
    (rig.bdir / ".sign-signed.tmp").mkdir()
    (rig.bdir / ".sign-signed.tmp" / "x").write_bytes(EVIL)


def plant_dangling_symlink(rig):
    (rig.bdir / ".sign-signed.tmp").symlink_to(rig.bdir.parent / "belum-ada")


@pytest.mark.parametrize("plant", [plant_regular, plant_fifo, plant_symlink, plant_dir, plant_dangling_symlink])
def test_a_planted_sign_signed_tmp_fails_the_job_closed_and_is_never_followed(race, plant):
    """Gerbang di `apksigner verify` (sesudah verifikasi, sebelum terbit): nama perantara penerbitan sudah ditanam -> O_EXCL gagal -> job GAGAL; tidak menimpa,
    tidak mengikuti symlink, FIFO tidak menggantung, tidak ada signed.apk berisi penyerang."""
    res, exc = within_call(120, race.race, "apksigner:verify", lambda: plant(race))
    assert exc is None
    res, _ = res
    assert res["ok"] is False and res["error_code"] == "internal", res
    assert not (race.bdir / "signed.apk").exists()
    if (race.bdir.parent / "korban.txt").exists():
        assert (race.bdir.parent / "korban.txt").read_text() == "jangan ditimpa"
    assert not (race.bdir / "belum-ada").exists() and not (race.bdir.parent / "belum-ada").exists()
    if plant is not plant_dir:           # direktori yang ditanam tidak bisa di-unlink signer (sama seperti 2a: input_unsafe bila ada di awal); worker membuangnya dengan rmtree_at
        assert not any(p.name.startswith(".sign-") for p in race.bdir.iterdir()), "perantara yang ditanam dibersihkan, bukan dibiarkan"
    assert signwork_empty(race)


def plant_signed_dir(rig):
    (rig.bdir / "signed.apk").mkdir()
    (rig.bdir / "signed.apk" / "x").write_bytes(EVIL)


def plant_signed_fifo(rig):
    os.mkfifo(rig.bdir / "signed.apk")


def plant_signed_file(rig):
    (rig.bdir / "signed.apk").write_bytes(EVIL)


def plant_signed_symlink(rig):
    (rig.bdir.parent / "korban2.txt").write_text("jangan ditimpa")
    (rig.bdir / "signed.apk").symlink_to(rig.bdir.parent / "korban2.txt")


@pytest.mark.parametrize("plant", [plant_signed_dir, plant_signed_fifo, plant_signed_file, plant_signed_symlink])
def test_a_planted_signed_apk_is_replaced_or_the_job_fails_never_the_attackers_content(race, plant):
    res, exc = within_call(120, race.race, "apksigner:verify", lambda: plant(race))
    assert exc is None
    res, _ = res
    signed = race.bdir / "signed.apk"
    if res["ok"]:
        assert signed.is_file() and not signed.is_symlink() and signed.read_bytes() == ORIGINAL
        assert res["output_sha256"] == hashlib.sha256(ORIGINAL).hexdigest()
    else:
        assert not signed.is_file() or signed.read_bytes() != EVIL
    assert not (signed.is_file() and b"EVIL-MARKER" in signed.read_bytes())
    if (race.bdir.parent / "korban2.txt").exists():
        assert (race.bdir.parent / "korban2.txt").read_text() == "jangan ditimpa"


def test_swapping_signed_apk_right_after_the_atomic_replace_is_detected_and_removed(race, monkeypatch):
    """Jendela tersisa: runner menukar signed.apk TEPAT setelah rename (hook os.replace). Baca ulang + hash menangkapnya -> ok:false, signed.apk dihapus."""
    d = race.d
    real_replace = d.os.replace

    def replace_then_swap(src, dst, **kw):
        out = real_replace(src, dst, **kw)
        if kw.get("src_dir_fd") is not None and dst == "signed.apk":
            (race.bdir / "palsu").write_bytes(EVIL)
            real_replace(race.bdir / "palsu", race.bdir / "signed.apk")
        return out

    monkeypatch.setattr(d.os, "replace", replace_then_swap)
    res, _ = race.race(None, lambda: None)
    assert (res["ok"], res["error_code"]) == (False, "internal") and "berubah" in res["error_text"]
    assert not (race.bdir / "signed.apk").exists()


@pytest.mark.parametrize("swap", ["fifo", "symlink", "dir", "hardlink"])
def test_other_swaps_of_signed_apk_after_the_replace_are_detected_without_hanging(race, monkeypatch, swap):
    d = race.d
    real_replace = d.os.replace

    def replace_then_swap(src, dst, **kw):
        out = real_replace(src, dst, **kw)
        if kw.get("src_dir_fd") is not None and dst == "signed.apk":
            target = race.bdir / "signed.apk"
            target.unlink()
            if swap == "fifo":
                os.mkfifo(target)
            elif swap == "symlink":
                target.symlink_to("/etc/hostname")
            elif swap == "dir":
                target.mkdir()
            else:
                (race.bdir / "lain").write_bytes(ORIGINAL)           # isi SAMA tetapi tautan keras ke berkas lain: nlink != 1
                os.link(race.bdir / "lain", target)
        return out

    monkeypatch.setattr(d.os, "replace", replace_then_swap)
    (res, _), exc = within_call(60, race.race, None, lambda: None)
    assert exc is None and (res["ok"], res["error_code"]) == (False, "internal")
    assert not (race.bdir / "signed.apk").is_file(), "yang ditukar dihapus bila bisa (FIFO/symlink/tautan keras); direktori tak bisa di-unlink tetapi bukan berkas"
    if swap != "dir":
        assert not os.path.lexists(race.bdir / "signed.apk")


def test_published_copy_is_compared_with_the_verified_hash_before_the_rename(race, monkeypatch):
    """Salinan ke `.sign-signed.tmp` dihitung ulang dari fd terverifikasi dan HARUS sama dengan hash terverifikasi SEBELUM rename (lapis pertama; baca ulang adalah lapis kedua)."""
    d = race.d
    state = {"on": False}
    real_publish, real_read = d.publish_signed, d.os.read

    def publish(*a, **k):
        state["on"] = True
        try:
            return real_publish(*a, **k)
        finally:
            state["on"] = False

    def read(fd, n):
        chunk = real_read(fd, n)
        return (b"X" + chunk[1:]) if state["on"] and chunk and n >= 1024 * 1024 else chunk

    monkeypatch.setattr(d, "publish_signed", publish)
    monkeypatch.setattr(d.os, "read", read)
    res, _ = race.race(None, lambda: None)
    assert (res["ok"], res["error_code"]) == (False, "internal") and "tidak sama dengan hasil yang diverifikasi" in res["error_text"]
    assert not (race.bdir / "signed.apk").exists() and not (race.bdir / ".sign-signed.tmp").exists()


def test_growing_unsigned_apk_is_cut_at_the_limit_while_copying(race, monkeypatch):
    """`unsigned.apk` tumbuh saat disalin (melewati SIGN_MAX_MB): input_too_large, ruang kerja privat bersih, tak ada alat."""
    d = race.d
    monkeypatch.setattr(d, "SIGN_MAX_MB", 1)
    apk = race.bdir / "unsigned.apk"
    apk.write_bytes(b"\0" * (1024 * 1024 - 10))
    grown = []
    real_read = d.os.read

    def growing_read(fd, n):
        chunk = real_read(fd, n)
        if not grown and chunk:
            grown.append(1)
            with open(apk, "ab") as fh:
                fh.write(b"\1" * (3 * 1024 * 1024))
        return chunk

    monkeypatch.setattr(d.os, "read", growing_read)
    res, _ = race.race(None, lambda: None)
    assert (res["ok"], res["error_code"]) == (False, "input_too_large") and tools_called(race) == []
    assert signwork_empty(race) and not (race.bdir / "signed.apk").exists()


# ======================================================================================== 4. rantai folder ditukar
def test_builds_aid_replaced_by_a_symlink_before_the_signer_opens_is_refused(race, tmp_path):
    victim = tmp_path / "korban"
    (victim / "2").mkdir(parents=True)
    shutil.copy(race.bdir / "unsigned.apk", victim / "2" / "unsigned.apk")
    (victim / "2" / "signed.apk").write_bytes(b"jangan hapus")
    job = sreq(race.d.LAYOUT, 1, 2)
    shutil.move(race.bdir.parent, tmp_path / "asli")
    race.bdir.parent.symlink_to(victim)
    res, _ = race.race(None, lambda: None, job=job)
    assert res["error_code"] == "input_unsafe" and tools_called(race) == []
    assert (victim / "2" / "signed.apk").read_bytes() == b"jangan hapus" and sorted(p.name for p in (victim / "2").iterdir()) == ["signed.apk", "unsigned.apk"]


def test_build_folder_renamed_away_before_the_signer_opens_is_input_missing(race, tmp_path):
    job = sreq(race.d.LAYOUT, 1, 2)
    race.bdir.rename(tmp_path / "dipindah")
    res, _ = race.race(None, lambda: None, job=job)
    assert res["error_code"] == "input_missing" and tools_called(race) == [] and not race.bdir.exists()


def test_build_folder_replaced_after_the_signer_opened_it_gets_the_result_in_the_inode_it_opened(race, tmp_path):
    """'Runner' me-rename folder build dan menaruh folder lain bernama sama di gerbang zipalign. Signer menerbitkan ke inode yang ia buka; folder baru tidak berisi
    artefak, sehingga worker (membuka rantai BARU saat memberi nama) mendapat berkas hilang -> artifact_changed. Tidak ada tulisan ke folder pengganti."""
    moved = tmp_path / "dipindah"

    def attack():
        race.bdir.rename(moved)
        race.bdir.mkdir()
        (race.bdir / "unsigned.apk").write_bytes(EVIL)

    res, _ = race.race("zipalign", attack)
    assert res["ok"] is True and (moved / "signed.apk").read_bytes() == ORIGINAL
    assert sorted(p.name for p in race.bdir.iterdir()) == ["unsigned.apk"], "folder pengganti tidak disentuh signer"


def test_builds_aid_swapped_for_a_symlink_mid_job_is_not_followed(race, tmp_path):
    victim = tmp_path / "korban"
    (victim / "2").mkdir(parents=True)
    (victim / "2" / "signed.apk").write_bytes(b"jangan hapus")
    (victim / "2" / ".sign-signed.tmp").write_bytes(b"jangan hapus")

    def attack():
        shutil.move(race.bdir.parent, tmp_path / "asli")
        race.bdir.parent.symlink_to(victim)

    res, _ = race.race("apksigner:verify", attack)
    assert res["ok"] is True and (tmp_path / "asli" / "2" / "signed.apk").read_bytes() == ORIGINAL
    assert sorted(p.name for p in (victim / "2").iterdir()) == [".sign-signed.tmp", "signed.apk"]
    assert all(p.read_bytes() == b"jangan hapus" for p in (victim / "2").iterdir())


# ======================================================================================== 5. kebersihan signwork
def test_signwork_is_emptied_after_success_failure_and_orphan_recovery(race):
    assert race.race(None, lambda: None)[0]["ok"] is True and signwork_empty(race)
    res, _ = race.race(None, lambda: None, **{"apksigner:sign": {"mode": "fail", "partial": True}})
    assert res["ok"] is False and signwork_empty(race)
    leftover = race.d.LAYOUT.signwork / "g9-9-abcdef12"
    (leftover / "dalam").mkdir(parents=True)
    (leftover / "dalam" / "in.apk").write_bytes(b"sisa")
    os.mkfifo(race.d.LAYOUT.signwork / "pipa")
    (race.d.LAYOUT.signwork / "korban-link").symlink_to(race.bdir)
    race.d.abort_orphans()
    assert signwork_empty(race) and (race.bdir / "unsigned.apk").exists(), "symlink di signwork di-unlink, sasarannya utuh"


def test_signwork_leftover_with_the_same_job_id_is_replaced_not_reused(race):
    d = race.d
    job = sreq(d.LAYOUT, 1, 2)
    stale = d.LAYOUT.signwork / job["job_id"]
    stale.mkdir(parents=True)
    (stale / "in.apk").write_bytes(EVIL)
    (stale / "signed.apk").write_bytes(EVIL)
    res, _ = race.race(None, lambda: None, job=job)
    assert res["ok"] is True and (race.bdir / "signed.apk").read_bytes() == ORIGINAL and signwork_empty(race)


def test_signwork_volume_is_never_mounted_into_the_runner_or_anything_but_the_signer():
    import re
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    body = compose.split("\nservices:\n", 1)[1].split("\nnetworks:\n", 1)[0]
    code = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    parts = re.split(r"(?m)^  ([\w-]+):[ \t]*$", code)
    holders = {parts[i] for i in range(1, len(parts), 2) if "signwork:" in parts[i + 1]}
    assert holders == {"signer"}


# ======================================================================================== 6. sisa warisan 2a: error_text keystore disaring
def test_keystore_error_text_does_not_leak_the_secret_paths(rig):
    d = rig.d
    p12 = rig.secrets / "signing_keystore"
    p12.unlink()
    job_id, res = rig.run()
    assert res["error_code"] == "keystore_missing"
    assert str(rig.secrets) not in res["error_text"] and "run-secrets" not in res["error_text"], res["error_text"]
    d.write_hb("idle")
    assert str(rig.secrets) not in d.SPOOL.heartbeat_file.read_text()
    assert str(rig.secrets) not in json.dumps(json.loads((d.SPOOL.results / f"{job_id}.json").read_text()))


def test_keystore_unreadable_detail_is_scrubbed_but_keeps_the_fix_hint(rig, monkeypatch):
    d = rig.d
    detail = f"{rig.secrets}/signing_keystore mode 600 milik uid 1000, uid 10001 tidak bisa membaca; jalankan 'make keystore-access' di host"
    monkeypatch.setattr(d, "key_status", lambda: d.KeyInfo("unreadable", detail, None))
    _, res = rig.run()
    assert res["error_code"] == "keystore_unreadable" and str(rig.secrets) not in res["error_text"]
    assert "make keystore-access" in res["error_text"] and "uid 1000" in res["error_text"]
    d.KEY_STATE["last"] = d.KeyInfo("unreadable", detail, None)
    d.write_hb("idle")
    hb = json.loads(d.SPOOL.heartbeat_file.read_text())
    assert str(rig.secrets) not in hb["keystore"]["detail"] and "make keystore-access" in hb["keystore"]["detail"]


# ======================================================================================== 7. PROSES TERPISAH uid 10001 (signer dan 'runner' adalah dua proses)
SH_ZIPALIGN = '''#!/bin/sh
REC=@REC@
echo "$@" >> "$REC/calls.txt"
if [ "$1" = "-c" ]; then exit 0; fi
if [ -e "$REC/gate.zipalign" ]; then : > "$REC/started.zipalign"; i=0; while [ ! -e "$REC/go.zipalign" ] && [ $i -lt 1200 ]; do sleep 0.05; i=$((i+1)); done; fi
cp "$5" "$6"
'''
SH_APKSIGNER = '''#!/bin/sh
REC=@REC@
echo "apksigner $@" >> "$REC/calls.txt"
if [ "$1" = "sign" ]; then
  while [ $# -gt 0 ]; do if [ "$1" = "--out" ]; then out="$2"; fi; last="$1"; shift; done
  src="$last"
  cp "$src" "$out"
  exit 0
fi
if [ -e "$REC/gate.verify" ]; then : > "$REC/started.verify"; i=0; while [ ! -e "$REC/go.verify" ] && [ $i -lt 1200 ]; do sleep 0.05; i=$((i+1)); done; fi
printf 'Verifies\\nVerified using v1 scheme (JAR signing): false\\nVerified using v2 scheme (APK Signature Scheme v2): true\\nVerified using v3 scheme (APK Signature Scheme v3): true\\nNumber of signers: 1\\nV3.0 Signer: certificate SHA-256 digest: %s\\n' "@OWNER@"
'''

SIGNER_BOOT = textwrap.dedent('''
    import importlib.machinery, importlib.util, json, os, sys
    from pathlib import Path
    sys.path.insert(0, os.environ["SERVICES"])
    loader = importlib.machinery.SourceFileLoader("signer_daemon_proc", os.environ["SIGNER_SCRIPT"])
    spec = importlib.util.spec_from_loader("signer_daemon_proc", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    m.TOOL_HOME_ROOT = Path(os.environ["TOOLHOME"]); m.TOOL_PATH = os.environ["TOOLBIN"]; m.TICK = 0.05; m.TERM_GRACE = 0.5
    m.key_status = lambda: m.KeyInfo("ok", "", os.environ["OWNER_SHA"])
    job = json.loads(os.environ["JOB_JSON"])
    m.SPOOL.ensure_dirs()
    m.SPOOL.submit(job)
    job_id, request = m.SPOOL.claim_next()
    res = m.run_job(job_id, request)
    print("RESULT " + json.dumps(res))
''')

RUNNER_ATTACK = textwrap.dedent('''
    # 'runner': proses uid 10001 TERPISAH yang menulis folder build yang sama, bertindak tepat di jendela gerbang.
    import os, sys, time
    rec, bdir, what = sys.argv[1:4]
    gate = {"zipalign": "started.zipalign", "verify": "started.verify"}[sys.argv[4]]
    end = time.time() + 60
    while time.time() < end and not os.path.exists(os.path.join(rec, gate)):
        time.sleep(0.01)
    evil = b"EVIL-MARKER-PENYERANG" * 50
    p = lambda n: os.path.join(bdir, n)
    if what == "swap-unsigned":
        os.unlink(p("unsigned.apk")); open(p("unsigned.apk"), "wb").write(evil)
    elif what == "symlink-unsigned":
        os.unlink(p("unsigned.apk")); os.symlink("/etc/passwd", p("unsigned.apk"))
    elif what == "fifo-unsigned":
        os.unlink(p("unsigned.apk")); os.mkfifo(p("unsigned.apk"))
    elif what == "plant-tmp":
        open(p(".sign-signed.tmp"), "wb").write(evil)
    elif what == "fifo-tmp":
        os.mkfifo(p(".sign-signed.tmp"))
    elif what == "symlink-tmp":
        os.symlink(os.path.join(os.path.dirname(bdir), "korban.txt"), p(".sign-signed.tmp"))
    elif what == "dir-signed":
        os.mkdir(p("signed.apk")); open(p("signed.apk") + "/x", "wb").write(evil)
    open(os.path.join(rec, "go." + sys.argv[4]), "w").write("1")
    print("ATTACK-DONE")
''')


@pytest.fixture
def procs():
    base = open_to_10001(Path(tempfile.mkdtemp(prefix="rv-race-")))
    data = open_to_10001(base / "data")
    for name in ("builds", "signspool", "signwork"):
        (data / name).mkdir()
        os.chown(data / name, 10001, 10001)
    rec, tbin, home = open_to_10001(base / "rec"), open_to_10001(base / "bin"), open_to_10001(base / "home")
    os.chmod(rec, 0o777), os.chmod(home, 0o777)
    for name, text in (("zipalign", SH_ZIPALIGN), ("apksigner", SH_APKSIGNER)):
        (tbin / name).write_text(text.replace("@REC@", str(rec)).replace("@OWNER@", OWNER))
        os.chmod(tbin / name, 0o755)
    (tbin / "keytool").write_text("#!/bin/sh\nexit 1\n")
    os.chmod(tbin / "keytool", 0o755)
    bdir = data / "builds" / "1" / "2"
    bdir.mkdir(parents=True)
    os.chown(data / "builds" / "1", 10001, 10001), os.chown(bdir, 10001, 10001)
    apk = bdir / "unsigned.apk"
    apk.write_bytes(ORIGINAL)
    os.chown(apk, 10001, 10001)
    (data / "builds" / "1" / "korban.txt").write_text("jangan ditimpa")
    os.chown(data / "builds" / "1" / "korban.txt", 10001, 10001)
    (base / "attack.py").write_text(RUNNER_ATTACK)
    (base / "signer_boot.py").write_text(SIGNER_BOOT)
    ns = SimpleNamespace(base=base, data=data, rec=rec, bin=tbin, home=home, bdir=bdir)
    yield ns
    shutil.rmtree(base, ignore_errors=True)


def signer_cmd(p, job: dict) -> list[str]:
    env = {"SERVICES": str(ROOT / "services"), "SIGNER_SCRIPT": str(SCRIPT), "TOOLHOME": str(p.home), "TOOLBIN": f"{p.bin}:/usr/bin:/bin", "OWNER_SHA": OWNER,
           "JOB_JSON": json.dumps(job), "DATA_DIR": str(p.data), "SIGNER_SECRETS_DIR": str(p.base / "none")}
    return as_user(env, str(p.base / "signer_boot.py"))


def run_two_processes(p, what: str, gate: str, *, expect: str | None = None) -> dict:
    """Dua proses uid 10001 NYATA: signer (men-load signer-daemon, satu job) dan 'runner' (menyerang di jendela gerbang)."""
    job = signspool.build_sign_request(1, 2, 60, expect or hashlib.sha256(ORIGINAL).hexdigest())
    (p.rec / f"gate.{gate}").write_text("")
    signer = subprocess.Popen(signer_cmd(p, job), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    attacker = subprocess.Popen([*AS_10001, str(p.base / "attack.py"), str(p.rec), str(p.bdir), what, gate], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        a_out = attacker.communicate(timeout=90)[0]
        s_out = signer.communicate(timeout=90)[0]
    finally:
        for proc in (signer, attacker):
            if proc.poll() is None:
                proc.kill()
    assert "ATTACK-DONE" in a_out, a_out
    line = next((ln for ln in s_out.splitlines() if ln.startswith("RESULT ")), None)
    assert line, s_out
    return json.loads(line[len("RESULT "):])


@need_uid
@pytest.mark.parametrize("what", ["swap-unsigned", "symlink-unsigned", "fifo-unsigned"])
def test_two_real_uid10001_processes_unsigned_apk_swapped_while_zipalign_runs(procs, what):
    res = run_two_processes(procs, what, "zipalign")
    assert res["ok"] is True, res
    assert (procs.bdir / "signed.apk").read_bytes() == ORIGINAL
    assert res["input_sha256"] == hashlib.sha256(ORIGINAL).hexdigest()
    calls = (procs.rec / "calls.txt").read_text()
    assert str(procs.bdir) not in calls, "alat hanya melihat jalur signwork"
    assert list((procs.data / "signwork").iterdir()) == []


@need_uid
@pytest.mark.parametrize("what", ["plant-tmp", "fifo-tmp", "symlink-tmp", "dir-signed"])
def test_two_real_uid10001_processes_publication_window_fails_closed(procs, what):
    res = run_two_processes(procs, what, "verify")
    signed = procs.bdir / "signed.apk"
    if what == "dir-signed":
        assert res["ok"] is False and signed.is_dir()
    elif what == "plant-tmp" or what == "fifo-tmp" or what == "symlink-tmp":
        assert res["ok"] is False and res["error_code"] == "internal" and not signed.exists()
    assert not (signed.is_file() and b"EVIL-MARKER" in signed.read_bytes())
    assert (procs.data / "builds" / "1" / "korban.txt").read_text() == "jangan ditimpa"
    assert list((procs.data / "signwork").iterdir()) == []


@need_uid
def test_two_real_processes_a_stale_hash_in_the_request_is_refused_before_any_tool(procs):
    (procs.rec / "gate.none").write_text("")
    job = signspool.build_sign_request(1, 2, 60, hashlib.sha256(b"yang dilaporkan runner").hexdigest())
    out = subprocess.run(signer_cmd(procs, job), capture_output=True, text=True, timeout=60).stdout
    res = json.loads(next(ln for ln in out.splitlines() if ln.startswith("RESULT "))[7:])
    assert (res["ok"], res["error_code"]) == (False, "input_unsafe")
    assert not (procs.rec / "calls.txt").exists(), "zipalign/apksigner TIDAK dipanggil"
    assert not (procs.bdir / "signed.apk").exists()


# ======================================================================================== 8. alat NYATA + 'runner' yang menghantam folder
@pytest.fixture(scope="module")
def rt(tmp_path_factory):
    """Alat NYATA: Build-Tools 37 + JDK 21 + keystore pemilik sementara (pola `real_tools` di test_signer_daemon)."""
    if not all(os.environ.get(v) for v in ("SIGNER_TEST_BUILD_TOOLS", "SIGNER_TEST_JAVA_HOME", "SIGNER_TEST_APK")):
        pytest.skip("alat nyata tidak ada")
    bt, jh, apk = Path(os.environ["SIGNER_TEST_BUILD_TOOLS"]), Path(os.environ["SIGNER_TEST_JAVA_HOME"]), Path(os.environ["SIGNER_TEST_APK"])
    root = tmp_path_factory.mktemp("realtools-race")
    bindir = root / "bin"
    bindir.mkdir()
    (bindir / "apksigner").write_text(WRAPPER.format(bt=bt))
    (bindir / "apksigner").chmod(0o755)
    (bindir / "zipalign").symlink_to(bt / "zipalign")
    (bindir / "java").symlink_to(jh / "bin" / "java")
    (bindir / "keytool").symlink_to(jh / "bin" / "keytool")
    tools = SimpleNamespace(root=root, bin=bindir, bt=bt, apk=apk, keytool=jh / "bin" / "keytool")
    tools.owner = make_keystore(tools, "owner")
    return tools


@real_only
@pytest.mark.parametrize("hammer", ["rewrite", "replace", "symlink", "tmp-signed"])
def test_real_tools_signer_under_a_hammering_runner_never_publishes_foreign_bytes(rt, sd, tmp_path, monkeypatch, hammer):
    """Alat NYATA (zipalign + apksigner + JDK 21): sebuah utas 'runner' menghantam unsigned.apk/.sign-signed.tmp/signed.apk terus-menerus selama job. Hasil sah hanya
    `ok:false` atau `ok:true` dengan signed.apk yang (a) lulus `apksigner verify` independen, (b) hash-nya == hasil job, (c) isinya turunan byte ASLI."""
    secrets = tmp_path / "run-secrets"
    secrets.mkdir()
    shutil.copy(rt.owner.p12, secrets / "signing_keystore")
    shutil.copy(rt.owner.pw, secrets / "signing_keystore_pass")
    bdir = sd.LAYOUT.build_dir(1, 2)
    bdir.mkdir(parents=True)
    original = rt.apk.read_bytes()
    (bdir / "unsigned.apk").write_bytes(original)
    monkeypatch.setattr(sd, "TOOL_PATH", str(rt.bin))
    monkeypatch.setattr(sd, "KEYTOOL_TIMEOUT", 60.0)
    monkeypatch.setattr(sd, "TICK", 0.1)
    job = sreq(sd.LAYOUT, 1, 2)
    stop = threading.Event()
    evil = b"EVIL-MARKER-PENYERANG" * 50

    def hammer_loop():
        n = 0
        while not stop.is_set():
            n += 1
            try:
                if hammer == "rewrite":
                    with open(bdir / "unsigned.apk", "r+b") as fh:
                        fh.write(evil)
                elif hammer == "replace":
                    (bdir / "x.tmp").write_bytes(evil)
                    os.replace(bdir / "x.tmp", bdir / "unsigned.apk")
                elif hammer == "symlink":
                    if os.path.lexists(bdir / "unsigned.apk"):
                        os.unlink(bdir / "unsigned.apk")
                    os.symlink("/etc/passwd", bdir / "unsigned.apk")
                else:
                    for name in (".sign-signed.tmp", "signed.apk"):
                        try:
                            os.unlink(bdir / name)
                        except OSError:
                            pass
                        try:
                            (bdir / name).write_bytes(evil)
                        except OSError:
                            pass
            except OSError:
                pass
            time.sleep(0.0005)

    th = threading.Thread(target=hammer_loop, daemon=True)
    sd.SPOOL.submit(job)
    claimed = sd.SPOOL.claim_next()
    th.start()
    time.sleep(0.0)
    try:
        if hammer in ("rewrite", "replace", "symlink"):
            time.sleep(0.2)
        res = sd.run_job(*claimed)
    finally:
        stop.set()
        th.join(5)
    signed = bdir / "signed.apk"
    if res["ok"]:
        assert signed.is_file() and not signed.is_symlink()
        data = signed.read_bytes()
        assert b"EVIL-MARKER" not in data and hashlib.sha256(data).hexdigest() == res["output_sha256"] and len(data) == res["output_size"]
        rc, out = independent_verify(rt, signed)
        assert rc == 0 and set(sd.parse_verify(rc, out).digests) == {rt.owner.sha}
        names = zipfile.ZipFile(signed).namelist()
        orig_names = zipfile.ZipFile(rt.apk).namelist()
        assert set(orig_names) <= set(names)
    else:
        # Gagal-tertutup: kode salah satu penolakan yang diharapkan dan hasilnya TIDAK memuat hash keluaran. (Berkas `signed.apk` yang ditanam 'runner' sendiri bisa tinggal di
        # folder yang ia kuasai; itu tidak berbahaya karena worker hanya memakai berkas bila hasil ok:true DAN hash cocok.)
        assert res["error_code"] in ("input_unsafe", "internal", "align_failed", "input_missing"), res
        assert res["output_sha256"] is None and res["output_size"] == 0
    assert not sd.LAYOUT.signwork.exists() or list(sd.LAYOUT.signwork.iterdir()) == []


@real_only
def test_real_tools_swapped_unsigned_apk_before_open_is_refused_by_expect_sha256(rt, sd, tmp_path, monkeypatch):
    secrets = tmp_path / "run-secrets"
    secrets.mkdir()
    shutil.copy(rt.owner.p12, secrets / "signing_keystore")
    shutil.copy(rt.owner.pw, secrets / "signing_keystore_pass")
    bdir = sd.LAYOUT.build_dir(1, 2)
    bdir.mkdir(parents=True)
    shutil.copy(rt.apk, bdir / "unsigned.apk")
    monkeypatch.setattr(sd, "TOOL_PATH", str(rt.bin))
    monkeypatch.setattr(sd, "KEYTOOL_TIMEOUT", 60.0)
    job = sreq(sd.LAYOUT, 1, 2)
    (bdir / "unsigned.apk").write_bytes(rt.apk.read_bytes() + b"\0")                  # ditukar setelah runner melapor
    sd.SPOOL.submit(job)
    res = sd.run_job(*sd.SPOOL.claim_next())
    assert (res["ok"], res["error_code"]) == (False, "input_unsafe") and not (bdir / "signed.apk").exists()
