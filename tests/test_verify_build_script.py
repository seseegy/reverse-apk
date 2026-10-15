"""scripts/verify-build.sh (`make verify-build`) dengan `docker` PALSU (Tahap 2b, FEAT G).

Skrip dijalankan SUNGGUHAN (bash) pada pohon repo mini (salinan verify-build.sh, `keystore.sh` palsu, secrets/ dan testdata/ buatan tes). `docker` palsu di PATH
adalah mesin-keadaan kecil: ia meniru `compose version|ps|exec|run|logs` dan `docker inspect`, menjawab `app.buildctl` (analyze/init/shell/diff/request/approve/wait/
cancel/status/artifact-info/delete), `signer-selftest --check-apk`, tamu runner (uji mount, balik-byte 7b, isi artefak langkah 8) dan kontainer sekali pakai worker
(`run_build`, `prune_for`), lalu mencatat tiap panggilan (JSON per baris). Yang diuji adalah LOGIKA skrip: urutan langkah, keputusan OK/GAGAL/DILEWATI, tabel, kode
keluar, `trap` (cancel -> wait -> delete), pola A-05 (tidak ada `exec` ke runner), A-04 (cap waktu dari DB). Yang TIDAK terbukti di sini: Compose 5.6.0/Docker nyata,
volume, healthcheck, `exec -T` meneruskan EOF stdin, buildctl/signer/runner/worker nyata (lihat .agents/run/unproven.md).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_SRC = ROOT / "scripts/verify-build.sh"
MAKEFILE = ROOT / "Makefile"
OWNER = hashlib.sha256(b"sertifikat pemilik").hexdigest()
OTHER = hashlib.sha256(b"sertifikat lain").hexdigest()
PW = "Pw-Uji-Verify-Build-0123456789-abcdef"
AID = 77

STEPS = ["1 prasyarat", "2 analisis uji", "3 init + diff kosong", "4 ubah string via shell", "5 negatif persetujuan", "6 build nyata", "7 verifikasi independen (signer)",
         "7b deteksi ubah-pasca-terbit", "8 isi artefak", "9 negatif TOCTOU", "10 negatif pembatalan", "11 retensi", "12 kebersihan", "13 ringkasan"]

FAKE_DOCKER = r'''#!@PY@
import hashlib, json, os, re, sys, time
cfg = json.load(open(@CFG@))
sc = cfg["scenario"]
args = sys.argv[1:]
SP = cfg["statefile"]
AID = 77
H0 = hashlib.sha256(b"kosong").hexdigest()
OWNER = cfg["owner"]
NAME = "app-modified-%d.apk"


def load():
    if os.path.exists(SP):
        return json.load(open(SP))
    return {"ws": 0, "marker": "", "next": 40, "builds": {}, "deleted": False, "flips": 0}


S = load()


def save():
    json.dump(S, open(SP, "w"))


def log(kind, **kw):
    with open(cfg["log"], "a") as f:
        f.write(json.dumps({"kind": kind, "argv": args, **kw}) + "\n")


def done(rc, out=""):
    save()
    if out:
        sys.stdout.write(out if out.endswith("\n") else out + "\n")
    sys.stdout.flush()
    sys.exit(rc)


def wsh():
    return H0 if S["ws"] == 0 else hashlib.sha256(("ws%d" % S["ws"]).encode()).hexdigest()


def kv(**pairs):
    return "\n".join("%s=%s" % (k, v) for k, v in pairs.items())


def bget(i):
    return S["builds"].get(str(i))


FINAL = ("done", "failed", "cancelled", "rejected")


def active():
    return [b for b in S["builds"].values() if b["status"] not in FINAL]


def settle(b):
    """Jalankan build yang sudah dilepas: hasilnya ditentukan saat `wait` dipanggil."""
    if b["status"] != "queued" or not b["released"]:
        return
    if sc.get("build_fail") and b["n"] == sc["build_fail"]:
        b.update(status="failed", error_code="runner_gagal", error_text="apktool gagal", dir=False)
        return
    if b["hash"] != wsh() and not (sc.get("toctou_done") and b["hold"]):
        b.update(status="failed", error_code="workspace_changed", error_text="pohon berubah", dir=bool(sc.get("failed_keeps_dir")))
        return
    b.update(status="done", dir=True, name=NAME % b["id"], sha=hashlib.sha256(("apk%d" % b["id"]).encode()).hexdigest(), size=4321,
             cert=OWNER, verify_ok=1, flipped=False)
    S["flips_for_%d" % b["id"]] = 0


def status_lines(b):
    ap, st, sg, fin = 1000.0, 1001.0, 1010.0, 1020.0
    stamps = sc.get("stamps")
    if stamps == "nonmonotonic":
        sg = 999.0
    if stamps == "equal":
        sg = st
    out = dict(build_id=b["id"], analysis_id=AID, status=b["status"], alasan="", diff_sha256=b["hash"], error_code=b.get("error_code", ""),
               error_text=b.get("error_text", ""), cancel_requested=0, output_name=b.get("name", ""), output_size=b.get("size", ""), output_sha256=b.get("sha", ""),
               cert_sha256=b.get("cert", ""), verify_ok=b.get("verify_ok", ""), approved_at="%.3f" % ap, started_at="%.3f" % st,
               signing_mulai="" if stamps == "missing" else "%.3f" % sg, finished_at="%.3f" % fin, waktu_antre="1.000", waktu_build="9.000", waktu_tanda_tangan="10.000")
    if b["status"] != "done":
        out.update(approved_at="", started_at="", signing_mulai="", finished_at="")
    if sc.get("output_name") == "salah" and b["status"] == "done":
        out["output_name"] = "../evil.apk"
    return kv(**out) + "\nl| signing_mulai=1010\n" + ("l| peak_mem_mib=812\n" if sc.get("peak") else "")


def buildctl(a):
    sub, rest = a[0], a[1:]
    if sub == "analyze":
        data = sys.stdin.buffer.read()
        log("analyze", stdin=len(data))
        if sc.get("analyze_fail"):
            done(3, kv(kode="analisis_gagal", alasan="x"))
        if sc.get("dup"):
            done(0, kv(duplicate=1, apk_id=5, analysis_id=9, sha256="a" * 64, status="done", elapsed="0.1"))
        S["analyzed"] = True
        done(0, kv(duplicate=0, apk_id=12, analysis_id=AID, sha256=hashlib.sha256(data).hexdigest(), status="done", elapsed="12.3"))
    if sub == "init":
        first = not S.get("inited")
        S["inited"] = True
        if sc.get("init_exists_first"):
            first = False
        done(0, kv(created=1 if first else 0, reason="" if first else "exists", files=10, dirs=3, bytes=100, skipped_symlink=0, skipped_special=0, skipped_root_ignored=0))
    if sub == "diff":
        if S["ws"] == 0 and not sc.get("diff_dirty"):
            done(0, kv(diff_sha256=H0, added=0, modified=0, removed=0, entries_total=0))
        extra = "\nfile.1=M res/values/strings.xml +1 -1" if S["ws"] else ""
        if S["ws"] == 0:
            extra = "\nfile.1=A x"
        done(0, kv(diff_sha256=wsh(), added=1 if S["ws"] == 0 else 0, modified=1 if S["ws"] else 0, removed=0, entries_total=1) + extra)
    if sub == "shell":
        cmd = rest[1]
        log("shell", command=cmd)
        if sc.get("shell_fail"):
            done(3, kv(status="ok", exit_code=1))
        if "sed -i" in cmd:
            S["ws"] += 1
            S["marker"] = re.search(r"VB[0-9a-f]{12}", cmd).group(0)
            done(0, kv(status="ok", exit_code=0, duration_ms=5, truncated=0) + "\no| \ne| ")
        done(0, kv(status="ok", exit_code=0, duration_ms=5, truncated=0) + '\no| <string name="app_name">VulnSample')
    if sub == "request":
        if active():
            done(3, kv(kode="build_aktif", alasan="ada build aktif"))
        i = S["next"]
        S["next"] += 1
        S["builds"][str(i)] = {"id": i, "n": len(S["builds"]) + 1, "status": "awaiting_approval", "hash": wsh(), "released": False, "hold": False, "dir": False}
        done(0, kv(build_id=i, diff_sha256=wsh(), status="awaiting_approval", added=0, modified=1, removed=0))
    if sub == "approve":
        i, h, hold = int(rest[0]), rest[rest.index("--diff-sha256") + 1], "--hold" in rest
        b = bget(i)
        if b is None:
            done(0 if sc.get("approve_missing_rc0") else 3, kv(kode="build_tidak_ada", alasan="x"))
        if b["status"] == "awaiting_approval":
            if h != b["hash"] and not sc.get("wrong_hash_accepted"):
                done(3, kv(kode="diff_berubah", alasan="x"))
            b["status"] = "queued"
            b["hold"] = hold
        elif b["status"] == "queued" and h != b["hash"]:
            done(3, kv(kode="diff_berubah", alasan="x"))
        if not hold:
            b["released"] = True
        done(0, kv(build_id=i, status="queued", enqueued=0 if hold else 1, hold=1 if hold else 0, persetujuan="pemilik-lewat-CLI"))
    if sub == "wait":
        i = int(rest[0])
        b = bget(i)
        trace = "--trace" in rest
        log("wait", build=i, timeout=rest[rest.index("--timeout") + 1] if "--timeout" in rest else "")
        if sc.get("hang_wait") == b["n"] and not os.path.exists(cfg["hang_marker"]):
            open(cfg["hang_marker"], "w").write("mulai")
            time.sleep(60)
        if b.get("cancel_asked"):
            done(3, kv(kode="waktu_habis", alasan="x", status=b["status"], elapsed="1.0"))
        if b["status"] == "queued" and not b["released"]:
            done(3, kv(kode="waktu_habis", alasan="x", status="queued", elapsed="1.0"))
        if b["status"] == "awaiting_approval":
            done(3, kv(kode="waktu_habis", alasan="x", status="awaiting_approval", elapsed="1.0"))
        if b["status"] == "queued" and sc.get("stuck_queue"):
            done(3, kv(kode="waktu_habis", alasan="x", status="queued", elapsed="1.0"))
        settle(b)
        tr = ""
        if trace and not sc.get("trace_empty") and b["status"] in ("done", "failed"):
            tr = "trace.1=queued@0.0\ntrace.2=building@1.0\ntrace.3=signing@9.0\ntrace.4=%s@20.0\n" % b["status"]
        if b["status"] == "done":
            done(0, tr + kv(status="done", elapsed="20.0"))
        done(3, tr + kv(status=b["status"], elapsed="2.0", error_code=b.get("error_code", ""), error_text=b.get("error_text", ""), kode="tidak_selesai"))
    if sub == "cancel":
        i = int(rest[0])
        b = bget(i)
        log("cancel", build=i)
        if b is None:
            done(3, kv(kode="build_tidak_ada", alasan="x"))
        if b["status"] in FINAL:
            done(3, kv(kode="sudah_final", alasan="x"))
        if sc.get("stuck_after_cancel"):
            b["cancel_asked"] = True
        else:
            b["status"] = "cancelled"
            b["dir"] = False
            if sc.get("cancel_wrong"):
                done(0, kv(build_id=i, hasil="requested"))
        done(0, kv(build_id=i, hasil="cancelled"))
    if sub == "status":
        if rest[0] == "--analysis":
            if S["deleted"]:
                done(3, kv(kode="analisis_tidak_ada", alasan="x"))
            bs = sorted(S["builds"].values(), key=lambda b: b["id"])
            dirs = [str(b["id"]) for b in bs if b.get("dir")]
            done(0, kv(analysis_id=AID, builds=",".join("%d:%s" % (b["id"], b["status"]) for b in bs), build_dirs=",".join(dirs), build_dirs_n=len(dirs)))
        b = bget(int(rest[0]))
        if b is None:
            done(3, kv(kode="build_tidak_ada", alasan="x"))
        done(0, status_lines(b))
    if sub == "artifact-info":
        i = int(rest[0])
        b = bget(i)
        if b is None:
            done(3, kv(kode="build_tidak_ada", alasan="x"))
        if b["status"] != "done":
            done(3, kv(kode="belum_selesai", alasan="x"))
        log("artifact-info", build=i, flipped=b["flipped"])
        if b["flipped"] and not sc.get("flip_undetected"):
            done(3, kv(kode="hash_tidak_cocok", alasan="x", disk_sha256="f" * 64, cocok=0, build_id=i, output_name=b["name"], output_size=b["size"], output_sha256=b["sha"]))
        if b["flipped"] and sc.get("flip_undetected"):
            done(0, kv(build_id=i, output_name=b["name"], output_size=b["size"], output_sha256=b["sha"], cert_sha256=b["cert"], disk_sha256=b["sha"], cocok=1))
        done(0, kv(build_id=i, output_name=b["name"], output_size=b["size"], output_sha256=b["sha"], cert_sha256=b["cert"], disk_sha256=b["sha"], cocok=1))
    if sub == "delete":
        log("delete", analysis=int(rest[0]))
        if active():
            done(3, kv(hasil="busy", builds_ada=1, bench_ada=1, work_ada=1) + "\n" + kv(kode="busy", alasan="x"))
        S["deleted"] = True
        S["builds"] = {}
        left = 1 if sc.get("delete_left") else 0
        done(3 if left else 0, kv(hasil="deleted", builds_ada=left, bench_ada=0, work_ada=0) + (("\n" + kv(kode="sisa_direktori", alasan="x")) if left else ""))
    done(64, "")


def main():
    rest = args[1:] if args[:1] == ["compose"] else None
    if args[:1] == ["inspect"]:
        log("inspect")
        cid = args[-1]
        svc = cid.replace("cid-", "")
        if "Log" in " ".join(args):
            done(0, "Health check gagal: contoh\n")
        done(0, "unhealthy" if sc.get("unhealthy") == svc else "healthy")
    if rest is None:
        log("lain")
        done(97, "fake-docker: tak dikenal")
    while rest and rest[0] == "--profile":
        rest = rest[2:]
    cmd, rest = rest[0], rest[1:]
    if cmd == "version":
        log("version")
        done(sc.get("version_rc", 0), "" if sc.get("version_rc") else "5.6.0")
    if cmd == "ps":
        log("ps")
        done(0, "cid-" + rest[-1])
    if cmd == "logs":
        log("logs")
        done(0, "Traceback ... PermissionError: [Errno 13]" if sc.get("logs_permission") else "web siap")
    if cmd in ("exec", "run"):
        env = []
        while rest and rest[0].startswith("-"):
            if rest[0] == "-e":
                env.append(rest[1])
                rest = rest[2:]
            else:
                rest = rest[1:]
        svc, c = rest[0], rest[1:]
        if sc.get("image_old") == svc and c[:1] in (["test"], ["grep"]):
            log("image", svc=svc)
            done(1, "")
        if c[:2] == ["test", "-f"] or c[:1] == ["grep"]:
            log("image", svc=svc)
            done(0, "")
        if c[:1] == ["bench-daemon"]:
            log("bench-check")
            done(sc.get("bench_check_rc", 0), "landlock_abi=4")
        if c[:2] == ["test", "!"] or c[:2] == ["test", "-d"]:
            log("mount-lain", svc=svc)
            done(sc.get("mount_other_rc", 0), "")
        if c[:1] == ["ls"]:
            log("ls", svc=svc, path=c[-1])
            done(0, "g%d-1\n" % AID if (svc == "signer" and sc.get("signwork_left")) else "")
        if svc == "web" and c[:3] == ["python", "-m", "app.buildctl"]:
            log("buildctl", sub=c[3], argv_ctl=c[3:])
            buildctl(c[3:])
        if svc == "signer" and c[:2] == ["signer-selftest", "--check-apk"]:
            aid, bid, name = c[2:5]
            b = bget(int(bid))
            log("selftest", build=int(bid), name=name)
            d = dict(signers=1, v2=1, v3=1, cert=OWNER, zipalign="ok", sha=b["sha"], size=b["size"])
            d.update(sc.get("selftest", {}))
            done(sc.get("selftest_rc", 0), kv(**d))
        if svc == "runner" and c[:1] == ["sh"] and "bench_tulis" in " ".join(c):
            log("mount", env=env)
            done(sc.get("mount_rc", 0), sc.get("mount_out", "mount=ok"))
        if svc == "runner" and c[:1] == ["sh"] and "vb-absent" in c:
            log("absent", paths=c[c.index("vb-absent") + 1:])
            bad = 0
            for p in c[c.index("vb-absent") + 1:]:
                m = re.match(r"/data/builds/\d+/(\d+)(/.*)?$", p)
                b = bget(int(m.group(1))) if m else None
                # folder build gagal hanya berisi build.log: isi (unsigned.apk, src/) tidak ada; folder build `done` berisi artefak
                if b is not None and b.get("dir") and (m.group(2) is None or b["status"] == "done"):
                    bad = 1
            if sc.get("absent_fail"):
                bad = 1
            done(bad, "")
        if svc == "runner" and c[:1] == ["python3"] and "# vb-flip" in c[2]:
            aid, bid, name = c[3:6]
            b = bget(int(bid))
            log("flip", build=int(bid), name=name)
            b["flipped"] = not b["flipped"]
            done(0, "flip=ok")
        if svc == "runner" and c[:1] == ["python3"] and "# vb-isi" in c[2]:
            log("isi", argv_isi=c[3:])
            if "isi" in sc:
                done(sc["isi"][0], sc["isi"][1])
            done(0, kv(apktool="ok", strings_baru=1, strings_lama=0, jejak_asal=1, jejak_diff=1, selisih_n=4, selisih_luar_n=0))
        if svc == "worker" and c[:2] == ["python", "-c"] and "tasks.run_build" in c[2]:
            b = bget(int(c[3]))
            log("run_build", build=int(c[3]))
            if sc.get("run_build_works") and b is not None:
                b["dir"] = True
            done(0, "")
        if svc == "worker" and c[:2] == ["python", "-c"] and "prune_for" in c[2]:
            log("prune", env=env, aid=c[3])
            keep = int(sc.get("prune_keep", 2))
            dn = sorted([b for b in S["builds"].values() if b["status"] == "done"], key=lambda b: b["id"])
            gone = dn[:-keep] if keep < len(dn) else []
            for b in gone:
                del S["builds"][str(b["id"])]
            done(0, "pruned=" + ",".join(str(b["id"]) for b in gone))
        log("tak-dikenal", svc=svc, c=c)
        done(97, "fake-docker: tak dikenal")
    log("lain2")
    done(97, "fake-docker: tak dikenal")


main()
'''

FAKE_KEYSTORE = """#!/usr/bin/env bash
case "${1-}" in
  present) exit "${FAKE_KS_PRESENT_RC:-0}" ;;
  check) echo "izin kunci benar"; exit "${FAKE_KS_CHECK_RC:-0}" ;;
  info) echo "  SHA-256 (heks kecil): %s"; exit 0 ;;
esac
exit 64
"""


class Rig:
    def __init__(self, tmp_path: Path):
        self.root = tmp_path
        self.repo = tmp_path / "repo"
        self.bin = tmp_path / "bin"
        self.state = tmp_path / "state.json"
        self.calls_log = tmp_path / "calls.jsonl"
        self.hang_marker = tmp_path / "hang.marker"
        for d in (self.repo / "scripts", self.bin, self.repo / "secrets", self.repo / "testdata"):
            d.mkdir(parents=True, exist_ok=True)
        self.script = self.repo / "scripts/verify-build.sh"
        if SCRIPT_SRC.exists():
            shutil.copy2(SCRIPT_SRC, self.script)
        ks = self.repo / "scripts/keystore.sh"
        ks.write_text(FAKE_KEYSTORE % OWNER)
        ks.chmod(0o755)
        (self.repo / "secrets/signing_keystore.p12").write_bytes(b"P12-PALSU" * 40)
        (self.repo / "secrets/signing_keystore_pass").write_text(PW + "\n")
        (self.repo / "testdata/vulnsample.apk").write_bytes(b"PK\x03\x04" + b"apk-uji" * 100)
        self.scenario: dict = {}
        self.write_docker()

    def write_docker(self):
        cfgp = self.root / "cfg.json"
        cfgp.write_text(json.dumps({"scenario": self.scenario, "statefile": str(self.state), "log": str(self.calls_log), "owner": OWNER,
                                    "hang_marker": str(self.hang_marker)}))
        docker = self.bin / "docker"
        docker.write_text(FAKE_DOCKER.replace("@PY@", sys.executable).replace("@CFG@", repr(str(cfgp))))
        docker.chmod(0o755)

    def scn(self, **kw):
        self.scenario.update(kw)
        self.write_docker()
        return self

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if k not in ("COMPOSE", "COMPOSE_FILE", "COMPOSE_PROFILES", "DOCKER_CMD", "BIG_MB", "KEYSTORE_STAMP", "TIMEOUT_BUILD",
                                                                "TIMEOUT_SIGN", "VB_STRICT_DIFF")}
        env.update({"PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "LC_ALL": "C.UTF-8"})
        env.update(extra)
        return env

    def popen(self, *args, **env):
        return subprocess.Popen(["bash", str(self.script), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env(**env), cwd=self.root,
                                start_new_session=True)

    def run(self, *args, timeout=120, **env):
        return subprocess.run(["bash", str(self.script), *args], capture_output=True, text=True, timeout=timeout, env=self.env(**env), cwd=self.root)

    def reset(self):
        """Keadaan palsu dan catatan panggilan dikosongkan (untuk tes yang menjalankan skrip dua kali)."""
        self.state.unlink(missing_ok=True)
        self.calls_log.unlink(missing_ok=True)

    def calls(self) -> list[dict]:
        return [json.loads(ln) for ln in self.calls_log.read_text().splitlines()] if self.calls_log.exists() else []

    def kinds(self, *kinds) -> list[dict]:
        return [c for c in self.calls() if c["kind"] in kinds]


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path)


HEADER_RE = re.compile(r"^LANGKAH\s+\| STATUS\s+\| KETERANGAN$", re.M)


def table(out: str) -> dict[str, tuple[str, str]]:
    rows = {}
    for line in out.splitlines():
        parts = [p.strip() for p in line.split(" | ", 2)]
        if len(parts) == 3 and parts[1] in ("OK", "GAGAL", "DILEWATI", "INFO"):
            rows[parts[0]] = (parts[1], parts[2])
    return rows


def status_of(rows, step: str) -> str:
    hits = [v for k, v in rows.items() if k == step]
    assert hits, f"baris '{step}' tidak ada di tabel: {list(rows)}"
    return hits[0][0]


def run_ok(rig, **env):
    res = rig.run(**env)
    return res, table(res.stdout)


# ================================================================================ bentuk skrip dan Makefile
def test_the_script_exists_is_executable_and_passes_bash_n():
    assert SCRIPT_SRC.exists(), "scripts/verify-build.sh belum ada"
    assert os.access(SCRIPT_SRC, os.X_OK)
    assert SCRIPT_SRC.read_text().startswith("#!/usr/bin/env bash\n")
    done = subprocess.run(["bash", "-n", str(SCRIPT_SRC)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_makefile_has_the_verify_build_target_phony_and_help():
    text = MAKEFILE.read_text()
    phony = next(ln for ln in text.splitlines() if ln.startswith(".PHONY:"))
    assert "verify-build" in phony.split()
    assert re.search(r"^verify-build: .*## .+\n\t@COMPOSE=\"\$\(COMPOSE\)\" \./scripts/verify-build\.sh$", text, re.M)
    assert "verify-build" in subprocess.run(["make", "-n", "verify-build"], capture_output=True, text=True, cwd=ROOT).stdout
    helped = subprocess.run(["make", "help"], capture_output=True, text=True, cwd=ROOT).stdout
    assert "verify-build" in helped


def host_code() -> str:
    """Kode bash di HOST: tanpa komentar dan tanpa isi heredoc (heredoc = skrip yang dijalankan DI DALAM kontainer uid 10001)."""
    out, end = [], None
    for ln in SCRIPT_SRC.read_text().splitlines():
        if end is not None:
            if ln.strip() == end:
                end = None
            continue
        m = re.search(r"<<'(\w+)'\s*$", ln)
        if m:
            end = m.group(1)
        if ln.lstrip().startswith("#"):
            continue
        out.append(ln)
    return "\n".join(out)


def test_the_script_never_uses_forbidden_patterns():
    code = host_code()
    assert not re.search(r"\bjq\b", code)
    assert "exec -u" not in code and "--user root" not in code and "-u root" not in code
    assert not re.search(r"\brm\b[^\n]*/data", code)                     # host tidak menghapus di volume
    assert "docker volume" not in code and "docker run" not in code
    assert "flock" in code and "secrets/.verify-build.lock" in code      # kunci antar-proses
    assert "trap" in code


def test_a05_no_exec_into_runner_and_no_multi_operand_test_e():
    code = host_code()
    for ln in code.splitlines():
        if re.search(r"\bexec\b", ln) and re.search(r"\brunner\b", ln):
            pytest.fail(f"exec ke runner dilarang (A-05): {ln.strip()}")
    full = SCRIPT_SRC.read_text()
    assert not re.search(r"test ! -e\s+[^\s;|&]+\s+(?!\|\||&&|;|\)|\})[^\s;]", full), "test ! -e dengan banyak operand dilarang (A-05)"
    assert len(re.findall(r"for p in [^;]*; do test ! -e \"\$p\" \|\| ", full)) >= 2
    # setiap pemanggilan runner berbentuk `run --rm --no-deps -T runner` (pembantu `cr`), tidak ada `$COMPOSE ... runner` lain
    assert re.search(r"^cr\(\) \{ OUT=\"\$\(exec 9>&-; \$COMPOSE run --rm --no-deps -T \"\$@\"", full, re.M)
    for ln in code.splitlines():
        if "$COMPOSE" in ln and re.search(r"\brunner\b", ln):
            pytest.fail(f"pemanggilan runner harus lewat pembantu cr: {ln.strip()}")


def test_a05_every_recorded_runner_call_is_a_oneshot_run(rig):
    run_ok(rig)
    runner_calls = [c for c in rig.calls() if "runner" in c["argv"] and c["kind"] not in ("ps", "inspect")]
    assert len(runner_calls) >= 6
    for c in runner_calls:
        a = c["argv"]
        assert "exec" not in a, a
        i = a.index("run")
        assert a[i:i + 5] == ["run", "--rm", "--no-deps", "-T", "runner"], a


# ================================================================================ jalur sukses
def test_all_ok_gives_exit_0_and_one_table_with_every_step(rig):
    res, rows = run_ok(rig)
    assert res.returncode == 0, res.stdout + res.stderr
    assert len(HEADER_RE.findall(res.stdout)) == 1
    for step in STEPS:
        assert step in rows, (step, list(rows))
        assert status_of(rows, step) in ("OK", "INFO"), (step, rows[step])
    for step in STEPS[:-1]:
        assert status_of(rows, step) == "OK", (step, rows[step])
    assert "GAGAL" not in HEADER_RE.split(res.stdout, 1)[1]
    assert "✓ semua OK" in res.stdout


def test_the_script_deletes_only_its_own_test_analysis_and_exactly_once(rig):
    res, _ = run_ok(rig)
    assert res.returncode == 0
    deletes = rig.kinds("delete")
    assert [d["analysis"] for d in deletes] == [AID]


def test_calls_follow_the_documented_step_order(rig):
    run_ok(rig)
    subs = [c["argv_ctl"][0] for c in rig.kinds("buildctl")]
    assert subs[0] == "analyze"
    first = {s: subs.index(s) for s in ("analyze", "init", "shell", "diff", "request", "approve", "wait", "status", "artifact-info", "cancel", "delete")}
    assert first["analyze"] < first["init"] < first["shell"] < first["request"] < first["wait"] < first["artifact-info"] < first["delete"]
    assert subs[-1] == "delete"
    kinds = [c["kind"] for c in rig.calls()]
    assert kinds.index("selftest") < kinds.index("flip") < kinds.index("isi") < kinds.index("prune") < kinds.index("delete")


def test_step_2_streams_the_apk_through_stdin_with_uniq(rig):
    run_ok(rig)
    call = next(c for c in rig.kinds("buildctl") if c["argv_ctl"][0] == "analyze")
    assert call["argv_ctl"][:3] == ["analyze", "-", "--uniq"]
    an = rig.kinds("analyze")[0]
    assert an["stdin"] == len((rig.repo / "testdata/vulnsample.apk").read_bytes())
    assert call["argv"][:4] == ["compose", "exec", "-T", "web"] or call["argv"][:2] == ["compose", "--profile"] or "exec" in call["argv"]


def test_step_4_uses_the_real_shell_with_an_unexpanded_ws_and_a_random_marker(rig):
    run_ok(rig)
    cmds = [c["command"] for c in rig.kinds("shell")]
    sed = [c for c in cmds if "sed -i" in c]
    assert len(sed) == 2                                          # langkah 4 dan langkah 9
    markers = {re.search(r"VB[0-9a-f]{12}", c).group(0) for c in sed}
    assert len(markers) == 2
    for c in cmds:
        assert "$WS/project/res/values/strings.xml" in c          # `$WS` TIDAK diekspansi di host
    assert any("grep -o" in c for c in cmds)


def test_step_5_covers_all_four_negatives_and_the_worker_oneshot_has_the_documented_shape(rig):
    run_ok(rig)
    rb = rig.kinds("run_build")
    assert len(rb) == 1
    argv = rb[0]["argv"]
    assert argv[argv.index("run"):argv.index("run") + 5] == ["run", "--rm", "--no-deps", "-T", "worker"]
    assert argv[-3:] == ["python", "-c", argv[-2]] or "tasks.run_build(int(sys.argv[1]))" in argv[-2]
    approve = [c["argv_ctl"] for c in rig.kinds("buildctl") if c["argv_ctl"][0] == "approve"]
    assert any(a[1] == "999999999" for a in approve)              # id tak ada
    wrong = [a for a in approve if a[1] == "40"]                   # build pertama (langkah 5): satu approve, dengan hash SALAH
    assert len(wrong) == 1
    real = {a[3] for a in approve if a[1] not in ("40", "999999999")}
    assert wrong[0][3] not in real


def test_step_6_waits_with_trace_and_a_generous_timeout(rig):
    run_ok(rig)
    w = next(c for c in rig.kinds("buildctl") if c["argv_ctl"][0] == "wait" and "--trace" in c["argv_ctl"])
    t = int(w["argv_ctl"][w["argv_ctl"].index("--timeout") + 1])
    assert t >= 1800 + 120
    rig.reset()
    res, rows = run_ok(rig, TIMEOUT_BUILD="3000")
    w2 = [c for c in rig.kinds("buildctl") if c["argv_ctl"][0] == "wait" and "--trace" in c["argv_ctl"]][-1]
    assert int(w2["argv_ctl"][w2["argv_ctl"].index("--timeout") + 1]) >= 3000 + 120


def test_step_6_reports_stage_times_from_the_db_and_never_decides_on_the_trace(rig):
    rig.scn(trace_empty=True, peak=True)
    res, rows = run_ok(rig)
    assert res.returncode == 0, res.stdout
    assert status_of(rows, "6 build nyata") == "OK"
    note = rows["6 build nyata"][1]
    assert "antre" in note and "build" in note and "tanda tangan" in note
    assert "812" in res.stdout                                    # peak_mem_mib hanya dilaporkan


@pytest.mark.parametrize("stamps", ["missing", "nonmonotonic", "equal"])
def test_a04_missing_or_non_monotonic_db_stamps_fail_step_6(rig, stamps):
    rig.scn(stamps=stamps)
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert status_of(rows, "6 build nyata") == "GAGAL"
    assert "signing_mulai" in rows["6 build nyata"][1]
    assert status_of(rows, "7 verifikasi independen (signer)") == "DILEWATI"


def test_a04_the_criterion_does_not_read_the_polled_trace(rig):
    code = "\n".join(ln for ln in SCRIPT_SRC.read_text().splitlines() if not ln.lstrip().startswith("#"))
    assert re.search(r"signing_mulai", code)
    assert not re.search(r"trace\.\d.*(signing|building)\s*\]\s*&&", code)


def test_step_6_build_failure_skips_the_dependent_steps_but_runs_the_independent_ones(rig):
    rig.scn(build_fail=2)                                          # build ke-2 (langkah 6) gagal
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert status_of(rows, "6 build nyata") == "GAGAL"
    for step in ("7 verifikasi independen (signer)", "7b deteksi ubah-pasca-terbit", "8 isi artefak"):
        assert status_of(rows, step) == "DILEWATI"
    assert status_of(rows, "9 negatif TOCTOU") == "OK"
    assert status_of(rows, "12 kebersihan") == "OK"


# ================================================================================ langkah 1
def test_step_1_old_image_stops_everything_after_it_with_the_make_up_hint(rig):
    rig.scn(image_old="runner")
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert status_of(rows, "1 prasyarat") == "GAGAL"
    assert "make up" in rows["1 prasyarat"][1]
    for step in STEPS[1:12]:
        assert status_of(rows, step) == "DILEWATI", step
    assert not rig.kinds("buildctl", "delete")                     # tidak ada analisis dibuat, tidak ada yang dihapus


@pytest.mark.parametrize("scn", [{"unhealthy": "bench"}, {"bench_check_rc": 1}, {"mount_rc": 1, "mount_out": "bench_tulis=1"}, {"version_rc": 1}, {"image_old": "web"},
                                 {"image_old": "signer"}, {"image_old": "worker"}, {"image_old": "bench"}])
def test_step_1_each_prerequisite_failure_is_a_failure(rig, scn):
    rig.scn(**scn)
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert status_of(rows, "1 prasyarat") == "GAGAL"
    assert status_of(rows, "2 analisis uji") == "DILEWATI"


def test_step_1_missing_sample_apk_tells_how_to_build_it_and_mentions_the_known_traceback(rig):
    (rig.repo / "testdata/vulnsample.apk").unlink()
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert status_of(rows, "1 prasyarat") == "GAGAL"
    note = rows["1 prasyarat"][1]
    assert "python3 scripts/sample-apk/build.py" in note and "TemporaryDirectory" in note


def test_step_1_missing_keystore_makes_zero_docker_calls(rig):
    res = rig.run(FAKE_KS_PRESENT_RC="1")
    assert res.returncode == 1
    rows = table(res.stdout)
    assert status_of(rows, "1 prasyarat") == "GAGAL"
    assert not rig.calls()


def test_step_1_mount_isolation_uses_a_one_shot_runner_with_a_loop(rig):
    run_ok(rig)
    m = rig.kinds("mount")
    assert len(m) == 1
    argv = m[0]["argv"]
    assert argv[argv.index("run"):argv.index("run") + 6] == ["run", "--rm", "--no-deps", "-T", "runner", "sh"]
    script = argv[-1]
    assert "for p in /data/signwork /data/signspool /data/benchspool /data/files /data/db; do test ! -e \"$p\"" in script
    assert "/data/bench/" in script and "/data/builds/" in script


# ================================================================================ langkah 2-4
def test_step_2_duplicate_stops_the_run_and_never_deletes_the_owners_analysis(rig):
    rig.scn(dup=True)
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert status_of(rows, "2 analisis uji") == "GAGAL"
    assert "duplicate" in rows["2 analisis uji"][1]
    for step in STEPS[2:12]:
        assert status_of(rows, step) == "DILEWATI", step
    assert not rig.kinds("delete")                                # analisis 9 milik pemilik TIDAK disentuh


def test_step_2_failed_analysis_still_cleans_up_the_created_analysis(rig):
    rig.scn(analyze_fail=True)
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert status_of(rows, "2 analisis uji") == "GAGAL"


def test_step_3_init_that_does_not_create_or_a_dirty_diff_fails(rig):
    rig.scn(init_exists_first=True)
    res, rows = run_ok(rig)
    assert status_of(rows, "3 init + diff kosong") == "GAGAL"
    assert status_of(rows, "4 ubah string via shell") == "DILEWATI"
    assert [d["analysis"] for d in rig.kinds("delete")] == [AID]   # analisis uji tetap dibersihkan


def test_step_3_nonempty_baseline_diff_fails(rig):
    rig.scn(diff_dirty=True)
    res, rows = run_ok(rig)
    assert status_of(rows, "3 init + diff kosong") == "GAGAL"


def test_step_4_failed_shell_fails_and_halts_the_rest(rig):
    rig.scn(shell_fail=True)
    res, rows = run_ok(rig)
    assert status_of(rows, "4 ubah string via shell") == "GAGAL"
    assert status_of(rows, "5 negatif persetujuan") == "DILEWATI"
    assert res.returncode == 1


# ================================================================================ langkah 5
@pytest.mark.parametrize("scn", [{"approve_missing_rc0": True}, {"wrong_hash_accepted": True}, {"run_build_works": True}])
def test_step_5_each_broken_guard_is_a_failure_and_the_run_continues_cleanly(rig, scn):
    rig.scn(**scn)
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert status_of(rows, "5 negatif persetujuan") == "GAGAL"
    assert status_of(rows, "6 build nyata") in ("OK", "GAGAL")     # alur lanjut; pembersihan tetap jalan
    assert [d["analysis"] for d in rig.kinds("delete")] == [AID]


# ================================================================================ langkah 7, 7b, 8
@pytest.mark.parametrize("sel", [{"signers": 2}, {"v2": 0}, {"v3": 0}, {"cert": OTHER}, {"zipalign": "gagal"}, {"sha": "e" * 64}, {"size": 1}])
def test_step_7_every_independent_check_must_hold(rig, sel):
    rig.scn(selftest=sel)
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert status_of(rows, "7 verifikasi independen (signer)") == "GAGAL"
    assert status_of(rows, "7b deteksi ubah-pasca-terbit") == "OK"  # tidak bergantung pada hasil 7


def test_step_7_nonzero_exit_of_the_selftest_is_a_failure(rig):
    rig.scn(selftest_rc=3)
    res, rows = run_ok(rig)
    assert status_of(rows, "7 verifikasi independen (signer)") == "GAGAL"


def test_step_7_passes_integer_ids_and_the_output_name_to_check_apk(rig):
    run_ok(rig)
    st = rig.kinds("selftest")[0]
    argv = st["argv"]
    assert argv[argv.index("signer-selftest"):][:2] == ["signer-selftest", "--check-apk"]
    assert re.fullmatch(r"\d+", argv[-3]) and re.fullmatch(r"\d+", argv[-2])
    assert re.fullmatch(r"[A-Za-z0-9._-]+-modified-\d+\.apk", argv[-1])


def test_step_7b_flips_twice_and_requires_hash_mismatch_then_match(rig):
    res, rows = run_ok(rig)
    assert status_of(rows, "7b deteksi ubah-pasca-terbit") == "OK"
    assert len(rig.kinds("flip")) == 2
    ai = [c for c in rig.kinds("artifact-info")]
    assert [c["flipped"] for c in ai].count(True) == 1
    flip = rig.kinds("flip")[0]["argv"]
    assert flip[flip.index("run"):flip.index("run") + 6] == ["run", "--rm", "--no-deps", "-T", "runner", "python3"]


def test_step_7b_undetected_modification_is_a_failure_and_the_byte_is_restored(rig):
    rig.scn(flip_undetected=True)
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert status_of(rows, "7b deteksi ubah-pasca-terbit") == "GAGAL"
    assert len(rig.kinds("flip")) == 2                              # byte DIKEMBALIKAN walau deteksi gagal
    assert status_of(rows, "8 isi artefak") in ("OK", "GAGAL", "DILEWATI")


def test_step_8_passes_marker_old_value_provenance_and_strict_flag(rig):
    run_ok(rig)
    isi = rig.kinds("isi")[0]["argv_isi"]
    aid, bid, name, marker, old, asal, dsha, strict = isi
    assert aid == str(AID) and bid.isdigit() and name.endswith(f"-modified-{bid}.apk")
    assert re.fullmatch(r"VB[0-9a-f]{12}", marker)
    assert old == "VulnSample"
    assert re.fullmatch(r"[0-9a-f]{64}", asal) and re.fullmatch(r"[0-9a-f]{64}", dsha)
    assert strict == "0"


def test_step_8_strict_mode_is_off_by_default_and_opt_in(rig):
    res, rows = run_ok(rig, VB_STRICT_DIFF="1")
    assert rig.kinds("isi")[0]["argv_isi"][-1] == "1"


def test_step_8_content_failure_is_reported_with_the_container_listing(rig):
    rig.scn(isi=[3, "apktool=ok\nstrings_baru=0\nstrings_lama=1\njejak_asal=1\njejak_diff=1\nselisih_n=5\nselisih_luar_n=1\nselisih_luar.1=M res/values/public.xml"])
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert status_of(rows, "8 isi artefak") == "GAGAL"
    assert "public.xml" in rows["8 isi artefak"][1]


def test_step_8_outside_allowlist_is_info_when_not_strict(rig):
    rig.scn(isi=[0, "apktool=ok\nstrings_baru=1\nstrings_lama=0\njejak_asal=1\njejak_diff=1\nselisih_n=5\nselisih_luar_n=1\nselisih_luar.1=M res/values/public.xml"])
    res, rows = run_ok(rig)
    assert res.returncode == 0
    assert status_of(rows, "8 isi artefak") == "OK"
    assert any(v[0] == "INFO" and "public.xml" in v[1] for v in rows.values())


# ================================================================================ langkah 9-12
def test_step_9_toctou_ends_in_a_failed_build_and_releases_with_the_original_hash(rig):
    res, rows = run_ok(rig)
    assert status_of(rows, "9 negatif TOCTOU") == "OK"
    approves = [c["argv_ctl"] for c in rig.kinds("buildctl") if c["argv_ctl"][0] == "approve"]
    held = [a for a in approves if "--hold" in a]
    assert len(held) == 2                                          # langkah 9 dan 10
    h1 = held[0][held[0].index("--diff-sha256") + 1]
    released = [a for a in approves if "--hold" not in a and a[a.index("--diff-sha256") + 1] == h1]
    assert released


def test_step_9_a_build_that_ran_despite_the_changed_workspace_is_a_failure(rig):
    rig.scn(toctou_done=True)
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert status_of(rows, "9 negatif TOCTOU") == "GAGAL"


def test_step_9_leftover_src_or_unsigned_apk_is_a_failure(rig):
    rig.scn(absent_fail=True)
    res, rows = run_ok(rig)
    assert status_of(rows, "9 negatif TOCTOU") == "GAGAL"
    assert status_of(rows, "10 negatif pembatalan") == "GAGAL"


def test_step_10_wrong_cancel_result_fails(rig):
    rig.scn(cancel_wrong=True)
    res, rows = run_ok(rig)
    assert status_of(rows, "10 negatif pembatalan") == "GAGAL"
    assert res.returncode == 1


def test_step_11_runs_the_real_prune_in_a_oneshot_with_build_keep_2(rig):
    res, rows = run_ok(rig)
    assert status_of(rows, "11 retensi") == "OK"
    pr = rig.kinds("prune")[0]
    argv = pr["argv"]
    assert argv[argv.index("run"):argv.index("run") + 7] == ["run", "--rm", "--no-deps", "-T", "-e", "BUILD_KEEP=2", "worker"]
    assert "builds.prune_for(int(sys.argv[1]))" in argv[-2] and argv[-1] == str(AID)


def test_step_11_ignores_the_folder_a_failed_build_keeps(rig):
    """e2e proses nyata: build gagal (workspace_changed langkah 9) tetap menyisakan folder berisi build.log; retensi menghitung `done` dan gagal terpisah,
    jadi langkah 11 hanya boleh menghitung folder milik build `done`."""
    rig.scn(failed_keeps_dir=True)
    res, rows = run_ok(rig)
    assert status_of(rows, "9 negatif TOCTOU") == "OK"
    assert status_of(rows, "11 retensi") == "OK"
    assert res.returncode == 0


def test_step_11_wrong_number_of_surviving_builds_fails(rig):
    rig.scn(prune_keep=3)
    res, rows = run_ok(rig)
    assert status_of(rows, "11 retensi") == "GAGAL"
    assert res.returncode == 1


@pytest.mark.parametrize("scn,needle", [({"delete_left": True}, "builds_ada"), ({"logs_permission": True}, "PermissionError")])
def test_step_12_leftovers_or_permission_errors_fail(rig, scn, needle):
    rig.scn(**scn)
    res, rows = run_ok(rig)
    assert status_of(rows, "12 kebersihan") == "GAGAL"
    assert needle in rows["12 kebersihan"][1]
    assert res.returncode == 1


def test_step_12_leftover_signwork_entry_for_the_test_analysis_is_info_not_failure(rig):
    rig.scn(signwork_left=True)
    res, rows = run_ok(rig)
    assert status_of(rows, "12 kebersihan") == "OK"
    assert res.returncode == 0
    assert any(v[0] == "INFO" and "signwork" in v[1] for v in rows.values())


# ================================================================================ trap
def test_trap_after_a_failure_leaves_no_active_build_and_deletes_last(rig):
    rig.scn(shell_fail=True)                                       # langkah 4 gagal; tidak ada build aktif, hanya analisis
    res, rows = run_ok(rig)
    subs = [c["argv_ctl"][0] for c in rig.kinds("buildctl")]
    assert subs[-1] == "delete" and subs.count("delete") == 1


def test_trap_cancels_then_waits_then_deletes_when_interrupted_during_the_build_wait(rig):
    rig.scn(hang_wait=2)                                           # build ke-2 (langkah 6) menggantung di `wait`
    proc = rig.popen()
    deadline = time.time() + 30
    while not rig.hang_marker.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert rig.hang_marker.exists(), "skrip tidak mencapai wait langkah 6"
    os.killpg(proc.pid, signal.SIGINT)
    out, err = proc.communicate(timeout=60)
    assert proc.returncode == 1
    rows = table(out)
    assert status_of(rows, "dihentikan") == "GAGAL"
    after = [c for c in rig.kinds("buildctl") if c["kind"] == "buildctl"]
    seq = [(c["argv_ctl"][0], c["argv_ctl"][1:2]) for c in after]
    cut = max(i for i, (s, _) in enumerate(seq) if s == "wait" and ("--trace" in after[i]["argv_ctl"]))
    tail = [s for s, _ in seq[cut + 1:]]
    assert tail.index("cancel") < tail.index("wait") < tail.index("delete"), tail
    assert tail[-1] == "delete"


def test_trap_reports_a_stuck_test_analysis_and_still_tries_the_delete(rig):
    rig.scn(stuck_after_cancel=True, hang_wait=2)
    proc = rig.popen()
    deadline = time.time() + 30
    while not rig.hang_marker.exists() and time.time() < deadline:
        time.sleep(0.05)
    os.killpg(proc.pid, signal.SIGINT)
    out, err = proc.communicate(timeout=60)
    assert proc.returncode == 1
    assert f"analisis uji TERTINGGAL aid={AID}" in out + err
    assert rig.kinds("delete"), "delete tetap dicoba"


def test_step_12_stuck_active_build_is_reported_not_silently_ignored(rig):
    rig.scn(stuck_after_cancel=True)
    res, rows = run_ok(rig)
    assert res.returncode == 1
    assert f"TERTINGGAL aid={AID}" in res.stdout + res.stderr


# ================================================================================ kunci, argumen, BIG_MB, rahasia
def test_usage_errors_exit_64_and_help_exits_0(rig):
    assert rig.run("--salah").returncode == 64
    assert rig.run("x", "y").returncode == 64
    h = rig.run("--help")
    assert h.returncode == 0 and "verify-build" in h.stdout
    assert not rig.calls()


@pytest.mark.parametrize("val", ["0", "1101", "abc", "-5", "1e3"])
def test_big_mb_out_of_range_is_a_usage_error(rig, val):
    res = rig.run(BIG_MB=val)
    assert res.returncode == 64
    assert not rig.calls()


def test_big_mb_is_optional_and_adds_one_info_row_when_given(rig):
    _, rows = run_ok(rig)
    assert not any("BIG_MB" in k for k in rows)
    rig.reset()
    res, rows2 = run_ok(rig, BIG_MB="1000")
    assert res.returncode == 0
    big = [v for k, v in rows2.items() if "BIG_MB" in k]
    assert big and big[0][0] == "INFO"


def test_second_instance_is_refused_while_the_lock_is_held(rig):
    lock = rig.repo / "secrets/.verify-build.lock"
    holder = subprocess.Popen(["flock", str(lock), "sleep", "30"])
    try:
        for _ in range(100):
            if lock.exists():
                break
            time.sleep(0.05)
        time.sleep(0.2)
        res = rig.run()
        assert res.returncode == 1
        assert "verify-build lain sedang berjalan" in res.stderr
        assert not HEADER_RE.findall(res.stdout)
        assert not rig.calls()
    finally:
        holder.kill()
        holder.wait()


def test_no_secret_value_ever_appears_in_any_argv_or_the_output(rig):
    res, _ = run_ok(rig)
    assert len(rig.calls()) > 30, "skrip harus benar-benar memanggil docker"
    blob = json.dumps(rig.calls()) + res.stdout + res.stderr
    assert PW not in blob
    for c in rig.calls():
        assert not any("signing_keystore" in a or "--ks-pass" in a for a in c["argv"])


def test_every_docker_call_goes_through_compose_or_inspect(rig):
    run_ok(rig)
    assert len(rig.calls()) > 30, "skrip harus benar-benar memanggil docker"
    for c in rig.calls():
        assert c["argv"][0] in ("compose", "inspect"), c["argv"]
        assert c["kind"] not in ("lain", "lain2", "tak-dikenal"), c


def test_keystore_overlay_is_exported_like_signer_verify_when_the_script_is_called_directly(rig):
    code = SCRIPT_SRC.read_text()
    assert "COMPOSE_FILE=docker-compose.yml:docker-compose.keystore.yml" in code
    assert "COMPOSE_PROFILES" in code


def test_the_table_is_printed_once_even_when_interrupted_or_failing(rig):
    rig.scn(selftest={"signers": 2})
    res, _ = run_ok(rig)
    assert len(HEADER_RE.findall(res.stdout)) == 1
