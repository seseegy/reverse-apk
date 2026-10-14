"""Perbaikan `apktool b` di kontainer runner. /tmp runner SENGAJA noexec, dan rootfs runner read-only milik root.

Dua akar masalah berurutan (keduanya terbukti di VPS):
1. (PR #43) Tanpa `--aapt`, apktool 3.0.3 mengekstrak aapt2 dari jarnya ke direktori sementara lalu menjalankannya; exec di tmpfs noexec ditolak (errno 13).
2. (PR ini) Dengan `--aapt <berkas>`, `AaptManager.setBinaryExecutable` memanggil `File.setExecutable(true)` => chmod(2) SELALU, walau bit x sudah ada. chmod ditolak pada
   rootfs read-only (EROFS) dan pada berkas milik root oleh uid 10001 (EPERM) => "Could not set aapt binary as executable". Uji sandbox PR #43 lolos karena berkas
   aapt2-nya milik pengguna yang sama pada disk yang bisa ditulis (sandbox != kontainer).

Perbaikan BUKAN menambah `exec` ke /tmp dan bukan menambal jar: ada SATU tmpfs khusus kecil (/opt/aapt-exec, exec, milik uid 10001) berisi salinan aapt2 pin yang disalin dan
diverifikasi wrapper `apktool`. Penjaga di bawah memastikan itu SATU-SATUNYA tmpfs exec di seluruh stack.

Hanya yang bisa diuji TANPA Docker: pemeriksaan teks, wrapper yang dijalankan sungguhan dengan `java` palsu, dan helper galat di runner-selftest.
Bukti nyata (build image, `make runner-selftest`) ada di VPS.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RUNNER_DOCKERFILE = (ROOT / "services/runner/Dockerfile").read_text(encoding="utf-8")
SELFTEST = (ROOT / "services/runner/runner-selftest").read_text(encoding="utf-8")
WRAPPER = ROOT / "services/runner/apktool-wrapper"
WRAPPER_TEXT = WRAPPER.read_text(encoding="utf-8") if WRAPPER.exists() else ""  # berkas hilang => tes gagal satu per satu, bukan error impor
BUILD_PY = (ROOT / "scripts/sample-apk/build.py").read_text(encoding="utf-8")
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
AAPT2 = "/opt/apktool/aapt2"
EXEC_DIR = "/opt/aapt-exec"
EXEC_ENTRY = f"{EXEC_DIR}:rw,exec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0755"
MAX_EXEC_BYTES = 16 * 1024 * 1024


def _scripts() -> dict[str, str]:
    """Semua skrip repo yang bisa memanggil `docker run --tmpfs` (build.py, bench-probe.sh, dst)."""
    return {str(p.relative_to(ROOT)): p.read_text(encoding="utf-8") for p in sorted((ROOT / "scripts").rglob("*")) if p.suffix in (".py", ".sh")}


def _joined(text: str) -> list[str]:
    """Instruksi Dockerfile tanpa komentar; baris lanjutan (`\\`) digabung."""
    joined = re.sub(r"\\\n", " ", text)
    return [ln.strip() for ln in joined.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def _tool_run() -> str:
    return next(i for i in _joined(RUNNER_DOCKERFILE) if i.startswith("RUN set -eux") and "apktool.jar" in i)


def tmpfs_entries(block: str) -> list[str]:
    """Isi daftar `tmpfs:` pada sebuah blok layanan (tanpa komentar)."""
    out, inside = [], False
    for line in block.splitlines():
        code = re.sub(r"\s+#.*$", "", line).rstrip()
        if re.match(r"^    tmpfs:\s*$", code):
            inside = True
        elif inside and re.match(r"^      - ", code):
            out.append(code.split("- ", 1)[1].strip().strip("\"'"))
        elif code.strip():
            inside = False
    return out


def has_exec_option(entry: str) -> bool:
    """True bila opsi `exec` (BUKAN `noexec`) ada pada entri tmpfs `/jalur:opsi,opsi`."""
    opts = entry.split(":", 1)[1].split(",") if ":" in entry else []
    return "exec" in [o.strip() for o in opts]


def services(compose_text: str) -> dict[str, str]:
    """Blok tiap layanan di bawah `services:` (tanpa `networks:`/`volumes:` tingkat atas)."""
    body = compose_text.split("\nservices:\n", 1)[1]
    body = re.split(r"\n(?=[A-Za-z])", body, maxsplit=1)[0]
    parts = re.split(r"(?m)^  ([\w-]+):[ \t]*$", body)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}


def _size_bytes(entry: str) -> int | None:
    m = re.search(r"(?:^|[:,])size=(\d+)([kKmMgG]?)(?:,|$)", entry)
    if not m:
        return None
    return int(m.group(1)) * {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[m.group(2).lower()]


def exec_tmpfs_violations(compose_text: str, scripts: dict[str, str]) -> list[str]:
    """Penjaga anti-regresi isolasi. SATU-SATUNYA tmpfs exec yang sah: layanan `runner`, jalur /opt/aapt-exec, nosuid+nodev, size <= 16m.
    Semua tmpfs lain (runner /tmp, bench, signer, egress, web, worker, caddy, dan `--tmpfs` di skrip) tidak boleh exec. Bentuk panjang `type: tmpfs` dilarang
    karena tak bisa diperiksa penjaga ini. Mengembalikan daftar pelanggaran (kosong = aman)."""
    bad: list[str] = []
    found: list[tuple[str, str]] = []
    for name, block in services(compose_text).items():
        if re.search(r"type:\s*tmpfs", block):
            bad.append(f"{name}: bentuk panjang `type: tmpfs` dilarang; pakai daftar `tmpfs:`")
        for e in tmpfs_entries(block):
            if has_exec_option(e):
                found.append((name, e))
    flags = [(f"skrip {n}", f) for n, t in scripts.items() for f in re.findall(r"--tmpfs[\s\"',]+([^\s\"',]+(?:,[^\s\"']*)?)", t)]
    for who, e in found + [x for x in flags if has_exec_option(x[1])]:
        path, opts = e.split(":", 1)[0], set(e.split(":", 1)[1].split(","))
        if who not in ("runner",) and not who.startswith("skrip "):
            bad.append(f"{who}: tmpfs {e!r} memuat exec; hanya runner:{EXEC_DIR} yang boleh")
        elif path != EXEC_DIR:
            bad.append(f"{who}: tmpfs exec {e!r} bukan {EXEC_DIR}")
        if not {"nosuid", "nodev"} <= opts:
            bad.append(f"{who}: tmpfs exec {e!r} harus nosuid,nodev")
        size = _size_bytes(e)
        if size is None or size > MAX_EXEC_BYTES:
            bad.append(f"{who}: tmpfs exec {e!r} harus size <= 16m (ukuran: {size})")
    if len(found) > 1:
        bad.append(f"tmpfs exec di compose harus tepat SATU, ditemukan {len(found)}: {found}")
    return bad


# ================================================================================ (a) Dockerfile runner
def test_dockerfile_extracts_pinned_aapt2_into_read_only_rootfs_before_unzip_is_purged():
    sha = re.search(r"^ARG AAPT2_SHA256=(\S+)$", RUNNER_DOCKERFILE, re.M)
    assert sha and re.fullmatch(r"[0-9a-f]{64}", sha.group(1)), "ARG AAPT2_SHA256 (64 heksadesimal) harus ada"
    run = _tool_run()
    extract = run.index("prebuilt/linux/aapt2")
    assert re.search(rf"unzip -p /opt/apktool/apktool\.jar prebuilt/linux/aapt2 > {AAPT2}\b", run), "aapt2 harus diekstrak dari jar ke /opt/apktool/aapt2"
    verify = f'echo "${{AAPT2_SHA256}}  {AAPT2}" | sha256sum -c -'
    assert verify in run and run.index(verify) > extract, "sha256 aapt2 diverifikasi SETELAH ekstraksi"
    assert f"chmod 0755 {AAPT2}" in run
    assert run.index("unzip -p") < run.index("apt-get purge -y --auto-remove curl unzip"), "ekstraksi harus SEBELUM unzip dibuang"
    # Tidak ada instruksi lain (RUN/COPY/ADD, mis. chown) yang menyentuh /opt/apktool sehingga aapt2 bisa ditulis runner; ENV hanya menyebut jalurnya.
    others = [i for i in _joined(RUNNER_DOCKERFILE) if i != run and "/opt/apktool" in i and re.match(r"(RUN|COPY|ADD)\b", i)]
    assert not others, others


def test_dockerfile_writes_pin_file_and_creates_empty_mount_point_for_the_exec_tmpfs():
    run = _tool_run()
    assert "printf '%s\\n' \"${AAPT2_SHA256}\" > /opt/apktool/aapt2.sha256" in run, "pin dibaca wrapper dari berkas (env alat dibersihkan, ENV tidak ikut)"
    assert "chmod 0644 /opt/apktool/aapt2.sha256" in run
    assert f"mkdir -p {EXEC_DIR}" in run and f"chmod 0755 {EXEC_DIR}" in run, "titik mount: milik root, tanpa isi"
    assert run.index("aapt2.sha256") > run.index(f"{AAPT2} version"), "pin ditulis setelah aapt2 terverifikasi"
    assert not re.search(r"chown\b.*(/opt/apktool|/opt/aapt-exec)", run), "sumber aapt2 dan titik mount tetap milik root"
    assert "/usr/local/bin/apktool" not in run, "wrapper kini berkas sendiri (runner/apktool-wrapper), bukan printf bertingkat kutip"
    assert "COPY runner/apktool-wrapper /usr/local/bin/apktool" in _joined(RUNNER_DOCKERFILE)
    chmods = [i for i in _joined(RUNNER_DOCKERFILE) if i.startswith("RUN chmod 0755 /usr/local/bin/")]
    assert chmods and "/usr/local/bin/apktool" in chmods[0]
    assert WRAPPER.exists() and WRAPPER.stat().st_mode & stat.S_IXUSR, "wrapper dikomit dengan bit exec"


def test_dockerfile_fails_loudly_on_non_x86_64_and_checks_the_elf():
    run = _tool_run()
    assert 'uname -m' in run and "x86_64" in run
    guard = run.index("uname -m")
    assert guard < run.index("curl -fsSL"), "pemeriksaan arsitektur harus sebelum unduhan (gagal cepat)"
    assert "exit 1" in run[guard:run.index("curl -fsSL")], "arsitektur lain harus menggagalkan build, bukan diam-diam"
    assert "GALAT" in run[guard:run.index("curl -fsSL")] and "amd64" in run[guard:run.index("curl -fsSL")], "pesan galat harus menjelaskan"
    # Berkas harus ELF 64-bit x86-64 (sha256 sudah mengikat isinya; ini jaring pengaman bila pin diganti sembarangan) dan bisa dijalankan.
    assert "7f454c46" in run and f"{AAPT2} version" in run


def test_dockerfile_exports_pin_and_exec_dir_as_env_for_the_selftest():
    assert re.search(r"^\s+AAPT2_SHA256=\$\{AAPT2_SHA256\}", RUNNER_DOCKERFILE, re.M), "selftest membaca pin dari ENV image, bukan menyalinnya"
    assert re.search(r"^\s+AAPT2_PATH=/opt/apktool/aapt2", RUNNER_DOCKERFILE, re.M)
    assert re.search(rf"^\s+AAPT2_EXEC_DIR={EXEC_DIR}", RUNNER_DOCKERFILE, re.M)


# ================================================================================ (b) compose runner: tepat dua tmpfs
def test_runner_compose_has_exactly_two_tmpfs_tmp_noexec_and_the_small_exec_one():
    block = services(COMPOSE)["runner"]
    entries = tmpfs_entries(block)
    assert len(entries) == 2, entries
    tmp = next(e for e in entries if e.startswith("/tmp:") or e == "/tmp")
    assert tmp == "/tmp:rw,size=256m,nosuid" and not has_exec_option(tmp), "/tmp runner TETAP tanpa exec (Docker menambahkan noexec)"
    exec_entry = next(e for e in entries if e != tmp)
    assert exec_entry == EXEC_ENTRY, exec_entry
    opts = set(exec_entry.split(":", 1)[1].split(","))
    assert {"rw", "exec", "nosuid", "nodev", "uid=10001", "gid=10001"} <= opts
    assert _size_bytes(exec_entry) == MAX_EXEC_BYTES and _size_bytes(exec_entry) <= MAX_EXEC_BYTES
    # Kebijakan isolasi runner TIDAK berubah.
    assert "network_mode: none" in block and re.search(r"^    read_only: true$", block, re.M)
    assert 'user: "10001:10001"' in block and "cap_drop: [ALL]" in block and "no-new-privileges:true" in block
    assert "cap_add" not in block and "privileged" not in block


# ================================================================================ (c) penjaga anti-regresi: tepat SATU tmpfs exec
def test_exec_tmpfs_guard_passes_on_the_real_repo_and_sees_every_tmpfs_service():
    assert exec_tmpfs_violations(COMPOSE, _scripts()) == []
    seen = {name for name, block in services(COMPOSE).items() if tmpfs_entries(block)}
    assert {"caddy", "web", "worker", "runner", "bench", "signer"} <= seen, f"pembaca tmpfs melewatkan layanan (penjaga jadi hampa): {seen}"
    scripts = _scripts()
    assert "--tmpfs" in scripts["scripts/sample-apk/build.py"] and "--tmpfs" in scripts["scripts/bench-probe.sh"], "pembaca --tmpfs di skrip tidak menemukan apa-apa"
    # Hanya runner yang punya tmpfs exec; layanan lain (egress tanpa tmpfs, dll.) tidak.
    execs = [(n, e) for n, b in services(COMPOSE).items() for e in tmpfs_entries(b) if has_exec_option(e)]
    assert execs == [("runner", EXEC_ENTRY)]


def _in_block(compose: str, name: str, old: str, new: str) -> str:
    """Ganti `old` -> `new` hanya di blok layanan `name` (kemunculan pertama di blok itu); gagal bila tak ada yang berubah."""
    start = compose.index(f"\n  {name}:\n")
    i = compose.index(old, start)
    return compose[:i] + new + compose[i + len(old):]


TMP_LINE = "      - /tmp:rw,size=256m,nosuid\n"
MUTATIONS = {
    "exec ditambahkan ke /tmp runner": lambda c, s: (_in_block(c, "runner", TMP_LINE, "      - /tmp:rw,size=256m,nosuid,exec\n"), s),
    "tmpfs exec kedua di runner": lambda c, s: (_in_block(c, "runner", TMP_LINE, TMP_LINE + "      - /x:rw,exec,nosuid,nodev,size=1m\n"), s),
    "tmpfs exec kedua di bench": lambda c, s: (_in_block(c, "bench", TMP_LINE, TMP_LINE + "      - /scratch:rw,exec,size=1m\n"), s),
    "exec di /tmp bench": lambda c, s: (_in_block(c, "bench", TMP_LINE, "      - /tmp:rw,size=256m,nosuid,exec\n"), s),
    "exec di /tmp signer": lambda c, s: (_in_block(c, "signer", TMP_LINE, "      - /tmp:rw,exec,size=256m,nosuid\n"), s),
    "exec di /tmp web": lambda c, s: (_in_block(c, "web", "      - /tmp\n", "      - /tmp:rw,exec\n"), s),
    "exec di /tmp worker": lambda c, s: (_in_block(c, "worker", "      - /tmp\n", "      - /tmp:rw,exec\n"), s),
    "exec di /tmp caddy": lambda c, s: (_in_block(c, "caddy", "      - /tmp\n", "      - /tmp:exec\n"), s),
    "tmpfs exec egress": lambda c, s: (_in_block(c, "egress", "    cap_drop: [ALL]\n", "    cap_drop: [ALL]\n    tmpfs:\n      - /tmp:rw,exec,nosuid,nodev,size=1m\n"), s),
    "ukuran 16m -> 64m": lambda c, s: (c.replace("nodev,size=16m,", "nodev,size=64m,"), s),
    "ukuran dihapus": lambda c, s: (c.replace("nodev,size=16m,", "nodev,"), s),
    "nodev dihapus": lambda c, s: (c.replace("nosuid,nodev,size=16m", "nosuid,size=16m"), s),
    "nosuid dihapus": lambda c, s: (c.replace("exec,nosuid,nodev,size=16m", "exec,nodev,size=16m"), s),
    "jalur exec lain (/opt/aapt-exec2)": lambda c, s: (c.replace("/opt/aapt-exec:rw,exec", "/opt/aapt-exec2:rw,exec"), s),
    "entri exec dipindah ke signer": lambda c, s: (_in_block(_in_block(c, "runner", f"      - {EXEC_ENTRY}\n", ""), "signer", TMP_LINE, TMP_LINE + f"      - {EXEC_ENTRY}\n"), s),
    "bentuk panjang type: tmpfs": lambda c, s: (_in_block(c, "web", "    read_only: true\n", "    read_only: true\n    volumes:\n      - type: tmpfs\n        target: /x\n"), s),
    "build.py: /tmp ber-exec": lambda c, s: (c, {**s, "scripts/sample-apk/build.py": s["scripts/sample-apk/build.py"].replace('"/tmp:rw,size=256m"', '"/tmp:rw,exec,size=256m"')}),
    "build.py: aapt-exec 64m": lambda c, s: (c, {**s, "scripts/sample-apk/build.py": s["scripts/sample-apk/build.py"].replace("size=16m,uid", "size=64m,uid")}),
    "skrip lain: --tmpfs exec": lambda c, s: (c, {**s, "scripts/bench-probe.sh": s["scripts/bench-probe.sh"].replace("--tmpfs /tmp:rw,size=16m,nosuid", "--tmpfs /tmp:rw,exec,size=16m,nosuid")}),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_exec_tmpfs_guard_is_not_hollow_every_mutation_is_caught(name):
    """Mutasi pembuktian: tiap pelonggaran HARUS menghasilkan pelanggaran. Bila mutasi tak mengubah apa-apa, tes ini sendiri gagal (bukan lulus diam-diam)."""
    scripts = _scripts()
    compose, new_scripts = MUTATIONS[name](COMPOSE, scripts)
    assert (compose, new_scripts) != (COMPOSE, scripts), f"mutasi {name!r} tidak mengubah apa-apa"
    assert exec_tmpfs_violations(compose, new_scripts), f"penjaga tidak mendeteksi: {name}"


def test_exec_option_detector_distinguishes_exec_from_noexec():
    assert has_exec_option("/tmp:rw,exec,size=256m") and has_exec_option("/tmp:exec") and has_exec_option("/tmp:rw,nosuid,exec")
    assert not has_exec_option("/tmp:rw,size=256m,nosuid") and not has_exec_option("/tmp:rw,noexec,nosuid") and not has_exec_option("/tmp")
    block = "  runner:\n    tmpfs:\n      - /tmp:rw,exec  # komentar\n    mem_limit: 1g\n"
    assert tmpfs_entries(block) == ["/tmp:rw,exec"]
    assert _size_bytes("/a:rw,size=16m,uid=1") == 16 * 1024 ** 2 and _size_bytes("/a:rw") is None and _size_bytes("/a:size=64m") == 64 * 1024 ** 2


# ================================================================================ (d) wrapper `apktool` (dijalankan sungguhan, tanpa root)
class Rig:
    """Lingkungan uji wrapper: sumber aapt2 palsu, berkas pin, direktori 'tmpfs' di tmp_path, dan `java` palsu yang mencetak satu argumen per baris."""

    def __init__(self, tmp_path: Path, aapt2_body: str = '#!/bin/sh\nif [ "$1" = version ]; then echo fake-aapt2; fi\nexit 0\n'):
        self.root = tmp_path
        self.src = tmp_path / "rootfs" / "aapt2"
        self.src.parent.mkdir()
        self.src.write_text(aapt2_body)
        self.src.chmod(0o755)
        self.sha = hashlib.sha256(self.src.read_bytes()).hexdigest()
        self.pin = tmp_path / "rootfs" / "aapt2.sha256"
        self.pin.write_text(self.sha + "\n")
        self.dir = tmp_path / "aapt-exec"
        self.dir.mkdir()
        self.dst = self.dir / "aapt2"
        self.jar = tmp_path / "rootfs" / "apktool.jar"
        self.jar.write_bytes(b"jar-palsu")
        self.bindir = tmp_path / "bin"
        self.bindir.mkdir()
        java = self.bindir / "java"
        java.write_text('#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done\n')
        java.chmod(0o755)

    def env(self, path: str | None = None, **over: str) -> dict[str, str]:
        env = {"PATH": path or f"{self.bindir}:/usr/bin:/bin", "HOME": str(self.root / "home"), "AAPT2_PATH": str(self.src), "AAPT2_EXEC_DIR": str(self.dir),
               "AAPT2_PIN_FILE": str(self.pin), "APKTOOL_JAR": str(self.jar)}
        env.update(over)
        return env

    def run(self, *args: str, **kw) -> subprocess.CompletedProcess:
        return subprocess.run([str(WRAPPER), *args], capture_output=True, text=True, env=self.env(**kw), timeout=60)


def test_wrapper_script_is_valid_posix_sh_and_keeps_production_flags():
    subprocess.run(["sh", "-n", str(WRAPPER)], check=True)
    assert WRAPPER_TEXT.startswith("#!/bin/sh\n") and "\nset -eu\n" in WRAPPER_TEXT
    assert '-Duser.home="${HOME:-/tmp/home}"' in WRAPPER_TEXT and "-Djava.io.tmpdir=/tmp" in WRAPPER_TEXT and "-Xmx2g" in WRAPPER_TEXT
    assert "/opt/aapt-exec" in WRAPPER_TEXT and "/opt/apktool/aapt2.sha256" in WRAPPER_TEXT and "/opt/apktool/apktool.jar" in WRAPPER_TEXT
    # Hash SALINAN (bukan sumber) diverifikasi SEBELUM rename ke tujuan; rename atomik di direktori yang sama.
    assert WRAPPER_TEXT.index('got="$(sha_of "$tmp")"') < WRAPPER_TEXT.index('mv -f "$tmp" "$dst"')
    assert 'mktemp "$dir/.aapt2.XXXXXX"' in WRAPPER_TEXT and 'cp "$src" "$tmp"' in WRAPPER_TEXT and 'cp "$src" "$dst"' not in WRAPPER_TEXT
    assert "exec java" in WRAPPER_TEXT


def test_wrapper_copies_verified_aapt2_and_inserts_aapt_for_build_subcommands(tmp_path):
    rig = Rig(tmp_path)
    for sub in ("b", "build"):
        out = rig.run(sub, "/w/proj dengan spasi", "-o", "/w/out.apk")
        assert out.returncode == 0, out.stderr
        argv = out.stdout.splitlines()
        i = argv.index(str(rig.jar))
        assert argv[i - 1] == "-jar"
        assert argv[i + 1:] == [sub, "--aapt", str(rig.dst), "/w/proj dengan spasi", "-o", "/w/out.apk"], argv
        assert f"-Duser.home={rig.root / 'home'}" in argv and "-Djava.io.tmpdir=/tmp" in argv and "-Xmx2g" in argv
    assert os.listdir(rig.dir) == ["aapt2"], "hanya aapt2 (tanpa sisa berkas sementara)"
    assert stat.S_IMODE(rig.dst.stat().st_mode) == 0o755 and hashlib.sha256(rig.dst.read_bytes()).hexdigest() == rig.sha


def test_wrapper_leaves_other_subcommands_and_global_options_alone(tmp_path):
    """Hanya argumen PERTAMA `b`/`build` yang dikenali. Opsi global di depan (`-v b`) ditolak apktool 3.0.3 sendiri ('Unrecognized command: -v', terbukti dengan jar asli;
    `-v`/`-q` sah hanya SESUDAH subperintah), jadi batasan ini terdokumentasi dan pemanggil wajib memakai `apktool b ...`."""
    rig = Rig(tmp_path)
    rig.dir.rmdir()
    for args in (["d", "-f", "-o", "/o", "/a.apk"], ["--version"], ["decode", "x.apk"], ["-v", "b", "/w/proj"], ["if", "framework.apk"]):
        out = rig.run(*args)
        assert out.returncode == 0, out.stderr
        argv = out.stdout.splitlines()
        assert "--aapt" not in argv, f"{args}: `--aapt` hanya untuk b/build"
        assert argv[argv.index(str(rig.jar)) + 1:] == args
    assert not rig.dir.exists(), "subperintah selain b/build tidak menyentuh direktori tmpfs"


def test_wrapper_reports_missing_source_and_never_runs_java(tmp_path):
    rig = Rig(tmp_path)
    out = rig.run("b", "/w/proj", AAPT2_PATH=str(tmp_path / "tidak-ada"))
    assert out.returncode == 1 and out.stdout == ""
    assert "GALAT apktool" in out.stderr and "sumber aapt2 tidak ada" in out.stderr
    assert os.listdir(rig.dir) == []


def test_wrapper_refuses_a_copy_whose_hash_differs_from_the_pin_and_leaves_nothing_behind(tmp_path):
    rig = Rig(tmp_path)
    rig.pin.write_text("0" * 64 + "\n")
    out = rig.run("b", "/w/proj")
    assert out.returncode == 1 and out.stdout == "", "java tidak boleh jalan dengan aapt2 yang hash-nya salah"
    assert "sha256" in out.stderr and "pin" in out.stderr and "GALAT apktool" in out.stderr
    assert os.listdir(rig.dir) == [], "tujuan tidak pernah berisi berkas salah, dan berkas sementara (.aapt2.*) dibersihkan"


def test_wrapper_replaces_a_corrupt_destination_and_skips_copying_a_valid_one(tmp_path):
    rig = Rig(tmp_path)
    rig.dst.write_text("rusak")
    rig.dst.chmod(0o755)
    assert rig.run("b", "/w/proj").returncode == 0
    assert hashlib.sha256(rig.dst.read_bytes()).hexdigest() == rig.sha, "salinan rusak diganti salinan sah"
    before = rig.dst.stat()
    assert rig.run("b", "/w/proj").returncode == 0
    after = rig.dst.stat()
    assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns), "salinan sah tidak disalin ulang"
    assert os.listdir(rig.dir) == ["aapt2"]


def test_wrapper_explains_when_the_exec_directory_is_missing_or_not_writable(tmp_path):
    rig = Rig(tmp_path)
    out = rig.run("b", "/w/proj", AAPT2_EXEC_DIR=str(tmp_path / "tidak-ada"))
    assert out.returncode == 1 and out.stdout == ""
    assert "tmpfs" in out.stderr and "noexec" in out.stderr and "/opt/aapt-exec:rw,exec" in out.stderr, "pesan harus menyebut tmpfs khusus dan bahwa /tmp sengaja noexec"
    if os.geteuid() != 0:  # root selalu bisa menulis
        rig.dir.chmod(0o555)
        try:
            out = rig.run("b", "/w/proj")
        finally:
            rig.dir.chmod(0o755)
        assert out.returncode == 1 and "tmpfs" in out.stderr and out.stdout == ""


def test_wrapper_fails_clearly_when_the_copy_cannot_be_executed(tmp_path):
    """Sumber ber-hash cocok tetapi tidak bisa dijalankan (meniru direktori tujuan ter-mount noexec: exec -> 126)."""
    rig = Rig(tmp_path, aapt2_body="#!/bin/sh\nexit 3\n")
    out = rig.run("b", "/w/proj")
    assert out.returncode == 1 and out.stdout == ""
    assert "tidak bisa dijalankan" in out.stderr and "noexec" in out.stderr and "kode 3" in out.stderr


@pytest.mark.parametrize("content", [None, "", "bukan-hash\n", "ab" * 31 + "\n"])
def test_wrapper_requires_a_valid_pin_file(tmp_path, content):
    rig = Rig(tmp_path)
    if content is None:
        rig.pin.unlink()
    else:
        rig.pin.write_text(content)
    out = rig.run("b", "/w/proj")
    assert out.returncode == 1 and out.stdout == "" and "pin hash aapt2" in out.stderr
    assert os.listdir(rig.dir) == []


def test_wrapper_parallel_first_builds_do_not_corrupt_the_copy(tmp_path):
    rig = Rig(tmp_path)
    procs = [subprocess.Popen([str(WRAPPER), "b", f"/w/p{i}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=rig.env()) for i in range(8)]
    results = [(p.communicate(timeout=60), p.returncode) for p in procs]
    assert all(rc == 0 for _, rc in results), results
    assert os.listdir(rig.dir) == ["aapt2"] and hashlib.sha256(rig.dst.read_bytes()).hexdigest() == rig.sha


def _path_without(tmp_path: Path, *excluded: str, fail: dict[str, str] | None = None) -> str:
    """PATH berisi hanya utilitas yang dipakai wrapper (symlink), tanpa yang di `excluded`; `fail` = utilitas yang diganti skrip palsu."""
    d = tmp_path / "pathbin"
    d.mkdir()
    for tool in ("tr", "cut", "sha256sum", "mktemp", "cp", "chmod", "mv", "rm", "id", "env", "sh", "flock"):
        real = shutil.which(tool)
        if tool not in excluded and real and not (fail and tool in fail):
            (d / tool).symlink_to(real)
    for tool, body in (fail or {}).items():
        (d / tool).write_text(body)
        (d / tool).chmod(0o755)
    (d / "java").symlink_to(tmp_path / "bin" / "java")
    return str(d)


@pytest.mark.skipif(shutil.which("flock") is None, reason="flock (util-linux) tidak ada")
def test_wrapper_serializes_the_first_copy_so_parallel_builds_do_not_all_copy(tmp_path):
    """tmpfs 16m hanya muat ~2 salinan aapt2; penyalin serentak tanpa kunci sama-sama kena ENOSPC (terukur: 4 build paralel SEMUA gagal). `cp` lambat + log
    membuktikan kunci: hanya SATU build yang menyalin, yang lain menunggu lalu memakai hasilnya."""
    rig = Rig(tmp_path)
    log = tmp_path / "cp.log"
    path = _path_without(tmp_path, fail={"cp": f'#!/bin/sh\necho x >> "{log}"\nsleep 0.5\nexec {shutil.which("cp")} "$@"\n'})
    procs = [subprocess.Popen([str(WRAPPER), "b", f"/w/p{i}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=rig.env(path=path)) for i in range(4)]
    results = [(p.communicate(timeout=60), p.returncode) for p in procs]
    assert all(rc == 0 for _, rc in results), results
    assert log.read_text().splitlines() == ["x"], "lebih dari satu build menyalin aapt2 (kunci flock hilang?)"
    assert os.listdir(rig.dir) == ["aapt2"] and hashlib.sha256(rig.dst.read_bytes()).hexdigest() == rig.sha


def test_wrapper_still_works_without_flock(tmp_path):
    rig = Rig(tmp_path)
    path = _path_without(tmp_path, "flock")
    assert not any(os.access(os.path.join(p, "flock"), os.X_OK) for p in path.split(":"))
    out = rig.run("b", "/w/proj", path=path)
    assert out.returncode == 0, out.stderr
    assert os.listdir(rig.dir) == ["aapt2"]


def test_wrapper_cleans_the_temp_file_when_the_copy_fails(tmp_path):
    """Meniru tmpfs penuh: `cp` gagal setelah berkas sementara dibuat. Pesan jelas, tidak ada sisa `.aapt2.*`, dan tujuan tidak dibuat."""
    rig = Rig(tmp_path)
    path = _path_without(tmp_path, fail={"cp": "#!/bin/sh\nexit 1\n"})
    out = rig.run("b", "/w/proj", path=path)
    assert out.returncode == 1 and out.stdout == ""
    assert "gagal menyalin aapt2" in out.stderr and "tmpfs penuh" in out.stderr
    assert os.listdir(rig.dir) == []


# ================================================================================ (e) runner-selftest
def test_selftest_checks_tmp_noexec_and_installed_aapt2():
    assert "noexec" in SELFTEST and "tmp runner noexec" in SELFTEST
    assert "/proc/self/mountinfo" in SELFTEST, "noexec dibaca dari opsi mount /tmp"
    assert "/bin/true" in SELFTEST and "PermissionError" in SELFTEST, "dan dibuktikan dengan percobaan exec sungguhan"
    assert "AAPT2_PATH" in SELFTEST and "AAPT2_SHA256" in SELFTEST and "hashlib" in SELFTEST
    assert "b'\\x7fELF'" in SELFTEST or '\\x7fELF' in SELFTEST
    assert "os.access" in SELFTEST and "os.X_OK" in SELFTEST
    # Pin dibaca dari ENV image, tidak disalin ke skrip.
    assert re.search(r"^ARG AAPT2_SHA256=(\S+)$", RUNNER_DOCKERFILE, re.M).group(1) not in SELFTEST


def test_selftest_checks_the_dedicated_exec_tmpfs_and_that_tmp_stays_noexec():
    assert 'os.environ.get("AAPT2_EXEC_DIR", "/opt/aapt-exec")' in SELFTEST and "RUNNER_UID = 10001" in SELFTEST and "MAX_EXEC_BYTES = 16 * 1024 * 1024" in SELFTEST
    block = SELFTEST.split("# 6b.", 1)[1].split("# 6.", 1)[0]
    assert "exec_fstype != \"tmpfs\"" in block and "\"noexec\" in exec_opts" in block, "mount terpisah, tmpfs, dan TIDAK noexec"
    assert '{"rw", "nosuid", "nodev"} <= set(exec_opts)' in block
    assert "os.statvfs" in block and "MAX_EXEC_BYTES" in block and "exec_uid != RUNNER_UID" in block
    assert '"noexec" not in tmp_opts' in block and "/tmp TIDAK lagi noexec" in block, "/tmp harus TETAP noexec"
    assert "tmpfs exec khusus" in block


def test_selftest_checks_the_pinned_source_cannot_be_changed_by_the_runner():
    block = SELFTEST.split("# Sumber TIDAK bisa diubah runner", 1)[1].split("# 6b.", 1)[0]
    assert "os.chmod(aapt2, 0o755)" in block and 'open(aapt2, "ab")' in block and "except OSError" in block
    assert "sumber aapt2 tidak bisa diubah runner" in block and "== pin" in block
    assert "aapt2.sha256" in block and "AAPT2_SHA256" in block, "berkas pin harus sama dengan ENV image"


def test_selftest_runs_apktool_b_through_the_wrapper_like_production_then_checks_the_exec_dir_contents():
    assert '["apktool", "b"' in SELFTEST
    assert "apktool.jar" not in SELFTEST and "-jar" not in SELFTEST, "apktool b harus lewat wrapper, bukan java -jar langsung"
    env_block = SELFTEST.split("tool_env = {", 1)[1].split("}", 1)[0]
    assert "AAPT2" not in env_block, "lingkungan bersih seperti runner-daemon: wrapper tidak boleh bergantung pada env AAPT2_*"
    assert '"--aapt" not in wrapper or "aapt-exec" not in wrapper' in SELFTEST and '"aapt2.sha256" not in wrapper' in SELFTEST, "selftest memeriksa isi wrapper produksi"
    after = SELFTEST.split('["apktool", "b"', 1)[1]
    assert 'f"isi {exec_dir} hanya aapt2' in after, "isi /opt/aapt-exec diperiksa SESUDAH apktool b dijalankan"
    tail = after.split('f"isi {exec_dir} hanya aapt2', 1)[0]
    assert 'names == ["aapt2"]' in tail and "os.listdir(exec_dir)" in tail and "copy_sha == pin" in tail and "RUNNER_UID" in tail


def _selftest_function(name: str):
    tree = ast.parse(SELFTEST)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    ns: dict = {"re": re}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "runner-selftest", "exec"), ns)  # noqa: S102 - fungsi murni dari berkas repo sendiri
    return ns[name]


TRACE = """I: Using Apktool 3.0.3 on proj
I: Building resources with aapt2...
Exception in thread "main" brut.androlib.exceptions.AndrolibException: brut.common.BrutException: could not exec: [/tmp/aapt2_1.tmp, compile]
\tat brut.androlib.res.Aapt2.invoke(Aapt2.java:80)
Caused by: java.io.IOException: Cannot run program "/tmp/aapt2_1.tmp": error=13, Permission denied
\tat java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1170)
\tat java.base/java.lang.ProcessImpl.start(ProcessImpl.java:225)
\t... 5 more
"""


def test_selftest_error_report_keeps_the_root_cause_instead_of_the_stack_tail():
    diagnose = _selftest_function("diagnose")
    msg = diagnose(TRACE)
    assert "Caused by: java.io.IOException" in msg and "error=13, Permission denied" in msg
    assert "ProcessImpl.start" not in msg and "5 more" not in msg, "ekor stack trace yang menyesatkan tidak boleh jadi satu-satunya isi"
    assert "Building resources with aapt2" in msg, "300 karakter pertama keluaran bermakna ikut ditampilkan"
    assert "\n" not in msg
    long = diagnose("x" * 5000)
    assert len(long) < 700
    assert diagnose("") == "(tanpa keluaran)"
    # Tanpa 'Caused by:'/'error=' tetap menampilkan awal keluaran.
    assert "galat biasa" in diagnose("galat biasa\n\tat a.b(C.java:1)\n")
    # Galat baris pertama wrapper dan galat chmod apktool juga sampai ke pengguna.
    assert "Could not set aapt binary as executable: /opt/apktool/aapt2" in diagnose("Could not set aapt binary as executable: /opt/apktool/aapt2\n\tat brut.X.y(Z.java:1)\n")
    assert "GALAT apktool: sha256 salinan aapt2" in diagnose("GALAT apktool: sha256 salinan aapt2 (abc) != pin (def)\n")


def test_selftest_uses_diagnose_for_the_apktool_b_failure_message():
    block = SELFTEST.split("# 6. Kelayakan build", 1)[1]
    assert "diagnose(text)" in block
    assert "[-3:]" not in block, "ekor 3 baris stack trace adalah pelaporan lama yang memotong akar masalah"


# ================================================================================ (f) scripts/sample-apk/build.py
def test_sample_build_script_uses_the_exec_tmpfs_and_the_production_wrapper():
    cmd = BUILD_PY.split("def main()", 1)[1]
    flags = re.findall(r'"--tmpfs", "([^"]+)"', cmd)
    assert len(flags) == 2 and EXEC_ENTRY in flags, flags
    tmp = next(f for f in flags if f != EXEC_ENTRY)
    assert tmp.startswith("/tmp:") and not has_exec_option(tmp), "/tmp di build.py tetap tanpa exec"
    assert "apktool b /w/proj -o /w/unsigned.apk" in cmd, "memakai wrapper image yang sama dengan produksi"
    assert "java -Xmx" not in cmd and "-jar" not in cmd and "/opt/apktool/apktool.jar" not in cmd, "tidak lagi memanggil jar langsung"
    assert "chmod" in BUILD_PY.split("def main()", 1)[0] and "setExecutable" in BUILD_PY, "komentar menjelaskan akar masalah chmod"


# ================================================================================ (g) dokumen
def test_docs_record_the_exec_tmpfs_root_cause_and_the_sandbox_lesson():
    pin = re.search(r"^ARG AAPT2_SHA256=(\S+)$", RUNNER_DOCKERFILE, re.M).group(1)
    deploy = (ROOT / "docs/deploy.md").read_text(encoding="utf-8")
    prd = (ROOT / "docs/prd/09-bundles-and-workbench.md").read_text(encoding="utf-8")
    audit = (ROOT / "audit.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert pin in deploy and AAPT2 in deploy and "noexec" in deploy
    assert "terbukti jalan offline di sandbox" not in prd, "klaim lama (keliru untuk kontainer runner) harus dikoreksi"
    assert "noexec" in prd and AAPT2 in prd
    for name, text in (("deploy.md", deploy), ("prd 09", prd), ("audit.md", audit)):
        assert EXEC_DIR in text, name
        assert "setExecutable" in text and "AaptManager" in text, f"{name}: akar masalah chmod belum dicatat"
        assert "kompromi" in text.lower(), f"{name}: kompromi keamanan tmpfs exec harus dicatat jujur"
    assert EXEC_DIR in readme
    assert "non-pemilik" in audit.lower() and "read-only" in audit and "bukan hanya" in audit, "pelajaran: uji sandbox meniru non-pemilik + filesystem read-only"
    assert "mode=1777" in deploy, "rencana cadangan bila opsi uid/gid tmpfs ditolak"
