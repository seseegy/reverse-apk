"""Pembantu: kurung diri dengan Landlock lalu `exec` bash. Dijalankan sebagai `python3 -m bench.confined_exec '<spec json>'`.

Alasan memakai proses pembantu (bukan preexec_fn): preexec_fn menjalankan kode Python di antara fork dan exec dan tidak aman bila ada thread di daemon.
GAGAL TERTUTUP: bash baru dijalankan SETELAH Landlock terpasang DAN uji kenari lulus. Bila tidak, keluar dengan kode khusus dan bash tidak pernah jalan.
"""

from __future__ import annotations

import json
import os
import resource
import sys

from .landlock import Confinement, LandlockError, Rule

EXIT_LANDLOCK = 120      # pengurungan tidak bisa dipasang
EXIT_CANARY = 121        # terpasang tetapi tidak efektif
EXIT_BAD_SPEC = 122


def _limits(spec: dict) -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (int(spec["nofile"]), int(spec["nofile"])))
    resource.setrlimit(resource.RLIMIT_FSIZE, (int(spec["fsize"]), int(spec["fsize"])))
    cpu = int(spec["cpu_seconds"])
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 5))
    resource.setrlimit(resource.RLIMIT_NPROC, (int(spec["nproc"]), int(spec["nproc"])))     # bom fork: berlaku per-uid, jadi mencakup seluruh kontainer


def main(argv: list[str]) -> int:
    try:
        spec = json.loads(argv[1])
        rules = [Rule(r["path"], int(r["rights"]), bool(r.get("optional"))) for r in spec["rules"]]
        command, cwd, env, canary = str(spec["command"]), str(spec["cwd"]), dict(spec["env"]), str(spec["canary"])
        _limits(spec)
        os.chdir(cwd)
    except (IndexError, KeyError, ValueError, TypeError, OSError) as exc:
        print(f"bench: spesifikasi tidak valid: {type(exc).__name__}", file=sys.stderr)
        return EXIT_BAD_SPEC
    try:
        ports = tuple(int(x) for x in spec.get("net_ports") or ())
        conf = Confinement(rules, connect_ports=ports)
        if ports and not conf.net_enforced:                 # jaringan diminta tetapi kernel tidak bisa mengunci TCP: JANGAN jalan dengan TCP terbuka
            print("bench: Landlock tidak bisa mengunci TCP (ABI < 4); jaringan diminta tetapi tidak aman", file=sys.stderr)
            return EXIT_LANDLOCK
        conf.apply()
        conf.close()
    except LandlockError as exc:
        print(f"bench: pengurungan gagal: {exc}", file=sys.stderr)
        return EXIT_LANDLOCK
    try:                                                    # kenari: daftar folder di luar aturan HARUS ditolak
        os.listdir(canary)
        print("bench: pengurungan tidak efektif (kenari terbaca)", file=sys.stderr)
        return EXIT_CANARY
    except PermissionError:
        pass
    except OSError as exc:
        print(f"bench: uji kenari tidak konklusif: {type(exc).__name__}", file=sys.stderr)
        return EXIT_CANARY
    # Penanda "sudah terkurung dan lulus uji kenari": ditulis lewat pipa SEBELUM exec. Daemon hanya menganggap perintah berjalan bila penanda ada,
    # sehingga kode keluar 120-122 dari perintah itu sendiri (mis. `exit 121`) tidak bisa tertukar dengan kegagalan pengurungan.
    try:
        mfd = int(spec["marker_fd"])
        os.write(mfd, b"1")
        os.set_inheritable(mfd, False)                      # tertutup otomatis saat exec: bash tidak mewarisinya
    except (KeyError, ValueError, TypeError, OSError):
        print("bench: penanda tidak bisa ditulis", file=sys.stderr)
        return EXIT_BAD_SPEC
    os.execve("/usr/bin/bash", ["bash", "--noprofile", "--norc", "-c", command], env)
    return 127


if __name__ == "__main__":
    sys.exit(main(sys.argv))
