"""CLI administrasi.

    printf '%s' "$PASSWORD" | python -m app.cli hash-stdin > secrets/admin_password_hash

Password dibaca dari stdin (bukan argumen) supaya tidak muncul di daftar proses/riwayat shell.
Hanya hash argon2id yang dicetak ke stdout; pesan galat ke stderr.
"""

from __future__ import annotations

import argparse
import sys

from .security import hash_password

MIN_LEN = 12


def hash_stdin() -> int:
    password = sys.stdin.read()
    if password.endswith("\n"):  # hilangkan satu newline penutup (mis. dari `echo`)
        password = password[:-1]
    if len(password) < MIN_LEN:
        print(f"Password terlalu pendek (minimal {MIN_LEN} karakter).", file=sys.stderr)
        return 1
    print(hash_password(password))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hash-stdin", help="Baca password dari stdin, cetak hash argon2id")
    args = parser.parse_args()
    if args.cmd == "hash-stdin":
        return hash_stdin()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
