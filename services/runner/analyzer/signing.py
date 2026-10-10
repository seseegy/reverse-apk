"""Sertifikat penanda tangan & skema tanda tangan APK (FR-3.2).

* Skema v1: berkas META-INF/*.RSA|DSA|EC (PKCS#7) di dalam ZIP.
* Skema v2/v3/v3.1: "APK Signing Block" tepat sebelum central directory (struktur biner, di-parse dengan struct).
* Sertifikat X.509 (DER) diserahkan ke `keytool -printcert`; stdlib tidak punya parser X.509.

APK adalah masukan tak tepercaya: semua panjang dibatasi dan diperiksa terhadap ukuran berkas.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

from .common import Findings

SIG_BLOCK_MAGIC = b"APK Sig Block 42"
BLOCK_IDS = {0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1", 0x6DFF800D: "v4 (stamp)"}
MAX_CERTS = 8
MAX_CERT_BYTES = 64 * 1024
KEYTOOL_TIMEOUT = 20

_DEBUG_SUBJECT = re.compile(r"CN=Android Debug", re.I)
_FIELD = re.compile(r"^\s*(Owner|Issuer|Serial number|Valid from|Signature algorithm name|Subject Public Key Algorithm|SHA256|SHA1):\s*(.*)$")


def _find_eocd(data: bytes) -> int:
    """Offset End-Of-Central-Directory (cari dari belakang; komentar ZIP maks 65535 byte)."""
    start = max(0, len(data) - 65557)
    idx = data.rfind(b"PK\x05\x06", start)
    return idx


def read_signing_block(apk: Path) -> dict[int, bytes] | None:
    """Kembalikan {id_blok: nilai} dari APK Signing Block, atau None bila tidak ada/rusak."""
    try:
        size = apk.stat().st_size
        with apk.open("rb") as fh:
            tail_len = min(size, 65557 + 22)
            fh.seek(size - tail_len)
            tail = fh.read(tail_len)
            eocd_rel = _find_eocd(tail)
            if eocd_rel < 0 or eocd_rel + 22 > len(tail):
                return None
            cd_offset = struct.unpack_from("<I", tail, eocd_rel + 16)[0]
            if cd_offset < 32 or cd_offset > size:
                return None
            fh.seek(cd_offset - 24)
            footer = fh.read(24)
            if len(footer) != 24 or footer[8:] != SIG_BLOCK_MAGIC:
                return None
            block_size = struct.unpack_from("<Q", footer, 0)[0]
            if block_size < 24 or block_size > 64 * 1024 * 1024 or block_size + 8 > cd_offset:
                return None
            fh.seek(cd_offset - block_size - 8)
            # Tata letak: [size:8][pasangan ID-nilai ...][size:8][magic:16]; size tidak menghitung field size awal.
            body = fh.read(block_size - 16)          # size awal (8) + seluruh pasangan (block_size - 24)
            if len(body) != block_size - 16 or struct.unpack_from("<Q", body, 0)[0] != block_size:
                return None
            pairs = body[8:]
    except (OSError, struct.error):
        return None

    out: dict[int, bytes] = {}
    pos = 0
    while pos + 12 <= len(pairs) and len(out) < 32:
        (length,) = struct.unpack_from("<Q", pairs, pos)
        if length < 4 or pos + 8 + length > len(pairs):
            break
        (bid,) = struct.unpack_from("<I", pairs, pos + 8)
        out[bid] = pairs[pos + 12: pos + 8 + length]
        pos += 8 + length
    return out


def _lp(buf: bytes, pos: int) -> tuple[bytes, int] | None:
    """Baca blok 'length-prefixed' (uint32 LE)."""
    if pos + 4 > len(buf):
        return None
    (n,) = struct.unpack_from("<I", buf, pos)
    if n > len(buf) - pos - 4:
        return None
    return buf[pos + 4: pos + 4 + n], pos + 4 + n


def certs_from_scheme_block(value: bytes) -> list[bytes]:
    """Ambil sertifikat X.509 (DER) dari nilai blok v2/v3: signers -> signer -> signed data -> certificates."""
    certs: list[bytes] = []
    signers = _lp(value, 0)
    if not signers:
        return certs
    spos = 0
    sdata = signers[0]
    while spos < len(sdata) and len(certs) < MAX_CERTS:
        signer = _lp(sdata, spos)
        if not signer:
            break
        spos = signer[1]
        signed = _lp(signer[0], 0)
        if not signed:
            continue
        sd = signed[0]
        digests = _lp(sd, 0)
        if not digests:
            continue
        cert_list = _lp(sd, digests[1])
        if not cert_list:
            continue
        cpos = 0
        while cpos < len(cert_list[0]) and len(certs) < MAX_CERTS:
            cert = _lp(cert_list[0], cpos)
            if not cert:
                break
            cpos = cert[1]
            if 0 < len(cert[0]) <= MAX_CERT_BYTES:
                certs.append(cert[0])
    return certs


def _parse_keytool(output: str) -> list[dict]:
    """Pecah keluaran `keytool -printcert` menjadi daftar sertifikat."""
    certs: list[dict] = []
    cur: dict | None = None
    for line in output.splitlines():
        m = _FIELD.match(line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if key == "Owner":
            cur = {"subject": val}
            certs.append(cur)
        elif cur is not None:
            name = {"Issuer": "issuer", "Serial number": "serial", "Signature algorithm name": "sig_algorithm",
                    "Subject Public Key Algorithm": "key_algorithm", "SHA256": "sha256", "SHA1": "sha1"}.get(key)
            if name and name not in cur:
                cur[name] = val
            elif key == "Valid from":
                vm = re.match(r"(.*?)\s+until:\s*(.*)$", val)
                cur["valid_from"], cur["valid_until"] = (vm.group(1), vm.group(2)) if vm else (val, "")
    return certs


def _keytool(args: list[str]) -> str:
    # JVM mengabaikan $HOME dan memakai home dari /etc/passwd (read-only di runner): paksa lewat -J.
    home = os.environ.get("HOME", "/tmp")
    try:
        r = subprocess.run(["keytool", f"-J-Duser.home={home}", "-J-Xmx256m", *args], capture_output=True, text=True, timeout=KEYTOOL_TIMEOUT,
                           stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return ""
    return r.stdout if r.returncode == 0 else ""


def analyze_signing(apk: Path, findings: Findings, log) -> dict:  # noqa: ANN001
    schemes: list[str] = []
    certs: list[dict] = []

    # --- v1 (JAR signing): berkas sertifikat di META-INF
    v1_names: list[str] = []
    try:
        with zipfile.ZipFile(apk) as zf:
            v1_names = [n for n in zf.namelist() if re.match(r"^META-INF/[^/]+\.(RSA|DSA|EC)$", n, re.I)]
            has_sf = any(re.match(r"^META-INF/[^/]+\.SF$", n, re.I) for n in zf.namelist())
    except (zipfile.BadZipFile, OSError):
        has_sf = False
    if v1_names and has_sf:
        schemes.append("v1")
        out = _keytool(["-printcert", "-jarfile", str(apk)])
        certs.extend(_parse_keytool(out))

    # --- v2/v3/v3.1: APK Signing Block
    block = read_signing_block(apk)
    block_certs: list[bytes] = []
    if block:
        for bid, name in BLOCK_IDS.items():
            if bid in block and name not in schemes:
                schemes.append(name)
        for bid in (0x7109871A, 0xF05368C0, 0x1B93AD61):
            if bid in block:
                block_certs.extend(certs_from_scheme_block(block[bid]))
    if block_certs:
        seen = {c.get("sha256") for c in certs}
        with tempfile.TemporaryDirectory(prefix="cert-") as td:
            for i, der in enumerate(block_certs[:MAX_CERTS]):
                f = Path(td) / f"c{i}.der"
                f.write_bytes(der)
                for c in _parse_keytool(_keytool(["-printcert", "-file", str(f)])):
                    if c.get("sha256") not in seen:
                        seen.add(c.get("sha256"))
                        certs.append(c)

    if not schemes:
        log("W: APK tidak memiliki tanda tangan yang dapat dikenali")
        findings.add(category="signing", severity="medium", rule_id="signing.unsigned",
                     title="APK tidak ditandatangani", key="unsigned",
                     description="Tidak ditemukan tanda tangan v1/v2/v3. Android menolak memasang APK tanpa tanda tangan; "
                                 "ini kemungkinan build yang dibongkar/dipasang ulang.")
    if schemes and "v2" not in schemes and "v3" not in schemes:
        findings.add(category="signing", severity="low", rule_id="signing.v1_only",
                     title="Hanya tanda tangan v1 (JAR)", key="v1only",
                     description="Tanpa v2/v3, tanda tangan v1 rentan terhadap manipulasi isi APK (celah 'Janus' pada "
                                 "Android < 7). Gunakan skema v2 atau lebih baru.")
    is_debug = any(_DEBUG_SUBJECT.search(c.get("subject", "")) for c in certs)
    if is_debug:
        findings.add(category="signing", severity="high", rule_id="signing.debug_cert",
                     title="Ditandatangani dengan sertifikat debug Android", key="debugcert",
                     description="Sertifikat 'CN=Android Debug' bersifat publik dan sama untuk semua developer; siapa pun "
                                 "bisa membuat APK yang tampak berasal dari penerbit yang sama. Tidak boleh dirilis.")
    sha1_only = [c for c in certs if "sha1" in (c.get("sig_algorithm", "").lower()) or "md5" in (c.get("sig_algorithm", "").lower())]
    if sha1_only:
        findings.add(category="signing", severity="low", rule_id="signing.weak_algorithm",
                     title="Sertifikat memakai algoritma tanda tangan lemah", key="weakalg",
                     description="Algoritma tanda tangan sertifikat: " + ", ".join(sorted({c.get('sig_algorithm', '?') for c in sha1_only})))
    return {"schemes": schemes, "certificates": certs[:MAX_CERTS], "debug_cert": is_debug, "has_signing_block": bool(block)}


def apk_digest(apk: Path) -> dict:
    h256, h1 = hashlib.sha256(), hashlib.sha1(usedforsecurity=False)
    with apk.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h256.update(block)
            h1.update(block)
    return {"sha256": h256.hexdigest(), "sha1": h1.hexdigest()}
