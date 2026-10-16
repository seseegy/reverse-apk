"""Pembantu verifikasi web Tahap 5 (pemilik, di kontainer web): `docker compose exec -T web python -m app.webcheck <perintah>`.

Mengirim permintaan HTTP ke aplikasi web yang SEDANG BERJALAN (bawaan http://127.0.0.1:8000, sama dengan healthcheck) dengan sesi pemilik yang dibuat dari `SECRET_KEY` kontainer
ini (tanpa password, tanpa jaringan luar). Dipakai untuk memeriksa halaman Build, persetujuan lewat web, dan unduhan (hash isi unduhan dihitung di sini) tanpa browser.
Siapa pun yang bisa `docker compose exec` ke web sudah memegang `SECRET_KEY` dan bisa memakai `buildctl approve`, jadi alat ini tidak menambah hak. Tidak dipakai kode AI.

Perintah (keluaran HANYA baris `kunci=nilai`, kode keluar 0 bila status HTTP < 400, 3 bila >= 400 atau galat sambungan, 64 salah pakai):
  get PATH [--save BERKAS]       GET; tidak mengikuti redirect. Mencetak status, location, content_type, content_disposition, nosniff, bytes, sha256 (isi), dan untuk halaman
                                 build: form_diff_sha256 (nilai kolom tersembunyi), has_checkbox, has_statement, build_js.
  post PATH [k=v ...]            POST form; kolom `csrf` ditambahkan otomatis (sesi ini). Mencetak status dan location.
  approve ANALISIS BUILD [--hash H] [--no-statement]
                                 meniru formulir persetujuan: membaca halaman build, mengambil hash dari kolom tersembunyi (atau `--hash`), lalu POST. `--no-statement` = tanpa
                                 mencentang pernyataan (harus ditolak).
Sesi dibuat sekali per proses (CSRF acak); aplikasi menerimanya karena cookie ditandatangani dengan SECRET_KEY yang sama.
"""

from __future__ import annotations

import hashlib
import http.client
import re
import sys
import urllib.parse
from typing import Sequence

from .context import sessions, settings
from .security import Session, new_token

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 3, 64
DEFAULT_BASE = "http://127.0.0.1:8000"
MAX_BODY = 4 * 1024 * 1024 * 1024
BLOCK = 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}")


def _kv(key: str, value: object) -> str:
    text = "".join(" " if not ch.isprintable() else ch for ch in str(value))
    return f"{key}={text.strip()[:300]}"


def _emit(**pairs: object) -> None:
    sys.stdout.write("".join(_kv(k, v) + "\n" for k, v in pairs.items()))
    sys.stdout.flush()


class Client:
    def __init__(self, base: str = DEFAULT_BASE) -> None:
        parts = urllib.parse.urlsplit(base)
        self.host, self.port = parts.hostname or "127.0.0.1", parts.port or 80
        self.session = Session(user=settings.admin_username, csrf=new_token())
        self.cookie = f"{settings.session_cookie}={sessions.dumps(self.session)}"

    def request(self, method: str, path: str, data: dict[str, str] | None = None, save: str | None = None) -> dict[str, object]:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=120)
        headers = {"Cookie": self.cookie, "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"}
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            digest, total, chunks = hashlib.sha256(), 0, []
            out = open(save, "wb") if save else None
            try:
                while True:
                    block = resp.read(BLOCK)
                    if not block:
                        break
                    total += len(block)
                    if total > MAX_BODY:
                        break
                    digest.update(block)
                    if out is not None:
                        out.write(block)
                    elif total <= 2 * BLOCK:
                        chunks.append(block)
            finally:
                if out is not None:
                    out.close()
            return {"status": resp.status, "headers": {k.lower(): v for k, v in resp.getheaders()}, "bytes": total, "sha256": digest.hexdigest(), "text": b"".join(chunks).decode("utf-8", errors="replace")}
        finally:
            conn.close()


def _report(res: dict[str, object]) -> int:
    h: dict[str, str] = res["headers"]  # type: ignore[assignment]
    text: str = res["text"]  # type: ignore[assignment]
    _emit(status=res["status"], location=h.get("location", ""), content_type=h.get("content-type", ""), content_disposition=h.get("content-disposition", ""),
          nosniff=int(h.get("x-content-type-options", "").lower() == "nosniff"), cache_control=h.get("cache-control", ""), bytes=res["bytes"], sha256=res["sha256"])
    m = re.search(r'name="diff_sha256" value="([0-9a-f]{64})"', text)
    if "Layar persetujuan" in text or m or "Build #" in text:
        _emit(form_diff_sha256=m.group(1) if m else "", has_checkbox=int('type="checkbox" name="statement"' in text), has_statement=int("berwenang memodifikasi" in text),
              build_js=int("/static/js/build.js" in text))
    return EXIT_OK if int(res["status"]) < 400 else EXIT_FAIL  # type: ignore[arg-type]


def main(argv: Sequence[str] | None = None, *, client: Client | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    base = DEFAULT_BASE
    if args[:1] == ["--base"] and len(args) >= 2:
        base, args = args[1], args[2:]
    if not args or args[0] not in ("get", "post", "approve"):
        sys.stderr.write(__doc__ or "")
        return EXIT_USAGE
    try:
        c = client or Client(base)
        cmd, rest = args[0], args[1:]
        if cmd == "get":
            save = None
            if "--save" in rest:
                i = rest.index("--save")
                save, rest = rest[i + 1], rest[:i] + rest[i + 2:]
            if len(rest) != 1 or not rest[0].startswith("/"):
                return EXIT_USAGE
            return _report(c.request("GET", rest[0], save=save))
        if cmd == "post":
            if not rest or not rest[0].startswith("/"):
                return EXIT_USAGE
            form = {"csrf": c.session.csrf}
            for item in rest[1:]:
                k, sep, v = item.partition("=")
                if not sep:
                    return EXIT_USAGE
                form[k] = v
            return _report(c.request("POST", rest[0], data=form))
        # approve
        flags = [a for a in rest if a.startswith("--")]
        pos = [a for a in rest if not a.startswith("--")]
        if len(pos) < 2 or not (pos[0].isdigit() and pos[1].isdigit()):
            return EXIT_USAGE
        aid, bid = int(pos[0]), int(pos[1])
        h = None
        if "--hash" in rest:
            h = rest[rest.index("--hash") + 1]
            pos = [a for a in pos if a != h]
        if h is None:
            page = c.request("GET", f"/analyses/{aid}/build/{bid}")
            m = re.search(r'name="diff_sha256" value="([0-9a-f]{64})"', str(page["text"]))
            if m is None:
                _emit(kode="tidak_ada_formulir", status=page["status"])
                return EXIT_FAIL
            h = m.group(1)
        form = {"csrf": c.session.csrf, "diff_sha256": h, "statement_version": "1"}
        if "--no-statement" not in flags:
            form["statement"] = "1"
        return _report(c.request("POST", f"/analyses/{aid}/build/{bid}/approve", data=form))
    except (OSError, http.client.HTTPException) as exc:
        _emit(kode="sambungan_gagal", galat=type(exc).__name__)
        return EXIT_FAIL


if __name__ == "__main__":
    raise SystemExit(main())
