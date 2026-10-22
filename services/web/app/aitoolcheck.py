"""Pembantu verifikasi TANPA LLM untuk tool build AI (Tahap 4): `docker compose exec -T web python -m app.aitoolcheck <perintah>`.

Perintah:
  schema [--shell 0|1]                     skema tool yang ditawarkan ke model (`tool.N=<nama>`)
  call <analysis_id> <tool> [--args JSON] [--shell 0|1]
                                           satu panggilan tool lewat `tools.run_tool`, jalur kode YANG SAMA dengan chat (pembungkus, batas keluaran, penghitung, audit,
                                           gerbang). Ini BUKAN implementasi paralel: modul ini tidak mengimpor `aibuild`/`builds`/`buildctl`.
  audit-approvals <analysis_id>            `via` tiap persetujuan build milik analisis itu (`approved_via.N=`), untuk membuktikan jalur AI tidak pernah menyetujui

Satu panggilan = satu giliran baru (penghitung per-giliran mulai dari nol). Sesi chat: sesi terbaru analisis, atau dibuat sekali bila belum ada (sesi milik analisis itu,
seperti yang dipastikan rute chat). `--shell` bawaan 1: pembantu ini memaksa gerbang shell hidup supaya langkah verify-build tidak bergantung pada AI_SHELL_ENABLED di .env
(sama seperti `buildctl shell`); `--shell 0` membuktikan gerbang menolak. Tidak butuh kunci API dan tidak memanggil model.

Format keluaran (untuk skrip bash tanpa JSON): HANYA baris `kunci=nilai` (kunci `[a-z_0-9.]+`, nilai satu baris, karakter cetak, <= 300; kontrol dan pengendali arah tulisan
diganti spasi), sehingga nilai dari APK tidak bisa memalsukan baris lain. `call` selalu mencetak `ok=1|0` dan `kode=` (kosong bila ok); hasil berstruktur diratakan:
`kunci.sub=`, daftar `kunci.N=` (mulai 1). Kode keluar: 0 tool sukses; 3 tool menolak (`ok=0`, `kode=<stabil>`); 64 salah pakai (pesan ke stderr).
Tidak ada jalur persetujuan, pembatalan, penandatanganan, atau unduh di sini (dijaga tests/test_ai_no_approve_invariant.py).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from contextlib import closing
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Sequence

from rvcore import db as rvdb
from rvcore import store
from rvcore.paths import MAX_PROTO_ID, Layout

from .ai import settings as ai_settings
from .ai import tools
from .ai.config import AIConfig, ConfigError
from .ai.redact import Redactor
from .config import load_settings

EXIT_OK, EXIT_REFUSED, EXIT_USAGE = 0, 3, 64
VALUE_MAX = 300
KEY_RE = re.compile(r"[a-z_0-9.]+")
TOOL_RE = re.compile(r"[a-z][a-z_0-9]{0,39}")
KODE_RE = re.compile(r"\[([a-z][a-z_0-9]{0,39})\]")
_BIDI = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_WRAP_OK = re.compile(r'<hasil_tool nama="[a-z_0-9]+">\nPERINGATAN:[^\n]*\n(.*)\n</hasil_tool>\Z', re.S)
_WRAP_ERR = re.compile(r'<hasil_tool nama="[a-z_0-9]+" galat="true">(.*)</hasil_tool>\Z', re.S)


@dataclass
class Deps:
    cfg: AIConfig
    db: Callable[[], Any]
    work: Callable[[int], Path]


class _Usage(Exception):
    pass


class _Help(Exception):
    pass


# ---------------------------------------------------------------------------------------------------- keluaran
def clean_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    text = "".join(" " if (ch in _BIDI or not ch.isprintable()) else ch for ch in str(value))
    return text.strip()[:VALUE_MAX]


def _key(raw: str) -> str:
    return re.sub(r"[^a-z_0-9.]", "_", raw.lower()) or "_"


def _emit(pairs: list[tuple[str, Any]]) -> None:
    lines = []
    for k, v in pairs:
        if not KEY_RE.fullmatch(k):
            raise ValueError(f"kunci keluaran tidak valid: {k!r}")
        lines.append(f"{k}={clean_value(v)}")
    sys.stdout.write("".join(ln + "\n" for ln in lines))
    sys.stdout.flush()


def _flatten(prefix: str, value: Any, out: list[tuple[str, Any]], depth: int = 0) -> None:
    if depth > 4:
        out.append((prefix, "…"))
    elif isinstance(value, dict):
        for k, v in value.items():
            _flatten(f"{prefix}.{_key(str(k))}" if prefix else _key(str(k)), v, out, depth + 1)
    elif isinstance(value, list):
        for n, v in enumerate(value[:60], 1):
            _flatten(f"{prefix}.{n}", v, out, depth + 1)
    else:
        out.append((prefix, value))


# ---------------------------------------------------------------------------------------------------- argumen
class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:
        raise _Usage(message)

    def exit(self, status: int = 0, message: str | None = None) -> Any:
        if status == 0:
            raise _Help()
        raise _Usage(message or "")


def _flag01(text: str) -> int:
    if text not in ("0", "1"):
        raise argparse.ArgumentTypeError("harus 0 atau 1")
    return int(text)


def _aid(text: str) -> int:
    if not re.fullmatch(r"[0-9]{1,18}", text) or not 1 <= int(text) <= MAX_PROTO_ID:
        raise argparse.ArgumentTypeError("analysis_id harus bilangan bulat 1..%d" % MAX_PROTO_ID)
    return int(text)


def _tool(text: str) -> str:
    if not TOOL_RE.fullmatch(text):
        raise argparse.ArgumentTypeError("nama tool tidak valid")
    return text


def _parser() -> argparse.ArgumentParser:
    p = _Parser(prog="aitoolcheck", description="Verifikasi tool build AI tanpa LLM")
    sub = p.add_subparsers(dest="cmd", required=True, parser_class=_Parser)
    s = sub.add_parser("schema")
    s.add_argument("--shell", type=_flag01, default=1)
    c = sub.add_parser("call")
    c.add_argument("analysis_id", type=_aid)
    c.add_argument("tool", type=_tool)
    c.add_argument("--args", default="{}")
    c.add_argument("--shell", type=_flag01, default=1)
    a = sub.add_parser("audit-approvals")
    a.add_argument("analysis_id", type=_aid)
    return p


# ---------------------------------------------------------------------------------------------------- perintah
def _default_deps() -> Deps:
    # Tanpa `app.context` (yang menarik redis/FastAPI): hanya data dir + SQLite, sama dengan context.db().
    layout = Layout(load_settings().data_dir)
    rvdb.migrate(layout.db_path)
    with closing(rvdb.connect(layout.db_path)) as conn:
        cfg = ai_settings.effective_config(conn)     # koneksi AI dari Pengaturan AI (DB), sama seperti web
    return Deps(cfg=cfg, db=lambda: rvdb.connect(layout.db_path), work=layout.work_dir)


def _schema(deps: Deps, args: argparse.Namespace) -> int:
    pairs: list[tuple[str, Any]] = [("ok", 1), ("kode", "")]
    pairs += [(f"tool.{n}", t["function"]["name"]) for n, t in enumerate(tools.schemas(vision=True, shell=bool(args.shell)), 1)]
    _emit(pairs)
    return EXIT_OK


def _session_for(deps: Deps, aid: int) -> int:
    with closing(deps.db()) as conn:
        found = store.list_chat_sessions(conn, aid, limit=1)
        return int(found[0]["id"]) if found else store.create_chat_session(conn, aid, "verifikasi tool build")


def _parse_result(text: str, ok: bool) -> tuple[str, str, Any]:
    """(kode, pesan, hasil) dari teks `run_tool`. Galat: '[kode] pesan'; tool tidak ada -> kode tool_tidak_ada."""
    if not ok:
        m = _WRAP_ERR.match(text)
        body = m.group(1) if m else text
        k = KODE_RE.match(body)
        if k:
            return k.group(1), body[k.end():].strip(), None
        return ("tool_tidak_ada" if "tidak ada" in body else "galat_tool"), body.strip(), None
    m = _WRAP_OK.match(text)
    if not m:
        return "keluaran_tidak_terbaca", "pembungkus hasil tool tidak dikenal", None
    try:
        return "", "", json.loads(m.group(1))
    except ValueError:
        return "keluaran_tidak_terbaca", "isi hasil tool bukan JSON", None


def _call(deps: Deps, args: argparse.Namespace) -> int:
    try:
        parsed = json.loads(args.args)
    except ValueError:
        raise _Usage("--args harus JSON objek") from None
    if not isinstance(parsed, dict):
        raise _Usage("--args harus JSON objek")
    aid = args.analysis_id
    cfg = replace(deps.cfg, shell_enabled=bool(args.shell))
    ctx = tools.ToolContext(aid, deps.work(aid), cfg, deps.db, Redactor(cfg.redact_secrets))
    ctx.session_id = _session_for(deps, aid)               # dari sesi analisis ini, BUKAN dari argumen; sama dengan chat.run_in_thread
    with closing(deps.db()) as conn:
        an = store.get_analysis(conn, aid)
    ctx.bench_sha256 = an["sha256"] if an else None
    text, ok = tools.run_tool(ctx, args.tool, json.dumps(parsed))
    kode, pesan, result = _parse_result(text, ok)
    if kode:
        _emit([("ok", 0), ("kode", kode), ("pesan", pesan)])
        return EXIT_REFUSED
    pairs: list[tuple[str, Any]] = [("ok", 1), ("kode", "")]
    _flatten("", result, pairs)
    _emit(pairs)
    return EXIT_OK


def _audit_approvals(deps: Deps, args: argparse.Namespace) -> int:
    vias: list[str] = []
    with closing(deps.db()) as conn:
        for row in conn.execute("SELECT detail FROM audit_log WHERE action = ? ORDER BY id", ("build_approved",)):
            try:
                detail = json.loads(row["detail"])
            except ValueError:
                continue
            if isinstance(detail, dict) and detail.get("analysis_id") == args.analysis_id:
                vias.append(str(detail.get("via", "")))
    _emit([("ok", 1), ("kode", ""), ("approved_n", len(vias))] + [(f"approved_via.{n}", v) for n, v in enumerate(vias[:50], 1)])
    return EXIT_OK


COMMANDS = {"schema": _schema, "call": _call, "audit-approvals": _audit_approvals}


def main(argv: Sequence[str] | None = None, *, deps: Deps | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        return COMMANDS[args.cmd](deps or _default_deps(), args)
    except _Help:
        return EXIT_OK
    except _Usage as exc:
        sys.stderr.write(f"aitoolcheck: {exc}\n")
        return EXIT_USAGE
    except ConfigError as exc:
        _emit([("ok", 0), ("kode", "konfigurasi_ai_salah"), ("pesan", str(exc))])
        return EXIT_REFUSED
    except Exception as exc:  # noqa: BLE001 - tidak boleh menumpahkan traceback ke stdout; jenis galat saja
        _emit([("ok", 0), ("kode", "internal"), ("galat", type(exc).__name__)])
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
