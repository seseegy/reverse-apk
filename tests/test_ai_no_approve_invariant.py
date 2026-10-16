"""Tahap 4, sub-area 2: invarian AST/impor. Kode tool AI (app/ai/*.py + app/aibuild.py, beserta dependensi TRANSITIFNYA) tidak punya jalur ke
persetujuan/penandatanganan/unduh/pembacaan artefak (termasuk rute web `app.routes_build` Tahap 5: persetujuan web hanya lewat sesi pemilik + CSRF). Analisis statis: simpul `ast.Name`/`ast.Attribute`/`ast.alias`, BUKAN string atau docstring.

Batas jujur: ini menjaga jalur yang tampak di kode; perilaku diuji di test_ai_build_tools.py (tool persetujuan tidak ada, store.approve_build dipatahkan tidak terpanggil).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "services" / "web"
RVCORE = ROOT / "services" / "rvcore"
AI_DIR = WEB / "app" / "ai"
# Modul tempat jalur terlarang hidup. `rvcore.store` boleh diimpor (tool memakai get/create), tetapi atributnya diperiksa lewat daftar nama terlarang di bawah.
FORBIDDEN_MODULES = {"app.builds", "app.buildctl", "app.routes_build", "app.jobs", "rvcore.signspool", "rvcore.bundleout", "rq", "redis", "worker", "runner"}
BANNED_NAMES = {"approve_build", "queue_build", "reject_build", "claim_build", "mark_signing", "finish_build", "fail_build", "request_cancel_build", "cancel_build",
                "delete_build", "artifact_info", "enqueue_build", "sign_build", "download_artifact", "open_artifact", "build_init_request", "parse_init_result"}
BANNED_RE = re.compile(r"^(approve|enqueue_|sign_|download_)\w*$")
DYNAMIC_CALLS = {"getattr", "setattr", "delattr", "__import__", "eval", "exec", "compile", "globals", "locals", "vars"}


def scanned_files() -> list[Path]:
    files = sorted(AI_DIR.glob("*.py")) + [WEB / "app" / "aibuild.py"]
    extra = WEB / "app" / "aitoolcheck.py"
    return files + ([extra] if extra.exists() else [])


def module_file(mod: str) -> Path | None:
    parts = mod.split(".")
    base = {"app": WEB / "app", "rvcore": RVCORE}.get(parts[0])
    if base is None:
        return None
    path = base.joinpath(*parts[1:])
    for cand in (path.with_suffix(".py"), path / "__init__.py"):
        if cand.exists():
            return cand
    return None


def package_of(path: Path) -> str:
    if WEB not in path.parents and RVCORE not in path.parents:
        return ""
    rel = path.relative_to(WEB) if WEB in path.parents else path.relative_to(ROOT / "services")
    parts = list(rel.with_suffix("").parts)
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts[:-1])


def imports_of(path: Path) -> set[str]:
    """Nama modul lengkap yang diimpor (absolut), termasuk `from pkg import sub` bila `sub` sebuah modul."""
    out: set[str] = set()
    pkg = package_of(path)
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                anchor = pkg.split(".")
                anchor = anchor[: len(anchor) - (node.level - 1)]
                base = ".".join(anchor + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            out.add(base)
            out |= {f"{base}.{a.name}" for a in node.names}
    return out


def transitive(starts: list[Path]) -> set[str]:
    seen: set[str] = set()
    todo = list(starts)
    done: set[Path] = set()
    while todo:
        path = todo.pop()
        if path in done:
            continue
        done.add(path)
        for mod in imports_of(path):
            seen.add(mod)
            nxt = module_file(mod)
            if nxt is not None:
                todo.append(nxt)
    return seen


def test_the_transitive_import_graph_of_the_ai_tools_never_reaches_a_forbidden_module():
    reached = transitive(scanned_files())
    assert any(m.startswith("rvcore.shellspool") for m in reached) and any(m == "app.aibuild" for m in reached)        # grafnya benar-benar ditelusuri
    bad = sorted(m for m in reached if any(m == f or m.startswith(f + ".") for f in FORBIDDEN_MODULES))
    assert not bad, bad


def test_the_import_graph_walker_really_detects_a_forbidden_edge(tmp_path):
    f = tmp_path / "x.py"
    f.write_text("from app import builds\nfrom rvcore import signspool\nimport rq\n", encoding="utf-8")
    assert {"app.builds", "rvcore.signspool", "rq"} <= imports_of(f)


def test_no_name_node_in_the_ai_code_can_call_an_approval_signing_download_or_artifact_function():
    offenders = []
    for path in scanned_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = ([node.id] if isinstance(node, ast.Name) else [node.attr] if isinstance(node, ast.Attribute)
                     else [a.name.split(".")[-1] for a in node.names] if isinstance(node, (ast.Import, ast.ImportFrom)) else [])
            if isinstance(node, ast.ImportFrom) and node.module:
                names.append(node.module.split(".")[-1])
            offenders += [(path.name, n) for n in names if n in BANNED_NAMES or BANNED_RE.match(n)]
    assert not offenders, offenders


def test_the_scan_catches_a_planted_violation(tmp_path):
    f = tmp_path / "v.py"
    f.write_text("def go(store):\n    return store.approve_build(1)\n", encoding="utf-8")
    hits = [n.attr for n in ast.walk(ast.parse(f.read_text())) if isinstance(n, ast.Attribute) and (n.attr in BANNED_NAMES or BANNED_RE.match(n.attr))]
    assert hits == ["approve_build"]
    assert not BANNED_RE.match("signal") and not BANNED_RE.match("signature") and not BANNED_RE.match("signing")


def test_no_dynamic_lookup_can_hide_a_forbidden_name():
    offenders = []
    for path in scanned_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id in DYNAMIC_CALLS:
                    offenders.append((path.name, fn.id))
                if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id == "importlib":
                    offenders.append((path.name, "importlib." + fn.attr))
            if isinstance(node, (ast.Import, ast.ImportFrom)) and any(n == "importlib" for n in ([a.name for a in node.names] + ([node.module or ""] if isinstance(node, ast.ImportFrom) else []))):
                offenders.append((path.name, "importlib"))
    assert not offenders, offenders


def test_tools_py_registers_no_function_that_is_a_banned_name():
    tree = ast.parse((AI_DIR / "tools.py").read_text(encoding="utf-8"))
    defined = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    assert not defined & BANNED_NAMES and not [d for d in defined if BANNED_RE.match(d)]
