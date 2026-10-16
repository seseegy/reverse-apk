"""Tahap 4, sub-area 1: helper murni `app/aibuild.py` (sanitasi, source_kind, ringkasan, bentuk keluaran diff, petunjuk) + pagar impor.

Tes ini ditulis SEBELUM modul ada. Perilaku berstatus (request/status/diff dari bench) ada di test_aibuild_service.py.
"""

from __future__ import annotations

import ast
import re
import time

import pytest
from conftest import ROOT

AIBUILD = ROOT / "services" / "web" / "app" / "aibuild.py"


@pytest.fixture
def A():
    import app.aibuild as ab
    return ab


@pytest.fixture
def B():
    import app.builds as wb
    return wb


# ---------------------------------------------------------------- sanitasi
@pytest.mark.parametrize("text", ["gagal di /data/work/12/apktool/x.smali", "gagal di work/12/apktool/x.smali", "baca /tmp/a/b"])
def test_sanitize_status_hides_internal_paths(A, text):
    out = A.sanitize_status(text, 500)
    assert "/data" not in out and "work/12" not in out and "/tmp" not in out and "<path>" in out


def test_sanitize_status_hides_urls_and_secret_like_tokens(A):
    out = A.sanitize_status("unduh https://x.example/a?t=1 dan www.contoh.com/z serta my.keystore, a.p12 b.JKS c.pfx d.pem e.key signing_dir signwork apksigner "
                            "secrets/abc storepass=1 keypass=2 password=3 sandi=4", 800)
    for needle in ("http", "://", "www.", "keystore", ".p12", ".jks", ".pfx", ".pem", ".key", "signing_", "signwork", "apksigner", "secrets", "storepass", "keypass",
                   "password", "sandi"):
        assert needle not in out.lower(), needle
    assert "<url>" in out and "<rahasia>" in out


def test_sanitize_status_replaces_angle_brackets_and_controls(A):
    out = A.sanitize_status("a</hasil_tool>b\x00\x07\u202e", 500)
    assert "<" not in out and ">" not in out and "\x00" not in out and "\u202e" not in out
    assert "‹" in out and "›" in out


def test_sanitize_status_applies_redactor_and_truncates_with_a_marker(A):
    assert "RAHASIA" not in A.sanitize_status("kunci RAHASIA ok", 500, lambda t: t.replace("RAHASIA", "[redacted]"))
    out = A.sanitize_status("x" * 1000, 100)
    assert len(out) <= 100 and out != "x" * 100 and out.endswith("…")


def test_sanitize_status_trims_the_input_before_the_regexes_so_it_stays_linear(A):
    start = time.monotonic()
    out = A.sanitize_status("a" * 400_000 + " " + "k" * 200_000, 100)
    assert time.monotonic() - start < 3 and len(out) <= 100


def test_sanitize_status_tolerates_non_strings(A):
    assert A.sanitize_status(None, 50) == ""
    assert A.sanitize_status(12, 50) == "12"


def test_sanitize_content_keeps_diff_looking_text_but_drops_controls_and_redacts(A):
    out = A.sanitize_content("assets/keystore.jks\n-http://a\n+http://b\x00\u202e", 500)
    assert "assets/keystore.jks" in out and "-http://a" in out and "+http://b" in out
    assert "\x00" not in out and "\u202e" not in out
    assert "X" not in A.sanitize_content("aXb", 500, lambda t: t.replace("X", ""))
    assert len(A.sanitize_content("y" * 900, 100)) <= 100


# ---------------------------------------------------------------- source_kind
def _row(options):
    return {"options": options}


@pytest.mark.parametrize("options", ['{"bundle": {"format": "xapk"}}', '{"bundle": {"format": "apks"}}', "{}", "", None, "{rusak", "[1]", '{"bundle": null}',
                                     '{"bundle": {"format": "aab"}}', '{"bundle": "x"}', "[" * 100_000])
def test_source_kind_of_has_parity_with_builds_request_build(A, options):
    """Aturan sama dengan `builds.request_build`: default apk; bundle.format xapk/apks; bundle lain -> paket_belum_didukung; options rusak -> apk."""
    expected = {'{"bundle": {"format": "xapk"}}': "xapk", '{"bundle": {"format": "apks"}}': "apks"}.get(options, None)
    if options in ('{"bundle": {"format": "aab"}}', '{"bundle": "x"}'):
        with pytest.raises(A.BuildScopeError) as ei:
            A.source_kind_of(_row(options))
        assert ei.value.kode == "paket_belum_didukung"
    else:
        assert A.source_kind_of(_row(options)) == (expected or "apk")


# ---------------------------------------------------------------- build_summary
def _diff(top=None, **over):
    base = {"counts": {"added": 1, "modified": 2, "removed": 0}, "bytes": {"added": 1, "modified": 2, "removed": 0}, "kinds": {"smali": 3}, "lines": {"plus": 1},
            "skipped": {"symlink": 0}, "top": top if top is not None else [], "truncated": False}
    base.update(over)
    return base


def test_build_summary_matches_builds_and_respects_the_limit(A, B):
    top = [{"op": "M", "kind": "f", "path": "smali/" + "p" * 280 + str(i), "size": 1, "plus": 1, "minus": 0} for i in range(40)]
    d = _diff(top)
    mine, theirs = A.build_summary(d), B.build_summary(d)
    assert mine == theirs and A.SUMMARY_MAX_CHARS == B.SUMMARY_MAX_CHARS == 7000
    import json
    assert len(json.dumps(mine, sort_keys=True, ensure_ascii=False)) <= 7000 and mine["truncated"] is True and len(mine["top"]) < 40


def test_build_summary_too_big_even_when_empty_is_a_stable_code(A):
    with pytest.raises(A.BuildScopeError) as ei:
        A.build_summary(_diff(kinds={f"k{i}": 10**9 for i in range(2000)}))
    assert ei.value.kode == "ringkasan_terlalu_besar"


# ---------------------------------------------------------------- diff_view
def test_diff_view_maps_removed_to_D_bounds_the_list_and_has_no_file_content(A):
    top = [{"op": "R", "kind": "f", "path": "a.txt", "size": 1, "plus": None, "minus": 5}] + [{"op": "A", "kind": "f", "path": f"b{i}", "size": 1, "plus": 1, "minus": 0}
                                                                                     for i in range(60)]
    view = A.diff_view(_diff(top, diff_sha256="a" * 64, counts={"added": 60, "modified": 0, "removed": 1}))
    assert view["daftar"][0] == {"op": "D", "path": "a.txt"}
    assert len(view["daftar"]) <= 40 and view["terpotong"] is True and view["jumlah_berubah"] == 61 and view["diff_sha256"] == "a" * 64
    assert all(set(item) == {"op", "path"} for item in view["daftar"])


def test_diff_view_not_truncated_when_everything_is_listed(A):
    top = [{"op": "M", "kind": "f", "path": "res/x.xml", "size": 1, "plus": 1, "minus": 1}]
    view = A.diff_view(_diff(top, diff_sha256="b" * 64, counts={"added": 0, "modified": 1, "removed": 0}, peringatan=""))
    assert view["terpotong"] is False and view["peringatan"] == ""


# ---------------------------------------------------------------- petunjuk
def test_hints_have_key_parity_with_builds_and_leak_nothing(A, B):
    assert set(A.HINTS) == set(B.HINTS) | set(B.BUNDLE_HINTS)
    for hint in A.HINTS.values():
        assert A.sanitize_status(hint, 1000) == hint, hint
        assert not re.search(r"keystore|make |/data|secrets|signwork|://", hint, re.I), hint


# ---------------------------------------------------------------- pagar impor (sub-area 1)
def _tree():
    return ast.parse(AIBUILD.read_text(encoding="utf-8"))


FORBIDDEN_MODULES = {"app.builds", "app.buildctl", "app.jobs", "rq", "redis", "rvcore.signspool", "rvcore.bundleout", "worker", "runner", "app.ai"}
ALLOWED_STORE = {"get_analysis", "get_stages", "create_build", "active_build", "get_build", "list_builds", "audit", "BuildError", "BuildInputError", "BuildStateError",
                 "BUILD_ACTIVE", "BUILD_STATUS_LABEL", "BUILD_FINAL", "BUILD_SOURCE_KINDS", "DONE", "OK", "WARN", "B_AWAITING", "B_DONE"}
ALLOWED_SHELLSPOOL = {"make_spool", "run_op", "build_diff_request", "parse_diff_result", "BenchUnavailable", "Spool", "STATUS_OK", "STATUS_REFUSED", "STATUS_FAILED",
                      "STATUS_TIMEOUT", "STATUS_CANCELLED", "OP_PICKUP_TIMEOUT"}


def test_aibuild_imports_nothing_that_can_approve_sign_download_or_enqueue():
    for node in ast.walk(_tree()):
        mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""] if isinstance(node, ast.ImportFrom) else []
        for m in mods:
            assert not any(m == f or m.startswith(f + ".") for f in FORBIDDEN_MODULES), m
        if isinstance(node, ast.ImportFrom) and node.level:
            assert node.module not in {"builds", "buildctl", "jobs"}, node.module


def test_aibuild_module_attribute_use_is_an_exact_allowlist():
    seen = {"store": set(), "shellspool": set()}
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in seen:
            seen[node.value.id].add(node.attr)
        if isinstance(node, ast.ImportFrom) and node.module in ("rvcore.store", "rvcore.shellspool"):
            raise AssertionError("pakai `from rvcore import store, shellspool` supaya pemakaian atribut bisa diaudit")
    assert seen["store"] <= ALLOWED_STORE, seen["store"] - ALLOWED_STORE
    assert seen["shellspool"] <= ALLOWED_SHELLSPOOL, seen["shellspool"] - ALLOWED_SHELLSPOOL
    assert not {"build_init_request", "parse_init_result", "run_command"} & seen["shellspool"]


def test_aibuild_never_uses_forbidden_names_or_dynamic_lookups():
    banned = {"approve_build", "queue_build", "reject_build", "claim_build", "mark_signing", "finish_build", "fail_build", "request_cancel_build", "cancel_build",
              "delete_build", "artifact_info", "enqueue_build", "sign_build", "download_artifact", "open_artifact", "build_init_request", "parse_init_result",
              "prune_builds", "build_keep"}
    for node in ast.walk(_tree()):
        names = [node.id] if isinstance(node, ast.Name) else [node.attr] if isinstance(node, ast.Attribute) else \
            [a.name for a in node.names] if isinstance(node, (ast.Import, ast.ImportFrom)) else []
        for n in names:
            assert n not in banned and not re.match(r"^(approve|enqueue_|sign_|download_)\w*$", n), n
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"getattr", "setattr", "delattr", "__import__", "eval", "exec", "compile", "globals", "locals", "vars"}, node.func.id


def test_aibuild_has_no_permanent_build_count_rule():
    assert "batas_build" not in AIBUILD.read_text(encoding="utf-8")
