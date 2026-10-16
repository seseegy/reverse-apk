"""Tahap 4, sub-area 4: `scripts/verify-build.sh` langkah 14a-14n (tool build AI TANPA LLM dan TANPA kunci API) dengan `docker` PALSU.

Yang diuji: LOGIKA skrip. Semua langkah baru ada dalam SATU tabel, urutannya, rantai DILEWATI, dan tiap langkah punya pesan gejala-gagal yang jelas bila SATU syarat dilanggar
(kenop skenario `atc_*` di FAKE_DOCKER milik test_verify_build_script). Yang TIDAK terbukti di sini: Docker/Compose nyata, bench/Landlock nyata, RQ, worker/signer nyata, dan
`app.aitoolcheck` nyata (itu diuji di test_aitoolcheck.py dengan bench palsu). Tidak bergantung root. Tes ditulis SEBELUM langkah 14 ada.
"""

from __future__ import annotations

import re

import pytest

import test_verify_build_script as V
from test_verify_build_script import ROOT, SCRIPT_SRC, Rig, run_ok, status_of, table

TOOL_STEPS = ["14a tool build: modul+skema", "14b tool build: analisis uji + bench_diff awal", "14c tool build: request diff kosong", "14d tool build: ubah via shell + bench_diff",
              "14e tool build: request_build", "14f tool build: permintaan kedua", "14g tool build: get_build_status menunggu", "14h tool build: negatif lintas analisis",
              "14i tool build: tanpa tool persetujuan + gerbang", "14j tool build: persetujuan pemilik -> selesai", "14k tool build: permintaan XAPK", "14l tool build: tanpa kebocoran",
              "14m tool build: pagar persetujuan", "14n tool build: kebersihan"]
S14 = {s[:3]: s for s in TOOL_STEPS}


@pytest.fixture(scope="module")
def ran(tmp_path_factory):
    rig = Rig(tmp_path_factory.mktemp("tahap4"))
    res = rig.run()
    return rig, res, table(res.stdout)


def script_region():
    text = SCRIPT_SRC.read_text(encoding="utf-8")
    start = text.index("Tahap 4: langkah 14a-14n (tool build AI tanpa LLM)")
    end = text.index("\nrun_all() {")
    return text[start:end]


# ================================================================================ bentuk skrip (statis)
def test_the_new_steps_are_in_the_single_order_array_after_12f_and_before_the_summary():
    text = SCRIPT_SRC.read_text(encoding="utf-8")
    order = re.search(r"^ORDER=\((.*)\)$", text, re.M).group(1).split()
    new = [f"N14{c}" for c in "ABCDEFGHIJKLMN"]
    assert order[-len(new):] == new and order[order.index("N12F") + 1] == "N14A"
    names = dict(re.findall(r'^(N14[A-N])="([^"]+)"$', text, re.M))
    assert [names[n] for n in new] == TOOL_STEPS
    assert text.count("print_table()") == 1 and len(re.findall(r"^\s+print_table$", text, re.M)) == 1               # tetap SATU tabel (satu fungsi, satu pemanggil di on_exit)


def test_the_tool_steps_need_no_api_key_and_add_no_key_material():
    region = script_region()
    for bad in ("AI_API_KEY", "API_KEY", "AI_BASE_URL", "storepass", "keypass", "keystore.sh", "signing_keystore", "base64", "openssl"):
        assert bad not in region, bad
    assert "aitoolcheck" in region and "app.ai.check" not in region           # tanpa model: `make ai-check` hanya opsional manual


def test_the_only_approval_in_the_tool_phase_is_the_owner_cli_and_never_through_the_helper():
    region = script_region()
    approves = re.findall(r"^.*\bapprove\b.*$", region, re.M)
    code = [ln for ln in approves if not ln.lstrip().startswith("#") and "row " not in ln and "bad=" not in ln and "echo" not in ln]
    assert [ln.strip() for ln in code if "bc approve" in ln] == ['bc approve "$B14" --diff-sha256 "$H14"']
    assert not [ln for ln in re.findall(r"^.*\batc\b.*$", region, re.M) if re.search(r"atc call [^|]*\b(approve|sign|download|cancel)\b\s*$", ln) and "_build" not in ln and "artifact" not in ln and "tool" not in ln.split("atc")[0]]
    assert "atc audit-approvals" in region                                    # persetujuan dibuktikan dari audit, bukan dari klaim


def test_the_step_helper_goes_through_the_same_container_and_closes_the_lock_fd():
    region = script_region()
    assert 'python -m app.aitoolcheck "$@"' in region and "9>&-" in region and "exec -T web" in region
    assert "app.aibuild" not in region and "app.builds" not in region        # bukan jalur paralel di skrip


def test_makefile_help_and_doc_mention_the_new_steps():
    mk = (ROOT / "Makefile").read_text(encoding="utf-8")
    line = next(ln for ln in mk.splitlines() if ln.startswith("verify-build:"))
    assert "14a" in line and "14n" in line


# ================================================================================ jalan penuh: semua OK
def test_all_tool_steps_ran_ok_in_order_inside_one_table(ran):
    rig, res, rows = ran
    assert res.returncode == 0, res.stdout + res.stderr
    keys = list(rows)
    pos = [keys.index(s) for s in TOOL_STEPS]
    assert pos == sorted(pos) and keys.index("12f negatif set") < pos[0] and pos[-1] < keys.index("13 ringkasan")
    for s in TOOL_STEPS:
        assert status_of(rows, s) == "OK", (s, rows[s])
    assert len(V.HEADER_RE.findall(res.stdout)) == 1


def test_the_helper_is_only_asked_for_schema_call_and_audit_never_for_an_approval_command(ran):
    rig, _, _ = ran
    calls = rig.kinds("aitoolcheck")
    assert calls and {c["argv_atc"][0] for c in calls} == {"schema", "call", "audit-approvals"}
    tools = {c["argv_atc"][2] for c in calls if c["argv_atc"][0] == "call"}
    assert {"bench_diff", "request_build", "get_build_status", "approve_build", "cancel_build", "download_artifact"} == tools
    assert all(c["argv_atc"][1].isdigit() for c in calls if c["argv_atc"][0] != "schema")


def test_exactly_one_owner_approval_happens_in_the_tool_phase_and_it_carries_the_diff_hash(ran):
    rig, _, _ = ran
    appr = [c["argv_ctl"] for c in rig.kinds("buildctl") if c["argv_ctl"][0] == "approve"]
    mine = [a for a in appr if 48 <= int(a[1]) < 10**6]                      # build 14e: setelah build langkah 5-12 (id mulai 41); 999999999 = negatif langkah 5
    assert len(mine) == 1 and mine[0][2] == "--diff-sha256" and re.fullmatch(r"[0-9a-f]{64}", mine[0][3])


def test_the_tool_phase_creates_three_extra_analyses_and_deletes_each_once(ran):
    rig, _, _ = ran
    ids = [d["analysis"] for d in rig.kinds("delete")]
    assert len(ids) == len(set(ids)) == 6 and ids[-1] == min(ids[3:])        # A dihapus terakhir (analisis tambahan dahulu)


def test_the_xapk_request_is_cancelled_by_the_owner_and_never_approved(ran):
    rig, _, _ = ran
    ctl = [c["argv_ctl"] for c in rig.kinds("buildctl")]
    last_cancel = [a for a in ctl if a[0] == "cancel"][-1]
    assert last_cancel[1].isdigit()
    appr = {a[1] for a in ctl if a[0] == "approve"}
    assert last_cancel[1] not in appr


# ================================================================================ negatif: satu syarat dilanggar -> langkah itu GAGAL dengan gejala jelas
CASES = [
    ({"atc_missing": True}, "14a", "app.aitoolcheck tidak jalan"),
    ({"atc_drop_tool": ["bench_diff"]}, "14a", "bench_diff TIDAK ada"),
    ({"atc_extra_tools": ["approve_build"]}, "14a", "nama tool penyetujuan"),
    ({"atc_gate_leak": True}, "14a", "shell=0"),
    ({"atc_hash_wrong": True}, "14b", "beda dari buildctl diff"),
    ({"atc_create_on_empty": True}, "14c", "diff_kosong"),
    ({"atc_hash_wrong": True}, "14b", "tool tidak memakai diff kanonik"),
    ({"atc_new_build_hash": True}, "14e", "beda dari hash bench_diff"),
    ({"atc_status_wrong": True}, "14e", "harus awaiting_approval"),
    ({"atc_not_ai": True}, "14e", "tidak tercatat diminta oleh AI"),
    ({"atc_ignore_model_hash": True}, "14f", "hash_tidak_cocok"),
    ({"atc_no_reuse": True}, "14f", "dipakai_ulang=1"),
    ({"atc_new_build_on_pending": True}, "14f", "build_tertunda"),
    ({"atc_status_leak_other": True}, "14h", "build_bukan_milik_analisis"),
    ({"atc_pesan_beda": True}, "14h", "IDENTIK"),
    ({"atc_call_extra": ["approve_build"]}, "14i", "approve_build"),
    ({"ai_approves": True}, "14i", "setelah panggilan tool"),
    ({"ai_approves": True}, "14m", "via='ai'"),
    ({"atc_build_fail": True}, "14j", "tidak mencapai done"),
    ({"atc_verify_missing": True}, "14j", "verifikasi_tanda_tangan"),
    ({"atc_leak": "/data/builds/1/x"}, "14l", "pola:/data/"),
    ({"atc_leak": "unduh di https://x.example/a"}, "14l", "pola:://"),
    ({"atc_leak": "secrets/signing_keystore.p12"}, "14l", "pola:keystore"),
    ({"atc_leak_name": True}, "14l", "pola:output_name"),
    ({"atc_stuck_delete": True}, "14n", "TERTINGGAL"),
]


@pytest.mark.parametrize("scn,step,needle", CASES, ids=[f"{c[1]}-{list(c[0])[0]}" for c in CASES])
def test_each_violated_condition_fails_its_own_step_with_a_clear_symptom(tmp_path, scn, step, needle):
    rig = Rig(tmp_path).scn(**scn)
    res, rows = run_ok(rig)
    assert res.returncode == 1, res.stdout
    assert status_of(rows, S14[step]) == "GAGAL", rows[S14[step]]
    assert needle in rows[S14[step]][1], rows[S14[step]]
    assert "/data/builds/1/x" not in res.stdout and "signing_keystore.p12" not in res.stdout and "x.example" not in res.stdout       # nilai terlarang tidak dicetak


def test_a_failing_prerequisite_skips_the_rest_and_creates_no_analysis(tmp_path):
    rig = Rig(tmp_path).scn(atc_missing=True)
    res, rows = run_ok(rig)
    assert status_of(rows, S14["14a"]) == "GAGAL"
    for s in TOOL_STEPS[1:]:
        assert status_of(rows, s) == "DILEWATI", s
    assert "14a" in rows[S14["14b"]][1] and len(rig.kinds("delete")) == 3        # hanya analisis langkah 2, 12b, 12e


def test_a_bench_diff_that_disagrees_with_buildctl_stops_the_chain_but_still_cleans_up(tmp_path):
    rig = Rig(tmp_path).scn(atc_hash_wrong=True)
    res, rows = run_ok(rig)
    assert status_of(rows, S14["14b"]) == "GAGAL"
    for s in TOOL_STEPS[2:13]:
        assert status_of(rows, s) == "DILEWATI", s
    assert status_of(rows, S14["14n"]) == "OK" and len(rig.kinds("delete")) == 4          # analisis 14b ikut dibersihkan


def test_an_empty_diff_that_creates_a_build_stops_the_chain(tmp_path):
    rig = Rig(tmp_path).scn(atc_create_on_empty=True)
    res, rows = run_ok(rig)
    assert status_of(rows, S14["14c"]) == "GAGAL"
    for s in TOOL_STEPS[3:13]:
        assert status_of(rows, s) == "DILEWATI", s
    assert status_of(rows, S14["14n"]) == "OK"


def test_14j_is_skipped_when_the_real_build_of_step_6_did_not_work(tmp_path):
    rig = Rig(tmp_path).scn(build_fail=2)                                  # build ke-2 (langkah 6) gagal
    res, rows = run_ok(rig)
    assert status_of(rows, "6 build nyata") == "GAGAL"
    assert status_of(rows, S14["14j"]) == "DILEWATI" and "langkah 6" in rows[S14["14j"]][1]
    for s in TOOL_STEPS:
        if s != S14["14j"]:
            assert status_of(rows, s) == "OK", (s, rows[s])
    assert not [c for c in rig.kinds("buildctl") if c["argv_ctl"][0] == "approve" and "--hold" not in c["argv_ctl"] and 48 <= int(c["argv_ctl"][1]) < 10**6]


def test_14k_is_skipped_when_the_bundle_samples_could_not_be_made(tmp_path):
    rig = Rig(tmp_path)
    res, rows = run_ok(rig, PYTHON3="/tidak/ada/python3")
    assert status_of(rows, S14["14k"]) == "DILEWATI" and "12a" in rows[S14["14k"]][1]
    for s in TOOL_STEPS:
        if s != S14["14k"]:
            assert status_of(rows, s) == "OK", (s, rows[s])


def test_no_tool_output_value_is_ever_echoed_into_the_table_on_success(ran):
    _, res, rows = ran
    text = "\n".join(v[1] for k, v in rows.items() if k[:2] == "14")
    assert not re.search(r"[0-9a-f]{64}", text) and "://" not in text and "/data/" not in text      # hanya awalan hash 12 hex yang boleh tampil
