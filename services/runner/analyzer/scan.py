"""Pemindai utama: satu kali baca per berkas -> indeks + temuan + ekstraksi string (FR-3.3 s/d 3.7, 3.9)."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import rules as R
from .common import Findings, Lines, is_library, iter_files, mask_secret, read_text, shannon_entropy
from .index import IndexWriter

URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>\\)\]}|]{3,300}", re.I)
IP_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
LITERAL_RE = re.compile(r'"((?:[^"\\\n]|\\.){4,400})"')
SMALI_LITERAL_RE = re.compile(r'const-string(?:/jumbo)?\s+[vp]\d+,\s*"((?:[^"\\\n]|\\.){4,400})"')
XML_SECRET_RE = re.compile(
    r'(?i)<string\s+name="([^"]{0,80}(?:secret|passw(?:or)?d|api[_-]?key|token|private[_-]?key|credential)[^"]{0,40})"'
    r'[^>]{0,60}>([^<]{8,200})</string>')
BARE_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|id|me|app|dev|ai|xyz|info|biz|"
                            r"us|uk|de|fr|jp|cn|ru|in|tv|cc|tech|cloud|online|site|shop|ly|gl)$", re.I)
_PKG_ROOTS = ("com.", "org.", "android.", "androidx.", "kotlin.", "java.", "javax.", "dalvik.", "net.", "io.", "j$.")
API_PATH_RE = re.compile(r"^/(?:api|v\d+|rest|graphql|oauth2?|auth|login|token|users?|account|public|internal|admin)\b"
                         r"[\w\-./{}:?=&%]{0,180}$", re.I)
B64_RE = re.compile(r"^[A-Za-z0-9+/]{40,400}={0,2}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")
UNSUPPORTED_RE = re.compile(r'throw new UnsupportedOperationException\("Method not decompiled: ([^"]{1,300})"\)')
R8_RE = re.compile(r"r8-map-id-|compiled from: r8-map-id")
JADX_RENAMED_RE = re.compile(r"JADX INFO: renamed from")

TEXT_RES_SUFFIXES = (".xml", ".json", ".txt", ".properties", ".html", ".js", ".yml", ".yaml", ".cfg", ".conf", ".ini", ".pem", ".config")
MAX_RES_BYTES = 512 * 1024


@dataclass
class ScanStats:
    java_files: int = 0
    app_classes: int = 0
    lib_classes: int = 0
    resource_files: int = 0
    skipped_large: list[str] = field(default_factory=list)
    decompile_failures: int = 0       # berkas dengan method yang gagal didekompilasi
    methods_not_decompiled: int = 0
    failed_samples: list[str] = field(default_factory=list)
    smali_fallback_files: int = 0
    r8_marker: bool = False
    renamed_markers: int = 0
    short_names: int = 0
    app_named_classes: int = 0
    string_counts: dict[str, int] = field(default_factory=dict)
    retrofit: list[dict] = field(default_factory=list)
    base_urls: list[str] = field(default_factory=list)
    pins: list[str] = field(default_factory=list)
    stack: dict[str, int] = field(default_factory=dict)


# Berkas data/aset yang memuat URL referensi (lisensi, daftar library) bukan endpoint yang dihubungi aplikasi.
_DATA_FILE = re.compile(r"(?i)(?:^|/)(?:assets|res/raw)/.*\.(?:json|txt|html|md|xml|properties)$|"
                        r"(?:license|licen[cs]es?|notice|aboutlibraries|third[_-]?party)[^/]*$")


# OID X.509/ASN.1 berbentuk a.b.c.d seperti IPv4. Arc pertama OID hanya 0, 1, atau 2; OID umum berawalan 2.5.x / 1.2.x / 1.3.x.
_OID_PREFIX = re.compile(r"^(?:2\.5\.|2\.16\.|1\.2\.|1\.3\.|0\.9\.)")
_OID_HINT = re.compile(r"(?i)\boid\b|\bx509\b|\bx\.?500\b|extension|asn1|\bcert|distinguished|subjectalt|keyusage")


def _looks_like_oid(ip: str, line_text: str) -> bool:
    if _OID_PREFIX.match(ip):
        return True
    # Pola umum kode OID: baris berisi beberapa string "x.y.z.w" berurutan atau kata kunci sertifikat.
    return bool(_OID_HINT.search(line_text)) and ip.split(".")[0] in ("0", "1", "2")


def _is_data_file(rel: str) -> bool:
    return bool(_DATA_FILE.search(rel))


def _rel(path: Path, work: Path) -> str:
    return path.relative_to(work).as_posix()


def _parse_url(raw: str) -> tuple[str, str, str] | None:
    """(url_bersih, scheme, host) atau None bila bukan endpoint nyata."""
    url = raw.rstrip(".,;:!?'\"")
    if any(c in url for c in "{}$%<>") or len(url) < 10:
        return None
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if not host or host in R.NOISE_HOSTS or (("." not in host) and host != "localhost"):
        return None
    return url, parts.scheme.lower(), host


class Scanner:
    def __init__(self, work: Path, index: IndexWriter, findings: Findings, log) -> None:  # noqa: ANN001
        self.work, self.index, self.findings, self.log = work, index, findings, log
        self.stats = ScanStats()
        self._seen_endpoint_keys: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------ string & secret
    def _add_string(self, kind: str, value: str, rel: str, line: int, *, host: str | None = None,
                    scheme: str | None = None, lib: bool = False) -> None:
        self.index.add_string(kind, value, rel, line, host=host, scheme=scheme, is_lib=lib)
        self.stats.string_counts[kind] = self.stats.string_counts.get(kind, 0) + 1

    def _record_secret(self, rule_id: str, title: str, severity: str, description: str, value: str, rel: str,
                       lines: Lines, pos: int, lib: bool, key: str) -> None:
        line = lines.line_of(pos)
        raw_line = lines.text_of(line)
        snippet = raw_line.replace(value, mask_secret(value)) if value in raw_line else mask_secret(value)
        if lib:
            severity, title, key = "info", f"{title} (di pustaka pihak ketiga)", key + "|lib"
        self.findings.add(category="secret", severity=severity, rule_id=rule_id, title=title,
                          description=description, key=key, file=rel, line=line, snippet=snippet,
                          secret=value[:300])

    def _scan_secrets(self, text: str, rel: str, lines: Lines, lib: bool) -> None:
        for pat in R.SECRET_PATTERNS:
            if pat.needle not in text:
                continue
            for m in pat.rx.finditer(text):
                value = m.group(pat.value_group)
                self._record_secret(pat.rule_id, pat.title, pat.severity, pat.description, value, rel, lines,
                                    m.start(), lib, value)

    def _scan_literals(self, text: str, rel: str, lines: Lines, lib: bool, pattern: re.Pattern[str]) -> None:
        for m in pattern.finditer(text):
            value = m.group(1)
            n = len(value)
            if "://" in value:
                for um in URL_RE.finditer(value):
                    self._classify_url(um.group(0), rel, lines.line_of(m.start()), lib, text, m.start(), lines)
                continue
            if value[0] == "/" and API_PATH_RE.match(value):
                self._add_string("path", value, rel, lines.line_of(m.start()), lib=lib)
                continue
            if n >= 7 and IP_RE.fullmatch(value):
                self._classify_ip(value, rel, lines.line_of(m.start()), lib, lines, m.start())
                continue
            if n <= 80 and "." in value and BARE_DOMAIN_RE.match(value) and not value.startswith(_PKG_ROOTS):
                self._add_string("domain", value.lower(), rel, lines.line_of(m.start()), host=value.lower(), lib=lib)
                continue
            if n >= 32 and " " not in value:
                if HEX_RE.match(value):
                    self._add_string("hex", value, rel, lines.line_of(m.start()), lib=lib)
                    continue
                if (B64_RE.match(value) and any(c.isdigit() for c in value) and any(c.isalpha() for c in value)
                        and shannon_entropy(value) >= 4.0):
                    self._add_string("base64", value, rel, lines.line_of(m.start()), lib=lib)
                    continue
            if not lib and n >= 8 and R.looks_like_secret(value):
                line_start = text.rfind("\n", 0, m.start()) + 1
                prefix = text[max(line_start, m.start() - 120):m.start()]
                nm = R.NAME_ASSIGN_RE.search(prefix)
                name = (nm.group(1) or nm.group(2) or "").strip(".") if nm else ""
                if nm and name and not R._CONSTANT_NAME.match(name):
                    name = name[:60]
                    self._record_secret(
                        "secret.hardcoded_credential", f"Kemungkinan credential tertanam: {name}", "medium",
                        "Nilai string berentropi tinggi ditetapkan ke variabel/kunci yang namanya menyiratkan rahasia. "
                        "Ini heuristik: verifikasi manual diperlukan.", value, rel, lines, m.start(), False, value)

    def _classify_url(self, raw: str, rel: str, line: int, lib: bool, text: str, pos: int, lines: Lines) -> None:
        parsed = _parse_url(raw)
        if not parsed:
            return
        url, scheme, host = parsed
        self._add_string("url", url, rel, line, host=host, scheme=scheme, lib=lib)
        if not IP_RE.fullmatch(host):
            self._add_string("domain", host, rel, line, host=host, lib=lib)
        if scheme in ("http", "ws") and not lib and not _is_data_file(rel):
            private = bool(R.PRIVATE_HOST_RE.match(host))
            self.findings.add(
                category="network", severity="low" if private else "medium", rule_id="network.cleartext_url",
                title=f"Endpoint tanpa TLS ({scheme}://) ke {host}",
                description="URL memakai skema tanpa enkripsi sehingga lalu lintas dapat disadap atau diubah di "
                            "jaringan. " + ("Host ini tampak lokal/internal (kemungkinan sisa debug)." if private else ""),
                key=host, file=rel, line=line, snippet=lines.text_of(line))
        if IP_RE.fullmatch(host):
            self._classify_ip(host, rel, line, lib, lines, pos, from_url=True)

    def _classify_ip(self, ip: str, rel: str, line: int, lib: bool, lines: Lines, pos: int, from_url: bool = False) -> None:
        if ip.startswith(("0.", "127.", "255.")):
            return  # wildcard / loopback / broadcast bukan endpoint
        if not from_url and _looks_like_oid(ip, lines.text_of(line)):
            return  # OID X.509 (mis. 2.5.4.3 = commonName) berbentuk sama dengan IPv4
        self._add_string("ip", ip, rel, line, host=ip, lib=lib)
        if not lib and not R.PRIVATE_HOST_RE.match(ip):
            self.findings.add(category="network", severity="low", rule_id="network.hardcoded_ip",
                              title=f"Alamat IP tertanam: {ip}",
                              description="Alamat IP publik ditulis langsung di kode. Server bisa berpindah, dan IP "
                                          "tertanam kerap menandakan endpoint pengembangan atau C2.",
                              key=ip, file=rel, line=line, snippet=lines.text_of(line))

    # ------------------------------------------------------------------ aturan kode
    def _scan_code_rules(self, text: str, rel: str, lines: Lines, lib: bool) -> None:
        for rule in R.CODE_RULES:
            if rule.needle not in text or (lib and rule.skip_in_lib):
                continue
            for m in rule.rx.finditer(text):
                if rule.check and not rule.check(m):
                    continue
                key = (m.group(rule.group) if rule.group else "")
                severity, title, description = rule.severity, rule.title, rule.description
                if rule.group and key and rule.rule_id.startswith("crypto.") and rule.group == 1:
                    title = f"{rule.title}: {key[:60]}"
                if lib:
                    severity, title, key = "info", f"{title} (di pustaka pihak ketiga)", key + "|lib"
                if rule.rule_id in ("crypto.hardcoded_key", "crypto.static_iv"):
                    value = m.group(1)
                    line = lines.line_of(m.start())
                    self.findings.add(category=rule.category, severity=severity, rule_id=rule.rule_id, title=title,
                                      description=description, key=value + ("|lib" if lib else ""), file=rel,
                                      line=line, snippet=lines.text_of(line).replace(value, mask_secret(value)),
                                      secret=value[:200])
                    continue
                line = lines.line_of(m.start())
                self.findings.add(category=rule.category, severity=severity, rule_id=rule.rule_id, title=title,
                                  description=description, key=key, file=rel, line=line,
                                  snippet=lines.text_of(line))

    def _scan_network_structure(self, text: str, rel: str, lines: Lines, lib: bool) -> None:
        if lib:
            return
        for name, rx in R.NETWORK_STACK:
            if rx.search(text):
                self.stats.stack[name] = self.stats.stack.get(name, 0) + 1
        if "@GET" in text or "@POST" in text or "@PUT" in text or "@DELETE" in text or "@PATCH" in text:
            for m in R.RETROFIT_RE.finditer(text):
                if len(self.stats.retrofit) < 800:
                    self.stats.retrofit.append({"method": m.group(1), "path": m.group(2), "file": rel,
                                                "line": lines.line_of(m.start())})
                if m.group(2).startswith("/"):
                    self._add_string("path", m.group(2), rel, lines.line_of(m.start()))
        if ".baseUrl(" in text:
            for m in R.BASEURL_RE.finditer(text):
                if m.group(1) not in self.stats.base_urls and len(self.stats.base_urls) < 50:
                    self.stats.base_urls.append(m.group(1))
        if "sha256/" in text or "sha1/" in text:
            for m in R.PIN_RE.finditer(text):
                if m.group(1) not in self.stats.pins and len(self.stats.pins) < 100:
                    self.stats.pins.append(m.group(1))

    # ------------------------------------------------------------------ per berkas
    def scan_java(self, path: Path) -> None:
        rel = _rel(path, self.work)
        lib = is_library(rel)
        text = read_text(path)
        s = self.stats
        s.java_files += 1
        if text is None:
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            if len(s.skipped_large) < 50:
                s.skipped_large.append(f"{rel} ({size // 1024} KB)")
            return
        lines = Lines(text)
        name = path.stem
        package = "/".join(rel.split("/")[2:-1]).replace("/", ".")
        n_lines = text.count("\n") + 1
        self.index.add_class(rel, name, package, n_lines, len(text), lib)
        self.index.add_code(rel, text)
        if lib:
            s.lib_classes += 1
        else:
            s.app_classes += 1
            if not package.startswith(("android.", "java.", "kotlin.")):
                s.app_named_classes += 1
                if len(name) <= 2:
                    s.short_names += 1

        if not s.r8_marker and R8_RE.search(text[:600]):
            s.r8_marker = True
        if JADX_RENAMED_RE.search(text[:2000]):
            s.renamed_markers += 1

        failed = UNSUPPORTED_RE.findall(text) if "Method not decompiled" in text else []
        if failed:
            s.decompile_failures += 1
            s.methods_not_decompiled += len(failed)
            if len(s.failed_samples) < 30:
                s.failed_samples.append(failed[0][:200])

        self._scan_secrets(text, rel, lines, lib)
        self._scan_literals(text, rel, lines, lib, LITERAL_RE)
        self._scan_code_rules(text, rel, lines, lib)
        self._scan_network_structure(text, rel, lines, lib)

        if failed:
            self._scan_smali_fallback(rel, lib)

    def _scan_smali_fallback(self, java_rel: str, lib: bool) -> None:
        """Method yang gagal didekompilasi tidak punya string di Java; baca smali kelas yang sama."""
        cls = java_rel[len("jadx/sources/"):-len(".java")]
        apktool = self.work / "apktool"
        try:
            dirs = [apktool / "smali"] + sorted(p for p in apktool.glob("smali_classes*") if p.is_dir())
        except OSError:
            return
        for d in dirs:
            cand = d / f"{cls}.smali"
            text = read_text(cand) if cand.is_file() and not cand.is_symlink() else None
            if text is None:
                continue
            self.stats.smali_fallback_files += 1
            rel = _rel(cand, self.work)
            lines = Lines(text)
            self._scan_secrets(text, rel, lines, lib)
            self._scan_literals(text, rel, lines, lib, SMALI_LITERAL_RE)
            return

    def scan_resource(self, path: Path) -> None:
        rel = _rel(path, self.work)
        try:
            if path.stat().st_size > MAX_RES_BYTES:
                return
        except OSError:
            return
        text = read_text(path, MAX_RES_BYTES)
        if text is None:
            return
        self.stats.resource_files += 1
        lines = Lines(text)
        self.index.add_code(rel, text)
        self._scan_secrets(text, rel, lines, False)
        if "://" in text:
            for um in URL_RE.finditer(text):
                self._classify_url(um.group(0), rel, lines.line_of(um.start()), False, text, um.start(), lines)
        if rel.endswith("strings.xml") or "/res/values" in rel:
            for m in XML_SECRET_RE.finditer(text):
                value = m.group(2).strip()
                if R.looks_like_secret(value):
                    self._record_secret("secret.hardcoded_credential", f"Kemungkinan credential di resource: {m.group(1)[:60]}",
                                        "medium", "Nilai string resource berentropi tinggi dengan nama yang menyiratkan rahasia. "
                                        "Heuristik: verifikasi manual diperlukan.", value, rel, lines, m.start(), False, value)

    # ------------------------------------------------------------------ orkestrasi
    def run(self) -> None:
        sources = self.work / "jadx" / "sources"
        files = list(iter_files(sources, (".java",)))
        total = len(files)
        self.log(f"I: Memindai {total:,} berkas Java…")
        last = time.monotonic()
        for i, p in enumerate(files, 1):
            self.scan_java(p)
            if time.monotonic() - last > 2:
                last = time.monotonic()
                self.log(f"progress: {i} of {total}")
        self.log(f"progress: {total} of {total}")

        res_roots = [self.work / "apktool" / "res" / "values", self.work / "apktool" / "res" / "xml",
                     self.work / "apktool" / "res" / "raw", self.work / "apktool" / "assets"]
        n = 0
        for root in res_roots:
            for p in iter_files(root, TEXT_RES_SUFFIXES):
                self.scan_resource(p)
                n += 1
        manifest = self.work / "apktool" / "AndroidManifest.xml"
        if manifest.is_file():
            self.scan_resource(manifest)
        self.log(f"I: {n:,} berkas resource/aset teks dipindai")
        if self.stats.smali_fallback_files:
            self.log(f"I: {self.stats.smali_fallback_files} berkas smali dipindai sebagai cadangan "
                     f"(method yang gagal didekompilasi jadx)")
