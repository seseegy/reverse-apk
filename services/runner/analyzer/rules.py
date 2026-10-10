"""Aturan deteksi (regex). Setiap aturan punya `needle` (substring murah) untuk melewati berkas yang pasti tidak cocok.

Prinsip: heuristik, BUKAN klaim kerentanan. Severity mencerminkan keyakinan dan dampak, bukan bukti eksploitasi.
Semua regex dibatasi (kuantifier berbatas, tanpa alternasi bersarang) agar kebal ReDoS terhadap isi APK.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from .common import shannon_entropy


@dataclass(frozen=True)
class CodeRule:
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    needle: str                       # substring cepat; berkas tanpa ini dilewati
    rx: re.Pattern[str]
    group: int = 0                    # grup regex yang dijadikan `key` agregasi (0 = tanpa pengelompokan per nilai)
    skip_in_lib: bool = False
    check: Callable[[re.Match[str]], bool] | None = None   # saringan tambahan


# ---------------------------------------------------------------- secret: pola penyedia (keyakinan tinggi)
@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    title: str
    severity: str
    description: str
    needle: str
    rx: re.Pattern[str]
    value_group: int = 0


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "secret.aws_access_key", "AWS Access Key ID", "high",
        "ID kunci akses AWS. Bila pasangannya (secret key) ikut tertanam, akun AWS dapat disalahgunakan.",
        "AKIA", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    SecretPattern(
        "secret.google_api_key", "Google API key", "medium",
        "Kunci API Google. Umum ada di aplikasi Firebase/Maps dan sering memang dimaksudkan publik; "
        "risikonya bergantung pada pembatasan kunci (paket/SHA-1/API) di Google Cloud Console.",
        "AIza", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    SecretPattern(
        "secret.private_key", "Kunci privat (PEM) tertanam", "high",
        "Blok kunci privat ditemukan di dalam APK; siapa pun yang mengunduh aplikasi dapat membacanya.",
        "PRIVATE KEY", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    SecretPattern(
        "secret.slack_token", "Token Slack", "high", "Token API Slack tertanam.",
        "xox", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,72}\b")),
    SecretPattern(
        "secret.github_token", "Token GitHub", "high", "Token akses GitHub tertanam.",
        "gh", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,255}\b")),
    SecretPattern(
        "secret.stripe_live_key", "Kunci rahasia Stripe (live)", "high",
        "Kunci rahasia Stripe mode live memberi akses penuh ke akun pembayaran.",
        "sk_live_", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,99}\b")),
    SecretPattern(
        "secret.twilio_key", "Kunci API Twilio", "high", "Kunci/SID API Twilio tertanam.",
        "SK", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    SecretPattern(
        "secret.jwt", "JSON Web Token (JWT) tertanam", "medium",
        "Token JWT statis ditemukan. Periksa apakah masih berlaku dan klaim apa yang dibawanya.",
        "eyJ", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,500}\.eyJ[A-Za-z0-9_\-]{10,500}\.[A-Za-z0-9_\-]{10,500}\b")),
    SecretPattern(
        "secret.url_credentials", "Kredensial di dalam URL", "high",
        "URL memuat user:password. Kredensial ini ikut terkirim di setiap permintaan dan tersimpan di APK.",
        "://", re.compile(r"\b[a-z][a-z0-9+.\-]{1,10}://[^/\s:@\"'<>\\]{1,64}:[^/\s@\"'<>\\]{3,64}@[A-Za-z0-9.\-]{3,100}"),
        0),
)


# ---------------------------------------------------------------- secret: tebakan generik (nama + entropi)
_SECRET_WORDS = (r"(?:secret|passw(?:or)?d|passwd|pwd|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
                 r"bearer|private[_-]?key|client[_-]?secret|credential|token)")
# Hanya PENETAPAN yang dikenali:  nama = "v" | nama: "v" | put/set/add("nama", "v").
# Sengaja TIDAK mencocokkan argumen posisi ke-N dari pemanggilan sembarang (mis. add(x, Token.ARROW, "Lfoo;")).
NAME_ASSIGN_RE = re.compile(
    r"(?i)(?:\b([\w]{0,40}" + _SECRET_WORDS + r"[\w]{0,40})[\"']?\s*(?:=|:)\s*$"
    r"|\b(?:put|set|add|setProperty|putString|setString|append)\w{0,12}\(\s*\"([\w.\-]{0,40}" + _SECRET_WORDS + r"[\w.\-]{0,40})\"\s*,\s*$)"
)
# Konstanta/enum (Token.ARROW, Keys.TOKEN): bukan nama variabel rahasia.
_CONSTANT_NAME = re.compile(r"^(?:[A-Z][A-Za-z0-9]*\.)+[A-Z][A-Z0-9_]+$")
# Deskriptor / nama internal JVM & bytecode.
_JVM_DESCRIPTOR = re.compile(r"^(?:\[*L[\w/$]+;|\([\w/$;\[]*\)[\w/$;\[]+|[\w$]+(?:/[\w$]+){1,}(?:;|\$[\w$]+)?)$")
_PLACEHOLDER_FULL = re.compile(
    r"(?i)^(?:password|passwd|secret|token|test|default|example|sample|dummy|placeholder|todo|null|none|"
    r"changeme|change_me|undefined|unknown|empty)$")
_PLACEHOLDER_PREFIX = re.compile(r"(?i)^(?:x{4,}|\*{4,}|0{6,}|your[_\- ]|change.?me|<|\$\{|\{\{)")
_IDENT_SNAKE = re.compile(r"^[a-z][a-z0-9]*(?:[_\-][a-z0-9]+)+$")
_IDENT_CAMEL = re.compile(r"^[a-z]+(?:[A-Z][a-z0-9]+)+$")
_DOTTED = re.compile(r"^[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*){1,}$")
_HEADER = re.compile(r"^[A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+$")          # X-Auth-Token, Content-Type
_PATHLIKE = re.compile(r"^[\w.\-]+(?:/[\w.\-]+)+/?$")                    # oauth2/token, api/v1/users
_FORMATTY = re.compile(r"%[sdif0-9]|\{\d*\}|\$\{")


def looks_like_secret(value: str) -> bool:
    """Saringan ketat untuk tebakan generik. Lebih baik melewatkan daripada membanjiri dengan false positive."""
    n = len(value)
    if n < 8 or n > 200 or any(c.isspace() for c in value):
        return False
    low = value.lower()
    if low.startswith(("http://", "https://", "content://", "file://", "@", "android.", "com.", "org.", "/")):
        return False
    if _PLACEHOLDER_FULL.match(value) or _PLACEHOLDER_PREFIX.match(value) or _FORMATTY.search(value):
        return False
    if _JVM_DESCRIPTOR.match(value):         # "Ljava/lang/Boolean;", "(I)V", "java/lang/String"
        return False
    if _IDENT_SNAKE.match(value) or _IDENT_CAMEL.match(value) or _DOTTED.match(value) or _HEADER.match(value):
        return False
    has_lower, has_upper = any(c.islower() for c in value), any(c.isupper() for c in value)
    has_digit = any(c.isdigit() for c in value)
    if value.isalpha() and n < 24:           # kata biasa ("Authorization", "RetryPolicy")
        return False
    if _PATHLIKE.match(value) and not (has_lower and has_upper and has_digit):
        return False                         # path/endpoint; base64 asli bercampur huruf besar-kecil-angka
    classes = sum([has_lower, has_upper, has_digit, any(not c.isalnum() for c in value)])
    if classes < 2 or len(set(value)) < 5:
        return False
    return shannon_entropy(value) >= (3.0 if n < 16 else 3.4)


# ---------------------------------------------------------------- aturan kode (crypto / network / webview / storage)
def _weak_transformation(m: re.Match[str]) -> bool:
    t = m.group(1).upper()
    algo = t.split("/")[0]
    return algo != "RSA" and ("/ECB/" in t or "/" not in t and algo in ("AES", "DES", "DESEDE", "BLOWFISH", "RC2"))


def _is_des_family(m: re.Match[str]) -> bool:
    return m.group(1).upper().split("/")[0] in ("DES", "DESEDE", "RC2", "RC4", "ARCFOUR")


_RC = re.compile
CODE_RULES: tuple[CodeRule, ...] = (
    # ---- crypto
    CodeRule("crypto.ecb_mode", "crypto", "high", "Enkripsi AES/DES dengan mode ECB",
             "Mode ECB mengenkripsi blok identik menjadi ciphertext identik sehingga pola data terlihat. "
             "Menulis hanya \"AES\" pada Cipher.getInstance berarti AES/ECB/PKCS5Padding di Android/JVM.",
             "Cipher", _RC(r'Cipher\.getInstance\(\s*"([^"]{2,60})"'), 1, False, _weak_transformation),
    CodeRule("crypto.weak_cipher", "crypto", "high", "Algoritma enkripsi usang (DES/3DES/RC2/RC4)",
             "Algoritma ini dianggap lemah atau usang dan sebaiknya diganti AES-GCM atau ChaCha20-Poly1305.",
             "Cipher", _RC(r'Cipher\.getInstance\(\s*"([^"]{2,60})"'), 1, False, _is_des_family),
    CodeRule("crypto.md5", "crypto", "medium", "Hash MD5",
             "MD5 rentan tabrakan; jangan dipakai untuk integritas, tanda tangan, atau penyimpanan password.",
             "MessageDigest", _RC(r'MessageDigest\.getInstance\(\s*"(MD5|MD2)"'), 1, True),
    CodeRule("crypto.sha1", "crypto", "low", "Hash SHA-1",
             "SHA-1 sudah tidak dianggap aman untuk tanda tangan/integritas.",
             "MessageDigest", _RC(r'MessageDigest\.getInstance\(\s*"(SHA-?1)"'), 1, True),
    CodeRule("crypto.hardcoded_key", "crypto", "high", "Kunci enkripsi ditulis langsung di kode",
             "SecretKeySpec dibuat dari string literal. Kunci yang tertanam di APK dapat diekstrak siapa saja.",
             "SecretKeySpec", _RC(r'SecretKeySpec\(\s*"([^"\n]{4,64})"'), 0, True),
    CodeRule("crypto.static_iv", "crypto", "medium", "IV statis (hard-coded)",
             "IV yang sama dipakai berulang melemahkan mode CBC/CTR/GCM. IV harus acak dan unik per enkripsi.",
             "IvParameterSpec", _RC(r'IvParameterSpec\(\s*"([^"\n]{4,64})"'), 0, True),
    CodeRule("crypto.insecure_random", "crypto", "low", "java.util.Random dipakai",
             "java.util.Random bisa ditebak. Untuk token, kunci, IV, atau nonce gunakan SecureRandom.",
             "Random", _RC(r"\bnew\s+Random\s*\("), 0, True),
    CodeRule("crypto.dynamic_code", "crypto", "medium", "Memuat kode secara dinamis (DexClassLoader)",
             "Aplikasi memuat DEX/JAR saat runtime. Jika sumbernya bisa dimanipulasi, ini jalur eksekusi kode.",
             "ClassLoader", _RC(r"\bnew\s+(DexClassLoader|InMemoryDexClassLoader)\s*\("), 1, True),
    # ---- network
    CodeRule("network.trust_all", "network", "high", "TrustManager menerima semua sertifikat",
             "checkServerTrusted kosong membuat validasi sertifikat TLS dimatikan: lalu lintas HTTPS dapat disadap (MITM).",
             "checkServerTrusted",
             _RC(r"void\s+checkServerTrusted\s*\([^)]{0,120}\)[^{;]{0,60}\{\s*(?:/\*[^*]{0,80}\*/\s*)?\}"), 0, True),
    CodeRule("network.hostname_verifier_all", "network", "high", "HostnameVerifier menerima semua host",
             "verify() selalu mengembalikan true sehingga nama host sertifikat tidak diperiksa.",
             "HostnameVerifier",
             _RC(r"boolean\s+verify\s*\(\s*String\s+\w+\s*,\s*SSLSession\s+\w+\s*\)\s*\{\s*return\s+true;"), 0, True),
    CodeRule("network.allow_all_hostname", "network", "high", "ALLOW_ALL_HOSTNAME_VERIFIER dipakai",
             "Verifier bawaan yang tidak memeriksa nama host.",
             "ALLOW_ALL_HOSTNAME_VERIFIER", _RC(r"ALLOW_ALL_HOSTNAME_VERIFIER"), 0, True),
    CodeRule("network.ssl_error_proceed", "network", "high", "WebView mengabaikan error SSL",
             "onReceivedSslError memanggil proceed(): halaman dengan sertifikat tidak valid tetap dimuat.",
             "onReceivedSslError", _RC(r"onReceivedSslError\s*\([^)]{0,120}\)\s*\{[^}]{0,300}\.proceed\(\)"), 0, True),
    CodeRule("network.cert_pinning_okhttp", "network", "info", "Certificate pinning (OkHttp CertificatePinner)",
             "Aplikasi memakai CertificatePinner. Pinning mempersulit intersepsi lalu lintas saat analisis dinamis.",
             "CertificatePinner", _RC(r"\bnew\s+CertificatePinner\.Builder\s*\(|\bCertificatePinner\.Builder\b"), 0, True),
    # ---- webview
    CodeRule("webview.js_interface", "webview", "medium", "WebView dengan JavaScript interface",
             "addJavascriptInterface mengekspos objek Java ke JavaScript. Dengan konten web tak tepercaya, "
             "ini dapat dieksploitasi (terutama di Android < 4.2).",
             "addJavascriptInterface", _RC(r"\.addJavascriptInterface\s*\("), 0, True),
    CodeRule("webview.js_enabled", "webview", "low", "JavaScript diaktifkan di WebView",
             "setJavaScriptEnabled(true). Risiko meningkat bila WebView memuat konten dari sumber tak tepercaya.",
             "setJavaScriptEnabled", _RC(r"\.setJavaScriptEnabled\s*\(\s*true\s*\)"), 0, True),
    CodeRule("webview.file_access", "webview", "high", "WebView mengizinkan akses file lintas-origin",
             "setAllowUniversalAccessFromFileURLs/FileAccessFromFileURLs(true) memungkinkan halaman file:// "
             "membaca berkas lokal dan origin lain.",
             "FromFileURLs", _RC(r"\.setAllow(?:Universal|File)AccessFromFileURLs\s*\(\s*true\s*\)"), 0, True),
    CodeRule("webview.debugging", "webview", "low", "WebView debugging diaktifkan",
             "setWebContentsDebuggingEnabled(true) memungkinkan inspeksi WebView lewat Chrome DevTools.",
             "setWebContentsDebuggingEnabled", _RC(r"setWebContentsDebuggingEnabled\s*\(\s*true\s*\)"), 0, True),
    # ---- storage
    CodeRule("storage.world_accessible", "storage", "high", "Berkas dibuat dengan mode world-readable/writable",
             "MODE_WORLD_READABLE/WRITEABLE membuat berkas dapat dibaca/ditulis aplikasi lain.",
             "MODE_WORLD", _RC(r"\bMODE_WORLD_(?:READABLE|WRITEABLE)\b"), 0, True),
    CodeRule("storage.sql_concat", "storage", "medium", "Query SQL disusun dengan penggabungan string",
             "rawQuery/execSQL dengan operator + berpotensi SQL injection bila ada masukan pengguna.",
             "Query", _RC(r'\b(?:rawQuery|execSQL)\s*\(\s*"[^"\n]{0,200}"\s*\+'), 0, True),
    CodeRule("storage.external", "storage", "low", "Menulis ke penyimpanan eksternal",
             "Penyimpanan eksternal dapat dibaca aplikasi lain. Jangan menyimpan data sensitif di sana.",
             "getExternalStorageDirectory", _RC(r"\bEnvironment\.getExternalStorageDirectory\s*\("), 0, True),
)

# Paket/kelas yang menandakan stack jaringan (untuk ringkasan, bukan temuan).
NETWORK_STACK = (
    ("OkHttp", re.compile(r"\bokhttp3\.")), ("Retrofit", re.compile(r"\bretrofit2\.")),
    ("Volley", re.compile(r"\bcom\.android\.volley\.")), ("HttpURLConnection", re.compile(r"\bHttpURLConnection\b")),
    ("Apache HttpClient", re.compile(r"\borg\.apache\.http\.")), ("WebSocket", re.compile(r"\bWebSocket\b")),
)
RETROFIT_RE = re.compile(r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(\s*"([^"\n]{1,200})"')
BASEURL_RE = re.compile(r'\.baseUrl\(\s*"([^"\n]{1,300})"')
PIN_RE = re.compile(r'"(sha(?:1|256)/[A-Za-z0-9+/]{27,44}={0,2})"')

# Packer/protector yang dikenal lewat nama library native.
PACKER_LIBS = {
    "libjiagu": "Qihoo 360 Jiagu", "libprotectClass": "Qihoo 360", "libsecexe": "Bangcle/SecNeo",
    "libsecmain": "Bangcle/SecNeo", "libDexHelper": "Bangcle/SecNeo", "libexec.so": "Bangcle",
    "libshell": "Tencent Legu/Shell", "libtup": "Tencent", "libmobisec": "Ali Security",
    "libaliprotect": "Ali Security", "libnqshield": "NQ Shield", "libddog": "DexGuard/Dexprotector",
    "libdexprotector": "DexProtector", "libapkprotect": "ApkProtect", "libarmprotect": "ArmProtect",
    "libegis": "Ijiami/Egis", "libijiami": "Ijiami", "libx3g": "Ijiami", "libkwscmm": "Kiwisec",
}

# URL "namespace" yang bukan endpoint.
NOISE_HOSTS = frozenset({
    "schemas.android.com", "www.w3.org", "w3.org", "xmlpull.org", "www.xmlpull.org", "ns.adobe.com",
    "schemas.microsoft.com", "purl.org", "www.apache.org", "apache.org", "java.sun.com", "xml.org",
    "www.opengis.net", "schemas.xmlsoap.org", "developer.android.com", "www.example.com",
})
PRIVATE_HOST_RE = re.compile(
    r"^(?:localhost|.*\.local|.*\.internal|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|0\.0\.0\.0|10\.0\.2\.2)$", re.I)
