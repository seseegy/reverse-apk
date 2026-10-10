"""Analisis statis APK (M2). Berjalan di runner (tanpa jaringan/DB), hanya pustaka standar.

Masukan: hasil jadx/apktool di work/<id>/ dan APK asli (read-only).
Keluaran di work/<id>/index/: index.sqlite, findings.jsonl, summary.json, done.json.
Semua isi yang dibaca berasal dari APK yang TIDAK TEPERCAYA: tidak dieksekusi, tidak di-eval, regex dibatasi.
"""

VERSION = 1
