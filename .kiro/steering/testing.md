# Tes

Keputusan pemilik (11 Okt 2026): **tes disimpan di repo** (`tests/`) dan dijalankan CI di setiap PR. Ini menggantikan aturan lama "jangan commit tes" di `audit.md` §8.

- Jalankan: `make test` (atau `python -m pyflakes services tests && python -m pytest`). Python 3.12; dependensi: `services/web/requirements.txt` + `tests/requirements.txt`.
- `tests/conftest.py` menyiapkan data di direktori sementara; Redis dan provider AI sengaja tidak terjangkau (tanpa jaringan). Fixture: `client` (login), `anon`, `json_headers`, `seeded`, `blocking_turns`.
- Setiap perbaikan bug menyertakan tes yang **gagal di kode lama dan lulus di kode baru**; sebut keduanya di deskripsi PR.
- Cakupan saat ini hanya aplikasi web. Worker, runner, dan analyzer belum punya tes; stack Docker penuh tetap diuji manual.
