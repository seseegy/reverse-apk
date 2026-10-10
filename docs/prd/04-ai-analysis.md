# 04 — AI Analysis (DeepSeek)

## Tujuan
Memakai DeepSeek API untuk mengubah fakta statis + potongan kode menjadi ringkasan dan laporan yang bisa dipahami, dengan biaya terkontrol dan hasil yang bisa diverifikasi ke kode.

## Keputusan M4 (provider generik + kredit)
- **Satu penghubung generik** untuk API kompatibel OpenAI (`services/web/app/ai/provider.py`); DeepSeek resmi, router pihak ketiga, dan lainnya hanya beda `AI_BASE_URL` + `AI_MODEL` di `.env`. Hanya pustaka standar (tanpa dependensi baru).
- **Anggaran dalam kredit**, bukan USD, mengikuti router yang dipakai (1 kredit = Rp300 pada router saat ini). Harga per model ada di `config/ai_models.json` (bisa diedit; bukan hard-code). Model tak dikenal dihitung dengan tarif default yang sengaja mahal.
- **Tool calling wajib** untuk chat agent dan diuji lewat `make ai-check`. Pemakaian token dari provider dipakai bila ada; bila tidak, diperkirakan (≈3,5 karakter/token) dan ditandai.
- **Retry hanya sebelum ada keluaran** yang sampai ke pemanggil (hindari jawaban ganda); timeout diulang sekali, 429/5xx/jaringan maks 3×.
- `http://` ke host publik ditolak (kunci dan kode APK tidak boleh melintas tanpa enkripsi).

## Provider & model (rencana awal)
- API kompatibel OpenAI, base URL `https://api.deepseek.com`.
- Per dokumentasi resmi (dicek 10 Okt 2026): model `deepseek-flash` (V4.1-Flash) dan `deepseek-v4-pro`; konteks 1M token, tool calls dan JSON output didukung, mode thinking tersedia. Nama lama `deepseek-chat` / `deepseek-reasoner` sudah tidak aktif.
- Harga berbeda jam sibuk vs tidak sibuk dan cache hit vs miss. **Jangan hard-code**: simpan di `config/models.yaml` dan perbarui dari halaman harga resmi.
- Pembagian peran (default, bisa diubah):
  | Tugas | Model | Mode |
  |-------|-------|------|
  | Ringkasan per class/package (volume besar) | `deepseek-flash` | non-thinking |
  | Laporan akhir, analisis alur crypto/auth | `deepseek-v4-pro` | thinking |
  | Chat sehari-hari | `deepseek-flash` | non-thinking, naik ke Pro atas permintaan |
- Lapisan adapter `LLMProvider` supaya provider/model bisa diganti tanpa mengubah logika.

## Kebutuhan fungsional
| ID | Kebutuhan | Prioritas |
|----|-----------|-----------|
| FR-4.1 | Pemilihan class prioritas: dari entry point manifest, class berhubungan dengan temuan statis, class dengan string menarik. Bukan semua class | P0 |
| FR-4.2 | Ringkasan per class (map) → per package → ringkasan aplikasi (reduce), disimpan terstruktur (JSON) | P0 |
| FR-4.3 | Laporan akhir (Markdown): fungsi aplikasi, alur utama, arsitektur jaringan, auth, crypto, penyimpanan data, temuan, saran lanjut. Setiap klaim penting mencantumkan sitasi `file:baris` | P0 |
| FR-4.4 | Verifikasi sitasi: sistem mengecek bahwa file/baris yang dikutip ada; sitasi tidak valid ditandai "tidak terverifikasi" | P0 |
| FR-4.5 | Cache by hash: kunci = hash(konten kode + prompt version + model); hasil sama tidak dipanggil ulang | P0 |
| FR-4.6 | Struktur prompt ramah prefix-cache (instruksi tetap di depan, konten variabel di belakang) agar cache hit murah | P0 |
| FR-4.7 | Anggaran: batas token/USD per analisis dan per hari; berhenti dengan elegan dan beri tahu pengguna | P0 |
| FR-4.8 | Pencatatan setiap panggilan di `ai_call` (token, cache hit, estimasi biaya) + tampilan biaya per analisis | P0 |
| FR-4.9 | Redaksi secret sebelum kirim ke API (opsi default aktif); string terredaksi diberi placeholder bertoken | P0 |
| FR-4.10 | Opsi "tanpa AI" per analisis | P0 |
| FR-4.11 | Estimasi biaya sebelum mulai ("kira-kira USD x untuk N class") dan konfirmasi | P1 |
| FR-4.12 | Penanganan error: retry dengan backoff, batas konkurensi, fallback bila model tidak tersedia | P0 |
| FR-4.13 | Keluaran terstruktur (JSON mode + skema) untuk ringkasan agar mudah disimpan dan dicari | P1 |

## Perlakuan kode APK sebagai data tak tepercaya
Isi APK (string, komentar, nama class) bisa berisi teks yang mencoba memerintah model.
- Prompt sistem menyatakan bahwa konten kode adalah **data**, bukan instruksi.
- Konten kode dibungkus delimiter yang jelas.
- AI tidak punya tool yang menulis, menjalankan, atau mengakses jaringan (lihat 05).
- Output yang dirender di UI di-sanitasi (tidak ada HTML/JS mentah dari model).

## Skill pack eksternal
Pengguna ingin AI diberi skill dari [`zhaoxuya520/reverse-skill`](https://github.com/zhaoxuya520/reverse-skill) (MIT, v1.0.1, commit `cab634bd855fc287f6e420c1f36fd1a6b9245960`). Repo itu berisi sekitar 45 modul untuk berbagai tujuan (pentest, AD, wifi, dan lain-lain), dirancang untuk agent CLI di mesin lokal, bukan untuk app web seperti ini.

**Keputusan integrasi**
| ID | Kebutuhan | Prioritas |
|----|-----------|-----------|
| FR-4.20 | Vendor **hanya modul yang relevan** ke `skills/vendor/reverse-skill/` dan pin ke commit di atas: `apk-reverse` (SKILL.md + `references/`), `mobile-reverse` (hanya `references/` terkait Android), serta bagian relevan dari `reverse-engineering` (mis. `anti-analysis.md`, `ollvm-deobfuscation.md`) | P0 |
| FR-4.21 | Simpan sebagai **bahan pengetahuan** (checklist, kosakata, pola temuan), dimuat ke konteks sesuai tugas (progressive disclosure). Bukan sebagai instruksi tingkat sistem | P0 |
| FR-4.22 | Tulis `SKILL.md` adaptasi milik repo ini (`skills/apk-analyst/SKILL.md`) yang memetakan pengetahuan tadi ke tool **yang benar-benar ada** di app (lihat 05) | P0 |
| FR-4.23 | Sertakan LICENSE MIT dan catatan sumber/commit; pembaruan skill lewat PR manual dengan review diff | P0 |
| FR-4.24 | Tidak ada pembaruan otomatis dari upstream | P0 |

**Yang sengaja tidak diambil, dan alasannya**
- `field-journal/precedent-*.md`: berisi pernyataan agar AI menganggap operasi tertentu "sudah diotorisasi" dan tidak ragu. Otorisasi di app ini ditentukan oleh kebijakan produk (00 §7), bukan oleh teks di prompt.
- Langkah "ACTION REQUIRED" di tiap SKILL.md (baca file otorisasi, jalankan bootstrap, instalasi tool): bergantung pada mesin lokal dan skrip PowerShell/bash, tidak berlaku di app ini.
- Skrip `decode`, `frida-run`, `rebuild-sign-install`, serta bagian Frida/ADB/repack: butuh perangkat, atau mengeksekusi/memodifikasi APK. Di luar scope MVP (non-goal 00 §4).
- Modul non-APK (windows-ad, wifi-wireless, pentest-tools, edr-bypass-re, dan lain-lain): di luar tujuan produk.
- Pemakaian skill tetap tunduk pada aturan 05 (tool read-only). Teks skill tidak boleh memperluas hak akses AI.

## Kebutuhan non-fungsional
- NFR-4.1: Laporan awal rata-rata ≤ USD 0,50; batas keras default USD 2 per analisis.
- NFR-4.2: Waktu tahap AI ≤ 8 menit untuk APK 50 MB.
- NFR-4.3: API key hanya di environment server, tidak pernah ke browser/log.
- NFR-4.4: Versi prompt tercatat; mengubah prompt membatalkan cache terkait.

## Kriteria penerimaan
- Laporan memuat sitasi dan ≥ 90% sitasi lolos verifikasi pada APK uji.
- Menjalankan analisis ulang atas APK sama tidak menghasilkan panggilan API baru (cache hit 100%).
- String berisi "abaikan instruksi sebelumnya dan ..." di APK uji tidak mengubah perilaku atau format keluaran model.
- Melebihi anggaran menghentikan job di tahap AI dengan status `partial` dan laporan parsial tetap tersimpan.

## Pertanyaan terbuka
- [OPEN] Berapa besar potongan kode per panggilan (usul ≤ 30K token) mengingat konteks 1M tapi biaya naik linear?
- [OPEN] Perlu evaluasi kualitas (set APK uji + rubrik) sebelum mengunci prompt?
