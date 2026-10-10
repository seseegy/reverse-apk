# Override: Detail Analisis

Halaman terpadat di app. Menimpa `MASTER.md` pada hal berikut.

## Layout
- **Header tetap (sticky):** nama + package + versi, status pipeline, biaya AI. Tinggi ringkas; kontennya tidak boleh menutupi fokus keyboard (beri `scroll-margin-top`).
- **Tab:** Ringkasan · Manifest · Temuan · Kode · Jaringan · Chat · Biaya & Log. Tab dapat dioperasikan keyboard (panah kiri/kanan), tab aktif ditandai dengan garis bawah **dan** teks tebal (bukan warna saja).
- **Tab Kode:** dua panel — pohon package/class (kiri, lebar 280px, bisa diciutkan) dan penampil kode (kanan). Di bawah 1024px pohon menjadi drawer.
- **Tab Chat:** kolom percakapan di kiri, panel "sumber" di kanan yang menampilkan kode yang disitasi. Di layar kecil panel sumber menjadi sheet dari bawah.

## Density
Density 7: padding sel tabel 8px × 12px, tinggi baris 36px, jarak antar bagian 24px.

## Status pipeline
Stepper horizontal: `Antre → Validasi → apktool → jadx → Indeks → Analisis statis → AI → Selesai`.
- Tiap langkah punya ikon + teks status (menunggu / berjalan / selesai / gagal), tidak hanya warna.
- Tahap gagal menampilkan pesan error ringkas dan tombol "Coba lagi tahap ini".
- Log di bawah stepper, `aria-live="off"` (agar tidak membanjiri pembaca layar); ringkasan status berubah via `role="status"`.

## Penampil kode
- Latar `--code-bg`, JetBrains Mono 13px, tinggi baris 1.55, nomor baris tidak ikut tersalin.
- Baris yang disitasi disorot + `scroll-into-view`; sorotan bukan hanya warna (tambahkan penanda di gutter).
- Class > 2.000 baris dirender bertahap (virtualisasi).
- Toolbar: salin tautan baris, Java/smali, cari di berkas, "Jelaskan kode ini".

## Tabel Temuan
- Kolom: Severity · Kategori · Judul · Lokasi · Sumber (static/ai).
- Filter kategori/severity berupa kontrol dengan label; hitungan hasil diumumkan lewat `role="status"`.
- Secret ter-mask default (`sk-••••••a3f9`) dengan tombol "Tampilkan". Aksi tampilkan dicatat di audit log.

## Chat
- Pesan model di-stream; tombol "Berhenti".
- Tool call tampil sebagai baris ringkas (`search_code("okhttp")` → 12 hasil) yang bisa dibuka.
- Sitasi `Kelas#method` berupa tautan; sitasi yang gagal verifikasi diberi label "tidak terverifikasi".
- Indikator biaya sesi di sudut panel.
