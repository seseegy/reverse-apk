# Override: Login

Menimpa `MASTER.md` hanya pada hal berikut.

- **Layout:** satu kartu di tengah (maks 400px), tanpa navigasi, tanpa dekorasi. Judul `reverse-apk` (JetBrains Mono).
- **Field:** username dan password, label terlihat (bukan hanya placeholder).
- **Atribut:** `autocomplete="username"` dan `autocomplete="current-password"`. **Jangan** blokir paste.
- **Password:** tombol tampil/sembunyi dengan nama aksesibel ("Tampilkan password"), `aria-pressed` sesuai state.
- **Error:** pesan inline di bawah form, `role="alert"`, tidak membedakan "user salah" vs "password salah". Setelah rate limit, tampilkan sisa waktu tunggu.
- **Fokus awal:** field username.
- **Tombol:** satu aksi utama (hijau `--color-accent`), nonaktif + label "Memproses…" saat submit.
- **Tidak ada:** "ingat saya" lintas perangkat, tautan registrasi, logo besar.
