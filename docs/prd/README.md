# PRD — reverse-apk

Platform web **privat** (single-user) untuk membongkar dan memahami APK Android, dibantu AI (DeepSeek API).
PRD dibagi per bagian supaya bisa direview dan dikerjakan bertahap.

| # | Dokumen | Isi |
|---|---------|-----|
| 00 | [Overview](00-overview.md) | Visi, tujuan, non-tujuan, persona, scope, metrik, risiko |
| 01 | [Ingestion & Storage](01-ingestion-storage.md) | Upload APK/XAPK, dedup hash, struktur data, retensi |
| 02 | [Decompile Pipeline](02-decompile-pipeline.md) | jadx, apktool, job queue, sandbox worker |
| 03 | [Static Analysis](03-static-analysis.md) | Manifest, permission, endpoint, secret, native lib, index kode |
| 04 | [AI Analysis](04-ai-analysis.md) | Integrasi DeepSeek, ringkasan map-reduce, laporan, biaya |
| 05 | [Chat Agent](05-chat-agent.md) | Tanya-jawab dengan kode via tool calling |
| 06 | [Web UI](06-web-ui.md) | Halaman, alur pengguna, kebutuhan UX |
| 07 | [Infra & Security](07-infra-security.md) | Deploy di VPS, jaringan, isolasi, auth, backup |
| 08 | [Roadmap](08-roadmap.md) | Milestone, urutan kerja, definisi selesai |
| 09 | [Paket multi-APK & bengkel](09-bundles-and-workbench.md) | **Rencana**: XAPK/APKS/APKM/AAB, membangun & menandatangani APK, shell AI di kontainer terpisah |
| 10 | [Penyimpanan](10-storage.md) | Halaman Penyimpanan: melihat pemakaian disk, membersihkan, dan menjelajah folder (hanya baca) — selesai |

## Konvensi
- ID requirement: `FR-<bagian>.<no>` (fungsional), `NFR-<bagian>.<no>` (non-fungsional).
- Prioritas: **P0** wajib MVP, **P1** setelah MVP, **P2** nice-to-have.
- Bagian yang belum pasti ditandai **[OPEN]** dan dikumpulkan di akhir tiap dokumen.
