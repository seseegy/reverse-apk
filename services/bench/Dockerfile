# Image bench: shell terisolasi untuk tool AI `shell_run` (PRD 09, Bagian C).
# Jaringan: BAWAAN TIDAK ADA. Layanan ini hanya ada di jaringan internal `benchnet` (tanpa rute ke internet); satu-satunya yang bisa dijangkau adalah proxy `egress`,
# dan itu pun hanya bila AI_SHELL_NET_ALLOW diisi (lihat docker-compose.yml). Non-root, rootfs read-only, TANPA rahasia (bukan kunci AI, DB, Redis, maupun keystore).
# Setiap perintah dikurung Landlock ke ruang kerja satu analisis (services/bench/bench/landlock.py); bila Landlock tidak tersedia perintah DITOLAK.
# Konteks build = ./services (agar paket bersama `rvcore` ikut tersalin); lihat docker-compose.yml.
FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    TMPDIR=/tmp

# Alat untuk menganalisis dan mengubah SALINAN hasil dekompilasi. `curl` + `ca-certificates` untuk menguji API lewat proxy egress (tanpa jaringan keduanya tak berguna,
# jadi tidak menambah kemampuan saat jaringan mati). Sengaja TIDAK ada: wget/git/ssh/nc, compiler, apksigner/keystore, dan Java (apktool/jadx berjalan di runner).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends unzip zip file xxd diffutils patch findutils grep sed gawk coreutils bash less binutils curl ca-certificates; \
    rm -rf /var/lib/apt/lists/* /tmp/*

# uid 10001 sama dengan web/worker/runner: ruang kerja harus bisa dihapus oleh web (hapus analisis).
RUN groupadd --system --gid 10001 bench \
 && useradd --uid 10001 --gid bench --no-create-home --shell /usr/sbin/nologin bench \
 && mkdir -p /data/work /data/uploads /data/bench /data/benchspool \
 && chown -R 10001:10001 /data

WORKDIR /app
COPY rvcore ./rvcore
COPY bench/bench ./bench
COPY bench/bench-daemon bench/bench-selftest /usr/local/bin/
RUN chmod 0755 /usr/local/bin/bench-daemon /usr/local/bin/bench-selftest

ENV PYTHONPATH=/app
USER 10001:10001
WORKDIR /tmp

CMD ["bench-daemon"]
