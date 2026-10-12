# Image bench: shell terisolasi untuk tool AI `shell_run` (PRD 09, Bagian C).
# Dijalankan TANPA JARINGAN, non-root, rootfs read-only, TANPA rahasia (bukan kunci AI, DB, Redis, maupun keystore).
# Setiap perintah dikurung Landlock ke ruang kerja satu analisis (services/bench/bench/landlock.py); bila Landlock tidak tersedia perintah DITOLAK.
# Konteks build = ./services (agar paket bersama `rvcore` ikut tersalin); lihat docker-compose.yml.
FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    TMPDIR=/tmp

# Alat untuk menganalisis dan mengubah SALINAN hasil dekompilasi. Sengaja TIDAK ada: curl/wget/git/ssh (tanpa jaringan juga tidak berguna), compiler,
# apksigner/keystore, dan Java (apktool/jadx berjalan di runner, bukan di sini).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends unzip zip file xxd diffutils patch findutils grep sed gawk coreutils bash less binutils; \
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
