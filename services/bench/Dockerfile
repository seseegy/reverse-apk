# Image bench: shell terisolasi untuk tool AI `shell_run` (PRD 09, Bagian C).
# Jaringan: BAWAAN TIDAK ADA. Layanan ini hanya ada di jaringan internal `benchnet` (tanpa rute ke internet); satu-satunya yang bisa dijangkau adalah proxy `egress`,
# dan itu pun hanya bila AI_SHELL_NET_ALLOW diisi (lihat docker-compose.yml). Non-root, rootfs read-only, TANPA rahasia (bukan kunci AI, DB, Redis, maupun keystore).
# Setiap perintah dikurung Landlock ke ruang kerja satu analisis (services/bench/bench/landlock.py); bila Landlock tidak tersedia perintah DITOLAK.
# Konteks build = ./services (agar paket bersama `rvcore` ikut tersalin); lihat docker-compose.yml.
FROM python:3.12-slim-trixie

# Ghidra untuk tool AI `analyze_native_library` (dipanggil lewat entrypoint tetap bench-ghidra, bukan shell bebas).
# Pin hash SAMA dengan runner (services/runner/Dockerfile): satu versi, satu hash, ditinjau bersama.
ARG GHIDRA_VERSION=11.4
ARG GHIDRA_SHA256=8b2902bb3166901bc6297a06892eee077c08605be65abfe73ce7aaaafb651632
ARG GHIDRA_ZIP=ghidra_11.4_PUBLIC_20250620.zip

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    TMPDIR=/tmp \
    GHIDRA_HOME=/opt/ghidra \
    GHIDRA_VERSION=${GHIDRA_VERSION}

# Alat untuk menganalisis dan mengubah SALINAN hasil dekompilasi. `curl` + `ca-certificates` untuk menguji API lewat proxy egress (tanpa jaringan keduanya tak berguna,
# jadi tidak menambah kemampuan saat jaringan mati). Sengaja TIDAK ada: wget/git/ssh/nc, compiler, dan apksigner/keystore (apktool/jadx tetap berjalan di runner).
# Java (JDK 21, syarat Ghidra 11.x) HANYA untuk Ghidra headless lewat bench-ghidra; tidak ada jalur lain memakainya.
# Heap analyzeHeadless dipatok MAXMEM=1G: batas kontainer bench 1,5 GB / 2 CPU (docker-compose.yml) — dinaikkan bersama pagar library 200 MB (22 Okt, dari 512M/1 GB); jumlah mem_limit semua kontainer dijaga tes tahap 6 <= 7 GB di VPS 8 GB, jadi 1,5 GB adalah plafon bench di amplop itu.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends unzip zip file xxd diffutils patch findutils grep sed gawk coreutils bash less binutils curl ca-certificates openjdk-21-jdk-headless; \
    curl -fsSL -o /tmp/ghidra.zip "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}"; \
    echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c -; \
    unzip -q /tmp/ghidra.zip -d /opt; \
    mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra; \
    rm /tmp/ghidra.zip; \
    sed -i 's/^MAXMEM=.*$/MAXMEM=1G/' /opt/ghidra/support/analyzeHeadless; \
    grep -q '^MAXMEM=1G$' /opt/ghidra/support/analyzeHeadless; \
    ln -s /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless; \
    rm -rf /var/lib/apt/lists/* /tmp/*

# uid 10001 sama dengan web/worker/runner: ruang kerja harus bisa dihapus oleh web (hapus analisis).
# --home-dir /tmp/home: JVM mengambil user.home dari /etc/passwd (BUKAN $HOME) dan LaunchSupport Ghidra
# menolak jalan bila direktori itu tidak ada (pelajaran runner PR #57). /tmp adalah tmpfs yang bisa
# ditulis; di dalam kurungan Landlock, bench-ghidra tetap mengarahkan user.home ke scratch per-job.
RUN groupadd --system --gid 10001 bench \
 && useradd --uid 10001 --gid bench --no-create-home --home-dir /tmp/home --shell /usr/sbin/nologin bench \
 && mkdir -p /data/work /data/uploads /data/bench /data/benchspool \
 && chown -R 10001:10001 /data

WORKDIR /app
COPY rvcore ./rvcore
COPY bench/bench ./bench
COPY bench/bench-daemon bench/bench-selftest bench/bench-ghidra /usr/local/bin/
# Skrip ekspor Ghidra yang SAMA dengan runner (sumber tunggal: services/runner/analyzer/GhidraExport.java).
COPY runner/analyzer/GhidraExport.java /usr/local/lib/bench-ghidra/GhidraExport.java
RUN chmod 0755 /usr/local/bin/bench-daemon /usr/local/bin/bench-selftest /usr/local/bin/bench-ghidra

ENV PYTHONPATH=/app
USER 10001:10001
WORKDIR /tmp

CMD ["bench-daemon"]
