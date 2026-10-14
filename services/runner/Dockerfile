# Image runner: berisi alat dekompilasi (jadx, apktool) + daemon yang menjalankan job dari spool.
# Dijalankan TANPA JARINGAN (network_mode: none), non-root, rootfs read-only. APK tidak pernah dieksekusi.
# Konteks build = ./services (agar paket bersama `rvcore` ikut tersalin); lihat docker-compose.yml.
FROM python:3.12-slim-trixie

ARG JADX_VERSION=1.5.6
ARG JADX_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974
ARG APKTOOL_VERSION=3.0.3
ARG APKTOOL_SHA256=dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423
# aapt2 = berkas `prebuilt/linux/aapt2` di dalam apktool_${APKTOOL_VERSION}.jar (ELF x86-64 statis, 6449680 byte). Dipin terpisah supaya
# mengganti versi apktool otomatis memaksa meninjau ulang hash ini. Harus dihitung ulang dari jar baru saat APKTOOL_VERSION dinaikkan.
ARG AAPT2_SHA256=df312db814c018019b2b79a993b041b738d7b76f4a8f28da25bc874a026368cc

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp/home \
    JADX_VERSION=${JADX_VERSION} \
    APKTOOL_VERSION=${APKTOOL_VERSION} \
    AAPT2_SHA256=${AAPT2_SHA256} \
    AAPT2_PATH=/opt/apktool/aapt2 \
    AAPT2_EXEC_DIR=/opt/aapt-exec \
    ANALYZER_VERSION=4 \
    JADX_OPTS="-Xmx2g"

# aapt2 dipasang di rootfs (/opt/apktool/aapt2: read-only, milik root, 0755, hash dipin) sebagai SUMBER tepercaya dan TIDAK diekstrak apktool ke /tmp:
# /tmp runner sengaja `noexec` (APK tak tepercaya), sedangkan tanpa `--aapt` apktool 3.0.3 mengekstrak aapt2 ke direktori sementara lalu menjalankannya (Permission denied).
# Menunjuk `--aapt` langsung ke rootfs juga GAGAL: AaptManager.setBinaryExecutable memanggil File.setExecutable(true) => chmod(2) SELALU, dan chmod ditolak
# pada rootfs read-only milik root (uid 10001 bukan pemilik) -> "Could not set aapt binary as executable". Karena itu wrapper `apktool` (runner/apktool-wrapper)
# menyalin aapt2 ke tmpfs khusus /opt/aapt-exec (titik mount dibuat di bawah; tmpfs kecil yang boleh exec, dipasang oleh docker-compose.yml), memverifikasi hash
# SALINAN terhadap pin (/opt/apktool/aapt2.sha256, ditulis dari ARG di bawah), lalu menyisipkan `--aapt` untuk b/build. Jangan "memperbaikinya" dengan `exec` pada /tmp.
RUN set -eux; \
    if [ "$(uname -m)" != "x86_64" ]; then \
      echo "GALAT: aapt2 bawaan apktool ${APKTOOL_VERSION} hanya untuk x86-64 (arsitektur ini: $(uname -m)); bangun image untuk linux/amd64." >&2; \
      exit 1; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends openjdk-21-jre-headless ca-certificates curl unzip; \
    curl -fsSL -o /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"; \
    echo "${JADX_SHA256}  /tmp/jadx.zip" | sha256sum -c -; \
    mkdir -p /opt/jadx; unzip -q /tmp/jadx.zip -d /opt/jadx; \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx; \
    mkdir -p /opt/apktool; \
    curl -fsSL -o /opt/apktool/apktool.jar "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"; \
    echo "${APKTOOL_SHA256}  /opt/apktool/apktool.jar" | sha256sum -c -; \
    unzip -p /opt/apktool/apktool.jar prebuilt/linux/aapt2 > /opt/apktool/aapt2; \
    echo "${AAPT2_SHA256}  /opt/apktool/aapt2" | sha256sum -c -; \
    chmod 0755 /opt/apktool/aapt2; \
    hdr="$(od -An -tx1 -N20 /opt/apktool/aapt2 | tr -d ' \n')"; \
    case "$hdr" in 7f454c4602*3e00) ;; *) echo "GALAT: aapt2 bukan ELF 64-bit x86-64 (header: $hdr)" >&2; exit 1 ;; esac; \
    /opt/apktool/aapt2 version; \
    printf '%s\n' "${AAPT2_SHA256}" > /opt/apktool/aapt2.sha256; \
    chmod 0644 /opt/apktool/aapt2.sha256; \
    mkdir -p /opt/aapt-exec; \
    chmod 0755 /opt/aapt-exec; \
    apt-get purge -y --auto-remove curl unzip; \
    rm -rf /var/lib/apt/lists/* /tmp/*

# uid 10001 sama dengan web/worker: berkas hasil dekompilasi harus bisa dihapus oleh web (hapus analisis)
# dan dibaca worker. Pemisahan hak dilakukan lewat container & volume (uploads read-only, tanpa db), bukan uid.
RUN groupadd --system --gid 10001 runner \
 && useradd --uid 10001 --gid runner --no-create-home --shell /usr/sbin/nologin runner \
 && mkdir -p /data/uploads /data/work /data/spool \
 && chown -R 10001:10001 /data

WORKDIR /app
COPY rvcore ./rvcore
COPY runner/analyzer ./analyzer
COPY runner/runner-selftest runner/runner-daemon /usr/local/bin/
COPY runner/apktool-wrapper /usr/local/bin/apktool
RUN chmod 0755 /usr/local/bin/runner-selftest /usr/local/bin/runner-daemon /usr/local/bin/apktool

ENV PYTHONPATH=/app
USER 10001:10001
WORKDIR /work

CMD ["runner-daemon"]
