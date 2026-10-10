# Image runner: berisi alat dekompilasi (jadx, apktool) + daemon yang menjalankan job dari spool.
# Dijalankan TANPA JARINGAN (network_mode: none), non-root, rootfs read-only. APK tidak pernah dieksekusi.
# Konteks build = ./services (agar paket bersama `rvcore` ikut tersalin); lihat docker-compose.yml.
FROM python:3.12-slim-trixie

ARG JADX_VERSION=1.5.6
ARG JADX_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974
ARG APKTOOL_VERSION=3.0.3
ARG APKTOOL_SHA256=dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp/home \
    JADX_VERSION=${JADX_VERSION} \
    APKTOOL_VERSION=${APKTOOL_VERSION} \
    JADX_OPTS="-Xmx2g"

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends openjdk-21-jre-headless ca-certificates curl unzip; \
    curl -fsSL -o /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"; \
    echo "${JADX_SHA256}  /tmp/jadx.zip" | sha256sum -c -; \
    mkdir -p /opt/jadx; unzip -q /tmp/jadx.zip -d /opt/jadx; \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx; \
    mkdir -p /opt/apktool; \
    curl -fsSL -o /opt/apktool/apktool.jar "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"; \
    echo "${APKTOOL_SHA256}  /opt/apktool/apktool.jar" | sha256sum -c -; \
    printf '#!/bin/sh\nexec java -Xmx2g -Duser.home="$HOME" -Djava.io.tmpdir=/tmp -jar /opt/apktool/apktool.jar "$@"\n' > /usr/local/bin/apktool; \
    chmod 0755 /usr/local/bin/apktool; \
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
COPY runner/runner-selftest runner/runner-daemon /usr/local/bin/
RUN chmod 0755 /usr/local/bin/runner-selftest /usr/local/bin/runner-daemon

ENV PYTHONPATH=/app
USER 10001:10001
WORKDIR /work

CMD ["runner-daemon"]
