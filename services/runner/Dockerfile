# Image runner: berisi alat dekompilasi (jadx, apktool). Dijalankan SEBAGAI KONTAINER SEKALI PAKAI
# tanpa jaringan (--network none), non-root, rootfs read-only. APK tidak pernah dieksekusi.
FROM python:3.12-slim-trixie

ARG JADX_VERSION=1.5.6
ARG JADX_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974
ARG APKTOOL_VERSION=3.0.3
ARG APKTOOL_SHA256=dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp/home \
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
    printf '#!/bin/sh\nexec java -Xmx2g -jar /opt/apktool/apktool.jar "$@"\n' > /usr/local/bin/apktool; \
    chmod 0755 /usr/local/bin/apktool; \
    apt-get purge -y --auto-remove curl unzip; \
    rm -rf /var/lib/apt/lists/* /tmp/*

COPY runner-selftest /usr/local/bin/runner-selftest
RUN chmod 0755 /usr/local/bin/runner-selftest

RUN groupadd --system --gid 10002 runner \
 && useradd --uid 10002 --gid runner --no-create-home --shell /usr/sbin/nologin runner
USER 10002:10002
WORKDIR /work

CMD ["runner-selftest"]
