# Image signer: HANYA toolchain tanda tangan APK (zipalign + apksigner dari Android SDK Build-Tools) — PRD 09 Bagian B, paket B-1b.
# BELUM ada daemon, keystore, volume, maupun rahasia di sini; keystore menunggu keputusan pemilik. Dijalankan TANPA JARINGAN (network_mode: none), non-root, rootfs read-only.
# Konteks build = ./services (agar paket bersama `rvcore` ikut tersalin); lihat docker-compose.yml (profil `build`).
FROM python:3.12-slim-trixie

# Google hanya menerbitkan SHA-1 untuk paket ini (repository2-3.xml: 70954e99f4c3d9d46ee70fa32624672fe7cd6ebe); SHA-256 di bawah dihitung sendiri dan dicocokkan dengan SHA-1 itu.
# Nama zip dan direktori hasil ekstraksi tidak bisa diturunkan mekanis dari versi (mis. 36.1.0 -> r36.1 / android-36.1), jadi dipin eksplisit di samping versinya.
ARG BUILD_TOOLS_VERSION=37.0.0
ARG BUILD_TOOLS_ZIP=build-tools_r37_linux.zip
ARG BUILD_TOOLS_DIR=android-37.0
ARG BUILD_TOOLS_SHA256=01af179347cbcd9c208b7f8171f7b21f6dd1d2f85bcd15e88caa51d5d7b86060

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp/home \
    BUILD_TOOLS_VERSION=${BUILD_TOOLS_VERSION}

# Hanya 3 berkas yang disalin dari zip (zipalign, apksigner.jar, lib64/libc++.so; ≈ 3 MB dari zip 66 MB); zip dibuang di layer yang sama.
# zipalign memuat libc++.so lewat RUNPATH ($ORIGIN/lib64), jadi keduanya harus berdampingan di /opt/build-tools. apktool TIDAK dipasang di sini
# (aapt2 sudah dibundel di dalam jar apktool milik runner). Skrip `apksigner` bawaan SDK tidak dipakai; wrapper memanggil jar langsung.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends openjdk-21-jre-headless ca-certificates curl unzip; \
    curl -fsSL -o /tmp/build-tools.zip "https://dl.google.com/android/repository/${BUILD_TOOLS_ZIP}"; \
    echo "${BUILD_TOOLS_SHA256}  /tmp/build-tools.zip" | sha256sum -c -; \
    unzip -q /tmp/build-tools.zip "${BUILD_TOOLS_DIR}/zipalign" "${BUILD_TOOLS_DIR}/lib/apksigner.jar" "${BUILD_TOOLS_DIR}/lib64/libc++.so" -d /tmp/bt; \
    mkdir -p /opt/build-tools/lib64; \
    install -m 0755 "/tmp/bt/${BUILD_TOOLS_DIR}/zipalign" /opt/build-tools/zipalign; \
    install -m 0644 "/tmp/bt/${BUILD_TOOLS_DIR}/lib/apksigner.jar" /opt/build-tools/apksigner.jar; \
    install -m 0644 "/tmp/bt/${BUILD_TOOLS_DIR}/lib64/libc++.so" /opt/build-tools/lib64/libc++.so; \
    ln -s /opt/build-tools/zipalign /usr/local/bin/zipalign; \
    printf '#!/bin/sh\nexec java -Xmx256m --enable-native-access=ALL-UNNAMED -Duser.home="$HOME" -Djava.io.tmpdir=/tmp -jar /opt/build-tools/apksigner.jar "$@"\n' > /usr/local/bin/apksigner; \
    chmod 0755 /usr/local/bin/apksigner; \
    if ldd /opt/build-tools/zipalign | grep -q 'not found'; then echo "zipalign: pustaka tidak ditemukan"; ldd /opt/build-tools/zipalign; exit 1; fi; \
    apt-get purge -y --auto-remove curl unzip; \
    rm -rf /var/lib/apt/lists/* /tmp/*

# uid 10001 seperti runner. Tanpa /data dan tanpa volume: pada tahap ini tidak ada yang disimpan di sini.
RUN groupadd --system --gid 10001 signer \
 && useradd --uid 10001 --gid signer --no-create-home --shell /usr/sbin/nologin signer

WORKDIR /app
# `rvcore` disiapkan untuk signer-daemon berikutnya; BELUM dipakai oleh selftest.
COPY rvcore ./rvcore
COPY signer/signer-selftest /usr/local/bin/
RUN chmod 0755 /usr/local/bin/signer-selftest

ENV PYTHONPATH=/app
USER 10001:10001
WORKDIR /tmp

CMD ["signer-selftest"]
