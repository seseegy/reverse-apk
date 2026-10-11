# Konteks build = ./services (agar paket bersama `rvcore` ikut tersalin); lihat docker-compose.yml.
FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# Titik mount volume dibuat & dimiliki uid aplikasi agar volume kosong yang baru dibuat mewarisi izinnya.
RUN groupadd --system --gid 10001 app \
 && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data/uploads /data/work /data/files /data/db \
 && chown -R 10001:10001 /data

WORKDIR /srv

COPY web/requirements.txt .
RUN pip install -r requirements.txt

COPY rvcore ./rvcore
# Pola secret yang sama dengan analyzer dipakai ulang untuk redaksi sebelum kirim ke AI (satu sumber kebenaran).
COPY runner/analyzer ./analyzer
COPY web/app ./app

USER 10001:10001
EXPOSE 8000

# --proxy-headers: IP klien asli dari Caddy (satu-satunya yang bisa menjangkau port ini
# lewat jaringan `edge`; port tidak dipublikasikan ke host).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header", "--workers", "1"]
