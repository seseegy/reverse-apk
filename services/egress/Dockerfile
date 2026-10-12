# Proxy keluar untuk shell AI (PRD 09). Satu-satunya kontainer dengan jalan ke internet yang bisa dijangkau `bench`.
# Tanpa volume, tanpa rahasia, tanpa akses ke jaringan `backend`/`edge` (hanya `benchnet` + `egressnet`). Konteks build = ./services.
FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN groupadd --system --gid 10003 egress \
 && useradd --uid 10003 --gid egress --no-create-home --shell /usr/sbin/nologin egress

WORKDIR /app
COPY egress/egress ./egress
COPY egress/egress-proxy /usr/local/bin/egress-proxy
RUN chmod 0755 /usr/local/bin/egress-proxy

ENV PYTHONPATH=/app
USER 10003:10003
EXPOSE 3128
CMD ["egress-proxy"]
