# Konteks build = ./services (agar paket bersama `rvcore` ikut tersalin); lihat docker-compose.yml.
FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

RUN groupadd --system --gid 10001 app \
 && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data/uploads /data/work /data/db /data/spool /data/builds /data/signspool \
 && chown -R 10001:10001 /data

WORKDIR /app

COPY worker/requirements.txt .
RUN pip install -r requirements.txt

COPY rvcore ./rvcore
COPY worker/worker.py worker/tasks.py worker/healthcheck.py worker/pipeline.py \
     worker/logtail.py worker/manifest.py worker/findings_import.py worker/signcheck.py ./

USER 10001:10001

CMD ["python", "worker.py"]
