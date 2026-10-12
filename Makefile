SHELL := /bin/bash
.DEFAULT_GOAL := help
COMPOSE ?= docker compose

.PHONY: help init password up down restart logs ps update runner-selftest bench-selftest ai-check env-check doctor test

help: ## Tampilkan daftar perintah
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[32m%-16s\033[0m %s\n", $$1, $$2}'

init: ## Buat .env (rahasia acak) dan folder secrets/
	@./scripts/init.sh

password: ## Atur password admin (disimpan sebagai hash argon2id)
	@test -f .env || { echo "Jalankan 'make init' dulu."; exit 1; }
	@read -rsp "Password baru (min 12 karakter): " p1; echo; \
	 read -rsp "Ulangi password: " p2; echo; \
	 [ "$$p1" = "$$p2" ] || { echo "Password tidak sama."; exit 1; }; \
	 printf '%s' "$$p1" | $(COMPOSE) run --rm --no-deps -T web python -m app.cli hash-stdin > secrets/admin_password_hash.tmp \
	   && mv secrets/admin_password_hash.tmp secrets/admin_password_hash \
	   && chmod 644 secrets/admin_password_hash \
	   && echo "Password admin disimpan. Jalankan 'make up' (atau 'docker compose restart web' bila sudah jalan)." \
	   || { rm -f secrets/admin_password_hash.tmp; echo "Gagal mengatur password."; exit 1; }

up: ## Build dan jalankan semua layanan
	@test -s secrets/admin_password_hash || { echo "Password admin belum diatur. Jalankan 'make password'."; exit 1; }
	$(COMPOSE) up -d --build

down: ## Hentikan semua layanan (data tetap tersimpan)
	$(COMPOSE) down

restart: ## Terapkan perubahan .env/compose dan restart (membuat ulang container yang berubah)
	@# `docker compose restart` TIDAK membaca ulang .env: container tetap memakai nilai lama. `up -d` membuat ulang yang berubah.
	$(COMPOSE) up -d
	@./scripts/envcheck.sh || true

logs: ## Ikuti log (Ctrl+C untuk keluar)
	$(COMPOSE) logs -f --tail=100

ps: ## Status kontainer
	$(COMPOSE) ps

update: ## Ambil kode terbaru lalu build ulang
	git pull --ff-only
	$(MAKE) up

runner-selftest: ## Uji runner: alat benar-benar bisa bekerja + bukti isolasi (jaringan, rootfs, non-root)
	$(COMPOSE) build runner
	$(COMPOSE) run --rm --no-deps runner runner-selftest

bench-selftest: ## Uji bench: BUKTI isolasi shell AI dari dalam kontainer (jalankan SEBELUM AI_SHELL_ENABLED=1)
	$(COMPOSE) build bench
	$(COMPOSE) run --rm --no-deps --entrypoint python3 bench /usr/local/bin/bench-selftest

ai-check: ## Uji provider AI (koneksi, streaming, tool calling, pemakaian token) memakai kunci di .env
	$(COMPOSE) run --rm --no-deps web python -m app.ai.check

env-check: ## Bandingkan .env dengan environment container (mengapa variabel tidak termuat?)
	@COMPOSE="$(COMPOSE)" ./scripts/envcheck.sh

test: ## Jalankan tes (lokal, tanpa Docker; butuh Python 3.12 + pip install -r services/web/requirements.txt -r tests/requirements.txt)
	python3 -m pyflakes services tests
	python3 -m pytest

doctor: ## Periksa konfigurasi dan kesehatan layanan
	@test -f .env || { echo "✗ .env belum ada (make init)"; exit 1; }
	@! grep -q '=__GENERATE__' .env || { echo "✗ .env masih berisi __GENERATE__ (make init)"; exit 1; }
	@echo "✓ .env terisi"
	@test -s secrets/admin_password_hash && echo "✓ password admin sudah diatur" || { echo "✗ password admin belum diatur (make password)"; exit 1; }
	@$(COMPOSE) config -q && echo "✓ docker-compose.yml valid"
	@$(COMPOSE) ps
	@set -a; . ./.env; set +a; \
	 curl -fsS -m 10 "https://$$APP_DOMAIN/healthz" && echo && echo "✓ https://$$APP_DOMAIN/healthz OK" || echo "✗ https://$$APP_DOMAIN/healthz tidak bisa dijangkau (cek DNS & log caddy)"
