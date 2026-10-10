SHELL := /bin/bash
.DEFAULT_GOAL := help
COMPOSE ?= docker compose

.PHONY: help init password up down restart logs ps update runner-selftest doctor

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

restart: ## Restart semua layanan
	$(COMPOSE) restart

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

doctor: ## Periksa konfigurasi dan kesehatan layanan
	@test -f .env || { echo "✗ .env belum ada (make init)"; exit 1; }
	@! grep -q '=__GENERATE__' .env || { echo "✗ .env masih berisi __GENERATE__ (make init)"; exit 1; }
	@echo "✓ .env terisi"
	@test -s secrets/admin_password_hash && echo "✓ password admin sudah diatur" || { echo "✗ password admin belum diatur (make password)"; exit 1; }
	@$(COMPOSE) config -q && echo "✓ docker-compose.yml valid"
	@$(COMPOSE) ps
	@set -a; . ./.env; set +a; \
	 curl -fsS -m 10 "https://$$APP_DOMAIN/healthz" && echo && echo "✓ https://$$APP_DOMAIN/healthz OK" || echo "✗ https://$$APP_DOMAIN/healthz tidak bisa dijangkau (cek DNS & log caddy)"
