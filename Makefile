SHELL := /bin/bash
.DEFAULT_GOAL := help
COMPOSE ?= docker compose

# Keystore penanda tangan ada? (scripts/keystore.sh present: senyap, tanpa efek samping, tanpa Docker; kosong bila belum ada, mis. di CI.)
# Dievaluasi saat Makefile DIBACA: jalankan `make init` dan `make up` sebagai dua perintah (bukan `make init up`), supaya `up` melihat keystore yang baru dibuat.
KEYSTORE_PRESENT := $(shell ./scripts/keystore.sh present >/dev/null 2>&1 && echo 1)
ifeq ($(KEYSTORE_PRESENT),1)
# Hanya bila KEDUA berkas ada: muat berkas tambahan (kunci HANYA ke signer) dan aktifkan profil `build` agar signer ikut `up`/`down`/`restart`.
export COMPOSE_FILE := docker-compose.yml:docker-compose.keystore.yml
export COMPOSE_PROFILES := build
# Bind-mount berkas mengunci INODE: berkas kunci yang diganti (mv/rsync/cp --remove-destination) tidak terlihat kontainer lama, dan isi berkas rahasia tidak
# masuk hash konfigurasi Compose. Label stempel (inode-ukuran-mtime) berubah -> `up -d` membuat ulang signer. Bukan rahasia.
export KEYSTORE_STAMP := $(shell stat -c '%i-%s-%Y' secrets/signing_keystore.p12 secrets/signing_keystore_pass 2>/dev/null | tr '\n' ':')
endif

.PHONY: help init keystore keystore-info keystore-access password up down restart logs ps update runner-selftest signer-selftest signer-verify tools-check bench-selftest net-check ai-check env-check doctor test

help: ## Tampilkan daftar perintah
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[32m%-16s\033[0m %s\n", $$1, $$2}'

init: ## Buat .env (rahasia acak), folder secrets/, dan keystore penanda tangan (butuh Docker; membangun image signer bila perlu)
	@./scripts/init.sh

keystore: ## Buat keystore penanda tangan (secrets/signing_keystore.p12) bila belum ada; aman diulang, TIDAK PERNAH menimpa
	@./scripts/keystore.sh create

keystore-info: ## Cetak sidik jari SHA-256, DN, masa berlaku, algoritma keystore (tanpa kata sandi)
	@./scripts/keystore.sh info

keystore-access: ## Pastikan kunci terbaca kontainer signer (secrets/ mode 700, kedua berkas keystore mode 644); hanya chmod, isi tidak berubah
	@./scripts/keystore.sh access

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
	@./scripts/keystore.sh access --auto || true
	$(COMPOSE) up -d --build

down: ## Hentikan semua layanan (data tetap tersimpan; signer ikut turun walau keystore sudah dipindah)
	COMPOSE_PROFILES=build $(COMPOSE) down

restart: ## Terapkan perubahan .env/compose dan restart (membuat ulang container yang berubah)
	@# `docker compose restart` TIDAK membaca ulang .env: container tetap memakai nilai lama. `up -d` membuat ulang yang berubah.
	@./scripts/keystore.sh access --auto || true
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

signer-selftest: ## Uji signer: zipalign + apksigner (keystore sementara -> sign -> verify, tes negatif) + bukti isolasi dari dalam kontainer (profil `build`, tidak ikut `make up`)
	$(COMPOSE) --profile build build signer
	$(COMPOSE) --profile build run --rm --no-deps signer signer-selftest

signer-verify: ## Bukti end-to-end signer: APK uji ditandatangani dengan keystore pemilik lewat spool + verifikasi independen + negatif + kebocoran sandi (BIG_MB=1000 menambah uji APK besar & memori)
	@COMPOSE="$(COMPOSE)" ./scripts/signer-verify.sh

tools-check: ## Tabel versi semua alat build (java, apktool, jadx, keytool, zipalign, apksigner) dari image runner & signer, dibandingkan dengan pin
	@COMPOSE="$(COMPOSE)" ./scripts/tools-check.sh

bench-selftest: ## Uji bench: BUKTI isolasi shell AI dari dalam kontainer (jalankan SEBELUM AI_SHELL_ENABLED=1; bila AI_SHELL_NET_ALLOW terisi, juga bukti jaringan)
	$(COMPOSE) build bench egress
	$(COMPOSE) up -d --no-deps egress
	$(COMPOSE) run --rm --no-deps --entrypoint python3 bench /usr/local/bin/bench-selftest

net-check: ## Uji jalur penuh jaringan shell AI ke satu URL lewat proxy egress: make net-check URL=https://api.contoh.com/ (host harus ada di AI_SHELL_NET_ALLOW)
	@test -n "$(URL)" || { echo "Pemakaian: make net-check URL=https://host/jalur"; exit 1; }
	$(COMPOSE) build bench egress
	$(COMPOSE) up -d --no-deps egress
	$(COMPOSE) run --rm --no-deps -e SELFTEST_NET_URL="$(URL)" --entrypoint python3 bench /usr/local/bin/bench-selftest

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
	@./scripts/keystore.sh status || true
	@$(COMPOSE) config -q && echo "✓ docker-compose.yml valid"
	@$(COMPOSE) ps
	@set -a; . ./.env; set +a; \
	 curl -fsS -m 10 "https://$$APP_DOMAIN/healthz" && echo && echo "✓ https://$$APP_DOMAIN/healthz OK" || echo "✗ https://$$APP_DOMAIN/healthz tidak bisa dijangkau (cek DNS & log caddy)"
