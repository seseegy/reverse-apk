#!/usr/bin/env bash
# Menjalankan scripts/bench-probe.py di dalam kontainer dengan pengaturan yang SAMA seperti rencana `bench`
# (docs/prd/09): tanpa jaringan, rootfs read-only, non-root, semua kapabilitas dibuang, no-new-privileges,
# profil seccomp & AppArmor bawaan Docker. Hanya membaca satu berkas skrip; tidak menyentuh volume atau data aplikasi.
#
# Pemakaian (di VPS, dari folder repo):   bash scripts/bench-probe.sh
# Kode keluar 0 = Landlock berfungsi penuh di kontainer bergaya bench.
set -uo pipefail
cd "$(dirname "$0")/.."

# Sama dengan image runner/worker/web (lihat services/*/Dockerfile), jadi biasanya sudah ada di host.
IMAGE="${PROBE_IMAGE:-python:3.12-slim-trixie}"
DOCKER="${DOCKER:-docker}"

echo "== Host =="
echo "kernel : $(uname -rm)"
echo "docker : $($DOCKER --version 2>&1)"
echo "LSM    : $(cat /sys/kernel/security/lsm 2>/dev/null || echo 'tidak terbaca')"
echo
echo "== Di dalam kontainer bergaya bench (image: $IMAGE) =="
$DOCKER run --rm \
  --network none \
  --read-only \
  --user 10001:10001 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 64 \
  --memory 128m \
  --tmpfs /tmp:rw,size=16m,nosuid \
  -v "$PWD/scripts/bench-probe.py:/probe.py:ro" \
  "$IMAGE" python3 /probe.py
rc=$?
echo
if [ "$rc" -eq 0 ]; then
  echo "HASIL: Landlock berfungsi di kontainer bergaya bench -> opsi 2 dipakai."
else
  echo "HASIL: Landlock TIDAK berfungsi penuh (kode $rc). Salin seluruh keluaran di atas ke percakapan."
fi
exit "$rc"
