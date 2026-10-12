#!/usr/bin/env bash
# Membandingkan isi .env dengan environment yang SEBENARNYA dipakai container (web, worker, runner, caddy).
# Menjawab: "saya sudah set di .env, kenapa tidak termuat?"
#   - nilai di .env beda dengan di container  -> container belum dibuat ulang (jalankan `make up` atau `make restart`)
#   - variabel ada di .env tetapi tidak diteruskan docker-compose.yml -> DIABAIKAN (tidak berefek apa pun)
# Pemakaian: scripts/envcheck.sh [KEY ...]   (tanpa argumen: semua variabel di .env)
set -uo pipefail
cd "$(dirname "$0")/.."
COMPOSE="${COMPOSE:-docker compose}"
ENVFILE="${ENVFILE:-.env}"
COMPOSE_FILE_PATH="${COMPOSE_FILE_PATH:-docker-compose.yml}"
[ -f "$ENVFILE" ] || { echo "✗ $ENVFILE tidak ada (jalankan make init)"; exit 1; }

# Nilai seperti yang dibaca Compose: potong komentar " #...", buang tanda kutip pembungkus, trim spasi.
parse_value() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"
  if [[ "$v" =~ ^\"(.*)\"[[:space:]]*(#.*)?$ ]]; then v="${BASH_REMATCH[1]}"
  elif [[ "$v" =~ ^\'(.*)\'[[:space:]]*(#.*)?$ ]]; then v="${BASH_REMATCH[1]}"
  else v="${v%%[[:space:]]#*}"; v="${v%"${v##*[![:space:]]}"}"; fi
  printf '%s' "$v"
}

# Variabel yang diteruskan compose ke container mana pun: yang muncul sebagai ${NAMA...} atau "NAMA:" di bagian environment.
forwarded=" $(grep -oE '\$\{[A-Z][A-Z0-9_]*' "$COMPOSE_FILE_PATH" | tr -d '${' | sort -u | tr '\n' ' ') "

SERVICES="${SERVICES:-web worker runner bench egress caddy}"
SECRETISH='^(SECRET_KEY|REDIS_PASSWORD|AI_API_KEY)$'
bad=0; ok=0; ignored=0
declare -a keys=()
if [ "$#" -gt 0 ]; then keys=("$@"); else
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*([A-Z][A-Z0-9_]*)[[:space:]]*= ]] && keys+=("${BASH_REMATCH[1]}")
  done < "$ENVFILE"
fi

for k in "${keys[@]}"; do
  raw="$(grep -E "^[[:space:]]*$k[[:space:]]*=" "$ENVFILE" | tail -n1 | sed -E "s/^[[:space:]]*$k[[:space:]]*=//")"
  [ -n "$raw" ] || { echo "·  $k: tidak diisi di $ENVFILE (memakai bawaan)"; continue; }
  want="$(parse_value "$raw")"
  if [ -z "$want" ]; then echo "·  $k: kosong di $ENVFILE (memakai bawaan)"; continue; fi
  if [[ "$forwarded" != *" $k "* ]]; then
    echo "✗  $k: ada di $ENVFILE tetapi TIDAK diteruskan oleh docker-compose.yml, jadi tidak berefek."; ignored=$((ignored+1)); continue
  fi
  show_w="$want"; [[ "$k" =~ $SECRETISH ]] && show_w="(rahasia, ${#want} karakter)"
  found=""; mismatch=""
  for svc in $SERVICES; do
    have="$($COMPOSE exec -T "$svc" printenv "$k" 2>/dev/null | tr -d '\r')"
    [ -n "$have" ] || continue
    if [ "$have" = "$want" ]; then found="$found $svc"
    else
      sh_h="$have"; [[ "$k" =~ $SECRETISH ]] && sh_h="(rahasia, ${#have} karakter)"
      mismatch="$mismatch $svc[$sh_h]"
    fi
  done
  if [ -n "$mismatch" ]; then
    echo "✗  $k: .env=$show_w tetapi container memakai${mismatch}  -> container belum dibuat ulang: jalankan make up"; bad=$((bad+1))
  elif [ -n "$found" ]; then echo "✓  $k = $show_w  (dipakai:${found})"; ok=$((ok+1))
  else
    echo "✗  $k: diteruskan oleh docker-compose.yml tetapi tidak ditemukan di container mana pun (belum dibuat ulang atau container mati)  -> make up"; bad=$((bad+1))
  fi
done
echo
echo "Ringkasan: $ok cocok, $bad belum diterapkan ke container, $ignored diabaikan compose."
[ "$bad" -eq 0 ] && [ "$ignored" -eq 0 ]
