#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
name="warden-task1-pg-$(id -u)-$$-$RANDOM"
password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
cleanup() { docker rm -f -v "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
# Dedicated disposable cluster. Never attach to an existing workload or volume.
docker run -d --name "$name" --label warden.test=task1 \
  --memory 512m --memory-swap 512m --pids-limit 128 --cpus 2 \
  -p 127.0.0.1::5432 -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB=warden_test \
  postgres:18-alpine >/dev/null
for attempt in $(seq 1 60); do
  if docker exec "$name" pg_isready -h 127.0.0.1 -U postgres -d warden_test >/dev/null 2>&1; then break; fi
  if [[ "$attempt" == 60 ]]; then echo 'Postgres failed to start' >&2; exit 1; fi
  sleep 0.25
done
port=$(docker port "$name" 5432/tcp | awk -F: '{print $NF}')
export WARDEN_TEST_DATABASE_URL="postgres://postgres:$password@127.0.0.1:$port/warden_test?sslmode=disable"
if [[ $# == 0 ]]; then set -- test ./controlplane/... -count=1; fi
"$root/scripts/go.sh" "$@"
