#!/usr/bin/env bash
# Observe only the container and anonymous volume created by this one harness run.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$root/.cache"
probe=$(mktemp -d "$root/.cache/warden-cleanup-probe.XXXXXX")
export WARDEN_CLEANUP_PROBE_DOCKER
WARDEN_CLEANUP_PROBE_DOCKER=$(command -v docker)
export WARDEN_CLEANUP_PROBE_DIR="$probe"
mkdir "$probe/bin"
cleanup() {
  if [[ -s "$probe/container" ]]; then
    "$WARDEN_CLEANUP_PROBE_DOCKER" rm -f -v "$(cat "$probe/container")" >/dev/null 2>&1 || true
  fi
  # On the RED path remove only this probe's proven orphan, never unknown volumes.
  if [[ -s "$probe/volumes" ]]; then
    while IFS= read -r volume; do
      [[ -z "$volume" ]] || "$WARDEN_CLEANUP_PROBE_DOCKER" volume rm "$volume" >/dev/null 2>&1 || true
    done < "$probe/volumes"
  fi
  rm -rf -- "$probe"
}
trap cleanup EXIT
cat > "$probe/bin/docker" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
capture=false
if [[ "${1:-}" == run ]]; then
  for arg in "$@"; do
    if [[ "$arg" == warden.test=task1 ]]; then capture=true; fi
  done
fi
if "$capture"; then
  container=$("$WARDEN_CLEANUP_PROBE_DOCKER" "$@")
  printf '%s\n' "$container" > "$WARDEN_CLEANUP_PROBE_DIR/container"
  "$WARDEN_CLEANUP_PROBE_DOCKER" inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name}}{{end}}{{end}}' "$container" > "$WARDEN_CLEANUP_PROBE_DIR/volumes"
  printf '%s\n' "$container"
else
  exec "$WARDEN_CLEANUP_PROBE_DOCKER" "$@"
fi
WRAPPER
chmod +x "$probe/bin/docker"
PATH="$probe/bin:$PATH" "$root/scripts/test-postgres.sh" version
[[ -s "$probe/container" && -s "$probe/volumes" ]] || { echo 'FAIL: no owned container/volume observed' >&2; exit 1; }
container=$(cat "$probe/container")
printf 'Observed harness container: %s\n' "$container"
if "$WARDEN_CLEANUP_PROBE_DOCKER" inspect "$container" >/dev/null 2>&1; then
  echo 'FAIL: harness container still exists' >&2
  exit 1
fi
failed=0
count=0
while IFS= read -r volume; do
  [[ -n "$volume" ]] || continue
  count=$((count+1))
  printf 'Observed container Mount.Name: %s\n' "$volume"
  if inspection=$("$WARDEN_CLEANUP_PROBE_DOCKER" volume inspect "$volume" 2>&1); then
    printf 'FAIL: captured volume remains after harness exit: %s\n' "$volume"
    failed=1
  elif [[ "$inspection" == *'no such volume'* ]]; then
    printf '%s\n' "$inspection"
    printf 'PASS: captured volume inspect reports absent: %s\n' "$volume"
  else
    printf 'FAIL: unexpected volume inspect error: %s\n' "$inspection"
    failed=1
  fi
done < "$probe/volumes"
[[ "$count" -gt 0 ]] || { echo 'FAIL: no anonymous volume observed' >&2; exit 1; }
exit "$failed"
