#!/usr/bin/env bash
set -euo pipefail
exec python3 -B "$(dirname -- "${BASH_SOURCE[0]}")/azure_guard.py" reap "$@"
