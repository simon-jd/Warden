#!/usr/bin/env bash
# Runs inside the dedicated runc lab container only (see docs/runtime-lab.md).
set -euo pipefail
# -B prevents privileged Python imports from writing through a __pycache__ alias.
exec python3 -B "$(dirname -- "${BASH_SOURCE[0]}")/runtime_lab_runner.py" "$@"
