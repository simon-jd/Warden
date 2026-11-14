#!/usr/bin/env bash
# Never execute before the dedicated lab's security review is accepted.
set -euo pipefail
# -B prevents privileged Python imports from writing through a __pycache__ alias.
exec python3 -B "$(dirname -- "${BASH_SOURCE[0]}")/runtime_lab_runner.py" "$@"
