#!/usr/bin/env bash
# Acutis AfterFileEdit hook wrapper. Uses system python3 (stdlib only — no venv needed).
set -euo pipefail
exec python3 "$(dirname "$0")/after-file-edit.py" "$@"
