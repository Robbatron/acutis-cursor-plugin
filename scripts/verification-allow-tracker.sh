#!/usr/bin/env bash
# Acutis verification-ALLOW tracker hook wrapper. Uses system python3 (stdlib only — no venv needed).
set -euo pipefail
exec python3 "$(dirname "$0")/verification-allow-tracker.py" "$@"
