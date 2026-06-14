#!/usr/bin/env bash
# Acutis scan-ALLOW tracker hook wrapper. Uses system python3 (stdlib only — no venv needed).
set -euo pipefail
exec python3 "$(dirname "$0")/scan-allow-tracker.py" "$@"
