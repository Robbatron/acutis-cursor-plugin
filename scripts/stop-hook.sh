#!/usr/bin/env bash
# Acutis Stop hook wrapper (Cursor). Uses system python3 (stdlib only).
set -euo pipefail
exec python3 "$(dirname "$0")/stop-hook.py" "$@"
