#!/usr/bin/env bash
# Acutis SessionStart hook wrapper (Cursor). Uses system python3 (stdlib only).
set -euo pipefail
exec python3 "$(dirname "$0")/session-start.py" "$@"
