#!/usr/bin/env bash
# Acutis PostToolUse hook wrapper. Uses system python3 (stdlib only — no venv needed).
set -euo pipefail
exec python3 "$(dirname "$0")/post-tool-use.py" "$@"
