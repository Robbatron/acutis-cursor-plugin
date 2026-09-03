#!/usr/bin/env bash
# Acutis verification-ALLOW tracker + ALLOW-ledger recorder wrapper (postToolUse + afterMCPExecution). Uses system python3 (stdlib only).
set -euo pipefail
exec python3 "$(dirname "$0")/verification-allow-tracker.py" "$@"
