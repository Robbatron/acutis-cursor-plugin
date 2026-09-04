#!/usr/bin/env bash
# Acutis post-shell sweep wrapper (Cursor afterShellExecution). Uses system python3 (stdlib only).
# Observational hook: the command already ran, so a failure here never fails the turn.
set -uo pipefail
python3 "$(dirname "$0")/after-shell.py" "$@" || true
exit 0
