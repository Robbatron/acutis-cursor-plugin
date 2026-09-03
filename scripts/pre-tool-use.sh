#!/usr/bin/env bash
# Acutis pre-write gate wrapper (Cursor preToolUse, matcher "Write"). Uses system python3 (stdlib only).
# Fail closed: if python3 is missing or the script cannot start, exit 2 (Cursor treats exit 2 as deny).
set -uo pipefail
python3 "$(dirname "$0")/pre-tool-use.py" "$@"
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "acutis pre-write gate: hook exited $rc; denying (fail closed)" >&2
  exit 2
fi
exit 0
