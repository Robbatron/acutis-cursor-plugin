#!/usr/bin/env bash
# Acutis shell gate wrapper (Cursor beforeShellExecution). Uses system python3 (stdlib only).
# Fail closed: if python3 is missing or the script cannot start, exit 2 (Cursor treats exit 2 as deny).
set -uo pipefail
# Housekeeping: drop filesystem snapshots orphaned by a crashed or denied
# command. Literal glob, no interpolation, failures ignored.
find /tmp -maxdepth 1 -name 'acutis-fs-snapshot-cursor-*.json' -mmin +1440 -delete 2>/dev/null || true
python3 "$(dirname "$0")/before-shell.py" "$@"
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "acutis shell gate: hook exited $rc; denying (fail closed)" >&2
  exit 2
fi
exit 0
