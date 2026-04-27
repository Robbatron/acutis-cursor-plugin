#!/usr/bin/env bash
# Wrapper script for the Acutis SessionStart hook.
# Mirrors stop-hook.sh: uses venv Python if local, system python3 otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Try to resolve the acutis source directory (local/dev mode)
REPO_ROOT=""
if [ -d "$PLUGIN_ROOT/../../src/acutis" ]; then
    REPO_ROOT="$(cd "$PLUGIN_ROOT/../.." && pwd)"
elif [ -d "$PLUGIN_ROOT/src/acutis" ]; then
    REPO_ROOT="$PLUGIN_ROOT"
fi

# Use venv Python if available (local mode), otherwise system python3
PYTHON="python3"
if [ -n "$REPO_ROOT" ]; then
    for venv_dir in "$REPO_ROOT/venv" "$REPO_ROOT/.venv"; do
        if [ -f "$venv_dir/bin/python3" ]; then
            PYTHON="$venv_dir/bin/python3"
            break
        fi
    done
fi

exec "$PYTHON" "$SCRIPT_DIR/session-start.py" "$@"
