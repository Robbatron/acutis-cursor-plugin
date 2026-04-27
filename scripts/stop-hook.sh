#!/usr/bin/env bash
# Wrapper script for the Acutis Stop hook.
#
# Works in two modes:
#   LOCAL  — acutis source is available (dev via --plugin-dir). Sets PYTHONPATH
#            and uses the venv Python so scan_code runs directly.
#   REMOTE — acutis source is NOT available (marketplace install). Uses bare
#            python3 (stdlib only). stop-hook.py gracefully handles ImportError
#            and blocks the agent, telling Claude to call the remote scan_code.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Try to resolve the acutis source directory (local/dev mode)
ACUTIS_SRC=""
REPO_ROOT=""
if [ -d "$PLUGIN_ROOT/../../src/acutis" ]; then
    ACUTIS_SRC="$PLUGIN_ROOT/../../src"
    REPO_ROOT="$(cd "$PLUGIN_ROOT/../.." && pwd)"
elif [ -d "$PLUGIN_ROOT/src/acutis" ]; then
    ACUTIS_SRC="$PLUGIN_ROOT/src"
    REPO_ROOT="$PLUGIN_ROOT"
fi

# Set PYTHONPATH only if local source is available
if [ -n "$ACUTIS_SRC" ]; then
    export PYTHONPATH="${ACUTIS_SRC}${PYTHONPATH:+:$PYTHONPATH}"
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

exec "$PYTHON" "$SCRIPT_DIR/stop-hook.py" "$@"
