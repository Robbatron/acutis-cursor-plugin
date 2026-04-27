#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${ACUTIS_CURSOR_REPO_URL:-https://github.com/Robbatron/acutis-cursor-plugin.git}"
PLUGIN_DIR="$HOME/.cursor/plugins/local/acutis"

mkdir -p "$(dirname "$PLUGIN_DIR")"

if [[ -d "$PLUGIN_DIR/.git" ]]; then
  git -C "$PLUGIN_DIR" pull --ff-only
elif [[ -e "$PLUGIN_DIR" ]]; then
  echo "Existing Acutis install is not a git checkout. Replacing it." >&2
  rm -rf "$PLUGIN_DIR"
  git clone --depth 1 "$REPO_URL" "$PLUGIN_DIR"
else
  git clone --depth 1 "$REPO_URL" "$PLUGIN_DIR"
fi

chmod +x "$PLUGIN_DIR"/scripts/*.sh

cat <<'EOF'
Acutis Cursor plugin installed.

Next steps:
  1. Run "Developer: Reload Window" in Cursor.
  2. Open Cursor Settings → Hooks and confirm Acutis hooks are listed.
  3. Open a new Agent chat and generate code — Acutis will remind and gate.
EOF
