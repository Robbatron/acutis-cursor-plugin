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

# Register Acutis MCP server in global config so agents can call scan_code.
# Plugin MCP servers appear in Settings but are not always exposed to Agent tools.
MCP_CONFIG="${MCP_CONFIG:-$HOME/.cursor/mcp.json}"
ACUTIS_MCP_URL="${ACUTIS_MCP_URL:-https://mcp.acutis.dev/mcp}"

if [[ -f "$MCP_CONFIG" ]]; then
  if MCP_CONFIG="$MCP_CONFIG" ACUTIS_MCP_URL="$ACUTIS_MCP_URL" python3 -c "
import json, os, sys

path = os.environ['MCP_CONFIG']
url = os.environ['ACUTIS_MCP_URL']

try:
    with open(path) as f:
        cfg = json.load(f)
except json.JSONDecodeError as e:
    print(f'Invalid JSON in {path}: {e}', file=sys.stderr)
    sys.exit(1)

ms = cfg.setdefault('mcpServers', {})
if 'acutis' in ms:
    existing = ms.get('acutis', {})
    if isinstance(existing, dict) and existing.get('url') == url:
        print(f'Acutis MCP already registered in {path} — skipping.', file=sys.stderr)
    else:
        print(
            f'Note: {path} already has an \"acutis\" entry; left unchanged. Edit manually if needed.',
            file=sys.stderr,
        )
    sys.exit(0)

ms['acutis'] = {'url': url}
with open(path, 'w') as f:
    json.dump(cfg, f, indent=2)
    f.write('\n')
print(f'Registered Acutis MCP server in {path}')
sys.exit(0)
"; then
    :
  else
    echo "Warning: Could not update $MCP_CONFIG. Add manually:" >&2
    echo "  {\"mcpServers\":{\"acutis\":{\"url\":\"$ACUTIS_MCP_URL\"}}}" >&2
  fi
else
  mkdir -p "$(dirname "$MCP_CONFIG")"
  cat > "$MCP_CONFIG" <<MCPEOF
{
  "mcpServers": {
    "acutis": {
      "url": "${ACUTIS_MCP_URL}"
    }
  }
}
MCPEOF
  echo "Created $MCP_CONFIG with Acutis MCP server"
fi

cat <<'EOF'
Acutis Cursor plugin installed.

Next steps:
  1. Run "Developer: Reload Window" in Cursor.
  2. Open Cursor Settings → MCP and sign in to Acutis (OAuth) if prompted.
  3. Open Cursor Settings → Hooks and confirm Acutis hooks are listed.
  4. Open an Agent chat in your project — the agent can call scan_code once MCP is connected.
EOF
