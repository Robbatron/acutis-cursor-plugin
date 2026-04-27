# Acutis — Cursor Plugin

Formal verification for AI-generated code. Catches 10 of the CWE Top 25 with mathematical proof.

This is the **Cursor-specific** plugin for Acutis. For Claude Code, see [acutis-plugin](https://github.com/Robbatron/acutis-plugin).

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Robbatron/acutis-cursor-plugin/main/scripts/install.sh | bash
```

Then run **Developer: Reload Window** in Cursor.

Or install manually:

```bash
git clone --depth 1 https://github.com/Robbatron/acutis-cursor-plugin.git \
  ~/.cursor/plugins/local/acutis
chmod +x ~/.cursor/plugins/local/acutis/scripts/*.sh
```

## Post-Install: Authenticate

Acutis uses a remote MCP server with OAuth. After installing:

1. Open **Cursor Settings → Tools**.
2. Under **Plugin MCP Servers**, find **acutis** and click **Login**.
3. Approve access in the browser window that opens.
4. Confirm the green dot appears next to the acutis server.

## What You Get

| Component | What it does |
| --- | --- |
| **MCP Server** (`mcp.acutis.dev`) | `scan_code` tool — takes code, language, and a PCST contract → returns ALLOW or BLOCK with proof artifacts. |
| **Hooks** | `sessionStart` primes the agent. `postToolUse` reminds after security-relevant edits. `stop` blocks completion until code is verified. |
| **Skill** (`scan`) | Teaches the agent how to build PCST contracts, reason through witness paths, and iterate on BLOCK results. |
| **Rule** (`acutis-security`) | Always-on rule that enforces scan-before-finish for security-relevant files. |

All components are auto-discovered by Cursor from the plugin directory. No manual `hooks.json` or `mcp.json` editing required.

## Update

```bash
cd ~/.cursor/plugins/local/acutis && git pull --ff-only
```

Then reload Cursor.

## Uninstall

```bash
rm -rf ~/.cursor/plugins/local/acutis
```

Then reload Cursor.

## Troubleshooting

**MCP returns 403/401:** Go to Cursor Settings → Tools, click **Logout** on the acutis server, then **Login** again to refresh your OAuth token.

**Hooks show "Config version must be a number":** Ensure `hooks/hooks.json` has `"version": 1` at the top level. Pull the latest version.

**Rules don't appear in Settings panel:** This is expected — plugin rules with `alwaysApply: true` are injected into agent context automatically without appearing in the Rules UI.

## License

MIT
