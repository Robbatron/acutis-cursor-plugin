# Acutis — Cursor Plugin

Formal verification for AI-generated code. Catches 10 of the CWE Top 25 with mathematical proof.

This is the **Cursor-specific** plugin for Acutis. For Claude Code, see [acutis-plugin](https://github.com/Robbatron/acutis-plugin).

## Install

Clone the plugin into Cursor's local plugin directory:

```bash
git clone https://github.com/Robbatron/acutis-cursor-plugin.git \
  ~/.cursor/plugins/local/acutis
```

Then run **Developer: Reload Window** in Cursor. Cursor auto-discovers the MCP
server, hooks, skill, and rule from the plugin directory — no install script and
no manual `mcp.json`/`hooks.json` editing.

## Post-Install: Authenticate

Acutis uses a remote MCP server with OAuth. After installing:

1. Open **Cursor Settings → Tools**.
2. Under **Plugin MCP Servers**, find **acutis** and click **Connect** / **Login**.
3. Approve access in the browser window that opens.
4. Confirm the green dot appears next to the acutis server.

## What You Get

| Component | What it does |
| --- | --- |
| **MCP Server** (`mcp.acutis.dev`) | `scan_code` tool — takes code, language, and a PCST contract → returns ALLOW or BLOCK with proof artifacts. |
| **Hooks** | `sessionStart` primes the agent. `afterFileEdit` records security-relevant writes. `postToolUse` reminds after writes and clears verified state on `scan_code` ALLOW. `stop` re-prompts until written code is verified. |
| **Skill** (`scan`) | Teaches the agent how to build PCST contracts, reason through witness paths, and iterate on BLOCK results. |
| **Rule** (`acutis-security`) | Always-on rule that enforces scan-before-finish for security-relevant files. |

### How enforcement works in Cursor

Cursor's `stop` hook cannot hard-block; it emits a `followup_message` that
auto-submits a new turn (bounded by `loop_limit`). Acutis tracks unverified
writes in a state file (`/tmp/acutis-unverified.json`): `afterFileEdit` records
each security-relevant write, `scan-allow-tracker` clears it when `scan_code`
returns ALLOW, and `stop` re-prompts while anything remains unverified. This is
robust to Cursor transcripts being disabled.

## Update

```bash
git -C ~/.cursor/plugins/local/acutis pull --ff-only
```

Then reload Cursor.

## Uninstall

```bash
rm -rf ~/.cursor/plugins/local/acutis
```

Then reload Cursor.

## Troubleshooting

**MCP returns 403/401:** Go to Cursor Settings → Tools, click **Logout** on the acutis server, then **Connect** / **Login** again to refresh your OAuth token.

**Hooks show "Config version must be a number":** Ensure `hooks/hooks.json` has `"version": 1` at the top level. Pull the latest version.

**Rules don't appear in Settings panel:** This is expected — plugin rules with `alwaysApply: true` are injected into agent context automatically without appearing in the Rules UI.

## License

MIT
