#!/usr/bin/env python3
"""
Acutis Stop hook (Cursor) — re-prompts the agent if it wrote security-relevant
code that has not been verified via scan_code.

Cursor's `stop` hook cannot hard-block; it can only emit `followup_message`,
which auto-submits a new turn (bounded by `loop_limit` in hooks.json). This hook
uses that to ask the agent to verify, looping until the work is scanned.

Verification state comes from /tmp/acutis-unverified.json, maintained by
after-file-edit.py (records writes) and scan-allow-tracker.py (clears on ALLOW).
The state file is used instead of the conversation transcript because Cursor's
transcript_path can be null (transcripts disabled) and its format is
undocumented — relying on it would let enforcement silently fail open.

If the remote Acutis MCP server is unreachable, the hook fails open (allows the
stop with a warning) rather than deadlocking the agent, since it could not scan.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Shared state file written by after-file-edit.py / cleared by scan-allow-tracker.py.
STATE_FILE = "/tmp/acutis-unverified.json"

# Hosted Acutis MCP server health endpoint. Hardcoded (not env- or input-derived)
# so the health check carries no user-controlled URL — this hook has no SSRF flow.
MCP_HEALTH_URL = "https://mcp.acutis.dev/health"
MCP_HEALTH_TIMEOUT = 3  # seconds

# Stop re-prompting after this many loops as a backstop (hooks.json also caps via loop_limit).
MAX_LOOPS = 3


def read_hook_input() -> dict:
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, IOError):
        return {}


def read_state() -> tuple:
    """Return (pending, all) from the state file, or ([], []) if absent/unreadable."""
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
        if not isinstance(state, dict):
            return [], []
        return state.get("pending", []), state.get("all", [])
    except (FileNotFoundError, json.JSONDecodeError, IOError):
        return [], []


def check_mcp_health() -> bool:
    """True if the Acutis MCP server is reachable. Fails open (returns True on
    error is the caller's choice) — here we just report reachability."""
    try:
        req = urllib.request.Request(MCP_HEALTH_URL, method="GET")
        with urllib.request.urlopen(req, timeout=MCP_HEALTH_TIMEOUT):
            return True
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return False


def allow() -> None:
    json.dump({}, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(0)


def main() -> None:
    hook_input = read_hook_input()

    # Loop guard: stop re-prompting after a few rounds.
    if hook_input.get("loop_count", 0) >= MAX_LOOPS:
        allow()

    pending, all_files = read_state()
    if not all_files or not pending:
        # Nothing security-relevant written, or everything already verified.
        allow()

    # Don't deadlock the agent if it cannot reach the server to scan.
    if not check_mcp_health():
        print(
            "Warning: Acutis MCP server is unreachable. Skipping verification enforcement.",
            file=sys.stderr,
        )
        allow()

    names = ", ".join(Path(f).name for f in pending)
    message = (
        f"Security-relevant code was written but not yet verified. "
        f"Files needing verification: {names}. "
        f"Call the Acutis scan_code MCP tool (server name contains 'acutis') "
        f"with the code and a PCST contract. Fix any BLOCK results before completing."
    )
    json.dump({"followup_message": message}, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
