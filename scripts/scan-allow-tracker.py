#!/usr/bin/env python3
"""
Acutis Scan-ALLOW Tracker (Cursor) — clears the pending list in the shared
state file when scan_code returns an ALLOW verdict.

Fires on every `postToolUse` event. Only acts when the tool name contains
"scan_code" and the result contains "ALLOW". Pairs with after-file-edit.py
(which records writes) and stop-hook.py (which reads `pending` under Cursor).

This is a no-op under Claude Code / VS Code: those environments enforce via the
transcript in stop-hook.py and never populate the state file, so clearing it
does nothing harmful.
"""

import json
import sys

SCAN_TOOL_KEYWORD = "scan_code"
STATE_FILE = "/tmp/acutis-unverified.json"


def result_contains_allow(hook_input: dict) -> bool:
    """Return True if the scan_code result in the hook input contains ALLOW."""
    # Cursor postToolUse provides tool_output; also check common aliases.
    for key in ("tool_output", "tool_result", "result", "output"):
        val = hook_input.get(key, "")
        if isinstance(val, str) and "ALLOW" in val:
            return True
        if isinstance(val, dict):
            decision = val.get("decision", val.get("verdict", ""))
            if "ALLOW" in str(decision):
                return True
            content = val.get("content", [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and "ALLOW" in str(item.get("text", "")):
                        return True
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict) and "ALLOW" in str(item.get("text", "")):
                    return True
    return False


def clear_pending() -> None:
    """Clear the pending list, keeping the 'all' history for the session."""
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
        if not isinstance(state, dict):
            state = {"pending": [], "all": []}
    except (FileNotFoundError, json.JSONDecodeError, IOError):
        state = {"pending": [], "all": []}

    state["pending"] = []
    state.setdefault("all", [])

    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except IOError:
        pass


def main() -> None:
    try:
        hook_input = json.loads(sys.stdin.read() or "{}")
    except (json.JSONDecodeError, IOError):
        hook_input = {}

    tool_name = str(hook_input.get("tool_name", ""))
    if SCAN_TOOL_KEYWORD not in tool_name:
        json.dump({}, sys.stdout)
        sys.stdout.write("\n")
        sys.exit(0)

    if result_contains_allow(hook_input):
        clear_pending()

    json.dump({}, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
