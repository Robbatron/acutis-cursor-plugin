#!/usr/bin/env python3
"""
Acutis Scan-ALLOW Tracker (Cursor) — clears the pending list in this
conversation's state file when scan_code returns an ALLOW verdict.

Fires on every `postToolUse` event. Only acts when the tool name contains
"scan_code" and the result contains "ALLOW". Pairs with after-file-edit.py
(which records writes) and stop-hook.py (which reads `pending` under Cursor).

This is a no-op under Claude Code / VS Code: those environments enforce via the
transcript in stop-hook.py and never populate the state file, so clearing it
does nothing harmful.
"""

import json
import re
import sys

SCAN_TOOL_KEYWORD = "scan_code"

# Keep in sync with after-file-edit.py / stop-hook.py: conversation-scoped state
# file with a charset-validated id and a fixed-path fallback (over-block-safe).
_CONVERSATION_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")

_BLOCK_MARKERS = ("BLOCK_VIOLATION", "BLOCK_INCOMPLETE")
_DECISION_ALLOW_RE = re.compile(r'"decision"\s*:\s*"ALLOW"')


def state_file_for(hook_input: dict) -> str:
    cid = str(hook_input.get("conversation_id", "") or "")
    if not _CONVERSATION_ID_RE.fullmatch(cid):
        return "/tmp/acutis-unverified.json"
    return "/tmp/acutis-unverified-cursor-" + cid + ".json"


def _text_is_allow(text: str) -> bool:
    """True only for a genuine ALLOW verdict body.

    scan_code's text result is the ScanResponse JSON, so a real verdict carries
    "decision": "ALLOW". BLOCK bodies can contain the bare word ALLOW in
    remediation prose ("iterate until ALLOW"), so a plain substring test fails
    open. Any BLOCK terminal state in the body wins over an ALLOW match.
    """
    if any(marker in text for marker in _BLOCK_MARKERS):
        return False
    if _DECISION_ALLOW_RE.search(text):
        return True
    # Fallback for client shapes that surface only the rendered verdict text.
    return re.search(r"\bALLOW\b", text) is not None


def result_contains_allow(hook_input: dict) -> bool:
    """Return True only if the scan_code result carries a real ALLOW verdict."""
    # Cursor postToolUse provides tool_output; also check common aliases.
    for key in ("tool_output", "tool_result", "result", "output"):
        val = hook_input.get(key, "")
        if isinstance(val, str) and _text_is_allow(val):
            return True
        if isinstance(val, dict):
            decision = str(val.get("decision", val.get("verdict", ""))).strip()
            if decision == "ALLOW":
                return True
            content = val.get("content", [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and _text_is_allow(str(item.get("text", ""))):
                        return True
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict) and _text_is_allow(str(item.get("text", ""))):
                    return True
    return False


def clear_pending(hook_input: dict) -> None:
    """Clear the pending list, keeping the 'all' history for the session."""
    state_file = state_file_for(hook_input)
    try:
        with open(state_file) as f:
            state = json.load(f)
        if not isinstance(state, dict):
            state = {"pending": [], "all": []}
    except (FileNotFoundError, json.JSONDecodeError, IOError):
        state = {"pending": [], "all": []}

    state["pending"] = []
    state.setdefault("all", [])

    try:
        with open(state_file, "w") as f:
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
        clear_pending(hook_input)

    json.dump({}, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
