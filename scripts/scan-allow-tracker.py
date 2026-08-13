#!/usr/bin/env python3
"""
Acutis Scan-ALLOW Tracker (Cursor) — clears the pending list in this
conversation's state file when verify_code returns an ALLOW verdict.

Fires on every `postToolUse` event. Only acts when the tool name contains
"verify_code" and the result contains "ALLOW". Pairs with after-file-edit.py
(which records writes) and stop-hook.py (which reads `pending` under Cursor).

This is a no-op under Claude Code / VS Code: those environments enforce via the
transcript in stop-hook.py and never populate the state file, so clearing it
does nothing harmful.
"""

import json
import re
import sys

SCAN_TOOL_KEYWORD = "verify_code"

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

    verify_code's text result is the ScanResponse JSON, so a real verdict carries
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
    """Return True only if the verify_code result carries a real ALLOW verdict."""
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


def _normalize(text) -> str:
    if not text:
        return ""
    if isinstance(text, list):
        text = "\n".join(str(t) for t in text)
    return "".join(str(text).split())


def _extract_scanned_code(hook_input: dict) -> str:
    tool_input = hook_input.get("tool_input", {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except (json.JSONDecodeError, TypeError):
            tool_input = {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    return _normalize(tool_input.get("code"))


def _file_matches_code(file_path: str, code: str) -> bool:
    """Correlate the ALLOWed scan payload against the file's on-disk content
    (normalized containment either way). An unreadable/deleted file clears:
    there is nothing left to verify and keeping it pending would deadlock."""
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            content = _normalize(f.read())
    except OSError:
        return True
    return bool(code) and (code in content or content in code)


def clear_pending(hook_input: dict) -> None:
    """Clear pending entries the ALLOW actually verified.

    Per-file evidence correlation (2026-08-05 field reports): the former
    unconditional clear let one ALLOW on an unrelated (even fabricated)
    snippet discharge EVERY pending file. Now a pending file clears only when
    the scanned code payload overlaps its on-disk content. When the payload is
    not visible in the hook input, fall back to the legacy full clear rather
    than deadlocking (that shape is client-controlled, not agent-controlled).
    The payload is also remembered so a scan-then-write sequence never marks
    the file pending in the first place (see after-file-edit.py).
    """
    state_file = state_file_for(hook_input)
    try:
        with open(state_file) as f:
            state = json.load(f)
        if not isinstance(state, dict):
            state = {"pending": [], "all": []}
    except (FileNotFoundError, json.JSONDecodeError, IOError):
        state = {"pending": [], "all": []}

    state.setdefault("pending", [])
    state.setdefault("all", [])
    state.setdefault("recent_allows", [])

    code = _extract_scanned_code(hook_input)
    if code:
        state["recent_allows"] = (state["recent_allows"] + [code])[-20:]
        state["pending"] = [
            fp for fp in state["pending"] if not _file_matches_code(fp, code)
        ]
    else:
        state["pending"] = []

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
