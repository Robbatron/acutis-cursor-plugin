#!/usr/bin/env python3
"""
Acutis Verification-ALLOW Tracker (Cursor): records every verify_code ALLOW.

Two jobs, both keyed on a genuine ALLOW verdict from the verify_code MCP tool:

1. Clears the pending list in this conversation's state file (backstop for the
   stop hook; pairs with after-file-edit.py which records writes).
2. Appends the normalized `code` argument of the ALLOWed call to the ALLOW
   ledger (/tmp/acutis-allow-cursor-<conversation_id>.json, shape
   {"allowed": [...]}, 200 most recent, atomic write). pre-tool-use.py (the
   pre-write gate) denies any Write whose text is not contained in a ledger
   entry. Cursor transcripts exclude tool outputs and transcript_path can be
   null, so the ledger is the only durable record of what was verified.

Registered on both MCP-result events so the ledger is written whichever one
Cursor delivers for the tool: `postToolUse` (generic; MCP tools included;
`tool_input` object, `tool_output` string) and `afterMCPExecution`
(`tool_input` JSON params string, `result_json` string). Both fire for one
call; recording is idempotent (dedup on content).

This is a no-op under Claude Code / VS Code: those environments enforce via the
transcript in stop-hook.py and never populate the state file.
"""

import json
import os
import re
import sys

VERIFY_TOOL_KEYWORD = "verify_code"

# Keep in sync with after-file-edit.py / stop-hook.py: conversation-scoped state
# file with a charset-validated id and a fixed-path fallback (over-block-safe).
_CONVERSATION_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")

_BLOCK_MARKERS = ("BLOCK_VIOLATION", "BLOCK_INCOMPLETE")
# Cursor hands an MCP result over as a JSON string of the MCP response, so the
# VerificationResponse text inside it is JSON-escaped (\"decision\": \"ALLOW\").
# The optional backslashes accept both the raw and the escaped form.
_DECISION_ALLOW_RE = re.compile(r'\\?"decision\\?"\s*:\s*\\?"ALLOW\\?"')

# Keys under which Cursor surfaces the tool result: result_json
# (afterMCPExecution), tool_output (postToolUse), plus common aliases.
_RESULT_KEYS = ("result_json", "tool_output", "tool_result", "result", "output")

# ALLOW ledger consumed by pre-tool-use.py. Keep the charset, prefix, cap and
# fallback literal in sync with that script.
_LEDGER_ID_RE = re.compile(r"[A-Za-z0-9_-]+")
LEDGER_PREFIX = "/tmp/acutis-allow-cursor-"
LEDGER_CAP = 200

# On-disk correlation only ever opens absolute source files with a
# security-relevant extension (the only paths after-file-edit.py records).
_SOURCE_EXTENSIONS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")


def state_file_for(hook_input: dict) -> str:
    cid = str(hook_input.get("conversation_id", "") or "")
    if not _CONVERSATION_ID_RE.fullmatch(cid):
        return "/tmp/acutis-unverified.json"
    return "/tmp/acutis-unverified-cursor-" + cid + ".json"


def validated_conversation_id(cid: str) -> str:
    """Guard-and-reject: only a charset-clean id may become part of a path."""
    if not _LEDGER_ID_RE.fullmatch(cid):
        return ""
    return cid


def ledger_path_for(hook_input: dict) -> str:
    cid = validated_conversation_id(str(hook_input.get("conversation_id") or ""))
    if not cid:
        return "/tmp/acutis-allow-cursor.json"
    return LEDGER_PREFIX + cid + ".json"


def validated_source_path(file_path: str) -> str:
    """Guard-and-reject: an absolute path with a security-relevant extension,
    else the empty string (nothing is opened)."""
    if not file_path.startswith("/"):
        return ""
    if not file_path.lower().endswith(_SOURCE_EXTENSIONS):
        return ""
    return file_path


def _text_is_allow(text: str, strict: bool = False) -> bool:
    """True only for a genuine ALLOW verdict body.

    verify_code's text result is the VerificationResponse JSON, so a real verdict
    carries "decision": "ALLOW". BLOCK bodies can contain the bare word ALLOW
    in remediation prose ("iterate until ALLOW"), so a plain substring test
    fails open. Any BLOCK terminal state in the body wins over an ALLOW match.
    `strict` (ledger recording) accepts only the decision-key form.
    """
    if any(marker in text for marker in _BLOCK_MARKERS):
        return False
    if _DECISION_ALLOW_RE.search(text):
        return True
    if strict:
        return False
    # Fallback for client shapes that surface only the rendered verdict text.
    return re.search(r"\bALLOW\b", text) is not None


def result_contains_allow(hook_input: dict, strict: bool = False) -> bool:
    """Return True only if the verify_code result carries a real ALLOW verdict."""
    for key in _RESULT_KEYS:
        val = hook_input.get(key, "")
        if isinstance(val, str) and _text_is_allow(val, strict):
            return True
        if isinstance(val, dict):
            decision = str(val.get("decision", val.get("verdict", ""))).strip()
            if decision == "ALLOW":
                return True
            content = val.get("content", [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and _text_is_allow(str(item.get("text", "")), strict):
                        return True
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict) and _text_is_allow(str(item.get("text", "")), strict):
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
    """Correlate the ALLOWed verification payload against the file's on-disk content
    (normalized containment either way). An unreadable/deleted file clears:
    there is nothing left to verify and keeping it pending would deadlock."""
    path = validated_source_path(file_path)
    if not path:
        return True
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            content = _normalize(f.read())
    except OSError:
        return True
    return bool(code) and (code in content or content in code)


def clear_pending(hook_input: dict) -> None:
    """Clear pending entries the ALLOW actually verified.

    Per-file evidence correlation (2026-08-05 field reports): the former
    unconditional clear let one ALLOW on an unrelated (even fabricated)
    snippet discharge EVERY pending file. Now a pending file clears only when
    the verified code payload overlaps its on-disk content. When the payload is
    not visible in the hook input, fall back to the legacy full clear rather
    than deadlocking (that shape is client-controlled, not agent-controlled).
    The payload is also remembered so a verification-then-write sequence never marks
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
            fp for fp in state["pending"] if not _file_matches_code(str(fp), code)
        ]
    else:
        state["pending"] = []

    try:
        with open(state_file, "w") as f:
            json.dump(state, f)
    except IOError:
        pass


def record_allow(hook_input: dict, code: str) -> None:
    """Append one normalized ALLOWed payload to the ledger (dedup, cap, atomic)."""
    ledger_path = ledger_path_for(hook_input)
    try:
        with open(ledger_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    allowed = data.get("allowed", []) if isinstance(data, dict) else []
    if not isinstance(allowed, list):
        allowed = []
    allowed = [a for a in allowed if isinstance(a, str) and a and a != code]
    allowed.append(code)
    allowed = allowed[-LEDGER_CAP:]
    tmp_path = ledger_path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump({"allowed": allowed}, f)
        os.replace(tmp_path, ledger_path)
    except OSError:
        pass


def main() -> None:
    try:
        hook_input = json.loads(sys.stdin.read() or "{}")
    except (json.JSONDecodeError, IOError):
        hook_input = {}
    if not isinstance(hook_input, dict):
        hook_input = {}

    tool_name = str(hook_input.get("tool_name", ""))
    if VERIFY_TOOL_KEYWORD not in tool_name:
        json.dump({}, sys.stdout)
        sys.stdout.write("\n")
        sys.exit(0)

    if result_contains_allow(hook_input):
        clear_pending(hook_input)
    if result_contains_allow(hook_input, strict=True):
        code = _extract_scanned_code(hook_input)
        if code:
            record_allow(hook_input, code)

    json.dump({}, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
