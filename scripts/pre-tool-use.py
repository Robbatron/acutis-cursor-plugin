#!/usr/bin/env python3
"""
Acutis pre-write gate (Cursor `preToolUse`, matcher "Write").

Decision (operator-approved 2026-09-03): nothing is written until an Acutis
verify_code ALLOW exists, and the written text must be exactly what Acutis
verified. This hook is a GATE, not a verifier: it never calls verify_code
itself (only the model can author the PCST contract). It checks that the model
already obtained an ALLOW whose `code` payload CONTAINS the text about to be
written, and denies the write otherwise with an `agent_message` the model acts
on (re-verify with the exact code, then re-issue the write byte-for-byte).

Match rule (one-directional): normalize both sides with `"".join(text.split())`;
the normalized written text must be a substring of a normalized ALLOWed
payload. A whole-file write with only one function verified is denied; a
fragment edit inside a verified function is allowed; empty written text on a
security-relevant path is denied.

ALLOW ledger: /tmp/acutis-allow-cursor-<conversation_id>.json, shape
{"allowed": ["<normalized code>", ...]}, written by
verification-allow-tracker.py on every verify_code ALLOW (Cursor transcripts
exclude tool outputs and transcript_path can be null, so the ledger is the only
durable record of what was verified).

Availability: only when nothing matches, GET https://mcp.acutis.dev/health
(3 s). If the server is unreachable the write is allowed with a stderr note,
the same fail-open policy as the stop hook. Never on the happy path.

Failure policy: Cursor documents `failClosed` only for beforeShellExecution,
beforeMCPExecution and beforeReadFile (not preToolUse), so this script is
fail-closed on its own: unparseable input or an internal error on a
security-relevant path denies (exit code 2 also denies per the hooks docs).
"""

import json
import re
import sys
import urllib.request
from pathlib import Path

# Keep in sync with after-file-edit.py / post-tool-use.py / stop-hook.py.
# HTML is deliberately ABSENT: VerificationRequest.language rejects it.
SECURITY_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".mjs", ".cjs",
}

SKIP_PATTERNS = {
    "node_modules", "__pycache__", ".git", "venv", ".venv",
    "package-lock.json", "yarn.lock", "poetry.lock",
}

# Claude Code scratchpad directories are session-local working files, never
# code that enters a codebase.
_SCRATCHPAD_RE = re.compile(r"^/(?:private/)?tmp/claude-[^/]*/(?:.*/)?scratchpad/")

# The conversation id becomes part of a filename: charset-validated first
# (guard-and-reject). Anything else falls back to the fixed literal path in
# ledger_path_for (keep that literal in sync with verification-allow-tracker.py).
_CONVERSATION_ID_RE = re.compile(r"[A-Za-z0-9_-]+")
LEDGER_PREFIX = "/tmp/acutis-allow-cursor-"

# Hosted Acutis MCP health endpoint. Hardcoded (not env- or input-derived) so
# the health check carries no user-controlled URL.
MCP_HEALTH_URL = "https://mcp.acutis.dev/health"
MCP_HEALTH_TIMEOUT = 3  # seconds

# Cursor's file-writing tool is named "Write" in preToolUse (docs + forum
# thread 165962). Anything else reaching this script means the matcher did not
# filter; pass it through rather than gate a Read.
WRITE_TOOL_NAME = "Write"

# Write tool_input keys. Cursor documents `file_path` + `content` for a whole
# file write (forum thread 165962); the search/replace shape is undocumented,
# so every plausible new-text carrier is inspected and an unrecognised shape
# on a security-relevant path is denied (and its keys logged so the shape can
# be learned).
_PATH_KEYS = (
    "file_path", "path", "filePath", "target_file", "targetFile",
    "relative_workspace_path",
)
_TEXT_KEYS = (
    "content", "contents", "new_string", "newString", "new_text", "newText",
    "text", "code_edit", "replacement",
)
_LIST_KEYS = ("edits", "replacements")

DENY_REASON_HEAD = "Acutis: no verify_code ALLOW covers this exact text for "
DENY_REASON_TAIL = (
    ". Call mcp__acutis__verify_code with this exact code and a PCST contract "
    "(sources, sinks, transforms); on ALLOW, re-issue the write with the "
    "verified text byte-for-byte. Acutis verifies generated code output, "
    "never a file."
)


def normalize(text) -> str:
    return "".join(str(text).split())


def validated_conversation_id(cid: str) -> str:
    """Guard-and-reject: only a charset-clean id may become part of a path."""
    if not _CONVERSATION_ID_RE.fullmatch(cid):
        return ""
    return cid


def ledger_path_for(hook_input: dict) -> str:
    """Conversation-scoped ledger path; the fixed literal path when the id is
    absent or fails validation (a shared fallback still requires an exact
    text match, so it over-blocks rather than under-blocks)."""
    cid = validated_conversation_id(str(hook_input.get("conversation_id") or ""))
    if not cid:
        return "/tmp/acutis-allow-cursor.json"
    return LEDGER_PREFIX + cid + ".json"


def load_allowed(hook_input: dict) -> list:
    """Normalized ALLOWed payloads for this conversation ([] when absent/corrupt)."""
    try:
        with open(ledger_path_for(hook_input), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    allowed = data.get("allowed", [])
    if not isinstance(allowed, list):
        return []
    return [a for a in allowed if isinstance(a, str) and a]


def parse_tool_input(hook_input: dict) -> dict:
    tool_input = hook_input.get("tool_input", {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except ValueError:
            return {}
    if not isinstance(tool_input, dict):
        return {}
    return tool_input


def extract_file_path(tool_input: dict, cwd: str) -> str:
    for key in _PATH_KEYS:
        val = tool_input.get(key)
        if isinstance(val, str) and val:
            p = Path(val)
            if cwd and not p.is_absolute():
                p = Path(cwd) / p
            return str(p)
    return ""


def is_security_relevant(file_path: str) -> bool:
    if not file_path:
        return False
    p = Path(file_path)
    if p.suffix.lower() not in SECURITY_EXTENSIONS:
        return False
    if set(p.parts) & SKIP_PATTERNS:
        return False
    if _SCRATCHPAD_RE.match(file_path):
        return False
    return True


def extract_written_texts(tool_input: dict) -> tuple:
    """Return (texts, found): every string that looks like new text, and
    whether any new-text field was present at all."""
    texts = []
    found = False
    for key in _TEXT_KEYS:
        val = tool_input.get(key)
        if isinstance(val, str):
            found = True
            texts.append(val)
    for key in _LIST_KEYS:
        items = tool_input.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            for tkey in _TEXT_KEYS:
                val = item.get(tkey)
                if isinstance(val, str):
                    found = True
                    texts.append(val)
    return texts, found


def covered(norms: list, allowed: list) -> bool:
    """One-directional: every normalized fragment is a substring of some
    normalized ALLOWed payload."""
    for norm in norms:
        if not norm:
            return False
        if not any(norm in payload for payload in allowed):
            return False
    return True


def acutis_reachable() -> bool:
    try:
        with urllib.request.urlopen(MCP_HEALTH_URL, timeout=MCP_HEALTH_TIMEOUT):
            return True
    except (OSError, ValueError):
        return False


def emit(payload: dict) -> None:
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")


def allow() -> int:
    emit({"permission": "allow"})
    return 0


def deny(name: str, note: str) -> int:
    reason = DENY_REASON_HEAD + name + DENY_REASON_TAIL + note
    emit({
        "permission": "deny",
        "user_message": "Acutis: write to " + name + " blocked until a verify_code ALLOW covers the exact text.",
        "agent_message": reason,
    })
    return 0


def main() -> int:
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw) if raw.strip() else {}
    except (OSError, ValueError):
        hook_input = None
    if not isinstance(hook_input, dict):
        print("acutis pre-write gate: unparseable hook input; denying (fail closed)", file=sys.stderr)
        emit({
            "permission": "deny",
            "user_message": "Acutis: pre-write gate could not read the hook input.",
            "agent_message": "Acutis: the pre-write gate could not parse its hook input, so the write was denied (fail closed). Retry the write.",
        })
        return 0

    tool_name = str(hook_input.get("tool_name") or "")
    if tool_name and tool_name != WRITE_TOOL_NAME:
        print("acutis pre-write gate: tool_name " + tool_name + " is not Write; passing through", file=sys.stderr)
        return allow()

    tool_input = parse_tool_input(hook_input)
    cwd = str(hook_input.get("cwd") or "")
    file_path = extract_file_path(tool_input, cwd)
    if not is_security_relevant(file_path):
        return allow()

    name = Path(file_path).name
    texts, found = extract_written_texts(tool_input)
    if not found:
        keys = ", ".join(sorted(str(k) for k in tool_input.keys()))
        print("acutis pre-write gate: no new-text field in Write tool_input for " + name + "; keys=[" + keys + "]", file=sys.stderr)
        return deny(name, " (Unrecognised Write input shape: keys [" + keys + "]; no new-text field found.)")

    norms = [normalize(t) for t in texts]
    if not all(norms):
        return deny(name, " (The written text is empty.)")

    if covered(norms, load_allowed(hook_input)):
        return allow()

    if not acutis_reachable():
        print("acutis pre-write gate: mcp.acutis.dev unreachable; allowing unverified write to " + name, file=sys.stderr)
        return allow()

    return deny(name, "")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - fail closed on any internal error
        print("acutis pre-write gate: internal error " + repr(exc) + "; denying (fail closed)", file=sys.stderr)
        sys.exit(2)
