#!/usr/bin/env python3
"""
Acutis Stop Hook — works in Claude Code, VS Code, and Cursor.

Safety net: blocks the agent from completing if it wrote security-relevant code
that hasn't been verified via scan_code. If the agent already called scan_code
and got ALLOW after its last edit, the hook is invisible.

The hook does NOT invoke Acutis directly — it only reads the transcript to
determine whether scan_code was called. The agent calls scan_code via MCP.

Environment detection:
  - Claude Code: hook_input has "stop_hook_active" key; output {"decision": "block"}
  - VS Code: hook_input has "hookEventName" key; output {"hookSpecificOutput": {"decision": "block"}}
  - Cursor: hook_input has "hook_event_name" key; output {"followup_message": "..."}

Hook protocol (both environments):
  - stdin: JSON with transcript_path, etc.
  - stdout: JSON response
  - exit 0: allow (parse stdout for JSON)
  - exit 2: blocking error
"""

import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SECURITY_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".html", ".htm", ".mjs", ".cjs",
}

SKIP_PATTERNS = {
    "node_modules", "__pycache__", ".git", "venv", ".venv",
    "package-lock.json", "yarn.lock", "poetry.lock",
}

WRITE_TOOLS = {
    "Write", "Edit", "write", "edit",          # Claude Code
    "editFiles", "createFile",                      # Cursor
    "create_file", "replace_string_in_file",         # VS Code Copilot
    "multi_replace_string_in_file", "edit_file",     # VS Code Copilot
}

# Substring match — plugin namespacing can prefix tool names
# (e.g. "plugin:acutis:mcp__acutis__scan_code")
SCAN_TOOL_KEYWORD = "scan_code"

# MCP server health check
MCP_HEALTH_URL = os.environ.get("ACUTIS_MCP_URL", "https://mcp.acutis.dev") + "/health"
MCP_HEALTH_TIMEOUT = 3  # seconds


def check_mcp_health() -> bool:
    """Check if the Acutis MCP server is reachable.

    Returns True if reachable, False otherwise. Fails open: if we can't
    reach the server, we allow the stop rather than deadlocking the agent.
    """
    try:
        req = urllib.request.Request(MCP_HEALTH_URL, method="GET")
        with urllib.request.urlopen(req, timeout=MCP_HEALTH_TIMEOUT):
            return True
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return False


def detect_environment(hook_input: dict) -> str:
    """Detect whether we're running in Claude Code, VS Code, or Cursor.

    Claude Code sends: stop_hook_active, session_id
    VS Code sends: hookEventName (PascalCase), sessionId
    Cursor sends: hook_event_name, cursor_version, conversation_id
    """
    if "hookEventName" in hook_input:
        return "vscode"
    if "hook_event_name" in hook_input or "cursor_version" in hook_input:
        return "cursor"
    return "claude"


def read_hook_input() -> dict:
    """Read the JSON hook input from stdin."""
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return {}
        return json.loads(raw)
    except (json.JSONDecodeError, IOError):
        return {}


def is_security_relevant(file_path: str) -> bool:
    """Check if a file path is security-relevant based on extension."""
    p = Path(file_path)
    if p.suffix.lower() not in SECURITY_EXTENSIONS:
        return False
    if set(p.parts) & SKIP_PATTERNS:
        return False
    return True


def analyze_transcript(transcript_path: str) -> tuple:
    """Walk the transcript and determine verification state.

    Returns (unverified_files, all_security_files):
      - all_security_files: list of all security-relevant files written
      - unverified_files: files written since the last scan_code ALLOW
    """
    if not transcript_path or not os.path.isfile(transcript_path):
        return [], []

    all_security_files: list[str] = []
    files_since_last_allow: list[str] = []

    try:
        with open(transcript_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                writes, allow, written_paths = _analyze_entry(entry)
                if writes:
                    for fp in written_paths:
                        if fp not in all_security_files:
                            all_security_files.append(fp)
                        if fp not in files_since_last_allow:
                            files_since_last_allow.append(fp)
                if allow:
                    files_since_last_allow.clear()
    except (IOError, PermissionError):
        pass

    return files_since_last_allow, all_security_files


def _analyze_entry(entry, _depth=0) -> tuple:
    """Check a transcript entry for security-relevant writes and scan ALLOWs.

    Returns (has_security_write, has_scan_allow, written_paths).
    """
    if _depth > 10:
        return False, False, []

    has_write = False
    has_allow = False
    written_paths: list[str] = []

    if isinstance(entry, dict):
        # Check for Write/Edit tool_use
        if entry.get("type") == "tool_use" and entry.get("name") in WRITE_TOOLS:
            tool_input = entry.get("input", entry.get("tool_input", {}))
            fp = tool_input.get("file_path", tool_input.get("filePath", ""))
            if fp and is_security_relevant(fp):
                has_write = True
                written_paths.append(fp)

        if entry.get("tool_name") in WRITE_TOOLS:
            tool_input = entry.get("tool_input", {})
            fp = tool_input.get("file_path", tool_input.get("filePath", ""))
            if fp and is_security_relevant(fp):
                has_write = True
                written_paths.append(fp)

        # Check for scan_code tool_result with ALLOW
        # Use substring match: plugin namespacing prefixes tool names
        entry_name = str(entry.get("name", ""))
        entry_tool_name = str(entry.get("tool_name", ""))
        is_scan_result = (
            entry.get("type") == "tool_result"
            and SCAN_TOOL_KEYWORD in entry_name
        )
        if is_scan_result:
            content = entry.get("content", "")
            if isinstance(content, str) and "ALLOW" in content:
                has_allow = True
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and "ALLOW" in str(item.get("text", "")):
                        has_allow = True

        # Also check for scan_code in tool_name + result patterns
        if SCAN_TOOL_KEYWORD in entry_tool_name:
            result = entry.get("result", entry.get("tool_result", ""))
            if isinstance(result, str) and "ALLOW" in result:
                has_allow = True
            elif isinstance(result, dict) and "ALLOW" in str(result.get("decision", "")):
                has_allow = True

        # Recurse into nested structures
        for key in ("content", "messages", "message"):
            val = entry.get(key)
            if isinstance(val, (dict, list)):
                w, a, paths = _analyze_entry(val, _depth + 1)
                has_write = has_write or w
                has_allow = has_allow or a
                written_paths.extend(paths)

    elif isinstance(entry, list):
        for item in entry:
            w, a, paths = _analyze_entry(item, _depth + 1)
            has_write = has_write or w
            has_allow = has_allow or a
            written_paths.extend(paths)

    return has_write, has_allow, written_paths


def main() -> None:
    """Main hook entry point."""
    hook_input = read_hook_input()
    env = detect_environment(hook_input)

    # Guard: prevent infinite loops
    # Claude Code: stop_hook_active flag
    # Cursor: loop_count field (max 5 enforced by Cursor itself)
    if hook_input.get("stop_hook_active", False):
        sys.exit(0)
    if hook_input.get("loop_count", 0) >= 3:
        sys.exit(0)

    transcript_path = hook_input.get("transcript_path", "")
    unverified_files, all_security_files = analyze_transcript(transcript_path)

    if not all_security_files or not unverified_files:
        # No security-relevant code, or already verified — allow stop
        sys.exit(0)

    # Before blocking, check if the MCP server is reachable.
    # If it's down, blocking would deadlock the agent (it can't scan).
    # Fail open: warn but allow.
    if not check_mcp_health():
        # Server unreachable — allow stop with a warning on stderr
        print(
            "Warning: Acutis MCP server is unreachable. "
            "Skipping verification enforcement.",
            file=sys.stderr,
        )
        sys.exit(0)

    # Block: unverified security-relevant code exists
    # Show just filenames, not full paths (cleaner for the agent)
    names = ", ".join(Path(f).name for f in unverified_files)
    message = (
        f"Security-relevant code was written but not yet verified. "
        f"Files needing verification: {names}. "
        f"Call mcp__acutis__scan_code with the code and a PCST contract. "
        f"Fix any BLOCK results before completing."
    )

    if env == "vscode":
        # VS Code: hookSpecificOutput wrapper with decision/reason
        response = {
            "hookSpecificOutput": {
                "hookEventName": "Stop",
                "decision": "block",
                "reason": message,
            }
        }
    elif env == "cursor":
        # Cursor: followup_message triggers a new turn
        response = {"followup_message": message}
    else:
        # Claude Code: decision/reason blocks the stop
        response = {"decision": "block", "reason": message}

    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
