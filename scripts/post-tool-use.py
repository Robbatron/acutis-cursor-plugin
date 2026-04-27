#!/usr/bin/env python3
"""
Acutis PostToolUse Hook — fires after each Write/Edit to remind the agent
to call scan_code for security-relevant files.

Works in Claude Code, Cursor, and VS Code.

Environment detection:
  - Claude Code: default (no cursor_version or hookEventName keys)
  - Cursor: hook_input has "cursor_version" or "hook_event_name" key
  - VS Code: hook_input has "hookEventName" key

Hook protocol:
  - stdin: JSON with tool_name, tool_input, etc.
  - stdout: JSON with additionalContext (non-blocking reminder)
  - exit 0: always (PostToolUse is advisory, not blocking)
"""

import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants — keep in sync with stop-hook.py
# ---------------------------------------------------------------------------

SECURITY_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".html", ".htm", ".mjs", ".cjs",
}

SKIP_PATTERNS = {
    "node_modules", "__pycache__", ".git", "venv", ".venv",
    "package-lock.json", "yarn.lock", "poetry.lock",
}


def detect_environment(hook_input: dict) -> str:
    """Detect whether we're running in Claude Code, Cursor, or VS Code.

    VS Code sends: hookEventName (PascalCase)
    Cursor sends: hook_event_name, cursor_version
    Claude Code: default
    """
    if "hookEventName" in hook_input:
        return "vscode"
    if "cursor_version" in hook_input or "hook_event_name" in hook_input:
        return "cursor"
    return "claude"


def extract_file_path(hook_input: dict, env: str) -> str:
    """Extract the file path from the hook input."""
    # Cursor afterFileEdit provides file_path directly
    if env == "cursor":
        fp = hook_input.get("file_path", "")
        if fp:
            return fp

    # Claude Code and VS Code: tool_input contains file_path
    tool_input = hook_input.get("tool_input", {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except (json.JSONDecodeError, TypeError):
            return ""
    return tool_input.get("file_path", tool_input.get("filePath", ""))


def is_security_relevant(file_path: str) -> bool:
    """Check if a file path is security-relevant based on extension."""
    if not file_path:
        return False
    p = Path(file_path)
    if p.suffix.lower() not in SECURITY_EXTENSIONS:
        return False
    if set(p.parts) & SKIP_PATTERNS:
        return False
    return True


def build_reminder(file_path: str) -> str:
    """Build the reminder message."""
    filename = Path(file_path).name
    return (
        f"ACUTIS: You just wrote {filename} — this is a security-relevant file. "
        f"Call scan_code with the code and a PCST contract declaring sources, "
        f"sinks, and transforms. The stop hook will block if unverified code "
        f"exists when you finish."
    )


def main() -> None:
    """Main hook entry point."""
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, IOError):
        hook_input = {}

    env = detect_environment(hook_input)
    file_path = extract_file_path(hook_input, env)

    if not is_security_relevant(file_path):
        # Not a security-relevant file — no action
        json.dump({}, sys.stdout)
        sys.stdout.write("\n")
        sys.exit(0)

    reminder = build_reminder(file_path)

    if env == "vscode":
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": reminder,
            }
        }
    elif env == "cursor":
        response = {"additional_context": reminder}
    else:
        # Claude Code
        response = {"additionalContext": reminder}

    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
