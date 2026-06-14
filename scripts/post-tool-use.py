#!/usr/bin/env python3
"""
Acutis PostToolUse hook (Cursor) — reminds the agent to call scan_code after a
security-relevant file write.

Cursor's postToolUse input provides `tool_name`, `tool_input`, `tool_output`,
`tool_use_id`, `cwd`, `duration`, `model` — but not a top-level `file_path`, so
the path (when present) is read out of `tool_input`. Output uses
`additional_context`, the field postToolUse supports for context injection.

This is a best-effort nudge; the load-bearing enforcement is the afterFileEdit
hook (records state) plus the stop hook (re-prompts on unverified state).
"""

import json
import sys
from pathlib import Path

# Keep in sync with after-file-edit.py / stop-hook.py
SECURITY_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".html", ".htm", ".mjs", ".cjs",
}

SKIP_PATTERNS = {
    "node_modules", "__pycache__", ".git", "venv", ".venv",
    "package-lock.json", "yarn.lock", "poetry.lock",
}


def extract_file_path(hook_input: dict) -> str:
    """Best-effort pull of the edited file path from a Cursor postToolUse event."""
    tool_input = hook_input.get("tool_input", {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except (json.JSONDecodeError, TypeError):
            return ""
    if not isinstance(tool_input, dict):
        return ""
    return tool_input.get("path", tool_input.get("file_path", tool_input.get("filePath", "")))


def is_security_relevant(file_path: str) -> bool:
    if not file_path:
        return False
    p = Path(file_path)
    if p.suffix.lower() not in SECURITY_EXTENSIONS:
        return False
    if set(p.parts) & SKIP_PATTERNS:
        return False
    return True


def main() -> None:
    try:
        hook_input = json.loads(sys.stdin.read() or "{}")
    except (json.JSONDecodeError, IOError):
        hook_input = {}

    file_path = extract_file_path(hook_input)
    if not is_security_relevant(file_path):
        json.dump({}, sys.stdout)
        sys.stdout.write("\n")
        sys.exit(0)

    filename = Path(file_path).name
    reminder = (
        f"ACUTIS: You just wrote {filename} — this is a security-relevant file. "
        f"Call the Acutis scan_code MCP tool (server name contains 'acutis') "
        f"with the code and a PCST contract declaring sources, sinks, and transforms. "
        f"The stop hook will ask you to verify if unverified code exists when you finish."
    )
    json.dump({"additional_context": reminder}, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
