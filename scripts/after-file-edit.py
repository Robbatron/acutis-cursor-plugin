#!/usr/bin/env python3
"""
Acutis AfterFileEdit Hook (Cursor) — records security-relevant file writes to
the shared state file so the stop hook can detect unverified edits.

Why this exists:
  Cursor's `stop` hook input may not carry usable conversation content
  (transcript_path can be null if transcripts are disabled, and its format is
  undocumented). Relying on it means enforcement can silently fail open. This
  hook makes enforcement robust by recording every security-relevant write to a
  state file the moment it happens — independent of transcripts.

  `afterFileEdit` is Cursor-specific, so this code path only runs under Cursor.
  Claude Code / VS Code never fire it and keep using the transcript path in
  stop-hook.py.

State file schema (/tmp/acutis-unverified.json):
  {
    "pending": ["path/to/file.py", ...],   # written but not yet scan_code ALLOW'd
    "all":     ["path/to/file.py", ...]     # all security files touched this run
  }

The state file is appended to here, and the `pending` list is cleared by
scan-allow-tracker.py when scan_code returns ALLOW.
"""

import json
import sys
from pathlib import Path

# Keep in sync with post-tool-use.py / stop-hook.py
SECURITY_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".html", ".htm", ".mjs", ".cjs",
}

SKIP_PATTERNS = {
    "node_modules", "__pycache__", ".git", "venv", ".venv",
    "package-lock.json", "yarn.lock", "poetry.lock",
}

# Global, machine-wide state file. A fixed path means every hook in the session
# agrees on it without threading an id through (which, if mismatched, would fail
# open — the unsafe direction). Stale entries from a prior session at worst cause
# a redundant scan request (over-block), which is the safe failure mode.
STATE_FILE = "/tmp/acutis-unverified.json"


def is_security_relevant(file_path: str) -> bool:
    if not file_path:
        return False
    p = Path(file_path)
    if p.suffix.lower() not in SECURITY_EXTENSIONS:
        return False
    if set(p.parts) & SKIP_PATTERNS:
        return False
    return True


def extract_file_path(hook_input: dict) -> str:
    """Pull the edited file path from the afterFileEdit payload."""
    # Cursor afterFileEdit provides file_path directly.
    fp = hook_input.get("file_path", "")
    if fp:
        return fp
    tool_input = hook_input.get("tool_input", {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except (json.JSONDecodeError, TypeError):
            return ""
    return tool_input.get("path", tool_input.get("file_path", tool_input.get("filePath", "")))


def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
        # Defensive: ensure expected shape.
        if not isinstance(state, dict):
            return {"pending": [], "all": []}
        state.setdefault("pending", [])
        state.setdefault("all", [])
        return state
    except (FileNotFoundError, json.JSONDecodeError, IOError):
        return {"pending": [], "all": []}


def save_state(state: dict) -> None:
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

    file_path = extract_file_path(hook_input)

    if not is_security_relevant(file_path):
        # Not security-relevant — emit nothing and exit cleanly.
        json.dump({}, sys.stdout)
        sys.stdout.write("\n")
        sys.exit(0)

    state = load_state()
    if file_path not in state["pending"]:
        state["pending"].append(file_path)
    if file_path not in state["all"]:
        state["all"].append(file_path)
    save_state(state)

    # afterFileEdit output support for context injection is not guaranteed by
    # Cursor; the reminder here is best-effort. The post-tool-use hook is the
    # primary reminder channel. State recording above is the load-bearing part.
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
