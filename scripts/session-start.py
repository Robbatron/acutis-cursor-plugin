#!/usr/bin/env python3
"""
Acutis SessionStart Hook — primes the agent with security context.

Fires once at the start of each session. Injects a brief message so the
agent knows Acutis is active and security verification is enforced.
"""

import json
import sys


def main() -> None:
    """Emit a context message for the agent."""
    try:
        hook_input = json.loads(sys.stdin.read() or "{}")
    except (json.JSONDecodeError, IOError):
        hook_input = {}

    message = (
        "Acutis security verification is active. "
        "When you write or edit security-relevant code (.py, .js, .ts, .html), "
        "you must call mcp__acutis__scan_code before finishing. "
        "Use /acutis:scan for guidance on building PCST contracts."
    )

    # Detect environment and format response
    if "hookEventName" in hook_input:
        # VS Code
        response = {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": message,
            }
        }
    elif "hook_event_name" in hook_input or "cursor_version" in hook_input:
        # Cursor
        response = {"additionalContext": message}
    else:
        # Claude Code
        response = {"additionalContext": message}

    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
