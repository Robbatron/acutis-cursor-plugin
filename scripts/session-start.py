#!/usr/bin/env python3
"""
Acutis SessionStart hook (Cursor) — primes the agent with security context.

Fires once at the start of each Cursor agent session. Emits an
`additional_context` message (the field Cursor's sessionStart hook consumes) so
the agent knows Acutis verification is active.
"""

import json
import sys


def main() -> None:
    # Drain stdin (Cursor sends a JSON payload); contents are not needed here.
    try:
        sys.stdin.read()
    except IOError:
        pass

    message = (
        "Acutis security verification is active. "
        "When you write or edit security-relevant code (.py, .js, .ts, .html), "
        "you must call the Acutis scan_code MCP tool before finishing. "
        "Use the /scan skill for guidance on building PCST contracts."
    )

    json.dump({"additional_context": message}, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
