#!/usr/bin/env python3
"""
Acutis sessionStart hook (Cursor).

Fires once when a composer conversation is created. It records the session
start mark the stop sweep uses as its mtime baseline, resets this
conversation's sweep state, and emits `additional_context` so the agent knows
the gates are live before it writes anything.

Cloud agents never fire sessionStart (Cursor defers it while a cloud agent can
still start read-only), so every other hook calls `ensure_session_start` too
and the first hook of the session sets the mark. Only this hook overwrites it.

The durable, always-on guidance lives in the plugin's always-apply rule
(`rules/acutis-security.mdc`); this message is a short pointer, not a copy.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import acutis_common as ac  # noqa: E402

MESSAGE = (
    "Acutis security verification is active. Write code files "
    "(.py .js .jsx .ts .tsx .mjs .cjs .java) with the Write tool and verify "
    "each file's exact text with the verify_code MCP tool first: the pre-write "
    "gate denies any write with no matching ALLOW, and the shell gate denies "
    "shell commands that write code files. Follow the always-on "
    "acutis-security rule and use the verify skill to build PCST contracts."
)


def main():
    hook_input = ac.read_hook_input()
    if hook_input is None:
        hook_input = {}
    ac.ensure_session_start(hook_input, True)
    ac.save_sweep_state(hook_input, {"attested": {}, "pending": [], "fail_open": []})
    ac.emit({"additional_context": MESSAGE})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - fire and forget, never break the session
        print("acutis session start: internal error " + ac.one_line(repr(exc)), file=sys.stderr)
        sys.exit(0)
