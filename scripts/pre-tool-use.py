#!/usr/bin/env python3
"""
Acutis pre-write gate (Cursor `preToolUse`, matcher "Write").

Nothing is written until an Acutis verify_code ALLOW exists, and the written
text must be exactly what Acutis verified. This hook is a GATE, not a verifier:
it never calls verify_code itself, because only the model can author the PCST
contract. It checks that the model already obtained an ALLOW whose `code`
payload CONTAINS the text about to be written, and denies otherwise with an
`agent_message` the model acts on.

Match rule (one-directional): both sides are normalized by removing whitespace;
the normalized written text must be a substring of a normalized ALLOWed
payload. A whole-file write with only one function verified is denied; a
fragment edit inside a verified function is allowed; empty written text on a
security-relevant path is denied.

Attestation: on allow, a single whole-text write records its content hash in
the conversation's sweep state, so the post-shell and stop sweeps do not
re-flag a file this gate already approved.

Sweep delivery: `afterShellExecution` has no output fields in Cursor's hooks
docs, so the post-shell sweep parks its finding in the sweep state. This gate
is the first event that can talk to the agent, so it surfaces that finding as a
deny (once, then clears it) before checking the write itself.

Availability: only when nothing matches, GET https://mcp.acutis.dev/health
(3 s). If the server is unreachable the write is allowed with a stderr note,
the same fail-open policy as the sweeps. Never on the happy path.

Failure policy: fail closed. Unparseable input or an internal error on a
security-relevant path denies (exit code 2 also denies per the hooks docs), and
the hook entry carries `failClosed: true`.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import acutis_common as ac  # noqa: E402

# Cursor's file-writing tool is named "Write" in preToolUse. Anything else
# reaching this script means the matcher did not filter; pass it through.
WRITE_TOOL_NAME = "Write"
ATTEST_CAP = 200

DENY_HEAD = "Acutis: "
DENY_TAIL = (
    " has no verify_code ALLOW for this exact text. Verify this code with a "
    "PCST contract, then re-issue the write with the verified text "
    "byte-for-byte."
)

# Cursor documents `file_path` + `content` for a whole-file write; the
# search/replace shape is undocumented, so every plausible carrier is inspected
# and an unrecognised shape on a security-relevant path is denied (its keys are
# logged so the shape can be learned).
_PATH_KEYS = (
    "file_path", "path", "filePath", "target_file", "targetFile",
    "relative_workspace_path",
)
_TEXT_KEYS = (
    "content", "contents", "new_string", "newString", "new_text", "newText",
    "text", "code_edit", "replacement",
)
_LIST_KEYS = ("edits", "replacements")


def parse_tool_input(hook_input):
    tool_input = hook_input.get("tool_input", {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except ValueError:
            return {}
    if not isinstance(tool_input, dict):
        return {}
    return tool_input


def extract_file_path(tool_input, cwd):
    for key in _PATH_KEYS:
        val = tool_input.get(key)
        if isinstance(val, str) and val:
            if cwd and not os.path.isabs(val):
                return os.path.join(cwd, val)
            return val
    return ""


def extract_written_texts(tool_input):
    """(texts, found): every string that looks like new text, and whether any
    new-text field was present at all."""
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
            for text_key in _TEXT_KEYS:
                val = item.get(text_key)
                if isinstance(val, str):
                    found = True
                    texts.append(val)
    return texts, found


def covered(norms, allowed):
    """One-directional: every normalized fragment is a substring of some
    normalized ALLOWed payload."""
    for norm in norms:
        if not norm:
            return False
        if not any(norm in payload for payload in allowed):
            return False
    return True


def attest(hook_input, file_path, norms):
    """Record the exact text this gate approved so the sweeps do not re-flag it.

    Only a single whole-text write is attested: a multi-fragment edit leaves a
    file whose final text is not any one of the fragments, and claiming
    otherwise would under-report.
    """
    if len(norms) != 1:
        return
    target = ac.validated_abs_path(file_path)
    if not target:
        return
    state = ac.load_sweep_state(hook_input)
    attested = state["attested"]
    attested[target] = ac.content_hash(norms[0])
    state["attested"] = dict(list(attested.items())[-ATTEST_CAP:])
    ac.save_sweep_state(hook_input, state)


def still_pending(hook_input, state):
    """Parked sweep findings whose file is still uncovered right now."""
    allowed = ac.load_allowed(hook_input)
    remaining = []
    for path in state["pending"]:
        target = ac.validated_abs_path(path)
        if not target:
            continue
        if ac.file_covered(target, allowed, state["attested"]):
            continue
        remaining.append(target)
    return remaining


def allow():
    ac.emit({"permission": "allow"})
    return 0


def deny(name):
    ac.emit({
        "permission": "deny",
        "user_message": "Acutis: write to " + name + " blocked until a verify_code ALLOW covers the exact text.",
        "agent_message": DENY_HEAD + name + DENY_TAIL,
    })
    return 0


def main():
    hook_input = ac.read_hook_input()
    if hook_input is None:
        ac.note("pre-write gate: unparseable hook input; denying (fail closed)")
        ac.emit({
            "permission": "deny",
            "user_message": "Acutis: the pre-write gate could not read the hook input.",
            "agent_message": "Acutis: the pre-write gate could not parse its hook input, so the write was denied (fail closed). Retry the write.",
        })
        return 0
    tool_name = ac.one_line(str(hook_input.get("tool_name") or ""))
    if tool_name and tool_name != WRITE_TOOL_NAME:
        ac.note("pre-write gate: tool_name " + tool_name + " is not Write; passing through")
        return allow()
    ac.ensure_session_start(hook_input)
    tool_input = parse_tool_input(hook_input)
    cwd = str(hook_input.get("cwd") or "")
    file_path = extract_file_path(tool_input, cwd)
    if not ac.is_security_relevant(file_path):
        return allow()
    name = ac.one_line(os.path.basename(file_path))
    state = ac.load_sweep_state(hook_input)
    pending = still_pending(hook_input, state)
    if pending:
        state["pending"] = []
        ac.save_sweep_state(hook_input, state)
        message = ac.one_line(ac.sweep_message(pending))
        ac.emit({
            "permission": "deny",
            "user_message": "Acutis: unverified code changed by a shell command is still on disk.",
            "agent_message": message,
        })
        return 0
    texts, found = extract_written_texts(tool_input)
    if not found:
        keys = ac.one_line(", ".join(sorted(str(k) for k in tool_input.keys())))
        ac.note("pre-write gate: no new-text field in Write tool_input for " + name + "; keys=[" + keys + "]")
        return deny(name)
    norms = [ac.normalize(text) for text in texts]
    if not all(norms):
        return deny(name)
    if covered(norms, ac.load_allowed(hook_input)):
        attest(hook_input, file_path, norms)
        return allow()
    if not ac.acutis_reachable():
        ac.note("pre-write gate: mcp.acutis.dev unreachable; allowing unverified write to " + name)
        return allow()
    return deny(name)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - fail closed on any internal error
        print("acutis pre-write gate: internal error " + ac.one_line(repr(exc)) + "; denying (fail closed)", file=sys.stderr)
        sys.exit(2)
