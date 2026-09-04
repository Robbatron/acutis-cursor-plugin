#!/usr/bin/env python3
"""
Acutis ALLOW-ledger recorder (Cursor `postToolUse` + `afterMCPExecution`).

Reduced role (2026-09-04): the old pending-file bookkeeping is gone with the
stop hook's enforcement role. Two jobs remain, both keyed on a genuine ALLOW
verdict from the verify_code MCP tool.

1. Ledger. Append the normalized `code` argument of the ALLOWed call to
   /tmp/acutis-allow-cursor-<conversation_id>.json (200 most recent, atomic
   write). The pre-write gate denies any Write whose text is not contained in a
   ledger entry, and both sweeps use the same ledger. Cursor transcripts
   exclude tool outputs and `transcript_path` can be null, so the ledger is the
   only durable record of what was verified.

2. Attestation upkeep. An ALLOW is the moment a parked sweep finding can clear:
   this is exactly the format-then-verify path, where a formatter rewrote a file
   and the model has now verified that file's final text. Findings whose file is
   covered again are dropped, and attestations for files that no longer exist
   are forgotten so the state file stays bounded.

Registered on both MCP-result events so the ledger is written whichever one
Cursor delivers: `postToolUse` (generic, MCP tools included; `tool_input`
object, `tool_output` string) and `afterMCPExecution` (`tool_input` JSON params
string, `result_json` string). Cloud agents run `postToolUse` but not
`afterMCPExecution`. Both may fire for one call; recording is idempotent.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import acutis_common as ac  # noqa: E402

VERIFY_TOOL_KEYWORD = "verify_code"

_BLOCK_MARKERS = ("BLOCK_VIOLATION", "BLOCK_INCOMPLETE")
# Cursor hands an MCP result over as a JSON string of the MCP response, so the
# VerificationResponse text inside it is JSON-escaped (\"decision\": \"ALLOW\").
# The optional backslashes accept both the raw and the escaped form.
_DECISION_ALLOW_RE = re.compile(r'\\?"decision\\?"\s*:\s*\\?"ALLOW\\?"')
_BARE_ALLOW_RE = re.compile(r"\bALLOW\b")

# Keys under which Cursor surfaces the tool result: result_json
# (afterMCPExecution), tool_output (postToolUse), plus common aliases.
_RESULT_KEYS = ("result_json", "tool_output", "tool_result", "result", "output")


def text_is_allow(text, strict=False):
    """True only for a genuine ALLOW verdict body.

    verify_code's text result is the VerificationResponse JSON, so a real
    verdict carries "decision": "ALLOW". BLOCK bodies can contain the bare word
    ALLOW in remediation prose ("iterate until ALLOW"), so a plain substring
    test fails open. Any BLOCK terminal state in the body wins over an ALLOW
    match. `strict` (ledger recording) accepts only the decision-key form.
    """
    for marker in _BLOCK_MARKERS:
        if marker in text:
            return False
    if _DECISION_ALLOW_RE.search(text):
        return True
    if strict:
        return False
    return _BARE_ALLOW_RE.search(text) is not None


def result_contains_allow(hook_input, strict=False):
    """True only if the verify_code result carries a real ALLOW verdict."""
    for key in _RESULT_KEYS:
        val = hook_input.get(key, "")
        if isinstance(val, str) and text_is_allow(val, strict):
            return True
        if isinstance(val, dict):
            decision = str(val.get("decision", val.get("verdict", "")))
            if decision.strip() == "ALLOW":
                return True
            content = val.get("content", [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and text_is_allow(str(item.get("text", "")), strict):
                        return True
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict) and text_is_allow(str(item.get("text", "")), strict):
                    return True
    return False


def extract_verified_code(hook_input):
    """The normalized `code` argument of the verify_code call, or ''."""
    tool_input = hook_input.get("tool_input", {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except ValueError:
            tool_input = {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    return ac.normalize(tool_input.get("code"))


def record_allow(hook_input, code):
    """Append one normalized ALLOWed payload to the ledger (dedup, cap, atomic)."""
    path = ac.ledger_path_for(hook_input)
    data = ac.load_json(path)
    allowed = []
    if isinstance(data, dict) and isinstance(data.get("allowed"), list):
        allowed = data["allowed"]
    kept = [a for a in allowed if isinstance(a, str) and a and a != code]
    kept.append(code)
    ac.write_json_atomic(path, {"allowed": kept[-ac.LEDGER_CAP:]})


def reconcile(hook_input):
    """Drop sweep findings the model has now verified, and forget attestations
    whose file is gone."""
    state = ac.load_sweep_state(hook_input)
    allowed = ac.load_allowed(hook_input)
    attested = state["attested"]
    remaining = []
    for path in state["pending"]:
        target = ac.validated_abs_path(path)
        if not target:
            continue
        if ac.file_covered(target, allowed, attested):
            continue
        remaining.append(target)
    kept = {}
    for path in attested:
        target = ac.validated_abs_path(path)
        if not target:
            continue
        if not os.path.exists(target):
            continue
        kept[target] = attested[path]
    state["pending"] = remaining
    state["attested"] = kept
    ac.save_sweep_state(hook_input, state)


def main():
    hook_input = ac.read_hook_input()
    if hook_input is None:
        ac.emit({})
        return 0
    tool_name = str(hook_input.get("tool_name") or "")
    if VERIFY_TOOL_KEYWORD not in tool_name:
        ac.emit({})
        return 0
    ac.ensure_session_start(hook_input)
    if result_contains_allow(hook_input, True):
        code = extract_verified_code(hook_input)
        if code:
            record_allow(hook_input, code)
    if result_contains_allow(hook_input):
        reconcile(hook_input)
    ac.emit({})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - bookkeeping must never break the turn
        print("acutis allow tracker: internal error " + ac.one_line(repr(exc)), file=sys.stderr)
        sys.exit(0)
