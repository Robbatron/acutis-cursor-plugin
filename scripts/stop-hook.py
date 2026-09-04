#!/usr/bin/env python3
"""
Acutis stop sweep (Cursor `stop`).

Reduced role (operator decision, 2026-09-04): enforcement happens per event,
before code lands, in the pre-write gate and the shell gate. This hook is no
longer the enforcement path and no longer tracks pending writes by path. It is
a silent filesystem sweep kept as a backstop through a validation period, and
it is scheduled for removal once the per-event gates have proven themselves.

What it does: list the project's security-relevant files, keep the ones whose
mtime is after the session start mark (recorded by `session-start.py`, or by
whichever hook fires first in a cloud agent, where sessionStart never runs),
add any finding the post-shell sweep parked because `afterShellExecution` has
no way to talk to the agent, and drop everything whose current content is
covered by a verify_code ALLOW or by the pre-write gate's attestation. Only
what survives all of that produces a `followup_message`; otherwise the hook
emits no output field and the stop proceeds.

Cursor's `stop` hook cannot hard-block; `followup_message` auto-submits one
more turn, bounded by MAX_LOOPS here and `loop_limit` in hooks.json. If the
remote Acutis server is unreachable the hook fails open rather than deadlocking
the agent, since it could not have verified anything either.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import acutis_common as ac  # noqa: E402

MAX_LOOPS = 3

FOLLOWUP_HEAD = (
    "Security-relevant code was written but not yet verified. "
    "Files needing verification: "
)
FOLLOWUP_TAIL = (
    ". Call the Acutis verify_code MCP tool (server name contains 'acutis') "
    "with the code and a PCST contract. Fix any BLOCK results before completing."
)


def sweep_root(hook_input):
    workspace = hook_input.get("workspace_roots")
    if isinstance(workspace, list):
        for item in workspace:
            root = ac.validated_root(item)
            if root:
                return root
    return ac.validated_root(os.environ.get("CURSOR_PROJECT_DIR", ""))


def written_since(root, started_at_ns):
    """Absolute paths under root whose mtime is after the session start mark,
    or None when the listing is above the cap. Zero trust: the root is
    re-validated here, because a caller-side check does not cross the
    function boundary."""
    top = ac.validated_root(root)
    if not top:
        return []
    rels = ac.list_files(top)
    if rels is None:
        return None
    touched = []
    for rel in rels:
        full = ac.validated_abs_path(os.path.join(top, rel))
        if not full:
            continue
        try:
            stamp = os.stat(full).st_mtime_ns
        except OSError:
            continue
        if stamp > started_at_ns:
            touched.append(full)
    return touched


def uncovered_now(paths, allowed, attested):
    """The subset whose content on disk has no verify_code ALLOW behind it."""
    found = []
    for path in paths:
        target = ac.validated_abs_path(path)
        if not target:
            continue
        if ac.file_covered(target, allowed, attested):
            continue
        found.append(target)
    return found


def main():
    hook_input = ac.read_hook_input()
    if hook_input is None:
        ac.emit({})
        return 0
    loop_count = hook_input.get("loop_count", 0)
    if isinstance(loop_count, int) and loop_count >= MAX_LOOPS:
        ac.emit({})
        return 0
    started = ac.read_session_start(hook_input)
    state = ac.load_sweep_state(hook_input)
    allowed = ac.load_allowed(hook_input)
    candidates = ac.merge_paths(state["pending"], [])
    root = sweep_root(hook_input)
    if root and started:
        touched = written_since(root, started)
        if touched is None:
            ac.note("stop sweep: listing above the snapshot cap; sweep skipped")
        else:
            candidates = ac.merge_paths(candidates, touched)
    uncovered = uncovered_now(candidates, allowed, state["attested"])
    if not uncovered:
        ac.emit({})
        return 0
    if not ac.acutis_reachable():
        ac.note("stop sweep: mcp.acutis.dev unreachable; allowing the stop")
        ac.emit({})
        return 0
    state["pending"] = []
    ac.save_sweep_state(hook_input, state)
    names = ac.one_line(", ".join(sorted({os.path.basename(path) for path in uncovered})))
    ac.emit({"followup_message": FOLLOWUP_HEAD + names + FOLLOWUP_TAIL})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - a backstop must never break the turn
        print("acutis stop sweep: internal error " + ac.one_line(repr(exc)), file=sys.stderr)
        sys.exit(0)
