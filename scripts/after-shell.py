#!/usr/bin/env python3
"""
Acutis post-shell sweep (Cursor `afterShellExecution`).

`before-shell.py` snapshots the project's security-relevant files before the
command runs. This hook rebuilds that listing, diffs it against the snapshot,
deletes the snapshot, and checks every changed code file against the ALLOW
ledger and the pre-write gate's attestations. A file whose current content has
no verify_code ALLOW behind it is a formatter or generator rewrite: under the
format-then-verify policy the model must verify that file's final text.

Delivery: Cursor documents NO output fields for `afterShellExecution` (only its
input schema), so nothing written here reaches the agent. The finding is
therefore persisted in the conversation's sweep state, where the next
`preToolUse` gate surfaces it as a deny and the `stop` sweep re-derives it from
the filesystem, and it is echoed to the Hooks output channel on stderr.

Availability: the health check runs only when a message is due, and an
unreachable server parks the finding in `fail_open` instead of reporting it
(the same fail-open policy as the pre-write gate and the stop sweep). A missing
snapshot is a no-op with a stderr note: nothing was recorded, so nothing is
claimed.

Contract note: the state accessors take the hook-input dict, never a path. The
path is derived inside them from a charset-validated conversation id, so the
dict argument is declared `Content` on a FileSystemPath sink rather than
recategorized.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import acutis_common as ac  # noqa: E402


def load_snapshot(hook_input, command):
    """(root, files) for this command, ('', {}) when there is no snapshot.

    The snapshot is consumed: it is deleted as soon as it is read, so a crashed
    or denied command cannot leave the next sweep working from a stale tree.
    """
    path = ac.snapshot_path_for(hook_input, ac.call_id_for(command))
    if not path:
        ac.note("post-shell sweep: no conversation id; nothing to sweep")
        return "", {}
    snapshot = ac.load_json(path)
    ac.remove_file(path)
    if not isinstance(snapshot, dict):
        ac.note("post-shell sweep: no snapshot for this command; nothing to sweep")
        return "", {}
    files = snapshot.get("files")
    if not isinstance(files, dict):
        files = {}
    return snapshot.get("root"), files


def uncovered_paths(root, changed, allowed, attested):
    """Absolute paths among `changed` whose current content has no ALLOW."""
    found = []
    for rel in changed:
        full = ac.validated_abs_path(os.path.join(root, rel))
        if not full:
            continue
        if not ac.file_covered(full, allowed, attested):
            found.append(full)
    return found


def main():
    hook_input = ac.read_hook_input()
    if hook_input is None:
        ac.note("post-shell sweep: unparseable hook input; nothing to sweep")
        ac.emit({})
        return 0
    ac.ensure_session_start(hook_input)
    command = str(hook_input.get("command") or "")
    raw_root, before = load_snapshot(hook_input, command)
    root = ac.validated_root(raw_root)
    if not root:
        ac.emit({})
        return 0
    after = ac.take_snapshot(root)
    if after is None:
        ac.note("post-shell sweep: listing above the snapshot cap; sweep skipped")
        ac.emit({})
        return 0
    changed = ac.changed_files(before, after)
    if not changed:
        ac.emit({})
        return 0
    state = ac.load_sweep_state(hook_input)
    uncovered = uncovered_paths(root, changed, ac.load_allowed(hook_input), state["attested"])
    if not uncovered:
        ac.emit({})
        return 0
    if not ac.acutis_reachable():
        state["fail_open"] = ac.merge_paths(state["fail_open"], uncovered)
        ac.save_sweep_state(hook_input, state)
        ac.note("post-shell sweep: mcp.acutis.dev unreachable; parking the finding")
        ac.emit({})
        return 0
    state["pending"] = ac.merge_paths(state["pending"], uncovered)
    ac.save_sweep_state(hook_input, state)
    message = ac.one_line(ac.sweep_message(uncovered))
    ac.note(message)
    ac.emit({})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - observational hook, never break the turn
        print("acutis post-shell sweep: internal error " + ac.one_line(repr(exc)), file=sys.stderr)
        sys.exit(0)
