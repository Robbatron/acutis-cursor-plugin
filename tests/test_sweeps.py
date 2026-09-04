"""Tests for the two Acutis sweeps: the post-shell sweep (after-shell.py) that
diffs the snapshot the shell gate took, and the silent stop sweep
(stop-hook.py). Stdlib + pytest only; no network."""

import pytest

from conftest import load, run, seed_ledger, write_file

CID = "conv-sweep_1"

SWEEP_TAIL = (
    " changed during that command without a verify_code ALLOW covering their "
    "new content. Verify each file's final text with verify_code now (format "
    "first, then verify), or revert the change."
)
FOLLOWUP_HEAD = (
    "Security-relevant code was written but not yet verified. "
    "Files needing verification: "
)
FOLLOWUP_TAIL = (
    ". Call the Acutis verify_code MCP tool (server name contains 'acutis') "
    "with the code and a PCST contract. Fix any BLOCK results before completing."
)

BEFORE = "def greet(name):\n    return 'hi ' + name\n"
AFTER = "def greet(name: str) -> str:\n    return 'hi ' + name\n\n\nX = 1\n"


@pytest.fixture
def gate(common):
    return load("before-shell")


@pytest.fixture
def sweep(common):
    return load("after-shell")


@pytest.fixture
def stop(common):
    return load("stop-hook")


def before_event(command, root):
    return {
        "hook_event_name": "beforeShellExecution",
        "conversation_id": CID,
        "command": command,
        "cwd": root,
        "workspace_roots": [root],
    }


def after_event(command, root):
    """afterShellExecution carries no cwd; the root comes from the snapshot."""
    return {
        "hook_event_name": "afterShellExecution",
        "conversation_id": CID,
        "command": command,
        "output": "",
        "duration": 5,
        "sandbox": False,
        "workspace_roots": [root],
    }


def stop_event(root, loop_count=0):
    return {
        "hook_event_name": "stop",
        "conversation_id": CID,
        "status": "completed",
        "loop_count": loop_count,
        "workspace_roots": [root],
    }


def set_session_start(common, started_at_ns):
    path = common.session_start_path_for({"conversation_id": CID})
    common.write_json_atomic(path, {"started_at_ns": started_at_ns})


def sweep_state(common):
    return common.load_sweep_state({"conversation_id": CID})


def snapshot_for(common, command):
    path = common.snapshot_path_for({"conversation_id": CID}, common.call_id_for(command))
    return common.load_json(path)


def formatted(gate, sweep, common, capsys, project, command="ruff format ."):
    """Snapshot, rewrite src/app.py behind the gate's back, then sweep."""
    write_file(project, "src/app.py", BEFORE)
    run(gate, capsys, before_event(command, project))
    write_file(project, "src/app.py", AFTER)
    return run(sweep, capsys, after_event(command, project))


def test_uncovered_change_is_parked_and_logged(gate, sweep, common, capsys, project):
    rc, out, err = formatted(gate, sweep, common, capsys, project)
    assert rc == 0
    assert out == {}
    pending = sweep_state(common)["pending"]
    assert [p.endswith("src/app.py") for p in pending] == [True]
    assert "Acutis: app.py" + SWEEP_TAIL in err


def test_covered_change_is_not_reported(gate, sweep, common, capsys, project):
    seed_ledger(common, CID, [AFTER])
    rc, out, err = formatted(gate, sweep, common, capsys, project)
    assert out == {}
    assert sweep_state(common)["pending"] == []
    assert "changed during that command" not in err


def test_unchanged_tree_reports_nothing(gate, sweep, common, capsys, project):
    write_file(project, "src/app.py", BEFORE)
    command = "pytest -q"
    run(gate, capsys, before_event(command, project))
    rc, out, err = run(sweep, capsys, after_event(command, project))
    assert out == {}
    assert sweep_state(common)["pending"] == []


def test_new_file_is_reported(gate, sweep, common, capsys, project):
    command = "npx create-thing"
    run(gate, capsys, before_event(command, project))
    write_file(project, "src/generated.ts", "export const x = 1;\n")
    rc, out, err = run(sweep, capsys, after_event(command, project))
    assert "Acutis: generated.ts" + SWEEP_TAIL in err


def test_snapshot_is_consumed(gate, sweep, common, capsys, project):
    command = "ruff format ."
    write_file(project, "src/app.py", BEFORE)
    run(gate, capsys, before_event(command, project))
    assert snapshot_for(common, command) is not None
    run(sweep, capsys, after_event(command, project))
    assert snapshot_for(common, command) is None


def test_missing_snapshot_is_a_no_op(sweep, common, capsys, project):
    rc, out, err = run(sweep, capsys, after_event("ls", project))
    assert rc == 0
    assert out == {}
    assert "no snapshot for this command" in err
    assert sweep_state(common)["pending"] == []


def test_unparseable_input_is_a_no_op(sweep, common, capsys):
    rc, out, err = run(sweep, capsys, "{not json")
    assert out == {}
    assert "unparseable hook input" in err


def test_offline_parks_the_finding_without_reporting(gate, sweep, offline, capsys, project):
    rc, out, err = formatted(gate, sweep, offline, capsys, project)
    state = sweep_state(offline)
    assert state["pending"] == []
    assert [p.endswith("src/app.py") for p in state["fail_open"]] == [True]
    assert "unreachable" in err
    assert "changed during that command" not in err


def test_attested_file_is_not_reflagged(gate, sweep, common, capsys, project):
    command = "ruff format ."
    write_file(project, "src/app.py", BEFORE)
    run(gate, capsys, before_event(command, project))
    target = write_file(project, "src/app.py", AFTER)
    state = sweep_state(common)
    state["attested"] = {target: common.content_hash(common.normalize(AFTER))}
    common.save_sweep_state({"conversation_id": CID}, state)
    rc, out, err = run(sweep, capsys, after_event(command, project))
    assert sweep_state(common)["pending"] == []
    assert "changed during that command" not in err


def test_stop_is_silent_without_a_session_mark(stop, common, capsys, project):
    write_file(project, "src/app.py", AFTER)
    rc, out, err = run(stop, capsys, stop_event(project))
    assert rc == 0
    assert out == {}


def test_stop_reports_an_uncovered_file(stop, common, capsys, project):
    set_session_start(common, 1)
    write_file(project, "src/app.py", AFTER)
    rc, out, err = run(stop, capsys, stop_event(project))
    assert out == {"followup_message": FOLLOWUP_HEAD + "app.py" + FOLLOWUP_TAIL}


def test_stop_is_silent_when_covered(stop, common, capsys, project):
    set_session_start(common, 1)
    seed_ledger(common, CID, [AFTER])
    write_file(project, "src/app.py", AFTER)
    rc, out, err = run(stop, capsys, stop_event(project))
    assert out == {}


def test_stop_ignores_files_older_than_the_session(stop, common, capsys, project):
    write_file(project, "src/app.py", AFTER)
    set_session_start(common, 2 ** 62)
    rc, out, err = run(stop, capsys, stop_event(project))
    assert out == {}


def test_stop_respects_the_loop_guard(stop, common, capsys, project):
    set_session_start(common, 1)
    write_file(project, "src/app.py", AFTER)
    rc, out, err = run(stop, capsys, stop_event(project, loop_count=3))
    assert out == {}


def test_stop_fails_open_when_offline(stop, offline, capsys, project):
    set_session_start(offline, 1)
    write_file(project, "src/app.py", AFTER)
    rc, out, err = run(stop, capsys, stop_event(project))
    assert out == {}
    assert "unreachable" in err


def test_stop_surfaces_a_parked_sweep_finding(stop, common, capsys, project):
    set_session_start(common, 2 ** 62)
    target = write_file(project, "src/app.py", AFTER)
    state = sweep_state(common)
    state["pending"] = [target]
    common.save_sweep_state({"conversation_id": CID}, state)
    rc, out, err = run(stop, capsys, stop_event(project))
    assert out == {"followup_message": FOLLOWUP_HEAD + "app.py" + FOLLOWUP_TAIL}
    assert sweep_state(common)["pending"] == []


def test_tracker_clears_a_parked_finding_on_allow(common, capsys, project):
    tracker = load("verification-allow-tracker")
    target = write_file(project, "src/app.py", AFTER)
    state = sweep_state(common)
    state["pending"] = [target]
    common.save_sweep_state({"conversation_id": CID}, state)
    event = {
        "conversation_id": CID,
        "tool_name": "mcp__acutis__verify_code",
        "tool_input": {"code": AFTER, "language": "python"},
        "result_json": '{"decision": "ALLOW"}',
    }
    rc, out, err = run(tracker, capsys, event)
    assert out == {}
    assert sweep_state(common)["pending"] == []
    assert common.normalize(AFTER) in common.load_allowed({"conversation_id": CID})
