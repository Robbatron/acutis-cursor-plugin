"""Tests for the Acutis pre-write gate (pre-tool-use.py) and the ALLOW ledger
recorder (verification-allow-tracker.py). Stdlib + pytest only; no network."""

import contextlib
import json
import os
import subprocess

import pytest

from conftest import load, repo_dir, run, seed_ledger, write_file

CID = "conv-abc_123"

FUNC = "def greet(name):\n    return 'hi ' + name\n"
WHOLE = "import os\n\n" + FUNC + "\n\nprint(greet('x'))\n"
FRAGMENT = "return 'hi ' + name"
OTHER = "def other():\n    return 2\n"

DENY_HEAD = "Acutis: "
DENY_TAIL = (
    " has no verify_code ALLOW for this exact text. Verify this code with a "
    "PCST contract, then re-issue the write with the verified text "
    "byte-for-byte."
)
SWEEP_TAIL = (
    " changed during that command without a verify_code ALLOW covering their "
    "new content. Verify each file's final text with verify_code now (format "
    "first, then verify), or revert the change."
)


@pytest.fixture
def gate(common):
    return load("pre-tool-use")


@pytest.fixture
def tracker(common):
    return load("verification-allow-tracker")


def write_event(file_path, **tool_input):
    tool_input.setdefault("file_path", file_path)
    return {
        "tool_name": "Write",
        "tool_input": tool_input,
        "tool_use_id": "t1",
        "conversation_id": CID,
        "generation_id": "g1",
        "cwd": "/work",
        "transcript_path": None,
    }


def mcp_response(decision, extra=""):
    inner = json.dumps({"decision": decision, "rationale": "r" + extra, "violations": []})
    return json.dumps({"content": [{"type": "text", "text": inner}], "isError": False})


def allow_event(code=FUNC, **overrides):
    event = {
        "tool_name": "mcp__acutis__verify_code",
        "tool_input": {"code": code, "language": "python"},
        "conversation_id": CID,
        "result_json": mcp_response("ALLOW"),
    }
    event.update(overrides)
    return event


def ledger(common):
    return common.load_allowed({"conversation_id": CID})


def sweep_state(common):
    return common.load_sweep_state({"conversation_id": CID})


def corrupt_ledger(common):
    path = common.ledger_path_for({"conversation_id": CID})
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("{not json")


# ---------------------------------------------------------------- gate: allows


def test_ledger_hit_allows(gate, common, capsys):
    seed_ledger(common, CID, [FUNC])
    rc, out, err = run(gate, capsys, write_event("/work/app.py", content=FUNC))
    assert rc == 0
    assert out == {"permission": "allow"}


def test_whitespace_reflow_allows(gate, common, capsys):
    seed_ledger(common, CID, [FUNC])
    rewrapped = "def greet(name):\n        return 'hi ' + name\n\n"
    rc, out, err = run(gate, capsys, write_event("/work/app.py", content=rewrapped))
    assert out == {"permission": "allow"}


def test_fragment_in_verified_allows(gate, common, capsys):
    seed_ledger(common, CID, [WHOLE])
    rc, out, err = run(gate, capsys, write_event("/work/app.py", new_string=FRAGMENT))
    assert out == {"permission": "allow"}


def test_edits_list_all_covered_allows(gate, common, capsys):
    seed_ledger(common, CID, [WHOLE])
    edits = [{"new_string": FRAGMENT}, {"new_string": "import os"}]
    rc, out, err = run(gate, capsys, write_event("/work/app.py", edits=edits))
    assert out == {"permission": "allow"}


def test_tool_input_as_json_string(gate, common, capsys):
    seed_ledger(common, CID, [FUNC])
    event = write_event("/work/app.py", content=FUNC)
    event["tool_input"] = json.dumps(event["tool_input"])
    rc, out, err = run(gate, capsys, event)
    assert out == {"permission": "allow"}


def test_relative_path_resolved_against_cwd(gate, common, capsys):
    seed_ledger(common, CID, [FUNC])
    rc, out, err = run(gate, capsys, write_event("src/app.py", content=FUNC))
    assert out == {"permission": "allow"}


def test_non_security_path_allows_without_ledger(gate, common, capsys):
    rc, out, err = run(gate, capsys, write_event("/work/notes.md", content="hi"))
    assert out == {"permission": "allow"}


def test_java_is_security_relevant(gate, common, capsys):
    rc, out, err = run(gate, capsys, write_event("/work/App.java", content="class App {}"))
    assert out["permission"] == "deny"
    assert out["agent_message"] == DENY_HEAD + "App.java" + DENY_TAIL


def test_non_write_tool_passes_through(gate, common, capsys):
    event = write_event("/work/app.py", content=FUNC)
    event["tool_name"] = "Read"
    rc, out, err = run(gate, capsys, event)
    assert out == {"permission": "allow"}
    assert "is not Write" in err


def test_health_failure_allows_with_stderr_note(gate, offline, capsys):
    rc, out, err = run(gate, capsys, write_event("/work/app.py", content=FUNC))
    assert out == {"permission": "allow"}
    assert "unreachable" in err


def test_allow_attests_the_written_text(gate, common, capsys, project):
    target = write_file(project, "app.py", FUNC)
    seed_ledger(common, CID, [FUNC])
    rc, out, err = run(gate, capsys, write_event(target, content=FUNC))
    assert out == {"permission": "allow"}
    assert sweep_state(common)["attested"][target] == common.content_hash(common.normalize(FUNC))


# ---------------------------------------------------------------- gate: denies


def test_whole_file_with_only_function_verified_denies(gate, common, capsys):
    seed_ledger(common, CID, [FUNC])
    rc, out, err = run(gate, capsys, write_event("/work/app.py", content=WHOLE))
    assert out["permission"] == "deny"


def test_one_comma_divergence_denies(gate, common, capsys):
    seed_ledger(common, CID, [FUNC])
    drifted = FUNC.replace("'hi '", "'hi, '")
    rc, out, err = run(gate, capsys, write_event("/work/app.py", content=drifted))
    assert out["permission"] == "deny"


def test_edits_list_one_uncovered_denies(gate, common, capsys):
    seed_ledger(common, CID, [WHOLE])
    edits = [{"new_string": FRAGMENT}, {"new_string": "os.system('rm -rf /')"}]
    rc, out, err = run(gate, capsys, write_event("/work/app.py", edits=edits))
    assert out["permission"] == "deny"


def test_empty_content_denies(gate, common, capsys):
    rc, out, err = run(gate, capsys, write_event("/work/app.py", content="   "))
    assert out["permission"] == "deny"


def test_unknown_input_shape_denies_and_logs_keys(gate, common, capsys):
    rc, out, err = run(gate, capsys, write_event("/work/app.py", mystery_blob=FUNC, other=1))
    assert out["permission"] == "deny"
    assert out["agent_message"] == DENY_HEAD + "app.py" + DENY_TAIL
    assert "file_path, mystery_blob, other" in err


def test_deny_json_shape_exact(gate, common, capsys):
    rc, out, err = run(gate, capsys, write_event("/work/app.py", content=FUNC))
    assert rc == 0
    assert list(out.keys()) == ["permission", "user_message", "agent_message"]
    assert out == {
        "permission": "deny",
        "user_message": "Acutis: write to app.py blocked until a verify_code ALLOW covers the exact text.",
        "agent_message": DENY_HEAD + "app.py" + DENY_TAIL,
    }


def test_other_conversation_ledger_does_not_count(gate, common, capsys):
    seed_ledger(common, "someone-else", [FUNC])
    rc, out, err = run(gate, capsys, write_event("/work/app.py", content=FUNC))
    assert out["permission"] == "deny"


def test_corrupt_ledger_denies(gate, common, capsys):
    corrupt_ledger(common)
    rc, out, err = run(gate, capsys, write_event("/work/app.py", content=FUNC))
    assert out["permission"] == "deny"


def test_unparseable_hook_input_denies(gate, common, capsys):
    rc, out, err = run(gate, capsys, "{not json")
    assert out["permission"] == "deny"
    assert "fail closed" in err


def test_parked_sweep_finding_denies_once(gate, common, capsys, project):
    target = write_file(project, "src/app.py", FUNC)
    state = sweep_state(common)
    state["pending"] = [target]
    common.save_sweep_state({"conversation_id": CID}, state)
    seed_ledger(common, CID, [OTHER])
    rc, out, err = run(gate, capsys, write_event("/work/other.py", content=OTHER))
    assert out["permission"] == "deny"
    assert out["agent_message"] == "Acutis: app.py" + SWEEP_TAIL
    rc, out, err = run(gate, capsys, write_event("/work/other.py", content=OTHER))
    assert out == {"permission": "allow"}


def test_parked_finding_already_covered_does_not_deny(gate, common, capsys, project):
    target = write_file(project, "src/app.py", FUNC)
    state = sweep_state(common)
    state["pending"] = [target]
    common.save_sweep_state({"conversation_id": CID}, state)
    seed_ledger(common, CID, [FUNC, OTHER])
    rc, out, err = run(gate, capsys, write_event("/work/other.py", content=OTHER))
    assert out == {"permission": "allow"}


# ------------------------------------------------------- conversation_id checks


@pytest.mark.parametrize("bad", ["../../etc/passwd", "abc/def", "a b", "", None, "x.y"])
def test_conversation_id_validation(common, bad):
    fallback = os.path.join(common.STATE_DIR, common.LEDGER_FALLBACK)
    assert common.ledger_path_for({"conversation_id": bad}) == fallback
    assert common.validated_conversation_id(bad) == ""


def test_conversation_id_valid_builds_scoped_path(common):
    expected = os.path.join(common.STATE_DIR, common.LEDGER_PREFIX + "Conv-1_A.json")
    assert common.ledger_path_for({"conversation_id": "Conv-1_A"}) == expected


# ------------------------------------------------------------------ recorder


def test_recorder_records_allow_from_result_json_string(tracker, common, capsys):
    rc, out, err = run(tracker, capsys, allow_event())
    assert out == {}
    assert ledger(common) == [common.normalize(FUNC)]


def test_recorder_handles_dict_result(tracker, common, capsys):
    event = allow_event()
    event["result_json"] = None
    event["tool_output"] = {"decision": "ALLOW"}
    rc, out, err = run(tracker, capsys, event)
    assert ledger(common) == [common.normalize(FUNC)]


def test_recorder_handles_content_list_result(tracker, common, capsys):
    event = allow_event()
    event["result_json"] = None
    event["tool_output"] = {"content": [{"text": '{"decision": "ALLOW"}'}]}
    rc, out, err = run(tracker, capsys, event)
    assert ledger(common) == [common.normalize(FUNC)]


@pytest.mark.parametrize("result", [
    mcp_response("BLOCK_VIOLATION"),
    mcp_response("BLOCK_INCOMPLETE", " iterate until ALLOW"),
    '{"note": "nothing here"}',
])
def test_recorder_ignores_block_and_non_verdict_results(tracker, common, capsys, result):
    rc, out, err = run(tracker, capsys, allow_event(result_json=result))
    assert ledger(common) == []


def test_recorder_ignores_other_tools(tracker, common, capsys):
    rc, out, err = run(tracker, capsys, allow_event(tool_name="Shell"))
    assert ledger(common) == []


def test_recorder_ignores_missing_code(tracker, common, capsys):
    event = allow_event()
    event["tool_input"] = {"language": "python"}
    rc, out, err = run(tracker, capsys, event)
    assert ledger(common) == []


def test_recorder_dedups_and_caps(tracker, common, capsys):
    original = common.LEDGER_CAP
    common.LEDGER_CAP = 3
    try:
        run(tracker, capsys, allow_event(code="x = 0\n"))
        run(tracker, capsys, allow_event(code="x = 1\n"))
        run(tracker, capsys, allow_event(code="x = 2\n"))
        run(tracker, capsys, allow_event(code="x = 3\n"))
        run(tracker, capsys, allow_event(code="x = 4\n"))
        run(tracker, capsys, allow_event(code="x = 4\n"))
    finally:
        common.LEDGER_CAP = original
    assert ledger(common) == ["x=2", "x=3", "x=4"]


def test_recorder_survives_corrupt_ledger(tracker, common, capsys):
    corrupt_ledger(common)
    rc, out, err = run(tracker, capsys, allow_event())
    assert ledger(common) == [common.normalize(FUNC)]


def test_recorder_then_gate_allows_exact_and_denies_drift(gate, tracker, common, capsys):
    run(tracker, capsys, allow_event())
    rc, out, err = run(gate, capsys, write_event("/work/app.py", content=FUNC))
    assert out == {"permission": "allow"}
    rc, out, err = run(gate, capsys, write_event("/work/app.py", content=FUNC + "x = 1\n"))
    assert out["permission"] == "deny"


# ----------------------------------------------------------- end to end (sh)
# The wrapper runs in its own process against the real state directory, so it
# is exercised with literal argv, literal stdin and literal state paths, and
# cleans up after itself.

WRAPPER_CID = "pytest-wrapper-ledger-hit"
WRAPPER_LEDGER = "/tmp/acutis-allow-cursor-pytest-wrapper-ledger-hit.json"
WRAPPER_SWEEP = "/tmp/acutis-sweep-cursor-pytest-wrapper-ledger-hit.json"
WRAPPER_SESSION = "/tmp/acutis-session-start-cursor-pytest-wrapper-ledger-hit.json"


def clean_wrapper_state():
    """Remove this test's own state files. Literal paths only."""
    with contextlib.suppress(OSError):
        os.remove(WRAPPER_LEDGER)
    with contextlib.suppress(OSError):
        os.remove(WRAPPER_SWEEP)
    with contextlib.suppress(OSError):
        os.remove(WRAPPER_SESSION)


def gate_wrapper():
    return os.path.join(repo_dir(), "scripts", "pre-tool-use.sh")


def test_wrapper_non_security_path_allows():
    event = json.dumps({
        "tool_name": "Write",
        "tool_input": {"file_path": "/work/notes.md", "content": "x"},
        "conversation_id": "pytest-wrapper",
    })
    proc = subprocess.run(
        ["bash", gate_wrapper()],
        input=event,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == {"permission": "allow"}


def test_wrapper_unparseable_input_denies():
    proc = subprocess.run(
        ["bash", gate_wrapper()],
        input="{oops",
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["permission"] == "deny"


def test_wrapper_ledger_hit_allows_real_path():
    clean_wrapper_state()
    with open(WRAPPER_LEDGER, "w", encoding="utf-8") as handle:
        handle.write(json.dumps({"allowed": ["".join(FUNC.split())]}))
    event = json.dumps({
        "tool_name": "Write",
        "tool_input": {"file_path": "/work/app.py", "content": FUNC},
        "conversation_id": WRAPPER_CID,
    })
    try:
        proc = subprocess.run(
            ["bash", gate_wrapper()],
            input=event,
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        clean_wrapper_state()
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == {"permission": "allow"}
    assert proc.stderr == ""
