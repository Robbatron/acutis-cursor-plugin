"""Tests for the Acutis pre-write gate (pre-tool-use.py) and the ALLOW ledger
recorder (verification-allow-tracker.py). Stdlib + pytest only; no network."""

import importlib.util
import io
import json
import os
import subprocess

import pytest

CID = "conv-abc_123"

FUNC = "def greet(name):\n    return 'hi ' + name\n"
WHOLE = "import os\n\n" + FUNC + "\n\nprint(greet('x'))\n"
FRAGMENT = "return 'hi ' + name"

DENY_REASON = (
    "Acutis: no verify_code ALLOW covers this exact text for app.py. Call "
    "mcp__acutis__verify_code with this exact code and a PCST contract (sources, "
    "sinks, transforms); on ALLOW, re-issue the write with the verified text "
    "byte-for-byte. Acutis verifies generated code output, never a file."
)


def _repo_dir() -> str:
    """Guard-and-reject: the plugin checkout that owns this test file."""
    d = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.isfile(os.path.join(d, "hooks", "hooks.json")):
        raise RuntimeError("tests must run from the acutis-cursor-plugin checkout")
    return d


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), os.path.join(_repo_dir(), "scripts", name + ".py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _read_ledger(mod, cid: str):
    with open(mod.ledger_path_for({"conversation_id": cid}), encoding="utf-8") as f:
        return json.load(f)


def _write_ledger(mod, cid: str, data) -> None:
    with open(mod.ledger_path_for({"conversation_id": cid}), "w", encoding="utf-8") as f:
        json.dump(data, f)


def _write_ledger_raw(mod, cid: str, raw: str) -> None:
    with open(mod.ledger_path_for({"conversation_id": cid}), "w", encoding="utf-8") as f:
        f.write(raw)


def _ledger_exists(mod, cid: str) -> bool:
    return os.path.exists(mod.ledger_path_for({"conversation_id": cid}))


@pytest.fixture
def gate(monkeypatch, tmp_path):
    mod = _load("pre-tool-use")
    monkeypatch.setattr(mod, "LEDGER_PREFIX", str(tmp_path / "acutis-allow-cursor-"))
    return mod


@pytest.fixture
def online(gate, monkeypatch):
    monkeypatch.setattr(gate, "acutis_reachable", lambda: True)


@pytest.fixture
def tracker(monkeypatch, tmp_path):
    mod = _load("verification-allow-tracker")
    monkeypatch.setattr(mod, "LEDGER_PREFIX", str(tmp_path / "acutis-allow-cursor-"))
    monkeypatch.setattr(mod, "state_file_for", lambda hook_input: str(tmp_path / "state.json"))
    return mod


def seed_ledger(gate, cid: str, codes: list) -> None:
    _write_ledger(gate, cid, {"allowed": [gate.normalize(c) for c in codes]})


def run_gate(gate, monkeypatch, capsys, hook_input):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(hook_input)))
    rc = gate.main()
    captured = capsys.readouterr()
    return rc, json.loads(captured.out), captured.err


def write_event(file_path: str, **tool_input):
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


def run_tracker(tracker, monkeypatch, capsys, hook_input):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(hook_input)))
    with pytest.raises(SystemExit) as exc:
        tracker.main()
    captured = capsys.readouterr()
    assert exc.value.code == 0
    assert json.loads(captured.out) == {}


def mcp_response(decision: str, extra: str = "") -> str:
    inner = json.dumps({"decision": decision, "rationale": "r" + extra, "violations": []})
    return json.dumps({"content": [{"type": "text", "text": inner}], "isError": False})


# ---------------------------------------------------------------- gate: allows


def test_ledger_hit_allows(gate, online, monkeypatch, capsys):
    seed_ledger(gate, CID, [FUNC])
    rewrapped = "def greet(name):\n        return 'hi ' + name\n\n"
    rc, out, err = run_gate(gate, monkeypatch, capsys, write_event("/work/app.py", content=rewrapped))
    assert rc == 0
    assert out == {"permission": "allow"}
    assert err == ""


def test_fragment_in_verified_allows(gate, online, monkeypatch, capsys):
    seed_ledger(gate, CID, [WHOLE])
    event = write_event("/work/app.py", old_string="return name", new_string=FRAGMENT)
    rc, out, err = run_gate(gate, monkeypatch, capsys, event)
    assert out == {"permission": "allow"}


def test_edits_list_all_covered_allows(gate, online, monkeypatch, capsys):
    seed_ledger(gate, CID, [WHOLE])
    event = write_event(
        "/work/app.py",
        edits=[{"old_string": "a", "new_string": FRAGMENT}, {"old_string": "b", "new_string": "import os"}],
    )
    rc, out, err = run_gate(gate, monkeypatch, capsys, event)
    assert out == {"permission": "allow"}


def test_tool_input_as_json_string(gate, online, monkeypatch, capsys):
    seed_ledger(gate, CID, [FUNC])
    event = write_event("/work/app.py", content=FUNC)
    event["tool_input"] = json.dumps(event["tool_input"])
    rc, out, err = run_gate(gate, monkeypatch, capsys, event)
    assert out == {"permission": "allow"}


def test_relative_path_resolved_against_cwd(gate, online, monkeypatch, capsys):
    seed_ledger(gate, CID, [FUNC])
    rc, out, err = run_gate(gate, monkeypatch, capsys, write_event("src/app.py", content=FUNC))
    assert out == {"permission": "allow"}
    rc, out, err = run_gate(gate, monkeypatch, capsys, write_event("src/app.py", content=WHOLE))
    assert out["permission"] == "deny"


def test_non_security_path_allows_without_ledger_or_health(gate, monkeypatch, capsys):
    def boom():
        raise AssertionError("health check must not run for non-security paths")

    monkeypatch.setattr(gate, "acutis_reachable", boom)
    for path in (
        "/work/README.md",
        "/work/node_modules/pkg/index.js",
        "/work/.venv/lib/site.py",
        "/private/tmp/claude-501/abc/def/scratchpad/probe.py",
        "/tmp/claude-501/x/scratchpad/nested/probe.ts",
        "/work/package-lock.json",
    ):
        rc, out, err = run_gate(gate, monkeypatch, capsys, write_event(path, content="anything"))
        assert out == {"permission": "allow"}, path


def test_non_write_tool_passes_through(gate, monkeypatch, capsys):
    event = write_event("/work/app.py")
    event["tool_name"] = "Read"
    rc, out, err = run_gate(gate, monkeypatch, capsys, event)
    assert out == {"permission": "allow"}
    assert "not Write" in err


def test_health_failure_allows_with_stderr_note(gate, monkeypatch, capsys):
    def unreachable(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(gate.urllib.request, "urlopen", unreachable)
    rc, out, err = run_gate(gate, monkeypatch, capsys, write_event("/work/app.py", content=FUNC))
    assert out == {"permission": "allow"}
    assert "unreachable" in err
    assert "app.py" in err


# ---------------------------------------------------------------- gate: denies


def test_whole_file_with_only_function_verified_denies(gate, online, monkeypatch, capsys):
    seed_ledger(gate, CID, [FUNC])
    rc, out, err = run_gate(gate, monkeypatch, capsys, write_event("/work/app.py", content=WHOLE))
    assert out["permission"] == "deny"
    assert out["agent_message"] == DENY_REASON


def test_one_comma_divergence_denies(gate, online, monkeypatch, capsys):
    seed_ledger(gate, CID, [FUNC])
    diverged = FUNC.replace("'hi '", "'hi,'")
    rc, out, err = run_gate(gate, monkeypatch, capsys, write_event("/work/app.py", content=diverged))
    assert out["permission"] == "deny"


def test_edits_list_one_uncovered_denies(gate, online, monkeypatch, capsys):
    seed_ledger(gate, CID, [WHOLE])
    event = write_event(
        "/work/app.py",
        edits=[{"old_string": "a", "new_string": FRAGMENT}, {"old_string": "b", "new_string": "import sys"}],
    )
    rc, out, err = run_gate(gate, monkeypatch, capsys, event)
    assert out["permission"] == "deny"


def test_empty_content_denies(gate, online, monkeypatch, capsys):
    seed_ledger(gate, CID, [FUNC])
    rc, out, err = run_gate(gate, monkeypatch, capsys, write_event("/work/app.py", content=""))
    assert out["permission"] == "deny"
    assert out["agent_message"].startswith(DENY_REASON)
    assert "empty" in out["agent_message"]


def test_unknown_input_shape_denies_and_logs_keys(gate, online, monkeypatch, capsys):
    seed_ledger(gate, CID, [FUNC])
    event = write_event("/work/app.py", mystery_blob="x", other=1)
    rc, out, err = run_gate(gate, monkeypatch, capsys, event)
    assert out["permission"] == "deny"
    assert out["agent_message"].startswith(DENY_REASON)
    assert "mystery_blob" in out["agent_message"]
    assert "keys=[" in err
    assert "file_path, mystery_blob, other" in err


def test_deny_json_shape_exact(gate, online, monkeypatch, capsys):
    rc, out, err = run_gate(gate, monkeypatch, capsys, write_event("/work/app.py", content=FUNC))
    assert rc == 0
    assert list(out.keys()) == ["permission", "user_message", "agent_message"]
    assert out == {
        "permission": "deny",
        "user_message": "Acutis: write to app.py blocked until a verify_code ALLOW covers the exact text.",
        "agent_message": DENY_REASON,
    }


def test_other_conversation_ledger_does_not_count(gate, online, monkeypatch, capsys):
    seed_ledger(gate, "someone-else", [FUNC])
    rc, out, err = run_gate(gate, monkeypatch, capsys, write_event("/work/app.py", content=FUNC))
    assert out["permission"] == "deny"


def test_corrupt_ledger_denies(gate, online, monkeypatch, capsys):
    _write_ledger_raw(gate, CID, "{not json")
    rc, out, err = run_gate(gate, monkeypatch, capsys, write_event("/work/app.py", content=FUNC))
    assert out["permission"] == "deny"


def test_unparseable_hook_input_denies(gate, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("{not json"))
    rc = gate.main()
    out = json.loads(capsys.readouterr().out)
    assert out["permission"] == "deny"


# ------------------------------------------------------- conversation_id checks


@pytest.mark.parametrize("bad", ["../../etc/passwd", "abc/def", "a b", "", None, "x.y"])
def test_conversation_id_validation_gate(gate, bad):
    assert gate.ledger_path_for({"conversation_id": bad}) == "/tmp/acutis-allow-cursor.json"


@pytest.mark.parametrize("bad", ["../../etc/passwd", "abc/def", "a b", "", None, "x.y"])
def test_conversation_id_validation_tracker(tracker, bad):
    assert tracker.ledger_path_for({"conversation_id": bad}) == "/tmp/acutis-allow-cursor.json"


def test_conversation_id_valid_builds_scoped_path(gate, tracker):
    assert gate.ledger_path_for({"conversation_id": "Conv-1_A"}) == gate.LEDGER_PREFIX + "Conv-1_A.json"
    assert tracker.ledger_path_for({"conversation_id": "Conv-1_A"}) == tracker.LEDGER_PREFIX + "Conv-1_A.json"
    assert gate.validated_conversation_id("../x") == ""
    assert tracker.validated_conversation_id("../x") == ""


# ------------------------------------------------------------------ recorder


def allow_event(code=FUNC, **overrides):
    event = {
        "tool_name": "verify_code",
        "mcp_server_name": "acutis",
        "tool_input": json.dumps({"code": code, "language": "python", "contract": {}}),
        "result_json": mcp_response("ALLOW"),
        "conversation_id": CID,
    }
    event.update(overrides)
    return event


def test_recorder_records_allow_from_result_json_string(tracker, monkeypatch, capsys):
    run_tracker(tracker, monkeypatch, capsys, allow_event())
    assert _read_ledger(tracker, CID) == {"allowed": [tracker._normalize(FUNC)]}


def test_recorder_handles_dict_tool_input_and_dict_result(tracker, monkeypatch, capsys):
    event = allow_event()
    event["tool_input"] = {"code": FUNC, "language": "python"}
    del event["result_json"]
    event["tool_output"] = {"content": [{"type": "text", "text": '{"decision": "ALLOW"}'}]}
    run_tracker(tracker, monkeypatch, capsys, event)
    assert _read_ledger(tracker, CID)["allowed"] == [tracker._normalize(FUNC)]


def test_recorder_handles_top_level_decision_dict(tracker, monkeypatch, capsys):
    event = allow_event()
    event["tool_input"] = {"code": FUNC}
    del event["result_json"]
    event["tool_output"] = {"decision": "ALLOW"}
    run_tracker(tracker, monkeypatch, capsys, event)
    assert _ledger_exists(tracker, CID)


@pytest.mark.parametrize(
    "result",
    [
        mcp_response("BLOCK_VIOLATION", " iterate until ALLOW"),
        mcp_response("BLOCK_INCOMPLETE", " until ALLOW"),
        json.dumps({"content": [{"type": "text", "text": "ALLOW"}]}),
        "ALLOW",
        "",
    ],
)
def test_recorder_ignores_block_and_non_verdict_results(tracker, monkeypatch, capsys, result):
    run_tracker(tracker, monkeypatch, capsys, allow_event(result_json=result))
    assert not _ledger_exists(tracker, CID)


def test_recorder_ignores_other_tools(tracker, monkeypatch, capsys):
    run_tracker(tracker, monkeypatch, capsys, allow_event(tool_name="Write"))
    assert not _ledger_exists(tracker, CID)


def test_recorder_ignores_missing_code(tracker, monkeypatch, capsys):
    run_tracker(tracker, monkeypatch, capsys, allow_event(tool_input=json.dumps({"language": "python"})))
    assert not _ledger_exists(tracker, CID)


def test_recorder_dedups_caps_and_is_atomic(tracker, monkeypatch, capsys):
    run_tracker(tracker, monkeypatch, capsys, allow_event())
    run_tracker(tracker, monkeypatch, capsys, allow_event())
    assert _read_ledger(tracker, CID)["allowed"] == [tracker._normalize(FUNC)]
    for i in range(205):
        run_tracker(tracker, monkeypatch, capsys, allow_event(code="x = " + str(i) + "\n"))
    allowed = _read_ledger(tracker, CID)["allowed"]
    assert len(allowed) == tracker.LEDGER_CAP
    assert allowed[-1] == "x=204"
    assert tracker._normalize(FUNC) not in allowed
    assert not os.path.exists(tracker.ledger_path_for({"conversation_id": CID}) + ".tmp")


def test_recorder_survives_corrupt_ledger(tracker, monkeypatch, capsys):
    _write_ledger_raw(tracker, CID, "[1, 2")
    run_tracker(tracker, monkeypatch, capsys, allow_event())
    assert _read_ledger(tracker, CID)["allowed"] == [tracker._normalize(FUNC)]


def test_recorder_then_gate_allows_exact_and_denies_drift(gate, tracker, online, monkeypatch, capsys):
    run_tracker(tracker, monkeypatch, capsys, allow_event())
    rc, out, err = run_gate(gate, monkeypatch, capsys, write_event("/work/app.py", content=FUNC))
    assert out == {"permission": "allow"}
    rc, out, err = run_gate(gate, monkeypatch, capsys, write_event("/work/app.py", content=FUNC + "x = 1\n"))
    assert out["permission"] == "deny"


# ----------------------------------------------------------- end to end (sh)
# The wrapper is exercised with literal argv and literal stdin from the repo
# root so nothing computed reaches the shell.

WRAPPER_CID = "pytest-wrapper-ledger-hit"


def test_wrapper_non_security_path_allows(monkeypatch):
    monkeypatch.chdir(_repo_dir())
    proc = subprocess.run(
        ["bash", "scripts/pre-tool-use.sh"],
        input='{"tool_name": "Write", "tool_input": {"file_path": "/work/notes.md", "content": "x"}, "conversation_id": "pytest-wrapper"}',
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == {"permission": "allow"}


def test_wrapper_unparseable_input_denies(monkeypatch):
    monkeypatch.chdir(_repo_dir())
    proc = subprocess.run(
        ["bash", "scripts/pre-tool-use.sh"],
        input="{oops",
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["permission"] == "deny"


def test_wrapper_ledger_hit_allows_real_path(monkeypatch):
    monkeypatch.chdir(_repo_dir())
    gate = _load("pre-tool-use")
    _write_ledger(gate, WRAPPER_CID, {"allowed": [gate.normalize(FUNC)]})
    try:
        proc = subprocess.run(
            ["bash", "scripts/pre-tool-use.sh"],
            input='{"tool_name": "Write", "tool_input": {"file_path": "/work/app.py", "content": "def greet(name):\\n    return \'hi \' + name\\n"}, "conversation_id": "pytest-wrapper-ledger-hit"}',
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        os.remove(gate.ledger_path_for({"conversation_id": WRAPPER_CID}))
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == {"permission": "allow"}
    assert proc.stderr == ""
