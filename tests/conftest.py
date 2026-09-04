"""Shared loader and fixtures for the Acutis Cursor hook tests.

Stdlib + pytest only; no network. Every hook script is loaded through the same
`acutis_common` instance that the scripts themselves import, so redirecting
`STATE_DIR` on that one module redirects every state file the hooks touch.

Patching here is plain attribute assignment with explicit restore rather than
`monkeypatch.setattr`: setting an attribute chosen by name is a reflection
boundary, and the tests have no reason to open one.
"""

import importlib
import io
import json
import os
import sys

import pytest

# Guard-and-reject: only a hook script shipped in this repo may be imported.
HOOK_MODULES = (
    "acutis_common",
    "before-shell",
    "after-shell",
    "pre-tool-use",
    "session-start",
    "stop-hook",
    "verification-allow-tracker",
)


def repo_dir():
    """The plugin checkout that owns this test file."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.isfile(os.path.join(here, "hooks", "hooks.json")):
        raise RuntimeError("tests must run from the acutis-cursor-plugin checkout")
    return here


def scripts_dir():
    return os.path.join(repo_dir(), "scripts")


def validated_hook_name(name):
    """Guard-and-reject: an allowlisted hook module name, else ''."""
    text = str(name or "")
    if text not in HOOK_MODULES:
        return ""
    return text


def common_module():
    """The one shared acutis_common instance the hook scripts import."""
    path = scripts_dir()
    if path not in sys.path:
        sys.path.insert(0, path)
    return importlib.import_module("acutis_common")


def load(name):
    """Import a hook script by its allowlisted name."""
    common_module()
    target = validated_hook_name(name)
    if not target:
        raise RuntimeError("not a hook module")
    return importlib.import_module(target)


def run(mod, capsys, hook_input):
    """Feed hook_input on stdin, run main(), return (rc, parsed stdout, stderr)."""
    payload = hook_input if isinstance(hook_input, str) else json.dumps(hook_input)
    original = sys.stdin
    sys.stdin = io.StringIO(payload)
    try:
        rc = mod.main()
    finally:
        sys.stdin = original
    captured = capsys.readouterr()
    out = json.loads(captured.out) if captured.out.strip() else {}
    return rc, out, captured.err


def under(root, rel):
    """Guard-and-reject: the normalized join of root and rel, '' if it escapes."""
    base = os.path.normpath(str(root))
    path = os.path.normpath(os.path.join(base, str(rel)))
    if path != base and not path.startswith(base + os.sep):
        return ""
    return path


def write_file(root, rel, text):
    """Create (or overwrite) a file under root and return its absolute path."""
    target = under(root, rel)
    if not target:
        raise RuntimeError("path escapes the test root")
    parent = under(root, os.path.dirname(str(rel)))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(text)
    return target


def seed_ledger(common, conversation_id, payloads):
    """Write the ALLOW ledger for a conversation."""
    path = common.ledger_path_for({"conversation_id": conversation_id})
    common.write_json_atomic(path, {"allowed": [common.normalize(p) for p in payloads]})


@pytest.fixture
def common(tmp_path):
    """acutis_common with its state directory redirected into tmp_path."""
    mod = common_module()
    state = tmp_path / "state"
    state.mkdir()
    original_dir = mod.STATE_DIR
    original_health = mod.acutis_reachable
    mod.STATE_DIR = str(state)
    mod.acutis_reachable = lambda: True
    yield mod
    mod.STATE_DIR = original_dir
    mod.acutis_reachable = original_health


@pytest.fixture
def offline(common):
    """The health check reports the server unreachable."""
    common.acutis_reachable = lambda: False
    return common


@pytest.fixture
def project(tmp_path):
    """An empty, non-git project root with a src/ subdirectory."""
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    return str(root)
