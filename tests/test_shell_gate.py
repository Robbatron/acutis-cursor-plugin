"""Tests for the Acutis shell gate (before-shell.py): which shell constructs
deny, which allow, and the filesystem snapshot it takes for the post-shell
sweep. Stdlib + pytest only; no network."""

import json
import os
import subprocess

import pytest

from conftest import load, repo_dir, run, write_file

CID = "conv-shell_1"

DENY_HEAD = "Acutis: "
DENY_TAIL = (
    " is a code file. Write code files with the Write tool so the Acutis gate "
    "can check them; the shell is for running things."
)


@pytest.fixture
def gate(common):
    return load("before-shell")


def shell_event(command, root):
    return {
        "hook_event_name": "beforeShellExecution",
        "conversation_id": CID,
        "command": command,
        "cwd": root,
        "sandbox": False,
        "workspace_roots": [root],
    }


def snapshot_for(common, command):
    path = common.snapshot_path_for({"conversation_id": CID}, common.call_id_for(command))
    return common.load_json(path)


DENIED = [
    ("redirect", "echo x > app.py", "app.py"),
    ("redirect glued", "echo x >app.py", "app.py"),
    ("append", "echo x >> src/app.py", "app.py"),
    ("fd redirect", "node build.js 2> src/out.ts", "out.ts"),
    ("clobber redirect", "echo x >| src/app.mjs", "app.mjs"),
    ("heredoc with redirect", "cat > app.py <<'EOF'\nprint(1)\nEOF", "app.py"),
    ("heredoc with code arg", "bash -s app.py <<EOF\nx\nEOF", "app.py"),
    ("tee", "npm run build | tee src/app.js", "app.js"),
    ("tee append", "echo x | tee -a src/app.tsx", "app.tsx"),
    ("sed in place", "sed -i 's/a/b/' src/app.py", "app.py"),
    ("sed in place suffix", "sed -i.bak 's/a/b/' src/app.js", "app.js"),
    ("sed bsd in place", "sed -i '' src/app.java", "app.java"),
    ("sed long in place", "sed --in-place=.bak 's/a/b/' app.java", "app.java"),
    ("perl in place", "perl -pi -e 's/a/b/' app.py", "app.py"),
    ("perl in place suffix", "perl -i.bak -pe 's/a/b/' src/app.tsx", "app.tsx"),
    ("cp onto a code file", "cp /tmp/gen.py src/app.py", "app.py"),
    ("cp into a project dir", "cp /tmp/gen.py src/", "gen.py"),
    ("mv onto a code file", "mv old.py src/app.py", "app.py"),
    ("install", "install -m 644 gen.py src/app.py", "app.py"),
    ("truncate", "truncate -s 0 src/app.py", "app.py"),
    ("later segment", "npm test && echo x > app.js", "app.js"),
    ("env assignment prefix", "FOO=1 tee app.py", "app.py"),
    ("unparsable with code and redirect", "echo 'oops > app.py", "app.py"),
]


@pytest.mark.parametrize("label,command,name", DENIED, ids=[case[0] for case in DENIED])
def test_denies(gate, common, capsys, project, label, command, name):
    rc, out, err = run(gate, capsys, shell_event(command, project))
    assert rc == 0
    assert out["permission"] == "deny"
    assert out["agent_message"] == DENY_HEAD + name + DENY_TAIL
    assert name in out["user_message"]


ALLOWED = [
    ("run a script", "python src/app.py"),
    ("list", "ls -la src"),
    ("read", "cat src/app.py"),
    ("redirect to a non-code file", "echo hi > notes.md"),
    ("sed without in place", "sed -n '1,5p' src/app.py"),
    ("perl without in place", "perl -e 'print 1' src/app.py"),
    ("grep", "grep -rn foo src/"),
    ("formatter in place", "ruff format src/app.py"),
    ("cp to a non-code file", "cp src/app.py backup.txt"),
    ("mv out of the project", "mv src/app.py /tmp/"),
    ("redirect outside the project", "echo x > /tmp/outside.py"),
    ("code path inside a quoted string", "git commit -m 'fix > app.py'"),
    ("unparsable without a code path", "echo 'unterminated > notes.md"),
    ("empty", ""),
]


@pytest.mark.parametrize("label,command", ALLOWED, ids=[case[0] for case in ALLOWED])
def test_allows(gate, common, capsys, project, label, command):
    rc, out, err = run(gate, capsys, shell_event(command, project))
    assert rc == 0
    assert out == {"permission": "allow"}


def test_unparseable_hook_input_denies(gate, common, capsys):
    rc, out, err = run(gate, capsys, "{not json")
    assert out["permission"] == "deny"
    assert "fail closed" in err


def test_snapshot_lists_only_security_relevant_files(gate, common, capsys, project):
    write_file(project, "src/app.py", "print(1)\n")
    write_file(project, "README.md", "hi\n")
    write_file(project, "node_modules/pkg/index.js", "x\n")
    command = "ls -la"
    rc, out, err = run(gate, capsys, shell_event(command, project))
    assert out == {"permission": "allow"}
    snapshot = snapshot_for(common, command)
    assert snapshot["root"] == project
    assert sorted(snapshot["files"]) == ["src/app.py"]


def test_snapshot_uses_git_listing_when_available(gate, common, capsys, project):
    write_file(project, "tracked.py", "print(1)\n")
    write_file(project, "untracked.js", "1\n")
    write_file(project, ".gitignore", "ignored.py\n")
    write_file(project, "ignored.py", "print(2)\n")
    if subprocess.run(["git", "init", "-q", project], check=False).returncode != 0:
        pytest.skip("git is unavailable")
    subprocess.run(["git", "-C", project, "add", "tracked.py"], check=False)
    command = "git status"
    rc, out, err = run(gate, capsys, shell_event(command, project))
    assert out == {"permission": "allow"}
    assert sorted(snapshot_for(common, command)["files"]) == ["tracked.py", "untracked.js"]


def test_snapshot_skipped_above_the_cap(gate, common, capsys, project):
    write_file(project, "src/app.py", "print(1)\n")
    original = common.SNAPSHOT_CAP
    common.SNAPSHOT_CAP = 0
    try:
        command = "ls"
        rc, out, err = run(gate, capsys, shell_event(command, project))
    finally:
        common.SNAPSHOT_CAP = original
    assert out == {"permission": "allow"}
    assert snapshot_for(common, command) is None
    assert "snapshot cap" in err


def test_denied_command_takes_no_snapshot(gate, common, capsys, project):
    command = "echo x > app.py"
    rc, out, err = run(gate, capsys, shell_event(command, project))
    assert out["permission"] == "deny"
    assert snapshot_for(common, command) is None


def test_snapshot_path_is_per_command(gate, common, capsys, project):
    write_file(project, "src/app.py", "print(1)\n")
    run(gate, capsys, shell_event("ls", project))
    run(gate, capsys, shell_event("pwd", project))
    assert snapshot_for(common, "ls") is not None
    assert snapshot_for(common, "pwd") is not None
    assert snapshot_for(common, "whoami") is None


def test_session_start_mark_is_created(gate, common, capsys, project):
    run(gate, capsys, shell_event("ls", project))
    assert common.read_session_start({"conversation_id": CID}) > 0


def test_wrapper_denies_a_redirect():
    event = json.dumps({
        "conversation_id": "pytest-wrapper-shell",
        "command": "echo x > app.py",
        "cwd": "/work",
        "workspace_roots": ["/work"],
    })
    proc = subprocess.run(
        ["bash", os.path.join(repo_dir(), "scripts", "before-shell.sh")],
        input=event,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["agent_message"] == DENY_HEAD + "app.py" + DENY_TAIL
