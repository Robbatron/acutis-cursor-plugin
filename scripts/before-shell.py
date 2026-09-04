#!/usr/bin/env python3
"""
Acutis shell gate (Cursor `beforeShellExecution`).

Two jobs in one run:

1. Deny any shell command that would write a security-relevant code file. Code
   files reach the codebase through the Write tool, where the pre-write gate
   requires a verify_code ALLOW covering the exact text; the shell is for
   running things. A `>`/`>>` redirect, a heredoc, `tee`, an in-place `sed` or
   `perl`, a `cp` / `mv` / `install` destination or `truncate` aimed at a code
   file bypasses that gate, so it is denied. Shell commands themselves are
   never verified: only code that lands in the project matters.

2. Snapshot the project's security-relevant files (relative path -> mtime, size)
   so `after-shell.py` can diff the tree afterwards and flag any code file the
   command rewrote without a verify_code ALLOW covering its new content. That is
   the format-then-verify policy: a formatter or generator produces unverified
   text, and the model must verify that file's final text.

Parsing: the command is split on `;`, `&&`, `||`, `|` and newlines, then each
segment is tokenized with `shlex`. If any segment fails to tokenize, the whole
command is re-examined as raw text and denied when it carries both a code-path
token and a redirect or heredoc operator (fail closed); every other unparsable
command is allowed.

Scope: only paths that land inside the workspace count. A relative path is
inside by construction; an absolute path must sit under the cwd, a workspace
root, or CURSOR_PROJECT_DIR. With no root known at all, every path counts
(over-block, the safe direction).

Failure policy: fail closed. Unparseable hook input or an internal error denies
(exit code 2 also denies per Cursor's hooks docs), and the hook entry carries
`failClosed: true`.
"""

import os
import re
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import acutis_common as ac  # noqa: E402

DENY_HEAD = "Acutis: "
DENY_TAIL = (
    " is a code file. Write code files with the Write tool so the Acutis gate "
    "can check them; the shell is for running things."
)

# `||` before `|` so the alternation never splits a logical-or in half, and a
# `|` directly after `>` is the clobber operator `>|`, not a pipe.
_SEGMENT_RE = re.compile(r"\|\||&&|;|(?<!>)\||\n")
_ENV_ASSIGN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*")
# `>`, `>>`, `2>`, `&>`, `>|`, with or without the target glued on.
_REDIRECT_RE = re.compile(r"[0-9]*&?>{1,2}\|?(.*)")
# `-i`, `-i.bak`, `-pi`, `--in-place`: an in-place rewrite switch.
_PERL_INPLACE_RE = re.compile(r"-[a-zA-Z]{0,3}i.*")
_SED_INPLACE_RE = re.compile(r"-[a-zA-Z]{0,3}i.*|--in-place.*")
_EXT_NAMES = sorted(ext.lstrip(".") for ext in ac.SECURITY_EXTENSIONS)
_CODE_TOKEN_RE = re.compile(
    r"[^\s\"'`;|&<>()]*\.(?:" + "|".join(_EXT_NAMES) + r")\b", re.IGNORECASE
)
_MOVERS = ("cp", "mv", "install")


def project_roots(hook_input, cwd):
    """Absolute directories a path must sit under to count as project code."""
    roots = []
    here = ac.validated_abs_path(cwd)
    if here:
        roots.append(here)
    workspace = hook_input.get("workspace_roots")
    if isinstance(workspace, list):
        for item in workspace:
            root = ac.validated_abs_path(item)
            if root:
                roots.append(root)
    env_root = ac.validated_abs_path(os.environ.get("CURSOR_PROJECT_DIR", ""))
    if env_root:
        roots.append(env_root)
    return roots


def snapshot_root(hook_input, cwd):
    """Widest root available: the workspace beats a cwd that is a subdirectory."""
    workspace = hook_input.get("workspace_roots")
    if isinstance(workspace, list):
        for item in workspace:
            root = ac.validated_root(item)
            if root:
                return root
    env_root = ac.validated_root(os.environ.get("CURSOR_PROJECT_DIR", ""))
    if env_root:
        return env_root
    return ac.validated_root(cwd)


def in_project(path, roots):
    if not roots:
        return True
    if not os.path.isabs(path):
        return True
    for root in roots:
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return True
    return False


def code_candidate(token):
    """The path-ish form of a token that names a security-relevant code file,
    else ''. Extension and skip-pattern check only, no project scoping."""
    text = str(token or "").strip()
    if not text:
        return ""
    candidate = os.path.expanduser(text)
    if not ac.is_security_relevant(candidate):
        return ""
    return candidate


def targets_code(token, roots):
    """True when this token names a code file that lands inside the project."""
    candidate = code_candidate(token)
    if not candidate:
        return False
    return in_project(candidate, roots)


def split_segments(command):
    return [seg for seg in _SEGMENT_RE.split(str(command or "")) if seg.strip()]


def strip_env_assignments(tokens):
    """Drop leading NAME=value tokens so the command word is the real one."""
    index = 0
    while index < len(tokens) and _ENV_ASSIGN_RE.fullmatch(tokens[index]):
        index += 1
    return tokens[index:]


def classify(tokens):
    """One segment's tokens as (words, flags, redirect targets, heredoc seen)."""
    words = []
    flags = []
    redirects = []
    heredoc = False
    index = 0
    total = len(tokens)
    while index < total:
        token = tokens[index]
        redirect = _REDIRECT_RE.fullmatch(token)
        if token.startswith("<<"):
            heredoc = True
        elif token.startswith("<"):
            if token == "<":
                index += 1
        elif redirect:
            target = redirect.group(1)
            if not target and index + 1 < total:
                index += 1
                target = tokens[index]
            redirects.append(target)
        elif token.startswith("-") and len(token) > 1:
            flags.append(token)
        else:
            words.append(token)
        index += 1
    return words, flags, redirects, heredoc


def first_code(candidates, roots):
    for candidate in candidates:
        if targets_code(candidate, roots):
            return candidate
    return ""


def segment_hit(tokens, roots):
    """The code file this segment would write, or ''."""
    words, flags, redirects, heredoc = classify(strip_env_assignments(tokens))
    hit = first_code(redirects, roots)
    if hit:
        return hit
    if heredoc:
        hit = first_code(words + redirects, roots)
        if hit:
            return hit
    if not words:
        return ""
    name = os.path.basename(words[0])
    args = words[1:]
    if name == "tee" or name == "truncate":
        return first_code(args, roots)
    if name == "sed" and any(_SED_INPLACE_RE.fullmatch(flag) for flag in flags):
        return first_code(args, roots)
    if name == "perl" and any(_PERL_INPLACE_RE.fullmatch(flag) for flag in flags):
        return first_code(args, roots)
    if name in _MOVERS and args:
        dest = args[-1]
        if targets_code(dest, roots):
            return dest
        looks_like_dir = dest.endswith("/") or dest.endswith(".")
        if looks_like_dir and in_project(dest, roots):
            for arg in args[:-1]:
                if code_candidate(arg):
                    return arg
    return ""


def unparsable_hit(command, roots):
    """Fail closed: raw text carrying both a code path and a write operator."""
    text = str(command or "")
    if ">" not in text and "<<" not in text:
        return ""
    for match in _CODE_TOKEN_RE.finditer(text):
        hit = match.group(0)
        if targets_code(hit, roots):
            return hit
    return ""


def evaluate(command, roots):
    parsed = []
    unparsable = False
    for segment in split_segments(command):
        try:
            parsed.append(shlex.split(segment))
        except ValueError:
            unparsable = True
    for tokens in parsed:
        hit = segment_hit(tokens, roots)
        if hit:
            return hit
    if unparsable:
        return unparsable_hit(command, roots)
    return ""


def take_snapshot_for(hook_input, command, cwd):
    root = ac.validated_root(snapshot_root(hook_input, cwd))
    if not root:
        ac.note("shell gate: no usable workspace root; sweep disabled for this command")
        return
    path = ac.snapshot_path_for(hook_input, ac.call_id_for(command))
    if not path:
        ac.note("shell gate: no conversation id; sweep disabled for this command")
        return
    files = ac.take_snapshot(root)
    if files is None:
        ac.note("shell gate: listing above the snapshot cap; sweep disabled for this command")
        return
    ac.write_json_atomic(path, {"root": root, "files": files})


def deny(name):
    ac.emit({
        "permission": "deny",
        "user_message": "Acutis: shell write to " + name + " blocked; code files go through the Write tool.",
        "agent_message": DENY_HEAD + name + DENY_TAIL,
    })
    return 0


def main():
    hook_input = ac.read_hook_input()
    if hook_input is None:
        ac.note("shell gate: unparseable hook input; denying (fail closed)")
        ac.emit({
            "permission": "deny",
            "user_message": "Acutis: the shell gate could not read the hook input.",
            "agent_message": "Acutis: the shell gate could not parse its hook input, so the command was denied (fail closed). Retry it.",
        })
        return 0
    ac.ensure_session_start(hook_input)
    command = str(hook_input.get("command") or "")
    cwd = str(hook_input.get("cwd") or "")
    hit = evaluate(command, project_roots(hook_input, cwd))
    if hit:
        return deny(ac.one_line(os.path.basename(hit.rstrip("/"))) or "that file")
    take_snapshot_for(hook_input, command, cwd)
    ac.emit({"permission": "allow"})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - fail closed on any internal error
        print("acutis shell gate: internal error " + ac.one_line(repr(exc)) + "; denying (fail closed)", file=sys.stderr)
        sys.exit(2)
