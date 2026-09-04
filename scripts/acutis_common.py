#!/usr/bin/env python3
"""
Shared helpers for the Acutis Cursor hooks (stdlib only, Python 3.9+).

Every hook script in this directory imports this module by inserting its own
directory on sys.path. The module owns:

- the security-relevant extension set and skip patterns,
- the conversation-scoped state files under STATE_DIR (all ids are
  charset-validated before they become part of a filename; a failed
  validation falls back to a fixed literal path, which over-blocks, the safe
  direction):
    ALLOW ledger    acutis-allow-cursor-<cid>.json          {"allowed": [norm, ...]}
    sweep state     acutis-sweep-cursor-<cid>.json          {"attested": {abs: sha}, "pending": [abs], "fail_open": [abs]}
    session start   acutis-session-start-cursor-<cid>.json  {"started_at_ns": int}
    fs snapshot     acutis-fs-snapshot-cursor-<cid>-<call>.json {"root": abs, "files": {rel: [mtime_ns, size]}}
- the filesystem enumerator (git ls-files inside a work tree, os.walk
  otherwise, capped at SNAPSHOT_CAP files),
- the one-directional coverage rule shared by the pre-write gate, the
  post-shell sweep and the stop sweep: a file is covered when its normalized
  content is a substring of a ledger payload, or when its content hash equals
  the hash attested right after a gate-allowed Write.

Every path helper re-validates its own argument (guard-and-reject) because a
caller-side check does not cross the function boundary.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# HTML is deliberately ABSENT: VerificationRequest.language rejects it.
SECURITY_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".mjs", ".cjs", ".java",
}

SKIP_PATTERNS = {
    "node_modules", "__pycache__", ".git", "venv", ".venv",
    "package-lock.json", "yarn.lock", "poetry.lock",
}

# Claude Code scratchpad directories are session-local working files, never
# code that enters a codebase.
_SCRATCHPAD_RE = re.compile(r"^/(?:private/)?tmp/claude-[^/]*/(?:.*/)?scratchpad/")

STATE_DIR = "/tmp"
LEDGER_PREFIX = "acutis-allow-cursor-"
LEDGER_FALLBACK = "acutis-allow-cursor.json"
SWEEP_PREFIX = "acutis-sweep-cursor-"
SWEEP_FALLBACK = "acutis-sweep-cursor.json"
SESSION_PREFIX = "acutis-session-start-cursor-"
SESSION_FALLBACK = "acutis-session-start-cursor.json"
SNAPSHOT_PREFIX = "acutis-fs-snapshot-cursor-"
LEDGER_CAP = 200
SNAPSHOT_CAP = 20000
SNAPSHOT_STALE_S = 86400.0

# Hosted Acutis MCP health endpoint. Hardcoded (not env- or input-derived) so
# the health check carries no user-controlled URL.
MCP_HEALTH_URL = "https://mcp.acutis.dev/health"
MCP_HEALTH_TIMEOUT = 3  # seconds

_ID_RE = re.compile(r"[A-Za-z0-9_-]+")
_CALL_ID_RE = re.compile(r"[0-9a-f]{16}")
_STATE_NAME_RE = re.compile(r"acutis-[A-Za-z0-9_-]+\.json(?:\.tmp)?")
_CRLF_RE = re.compile(r"[\r\n]+")


# ------------------------------------------------------------------ text


def normalize(text) -> str:
    """Whitespace-free form used for every containment check."""
    if text is None:
        return ""
    if isinstance(text, list):
        text = "\n".join(str(t) for t in text)
    return "".join(str(text).split())


def one_line(text) -> str:
    """Collapse CR/LF so a hook-input value cannot forge a stderr log line."""
    return _CRLF_RE.sub(" ", str(text))


def content_hash(norm: str) -> str:
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ ids and paths


def validated_conversation_id(cid) -> str:
    """Guard-and-reject: only a charset-clean id may become part of a path."""
    text = str(cid or "")
    if not _ID_RE.fullmatch(text):
        return ""
    return text


def validated_call_id(call_id) -> str:
    text = str(call_id or "")
    if not _CALL_ID_RE.fullmatch(text):
        return ""
    return text


def validated_state_path(path) -> str:
    """Guard-and-reject: a JSON state file (or its .tmp sibling) directly
    under STATE_DIR with an acutis- name, else ''."""
    text = str(path or "")
    if os.path.dirname(text) != STATE_DIR:
        return ""
    if not _STATE_NAME_RE.fullmatch(os.path.basename(text)):
        return ""
    return text


def validated_abs_path(path) -> str:
    """Guard-and-reject: an absolute path with no '.' or '..' component."""
    text = str(path or "")
    if not text or not os.path.isabs(text):
        return ""
    if any(part in (".", "..") for part in text.replace("\\", "/").split("/")):
        return ""
    return text


def validated_root(path) -> str:
    """Guard-and-reject: an absolute path to an existing directory, else ''."""
    text = str(path or "")
    if not text or not os.path.isabs(text):
        return ""
    if not os.path.isdir(text):
        return ""
    return text


def validated_relpath(rel) -> str:
    """Guard-and-reject: a relative path with no '.', '..' or empty component."""
    text = str(rel or "")
    if not text or os.path.isabs(text):
        return ""
    if any(part in ("", ".", "..") for part in text.replace("\\", "/").split("/")):
        return ""
    return text


def call_id_for(command) -> str:
    """Per-call id shared by beforeShellExecution and afterShellExecution:
    both receive the same `command` string and nothing else in common."""
    return hashlib.sha256(str(command or "").encode("utf-8")).hexdigest()[:16]


def _scoped_path(hook_input: dict, prefix: str, fallback: str) -> str:
    cid = validated_conversation_id(hook_input.get("conversation_id"))
    if not cid:
        return os.path.join(STATE_DIR, fallback)
    return os.path.join(STATE_DIR, prefix + cid + ".json")


def ledger_path_for(hook_input: dict) -> str:
    return _scoped_path(hook_input, LEDGER_PREFIX, LEDGER_FALLBACK)


def sweep_state_path_for(hook_input: dict) -> str:
    return _scoped_path(hook_input, SWEEP_PREFIX, SWEEP_FALLBACK)


def session_start_path_for(hook_input: dict) -> str:
    return _scoped_path(hook_input, SESSION_PREFIX, SESSION_FALLBACK)


def snapshot_path_for(hook_input: dict, call_id) -> str:
    """Snapshot path, or '' when either id fails validation (no snapshot is
    taken and the sweep is a no-op for that command)."""
    cid = validated_conversation_id(hook_input.get("conversation_id"))
    call = validated_call_id(call_id)
    if not cid or not call:
        return ""
    return os.path.join(STATE_DIR, SNAPSHOT_PREFIX + cid + "-" + call + ".json")


def stale_snapshot_paths(hook_input: dict) -> list:
    """Snapshots of this conversation older than SNAPSHOT_STALE_S (orphaned by
    a crashed or denied command)."""
    cid = validated_conversation_id(hook_input.get("conversation_id"))
    if not cid:
        return []
    prefix = SNAPSHOT_PREFIX + cid + "-"
    now = time.time()
    found = []
    try:
        names = os.listdir(STATE_DIR)
    except OSError:
        return []
    for name in names:
        if not name.startswith(prefix) or not name.endswith(".json"):
            continue
        call = validated_call_id(name[len(prefix):-5])
        if not call:
            continue
        path = validated_state_path(os.path.join(STATE_DIR, prefix + call + ".json"))
        if not path:
            continue
        try:
            if now - os.stat(path).st_mtime > SNAPSHOT_STALE_S:
                found.append(path)
        except OSError:
            continue
    return found


# ------------------------------------------------------------------ json state


def read_hook_input():
    """Parsed stdin JSON object, or None when it is missing or unparseable."""
    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def load_json(path: str):
    target = validated_state_path(path)
    if not target:
        return None
    try:
        with open(target, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def write_json_atomic(path: str, data) -> bool:
    target = validated_state_path(path)
    if not target:
        return False
    tmp_path = validated_state_path(str(path) + ".tmp")
    if not tmp_path:
        return False
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        tmp = Path(tmp_path)
        tmp.replace(target)
        return True
    except OSError:
        return False


def remove_file(path: str) -> None:
    target = validated_state_path(path)
    if not target:
        return
    try:
        os.remove(target)
    except OSError:
        pass


def load_allowed(hook_input: dict) -> list:
    """Normalized ALLOWed payloads for this conversation ([] when absent/corrupt)."""
    data = load_json(ledger_path_for(hook_input))
    if not isinstance(data, dict):
        return []
    allowed = data.get("allowed", [])
    if not isinstance(allowed, list):
        return []
    return [a for a in allowed if isinstance(a, str) and a]


def _str_list(value) -> list:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


def load_sweep_state(hook_input: dict) -> dict:
    data = load_json(sweep_state_path_for(hook_input))
    if not isinstance(data, dict):
        data = {}
    attested = data.get("attested", {})
    if not isinstance(attested, dict):
        attested = {}
    attested = {str(k): str(v) for k, v in attested.items() if isinstance(v, str)}
    return {
        "attested": attested,
        "pending": _str_list(data.get("pending")),
        "fail_open": _str_list(data.get("fail_open")),
    }


def save_sweep_state(hook_input: dict, state: dict) -> None:
    write_json_atomic(sweep_state_path_for(hook_input), state)


def ensure_session_start(hook_input: dict, overwrite: bool = False) -> int:
    """Record the session start wall clock (ns) once; sessionStart overwrites.
    Cloud agents never fire sessionStart, so every other hook calls this with
    overwrite=False and the first hook of the session sets the mark."""
    if not overwrite:
        existing = read_session_start(hook_input)
        if existing:
            return existing
    now_ns = time.time_ns()
    write_json_atomic(session_start_path_for(hook_input), {"started_at_ns": now_ns})
    return now_ns


def read_session_start(hook_input: dict) -> int:
    data = load_json(session_start_path_for(hook_input))
    if not isinstance(data, dict):
        return 0
    value = data.get("started_at_ns", 0)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return 0
    return value


# ------------------------------------------------------------------ files


def is_security_relevant(file_path) -> bool:
    if not file_path:
        return False
    text = str(file_path)
    p = Path(text)
    if p.suffix.lower() not in SECURITY_EXTENSIONS:
        return False
    if set(p.parts) & SKIP_PATTERNS:
        return False
    if _SCRATCHPAD_RE.match(text):
        return False
    return True


def _git_ls(root: str, untracked: bool):
    """Tracked (or, with untracked, untracked non-ignored) files under a
    validated root, or None when root is not inside a git work tree or git is
    unavailable."""
    top = validated_root(root)
    if not top:
        return None
    try:
        if untracked:
            proc = subprocess.run(["git", "-C", top, "ls-files", "-z", "-o", "--exclude-standard"], capture_output=True, timeout=15, check=False)
        else:
            proc = subprocess.run(["git", "-C", top, "ls-files", "-z"], capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return [p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p]


def _walk_files(root: str) -> list:
    found = []
    top = validated_root(root)
    if not top:
        return found
    walker = os.walk(top)
    for dirpath, dirnames, filenames in walker:
        dirnames[:] = [d for d in dirnames if d not in SKIP_PATTERNS]
        for name in filenames:
            found.append(os.path.relpath(os.path.join(dirpath, name), top))
            if len(found) > SNAPSHOT_CAP:
                return found
    return found


def list_files(root: str):
    """Relative paths of security-relevant files under a validated root, or
    None above SNAPSHOT_CAP (the caller notes it on stderr and skips)."""
    tracked = _git_ls(root, False)
    if tracked is None:
        names = _walk_files(root)
    else:
        names = tracked + (_git_ls(root, True) or [])
    if len(names) > SNAPSHOT_CAP:
        return None
    result = []
    seen = set()
    for name in names:
        rel = validated_relpath(name)
        if not rel or rel in seen or not is_security_relevant(rel):
            continue
        seen.add(rel)
        result.append(rel)
    return result


def take_snapshot(root: str):
    """{rel: [mtime_ns, size]} for security-relevant files, or None above cap."""
    rels = list_files(root)
    if rels is None:
        return None
    files = {}
    for rel in rels:
        full = validated_abs_path(os.path.join(root, rel))
        if not full:
            continue
        try:
            st = os.stat(full)
        except OSError:
            continue
        files[rel] = [st.st_mtime_ns, st.st_size]
    return files


def changed_files(old: dict, new: dict) -> list:
    """Relative paths present in new whose [mtime_ns, size] differ from old
    (new files included, deleted files ignored)."""
    return sorted(rel for rel, meta in new.items() if old.get(rel) != meta)


def read_normalized(path: str) -> str:
    target = validated_abs_path(path)
    if not target:
        return ""
    try:
        with open(target, encoding="utf-8", errors="replace") as f:
            return normalize(f.read())
    except OSError:
        return ""


def file_covered(path: str, allowed: list, attested: dict) -> bool:
    """One-directional coverage: the file's normalized content is a substring
    of a ledger payload, or its hash matches the attestation recorded after a
    gate-allowed Write. An empty or unreadable file has nothing to verify."""
    norm = read_normalized(path)
    if not norm:
        return True
    if any(norm in payload for payload in allowed):
        return True
    return attested.get(path, "") == content_hash(norm)


SWEEP_MESSAGE_HEAD = "Acutis: "
SWEEP_MESSAGE_TAIL = (
    " changed during that command without a verify_code ALLOW covering their "
    "new content. Verify each file's final text with verify_code now (format "
    "first, then verify), or revert the change."
)


def sweep_message(paths) -> str:
    """The one uncovered-file message the post-shell sweep and the pre-write
    gate both emit, so the text never drifts between the two channels."""
    names = sorted({os.path.basename(str(p)) for p in paths or []})
    return SWEEP_MESSAGE_HEAD + ", ".join(names) + SWEEP_MESSAGE_TAIL


def merge_paths(existing, extra) -> list:
    """Union of two absolute-path lists, sorted, strings only."""
    both = [p for p in list(existing or []) + list(extra or []) if isinstance(p, str) and p]
    return sorted(set(both))


# ------------------------------------------------------------------ network and output


def acutis_reachable() -> bool:
    try:
        with urllib.request.urlopen(MCP_HEALTH_URL, timeout=MCP_HEALTH_TIMEOUT):
            return True
    except (OSError, ValueError):
        return False


def emit(payload: dict) -> None:
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")


def note(text: str) -> None:
    print("acutis: " + one_line(text), file=sys.stderr)
