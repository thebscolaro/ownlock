"""Shared hook plumbing for shield/guard emitters plus an execution harness.

Two halves:

* Config helpers (`hook_command`, `write_script`, `upsert_command_hooks`)
  used by both :mod:`ownlock.shield` and :mod:`ownlock.guard` so agent
  settings files are updated identically and idempotently.
* An execution harness (`run_hook`, the payload matrices, `run_selftest`)
  that actually runs emitted hook scripts with synthetic payloads and checks
  the allow/deny answer. Both ``tests/test_hook_exec.py`` and
  ``ownlock shield --selftest`` go through this code, so what CI verifies is
  exactly what users can verify locally.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ALLOW = "allow"
DENY = "deny"


# ---------------------------------------------------------------------------
# Config helpers shared by shield.py / guard.py
# ---------------------------------------------------------------------------


def hook_command(rel_hook: str) -> str:
    """Return the command string an agent config should invoke for a hook."""
    if os.name == "nt":
        return f"powershell -NoProfile -File {rel_hook}"
    return rel_hook


def write_script(path: Path, body: str, *, force: bool) -> bool:
    """Write *body* to *path* (exec bit on POSIX .sh). Returns True if changed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not force and path.exists() and path.read_text(encoding="utf-8") == body:
        return False
    path.write_text(body, encoding="utf-8")
    if os.name == "posix" and path.suffix == ".sh":
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return True


def entry_commands(entry: dict) -> list[str]:
    """Collect command strings from a hook entry (flat or Claude-style nested)."""
    cmds: list[str] = []
    if isinstance(entry.get("command"), str):
        cmds.append(entry["command"])
    for h in entry.get("hooks") or []:
        if isinstance(h, dict) and isinstance(h.get("command"), str):
            cmds.append(h["command"])
    return cmds


def upsert_command_hooks(entries: list, marker: str, new_entry: dict) -> bool:
    """Replace entries whose command mentions *marker* with *new_entry* (idempotent)."""
    others: list = []
    ownlock: list = []
    for entry in entries:
        if isinstance(entry, dict) and any(marker in c for c in entry_commands(entry)):
            ownlock.append(entry)
        else:
            others.append(entry)
    if len(ownlock) == 1 and ownlock[0] == new_entry:
        return False
    entries[:] = others + [new_entry]
    return True


# ---------------------------------------------------------------------------
# Hook execution harness
# ---------------------------------------------------------------------------


def find_bash() -> Optional[str]:
    """Absolute path to bash, or None."""
    return shutil.which("bash")


def find_powershell() -> Optional[str]:
    """Absolute path to pwsh (preferred) or Windows PowerShell, or None."""
    for exe in ("pwsh", "powershell"):
        found = shutil.which(exe)
        if found:
            return found
    return None


def run_hook(
    script: Path,
    payload: str,
    *,
    env: Optional[dict[str, str]] = None,
    timeout: float = 60.0,
) -> tuple[int, str]:
    """Execute a hook *script* with *payload* on stdin; return (exit_code, stdout).

    Dispatches on suffix: ``.ps1`` runs under pwsh/powershell, anything else
    under bash. Raises RuntimeError when no suitable interpreter exists.
    """
    if script.suffix == ".ps1":
        shell = find_powershell()
        if shell is None:
            raise RuntimeError("no PowerShell (pwsh/powershell) on PATH")
        argv = [shell, "-NoProfile", "-NonInteractive", "-File", str(script)]
    else:
        shell = find_bash()
        if shell is None:
            raise RuntimeError("no bash on PATH")
        argv = [shell, str(script)]
    proc = subprocess.run(  # noqa: S603 — runs our own emitted hook scripts
        argv,
        input=payload.encode("utf-8"),
        capture_output=True,
        timeout=timeout,
        env=env,
    )
    return proc.returncode, proc.stdout.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Payload matrix (agent x case). Payloads are raw stdin strings.
# ---------------------------------------------------------------------------


def _j(obj: object) -> str:
    return json.dumps(obj)


# Cursor hooks receive flat fields (beforeReadFile/beforeShellExecution) or
# tool_input (preToolUse).
CURSOR_CASES: list[tuple[str, str, str]] = [
    ("allow read", _j({"file_path": "src/app.py"}), ALLOW),
    ("allow shell", _j({"command": "echo hello"}), ALLOW),
    ("deny .env", _j({"file_path": ".env"}), DENY),
    ("deny .env.local", _j({"file_path": ".env.local"}), DENY),
    ("deny .ownlock path", _j({"file_path": "x/.ownlock/vault.db"}), DENY),
    ("deny target_directory", _j({"tool_input": {"target_directory": ".ownlock"}}), DENY),
    ("deny shell cat .env", _j({"command": "cat .env"}), DENY),
    ("deny windows .env", _j({"file_path": "C:\\proj\\.env"}), DENY),
    ("allow unicode path", _j({"file_path": "src/donn\u00e9es.py"}), ALLOW),
    ("allow empty stdin", "", ALLOW),
    ("allow malformed json", "{not json", ALLOW),
]

# Claude hooks receive {tool_name, tool_input}.
CLAUDE_CASES: list[tuple[str, str, str]] = [
    ("allow read", _j({"tool_name": "Read", "tool_input": {"file_path": "src/app.py"}}), ALLOW),
    ("allow shell", _j({"tool_name": "Bash", "tool_input": {"command": "echo hello"}}), ALLOW),
    ("deny .env", _j({"tool_name": "Read", "tool_input": {"file_path": ".env"}}), DENY),
    ("deny .env.local", _j({"tool_name": "Read", "tool_input": {"file_path": ".env.local"}}), DENY),
    (
        "deny .ownlock path",
        _j({"tool_name": "Read", "tool_input": {"file_path": "x/.ownlock/vault.db"}}),
        DENY,
    ),
    (
        "deny target_directory",
        _j({"tool_name": "Grep", "tool_input": {"target_directory": ".ownlock"}}),
        DENY,
    ),
    ("deny shell cat .env", _j({"tool_name": "Bash", "tool_input": {"command": "cat .env"}}), DENY),
    (
        "deny windows .env",
        _j({"tool_name": "Read", "tool_input": {"file_path": "C:\\proj\\.env"}}),
        DENY,
    ),
    (
        "allow unicode path",
        _j({"tool_name": "Read", "tool_input": {"file_path": "src/donn\u00e9es.py"}}),
        ALLOW,
    ),
    ("allow empty stdin", "", ALLOW),
    ("allow malformed json", "{not json", ALLOW),
]

# Hermes pre_tool_call hooks receive {tool_input} without a tool gate.
HERMES_CASES: list[tuple[str, str, str]] = [
    ("allow read", _j({"tool_input": {"file_path": "src/app.py"}}), ALLOW),
    ("allow shell", _j({"tool_input": {"command": "echo hello"}}), ALLOW),
    ("deny .env", _j({"tool_input": {"file_path": ".env"}}), DENY),
    ("deny .env.local", _j({"tool_input": {"file_path": ".env.local"}}), DENY),
    ("deny .ownlock path", _j({"tool_input": {"file_path": "x/.ownlock/vault.db"}}), DENY),
    ("deny target_directory", _j({"tool_input": {"target_directory": ".ownlock"}}), DENY),
    ("deny shell cat .env", _j({"tool_input": {"command": "cat .env"}}), DENY),
    ("deny windows .env", _j({"tool_input": {"file_path": "C:\\proj\\.env"}}), DENY),
    ("allow unicode path", _j({"tool_input": {"file_path": "src/donn\u00e9es.py"}}), ALLOW),
    ("allow empty stdin", "", ALLOW),
    ("allow malformed json", "{not json", ALLOW),
]

# Red-team payloads shared across agents. Each is applied in the agent's own
# schema by _redteam_cases(). Split into file-path probes and shell-command
# probes so we can wrap them correctly (Claude gates on tool_name).
_REDTEAM_FILE_CASES: list[tuple[str, str, str]] = [
    ("deny uppercase .ENV", ".ENV", DENY),
    ("deny mixedcase .Env", ".Env", DENY),
    ("deny .env.bak", ".env.bak", DENY),
    ("deny leading-dot ./.env", "./.env", DENY),
    ("deny traversal ../.env", "x/../.env", DENY),
    ("deny home ~/.env", "~/.env", DENY),
    ("deny absolute .env", "/home/u/proj/.env", DENY),
    ("deny uppercase .OWNLOCK", "x/.OWNLOCK/vault.db", DENY),
    # No false positives: these are NOT secret files.
    ("allow foo.env", "foo.env", ALLOW),
    ("allow .environment", ".environment", ALLOW),
    ("allow environment dir", "environment/config.py", ALLOW),
    ("allow prevent.envy", "prevent.envy", ALLOW),
]
_REDTEAM_CMD_CASES: list[tuple[str, str, str]] = [
    ("deny redirect cat < .env", "cat < .env", DENY),
    ("deny cp .env", "cp .env /tmp/x", DENY),
    ("deny head -c .env", "head -c100 .env", DENY),
    ("deny cmd subst .env", "cat $(echo .env)", DENY),
    ("deny python open .env", "python -c \"open('.env')\"", DENY),
    ("deny uppercase cat .ENV", "cat .ENV", DENY),
    # No false positives.
    ("allow benign echo", "echo environment ready", ALLOW),
    ("allow git status", "git status", ALLOW),
]


def _redteam_cases(agent: str) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for name, path, expect in _REDTEAM_FILE_CASES:
        if agent == "cursor":
            payload = _j({"file_path": path})
        elif agent == "claude":
            payload = _j({"tool_name": "Read", "tool_input": {"file_path": path}})
        else:
            payload = _j({"tool_input": {"file_path": path}})
        out.append((name, payload, expect))
    for name, cmd, expect in _REDTEAM_CMD_CASES:
        if agent == "cursor":
            payload = _j({"command": cmd})
        elif agent == "claude":
            payload = _j({"tool_name": "Bash", "tool_input": {"command": cmd}})
        else:
            payload = _j({"tool_input": {"command": cmd}})
        out.append((name, payload, expect))
    return out


CASES_BY_AGENT: dict[str, list[tuple[str, str, str]]] = {
    "cursor": CURSOR_CASES + _redteam_cases("cursor"),
    "claude": CLAUDE_CASES + _redteam_cases("claude"),
    "hermes": HERMES_CASES + _redteam_cases("hermes"),
}


def evaluate(agent: str, expect: str, exit_code: int, stdout: str) -> Optional[str]:
    """Check one hook answer against expectations. Returns a failure reason or None."""
    text = stdout.strip()

    if agent == "cursor":
        # Cursor is wired fail-closed: every answer must be permission JSON.
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return f"stdout is not valid JSON: {text[:120]!r}"
        perm = data.get("permission") if isinstance(data, dict) else None
        if expect == ALLOW:
            if perm != "allow":
                return f"expected permission=allow, got {perm!r}"
            if exit_code != 0:
                return f"expected exit 0 on allow, got {exit_code}"
        else:
            if perm != "deny":
                return f"expected permission=deny, got {perm!r}"
            if exit_code != 2:
                return f"expected exit 2 on deny, got {exit_code}"
        return None

    if agent == "claude":
        if exit_code != 0:
            return f"expected exit 0, got {exit_code}"
        decision = None
        if text:
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    decision = (data.get("hookSpecificOutput") or {}).get("permissionDecision")
            except (json.JSONDecodeError, ValueError):
                return f"stdout is not valid JSON: {text[:120]!r}"
        if expect == ALLOW and decision == "deny":
            return "expected allow, hook denied"
        if expect == DENY and decision != "deny":
            return f"expected permissionDecision=deny, got {decision!r}"
        return None

    if agent == "hermes":
        if exit_code != 0:
            return f"expected exit 0, got {exit_code}"
        try:
            data = json.loads(text or "{}")
        except (json.JSONDecodeError, ValueError):
            return f"stdout is not valid JSON: {text[:120]!r}"
        blocked = isinstance(data, dict) and data.get("action") == "block"
        if expect == ALLOW and blocked:
            return "expected allow, hook blocked"
        if expect == DENY and not blocked:
            return f"expected action=block, got {text[:120]!r}"
        return None

    return f"unknown agent {agent!r}"


# ---------------------------------------------------------------------------
# Selftest over installed hooks
# ---------------------------------------------------------------------------


@dataclass
class SelftestResult:
    agent: str
    script: str
    case: str
    ok: bool
    detail: str = field(default="")


def _agent_scripts(project_dir: Path) -> dict[str, list[Path]]:
    return {
        "claude": [
            project_dir / ".claude" / "hooks" / "ownlock-shield.sh",
            project_dir / ".claude" / "hooks" / "ownlock-shield.ps1",
        ],
        "cursor": [
            project_dir / ".cursor" / "hooks" / "ownlock-shield.sh",
            project_dir / ".cursor" / "hooks" / "ownlock-shield.ps1",
        ],
        "hermes": [
            project_dir / ".ownlock" / "hooks" / "ownlock-hermes-shield.sh",
            project_dir / ".ownlock" / "hooks" / "ownlock-hermes-shield.ps1",
        ],
    }


def run_selftest(project_dir: Path) -> list[SelftestResult]:
    """Execute every installed shield hook against the payload matrix.

    Scripts whose interpreter is missing on this machine are skipped (a .ps1
    on a box without PowerShell is not a failure). Returns an empty list when
    no hook script exists at all — the caller should suggest ``ownlock shield``.
    """
    project_dir = project_dir.resolve()
    bash = find_bash()
    powershell = find_powershell()
    results: list[SelftestResult] = []

    for agent, scripts in _agent_scripts(project_dir).items():
        for script in scripts:
            if not script.exists():
                continue
            interpreter = powershell if script.suffix == ".ps1" else bash
            if interpreter is None:
                continue
            try:
                rel = str(script.relative_to(project_dir)).replace("\\", "/")
            except ValueError:
                rel = str(script)
            for case_name, payload, expect in CASES_BY_AGENT[agent]:
                try:
                    exit_code, stdout = run_hook(script, payload)
                except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
                    results.append(
                        SelftestResult(agent, rel, case_name, False, f"failed to run: {exc}")
                    )
                    continue
                detail = evaluate(agent, expect, exit_code, stdout)
                results.append(SelftestResult(agent, rel, case_name, detail is None, detail or ""))
    return results


SELFTEST_MARKER_REL = ".ownlock/selftest.json"


def write_selftest_marker(project_dir: Path, results: list[SelftestResult]) -> None:
    """Persist a small summary so `ownlock status` can tell selftest has run."""
    from datetime import UTC, datetime

    marker = project_dir.resolve() / SELFTEST_MARKER_REL
    marker.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "ts": datetime.now(UTC).isoformat(),
        "passed": sum(1 for r in results if r.ok),
        "failed": sum(1 for r in results if not r.ok),
    }
    marker.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def selftest_marker_exists(project_dir: Path) -> bool:
    return (project_dir.resolve() / SELFTEST_MARKER_REL).exists()


def selftest_passed(project_dir: Path) -> bool:
    """True only when a marker exists and records zero failures."""
    marker = project_dir.resolve() / SELFTEST_MARKER_REL
    if not marker.exists():
        return False
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return False
    return isinstance(data, dict) and int(data.get("failed", 1)) == 0
