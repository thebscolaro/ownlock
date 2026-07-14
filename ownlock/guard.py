"""DLP guard: redact secret values from agent output streams."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

from ownlock.redactor import SecretRedactor

SHIELD_MARKER = "# ownlock-guard"

# Fail-closed: if ownlock guard cannot run, deny the tool output rather than
# leaking raw secrets into the agent context.
_GUARD_HOOK_SCRIPT = """#!/usr/bin/env bash
# Installed by `ownlock guard --install-hook` — redacts vault values from tool output.
set -euo pipefail
INPUT=$(cat)
TEXT=$(echo "$INPUT" | jq -r '.tool_response // .tool_output // empty' 2>/dev/null || true)
if [ -z "$TEXT" ] || [ "$TEXT" = "null" ]; then
  exit 0
fi
if ! REDACTED=$(printf '%s' "$TEXT" | ownlock guard --stdin 2>/dev/null); then
  echo "ownlock guard failed; refusing to pass unredacted tool output" >&2
  exit 1
fi
if [ "$REDACTED" != "$TEXT" ]; then
  jq -n --arg out "$REDACTED" \\
    '{hookSpecificOutput: {hookEventName: "PostToolUse", updatedToolOutput: $out}}'
fi
exit 0
"""


def redact_text(text: str, secrets: dict[str, str]) -> str:
    """Return *text* with known secrets replaced by placeholders."""
    if not secrets:
        return text
    return SecretRedactor(secrets).redact(text)


def guard_stdin(secrets: dict[str, str]) -> int:
    """Read stdin, redact, write stdout. Returns 0."""
    data = sys.stdin.read()
    sys.stdout.write(redact_text(data, secrets))
    return 0


def install_guard_hook(project_dir: Path, *, force: bool = False) -> bool:
    """Install PostToolUse hook that pipes tool output through ``ownlock guard``."""
    project_dir = project_dir.resolve()
    claude_dir = project_dir / ".claude"
    hook_path = claude_dir / "hooks" / "ownlock-guard.sh"
    settings_path = claude_dir / "settings.json"

    claude_dir.mkdir(parents=True, exist_ok=True)
    (claude_dir / "hooks").mkdir(parents=True, exist_ok=True)

    changed = False
    if force or not hook_path.exists() or hook_path.read_text(encoding="utf-8") != _GUARD_HOOK_SCRIPT:
        hook_path.write_text(_GUARD_HOOK_SCRIPT, encoding="utf-8")
        if os.name == "posix":
            hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        changed = True

    settings: dict = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            settings = {}

    hooks = settings.setdefault("hooks", {})
    post: list = hooks.setdefault("PostToolUse", [])
    rel_hook = str(hook_path.relative_to(project_dir))
    entry = {
        "matcher": "Read|Edit|Write|Grep|Search|Glob|Bash",
        "hooks": [{"type": "command", "command": rel_hook}],
    }
    if entry not in post:
        post.append(entry)
        changed = True

    if changed:
        settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return changed
