"""Harden a project directory against AI agents reading secrets on disk."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Optional

SHIELD_MARKER = "# ownlock-shield"
IGNORE_ENTRIES: tuple[str, ...] = (
    ".env",
    ".env.*",
    "**/.ownlock/",
    "**/.ownlock/**",
    "**/*.ownlock.bak",
)

CLAUDE_DENY_PERMISSIONS: tuple[str, ...] = (
    "Read(./.env)",
    "Read(./.env.*)",
    "Read(./.ownlock/**)",
    "Read(./**/.ownlock/**)",
)

_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|token|password|passwd|secret|credential|private[_-]?key|"
    r"access[_-]?key|auth[_-]?token|client[_-]?secret|bearer)",
    re.IGNORECASE,
)
_OBVIOUS_NON_SECRET_RE = re.compile(
    r"^(true|false|yes|no|on|off|null|none|development|production|test|"
    r"staging|local|debug|info|warn|error|0|1)$",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"^(sk-|ghp_|gho_|github_pat_|xox[baprs]-|AKIA[0-9A-Z]{16})"
    r"|^[A-Za-z0-9+/_-]{24,}={0,2}$"
    r"|^[0-9a-fA-F]{32,}$"
)

_HOOK_SCRIPT = """#!/usr/bin/env bash
# Installed by `ownlock shield` — blocks agent tools from reading .env / .ownlock.
set -euo pipefail
INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty')
deny() {
  jq -n --arg reason "$1" \\
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
  exit 0
}
# Paths may appear as file_path, path, pattern (Glob), or target_directory.
path_haystack() {
  echo "$INPUT" | jq -r '
    [
      .tool_input.file_path // empty,
      .tool_input.path // empty,
      .tool_input.pattern // empty,
      .tool_input.glob // empty,
      .tool_input.target_directory // empty
    ] | map(select(length > 0)) | join("\\n")
  ' 2>/dev/null || true
}
case "$TOOL" in
  Read|Edit|Write|Grep|Search|Glob)
    FILE=$(path_haystack)
    # Match .env, .env.*, paths containing /.env, and Windows-style \\\\.env
    if echo "$FILE" | grep -qE '(^|[/\\\\])\\.env([.]|$|/|\\\\)|(^|[/\\\\])\\.env$' 2>/dev/null; then
      deny "ownlock shield: .env files are blocked"
    fi
    if echo "$FILE" | grep -qE '(^|[/\\\\])\\.ownlock([/\\\\]|$)' 2>/dev/null; then
      deny "ownlock shield: .ownlock/ is blocked"
    fi
    ;;
  Bash)
    CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
    if echo "$CMD" | grep -qE '\\.env\\b|\\.ownlock' 2>/dev/null; then
      deny "ownlock shield: shell access to .env/.ownlock is blocked"
    fi
    ;;
esac
exit 0
"""

_HOOK_SCRIPT_PS1 = r"""# Installed by `ownlock shield` — blocks agent tools from reading .env / .ownlock.
$ErrorActionPreference = 'Stop'
$inputJson = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($inputJson)) { exit 0 }
try { $obj = $inputJson | ConvertFrom-Json } catch { exit 0 }

function Deny-Reason([string]$Reason) {
  $payload = @{
    hookSpecificOutput = @{
      hookEventName = 'PreToolUse'
      permissionDecision = 'deny'
      permissionDecisionReason = $Reason
    }
  } | ConvertTo-Json -Depth 6 -Compress
  Write-Output $payload
  exit 0
}

function Get-PathHaystack($ToolInput) {
  if ($null -eq $ToolInput) { return '' }
  $parts = @()
  foreach ($name in @('file_path', 'path', 'pattern', 'glob', 'target_directory')) {
    $val = $ToolInput.$name
    if ($null -ne $val -and "$val".Length -gt 0) { $parts += "$val" }
  }
  return ($parts -join "`n")
}

$tool = [string]$obj.tool_name
$hay = Get-PathHaystack $obj.tool_input
switch -Regex ($tool) {
  '^(Read|Edit|Write|Grep|Search|Glob)$' {
    if ($hay -match '(^|[/\\])\.env([.]|$|/|\\)|(^|[/\\])\.env$') {
      Deny-Reason 'ownlock shield: .env files are blocked'
    }
    if ($hay -match '(^|[/\\])\.ownlock([/\\]|$)') {
      Deny-Reason 'ownlock shield: .ownlock/ is blocked'
    }
  }
  '^Bash$' {
    $cmd = ''
    if ($null -ne $obj.tool_input -and $null -ne $obj.tool_input.command) {
      $cmd = [string]$obj.tool_input.command
    }
    if ($cmd -match '\.env\b|\.ownlock') {
      Deny-Reason 'ownlock shield: shell access to .env/.ownlock is blocked'
    }
  }
}
exit 0
"""


def _hook_basename() -> str:
    return "ownlock-shield.ps1" if os.name == "nt" else "ownlock-shield.sh"


def _hook_script_body() -> str:
    return _HOOK_SCRIPT_PS1 if os.name == "nt" else _HOOK_SCRIPT


def _hook_command(rel_hook: str) -> str:
    if os.name == "nt":
        return f"powershell -NoProfile -File {rel_hook}"
    return rel_hook


def _merge_ignore_file(path: Path, entries: tuple[str, ...]) -> bool:
    """Append missing *entries* to an ignore file. Returns True if changed."""
    existing = ""
    if path.exists():
        existing = path.read_text(encoding="utf-8")
    if SHIELD_MARKER in existing:
        body = existing
    else:
        body = existing
        if body and not body.endswith("\n"):
            body += "\n"
        body += f"\n{SHIELD_MARKER}\n"
    changed = SHIELD_MARKER not in existing
    for entry in entries:
        if entry not in body:
            if not body.endswith("\n"):
                body += "\n"
            body += f"{entry}\n"
            changed = True
    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return changed


def install_shield(
    project_dir: Path,
    *,
    force: bool = False,
) -> dict[str, bool]:
    """Write ignore files, Claude settings, and PreToolUse hook under *project_dir*."""
    project_dir = project_dir.resolve()
    results: dict[str, bool] = {}

    for name in (".cursorignore", ".claudeignore"):
        results[name] = _merge_ignore_file(project_dir / name, IGNORE_ENTRIES)

    claude_dir = project_dir / ".claude"
    hook_name = _hook_basename()
    hook_path = claude_dir / "hooks" / hook_name
    settings_path = claude_dir / "settings.json"
    hook_body = _hook_script_body()

    claude_dir.mkdir(parents=True, exist_ok=True)
    (claude_dir / "hooks").mkdir(parents=True, exist_ok=True)

    rel_key = f".claude/hooks/{hook_name}"
    if force or not hook_path.exists() or hook_path.read_text(encoding="utf-8") != hook_body:
        hook_path.write_text(hook_body, encoding="utf-8")
        if os.name == "posix":
            hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        results[rel_key] = True
    else:
        results[rel_key] = False

    settings: dict = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            settings = {}

    changed_settings = False
    perms = settings.setdefault("permissions", {})
    deny: list[str] = list(perms.get("deny", []))
    for rule in CLAUDE_DENY_PERMISSIONS:
        if rule not in deny:
            deny.append(rule)
            changed_settings = True
    if changed_settings:
        perms["deny"] = deny

    hooks = settings.setdefault("hooks", {})
    pre: list = hooks.setdefault("PreToolUse", [])
    rel_hook = str(hook_path.relative_to(project_dir)).replace("\\", "/")
    hook_entry = {
        "matcher": "Read|Edit|Write|Grep|Search|Glob|Bash",
        "hooks": [{"type": "command", "command": _hook_command(rel_hook)}],
    }
    if hook_entry not in pre:
        pre.append(hook_entry)
        changed_settings = True

    if changed_settings:
        settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    results[".claude/settings.json"] = changed_settings

    return results


def verify_shield(project_dir: Path) -> list[str]:
    """Return human-readable failures when shield artifacts are missing."""
    project_dir = project_dir.resolve()
    issues: list[str] = []
    for name in (".cursorignore", ".claudeignore"):
        path = project_dir / name
        if not path.exists() or SHIELD_MARKER not in path.read_text(encoding="utf-8"):
            issues.append(f"Missing or incomplete {name}")
    hook_name = _hook_basename()
    hook = project_dir / ".claude" / "hooks" / hook_name
    if not hook.exists():
        issues.append(f"Missing .claude/hooks/{hook_name}")
    elif os.name == "posix" and not os.access(hook, os.X_OK):
        issues.append("Hook script is not executable")
    settings = project_dir / ".claude" / "settings.json"
    if not settings.exists():
        issues.append("Missing .claude/settings.json")
    else:
        try:
            data = json.loads(settings.read_text(encoding="utf-8"))
            deny = data.get("permissions", {}).get("deny", [])
            if not any("Read(./.env" in d for d in deny):
                issues.append("Claude permissions.deny missing .env rules")
            pre = data.get("hooks", {}).get("PreToolUse", [])
            hook_wired = False
            for entry in pre:
                if not isinstance(entry, dict):
                    continue
                for h in entry.get("hooks") or []:
                    if not isinstance(h, dict):
                        continue
                    cmd = str(h.get("command", ""))
                    if "ownlock-shield" in cmd:
                        hook_wired = True
                        break
                if hook_wired:
                    break
            if not hook_wired:
                issues.append("Claude PreToolUse hook not wired to ownlock-shield")
        except json.JSONDecodeError:
            issues.append(".claude/settings.json is not valid JSON")
    return issues


def _looks_secret_shaped(key: str, value: str) -> bool:
    """True when key or value resembles a secret (not a short non-secret enum)."""
    if not value or value.startswith("vault("):
        return False
    if _OBVIOUS_NON_SECRET_RE.match(value):
        return False
    if _SECRET_KEY_RE.search(key):
        return len(value) >= 4
    if _SECRET_VALUE_RE.search(value):
        return True
    return False


def simulate_agent_env_read(project_dir: Path) -> Optional[str]:
    """Return a leaked line if a plaintext secret-shaped .env value would be readable."""
    for pattern in (".env", ".env.local"):
        env_path = project_dir / pattern
        if not env_path.exists():
            continue
        text = env_path.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, val = stripped.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if _looks_secret_shaped(key, val):
                return f"{env_path.name} contains plaintext value (agent could read it)"
    return None
