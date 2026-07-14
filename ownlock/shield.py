"""Harden a project directory against AI agents reading secrets on disk."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Optional

SHIELD_MARKER = "# ownlock-shield"
HERMES_BEGIN = "# ownlock-shield-begin"
HERMES_END = "# ownlock-shield-end"
PI_EXTENSION_REL = ".ownlock/pi/ownlock-shield.js"
# Paths in .pi/settings.json resolve relative to .pi/
PI_EXTENSION_FROM_PI = "../.ownlock/pi/ownlock-shield.js"

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

# Token-boundary match: API_KEY / GH_TOKEN match; CUSTOM_TOKENIZER / SECRETARY do not.
_SECRET_KEY_RE = re.compile(
    r"(^|_)(api[_-]?key|token|password|passwd|secret|credential|private[_-]?key|"
    r"access[_-]?key|auth[_-]?token|client[_-]?secret|bearer)(_|$)",
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

_CURSOR_HOOK_SH = """#!/usr/bin/env bash
# Installed by `ownlock shield` — Cursor hooks (beforeReadFile / beforeShellExecution / preToolUse).
set -euo pipefail
INPUT=$(cat)
deny() {
  jq -n --arg msg "$1" '{permission: "deny", user_message: $msg}'
  exit 2
}
FILE=$(echo "$INPUT" | jq -r '
  [
    .file_path // empty,
    .path // empty,
    .cwd // empty,
    .working_directory // empty,
    .tool_input.file_path // empty,
    .tool_input.path // empty,
    .tool_input.pattern // empty,
    .tool_input.glob // empty,
    .tool_input.target_directory // empty,
    .tool_input.cwd // empty,
    .tool_input.working_directory // empty
  ] | map(select(length > 0)) | join("\n")
' 2>/dev/null || true)
CMD=$(echo "$INPUT" | jq -r '.command // .tool_input.command // empty' 2>/dev/null || true)
HAY="${FILE}"$'\\n'"${CMD}"
if echo "$HAY" | grep -qE '(^|[/\\\\])\\.env([.]|$|/|\\\\)|(^|[/\\\\])\\.env$' 2>/dev/null; then
  deny "ownlock shield: .env files are blocked"
fi
if echo "$HAY" | grep -qE '(^|[/\\\\])\\.ownlock([/\\\\]|$)' 2>/dev/null; then
  deny "ownlock shield: .ownlock/ is blocked"
fi
if echo "$CMD" | grep -qE '\\.env\\b|\\.ownlock' 2>/dev/null; then
  deny "ownlock shield: shell access to .env/.ownlock is blocked"
fi
exit 0
"""

_CURSOR_HOOK_PS1 = r"""# Installed by `ownlock shield` — Cursor hooks.
$ErrorActionPreference = 'Stop'
$inputJson = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($inputJson)) { exit 0 }
try { $obj = $inputJson | ConvertFrom-Json } catch { exit 0 }

function Deny-Cursor([string]$Msg) {
  (@{ permission = 'deny'; user_message = $Msg } | ConvertTo-Json -Compress)
  exit 2
}

$parts = @()
foreach ($name in @('file_path', 'path', 'cwd', 'working_directory')) {
  if ($null -ne $obj.$name -and "$($obj.$name)".Length -gt 0) { $parts += [string]$obj.$name }
}
if ($null -ne $obj.tool_input) {
  foreach ($name in @('file_path', 'path', 'pattern', 'glob', 'target_directory', 'cwd', 'working_directory')) {
    $val = $obj.tool_input.$name
    if ($null -ne $val -and "$val".Length -gt 0) { $parts += [string]$val }
  }
}
$cmd = ''
if ($null -ne $obj.command) { $cmd = [string]$obj.command }
elseif ($null -ne $obj.tool_input -and $null -ne $obj.tool_input.command) {
  $cmd = [string]$obj.tool_input.command
}
$hay = ($parts + @($cmd)) -join "`n"
if ($hay -match '(^|[/\\])\.env([.]|$|/|\\)|(^|[/\\])\.env$') {
  Deny-Cursor 'ownlock shield: .env files are blocked'
}
if ($hay -match '(^|[/\\])\.ownlock([/\\]|$)') {
  Deny-Cursor 'ownlock shield: .ownlock/ is blocked'
}
if ($cmd -match '\.env\b|\.ownlock') {
  Deny-Cursor 'ownlock shield: shell access to .env/.ownlock is blocked'
}
exit 0
"""

_HERMES_HOOK_SH = """#!/usr/bin/env bash
# Installed by `ownlock shield` — Hermes pre_tool_call shell hook.
set -euo pipefail
INPUT=$(cat)
deny() {
  jq -n --arg msg "$1" '{action: "block", message: $msg}'
  exit 0
}
FILE=$(echo "$INPUT" | jq -r '
  [
    .tool_input.file_path // empty,
    .tool_input.path // empty,
    .tool_input.pattern // empty,
    .tool_input.glob // empty,
    .tool_input.target_directory // empty
  ] | map(select(length > 0)) | join("\n")
' 2>/dev/null || true)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || true)
HAY="${FILE}"$'\\n'"${CMD}"
if echo "$HAY" | grep -qE '(^|[/\\\\])\\.env([.]|$|/|\\\\)|(^|[/\\\\])\\.env$' 2>/dev/null; then
  deny "ownlock shield: .env files are blocked"
fi
if echo "$HAY" | grep -qE '(^|[/\\\\])\\.ownlock([/\\\\]|$)' 2>/dev/null; then
  deny "ownlock shield: .ownlock/ is blocked"
fi
if echo "$CMD" | grep -qE '\\.env\\b|\\.ownlock' 2>/dev/null; then
  deny "ownlock shield: shell access to .env/.ownlock is blocked"
fi
printf '{}\\n'
exit 0
"""

_HERMES_HOOK_PS1 = r"""# Installed by `ownlock shield` — Hermes pre_tool_call shell hook.
$ErrorActionPreference = 'Stop'
$inputJson = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($inputJson)) { Write-Output '{}'; exit 0 }
try { $obj = $inputJson | ConvertFrom-Json } catch { Write-Output '{}'; exit 0 }

function Deny-Hermes([string]$Msg) {
  (@{ action = 'block'; message = $Msg } | ConvertTo-Json -Compress)
  exit 0
}

$parts = @()
if ($null -ne $obj.tool_input) {
  foreach ($name in @('file_path', 'path', 'pattern', 'glob', 'target_directory')) {
    $val = $obj.tool_input.$name
    if ($null -ne $val -and "$val".Length -gt 0) { $parts += [string]$val }
  }
}
$cmd = ''
if ($null -ne $obj.tool_input -and $null -ne $obj.tool_input.command) {
  $cmd = [string]$obj.tool_input.command
}
$hay = ($parts + @($cmd)) -join "`n"
if ($hay -match '(^|[/\\])\.env([.]|$|/|\\)|(^|[/\\])\.env$') {
  Deny-Hermes 'ownlock shield: .env files are blocked'
}
if ($hay -match '(^|[/\\])\.ownlock([/\\]|$)') {
  Deny-Hermes 'ownlock shield: .ownlock/ is blocked'
}
if ($cmd -match '\.env\b|\.ownlock') {
  Deny-Hermes 'ownlock shield: shell access to .env/.ownlock is blocked'
}
Write-Output '{}'
exit 0
"""

_PI_EXTENSION_JS = r"""// Installed by `ownlock shield` — Pi extension (tool_call interceptor).
// Defensive: no-ops if ExtensionAPI.on is missing.
function looksBlocked(hay) {
  if (!hay) return null;
  const s = String(hay);
  if (/(^|[/\\])\.env([.]|$|[/\\])|(^|[/\\])\.env$/.test(s)) {
    return "ownlock shield: .env files are blocked";
  }
  if (/(^|[/\\])\.ownlock([/\\]|$)/.test(s)) {
    return "ownlock shield: .ownlock/ is blocked";
  }
  if (/\.env\b|\.ownlock/.test(s)) {
    return "ownlock shield: shell access to .env/.ownlock is blocked";
  }
  return null;
}

export default function (pi) {
  if (!pi || typeof pi.on !== "function") {
    console.warn("ownlock-shield: Pi ExtensionAPI.on missing; no-op");
    return;
  }
  pi.on("tool_call", async (event) => {
    const input = (event && event.input) || {};
    const parts = [
      input.file_path,
      input.path,
      input.pattern,
      input.glob,
      input.target_directory,
      input.command,
      event && event.toolName,
    ].filter(Boolean);
    const reason = looksBlocked(parts.join("\n"));
    if (reason) {
      return { block: true, reason };
    }
  });
}
"""


def _claude_hook_basename() -> str:
    return "ownlock-shield.ps1" if os.name == "nt" else "ownlock-shield.sh"


def _claude_hook_body() -> str:
    return _HOOK_SCRIPT_PS1 if os.name == "nt" else _HOOK_SCRIPT


def _hook_command(rel_hook: str) -> str:
    if os.name == "nt":
        return f"powershell -NoProfile -File {rel_hook}"
    return rel_hook


def _cursor_hook_rel() -> str:
    name = "ownlock-shield.ps1" if os.name == "nt" else "ownlock-shield.sh"
    return f".cursor/hooks/{name}"


def _hermes_hook_basename() -> str:
    return "ownlock-hermes-shield.ps1" if os.name == "nt" else "ownlock-hermes-shield.sh"


def _write_script(path: Path, body: str, *, force: bool) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not force and path.exists() and path.read_text(encoding="utf-8") == body:
        return False
    path.write_text(body, encoding="utf-8")
    if os.name == "posix" and path.suffix == ".sh":
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return True


def _entry_commands(entry: dict) -> list[str]:
    cmds: list[str] = []
    if isinstance(entry.get("command"), str):
        cmds.append(entry["command"])
    for h in entry.get("hooks") or []:
        if isinstance(h, dict) and isinstance(h.get("command"), str):
            cmds.append(h["command"])
    return cmds


def _upsert_command_hooks(entries: list, marker: str, new_entry: dict) -> bool:
    """Replace entries whose command mentions *marker* with *new_entry* (idempotent)."""
    others: list = []
    ownlock: list = []
    for entry in entries:
        if isinstance(entry, dict) and any(marker in c for c in _entry_commands(entry)):
            ownlock.append(entry)
        else:
            others.append(entry)
    if len(ownlock) == 1 and ownlock[0] == new_entry:
        return False
    entries[:] = others + [new_entry]
    return True

def _remove_marker_block(text: str, begin: str, end: str) -> str:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    skipping = False
    for line in lines:
        stripped = line.strip()
        if stripped == begin:
            skipping = True
            continue
        if skipping:
            if stripped == end:
                skipping = False
            continue
        out.append(line)
    return "".join(out)


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


def _emit_claude(project_dir: Path, *, force: bool) -> dict[str, bool]:
    results: dict[str, bool] = {}
    claude_dir = project_dir / ".claude"
    hook_name = _claude_hook_basename()
    hook_path = claude_dir / "hooks" / hook_name
    settings_path = claude_dir / "settings.json"
    rel_key = f".claude/hooks/{hook_name}"
    results[rel_key] = _write_script(hook_path, _claude_hook_body(), force=force)

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
    if deny != perms.get("deny"):
        perms["deny"] = deny

    hooks = settings.setdefault("hooks", {})
    pre: list = hooks.setdefault("PreToolUse", [])
    rel_hook = str(hook_path.relative_to(project_dir)).replace("\\", "/")
    hook_entry = {
        "matcher": "Read|Edit|Write|Grep|Search|Glob|Bash",
        "hooks": [{"type": "command", "command": _hook_command(rel_hook)}],
    }
    if _upsert_command_hooks(pre, "ownlock-shield", hook_entry):
        changed_settings = True

    if changed_settings:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    results[".claude/settings.json"] = changed_settings
    return results


def _emit_cursor(project_dir: Path, *, force: bool) -> dict[str, bool]:
    results: dict[str, bool] = {}
    hooks_dir = project_dir / ".cursor" / "hooks"
    results[".cursor/hooks/ownlock-shield.sh"] = _write_script(
        hooks_dir / "ownlock-shield.sh", _CURSOR_HOOK_SH, force=force
    )
    results[".cursor/hooks/ownlock-shield.ps1"] = _write_script(
        hooks_dir / "ownlock-shield.ps1", _CURSOR_HOOK_PS1, force=force
    )

    rel = _cursor_hook_rel().replace("\\", "/")
    cmd = _hook_command(rel)
    desired = {
        "version": 1,
        "hooks": {
            "beforeReadFile": [{"command": cmd, "failClosed": True}],
            "beforeShellExecution": [{"command": cmd, "failClosed": True}],
            # No matcher: cover Edit/Search/Glob/Task and MCP:<name> tools too.
            "preToolUse": [{"command": cmd, "failClosed": True}],
        },
    }
    hooks_path = project_dir / ".cursor" / "hooks.json"
    existing: dict = {}
    if hooks_path.exists():
        try:
            existing = json.loads(hooks_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = {}

    if not isinstance(existing, dict):
        existing = {}
    hooks = existing.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        existing["hooks"] = hooks
    existing["version"] = 1

    for event, entries in desired["hooks"].items():
        current = list(hooks.get(event) or [])
        kept = [
            e
            for e in current
            if not (
                isinstance(e, dict)
                and isinstance(e.get("command"), str)
                and "ownlock-shield" in e["command"]
            )
        ]
        for entry in entries:
            if entry not in kept:
                kept.append(entry)
        hooks[event] = kept

    new_text = json.dumps(existing, indent=2) + "\n"
    if hooks_path.exists() and hooks_path.read_text(encoding="utf-8") == new_text:
        results[".cursor/hooks.json"] = False
    else:
        hooks_path.parent.mkdir(parents=True, exist_ok=True)
        hooks_path.write_text(new_text, encoding="utf-8")
        results[".cursor/hooks.json"] = True
    return results

def _yaml_single_quoted(value: str) -> str:
    """Return a YAML single-quoted scalar (backslashes literal; safe on Windows)."""
    return "'" + value.replace("'", "''") + "'"


def _hermes_hook_item(script_abs: Path) -> str:
    cmd = _yaml_single_quoted(str(script_abs))
    return (
        f'    - matcher: ".*"\n'
        f"      command: {cmd}\n"
        f"      timeout: 5\n"
    )


def _hermes_snippet(script_abs: Path) -> str:
    return (
        "# Merge into ~/.hermes/config.yaml (or run ownlock shield when ~/.hermes exists)\n"
        "hooks:\n"
        "  pre_tool_call:\n"
        f"{_hermes_hook_item(script_abs)}"
    )


def _hermes_command_line(script_abs: Path) -> str:
    return f"      command: {_yaml_single_quoted(str(script_abs))}"


def _replace_stale_hermes_commands(raw: str, script_abs: Path) -> str:
    """Rewrite any ownlock-hermes-shield command lines to the current absolute path."""
    wanted = _hermes_command_line(script_abs)
    out: list[str] = []
    for line in raw.splitlines(keepends=True):
        if "ownlock-hermes-shield" in line and "command:" in line:
            nl = "\n" if line.endswith("\n") else ""
            out.append(wanted + nl)
        else:
            out.append(line)
    return "".join(out)


def _merge_hermes_config(config_path: Path, script_abs: Path) -> bool:
    """Idempotently ensure a pre_tool_call entry for the Hermes shield script."""
    original = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    raw = _remove_marker_block(original, HERMES_BEGIN, HERMES_END)

    # Already wired: refresh command path if stale; never append orphan list items.
    if "ownlock-hermes-shield" in raw:
        refreshed = _replace_stale_hermes_commands(raw, script_abs)
        new_text = refreshed if (not refreshed or refreshed.endswith("\n")) else refreshed + "\n"
        if new_text == original:
            return False
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(new_text, encoding="utf-8")
        return True

    item = _hermes_hook_item(script_abs)
    block = f"{HERMES_BEGIN}\n{item}{HERMES_END}\n"

    if re.search(r"(?m)^\s*pre_tool_call\s*:", raw):
        lines = raw.splitlines(keepends=True)
        new_lines: list[str] = []
        inserted = False
        for line in lines:
            new_lines.append(line)
            if not inserted and re.match(r"^\s*pre_tool_call\s*:", line):
                new_lines.append(block if block.endswith("\n") else block + "\n")
                inserted = True
        new_text = "".join(new_lines)
        if not inserted:
            new_text = raw.rstrip() + "\n\n" + f"hooks:\n  pre_tool_call:\n{block}"
    elif re.search(r"(?m)^\s*hooks\s*:", raw):
        # Nest under the existing hooks: key (do not append a sibling at EOF).
        lines = raw.splitlines(keepends=True)
        new_lines: list[str] = []
        inserted = False
        for line in lines:
            new_lines.append(line)
            if not inserted and re.match(r"^\s*hooks\s*:", line):
                new_lines.append(f"  pre_tool_call:\n{block}")
                inserted = True
        new_text = "".join(new_lines) if inserted else (
            raw.rstrip() + "\n\n" + f"hooks:\n  pre_tool_call:\n{block}"
        )
    else:
        new_text = (raw.rstrip() + "\n\n" if raw.strip() else "") + (
            f"hooks:\n  pre_tool_call:\n{block}"
        )

    if new_text == original:
        return False
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(new_text, encoding="utf-8")
    return True


def _emit_hermes(
    project_dir: Path,
    *,
    force: bool,
    hermes_home: Optional[Path] = None,
) -> dict[str, bool]:
    results: dict[str, bool] = {}
    hooks_dir = project_dir / ".ownlock" / "hooks"
    results[".ownlock/hooks/ownlock-hermes-shield.sh"] = _write_script(
        hooks_dir / "ownlock-hermes-shield.sh", _HERMES_HOOK_SH, force=force
    )
    results[".ownlock/hooks/ownlock-hermes-shield.ps1"] = _write_script(
        hooks_dir / "ownlock-hermes-shield.ps1", _HERMES_HOOK_PS1, force=force
    )

    active = hooks_dir / _hermes_hook_basename()
    script_abs = active.resolve()
    snippet_path = project_dir / ".ownlock" / "hermes-hooks.snippet.yaml"
    snippet = _hermes_snippet(script_abs)
    if force or not snippet_path.exists() or snippet_path.read_text(encoding="utf-8") != snippet:
        snippet_path.parent.mkdir(parents=True, exist_ok=True)
        snippet_path.write_text(snippet, encoding="utf-8")
        results[".ownlock/hermes-hooks.snippet.yaml"] = True
    else:
        results[".ownlock/hermes-hooks.snippet.yaml"] = False

    # Avoid Path.home() — it follows os.name and breaks under Windows monkeypatches on POSIX.
    home = (
        hermes_home
        if hermes_home is not None
        else Path(os.path.expanduser("~")) / ".hermes"
    )
    config_path = home / "config.yaml"
    if home.is_dir() or config_path.exists():
        results["~/.hermes/config.yaml"] = _merge_hermes_config(config_path, script_abs)
    else:
        results["~/.hermes/config.yaml"] = False
        results["hermes_tip"] = True
    return results


def _emit_pi(project_dir: Path, *, force: bool) -> dict[str, bool]:
    results: dict[str, bool] = {}
    ext_path = project_dir / PI_EXTENSION_REL
    results[PI_EXTENSION_REL] = _write_script(ext_path, _PI_EXTENSION_JS, force=force)

    settings_path = project_dir / ".pi" / "settings.json"
    settings: dict = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            settings = {}

    exts = list(settings.get("extensions") or [])
    # Normalize to the path Pi resolves from .pi/
    wanted = PI_EXTENSION_FROM_PI
    changed = False
    # Drop stale ownlock shield extension paths, then ensure wanted.
    cleaned = [
        e
        for e in exts
        if not (isinstance(e, str) and "ownlock-shield" in e and e != wanted)
    ]
    if wanted not in cleaned:
        cleaned.append(wanted)
        changed = True
    if cleaned != exts:
        changed = True
    if changed:
        settings["extensions"] = cleaned
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    results[".pi/settings.json"] = changed
    return results


def install_shield(
    project_dir: Path,
    *,
    force: bool = False,
    hermes_home: Optional[Path] = None,
) -> dict[str, bool]:
    """Write ignore files and Claude/Cursor/Hermes/Pi shield artifacts."""
    project_dir = project_dir.resolve()
    results: dict[str, bool] = {}

    for name in (".cursorignore", ".claudeignore"):
        results[name] = _merge_ignore_file(project_dir / name, IGNORE_ENTRIES)

    results.update(_emit_claude(project_dir, force=force))
    results.update(_emit_cursor(project_dir, force=force))
    results.update(_emit_hermes(project_dir, force=force, hermes_home=hermes_home))
    results.update(_emit_pi(project_dir, force=force))
    return results


def _verify_claude(project_dir: Path, issues: list[str]) -> None:
    sh = project_dir / ".claude" / "hooks" / "ownlock-shield.sh"
    ps1 = project_dir / ".claude" / "hooks" / "ownlock-shield.ps1"
    if not sh.exists() and not ps1.exists():
        issues.append("Missing .claude/hooks/ownlock-shield.sh or .ps1")
    elif sh.exists() and os.name == "posix" and not os.access(sh, os.X_OK):
        issues.append("Hook script is not executable")

    settings = project_dir / ".claude" / "settings.json"
    if not settings.exists():
        issues.append("Missing .claude/settings.json")
        return
    try:
        data = json.loads(settings.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        issues.append(".claude/settings.json is not valid JSON")
        return
    deny = data.get("permissions", {}).get("deny", [])
    if not any("Read(./.env" in d for d in deny):
        issues.append("Claude permissions.deny missing .env rules")
    pre = data.get("hooks", {}).get("PreToolUse", [])
    hook_wired = False
    for entry in pre:
        if not isinstance(entry, dict):
            continue
        for h in entry.get("hooks") or []:
            if isinstance(h, dict) and "ownlock-shield" in str(h.get("command", "")):
                hook_wired = True
                break
        if hook_wired:
            break
    if not hook_wired:
        issues.append("Claude PreToolUse hook not wired to ownlock-shield")


def _verify_cursor(project_dir: Path, issues: list[str]) -> None:
    sh = project_dir / ".cursor" / "hooks" / "ownlock-shield.sh"
    ps1 = project_dir / ".cursor" / "hooks" / "ownlock-shield.ps1"
    if not sh.exists() and not ps1.exists():
        issues.append("Missing .cursor/hooks/ownlock-shield script")
    hooks_path = project_dir / ".cursor" / "hooks.json"
    if not hooks_path.exists():
        issues.append("Missing .cursor/hooks.json")
        return
    try:
        data = json.loads(hooks_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        issues.append(".cursor/hooks.json is not valid JSON")
        return
    wired = False
    for event_hooks in (data.get("hooks") or {}).values():
        if not isinstance(event_hooks, list):
            continue
        for entry in event_hooks:
            if isinstance(entry, dict) and "ownlock-shield" in str(entry.get("command", "")):
                wired = True
                break
        if wired:
            break
    if not wired:
        issues.append("Cursor hooks.json not wired to ownlock-shield")


def _verify_hermes(
    project_dir: Path,
    issues: list[str],
    *,
    hermes_home: Optional[Path] = None,
) -> None:
    sh = project_dir / ".ownlock" / "hooks" / "ownlock-hermes-shield.sh"
    ps1 = project_dir / ".ownlock" / "hooks" / "ownlock-hermes-shield.ps1"
    if not sh.exists() and not ps1.exists():
        issues.append("Missing .ownlock/hooks/ownlock-hermes-shield script")
    home = (
        hermes_home
        if hermes_home is not None
        else Path(os.path.expanduser("~")) / ".hermes"
    )
    config_path = home / "config.yaml"
    if config_path.exists():
        text = config_path.read_text(encoding="utf-8")
        if "ownlock-hermes-shield" not in text and HERMES_BEGIN not in text:
            issues.append("Hermes config.yaml missing ownlock shield hook")


def _verify_pi(project_dir: Path, issues: list[str]) -> None:
    ext = project_dir / PI_EXTENSION_REL
    if not ext.exists():
        issues.append(f"Missing {PI_EXTENSION_REL}")
    settings = project_dir / ".pi" / "settings.json"
    if not settings.exists():
        issues.append("Missing .pi/settings.json")
        return
    try:
        data = json.loads(settings.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        issues.append(".pi/settings.json is not valid JSON")
        return
    exts = data.get("extensions") or []
    if not any(isinstance(e, str) and "ownlock-shield" in e for e in exts):
        issues.append("Pi settings.json missing ownlock-shield extension")


def verify_shield(
    project_dir: Path,
    *,
    hermes_home: Optional[Path] = None,
) -> list[str]:
    """Return human-readable failures when shield artifacts are missing."""
    project_dir = project_dir.resolve()
    issues: list[str] = []
    for name in (".cursorignore", ".claudeignore"):
        path = project_dir / name
        if not path.exists() or SHIELD_MARKER not in path.read_text(encoding="utf-8"):
            issues.append(f"Missing or incomplete {name}")
    _verify_claude(project_dir, issues)
    _verify_cursor(project_dir, issues)
    _verify_hermes(project_dir, issues, hermes_home=hermes_home)
    _verify_pi(project_dir, issues)
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
