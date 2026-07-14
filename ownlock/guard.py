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

# Explicit Process I/O — never pipe strings through PowerShell enumeration
# (that turns multi-line output into string[] and can append spurious newlines).
_GUARD_HOOK_SCRIPT_PS1 = r"""# Installed by `ownlock guard --install-hook` — redacts vault values from tool output.
$ErrorActionPreference = 'Stop'
$inputJson = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($inputJson)) { exit 0 }
try { $obj = $inputJson | ConvertFrom-Json } catch { exit 0 }

$text = $null
if ($null -ne $obj.tool_response) { $text = [string]$obj.tool_response }
elseif ($null -ne $obj.tool_output) { $text = [string]$obj.tool_output }
if ([string]::IsNullOrEmpty($text) -or $text -eq 'null') { exit 0 }

$ownlock = Get-Command ownlock -ErrorAction SilentlyContinue
if ($null -eq $ownlock) {
  Write-Error 'ownlock guard failed; refusing to pass unredacted tool output'
  exit 1
}

try {
  # Redirect stdout only — redirecting stderr without draining it can deadlock
  # when the child writes enough to fill the OS pipe buffer.
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $ownlock.Source
  $psi.Arguments = 'guard --stdin'
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $false
  $psi.CreateNoWindow = $true
  $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi
  [void]$proc.Start()
  $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
  $proc.StandardInput.Write($text)
  $proc.StandardInput.Close()
  $proc.WaitForExit()
  $redacted = [string]$stdoutTask.GetAwaiter().GetResult()
  if ($proc.ExitCode -ne 0) { throw 'guard failed' }
} catch {
  Write-Error 'ownlock guard failed; refusing to pass unredacted tool output'
  exit 1
}

if ($redacted -cne $text) {
  $payload = @{
    hookSpecificOutput = @{
      hookEventName = 'PostToolUse'
      updatedToolOutput = $redacted
    }
  } | ConvertTo-Json -Depth 6 -Compress
  Write-Output $payload
}
exit 0
"""


def _hook_basename() -> str:
    return "ownlock-guard.ps1" if os.name == "nt" else "ownlock-guard.sh"


def _hook_script_body() -> str:
    return _GUARD_HOOK_SCRIPT_PS1 if os.name == "nt" else _GUARD_HOOK_SCRIPT


def _hook_command(rel_hook: str) -> str:
    if os.name == "nt":
        return f"powershell -NoProfile -File {rel_hook}"
    return rel_hook


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
    hook_name = _hook_basename()
    hook_path = claude_dir / "hooks" / hook_name
    settings_path = claude_dir / "settings.json"
    hook_body = _hook_script_body()

    claude_dir.mkdir(parents=True, exist_ok=True)
    (claude_dir / "hooks").mkdir(parents=True, exist_ok=True)

    changed = False
    if force or not hook_path.exists() or hook_path.read_text(encoding="utf-8") != hook_body:
        hook_path.write_text(hook_body, encoding="utf-8")
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
    rel_hook = str(hook_path.relative_to(project_dir)).replace("\\", "/")
    entry = {
        "matcher": "Read|Edit|Write|Grep|Search|Glob|Bash",
        "hooks": [{"type": "command", "command": _hook_command(rel_hook)}],
    }
    if _upsert_command_hooks(post, "ownlock-guard", entry):
        changed = True

    if changed:
        settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return changed
