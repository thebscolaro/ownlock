"""MCP server: delegates all vault access to the `ownlock` CLI subprocess.

This module does not import crypto or open the vault; decryption happens only in the child
`ownlock` process (passphrase via env/keyring as usual). Tools return exit codes and captured
output from those subprocesses—not raw decrypted secrets as structured MCP fields.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

# Cursor / IDE configs often use stdio; keep instructions explicit for clients.
_INSTRUCTIONS = (
    "ownlock MCP: run commands with `ownlock run` (injected env, stdout redaction in child) "
    "and list secret names via `ownlock list`. Does not expose `get` or `export`. "
    "The MCP process does not decrypt the vault; the ownlock CLI subprocess does."
)

_MAX_IO_BYTES = 256_000

mcp = FastMCP("ownlock", instructions=_INSTRUCTIONS)


def _ownlock_argv() -> list[str]:
    exe = shutil.which("ownlock")
    if exe:
        return [exe]
    return [sys.executable, "-m", "ownlock"]


def _truncate(s: str) -> str:
    if len(s) <= _MAX_IO_BYTES:
        return s
    return s[:_MAX_IO_BYTES] + "\n… [truncated]"


def _resolve_cwd(cwd: Optional[str]) -> Optional[Path]:
    if cwd is None or cwd == "":
        return None
    return Path(cwd).expanduser().resolve()


def _run_ownlock(
    args: list[str],
    *,
    cwd: Optional[Path] = None,
    timeout: Optional[float] = None,
) -> subprocess.CompletedProcess[str]:
    cmd = _ownlock_argv() + args
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=os.environ.copy(),
    )


@mcp.tool()
def ownlock_run(
    command: list[str],
    cwd: Optional[str] = None,
    env_file: str = ".env",
    vault_env: str = "default",
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Run a command with env injection via `ownlock run` (subprocess). Same as: ownlock run -f <env_file> -e <vault_env> -- <command...>. Returns exit_code and captured stdout/stderr; decryption happens in the child process only."""
    if not command:
        return {"exit_code": 1, "stdout": "", "stderr": "command must be non-empty"}
    resolved = _resolve_cwd(cwd)
    args = ["run", "-f", env_file, "-e", vault_env, "--", *command]
    try:
        proc = _run_ownlock(args, cwd=resolved, timeout=float(timeout_seconds))
    except subprocess.TimeoutExpired:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"timeout after {timeout_seconds}s",
        }
    except OSError as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e)}
    return {
        "exit_code": proc.returncode,
        "stdout": _truncate(proc.stdout or ""),
        "stderr": _truncate(proc.stderr or ""),
    }


@mcp.tool()
def ownlock_list_secret_names(
    cwd: Optional[str] = None,
    env: Optional[str] = None,
    global_vault: bool = False,
    project: bool = False,
) -> str:
    """List secret names (never values) via `ownlock list` subprocess. Optional --env and vault flags."""
    resolved = _resolve_cwd(cwd)
    args = ["list"]
    if env is not None:
        args.extend(["--env", env])
    if global_vault:
        args.append("--global")
    if project:
        args.append("--project")
    try:
        proc = _run_ownlock(args, cwd=resolved, timeout=60.0)
    except (subprocess.TimeoutExpired, OSError) as e:
        return f"error: {e}"
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        return _truncate(out if out else f"exit {proc.returncode}")
    return _truncate(out)


@mcp.tool()
def ownlock_version() -> str:
    """Installed ownlock package version (from metadata; no vault access)."""
    from importlib.metadata import version

    return version("ownlock")


def main() -> None:
    """Stdio MCP entrypoint for IDEs (e.g. Cursor)."""
    mcp.run()


if __name__ == "__main__":
    main()
