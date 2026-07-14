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


@mcp.tool()
def ownlock_doctor(cwd: Optional[str] = None) -> dict[str, Any]:
    """Run `ownlock doctor --json` in a subprocess. Returns vault paths, schema/KDF status, passphrase source — never decrypted values. The MCP process itself does not open the vault."""
    import json as _json

    resolved = _resolve_cwd(cwd)
    try:
        proc = _run_ownlock(["doctor", "--json"], cwd=resolved, timeout=30.0)
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"error": str(e)}
    if proc.returncode != 0:
        return {
            "error": f"ownlock doctor failed (exit {proc.returncode})",
            "stderr": _truncate(proc.stderr or ""),
        }
    try:
        return _json.loads(proc.stdout)
    except _json.JSONDecodeError as e:
        return {
            "error": f"could not parse doctor JSON: {e}",
            "stdout": _truncate(proc.stdout or ""),
        }


@mcp.tool()
def ownlock_status(
    cwd: Optional[str] = None,
    env: Optional[str] = None,
    global_vault: bool = False,
    project: bool = False,
) -> dict[str, Any]:
    """Quick vault summary: which vault is in use, secret count, environments. Wraps `ownlock list --json` and `ownlock doctor --json` (subprocess); no decryption in this process."""
    import json as _json

    resolved = _resolve_cwd(cwd)
    list_args = ["list", "--json"]
    if env is not None:
        list_args.extend(["--env", env])
    if global_vault:
        list_args.append("--global")
    if project:
        list_args.append("--project")

    try:
        list_proc = _run_ownlock(list_args, cwd=resolved, timeout=30.0)
        doctor_proc = _run_ownlock(["doctor", "--json"], cwd=resolved, timeout=30.0)
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"error": str(e)}

    rows: list[dict[str, Any]] = []
    if list_proc.returncode == 0:
        try:
            rows = _json.loads(list_proc.stdout)
        except _json.JSONDecodeError:
            pass

    info: dict[str, Any] = {}
    if doctor_proc.returncode == 0:
        try:
            info = _json.loads(doctor_proc.stdout)
        except _json.JSONDecodeError:
            pass

    project_vault = info.get("project_vault") or {}
    global_vault_info = info.get("global_vault") or {}
    selected = "global"
    if not global_vault and (project or project_vault.get("exists")):
        selected = "project"

    envs = sorted({row["env"] for row in rows if isinstance(row, dict) and "env" in row})

    return {
        "selected_vault": selected,
        "vault_path": (
            project_vault.get("path") if selected == "project" else global_vault_info.get("path")
        ),
        "secret_count": len(rows),
        "environments": envs,
        "schema_version": (
            project_vault.get("schema_version") if selected == "project"
            else global_vault_info.get("schema_version")
        ),
        "kdf_iterations": (
            project_vault.get("kdf_iterations") if selected == "project"
            else global_vault_info.get("kdf_iterations")
        ),
        "kdf_stale": (
            project_vault.get("kdf_stale") if selected == "project"
            else global_vault_info.get("kdf_stale")
        ),
        "passphrase_source": info.get("passphrase_source"),
    }


@mcp.tool()
def ownlock_request_access(
    secret_name: str,
    env: str = "default",
    reason: Optional[str] = None,
    cwd: Optional[str] = None,
    global_vault: bool = False,
    project: bool = False,
) -> dict[str, Any]:
    """Request human approval to read a policy-gated secret (confirm/session policies).

    Spawns `ownlock get` in a subprocess. Interactive approval happens in the
  terminal where ownlock runs; non-interactive callers receive an error.
    """
    resolved = _resolve_cwd(cwd)
    args = ["get", secret_name, "--env", env]
    if global_vault:
        args.append("--global")
    if project:
        args.append("--project")
    try:
        proc = _run_ownlock(args, cwd=resolved, timeout=120.0)
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"approved": False, "error": str(e)}
    if proc.returncode != 0:
        return {
            "approved": False,
            "error": _truncate((proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"),
        }
    return {
        "approved": True,
        "secret_name": secret_name,
        "env": env,
        "reason": reason,
        "note": "Value was printed to the ownlock subprocess stdout (not returned via MCP).",
    }


def main() -> None:
    """Stdio MCP entrypoint for IDEs (e.g. Cursor)."""
    mcp.run()


if __name__ == "__main__":
    main()
