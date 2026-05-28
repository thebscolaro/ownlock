"""Diagnostic state collection for ``ownlock doctor``.

Walks the user's environment without ever decrypting a secret:

* Reads vault meta (schema version, KDF iterations, secret count) by opening
  the SQLite file directly — no passphrase needed.
* Resolves which source ``OWNLOCK_PASSPHRASE`` would come from right now,
  without printing the value.
* Surfaces stale plaintext leftovers (legacy backups, ``.ownlock-tmp``) that
  ``ownlock scan`` would also flag.
* Checks ``.gitignore`` covers ``.ownlock/``.

Returned as a plain ``dict`` so the CLI can render it (Rich text) or emit it
as JSON (``ownlock doctor --json`` / the ``ownlock_doctor`` MCP tool) without
duplicating the gathering logic.
"""

from __future__ import annotations

import importlib.util
import os
import sqlite3
import sys
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Any

from rich.console import Console

from ownlock import vault as _vault_module
from ownlock.backups import LEGACY_BACKUP_SUFFIX
from ownlock.crypto import KDF_ITERATIONS_CURRENT
from ownlock.vault import VaultManager


def passphrase_source() -> str:
    """Identify which source would resolve the passphrase right now.

    Mirrors :func:`ownlock.keyring_util.resolve_passphrase`'s precedence
    (env var > keyring > prompt) but does not return the value itself.
    """
    if os.environ.get("OWNLOCK_PASSPHRASE"):
        return "env var"
    try:
        from ownlock.keyring_util import get_passphrase

        if get_passphrase():
            return "keyring"
    except Exception:
        return "keyring (unavailable)"
    return "would prompt"


def vault_health(vault_path: Path) -> dict[str, Any]:
    """Return a dict describing a vault's existence + meta, no values exposed.

    Reads the SQLite ``meta`` table directly so this works without the user's
    passphrase. A vault file predating the meta table is reported as schema
    v1 with the legacy 200_000 KDF iterations.
    """
    info: dict[str, Any] = {
        "path": str(vault_path),
        "exists": vault_path.exists(),
    }
    if not info["exists"]:
        return info

    try:
        conn = sqlite3.connect(str(vault_path))
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute("SELECT key, value FROM meta")
            meta = {row["key"]: row["value"] for row in cursor.fetchall()}
        except sqlite3.OperationalError:
            meta = {}  # legacy vault without meta table
        try:
            secret_count = conn.execute("SELECT COUNT(*) AS n FROM secrets").fetchone()["n"]
        except sqlite3.OperationalError:
            secret_count = 0
        conn.close()
    except sqlite3.DatabaseError as e:
        info["error"] = str(e)
        return info

    schema_version = int(meta.get("schema_version", "1"))
    kdf_iterations = int(meta.get("kdf_iterations", "200000"))
    info.update(
        {
            "schema_version": schema_version,
            "kdf_algo": meta.get("kdf_algo", "PBKDF2-HMAC-SHA256"),
            "kdf_iterations": kdf_iterations,
            "kdf_stale": kdf_iterations < KDF_ITERATIONS_CURRENT,
            "secret_count": secret_count,
        }
    )
    return info


def _scan_cwd_for_stale_files(cwd: Path) -> tuple[list[str], list[str]]:
    """Find legacy ``.ownlock.bak`` files and partial ``.ownlock-tmp`` renders.

    Returns ``(legacy_backups, stale_tmp)`` lists. Best-effort; OSError on
    any branch yields empty results rather than tanking ``doctor``.
    """
    legacy: list[str] = []
    stale: list[str] = []
    skip = {".git", "node_modules", ".venv", ".ownlock"}
    try:
        for path in cwd.rglob("*"):
            if any(part in skip for part in path.parts):
                continue
            if not path.is_file():
                continue
            if path.name.endswith(LEGACY_BACKUP_SUFFIX):
                legacy.append(str(path))
            elif path.name.startswith(".") and ".ownlock-tmp" in path.name:
                stale.append(str(path))
    except OSError:
        pass
    return legacy, stale


def _gitignore_status(cwd: Path) -> bool | None:
    """Return True if ``.gitignore`` covers ``.ownlock``, False if not, None on read error."""
    gitignore = cwd / ".gitignore"
    if not gitignore.exists():
        return False
    try:
        return ".ownlock" in gitignore.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def gather_doctor_state() -> dict[str, Any]:
    """Collect everything ``ownlock doctor`` reports, no secret values."""
    pv = VaultManager.find_project_vault()
    # Look up GLOBAL_VAULT_PATH lazily through the module attribute so tests
    # that monkeypatch ``ownlock.vault.GLOBAL_VAULT_PATH`` after import (and
    # ownlock at runtime if the home dir gets rebound) see the right path.
    state: dict[str, Any] = {
        "ownlock_version": pkg_version("ownlock"),
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "global_vault": vault_health(_vault_module.GLOBAL_VAULT_PATH),
        "project_vault": vault_health(pv) if pv else {"path": None, "exists": False},
        "ownlock_passphrase_env_set": bool(os.environ.get("OWNLOCK_PASSPHRASE")),
        "passphrase_source": passphrase_source(),
        "mcp_importable": importlib.util.find_spec("mcp.server.fastmcp") is not None,
    }
    try:
        from ownlock.keyring_util import get_passphrase

        state["keyring_passphrase_stored"] = bool(get_passphrase())
    except Exception as e:
        state["keyring_passphrase_stored"] = None
        state["keyring_error"] = str(e)

    legacy, stale = _scan_cwd_for_stale_files(Path.cwd())
    state["legacy_backups_in_cwd"] = legacy
    state["stale_render_tmp_files"] = stale
    state["gitignore_covers_ownlock"] = _gitignore_status(Path.cwd())
    return state


def render_doctor_report(state: dict[str, Any], console: Console) -> None:
    """Print the human-readable ``ownlock doctor`` report to *console*.

    Pulled out of ``cli.doctor`` so the CLI command body is small and so
    formatting can be unit-tested directly against a state dict. The
    ``--json`` output path bypasses this entirely.
    """
    console.print(f"[bold]ownlock[/bold] {state['ownlock_version']}")
    console.print(
        f"Python {state['python_version']} — {state['python_executable']}"
    )

    def _fmt_vault(label: str, info: dict[str, Any]) -> None:
        path = info.get("path")
        if path is None:
            console.print(f"{label}: (none found from cwd)")
            return
        if not info.get("exists"):
            console.print(f"{label}: {path} — missing")
            return
        line = f"{label}: {path} — exists"
        if "schema_version" in info:
            line += f", schema v{info['schema_version']}"
            line += f", {info['kdf_algo']} {info['kdf_iterations']:,} iters"
            if info.get("kdf_stale"):
                line += "  [yellow](stale)[/yellow]"
            line += f", {info['secret_count']} secret(s)"
        console.print(line)

    _fmt_vault("Global vault", state["global_vault"])
    _fmt_vault("Project vault", state["project_vault"])

    console.print(
        f"OWNLOCK_PASSPHRASE: {'set' if state['ownlock_passphrase_env_set'] else 'not set'}"
    )
    keyring_state = state.get("keyring_passphrase_stored")
    if keyring_state is None:
        console.print("Keyring passphrase: unavailable (error reading keyring)")
    else:
        console.print(
            f"Keyring passphrase: {'stored' if keyring_state else 'not stored'}"
        )
    console.print(f"Passphrase resolved from: {state['passphrase_source']}")

    if state["legacy_backups_in_cwd"]:
        console.print(
            f"[yellow]Legacy plaintext backups (*.ownlock.bak) found:[/yellow] "
            f"{len(state['legacy_backups_in_cwd'])} — move or delete these "
            f"(run [bold]ownlock scan[/bold] for details)."
        )
    if state["stale_render_tmp_files"]:
        console.print(
            f"[yellow]Stale render temp files (.ownlock-tmp) found:[/yellow] "
            f"{len(state['stale_render_tmp_files'])} — delete these manually."
        )

    if state["gitignore_covers_ownlock"] is False:
        console.print(
            "[yellow].gitignore does not cover .ownlock/ — run "
            "[bold]ownlock init[/bold] in this directory or add the entry "
            "manually.[/yellow]"
        )

    stale_global = state["global_vault"].get("kdf_stale")
    stale_project = state["project_vault"].get("kdf_stale")
    if stale_global or stale_project:
        target_flag = "--global" if stale_global and not stale_project else "--project"
        console.print(
            f"[dim]Tip: this vault uses KDF iterations below the current "
            f"default ({KDF_ITERATIONS_CURRENT:,}). Run "
            f"[bold]ownlock rekey --upgrade-kdf {target_flag} --yes[/bold] to "
            "upgrade.[/dim]"
        )

    console.print(
        f"MCP package importable: {'yes' if state['mcp_importable'] else 'no'} "
        "(pip install 'ownlock[mcp]')"
    )
