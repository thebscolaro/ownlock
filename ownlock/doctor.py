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
