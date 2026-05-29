"""Path validation, vault selection, and gitignore management.

These helpers are shared by every command in the CLI plus a few internal
modules (e.g. :mod:`ownlock.backups`). Pulled into one focused module so
``cli.py`` stays focused on command bodies, and so unit tests can target the
helpers directly without spinning up a Typer runner.

Conventions:

* ``validate_*`` helpers print a Rich error and raise ``typer.Exit(1)`` on
  bad input — they're meant to be called at the top of a CLI command, not
  from library code. Library callers should validate paths themselves.
* :func:`resolve_vault_path` is the single source of truth for the project /
  global vault selection rules used by every subcommand.
* :func:`is_tty` exists so tests can monkeypatch one symbol instead of two
  ``isatty`` checks.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import typer
from rich.console import Console

from ownlock import vault as _vault_module
from ownlock.vault import (
    PROJECT_VAULT_DB,
    PROJECT_VAULT_DIR,
    VaultManager,
)

# Shared with the rest of the codebase (resolver/templates re-export their
# own copies for backwards compatibility, but new code should import from
# here).
SECRET_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

OWNLOCK_GITIGNORE_ENTRY = "\n# ownlock vault (never commit)\n.ownlock/\n"

_console = Console()


def format_vault_path(path: Path) -> str:
    """Return a user-safe display path (e.g. ``~/.ownlock/vault.db``).

    Prefers a ``~``-prefixed form when *path* is under the user's home, so
    output stays portable across machines and we don't print absolute home
    directories in screenshots.
    """
    try:
        resolved = path.resolve()
        home = Path.home()
        if resolved.is_relative_to(home):
            return "~" + str(resolved)[len(str(home)) :]
    except (OSError, RuntimeError):
        pass
    return str(path)


def _validate_under_cwd(path: Path, *, kind: str) -> Path:
    """Resolve *path*; if relative, ensure it stays under cwd.

    *kind* is plain English used in the error message ("Path", "Directory",
    etc.) so each caller can phrase its prompt naturally.
    """
    resolved = path.resolve()
    if not path.is_absolute():
        try:
            resolved.relative_to(Path.cwd())
        except ValueError:
            _console.print(
                f"[red]{kind} must be inside the current directory.[/red]"
            )
            raise typer.Exit(1)
    return resolved


def validate_env_file(path: Path) -> Path:
    """Resolve *path*; raise typer.Exit(1) if it escapes cwd via ``../``."""
    return _validate_under_cwd(path, kind="Path")


def validate_scan_dir(path: Path) -> Path:
    """Resolve *path*; raise typer.Exit(1) if it escapes cwd via ``../``."""
    return _validate_under_cwd(path, kind="Directory")


def is_valid_secret_name(name: str) -> bool:
    """Return True for names containing only letters, digits, ``-`` and ``_``."""
    return bool(SECRET_NAME_RE.match(name))


def validate_secret_name(name: str) -> None:
    """Fatal version of :func:`is_valid_secret_name` for ``ownlock set``."""
    if not is_valid_secret_name(name):
        _console.print(
            "[red]Secret name must use only letters, numbers, hyphens, and underscores.[/red]"
        )
        raise typer.Exit(1)


def is_tty() -> bool:
    """Return True when stdin and stdout are both real TTYs.

    Tests monkeypatch this to flip CLI commands between interactive and
    non-interactive code paths without juggling stdin/stdout fakes.
    """
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def resolve_vault_path(global_vault: bool = False, project: bool = False) -> Path:
    """Pick the vault path for a CLI command.

    * ``--global`` always wins.
    * ``--project`` forces the cwd's ``.ownlock/vault.db``.
    * Otherwise: walk up from cwd looking for a project vault; fall back to
      the global vault if none is found.

    ``GLOBAL_VAULT_PATH`` is read dynamically from :mod:`ownlock.vault` so
    tests that monkeypatch the symbol there see the change here too.
    """
    if global_vault:
        return _vault_module.GLOBAL_VAULT_PATH
    if project:
        return Path.cwd() / PROJECT_VAULT_DIR / PROJECT_VAULT_DB
    proj = VaultManager.find_project_vault()
    if proj:
        return proj
    return _vault_module.GLOBAL_VAULT_PATH


def vault_path_for_ref(
    project_flag: Optional[str],
    global_flag: Optional[str],
) -> Path:
    """Pick the vault file for a single ``vault(...)`` reference.

    Mirrors :class:`ownlock.resolver.VaultLookup` selection rules so
    ``import`` vault_refs writes land in the same vault ``run`` reads from.
    """
    use_global = (global_flag == "true") if global_flag else None
    project = (project_flag == "true") if project_flag else None
    if use_global is True:
        return _vault_module.GLOBAL_VAULT_PATH
    proj = VaultManager.find_project_vault()
    if proj and (project is True or (project is None and use_global is None)):
        return proj
    return _vault_module.GLOBAL_VAULT_PATH


def ensure_gitignore() -> None:
    """Add ``.ownlock/`` to ``.gitignore`` if not already present.

    Creates ``.gitignore`` if missing. No-op when the literal substring
    ``.ownlock`` already appears (covers ``.ownlock/``, ``.ownlock``, and
    negation patterns like ``!.ownlock/keep`` — false positives here are
    safer than the alternative of double-adding the entry).
    """
    gitignore_path = Path.cwd() / ".gitignore"
    if not gitignore_path.exists():
        gitignore_path.write_text(
            "# ownlock vault (never commit)\n.ownlock/\n",
            encoding="utf-8",
        )
        _console.print("[dim]Created .gitignore with .ownlock/[/dim]")
        return

    content = gitignore_path.read_text(encoding="utf-8")
    if ".ownlock" in content:
        return

    with gitignore_path.open("a", encoding="utf-8") as f:
        f.write(OWNLOCK_GITIGNORE_ENTRY)
    _console.print("[dim]Added .ownlock/ to .gitignore[/dim]")
