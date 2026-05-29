"""Plaintext-safe backups for env-file rewrites and vault snapshots.

Centralizes the rules ownlock applies to every backup it writes:

* Backup directory is ``.ownlock/backups/`` so a single ``.gitignore`` entry
  (added by :func:`ownlock.paths.ensure_gitignore`) covers everything ownlock
  produces.
* On POSIX the file is mode ``0600`` (owner read/write only).
* Backup names embed a UTC timestamp so repeated rewrites or rekeys leave a
  trail rather than clobbering each other.

Pre-0.2.0 ownlock wrote ``<file>.ownlock.bak`` next to the original .env, an
easy footgun for anyone who staged it without checking. The
:data:`LEGACY_BACKUP_SUFFIX` constant is exposed so :mod:`ownlock.scanner` and
:mod:`ownlock.doctor` can flag any leftover legacy backups for the user to
clean up.
"""

from __future__ import annotations

import os
from datetime import datetime, UTC
from pathlib import Path

from ownlock.vault import PROJECT_VAULT_DIR, VaultManager

LEGACY_BACKUP_SUFFIX = ".ownlock.bak"


def backup_dir_for(env_file: Path) -> Path:
    """Pick the safe backup directory for *env_file*.

    Prefers the project vault's ``.ownlock`` directory when one is reachable
    from cwd; otherwise falls back to ``<cwd>/.ownlock/backups``.
    """
    proj_vault = VaultManager.find_project_vault()
    if proj_vault is not None:
        return proj_vault.parent / "backups"
    return Path.cwd() / PROJECT_VAULT_DIR / "backups"


def _chmod_0600(path: Path) -> None:
    """Best-effort tighten POSIX permissions; silent on systems that don't support it."""
    if os.name != "posix":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def write_env_backup(env_file: Path, content: str, *, ensure_gitignore_fn: object) -> Path:
    """Write *content* as a timestamped backup under ``.ownlock/backups/``.

    Returns the path written. The caller passes ``ensure_gitignore_fn`` so
    this module doesn't pull in the CLI's gitignore handling — keeping the
    dependency direction one-way (cli → backups, never the reverse).
    """
    if callable(ensure_gitignore_fn):
        ensure_gitignore_fn()
    backup_dir = backup_dir_for(env_file)
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"{env_file.name}.{timestamp}.bak"
    backup_path.write_text(content, encoding="utf-8")
    _chmod_0600(backup_path)
    return backup_path


def backup_vault_file(vault_path: Path) -> Path:
    """Copy *vault_path* (and any WAL sidecars) to ``.ownlock/backups/`` (mode 0600).

    Used by ``ownlock rekey`` so a partial / failed rekey can never corrupt
    the live vault: the live file is untouched until the SQL transaction
    commits, and the backup copy is left in place after success for the user
    to delete once they're confident.

    SQLite WAL mode keeps recent writes in ``vault.db-wal`` (and a small
    shared-memory file ``vault.db-shm``) until they're checkpointed back
    into the main file. We snapshot all three so a hard-killed previous
    process whose writes are still in the WAL is captured in the backup
    too — restoring the main file alone would lose those writes.
    """
    backup_dir = vault_path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"{vault_path.name}.backup-{timestamp}"
    backup_path.write_bytes(vault_path.read_bytes())
    _chmod_0600(backup_path)

    for suffix in ("-wal", "-shm"):
        sidecar = vault_path.with_name(vault_path.name + suffix)
        if sidecar.exists():
            sidecar_backup = backup_dir / f"{sidecar.name}.backup-{timestamp}"
            sidecar_backup.write_bytes(sidecar.read_bytes())
            _chmod_0600(sidecar_backup)

    return backup_path
