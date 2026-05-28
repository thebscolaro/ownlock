"""Tests for ownlock.backups — backup file helpers."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ownlock.backups import (
    LEGACY_BACKUP_SUFFIX,
    backup_dir_for,
    backup_vault_file,
    write_env_backup,
)


def test_legacy_suffix_constant() -> None:
    assert LEGACY_BACKUP_SUFFIX == ".ownlock.bak"


def test_backup_dir_for_with_no_project_vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "ownlock.vault.VaultManager.find_project_vault",
        staticmethod(lambda: None),
    )
    d = backup_dir_for(tmp_path / ".env")
    assert d == tmp_path / ".ownlock" / "backups"


def test_backup_dir_for_uses_project_vault_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    proj_vault = tmp_path / "myproj" / ".ownlock" / "vault.db"
    proj_vault.parent.mkdir(parents=True)
    monkeypatch.setattr(
        "ownlock.vault.VaultManager.find_project_vault",
        staticmethod(lambda: proj_vault),
    )
    d = backup_dir_for(tmp_path / ".env")
    assert d == proj_vault.parent / "backups"


def test_write_env_backup_writes_timestamped_0600_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "ownlock.vault.VaultManager.find_project_vault",
        staticmethod(lambda: None),
    )
    env_file = tmp_path / ".env"
    env_file.write_text("FOO=bar\n")

    called: list[bool] = []

    def _ensure_gitignore() -> None:
        called.append(True)

    backup = write_env_backup(env_file, "FOO=bar\n", ensure_gitignore_fn=_ensure_gitignore)
    assert called == [True]
    assert backup.parent == tmp_path / ".ownlock" / "backups"
    assert backup.name.startswith(".env.")
    assert backup.name.endswith(".bak")
    assert backup.read_text() == "FOO=bar\n"
    if os.name == "posix":
        assert backup.stat().st_mode & 0o777 == 0o600


def test_write_env_backup_tolerates_missing_gitignore_fn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "ownlock.vault.VaultManager.find_project_vault",
        staticmethod(lambda: None),
    )
    env_file = tmp_path / ".env"
    env_file.write_text("X=y")
    # Passing ``None`` exercises the "no callable" branch — should not raise.
    backup = write_env_backup(env_file, "X=y", ensure_gitignore_fn=None)
    assert backup.exists()


def test_backup_vault_file_writes_under_backups_dir(tmp_path: Path) -> None:
    vault = tmp_path / ".ownlock" / "vault.db"
    vault.parent.mkdir(parents=True)
    vault.write_bytes(b"sqlite-bytes-here")

    backup = backup_vault_file(vault)
    assert backup.parent == vault.parent / "backups"
    assert backup.name.startswith("vault.db.backup-")
    assert backup.read_bytes() == b"sqlite-bytes-here"
    if os.name == "posix":
        assert backup.stat().st_mode & 0o777 == 0o600
