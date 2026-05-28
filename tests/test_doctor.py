"""Tests for ownlock.doctor — diagnostic gathering, no decryption."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from ownlock.doctor import (
    gather_doctor_state,
    passphrase_source,
    vault_health,
)


PASSPHRASE = "test-pass-doctor"


def test_passphrase_source_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
    assert passphrase_source() == "env var"


def test_passphrase_source_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
    monkeypatch.setattr("ownlock.keyring_util.get_passphrase", lambda: "stored")
    assert passphrase_source() == "keyring"


def test_passphrase_source_would_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
    monkeypatch.setattr("ownlock.keyring_util.get_passphrase", lambda: None)
    assert passphrase_source() == "would prompt"


def test_vault_health_missing_file(tmp_path: Path) -> None:
    info = vault_health(tmp_path / "nope.db")
    assert info["exists"] is False


def test_vault_health_legacy_db_without_meta(tmp_path: Path) -> None:
    """A vault file predating the meta table reports schema v1 / legacy KDF."""
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE secrets ("
        "  name TEXT NOT NULL, env TEXT NOT NULL DEFAULT 'default', "
        "  value_enc TEXT NOT NULL, created_at TEXT NOT NULL, "
        "  updated_at TEXT NOT NULL, PRIMARY KEY (name, env))"
    )
    conn.commit()
    conn.close()

    info = vault_health(db)
    assert info["exists"] is True
    assert info["schema_version"] == 1
    assert info["kdf_iterations"] == 200_000
    assert info["kdf_stale"] is True
    assert info["secret_count"] == 0


def test_vault_health_current_db(tmp_path: Path) -> None:
    """A vault initialized through VaultManager reports schema v2 / current KDF."""
    from ownlock.crypto import KDF_ITERATIONS_CURRENT
    from ownlock.vault import SCHEMA_VERSION_CURRENT, VaultManager

    db = tmp_path / "v2.db"
    with VaultManager(db, PASSPHRASE) as vm:
        vm.set("ANY", "value")

    info = vault_health(db)
    assert info["schema_version"] == SCHEMA_VERSION_CURRENT
    assert info["kdf_iterations"] == KDF_ITERATIONS_CURRENT
    assert info["kdf_stale"] is False
    assert info["secret_count"] == 1


def test_gather_doctor_state_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
    monkeypatch.setattr(
        "ownlock.vault.VaultManager.find_project_vault",
        staticmethod(lambda: None),
    )
    monkeypatch.setattr(
        "ownlock.vault.GLOBAL_VAULT_PATH", tmp_path / "global" / "vault.db"
    )

    state = gather_doctor_state()
    for required in (
        "ownlock_version",
        "python_version",
        "global_vault",
        "project_vault",
        "passphrase_source",
        "ownlock_passphrase_env_set",
        "stale_render_tmp_files",
        "legacy_backups_in_cwd",
        "gitignore_covers_ownlock",
    ):
        assert required in state


def test_gather_doctor_state_finds_legacy_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".env.ownlock.bak").write_text("OLD=stale")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
    monkeypatch.setattr(
        "ownlock.vault.VaultManager.find_project_vault",
        staticmethod(lambda: None),
    )
    monkeypatch.setattr(
        "ownlock.vault.GLOBAL_VAULT_PATH", tmp_path / "global" / "vault.db"
    )

    state = gather_doctor_state()
    assert any(p.endswith(".env.ownlock.bak") for p in state["legacy_backups_in_cwd"])
