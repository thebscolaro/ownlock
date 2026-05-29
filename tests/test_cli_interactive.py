"""Interactive CLI flows — Typer CliRunner with scripted stdin."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ownlock.cli import app
from ownlock.vault import VaultManager

PASSPHRASE = "test-pass"
runner = CliRunner()


@pytest.fixture(autouse=True)
def _vault_env(tmp_path, monkeypatch):
    monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
    vault_path = tmp_path / ".ownlock" / "vault.db"
    monkeypatch.setattr("ownlock.vault.GLOBAL_VAULT_PATH", vault_path)
    monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", vault_path)
    monkeypatch.setattr(
        "ownlock.cli._resolve_vault_path",
        lambda global_vault=False, project=False: vault_path,
    )
    monkeypatch.setattr(
        "ownlock.vault.VaultManager.find_project_vault",
        staticmethod(lambda: None),
    )


class TestImportInteractive:
    def test_import_picks_subset_of_keys(self, tmp_path, monkeypatch):
        VaultManager.init_vault(tmp_path / ".ownlock" / "vault.db", PASSPHRASE).close()
        env_file = tmp_path / ".env"
        env_file.write_text("A=1\nB=2\nC=3\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: True)

        result = runner.invoke(
            app,
            ["import", str(env_file)],
            input="1,3\n",
        )
        assert result.exit_code == 0, result.output
        assert "Found 3 key(s)" in result.output
        with VaultManager(tmp_path / ".ownlock" / "vault.db", PASSPHRASE) as vm:
            assert vm.get("A") == "1"
            assert vm.get("B") is None
            assert vm.get("C") == "3"

    def test_import_multi_file_discovery_picker(self, tmp_path, monkeypatch):
        VaultManager.init_vault(tmp_path / ".ownlock" / "vault.db", PASSPHRASE).close()
        (tmp_path / ".env").write_text("FROM_DOTENV=yes\n")
        (tmp_path / ".env.local").write_text("FROM_LOCAL=yes\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: True)

        # File index 2, then accept default "all" for the single key in .env.local.
        result = runner.invoke(app, ["import"], input="2\n\n")
        assert result.exit_code == 0, result.output
        assert "Found env files" in result.output
        with VaultManager(tmp_path / ".ownlock" / "vault.db", PASSPHRASE) as vm:
            assert vm.get("FROM_DOTENV") is None
            assert vm.get("FROM_LOCAL") == "yes"

    def test_import_key_picker_invalid_index_exits(self, tmp_path, monkeypatch):
        VaultManager.init_vault(tmp_path / ".ownlock" / "vault.db", PASSPHRASE).close()
        (tmp_path / ".env").write_text("ONLY=1\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: True)

        result = runner.invoke(app, ["import", str(tmp_path / ".env")], input="9\n")
        assert result.exit_code == 1
        assert "out of range" in result.output


class TestCliErrorPaths:
    def test_rewrite_env_missing_file_exits(self, tmp_path):
        missing = tmp_path / "missing.env"
        result = runner.invoke(app, ["rewrite-env", "-f", str(missing)])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_set_mutually_exclusive_from_file_and_editor(self, tmp_path):
        f = tmp_path / "x.txt"
        f.write_text("value\n")
        result = runner.invoke(
            app, ["set", "K", "--from-file", str(f), "--editor"]
        )
        assert result.exit_code == 1
        assert "mutually exclusive" in result.output

    def test_share_empty_vault_exits(self, tmp_path, monkeypatch):
        vault = tmp_path / ".ownlock" / "vault.db"
        VaultManager.init_vault(vault, PASSPHRASE).close()
        monkeypatch.setenv("OWNLOCK_BUNDLE_PASSPHRASE", "bundle-pp")
        result = runner.invoke(
            app, ["share", "-o", str(tmp_path / "b.olbundle"), "--yes"]
        )
        assert result.exit_code == 1
        assert "empty" in result.output.lower()

    def test_import_values_from_invalid_json(self, tmp_path, monkeypatch):
        vault = tmp_path / ".ownlock" / "vault.db"
        VaultManager.init_vault(vault, PASSPHRASE).close()
        env_file = tmp_path / ".env"
        env_file.write_text('NEED=vault("NEED")\n')
        bad = tmp_path / "bad.json"
        bad.write_text("not-json")
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            app, ["import", str(env_file), "--values-from", str(bad)]
        )
        assert result.exit_code == 1
        assert "values-from" in result.output.lower() or "JSON" in result.output
