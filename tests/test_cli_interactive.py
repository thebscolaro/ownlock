"""Interactive CLI flows — Typer CliRunner with scripted stdin."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ownlock.cli import app
from ownlock.vault import VaultManager

PASSPHRASE = "test-pass"
runner = CliRunner(env={"OWNLOCK_PASSPHRASE": PASSPHRASE})


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
        "ownlock.cli._resolve_scan_vault_path",
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

    def test_import_multiple_positionals_shows_file_picker(
        self, tmp_path, monkeypatch
    ):
        """``import test.env .env`` lists both files for interactive selection."""
        VaultManager.init_vault(tmp_path / ".ownlock" / "vault.db", PASSPHRASE).close()
        a = tmp_path / "test.env"
        a.write_text("FROM_A=a\n")
        b = tmp_path / ".env"
        b.write_text("FROM_B=b\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: True)

        result = runner.invoke(app, ["import", str(a), str(b)], input="1\n\n")
        assert result.exit_code == 0, result.output
        assert "Found env files" in result.output
        with VaultManager(tmp_path / ".ownlock" / "vault.db", PASSPHRASE) as vm:
            assert vm.get("FROM_A") == "a"
            assert vm.get("FROM_B") is None

    def test_import_multiple_positionals_with_yes_imports_all(
        self, tmp_path, monkeypatch
    ):
        VaultManager.init_vault(tmp_path / ".ownlock" / "vault.db", PASSPHRASE).close()
        a = tmp_path / "test.env"
        a.write_text("KA=1\n")
        b = tmp_path / ".env"
        b.write_text("KB=2\n")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["import", str(a), str(b), "--yes"])
        assert result.exit_code == 0, result.output
        with VaultManager(tmp_path / ".ownlock" / "vault.db", PASSPHRASE) as vm:
            assert vm.get("KA") == "1"
            assert vm.get("KB") == "2"


class TestRekeyInteractive:
    def test_rekey_interactive_final_confirm(self, tmp_path, monkeypatch):
        """TTY rekey --upgrade-kdf still asks for final re-encrypt confirmation."""
        vault = tmp_path / ".ownlock" / "vault.db"
        with VaultManager(vault, PASSPHRASE) as vm:
            vm.set("K", "long-secret-value")
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: True)
        result = runner.invoke(
            app,
            ["rekey", "--upgrade-kdf"],
            input="y\n",
        )
        assert result.exit_code == 0, result.output


class TestInitInteractive:
    def test_init_offers_import_when_env_present(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("ONBOARD=secret-value\n")
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: True)
        monkeypatch.setattr(
            "ownlock.cli.getpass.getpass",
            lambda prompt="": PASSPHRASE,
        )
        monkeypatch.setattr(
            "ownlock.cli.store_passphrase",
            lambda p: (False, "no keyring"),
        )
        result = runner.invoke(app, ["init"], input="n\n")
        assert result.exit_code == 0, result.output
        assert "Skipping import" in result.output


class TestScanCliNoVault:
    """Scan without a patched vault path — exercises real resolve_scan rules."""

    def test_scan_without_vault_or_passphrase(self, tmp_path, monkeypatch):
        from ownlock.paths import resolve_scan_vault_path

        monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
        monkeypatch.setattr("ownlock.keyring_util.get_passphrase", lambda: None)
        monkeypatch.setattr(
            "ownlock.cli._resolve_scan_vault_path",
            resolve_scan_vault_path,
        )
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: None),
        )
        monkeypatch.chdir(tmp_path)
        (tmp_path / "safe.txt").write_text("hello\n")

        result = runner.invoke(
            app, ["scan", ".", "--yes"], env={"OWNLOCK_PASSPHRASE": None}
        )
        assert result.exit_code == 0, result.output
        assert "No project vault found" in result.output
        assert "Invalid passphrase" not in result.output
        assert "No legacy backup files found" in result.output


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
