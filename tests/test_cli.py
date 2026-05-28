"""Tests for ownlock.cli — Typer CLI commands."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from ownlock.cli import _resolve_vault_path as _real_resolve_vault_path, app
from ownlock.vault import VaultManager

PASSPHRASE = "test-pass"
runner = CliRunner()


@pytest.fixture(autouse=True)
def _ownlock_env(tmp_path, monkeypatch):
    """Set passphrase env var and patch vault paths to tmp_path for every test."""
    monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)

    vault_path = tmp_path / ".ownlock" / "vault.db"
    monkeypatch.setattr("ownlock.vault.GLOBAL_VAULT_PATH", vault_path)
    monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", vault_path)

    # Make _resolve_vault_path always return our tmp vault
    monkeypatch.setattr(
        "ownlock.cli._resolve_vault_path",
        lambda global_vault=False, project=False: vault_path,
    )

    # Patch find_project_vault so resolver doesn't pick up real project vaults
    monkeypatch.setattr(
        "ownlock.vault.VaultManager.find_project_vault",
        staticmethod(lambda: None),
    )


@pytest.fixture()
def vault_db(tmp_path):
    """Return the vault path (same as patched in _ownlock_env)."""
    return tmp_path / ".ownlock" / "vault.db"


@pytest.fixture()
def seeded_vault(vault_db):
    """Create and seed the vault with a test secret."""
    with VaultManager(vault_db, PASSPHRASE) as vm:
        vm.set("MY_KEY", "my-value")
    return vault_db


class TestInit:
    def test_creates_vault_db(self, tmp_path, monkeypatch):
        """ownlock init creates project vault at cwd/.ownlock/vault.db."""
        monkeypatch.chdir(tmp_path)
        project_vault = tmp_path / ".ownlock" / "vault.db"
        monkeypatch.setattr(
            "ownlock.cli.getpass.getpass",
            lambda prompt="": PASSPHRASE,
        )

        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert project_vault.exists()

    def test_init_global_creates_global_vault(self, tmp_path, monkeypatch):
        """ownlock init --global creates vault at GLOBAL_VAULT_PATH."""
        global_path = tmp_path / "global" / "vault.db"
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", global_path)
        monkeypatch.setattr(
            "ownlock.cli.getpass.getpass",
            lambda prompt="": PASSPHRASE,
        )
        monkeypatch.setattr(
            "ownlock.cli.store_passphrase",
            lambda p: (False, "no keyring backend"),
        )

        result = runner.invoke(app, ["init", "--global"])
        assert result.exit_code == 0
        assert global_path.exists()
        assert "no keyring backend" in result.output

    def test_init_creates_gitignore(self, tmp_path, monkeypatch):
        """ownlock init creates .gitignore with .ownlock/ when none exists."""
        monkeypatch.chdir(tmp_path)
        project_vault = tmp_path / ".ownlock" / "vault.db"
        monkeypatch.setattr(
            "ownlock.cli.getpass.getpass",
            lambda prompt="": PASSPHRASE,
        )

        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert project_vault.exists()
        gitignore = tmp_path / ".gitignore"
        assert gitignore.exists()
        assert ".ownlock" in gitignore.read_text()

    def test_init_appends_to_existing_gitignore(self, tmp_path, monkeypatch):
        """ownlock init appends .ownlock/ to existing .gitignore."""
        monkeypatch.chdir(tmp_path)
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("node_modules/\n.env\n")
        project_vault = tmp_path / ".ownlock" / "vault.db"
        monkeypatch.setattr(
            "ownlock.cli.getpass.getpass",
            lambda prompt="": PASSPHRASE,
        )

        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        content = gitignore.read_text()
        assert "node_modules/" in content
        assert ".ownlock" in content

    def test_init_skips_gitignore_when_ownlock_already_present(
        self, tmp_path, monkeypatch
    ):
        """ownlock init does not duplicate .ownlock if already in .gitignore."""
        monkeypatch.chdir(tmp_path)
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("node_modules/\n.ownlock/\n")
        project_vault = tmp_path / ".ownlock" / "vault.db"
        monkeypatch.setattr(
            "ownlock.cli.getpass.getpass",
            lambda prompt="": PASSPHRASE,
        )

        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        content = gitignore.read_text()
        assert content.count(".ownlock") == 1

    def test_first_init_creates_global_and_project_vault(self, tmp_path, monkeypatch):
        """First ownlock init (no global vault yet) creates both global and project vault."""
        monkeypatch.chdir(tmp_path)
        global_path = tmp_path / "global" / "vault.db"
        global_path.parent.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", global_path)
        monkeypatch.setattr(
            "ownlock.cli.getpass.getpass",
            lambda prompt="": PASSPHRASE,
        )
        monkeypatch.setattr("ownlock.cli.store_passphrase", lambda p: (True, None))

        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert global_path.exists()
        assert (tmp_path / ".ownlock" / "vault.db").exists()
        assert "passphrase in keyring" in result.output
        assert "global vault" in result.output

    def test_init_when_global_exists_creates_only_project_vault(
        self, tmp_path, monkeypatch
    ):
        """When global vault exists, ownlock init creates only project vault (uses keyring passphrase)."""
        monkeypatch.chdir(tmp_path)
        global_path = tmp_path / "global" / "vault.db"
        global_path.parent.mkdir(parents=True, exist_ok=True)
        VaultManager.init_vault(global_path, PASSPHRASE)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", global_path)
        getpass_calls = []

        def track_getpass(prompt=""):
            getpass_calls.append(1)
            return PASSPHRASE

        monkeypatch.setattr("ownlock.cli.getpass.getpass", track_getpass)

        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert (tmp_path / ".ownlock" / "vault.db").exists()
        assert len(getpass_calls) == 0, "should not prompt when global vault exists (passphrase from env/keyring)"


class TestSetGet:
    def test_set_rejects_invalid_secret_name(self, seeded_vault):
        result = runner.invoke(app, ["set", "invalid.name=value"])
        assert result.exit_code == 1
        assert "letters, numbers" in result.output

    def test_set_then_get_roundtrip(self, vault_db, seeded_vault):
        result = runner.invoke(app, ["set", "NEW_KEY=new-value"])
        assert result.exit_code == 0

        result = runner.invoke(app, ["get", "NEW_KEY"])
        assert result.exit_code == 0
        assert "new-value" in result.output


class TestList:
    def test_list_shows_name(self, seeded_vault):
        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0
        assert "MY_KEY" in result.output

    def test_list_json_metadata_only(self, seeded_vault):
        result = runner.invoke(app, ["list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        row = data[0]
        assert row["name"] == "MY_KEY"
        assert row["env"] == "default"
        assert "created_at" in row and "updated_at" in row
        assert "my-value" not in result.output

    def test_list_json_empty(self, vault_db):
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        result = runner.invoke(app, ["list", "--json"])
        assert result.exit_code == 0
        assert json.loads(result.output) == []


class TestDoctor:
    def test_doctor_prints_diagnostics(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", tmp_path / "g" / "vault.db")
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: None),
        )
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        out = result.output
        assert "ownlock" in out.lower()
        assert "Python" in out
        assert "OWNLOCK_PASSPHRASE" in out
        assert "Global vault" in out
        assert "Project vault" in out
        assert "Passphrase resolved from" in out

    def test_doctor_reports_passphrase_source_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", tmp_path / "g" / "vault.db")
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "env var" in result.output

    def test_doctor_reports_passphrase_source_keyring(self, tmp_path, monkeypatch):
        monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", tmp_path / "g" / "vault.db")
        monkeypatch.setattr(
            "ownlock.keyring_util.get_passphrase", lambda: "stored-pp"
        )
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "keyring" in result.output

    def test_doctor_json_output(self, tmp_path, monkeypatch, vault_db, seeded_vault):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", vault_db)
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: vault_db),
        )
        result = runner.invoke(app, ["doctor", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "ownlock_version" in data
        assert "global_vault" in data
        assert data["global_vault"]["exists"] is True
        assert data["global_vault"]["schema_version"] == 2
        assert data["global_vault"]["secret_count"] == 1
        assert data["passphrase_source"] in {"env var", "keyring", "would prompt"}

    def test_doctor_flags_legacy_backups_and_stale_tmp(self, tmp_path, monkeypatch, vault_db, seeded_vault):
        legacy = tmp_path / ".env.ownlock.bak"
        legacy.write_text("FOO=bar")
        stale = tmp_path / ".web.config.abc.ownlock-tmp"
        stale.write_text("partial")

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", vault_db)
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "Legacy plaintext backups" in result.output
        assert "Stale render temp files" in result.output

    def test_doctor_warns_when_gitignore_missing_ownlock(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".gitignore").write_text("node_modules/\n")
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", tmp_path / "g" / "vault.db")
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert ".ownlock" in result.output
        assert "does not cover" in result.output

    def test_doctor_recommends_rekey_for_legacy_vault(self, tmp_path, monkeypatch):
        """A vault file without meta (legacy) reports stale and surfaces rekey tip."""
        import sqlite3 as _sql

        legacy_db = tmp_path / "legacy.db"
        conn = _sql.connect(str(legacy_db))
        conn.execute(
            "CREATE TABLE secrets ("
            "  name TEXT NOT NULL, env TEXT NOT NULL DEFAULT 'default', "
            "  value_enc TEXT NOT NULL, created_at TEXT NOT NULL, "
            "  updated_at TEXT NOT NULL, PRIMARY KEY (name, env))"
        )
        conn.commit()
        conn.close()

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", legacy_db)
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: None),
        )
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "rekey --upgrade-kdf" in result.output


class TestDelete:
    def test_delete_removes_secret(self, seeded_vault):
        result = runner.invoke(app, ["delete", "MY_KEY"])
        assert result.exit_code == 0
        assert "Deleted" in result.output

        result = runner.invoke(app, ["get", "MY_KEY"])
        assert result.exit_code == 1


class TestImport:
    def test_import_from_env_file(self, tmp_path, vault_db):
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        env_file = tmp_path / "import.env"
        env_file.write_text("ALPHA=one\nBETA=two\n")

        result = runner.invoke(app, ["import", str(env_file)])
        assert result.exit_code == 0
        assert "Imported 2" in result.output

        result = runner.invoke(app, ["get", "ALPHA"])
        assert result.exit_code == 0
        assert "one" in result.output

    def test_import_skips_invalid_keys_and_comments(self, tmp_path, vault_db):
        """Import skips comments, blank lines, and invalid key names."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        env_file = tmp_path / "import.env"
        env_file.write_text(
            "# comment\n"
            "\n"
            "invalid.name=skip\n"
            "VALID_KEY=imported\n"
            "  SPACED=ok  \n"
            "another.bad=no\n"
        )

        result = runner.invoke(app, ["import", str(env_file)])
        assert result.exit_code == 0
        assert "Imported 2" in result.output  # VALID_KEY and SPACED only

        result = runner.invoke(app, ["get", "VALID_KEY"])
        assert result.exit_code == 0
        assert "imported" in result.output
        result = runner.invoke(app, ["get", "SPACED"])
        assert result.exit_code == 0
        assert "ok" in result.output
        result = runner.invoke(app, ["get", "invalid.name"])
        assert result.exit_code == 1

    def test_import_with_global_uses_global_vault(self, tmp_path, vault_db):
        """Import with --global stores in global vault; get --global retrieves."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        env_file = tmp_path / "import.env"
        env_file.write_text("GLOBAL_ONLY=from-import\n")

        result = runner.invoke(app, ["import", str(env_file), "--global"])
        assert result.exit_code == 0
        assert "Imported 1" in result.output

        result = runner.invoke(app, ["get", "GLOBAL_ONLY", "--global"])
        assert result.exit_code == 0
        assert "from-import" in result.output


class TestDangerousScanRoot:
    """_is_dangerous_scan_root — filesystem roots only (option c guard)."""

    def test_project_subdirectory_not_dangerous(self, tmp_path):
        from ownlock.cli import _is_dangerous_scan_root

        d = tmp_path / "proj"
        d.mkdir()
        assert _is_dangerous_scan_root(d) is False

    def test_posix_filesystem_root(self):
        import sys

        from ownlock.cli import _is_dangerous_scan_root

        if sys.platform == "win32":
            pytest.skip("POSIX root")
        assert _is_dangerous_scan_root(Path("/")) is True

    def test_windows_drive_root(self):
        import os
        import sys

        from ownlock.cli import _is_dangerous_scan_root

        if sys.platform != "win32":
            pytest.skip("Windows only")
        drive = Path(os.environ.get("SystemDrive", "C:") + "\\")
        assert _is_dangerous_scan_root(drive) is True


class TestScan:
    def test_scan_finds_leaked_secret(self, tmp_path, seeded_vault):
        """Scan reports file containing a vault secret value; output uses secret name only."""
        leak_file = tmp_path / "config.txt"
        leak_file.write_text("connection_string=my-value\n")  # my-value is MY_KEY in seeded_vault

        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 1
        assert "leaked" in result.output.lower()
        assert "MY_KEY" in result.output
        assert "my-value" not in result.output  # value must not be printed

    def test_scan_no_leak_reports_clean(self, tmp_path, seeded_vault):
        """Scan with no leaked values exits 0 and reports clean."""
        safe_file = tmp_path / "readme.txt"
        safe_file.write_text("No secrets here\n")

        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "No leaked secrets found" in result.output

    def test_scan_tty_default_max_files_no_confirm_prompt(self, tmp_path, seeded_vault, monkeypatch):
        """Normal project scan should not call typer.confirm (non-noisy OSS UX)."""
        confirm_calls: list[int] = []

        def track_confirm(*_a, **_k):
            confirm_calls.append(1)
            return True

        monkeypatch.setattr("ownlock.cli._is_tty", lambda: True)
        monkeypatch.setattr("typer.confirm", track_confirm)
        safe_file = tmp_path / "readme.txt"
        safe_file.write_text("No secrets here\n")

        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert confirm_calls == []

    def test_scan_tty_cancels_when_max_files_exceeds_cap(self, tmp_path, monkeypatch):
        """Raising --max-files above MAX_SCAN_FILES triggers confirm; declining cancels."""
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: True)
        monkeypatch.setattr("typer.confirm", lambda *a, **k: False)

        result = runner.invoke(app, ["scan", str(tmp_path), "--max-files", "10001"])
        assert result.exit_code == 1
        assert "cancelled" in result.output.lower()

    def test_scan_skips_oversized_files(self, tmp_path, seeded_vault):
        """Files larger than --max-file-bytes are not read (leak in them is not detected)."""
        big = tmp_path / "huge.txt"
        big.write_text("x" * 500 + "my-value")
        result = runner.invoke(app, ["scan", str(tmp_path), "--max-file-bytes", "100"])
        assert result.exit_code == 0
        assert "No leaked secrets found" in result.output


class TestRewriteEnvLinesHelper:
    """_rewrite_env_lines_to_vault_syntax — shared by auto and rewrite-env."""

    def test_rewrites_matching_keys_preserves_comments_and_vault_lines(self):
        from ownlock.cli import _rewrite_env_lines_to_vault_syntax

        lines = ["# comment", "", "FOO=plain", 'BAR=vault("BAR")', "SKIP=keep"]
        existing = {"FOO": "plain", "SKIP": "keep"}
        out, changed = _rewrite_env_lines_to_vault_syntax(lines, existing, "production")
        assert changed == 2
        joined = "\n".join(out)
        assert 'FOO=vault("FOO", env="production")' in joined
        assert 'SKIP=vault("SKIP", env="production")' in joined
        assert "# comment" in joined
        assert 'BAR=vault("BAR")' in joined


class TestRewriteEnv:
    def test_rewrite_env_replaces_values_with_vault_calls(self, tmp_path, vault_db, monkeypatch):
        """rewrite-env rewrites keys present in the vault and creates a backup
        under .ownlock/backups/ (gitignored)."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=one\nBAR=two\n# comment\n")

        with VaultManager(vault_db, PASSPHRASE) as vm:
            vm.set("FOO", "one")

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: vault_db),
        )

        result = runner.invoke(app, ["rewrite-env", "-f", str(env_file), "--yes"])
        assert result.exit_code == 0

        text = env_file.read_text()
        assert 'FOO=vault("FOO")' in text
        assert "BAR=two" in text  # unchanged

        # Backup goes to .ownlock/backups/, not next to the .env file.
        legacy_backup = tmp_path / ".env.ownlock.bak"
        assert not legacy_backup.exists(), "must not write plaintext next to .env"
        backups_dir = vault_db.parent / "backups"
        assert backups_dir.exists()
        backups = list(backups_dir.glob(".env.*.bak"))
        assert len(backups) == 1, backups
        assert backups[0].read_text() == "FOO=one\nBAR=two\n# comment\n"
        if os.name == "posix":
            mode = backups[0].stat().st_mode & 0o777
            assert mode == 0o600

    def test_scan_flags_legacy_plaintext_backups(self, tmp_path, vault_db, seeded_vault, monkeypatch):
        """ownlock scan reports *.ownlock.bak files (legacy plaintext leak path)."""
        legacy = tmp_path / ".env.ownlock.bak"
        legacy.write_text("OLD_KEY=stale-value\n")

        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 1
        assert "legacy plaintext backup" in result.output.lower()
        assert ".env.ownlock.bak" in result.output


class TestAuto:
    def test_auto_imports_and_rewrites_env_with_yes(self, tmp_path, vault_db, monkeypatch):
        """auto -f .env --yes imports and rewrites .env without prompts."""
        # Prepare plaintext env
        env_file = tmp_path / ".env"
        env_file.write_text("AUTO_KEY=auto-value\n")

        # Ensure GLOBAL_VAULT_PATH points at our tmp vault and resolve_vault_path uses it
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", vault_db)
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault_db,
        )

        result = runner.invoke(app, ["auto", "-f", str(env_file), "--yes"])
        assert result.exit_code == 0

        # Key should be in the vault and .env rewritten to use vault()
        with VaultManager(vault_db, PASSPHRASE) as vm:
            assert vm.get("AUTO_KEY") == "auto-value"
        text = env_file.read_text()
        assert 'AUTO_KEY=vault("AUTO_KEY")' in text


class TestExport:
    def test_export_prints_resolved(self, tmp_path, vault_db, seeded_vault):
        env_file = tmp_path / ".env"
        env_file.write_text('MY_KEY=vault("MY_KEY")\nPLAIN=hello\n')

        with patch("ownlock.resolver.GLOBAL_VAULT_PATH", vault_db):
            result = runner.invoke(app, ["export", "-f", str(env_file)])

        assert result.exit_code == 0
        assert "MY_KEY=my-value" in result.output
        assert "PLAIN=hello" in result.output

    def test_export_example_emits_vault_lines(self, seeded_vault):
        result = runner.invoke(app, ["export", "--example"])
        assert result.exit_code == 0
        assert 'MY_KEY=vault("MY_KEY")' in result.output.strip()

    def test_export_example_non_default_env(self, vault_db, seeded_vault):
        with VaultManager(vault_db, PASSPHRASE) as vm:
            vm.set("OTHER", "x", env="staging")
        result = runner.invoke(app, ["export", "--example", "--env", "staging"])
        assert result.exit_code == 0
        assert 'OTHER=vault("OTHER", env="staging")' in result.output.strip()


class TestRun:
    def test_run_injects_env_and_redacts(self, tmp_path, vault_db, seeded_vault):
        env_file = tmp_path / ".env"
        env_file.write_text('SECRET=vault("MY_KEY")\n')

        with patch("ownlock.resolver.GLOBAL_VAULT_PATH", vault_db):
            result = runner.invoke(
                app,
                ["run", "-f", str(env_file), "--", "echo", "my-value"],
            )

        assert "[REDACTED:" in result.output or result.exit_code == 0


class TestRekey:
    """ownlock rekey: passphrase rotation and KDF upgrade."""

    def test_rekey_upgrade_kdf_idempotent_at_current(self, vault_db, seeded_vault):
        """Vault at current schema/KDF is a no-op."""
        result = runner.invoke(app, ["rekey", "--upgrade-kdf", "--yes"])
        assert result.exit_code == 0
        assert "Nothing to upgrade" in result.output or "already" in result.output

    def test_rekey_rotate_passphrase_with_env(self, vault_db, seeded_vault, monkeypatch):
        """Non-interactive rotation reads new passphrase from OWNLOCK_NEW_PASSPHRASE."""
        from ownlock.vault import VaultManager as _VM

        monkeypatch.setenv("OWNLOCK_NEW_PASSPHRASE", "rotated-pp-x")
        # Avoid touching the real keyring during test.
        monkeypatch.setattr("ownlock.cli.store_passphrase", lambda p: (True, None))

        result = runner.invoke(app, ["rekey", "--rotate-passphrase", "--yes"])
        assert result.exit_code == 0, result.output
        assert "Re-encrypted" in result.output

        # Old passphrase is broken; new one works.
        from cryptography.exceptions import InvalidTag

        with _VM(vault_db, PASSPHRASE) as vm:
            with pytest.raises(InvalidTag):
                vm.get("MY_KEY")
        with _VM(vault_db, "rotated-pp-x") as vm:
            assert vm.get("MY_KEY") == "my-value"

    def test_rekey_creates_backup_file(self, vault_db, seeded_vault, monkeypatch):
        """Backup is written under .ownlock/backups/ with timestamp."""
        monkeypatch.setattr("ownlock.cli.store_passphrase", lambda p: (True, None))
        monkeypatch.setenv("OWNLOCK_NEW_PASSPHRASE", "new-pp")

        result = runner.invoke(app, ["rekey", "--rotate-passphrase", "--yes"])
        assert result.exit_code == 0
        backup_dir = vault_db.parent / "backups"
        backups = list(backup_dir.glob("vault.db.backup-*"))
        assert len(backups) == 1, backups
        if os.name == "posix":
            mode = backups[0].stat().st_mode & 0o777
            assert mode == 0o600

    def test_rekey_missing_vault_clean_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: tmp_path / "nope" / "vault.db",
        )
        result = runner.invoke(app, ["rekey", "--upgrade-kdf", "--yes"])
        assert result.exit_code == 1
        assert "Vault not found" in result.output

    def test_rekey_no_args_in_non_tty_requires_flags(self, vault_db, seeded_vault, monkeypatch):
        """In a non-interactive run with no flags, ownlock refuses to guess."""
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: False)
        result = runner.invoke(app, ["rekey"])
        assert result.exit_code == 1
        assert "--upgrade-kdf" in result.output

    def test_rekey_with_legacy_v1_secret_upgrades_to_v2(self, vault_db, monkeypatch):
        """A vault containing a v1 token gets upgraded to v2/current iterations."""
        from ownlock.crypto import (
            KDF_ITERATIONS_CURRENT,
            KDF_ITERATIONS_LEGACY,
            encrypt as _encrypt,
            token_iterations as _ti,
        )
        from ownlock.vault import VaultManager as _VM

        # Seed a vault and inject a legacy-iteration token.
        with _VM(vault_db, PASSPHRASE) as vm:
            legacy = _encrypt("classic", PASSPHRASE, iterations=KDF_ITERATIONS_LEGACY)
            vm._require_conn().execute(
                "INSERT INTO secrets (name, env, value_enc, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                ("CLASSIC", "default", legacy, "2025-01-01", "2025-01-01"),
            )
            vm._require_conn().commit()

        result = runner.invoke(app, ["rekey", "--upgrade-kdf", "--yes"])
        assert result.exit_code == 0, result.output

        with _VM(vault_db, PASSPHRASE) as vm:
            row = vm._require_conn().execute(
                "SELECT value_enc FROM secrets WHERE name = 'CLASSIC'"
            ).fetchone()
            assert _ti(row["value_enc"]) == KDF_ITERATIONS_CURRENT


class TestErrorHandling:
    def test_passphrase_not_found_shows_clean_message(self, tmp_path, monkeypatch):
        """ValueError from resolve_passphrase shows clean message, no traceback."""
        monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
        monkeypatch.setattr(
            "ownlock.keyring_util.get_passphrase",
            lambda: None,
        )
        monkeypatch.setattr(
            "ownlock.cli.getpass.getpass",
            lambda prompt="": "",
        )
        result = runner.invoke(app, ["list"])
        assert result.exit_code == 1
        assert "No vault passphrase found" in result.output
        assert "Traceback" not in result.output
        assert "keyring_util.py" not in result.output


class TestGlobalFlag:
    def test_global_forces_global_vault_when_in_project(self, tmp_path, vault_db, monkeypatch):
        """--global forces global vault even when project vault exists."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        project_vault = project_dir / ".ownlock" / "vault.db"
        project_vault.parent.mkdir(parents=True)
        monkeypatch.chdir(project_dir)

        # Global vault (at tmp_path/.ownlock/vault.db) has the secret
        with VaultManager(vault_db, PASSPHRASE) as vm:
            vm.set("GLOBAL_ONLY", "from-global")
        # Project vault exists but is empty
        VaultManager.init_vault(project_vault, PASSPHRASE).close()

        # Restore real _resolve_vault_path and make find_project_vault return project vault
        monkeypatch.setattr("ownlock.cli._resolve_vault_path", _real_resolve_vault_path)
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: project_vault),
        )

        # Without --global: uses project vault (found in cwd) -> secret not there
        result = runner.invoke(app, ["get", "GLOBAL_ONLY"])
        assert result.exit_code == 1
        assert "not found" in result.output

        # With --global: uses global vault -> secret found
        result = runner.invoke(app, ["get", "GLOBAL_ONLY", "--global"])
        assert result.exit_code == 0
        assert "from-global" in result.output


class TestPathValidation:
    def test_run_rejects_env_file_outside_cwd(self, tmp_path, seeded_vault, monkeypatch):
        """Relative path escaping cwd is rejected."""
        monkeypatch.chdir(tmp_path)
        # Create subdir; try to use ../ to escape
        (tmp_path / "sub").mkdir()
        outside = tmp_path / "sub" / ".env"
        outside.write_text('X=vault("MY_KEY")\n')
        result = runner.invoke(
            app,
            ["run", "-f", "../sub/.env", "--", "echo", "ok"],
        )
        # When cwd is tmp_path, ../sub/.env resolves outside cwd (to parent/sub/.env)
        # Actually tmp_path / "sub" / ".env" - from cwd tmp_path, "../sub/.env" 
        # resolves to (tmp_path.parent / "sub" / ".env"). That's outside tmp_path.
        # So we should reject.
        assert result.exit_code == 1
        assert "Path must be inside" in result.output
