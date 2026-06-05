"""Tests for ownlock.cli — Typer CLI commands."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from ownlock.cli import _resolve_vault_path as _real_resolve_vault_path, app
from ownlock.passphrase import Passphrase
from ownlock.vault import VaultManager

PASSPHRASE = "test-pass"
runner = CliRunner(env={"OWNLOCK_PASSPHRASE": PASSPHRASE})


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
    monkeypatch.setattr(
        "ownlock.cli._resolve_scan_vault_path",
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

    def test_init_no_onboarding_when_not_tty(self, tmp_path, monkeypatch):
        """Non-interactive init must NOT block waiting for an onboarding prompt."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("FOO=bar\n")
        global_path = tmp_path / "global" / "vault.db"
        global_path.parent.mkdir(parents=True, exist_ok=True)
        VaultManager.init_vault(global_path, PASSPHRASE)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", global_path)
        # Default _is_tty returns False inside the test runner; just be explicit.
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: False)

        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        # .env was untouched and onboarding never ran.
        assert "Found .env" not in result.output
        assert (tmp_path / ".env").read_text() == "FOO=bar\n"

    def test_init_offers_onboarding_when_tty_and_env_present(
        self, tmp_path, monkeypatch
    ):
        """Interactive init with a .env in cwd offers to import + rewrite."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("FOO=bar-value\n")
        global_path = tmp_path / "global" / "vault.db"
        global_path.parent.mkdir(parents=True, exist_ok=True)
        VaultManager.init_vault(global_path, PASSPHRASE)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", global_path)
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: True)
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: tmp_path / ".ownlock" / "vault.db",
        )

        # Three prompts: import? + rewrite-after? + which-keys? (default "all").
        result = runner.invoke(app, ["init"], input="y\ny\nall\n")
        assert result.exit_code == 0, result.output
        assert "Found .env" in result.output
        # Secret made it into the project vault.
        with VaultManager(tmp_path / ".ownlock" / "vault.db", PASSPHRASE) as vm:
            assert vm.get("FOO") == "bar-value"
        # File was rewritten to use vault().
        assert 'FOO=vault("FOO")' in (tmp_path / ".env").read_text()

    def test_init_skips_onboarding_when_user_declines(self, tmp_path, monkeypatch):
        """If the user answers N to the import prompt, .env is left alone."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("FOO=bar-value\n")
        global_path = tmp_path / "global" / "vault.db"
        global_path.parent.mkdir(parents=True, exist_ok=True)
        VaultManager.init_vault(global_path, PASSPHRASE)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", global_path)
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: True)
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: tmp_path / ".ownlock" / "vault.db",
        )

        result = runner.invoke(app, ["init"], input="n\n")
        assert result.exit_code == 0, result.output
        assert "Skipping import" in result.output
        # File untouched.
        assert (tmp_path / ".env").read_text() == "FOO=bar-value\n"

    def test_init_vault_refs_onboarding(
        self, tmp_path, monkeypatch
    ):
        """Init with an existing vault()-style .env runs vault_refs flow, not seed import."""
        monkeypatch.chdir(tmp_path)
        env_file = tmp_path / ".env"
        env_file.write_text('NEEDED=vault("NEEDED")\n')
        values_file = tmp_path / "values.json"
        values_file.write_text(json.dumps({"NEEDED": "from-teammate"}))

        global_path = tmp_path / "global" / "vault.db"
        global_path.parent.mkdir(parents=True, exist_ok=True)
        VaultManager.init_vault(global_path, PASSPHRASE)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", global_path)
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: True)
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: tmp_path / ".ownlock" / "vault.db",
        )
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: None),
        )

        # y = import now; vault_refs path uses --values-from in real life but
        # init calls _import_vault_refs_flow interactively — mock getpass.
        monkeypatch.setattr(
            "ownlock.cli.getpass.getpass",
            lambda prompt="": "from-teammate",
        )

        result = runner.invoke(app, ["init"], input="y\ny\n")
        assert result.exit_code == 0, result.output
        assert "Stored 1 secret" in result.output
        with VaultManager(tmp_path / ".ownlock" / "vault.db", PASSPHRASE) as vm:
            assert vm.get("NEEDED") == "from-teammate"


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

    def test_set_from_file_preserves_multi_line(self, tmp_path, vault_db, seeded_vault):
        pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSk\n"
            "AgEAAoIBAQDFakeMultiLineKeyContent==\n"
            "-----END PRIVATE KEY-----\n"
        )
        key_file = tmp_path / "key.pem"
        key_file.write_text(pem)

        result = runner.invoke(app, ["set", "PEM_KEY", "--from-file", str(key_file)])
        assert result.exit_code == 0

        with VaultManager(vault_db, PASSPHRASE) as vm:
            stored = vm.get("PEM_KEY")
        # Default --strip removes the single trailing newline.
        assert stored == pem.rstrip("\n")
        assert "-----BEGIN PRIVATE KEY-----" in stored
        assert "MIIE" in stored

    def test_set_from_file_no_strip(self, tmp_path, vault_db, seeded_vault):
        f = tmp_path / "v.txt"
        f.write_text("line1\nline2\n")
        result = runner.invoke(
            app, ["set", "MULTI", "--from-file", str(f), "--no-strip"]
        )
        assert result.exit_code == 0
        with VaultManager(vault_db, PASSPHRASE) as vm:
            assert vm.get("MULTI") == "line1\nline2\n"

    def test_set_from_file_with_value_form_is_rejected(self, vault_db, seeded_vault, tmp_path):
        f = tmp_path / "x"
        f.write_text("y")
        result = runner.invoke(
            app, ["set", "K=ignored", "--from-file", str(f)]
        )
        assert result.exit_code == 1
        assert "Use either" in result.output

    def test_set_editor_uses_OWNLOCK_EDITOR(self, vault_db, seeded_vault, tmp_path, monkeypatch):
        """--editor invokes a fake editor that writes a known multi-line value."""
        import sys as _sys

        # Build a tiny "editor" that writes a fixed value to its argv[1].
        helper = tmp_path / "fake_editor.py"
        helper.write_text(
            "import sys, pathlib\n"
            "pathlib.Path(sys.argv[1]).write_text('hello\\nworld\\n')\n"
        )
        editor_cmd = f"{_sys.executable} {helper}"
        monkeypatch.setenv("OWNLOCK_EDITOR", editor_cmd)

        result = runner.invoke(app, ["set", "VIA_EDITOR", "--editor"])
        assert result.exit_code == 0, result.output
        with VaultManager(vault_db, PASSPHRASE) as vm:
            assert vm.get("VIA_EDITOR") == "hello\nworld"  # trailing newline stripped


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
        result = runner.invoke(
            app, ["doctor"], env={"OWNLOCK_PASSPHRASE": None}
        )
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
        assert data["global_vault"]["schema_version"] == 3
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
        monkeypatch.setattr("ownlock.vault.GLOBAL_VAULT_PATH", legacy_db)
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

    def test_import_routes_to_vault_refs_when_file_has_vault_refs(
        self, tmp_path, vault_db, monkeypatch
    ):
        """A file containing vault(...) refs triggers vault_refs fill prompting."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        env_file = tmp_path / ".env"
        env_file.write_text('NEEDED=vault("NEEDED")\n')
        values_file = tmp_path / "v.json"
        values_file.write_text(json.dumps({"NEEDED": "from-import"}))
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(
            app, ["import", str(env_file), "--values-from", str(values_file)]
        )
        assert result.exit_code == 0
        assert "Stored 1 secret" in result.output
        with VaultManager(vault_db, PASSPHRASE) as vm:
            assert vm.get("NEEDED") == "from-import"

    def test_import_with_rewrite_flag_seeds_then_rewrites(
        self, tmp_path, vault_db, monkeypatch
    ):
        """`import --rewrite` does today's auto job: import KEY=VALUE then rewrite to vault()."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=secret-value\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault_db,
        )

        result = runner.invoke(app, ["import", str(env_file), "--rewrite", "--yes"])
        assert result.exit_code == 0, result.output
        with VaultManager(vault_db, PASSPHRASE) as vm:
            assert vm.get("API_KEY") == "secret-value"
        assert 'API_KEY=vault("API_KEY")' in env_file.read_text()
        assert "Imported" in result.output
        assert "Rewrote" in result.output
        assert "Backup saved to" in result.output
        # Rewrite summary and backup path are separate lines (not one green blob).
        rewrite_line = next(l for l in result.output.splitlines() if "Rewrote" in l)
        backup_line = next(l for l in result.output.splitlines() if "Backup saved to" in l)
        assert rewrite_line != backup_line
        assert "Backup saved to" not in rewrite_line

    def test_import_warns_when_rewrite_used_with_vault_ref_file(
        self, tmp_path, vault_db, monkeypatch
    ):
        """--rewrite is meaningless on a file that already uses vault(); we warn instead of silently ignoring."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        with VaultManager(vault_db, PASSPHRASE) as vm:
            vm.set("ALREADY", "x")
        env_file = tmp_path / ".env"
        env_file.write_text('ALREADY=vault("ALREADY")\n')
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["import", str(env_file), "--rewrite"])
        assert result.exit_code == 0
        assert "--rewrite has no effect" in result.output

    def test_import_auto_discovers_default_files(
        self, tmp_path, vault_db, monkeypatch
    ):
        """No args + .env present in cwd → import that .env."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        (tmp_path / ".env").write_text("AUTO_FOUND=value\n")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["import"])
        assert result.exit_code == 0
        with VaultManager(vault_db, PASSPHRASE) as vm:
            assert vm.get("AUTO_FOUND") == "value"

    def test_import_reports_when_no_files_exist(self, tmp_path, vault_db, monkeypatch):
        """Auto-discovery with nothing on disk: friendly hint, exit 0."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["import"])
        assert result.exit_code == 0
        assert "No env files found" in result.output

    def test_import_repeatable_file_flag(self, tmp_path, vault_db, monkeypatch):
        """-f a -f b imports both files."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        a = tmp_path / "a.env"
        a.write_text("KA=va\n")
        b = tmp_path / "b.env"
        b.write_text("KB=vb\n")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["import", "-f", str(a), "-f", str(b)])
        assert result.exit_code == 0
        with VaultManager(vault_db, PASSPHRASE) as vm:
            assert vm.get("KA") == "va"
            assert vm.get("KB") == "vb"

    def test_import_vault_refs_writes_global_ref_to_global_vault(
        self, tmp_path, monkeypatch
    ):
        """vault('KEY', global=true) is stored in the global vault, not project."""
        global_path = tmp_path / "global" / "vault.db"
        global_path.parent.mkdir(parents=True)
        VaultManager.init_vault(global_path, PASSPHRASE).close()

        project_path = tmp_path / ".ownlock" / "vault.db"
        project_path.parent.mkdir(parents=True)
        VaultManager.init_vault(project_path, PASSPHRASE).close()

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", global_path)
        monkeypatch.setattr("ownlock.vault.GLOBAL_VAULT_PATH", global_path)
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: project_path),
        )

        env_file = tmp_path / ".env"
        env_file.write_text('GTOKEN=vault("GTOKEN", global=true)\n')
        values_file = tmp_path / "v.json"
        values_file.write_text(json.dumps({"GTOKEN": "global-secret-value"}))

        result = runner.invoke(
            app, ["import", str(env_file), "--values-from", str(values_file)]
        )
        assert result.exit_code == 0, result.output

        with VaultManager(global_path, PASSPHRASE) as vm:
            assert vm.get("GTOKEN") == "global-secret-value"
        with VaultManager(project_path, PASSPHRASE) as vm:
            assert vm.get("GTOKEN") is None

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

    def test_import_vault_refs_with_values_from_json(
        self, tmp_path, vault_db, monkeypatch
    ):
        """Missing keys are read from --values-from; existing keys untouched."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        with VaultManager(vault_db, PASSPHRASE) as vm:
            vm.set("ALREADY_THERE", "x")

        env_file = tmp_path / ".env"
        env_file.write_text(
            'API_KEY=vault("API_KEY")\n'
            'DB_URL=vault("DB_URL")\n'
            'KNOWN=vault("ALREADY_THERE")\n'
            "PLAIN=hello\n"
        )

        values_file = tmp_path / "values.json"
        values_file.write_text(json.dumps({"API_KEY": "ak-123", "DB_URL": "postgres://"}))

        monkeypatch.chdir(tmp_path)

        result = runner.invoke(
            app,
            ["import", str(env_file), "--values-from", str(values_file)],
        )
        assert result.exit_code == 0
        assert "Missing 2 secret(s)" in result.output

        with VaultManager(vault_db, PASSPHRASE) as vm:
            assert vm.get("API_KEY") == "ak-123"
            assert vm.get("DB_URL") == "postgres://"
            assert vm.get("ALREADY_THERE") == "x"

    def test_import_vault_refs_idempotent_when_all_present(
        self, tmp_path, vault_db, monkeypatch
    ):
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        with VaultManager(vault_db, PASSPHRASE) as vm:
            vm.set("K1", "v1")
            vm.set("K2", "v2")

        env_file = tmp_path / ".env"
        env_file.write_text('A=vault("K1")\nB=vault("K2")\n')

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["import", str(env_file)])
        assert result.exit_code == 0
        assert "already populated" in result.output

    def test_import_vault_refs_non_interactive_without_values_errors(
        self, tmp_path, vault_db, monkeypatch
    ):
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        env_file = tmp_path / ".env"
        env_file.write_text('NEED=vault("NEED")\n')

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: False)
        result = runner.invoke(app, ["import", str(env_file)])
        assert result.exit_code == 1
        assert "values-from" in result.output

    def test_import_vault_refs_picks_up_env_argument(
        self, tmp_path, vault_db, monkeypatch
    ):
        """vault('K', env='production') is checked against the production env."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        env_file = tmp_path / ".env"
        env_file.write_text('PROD_KEY=vault("PROD_KEY", env="production")\n')

        values_file = tmp_path / "v.json"
        values_file.write_text(json.dumps({"PROD_KEY": "secret-prod"}))

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            app,
            ["import", str(env_file), "--values-from", str(values_file)],
        )
        assert result.exit_code == 0

        with VaultManager(vault_db, PASSPHRASE) as vm:
            assert vm.get("PROD_KEY", env="production") == "secret-prod"
            assert vm.get("PROD_KEY") is None

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


# Note: filesystem-root guard logic for `scan` lives in `ownlock.scanner.is_dangerous_scan_root`;
# unit tests for that helper are in tests/test_scanner.py::TestDangerousScanRoot.


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

    def test_scan_no_project_vault_does_not_use_global(
        self, tmp_path, monkeypatch
    ):
        """Without a project vault, scan must not open the global vault."""
        monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
        monkeypatch.setattr("ownlock.keyring_util.get_passphrase", lambda: None)
        monkeypatch.setattr(
            "ownlock.cli._resolve_scan_vault_path",
            lambda global_vault=False, project=False: None,
        )
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: None),
        )
        (tmp_path / "readme.txt").write_text("nothing\n")

        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--yes"],
            env={"OWNLOCK_PASSPHRASE": None},
        )
        assert result.exit_code == 0, result.output
        assert "No project vault found" in result.output
        assert "Invalid passphrase" not in result.output

    def test_scan_wrong_passphrase_continues_legacy_scan(
        self, tmp_path, vault_db, monkeypatch
    ):
        """Bad passphrase prints a clear message but still flags legacy backups."""
        with VaultManager(vault_db, "correct-pass") as vm:
            vm.set("K", "long-secret-value-here")
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", "wrong-pass")
        monkeypatch.setattr(
            "ownlock.cli._resolve_scan_vault_path",
            lambda global_vault=False, project=False: vault_db,
        )
        legacy = tmp_path / ".env.ownlock.bak"
        legacy.write_text("OLD=1\n")

        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--yes"],
            env={"OWNLOCK_PASSPHRASE": "wrong-pass"},
        )
        assert result.exit_code == 1, result.output
        assert "Passphrase does not unlock vault" in result.output
        assert "legacy plaintext backup" in result.output.lower()
        assert legacy.name in result.output.replace("\n", "")

# Note: --max-file-bytes / unit-level rewrite logic are covered by
# tests/test_scanner.py::test_max_file_bytes_skips_oversized and
# tests/test_envfile.py::test_rewrite_env_lines_to_vault_syntax.


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
        # Rich may wrap long paths across lines on narrow terminals (CI).
        assert "ownlock.bak" in result.output.replace("\n", "")


class TestExport:
    def test_export_prints_resolved(self, tmp_path, vault_db, seeded_vault):
        env_file = tmp_path / ".env"
        env_file.write_text('MY_KEY=vault("MY_KEY")\nPLAIN=hello\n')

        with patch("ownlock.vault.GLOBAL_VAULT_PATH", vault_db):
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

    def test_export_docker_format_quotes_special_characters(
        self, tmp_path, vault_db, seeded_vault
    ):
        """Docker -e style output must quote values with spaces, quotes, or newlines."""
        with VaultManager(vault_db, PASSPHRASE) as vm:
            vm.set("DOCKER_KEY", 'say "hello"\nworld')

        env_file = tmp_path / ".env"
        env_file.write_text('DOCKER_KEY=vault("DOCKER_KEY")\n')

        result = runner.invoke(
            app, ["export", "-f", str(env_file), "--format", "docker"]
        )
        assert result.exit_code == 0
        line = result.output.strip()
        assert line.startswith("DOCKER_KEY=")
        # Value must be shell-safe: wrapped in double quotes with escapes.
        assert '\\"' in line or "hello" in line
        assert "say" in line


class TestRun:
    def test_run_injects_vault_secret_into_child(self, tmp_path, vault_db, seeded_vault):
        env_file = tmp_path / ".env"
        env_file.write_text('SECRET=vault("MY_KEY")\n')
        code = (
            "import os, sys\n"
            "sys.exit(0 if os.environ.get('SECRET') == 'my-value' else 1)\n"
        )
        result = runner.invoke(
            app,
            ["run", "-f", str(env_file), "--", sys.executable, "-c", code],
        )
        assert result.exit_code == 0

    def test_run_injects_inline_env_literal_into_child(self, tmp_path, vault_db):
        """Migration .env files may still have plaintext values; run injects them."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        env_file = tmp_path / ".env"
        env_file.write_text("LEGACY_API_KEY=sk-live-migration-secret\n")
        code = (
            "import os, sys\n"
            "sys.exit(0 if os.environ.get('LEGACY_API_KEY') == "
            "'sk-live-migration-secret' else 1)\n"
        )
        result = runner.invoke(
            app,
            ["run", "-f", str(env_file), "--", sys.executable, "-c", code],
        )
        assert result.exit_code == 0


class TestInstallHook:
    """ownlock install-hook: pre-commit framework + raw git hook modes."""

    def test_writes_git_hook_when_no_pre_commit_config(self, tmp_path, monkeypatch):
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-hook"])
        assert result.exit_code == 0, result.output
        hook = tmp_path / ".git" / "hooks" / "pre-commit"
        assert hook.exists()
        assert "ownlock scan" in hook.read_text()
        if os.name == "posix":
            assert hook.stat().st_mode & 0o111, "git hook must be executable"

    def test_appends_to_pre_commit_config(self, tmp_path, monkeypatch):
        config = tmp_path / ".pre-commit-config.yaml"
        config.write_text("repos:\n  - repo: meta\n    hooks: []\n")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-hook"])
        assert result.exit_code == 0, result.output
        text = config.read_text()
        assert "id: ownlock-scan" in text
        assert "ownlock scan ." in text
        # Existing entries preserved
        assert "id: meta" not in text  # original was just "- repo: meta", check still there
        assert "- repo: meta" in text

    def test_force_overwrites_existing_git_hook(self, tmp_path, monkeypatch):
        hooks_dir = tmp_path / ".git" / "hooks"
        hooks_dir.mkdir(parents=True)
        hook = hooks_dir / "pre-commit"
        hook.write_text("#!/bin/sh\necho previous\n")
        monkeypatch.chdir(tmp_path)

        # Without --force: refuses
        result = runner.invoke(app, ["install-hook", "--git-hook"])
        assert result.exit_code == 0
        assert "already exists" in result.output
        assert "echo previous" in hook.read_text()

        # With --force: overwrites
        result = runner.invoke(app, ["install-hook", "--git-hook", "--force"])
        assert result.exit_code == 0
        assert "ownlock scan" in hook.read_text()

    def test_idempotent_pre_commit_yaml(self, tmp_path, monkeypatch):
        config = tmp_path / ".pre-commit-config.yaml"
        config.write_text("repos:\n")
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-hook"])
        assert result.exit_code == 0

        first = config.read_text()
        result = runner.invoke(app, ["install-hook"])
        assert result.exit_code == 0
        assert "already present" in result.output
        # Running twice should not duplicate the block.
        assert config.read_text() == first

    def test_no_git_repo_clean_error(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["install-hook", "--git-hook"])
        assert result.exit_code == 1
        assert "Not in a git repository" in result.output


class TestCompletion:
    """ownlock completion: prints non-empty script for each supported shell."""

    @pytest.mark.parametrize("shell", ["bash", "zsh", "fish", "pwsh"])
    def test_completion_prints_script(self, shell):
        from click.shell_completion import get_completion_class
        from typer.main import get_command

        click_shell = "powershell" if shell == "pwsh" else shell
        if get_completion_class(click_shell) is None:
            pytest.skip(f"Click has no completion class for {shell} on this platform")

        result = runner.invoke(app, ["completion", shell])
        assert result.exit_code == 0, result.output
        assert "ownlock" in result.output.lower()
        assert "_OWNLOCK_COMPLETE" in result.output

    def test_completion_powershell_alias(self):
        from click.shell_completion import get_completion_class

        if get_completion_class("powershell") is None:
            pytest.skip("PowerShell completion not available on this platform")
        a = runner.invoke(app, ["completion", "pwsh"]).output
        b = runner.invoke(app, ["completion", "powershell"]).output
        assert a == b

    def test_completion_unsupported_shell(self):
        result = runner.invoke(app, ["completion", "cmd"])
        assert result.exit_code == 1
        assert "Unsupported" in result.output


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

        # Old passphrase no longer resolves rows after rotation.
        with _VM(vault_db, PASSPHRASE) as vm:
            assert vm.get("MY_KEY") is None
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
            secret_name_lookup,
            token_iterations as _ti,
        )
        from ownlock.vault import VaultManager as _VM

        with _VM(vault_db, PASSPHRASE) as vm:
            vm.set("CLASSIC", "classic")
            lookup = secret_name_lookup(PASSPHRASE, "CLASSIC", "default")
            legacy = _encrypt("classic", PASSPHRASE, iterations=KDF_ITERATIONS_LEGACY)
            vm._require_conn().execute(
                "UPDATE secrets SET value_enc = ? WHERE name_lookup = ?",
                (legacy, lookup),
            )
            vm._require_conn().commit()

        result = runner.invoke(app, ["rekey", "--upgrade-kdf", "--yes"])
        assert result.exit_code == 0, result.output

        with _VM(vault_db, PASSPHRASE) as vm:
            row = vm._require_conn().execute(
                "SELECT value_enc FROM secrets WHERE name_lookup = ?",
                (lookup,),
            ).fetchone()
            assert _ti(row["value_enc"]) == KDF_ITERATIONS_CURRENT


class TestPassphraseSession:
    def test_list_command_clears_session_passphrase(self, vault_db, monkeypatch):
        """CLI commands zero the resolve_passphrase buffer when they finish."""
        VaultManager.init_vault(vault_db, PASSPHRASE).close()
        cleared_ids: list[int] = []
        original_clear = Passphrase.clear

        def tracking_clear(self: Passphrase) -> None:
            cleared_ids.append(id(self))
            original_clear(self)

        monkeypatch.setattr(Passphrase, "clear", tracking_clear)
        result = runner.invoke(app, ["list", "--json"])
        assert result.exit_code == 0
        assert len(cleared_ids) >= 2  # VaultManager + passphrase_session


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
        result = runner.invoke(
            app, ["list"], env={"OWNLOCK_PASSPHRASE": None}
        )
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
