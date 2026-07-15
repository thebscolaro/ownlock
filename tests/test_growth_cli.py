"""CLI smoke coverage for shield / guard / status / init --project."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ownlock.cli import app
from ownlock.vault import VaultManager

PASSPHRASE = "cov-pass"
runner = CliRunner(env={"OWNLOCK_PASSPHRASE": PASSPHRASE, "OWNLOCK_AUDIT": "0"})


@pytest.fixture()
def project_vault(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db = tmp_path / ".ownlock" / "vault.db"
    with VaultManager(db, PASSPHRASE) as vm:
        vm.set("SECRET", "supersecretvalue")
        vm.set("OTHER", "othersecret99", env="prod")
    return db


class TestInitProjectFlag:
    def test_init_project_flag(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "ownlock.cli.getpass.getpass",
            lambda prompt="": PASSPHRASE,
        )
        global_path = tmp_path / "global" / "vault.db"
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", global_path)
        monkeypatch.setattr("ownlock.vault.GLOBAL_VAULT_PATH", global_path)
        result = runner.invoke(app, ["init", "--project"])
        assert result.exit_code == 0, result.output
        assert (tmp_path / ".ownlock" / "vault.db").exists()

    def test_init_rejects_global_and_project(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init", "--global", "--project"])
        assert result.exit_code == 1
        assert "either" in result.output.lower() or "not both" in result.output.lower()


class TestShieldGuardStatus:
    def test_shield_and_verify(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["shield", str(tmp_path)])
        assert result.exit_code == 0, result.output
        verify = runner.invoke(app, ["shield", str(tmp_path), "--verify"])
        assert verify.exit_code == 0, verify.output

    def test_shield_selftest(self, tmp_path, monkeypatch):
        from ownlock import hookutil

        if hookutil.find_bash() is None and hookutil.find_powershell() is None:
            pytest.skip("no hook interpreter available")
        monkeypatch.chdir(tmp_path)
        install = runner.invoke(app, ["shield", str(tmp_path)])
        assert install.exit_code == 0, install.output
        result = runner.invoke(app, ["shield", str(tmp_path), "--selftest"])
        assert result.exit_code == 0, result.output
        assert "hook checks passed" in result.output
        assert (tmp_path / ".ownlock" / "selftest.json").exists()

    def test_shield_selftest_without_install_fails(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["shield", str(tmp_path), "--selftest"])
        assert result.exit_code == 1
        assert "No runnable shield hooks" in result.output

    def test_status_json(self, project_vault, monkeypatch):
        monkeypatch.setattr("ownlock.agent.detect_agent_actor", lambda: None)
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["vault_exists"] is True
        assert payload["secret_count"] >= 1
        assert "shield_ok" in payload
        assert payload["shield_selftest_ok"] is False

    def test_guard_stdin_all_envs(self, project_vault, monkeypatch):
        result = runner.invoke(
            app, ["guard", "--stdin"], input="leak othersecret99 here"
        )
        assert result.exit_code == 0
        assert "othersecret99" not in result.output
        assert "REDACTED" in result.output

    def test_guard_install_hook(self, tmp_path, monkeypatch):
        import os

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["guard", "--install-hook", "-C", str(tmp_path)])
        assert result.exit_code == 0, result.output
        name = "ownlock-guard.ps1" if os.name == "nt" else "ownlock-guard.sh"
        assert (tmp_path / ".claude" / "hooks" / name).exists()


class TestEnsureGitignorePaths:
    def test_ensure_gitignore_noop_when_complete(self, tmp_path, monkeypatch):
        from ownlock.paths import ensure_gitignore

        monkeypatch.chdir(tmp_path)
        gi = tmp_path / ".gitignore"
        gi.write_text(".ownlock/*\n!.ownlock/team.olbundle\n")
        ensure_gitignore()
        assert gi.read_text().count("!.ownlock/team.olbundle") == 1
        assert gi.read_text().count(".ownlock/*") == 1

    def test_ensure_gitignore_strips_legacy_dir_rule(self, tmp_path, monkeypatch):
        from ownlock.paths import ensure_gitignore

        monkeypatch.chdir(tmp_path)
        gi = tmp_path / ".gitignore"
        gi.write_text("foo\n.ownlock/\n.ownlock\n")
        ensure_gitignore()
        text = gi.read_text()
        assert ".ownlock/" not in {ln.strip() for ln in text.splitlines()}
        assert ".ownlock" not in {ln.strip() for ln in text.splitlines()}
        assert ".ownlock/*" in text
        assert "!.ownlock/team.olbundle" in text
