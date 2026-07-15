"""`ownlock sync gh` — push via gh secret set stdin, names-only pull diff."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from ownlock import ghsync
from ownlock.cli import app
from ownlock.ghsync import (
    GhSyncError,
    check_authenticated,
    list_remote_secret_names,
    push_secret,
    require_gh,
)
from ownlock.vault import VaultManager

PASSPHRASE = "ghsync-pass"
runner = CliRunner(env={"OWNLOCK_PASSPHRASE": PASSPHRASE, "OWNLOCK_AUDIT": "0"})


class FakeProc(SimpleNamespace):
    pass


def _fake_run(record, *, returncode=0, stdout=b"", stderr=b""):
    def run(argv, **kwargs):
        record.append({"argv": argv, "input": kwargs.get("input")})
        return FakeProc(returncode=returncode, stdout=stdout, stderr=stderr)

    return run


class TestGhPlumbing:
    def test_validate_rejects_flag_like_repo(self):
        from ownlock.ghsync import validate_sync_targets

        with pytest.raises(GhSyncError, match="invalid --repo"):
            validate_sync_targets(repo="--help")
        with pytest.raises(GhSyncError, match="invalid --repo"):
            validate_sync_targets(repo="not-a-repo")
        with pytest.raises(GhSyncError, match="invalid secret name"):
            validate_sync_targets("--API_KEY")
        validate_sync_targets("API_KEY", repo="o/r", gh_env="production")

    def test_require_gh_missing(self, monkeypatch):
        monkeypatch.setattr(ghsync.shutil, "which", lambda _: None)
        with pytest.raises(GhSyncError, match="gh.* not found"):
            require_gh()

    def test_require_gh_found(self, monkeypatch):
        monkeypatch.setattr(ghsync.shutil, "which", lambda _: "/usr/bin/gh")
        assert require_gh() == "/usr/bin/gh"

    def test_check_authenticated_ok(self, monkeypatch):
        calls: list = []
        monkeypatch.setattr(ghsync.subprocess, "run", _fake_run(calls))
        check_authenticated("gh")
        assert calls[0]["argv"] == ["gh", "auth", "status"]

    def test_check_authenticated_fails(self, monkeypatch):
        calls: list = []
        monkeypatch.setattr(
            ghsync.subprocess,
            "run",
            _fake_run(calls, returncode=1, stderr=b"not logged in"),
        )
        with pytest.raises(GhSyncError, match="not authenticated"):
            check_authenticated("gh")

    def test_push_secret_uses_stdin_never_argv(self, monkeypatch):
        calls: list = []
        monkeypatch.setattr(ghsync.subprocess, "run", _fake_run(calls))
        push_secret("gh", "API_KEY", "s3cret-value", repo="o/r", gh_env="production")
        call = calls[0]
        assert call["argv"] == [
            "gh", "secret", "set", "API_KEY", "--repo", "o/r", "--env", "production",
        ]
        assert call["input"] == b"s3cret-value"
        assert all("s3cret-value" not in str(a) for a in call["argv"])

    def test_push_secret_failure_raises(self, monkeypatch):
        calls: list = []
        monkeypatch.setattr(
            ghsync.subprocess, "run", _fake_run(calls, returncode=1, stderr=b"boom")
        )
        with pytest.raises(GhSyncError, match="boom"):
            push_secret("gh", "API_KEY", "v")

    def test_list_remote_secret_names(self, monkeypatch):
        calls: list = []
        payload = json.dumps([{"name": "B_KEY"}, {"name": "A_KEY"}]).encode()
        monkeypatch.setattr(
            ghsync.subprocess, "run", _fake_run(calls, stdout=payload)
        )
        assert list_remote_secret_names("gh") == ["A_KEY", "B_KEY"]
        assert calls[0]["argv"][:4] == ["gh", "secret", "list", "--json"]

    def test_list_remote_bad_json(self, monkeypatch):
        calls: list = []
        monkeypatch.setattr(
            ghsync.subprocess, "run", _fake_run(calls, stdout=b"not json")
        )
        with pytest.raises(GhSyncError, match="unparseable"):
            list_remote_secret_names("gh")


@pytest.fixture()
def project_vault(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db = tmp_path / ".ownlock" / "vault.db"
    with VaultManager(db, PASSPHRASE) as vm:
        vm.set("API_KEY", "topsecret-123")
        vm.set("DB_PASSWORD", "hunter2hunter2")
    return db


class TestSyncGhCli:
    def test_push_happy_path(self, project_vault, monkeypatch):
        pushed: list = []
        monkeypatch.setattr("ownlock.ghsync.find_gh", lambda: "gh")
        monkeypatch.setattr("ownlock.ghsync.check_authenticated", lambda gh: None)
        monkeypatch.setattr(
            "ownlock.ghsync.push_secret",
            lambda gh, name, value, repo=None, gh_env=None: pushed.append(
                (name, value, repo, gh_env)
            ),
        )
        result = runner.invoke(
            app,
            ["sync", "gh", "push", "API_KEY", "--project", "--repo", "o/r", "--yes"],
        )
        assert result.exit_code == 0, result.output
        assert pushed == [("API_KEY", "topsecret-123", "o/r", None)]
        assert "1 secret(s) pushed" in result.output

    def test_push_missing_name_fails_before_pushing(self, project_vault, monkeypatch):
        monkeypatch.setattr("ownlock.ghsync.find_gh", lambda: "gh")
        monkeypatch.setattr("ownlock.ghsync.check_authenticated", lambda gh: None)
        result = runner.invoke(
            app, ["sync", "gh", "push", "API_KEY", "NOPE", "--project", "--yes"]
        )
        assert result.exit_code == 1
        assert "NOPE" in result.output
        assert "nothing pushed" in result.output

    def test_push_requires_confirmation(self, project_vault, monkeypatch):
        monkeypatch.setattr("ownlock.ghsync.find_gh", lambda: "gh")
        monkeypatch.setattr("ownlock.ghsync.check_authenticated", lambda gh: None)
        result = runner.invoke(
            app, ["sync", "gh", "push", "API_KEY", "--project"], input="n\n"
        )
        assert result.exit_code == 1
        assert "Aborted" in result.output

    def test_push_fails_cleanly_without_gh(self, project_vault, monkeypatch):
        monkeypatch.setattr("ownlock.ghsync.find_gh", lambda: None)
        result = runner.invoke(
            app, ["sync", "gh", "push", "API_KEY", "--project", "--yes"]
        )
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_push_writes_audit_log(self, project_vault, monkeypatch):
        monkeypatch.setattr("ownlock.ghsync.find_gh", lambda: "gh")
        monkeypatch.setattr("ownlock.ghsync.check_authenticated", lambda gh: None)
        monkeypatch.setattr(
            "ownlock.ghsync.push_secret",
            lambda gh, name, value, repo=None, gh_env=None: None,
        )
        result = runner.invoke(
            app,
            ["sync", "gh", "push", "API_KEY", "--project", "--yes"],
            env={"OWNLOCK_PASSPHRASE": PASSPHRASE, "OWNLOCK_AUDIT": "1"},
        )
        assert result.exit_code == 0, result.output
        log = project_vault.parent / "audit.log"
        assert log.exists()
        lines = [json.loads(ln) for ln in log.read_text().splitlines()]
        ops = [ln["op"] for ln in lines]
        assert "sync-gh-push" in ops
        assert all("topsecret" not in ln for ln in log.read_text().splitlines())

    def test_pull_reports_missing_from_vault(self, project_vault, monkeypatch):
        monkeypatch.setattr("ownlock.ghsync.find_gh", lambda: "gh")
        monkeypatch.setattr("ownlock.ghsync.check_authenticated", lambda gh: None)
        monkeypatch.setattr(
            "ownlock.ghsync.list_remote_secret_names",
            lambda gh, repo=None, gh_env=None: ["API_KEY", "ONLY_ON_GH"],
        )
        result = runner.invoke(app, ["sync", "gh", "pull", "--project"])
        assert result.exit_code == 0, result.output
        assert "ONLY_ON_GH" in result.output
        assert "not in vault" in result.output
        assert "cannot return secret values" in result.output

    def test_pull_all_present(self, project_vault, monkeypatch):
        monkeypatch.setattr("ownlock.ghsync.find_gh", lambda: "gh")
        monkeypatch.setattr("ownlock.ghsync.check_authenticated", lambda gh: None)
        monkeypatch.setattr(
            "ownlock.ghsync.list_remote_secret_names",
            lambda gh, repo=None, gh_env=None: ["API_KEY"],
        )
        result = runner.invoke(app, ["sync", "gh", "pull", "--project"])
        assert result.exit_code == 0, result.output
        assert "All GitHub Actions secret names exist" in result.output
