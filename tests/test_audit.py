"""Tests for ownlock.audit — opt-in JSONL operation log."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ownlock import audit
from ownlock.cli import app
from ownlock.vault import VaultManager

PASSPHRASE = "audit-pp"
runner = CliRunner()


@pytest.fixture()
def vault(tmp_path: Path):
    db = tmp_path / ".ownlock" / "vault.db"
    VaultManager.init_vault(db, PASSPHRASE).close()
    return db


class TestIsEnabled:
    @pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
    def test_truthy(self, val, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OWNLOCK_AUDIT", val)
        assert audit.is_enabled() is True

    @pytest.mark.parametrize("val", ["", "0", "false", "no", "off", "anything-else"])
    def test_falsy(self, val, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OWNLOCK_AUDIT", val)
        assert audit.is_enabled() is False

    def test_unset_is_disabled(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("OWNLOCK_AUDIT", raising=False)
        assert audit.is_enabled() is False


class TestRecordNoop:
    def test_record_does_nothing_when_disabled(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("OWNLOCK_AUDIT", raising=False)
        vault = tmp_path / ".ownlock" / "vault.db"
        vault.parent.mkdir(parents=True)
        vault.touch()
        wrote = audit.record("set", vault_path=vault, name="X", env="default")
        assert wrote is False
        assert not (vault.parent / "audit.log").exists()


class TestRecordEnabled:
    def test_appends_one_jsonl_line(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        vault = tmp_path / ".ownlock" / "vault.db"
        vault.parent.mkdir(parents=True)
        vault.touch()

        assert audit.record("set", vault_path=vault, name="API_KEY", env="prod") is True

        log = vault.parent / "audit.log"
        assert log.exists()
        lines = log.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["op"] == "set"
        assert record["name"] == "API_KEY"
        assert record["env"] == "prod"
        assert record["actor"] == "ownlock"
        assert record["vault"] == str(vault)
        assert "ts" in record

        # No value-bearing fields ever leak.
        assert "value" not in record
        assert "value_enc" not in record
        assert "passphrase" not in record

    def test_log_file_mode_0600_on_posix(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        if os.name != "posix":
            pytest.skip("POSIX file-mode check")
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        vault = tmp_path / ".ownlock" / "vault.db"
        vault.parent.mkdir(parents=True)
        vault.touch()
        audit.record("set", vault_path=vault, name="X", env="default")
        mode = (vault.parent / "audit.log").stat().st_mode & 0o777
        assert mode == 0o600

    def test_appending_does_not_overwrite(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        vault = tmp_path / ".ownlock" / "vault.db"
        vault.parent.mkdir(parents=True)
        vault.touch()

        for i in range(3):
            audit.record("set", vault_path=vault, name=f"K{i}", env="default")

        lines = (vault.parent / "audit.log").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 3
        ops = [json.loads(line)["name"] for line in lines]
        assert ops == ["K0", "K1", "K2"]

    def test_extra_fields_round_trip(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        vault = tmp_path / ".ownlock" / "vault.db"
        vault.parent.mkdir(parents=True)
        vault.touch()

        audit.record(
            "rekey",
            vault_path=vault,
            extra={"secrets_rekeyed": 5, "rotated_passphrase": True},
        )

        line = (vault.parent / "audit.log").read_text().strip()
        record = json.loads(line)
        assert record["secrets_rekeyed"] == 5
        assert record["rotated_passphrase"] is True

    def test_extra_cannot_clobber_canonical_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A bad caller passing extra={'op': 'something-else'} must not change the op."""
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        vault = tmp_path / ".ownlock" / "vault.db"
        vault.parent.mkdir(parents=True)
        vault.touch()
        audit.record(
            "set",
            vault_path=vault,
            name="K",
            env="default",
            extra={"op": "spoofed", "vault": "/etc/passwd"},
        )
        line = (vault.parent / "audit.log").read_text().strip()
        record = json.loads(line)
        assert record["op"] == "set"
        assert record["vault"] == str(vault)


class TestCliIntegration:
    """End-to-end: enable OWNLOCK_AUDIT and confirm CLI commands log."""

    def test_set_logs_op(
        self, vault: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault,
        )
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: None),
        )

        result = runner.invoke(app, ["set", "AUDITED=1234567890"])
        assert result.exit_code == 0

        log = vault.parent / "audit.log"
        assert log.exists()
        record = json.loads(log.read_text().strip())
        assert record["op"] == "set"
        assert record["name"] == "AUDITED"
        assert "value" not in record

    def test_no_log_without_env_var(
        self, vault: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.delenv("OWNLOCK_AUDIT", raising=False)
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault,
        )
        result = runner.invoke(app, ["set", "K=longvalueX"])
        assert result.exit_code == 0
        assert not (vault.parent / "audit.log").exists()

    def test_delete_logs_only_when_secret_existed(
        self, vault: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault,
        )
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: None),
        )
        with VaultManager(vault, PASSPHRASE) as vm:
            vm.set("ZAPPED", "1234567890")

        runner.invoke(app, ["delete", "ZAPPED"])
        runner.invoke(app, ["delete", "MISSING"])

        records = [
            json.loads(line)
            for line in (vault.parent / "audit.log").read_text().splitlines()
        ]
        ops = [r for r in records if r["op"] == "delete"]
        assert len(ops) == 1
        assert ops[0]["name"] == "ZAPPED"
