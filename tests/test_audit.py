"""Tests for ownlock.audit — opt-in JSONL operation log."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from ownlock import audit
from ownlock.cli import app
from ownlock.vault import VaultManager

PASSPHRASE = "audit-pp"
runner = CliRunner()


@pytest.fixture()
def vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = tmp_path / ".ownlock" / "vault.db"
    VaultManager.init_vault(db, PASSPHRASE).close()
    monkeypatch.setattr("ownlock.vault.GLOBAL_VAULT_PATH", db)
    monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", db)
    monkeypatch.setattr(
        "ownlock.vault.VaultManager.find_project_vault",
        staticmethod(lambda: None),
    )
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

    def test_record_returns_false_on_oserror(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        vault = tmp_path / ".ownlock" / "vault.db"
        vault.parent.mkdir(parents=True)
        vault.touch()
        with patch.object(Path, "open", side_effect=OSError("disk full")):
            assert audit.record("set", vault_path=vault, name="X", env="default") is False

    def test_record_succeeds_when_chmod_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        if os.name != "posix":
            pytest.skip("POSIX chmod path")
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        vault = tmp_path / ".ownlock" / "vault.db"
        vault.parent.mkdir(parents=True)
        vault.touch()
        with patch("ownlock.audit.os.chmod", side_effect=OSError("permission denied")):
            assert audit.record("set", vault_path=vault, name="X", env="default") is True
        assert (vault.parent / "audit.log").exists()

    def test_init_logs_op(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        monkeypatch.chdir(tmp_path)
        project_vault = tmp_path / ".ownlock" / "vault.db"
        global_path = tmp_path / "global" / "vault.db"
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", global_path)
        monkeypatch.setattr(
            "ownlock.cli.getpass.getpass",
            lambda prompt="": PASSPHRASE,
        )
        monkeypatch.setattr(
            "ownlock.cli.store_passphrase",
            lambda p: (False, "no keyring"),
        )

        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0, result.output

        log = project_vault.parent / "audit.log"
        assert log.exists()
        records = [json.loads(line) for line in log.read_text().splitlines()]
        init_ops = [r for r in records if r["op"] == "init"]
        assert len(init_ops) >= 1
        assert any(r.get("scope") == "project" for r in init_ops)

    def test_import_seed_logs_op(
        self, vault: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        env_file = tmp_path / "seed.env"
        env_file.write_text("SEED_KEY=seed-value\n")
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault,
        )

        result = runner.invoke(app, ["import", str(env_file)])
        assert result.exit_code == 0

        record = json.loads((vault.parent / "audit.log").read_text().strip())
        assert record["op"] == "import"
        assert record["mode"] == "seed"
        assert record["secrets_imported"] == 1

    def test_import_vault_refs_logs_op(
        self, vault: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        env_file = tmp_path / ".env"
        env_file.write_text('NEED=vault("NEED")\n')
        values_file = tmp_path / "v.json"
        values_file.write_text(json.dumps({"NEED": "filled"}))
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault,
        )

        result = runner.invoke(
            app, ["import", str(env_file), "--values-from", str(values_file)]
        )
        assert result.exit_code == 0

        record = json.loads((vault.parent / "audit.log").read_text().strip())
        assert record["op"] == "import"
        assert record["mode"] == "vault_refs"
        assert "NEED" in record["names"]

    def test_rekey_logs_op(
        self, vault: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        monkeypatch.setenv("OWNLOCK_NEW_PASSPHRASE", "new-audit-pp")
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault,
        )
        monkeypatch.setattr("ownlock.cli.store_passphrase", lambda p: (True, None))
        with VaultManager(vault, PASSPHRASE) as vm:
            vm.set("AUDIT_KEY", "1234567890")

        result = runner.invoke(app, ["rekey", "--rotate-passphrase", "--yes"])
        assert result.exit_code == 0, result.output

        records = [
            json.loads(line)
            for line in (vault.parent / "audit.log").read_text().splitlines()
        ]
        rekey_ops = [r for r in records if r["op"] == "rekey"]
        assert len(rekey_ops) == 1
        assert rekey_ops[0]["rotated_passphrase"] is True

    def test_share_and_import_share_log_ops(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        vault_path = tmp_path / ".ownlock" / "vault.db"
        with VaultManager(vault_path, PASSPHRASE) as vm:
            vm.set("SHARE_ME", "share-value-xyz")

        bundle_path = tmp_path / "bundle.olbundle"
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setenv("OWNLOCK_AUDIT", "1")
        monkeypatch.setenv("OWNLOCK_BUNDLE_PASSPHRASE", "bundle-audit-pp")
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault_path,
        )

        result = runner.invoke(
            app, ["share", "-o", str(bundle_path), "--yes"]
        )
        assert result.exit_code == 0, result.output

        share_record = json.loads(
            (vault_path.parent / "audit.log").read_text().splitlines()[0]
        )
        assert share_record["op"] == "share"
        assert "SHARE_ME" in share_record["names"]

        dest = tmp_path / "dest" / "vault.db"
        VaultManager.init_vault(dest, PASSPHRASE).close()
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: dest,
        )
        result = runner.invoke(app, ["import-share", str(bundle_path)])
        assert result.exit_code == 0, result.output

        records = [
            json.loads(line)
            for line in (dest.parent / "audit.log").read_text().splitlines()
        ]
        import_ops = [r for r in records if r["op"] == "import-share"]
        assert len(import_ops) == 1
        assert "SHARE_ME" in import_ops[0]["names"]
