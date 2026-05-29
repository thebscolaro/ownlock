"""Golden / shape tests for ``ownlock doctor --json`` output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ownlock.cli import app
from ownlock.vault import VaultManager

PASSPHRASE = "test-pass"
runner = CliRunner()

_GOLDEN = Path(__file__).parent / "golden" / "doctor_output_shape.json"


def _load_shape() -> dict:
    return json.loads(_GOLDEN.read_text(encoding="utf-8"))


@pytest.fixture()
def shape() -> dict:
    return _load_shape()


class TestDoctorGoldenShape:
    def test_doctor_json_matches_documented_shape(
        self, tmp_path, monkeypatch, shape
    ) -> None:
        vault_db = tmp_path / ".ownlock" / "vault.db"
        vault_db.parent.mkdir(parents=True)
        with VaultManager.init_vault(vault_db, PASSPHRASE) as vm:
            vm.set("GOLDEN_KEY", "golden-value")

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", vault_db)
        monkeypatch.setattr("ownlock.vault.GLOBAL_VAULT_PATH", vault_db)
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: vault_db),
        )

        result = runner.invoke(app, ["doctor", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)

        for key in shape["required_top_level_keys"]:
            assert key in data, f"missing top-level key: {key}"

        assert isinstance(data["global_vault"], dict)
        assert data["global_vault"]["exists"] is True
        for key in shape["global_vault_keys_when_exists"]:
            assert key in data["global_vault"], f"missing global_vault.{key}"

        assert data["global_vault"]["schema_version"] == 3
        assert data["global_vault"]["secret_count"] == 1
        assert data["global_vault"]["kdf_stale"] is False

        assert isinstance(data["project_vault"], dict)
        for key in shape["project_vault_keys_when_missing"]:
            assert key in data["project_vault"]

        assert data["passphrase_source"] in {
            "env var",
            "keyring",
            "keyring (unavailable)",
            "would prompt",
        }

    def test_golden_fixture_file_is_valid_json(self) -> None:
        data = _load_shape()
        assert "required_top_level_keys" in data
        assert isinstance(data["required_top_level_keys"], list)
