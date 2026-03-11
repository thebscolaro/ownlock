"""Tests for ownlock.vault — SQLite-backed encrypted secret storage."""

import pytest

from ownlock.vault import VaultManager


PASSPHRASE = "test-pass"


@pytest.fixture()
def vault(tmp_path):
    db = tmp_path / "vault.db"
    with VaultManager(db, PASSPHRASE) as vm:
        yield vm


class TestSetGet:
    def test_set_then_get(self, vault):
        vault.set("API_KEY", "sk-123")
        assert vault.get("API_KEY") == "sk-123"

    def test_get_nonexistent_returns_none(self, vault):
        assert vault.get("MISSING") is None

    def test_set_overwrites(self, vault):
        vault.set("TOKEN", "old")
        vault.set("TOKEN", "new")
        assert vault.get("TOKEN") == "new"


class TestDelete:
    def test_delete_existing_returns_true(self, vault):
        vault.set("KEY", "val")
        assert vault.delete("KEY") is True

    def test_delete_nonexistent_returns_false(self, vault):
        assert vault.delete("NOPE") is False

    def test_get_after_delete_returns_none(self, vault):
        vault.set("KEY", "val")
        vault.delete("KEY")
        assert vault.get("KEY") is None


class TestListSecrets:
    def test_list_returns_names_and_envs(self, vault):
        vault.set("A", "1")
        vault.set("B", "2")
        secrets = vault.list_secrets()
        names = [s["name"] for s in secrets]
        assert "A" in names and "B" in names
        for s in secrets:
            assert "value_enc" not in s

    def test_list_with_env_filter(self, vault):
        vault.set("X", "val", env="prod")
        vault.set("Y", "val", env="staging")
        prod = vault.list_secrets(env="prod")
        assert len(prod) == 1
        assert prod[0]["name"] == "X"


class TestGetAllDecrypted:
    def test_returns_name_value_dict(self, vault):
        vault.set("DB_PASS", "s3cr3t")
        vault.set("API_KEY", "sk-abc")
        result = vault.get_all_decrypted()
        assert result == {"DB_PASS": "s3cr3t", "API_KEY": "sk-abc"}

    def test_scoped_to_env(self, vault):
        vault.set("KEY", "default-val")
        vault.set("KEY", "prod-val", env="prod")
        assert vault.get_all_decrypted("default") == {"KEY": "default-val"}
        assert vault.get_all_decrypted("prod") == {"KEY": "prod-val"}


class TestMultiEnv:
    def test_same_name_different_envs_independent(self, vault):
        vault.set("SECRET", "dev-value", env="dev")
        vault.set("SECRET", "prod-value", env="prod")
        assert vault.get("SECRET", env="dev") == "dev-value"
        assert vault.get("SECRET", env="prod") == "prod-value"


class TestContextManager:
    def test_with_statement(self, tmp_path):
        db = tmp_path / "ctx.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("K", "V")
            assert vm.get("K") == "V"
        # Re-open to verify persistence
        with VaultManager(db, PASSPHRASE) as vm2:
            assert vm2.get("K") == "V"


class TestInitVault:
    def test_creates_db_file(self, tmp_path):
        db = tmp_path / "sub" / "vault.db"
        vm = VaultManager.init_vault(db, PASSPHRASE)
        try:
            assert db.exists()
        finally:
            vm.close()
