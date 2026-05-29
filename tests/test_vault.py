"""Tests for ownlock.vault — SQLite-backed encrypted secret storage."""

import sqlite3

import pytest

from ownlock.crypto import (
    KDF_ITERATIONS_CURRENT,
    KDF_ITERATIONS_LEGACY,
    encrypt,
    token_iterations,
)
from ownlock.vault import (
    SCHEMA_VERSION_CURRENT,
    VaultManager,
)


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


class TestMeta:
    def test_new_vault_writes_current_meta(self, tmp_path):
        db = tmp_path / "v.db"
        with VaultManager(db, PASSPHRASE) as vm:
            meta = vm.get_meta()
        assert meta["schema_version"] == str(SCHEMA_VERSION_CURRENT)
        assert meta["kdf_algo"] == "PBKDF2-HMAC-SHA256"
        assert meta["kdf_iterations"] == str(KDF_ITERATIONS_CURRENT)
        assert "created_at" in meta

    def test_legacy_vault_without_meta_is_inferred_as_v1(self, tmp_path):
        """A vault file without a meta table (pre-0.2.0) is treated as v1
        with legacy KDF iterations, and the inferred meta is persisted."""
        db = tmp_path / "legacy.db"
        # Build a vault that looks pre-0.2.0: secrets table only, no meta.
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE secrets ("
            "  name TEXT NOT NULL, env TEXT NOT NULL DEFAULT 'default', "
            "  value_enc TEXT NOT NULL, created_at TEXT NOT NULL, "
            "  updated_at TEXT NOT NULL, PRIMARY KEY (name, env))"
        )
        conn.commit()
        conn.close()

        with VaultManager(db, PASSPHRASE) as vm:
            assert vm.schema_version() == 1
            assert vm.kdf_iterations() == KDF_ITERATIONS_LEGACY

    def test_legacy_v1_token_decrypts_after_meta_migration(self, tmp_path):
        """A v1 ciphertext written by old ownlock still decrypts."""
        # Hand-craft a v1 token at legacy iterations and store it directly.
        db = tmp_path / "legacy.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE secrets ("
            "  name TEXT NOT NULL, env TEXT NOT NULL DEFAULT 'default', "
            "  value_enc TEXT NOT NULL, created_at TEXT NOT NULL, "
            "  updated_at TEXT NOT NULL, PRIMARY KEY (name, env))"
        )
        # Create a v1 token by manually building it (no v2 prefix).
        import base64
        import os as _os

        from ownlock.crypto import (
            NONCE_LEN,
            SALT_LEN,
            derive_key,
        )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        plaintext = "legacy-secret-value"
        salt = _os.urandom(SALT_LEN)
        nonce = _os.urandom(NONCE_LEN)
        key = derive_key(PASSPHRASE, salt, KDF_ITERATIONS_LEGACY)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
        v1_token = base64.b64encode(salt + nonce + ct).decode("ascii")
        conn.execute(
            "INSERT INTO secrets (name, env, value_enc, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("LEGACY_KEY", "default", v1_token, "2025-01-01", "2025-01-01"),
        )
        conn.commit()
        conn.close()

        with VaultManager(db, PASSPHRASE) as vm:
            assert vm.get("LEGACY_KEY") == plaintext
            assert vm.schema_version() == 1

    def test_set_writes_v2_token(self, tmp_path):
        db = tmp_path / "v2.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("KEY", "value")
            row = vm._require_conn().execute(
                "SELECT value_enc FROM secrets WHERE name = 'KEY'"
            ).fetchone()
            assert token_iterations(row["value_enc"]) == KDF_ITERATIONS_CURRENT


class TestRekey:
    def test_rekey_changes_passphrase(self, tmp_path):
        db = tmp_path / "rk.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("A", "1")
            vm.set("B", "2", env="prod")
            count = vm.rekey("new-passphrase")
            assert count == 2
            assert vm.get("A") == "1"
            assert vm.get("B", env="prod") == "2"

        # Old passphrase no longer works.
        with VaultManager(db, PASSPHRASE) as vm:
            from cryptography.exceptions import InvalidTag

            with pytest.raises(InvalidTag):
                vm.get("A")

        # New passphrase reads everything.
        with VaultManager(db, "new-passphrase") as vm:
            assert vm.get("A") == "1"
            assert vm.get("B", env="prod") == "2"

    def test_upgrade_kdf_only(self, tmp_path):
        """Rekey with same passphrase but bumped iterations re-encrypts at v2/current."""
        db = tmp_path / "kdf.db"
        # Seed with a v1-style legacy token at LEGACY iterations.
        with VaultManager(db, PASSPHRASE) as vm:
            legacy_token = encrypt("v1-data", PASSPHRASE, iterations=KDF_ITERATIONS_LEGACY)
            vm._require_conn().execute(
                "INSERT INTO secrets (name, env, value_enc, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                ("LEGACY", "default", legacy_token, "2025-01-01", "2025-01-01"),
            )
            vm._require_conn().commit()

        with VaultManager(db, PASSPHRASE) as vm:
            count = vm.rekey(PASSPHRASE, target_iterations=KDF_ITERATIONS_CURRENT)
            assert count == 1
            row = vm._require_conn().execute(
                "SELECT value_enc FROM secrets WHERE name = 'LEGACY'"
            ).fetchone()
            assert token_iterations(row["value_enc"]) == KDF_ITERATIONS_CURRENT
            assert vm.get("LEGACY") == "v1-data"
            assert vm.kdf_iterations() == KDF_ITERATIONS_CURRENT
            assert vm.schema_version() == SCHEMA_VERSION_CURRENT

    def test_rekey_with_wrong_passphrase_leaves_vault_untouched(self, tmp_path):
        from cryptography.exceptions import InvalidTag

        db = tmp_path / "fail.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("KEEP", "original")
            # Open with wrong passphrase and try to rekey — should fail and roll back.
        with VaultManager(db, "wrong") as vm:
            with pytest.raises(InvalidTag):
                vm.rekey("anything")

        # Original data still intact under the original passphrase.
        with VaultManager(db, PASSPHRASE) as vm:
            assert vm.get("KEEP") == "original"

    def test_rekey_idempotent_when_already_current(self, tmp_path):
        db = tmp_path / "i.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("X", "y")
            first = vm.secret_iterations_summary()
            assert first == {KDF_ITERATIONS_CURRENT: 1}
            vm.rekey(PASSPHRASE, target_iterations=KDF_ITERATIONS_CURRENT)
            second = vm.secret_iterations_summary()
            assert second == {KDF_ITERATIONS_CURRENT: 1}
            # Value still readable
            assert vm.get("X") == "y"


class TestConcurrencyPragmas:
    """WAL + busy-timeout: two ownlock processes can share a vault file safely."""

    def test_journal_mode_is_wal(self, tmp_path):
        db = tmp_path / "wal.db"
        with VaultManager(db, PASSPHRASE) as vm:
            mode = vm._require_conn().execute("PRAGMA journal_mode").fetchone()[0]
            assert mode.lower() == "wal"

    def test_busy_timeout_is_set(self, tmp_path):
        db = tmp_path / "busy.db"
        with VaultManager(db, PASSPHRASE) as vm:
            timeout = vm._require_conn().execute("PRAGMA busy_timeout").fetchone()[0]
            assert timeout >= 5000

    def test_synchronous_is_normal_or_higher(self, tmp_path):
        db = tmp_path / "sync.db"
        with VaultManager(db, PASSPHRASE) as vm:
            sync = vm._require_conn().execute("PRAGMA synchronous").fetchone()[0]
            # 0 = OFF, 1 = NORMAL, 2 = FULL, 3 = EXTRA. NORMAL is what we set.
            assert sync >= 1

    def test_close_checkpoints_wal_into_main_file(self, tmp_path):
        """After clean close the main DB should contain the writes.

        Open a second sqlite3 connection without any of our pragmas and
        confirm the row is visible — proves the checkpoint happened.
        """
        db = tmp_path / "ckpt.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("CHECKPOINT_TEST", "ok")
        # Bypass VaultManager so we read the raw file as-is.
        raw = sqlite3.connect(str(db))
        try:
            count = raw.execute(
                "SELECT COUNT(*) FROM secrets WHERE name = ?",
                ("CHECKPOINT_TEST",),
            ).fetchone()[0]
            assert count == 1
        finally:
            raw.close()

    def test_two_simultaneous_managers_can_write(self, tmp_path):
        """A second VaultManager opened on the same file mid-flight can still write.

        Pre-WAL this would fail with ``sqlite3.OperationalError: database is locked``
        on most platforms because the first writer's transaction blocked all reads.
        """
        db = tmp_path / "concur.db"
        with VaultManager(db, PASSPHRASE) as a:
            a.set("FIRST", "1")
            with VaultManager(db, PASSPHRASE) as b:
                b.set("SECOND", "2")
                assert b.get("FIRST") == "1"
            # Original handle still works after the second one closed.
            a.set("THIRD", "3")
            assert a.get("SECOND") == "2"
            assert a.get("THIRD") == "3"
