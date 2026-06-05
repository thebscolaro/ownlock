"""Tests for ownlock.vault — SQLite-backed encrypted secret storage."""

import sqlite3
from pathlib import Path

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


class _ConnExecuteProxy:
    """Delegate to a real sqlite3 connection but override ``execute``."""

    def __init__(self, conn: sqlite3.Connection, handler) -> None:
        object.__setattr__(self, "_conn", conn)
        object.__setattr__(self, "_handler", handler)

    def execute(self, sql, parameters=(), /, *args, **kwargs):
        return self._handler(self._conn, sql, parameters, *args, **kwargs)

    def __getattr__(self, name: str):
        return getattr(self._conn, name)

    def __setattr__(self, name: str, value) -> None:
        if name in ("_conn", "_handler"):
            object.__setattr__(self, name, value)
        else:
            setattr(self._conn, name, value)


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
            # Opening a legacy vault infers v1 KDF meta, then auto-migrates names
            # to schema v3 on first open with the passphrase.
            assert vm.schema_version() == SCHEMA_VERSION_CURRENT
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
            assert vm.schema_version() == SCHEMA_VERSION_CURRENT

    def test_set_writes_v2_token(self, tmp_path):
        db = tmp_path / "v2.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("KEY", "value")
            row = vm._require_conn().execute(
                "SELECT value_enc FROM secrets LIMIT 1"
            ).fetchone()
            assert token_iterations(row["value_enc"]) == KDF_ITERATIONS_CURRENT

    def test_secret_names_not_stored_in_plaintext(self, tmp_path):
        """Schema v3: copying vault.db without the passphrase hides key names."""
        db = tmp_path / "hidden.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("API_KEY", "super-secret-value-long")

        raw = db.read_bytes()
        assert b"API_KEY" not in raw
        assert b"super-secret-value-long" not in raw

        with VaultManager(db, PASSPHRASE) as vm:
            assert vm.get("API_KEY") == "super-secret-value-long"


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

        # Old passphrase no longer resolves rows (lookup ids are passphrase-bound).
        with VaultManager(db, PASSPHRASE) as vm:
            assert vm.get("A") is None
            assert vm.get("B", env="prod") is None

        # New passphrase reads everything.
        with VaultManager(db, "new-passphrase") as vm:
            assert vm.get("A") == "1"
            assert vm.get("B", env="prod") == "2"

    def test_upgrade_kdf_only(self, tmp_path):
        """Rekey with same passphrase but bumped iterations re-encrypts at v2/current."""
        from ownlock.crypto import secret_name_lookup

        db = tmp_path / "kdf.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("LEGACY", "v1-data")
            lookup = secret_name_lookup(PASSPHRASE, "LEGACY", "default")
            legacy_token = encrypt("v1-data", PASSPHRASE, iterations=KDF_ITERATIONS_LEGACY)
            vm._require_conn().execute(
                "UPDATE secrets SET value_enc = ? WHERE name_lookup = ?",
                (legacy_token, lookup),
            )
            vm._require_conn().commit()

        with VaultManager(db, PASSPHRASE) as vm:
            count = vm.rekey(PASSPHRASE, target_iterations=KDF_ITERATIONS_CURRENT)
            assert count == 1
            row = vm._require_conn().execute(
                "SELECT value_enc FROM secrets LIMIT 1"
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
            count = raw.execute("SELECT COUNT(*) FROM secrets").fetchone()[0]
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

    def test_vault_db_created_with_mode_0600_on_posix(self, tmp_path):
        import os

        if os.name != "posix":
            pytest.skip("POSIX file modes only")
        db = tmp_path / "perms.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("K", "v")
        assert db.stat().st_mode & 0o777 == 0o600


class TestSqlInjectionResistance:
    """Secret names and envs are bound as parameters, never interpolated into SQL."""

    PAYLOADS = [
        "'; DROP TABLE secrets; --",
        "1 OR 1=1",
        "name' UNION SELECT value_enc FROM secrets --",
        '"; DELETE FROM secrets; --',
        "x\0y",
    ]

    def test_set_get_delete_with_sql_metacharacters_in_name(self, tmp_path):
        db = tmp_path / "inj.db"
        for payload in self.PAYLOADS:
            with VaultManager(db, PASSPHRASE) as vm:
                vm.set(payload, "secret-value")
                assert vm.get(payload) == "secret-value"
                assert vm.delete(payload) is True
                assert vm.get(payload) is None
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("still_here", "ok")
            assert vm.get("still_here") == "ok"

    def test_list_and_get_all_with_sql_metacharacters_in_env(self, tmp_path):
        db = tmp_path / "env_inj.db"
        evil_env = "prod'; DROP TABLE secrets; --"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("KEY", "v", env=evil_env)
            assert vm.get("KEY", env=evil_env) == "v"
            assert len(vm.list_secrets(env=evil_env)) == 1
            assert vm.get_all_decrypted(env=evil_env) == {"KEY": "v"}


class TestVaultEdgeCases:
    def test_require_conn_before_open_raises(self, tmp_path):
        vm = VaultManager(tmp_path / "closed.db", PASSPHRASE)
        with pytest.raises(RuntimeError, match="not open"):
            vm.get("K")

    def test_secret_iterations_summary_skips_corrupt_tokens(self, tmp_path):
        db = tmp_path / "corrupt.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("OK", "v")
            vm._require_conn().execute(
                "UPDATE secrets SET value_enc = ?",
                ("not-a-valid-token",),
            )
            vm._require_conn().commit()
            assert vm.secret_iterations_summary() == {}

    def test_recreates_secrets_table_with_unexpected_shape(self, tmp_path):
        """Pre-v3 file with a broken ``secrets`` table is rebuilt on open."""
        db = tmp_path / "weird.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE secrets (foo TEXT NOT NULL)")
        conn.commit()
        conn.close()

        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("A", "1")
            assert vm.get("A") == "1"
            assert "name_lookup" in vm._secrets_columns()


class TestPassphraseMemory:
    def test_close_clears_passphrase_buffer(self, tmp_path):
        db = tmp_path / "wipe.db"
        vm = VaultManager(db, PASSPHRASE)
        vm.open()
        vm.set("K", "v")
        vm.close()
        assert not vm._passphrase

    def test_context_manager_clears_passphrase(self, tmp_path):
        db = tmp_path / "ctx_wipe.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("K", "v")
            assert bytes(vm._passphrase.material()) == PASSPHRASE.encode()
        assert not vm._passphrase


class TestDefensivePaths:
    def test_db_path_property(self, tmp_path):
        db = tmp_path / "prop.db"
        vm = VaultManager(db, PASSPHRASE)
        assert vm.db_path == db

    def test_apply_concurrency_pragmas_without_open_conn(self, tmp_path):
        vm = VaultManager(tmp_path / "pragma.db", PASSPHRASE)
        vm._apply_concurrency_pragmas()

    def test_open_continues_when_chmod_raises(self, tmp_path, monkeypatch):
        import os

        db = tmp_path / "chmod.db"
        monkeypatch.setattr(os, "chmod", lambda *a, **k: (_ for _ in ()).throw(OSError(1, "chmod")))
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("K", "v")
            assert vm.get("K") == "v"

    def test_close_ignores_wal_checkpoint_failure(self, tmp_path, monkeypatch):
        db = tmp_path / "ckpt_fail.db"
        real_connect = sqlite3.connect

        def connect(*args, **kwargs):
            conn = real_connect(*args, **kwargs)

            def execute(inner, sql, parameters=(), /, *a, **k):
                if isinstance(sql, str) and "wal_checkpoint" in sql:
                    raise sqlite3.DatabaseError("busy")
                return inner.execute(sql, parameters, *a, **k)

            return _ConnExecuteProxy(conn, execute)

        monkeypatch.setattr(sqlite3, "connect", connect)
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("K", "v")
        with VaultManager(db, PASSPHRASE) as vm2:
            assert vm2.get("K") == "v"

    def test_rekey_rolls_back_when_update_fails(self, tmp_path, monkeypatch):
        db = tmp_path / "rekey_rb.db"
        real_connect = sqlite3.connect
        update_calls = 0

        def connect(*args, **kwargs):
            conn = real_connect(*args, **kwargs)

            def execute(inner, sql, parameters=(), /, *a, **k):
                nonlocal update_calls
                if isinstance(sql, str) and "UPDATE secrets" in sql:
                    update_calls += 1
                    if update_calls >= 2:
                        raise RuntimeError("simulated update failure")
                return inner.execute(sql, parameters, *a, **k)

            return _ConnExecuteProxy(conn, execute)

        monkeypatch.setattr(sqlite3, "connect", connect)
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("A", "1")
            vm.set("B", "2")
            with pytest.raises(RuntimeError, match="simulated"):
                vm.rekey("new-passphrase")
            assert vm.get("A") == "1"
            assert vm.get("B") == "2"
            assert bytes(vm._passphrase.material()) == PASSPHRASE.encode()


class TestFindProjectVault:
    def test_does_not_treat_global_vault_as_project(self, tmp_path, monkeypatch):
        """Walking up to $HOME must not return ~/.ownlock/vault.db as a project vault."""
        from ownlock import vault as vault_module

        global_vault = tmp_path / "home" / ".ownlock" / "vault.db"
        global_vault.parent.mkdir(parents=True)
        VaultManager.init_vault(global_vault, PASSPHRASE).close()
        monkeypatch.setattr(vault_module, "GLOBAL_VAULT_PATH", global_vault)

        repo = tmp_path / "code" / "myapp"
        repo.mkdir(parents=True)
        monkeypatch.chdir(repo)

        assert VaultManager.find_project_vault() is None

    def test_finds_real_project_vault_above_cwd(self, tmp_path, monkeypatch):
        project_vault = tmp_path / "repo" / ".ownlock" / "vault.db"
        VaultManager.init_vault(project_vault, PASSPHRASE).close()
        subdir = tmp_path / "repo" / "pkg" / "inner"
        subdir.mkdir(parents=True)
        monkeypatch.chdir(subdir)

        assert VaultManager.find_project_vault() == project_vault

    def test_global_resolve_oserror_uses_unresolved_path(self, tmp_path, monkeypatch):
        from ownlock import vault as vault_module

        global_vault = tmp_path / "home" / ".ownlock" / "vault.db"
        global_vault.parent.mkdir(parents=True)
        VaultManager.init_vault(global_vault, PASSPHRASE).close()
        monkeypatch.setattr(vault_module, "GLOBAL_VAULT_PATH", global_vault)

        project_vault = tmp_path / "repo" / ".ownlock" / "vault.db"
        VaultManager.init_vault(project_vault, PASSPHRASE).close()
        subdir = tmp_path / "repo" / "pkg"
        subdir.mkdir(parents=True)
        monkeypatch.chdir(subdir)

        real_resolve = Path.resolve

        def resolve(self):
            if self == global_vault:
                raise OSError("resolve failed")
            return real_resolve(self)

        monkeypatch.setattr(Path, "resolve", resolve)
        assert VaultManager.find_project_vault() == project_vault

    def test_skips_global_candidate_when_resolve_raises(self, tmp_path, monkeypatch):
        from ownlock import vault as vault_module

        global_vault = tmp_path / "home" / ".ownlock" / "vault.db"
        global_vault.parent.mkdir(parents=True)
        VaultManager.init_vault(global_vault, PASSPHRASE).close()
        monkeypatch.setattr(vault_module, "GLOBAL_VAULT_PATH", global_vault)

        work = tmp_path / "home" / "myapp"
        work.mkdir(parents=True)
        monkeypatch.chdir(work)

        monkeypatch.setattr(Path, "resolve", lambda self: (_ for _ in ()).throw(OSError(1)))
        assert VaultManager.find_project_vault() is None
