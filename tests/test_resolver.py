"""Tests for ownlock.resolver — .env parsing and vault() resolution."""

from pathlib import Path
from unittest.mock import patch

import pytest

from ownlock.passphrase import Passphrase
from ownlock.resolver import VaultLookup, resolve_env_file
from ownlock.vault import VaultManager


PASSPHRASE = "test-pass"


@pytest.fixture()
def global_vault(tmp_path):
    """Create a global vault in tmp_path and patch GLOBAL_VAULT_PATH."""
    db = tmp_path / "global" / "vault.db"
    with patch("ownlock.vault.GLOBAL_VAULT_PATH", db):
        with VaultManager(db, PASSPHRASE) as vm:
            yield vm, db


@pytest.fixture()
def project_vault(tmp_path):
    """Create a project vault in tmp_path."""
    db = tmp_path / ".ownlock" / "vault.db"
    vm = VaultManager.init_vault(db, PASSPHRASE)
    yield vm, db
    vm.close()


class TestCollectVaultRefs:
    def test_missing_env_file_returns_empty(self, tmp_path: Path) -> None:
        from ownlock.resolver import collect_vault_refs

        assert collect_vault_refs(tmp_path / "missing.env") == []

    def test_skips_lines_without_equals(self, tmp_path: Path) -> None:
        from ownlock.resolver import collect_vault_refs

        env_file = tmp_path / ".env"
        env_file.write_text("noequals\nKEY=vault(\"A\")\n")
        refs = collect_vault_refs(env_file)
        assert len(refs) == 1
        assert refs[0]["key"] == "A"


class TestResolveEnvFileEdgeCases:
    def test_skips_lines_without_equals(self, tmp_path: Path, global_vault) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("broken-line\nPLAIN=ok\n")
        resolved, _ = resolve_env_file(env_file, PASSPHRASE)
        assert resolved == {"PLAIN": "ok"}


class TestVaultLookupPassphrase:
    def test_close_clears_internal_passphrase_buffer(self) -> None:
        pp = Passphrase.from_str(PASSPHRASE)
        lookup = VaultLookup(pp)
        lookup.close()
        assert bytes(pp.material()) == PASSPHRASE.encode()
        assert not lookup._passphrase


class TestPlainEnv:
    def test_plain_values_pass_through(self, tmp_path, global_vault):
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\nBAZ=123\n")
        resolved, secret_names = resolve_env_file(env_file, PASSPHRASE)
        assert resolved == {"FOO": "bar", "BAZ": "123"}
        assert secret_names == []

    def test_comments_and_empty_lines_skipped(self, tmp_path, global_vault):
        env_file = tmp_path / ".env"
        env_file.write_text("# comment\n\n  \nKEY=val\n")
        resolved, _ = resolve_env_file(env_file, PASSPHRASE)
        assert resolved == {"KEY": "val"}

    def test_nonexistent_env_file_returns_empty(self, tmp_path, global_vault):
        env_file = tmp_path / "nope.env"
        resolved, secret_names = resolve_env_file(env_file, PASSPHRASE)
        assert resolved == {}
        assert secret_names == []


class TestVaultReference:
    def test_vault_ref_uses_project_when_available(self, tmp_path, project_vault, global_vault):
        # Same key in both vaults; project should win when both exist.
        proj_vm, proj_db = project_vault
        proj_vm.set("DB_PASS", "proj-secret")

        glob_vm, _ = global_vault
        glob_vm.set("DB_PASS", "global-secret")

        with patch(
            "ownlock.resolver.VaultManager.find_project_vault",
            return_value=proj_db,
        ):
            env_file = tmp_path / ".env"
            env_file.write_text('DATABASE_URL=vault("DB_PASS")\n')
            resolved, secret_names = resolve_env_file(env_file, PASSPHRASE)
            assert resolved["DATABASE_URL"] == "proj-secret"
            assert "DATABASE_URL" in secret_names

    def test_vault_ref_uses_global_when_no_project_vault(self, tmp_path, global_vault):
        vm, _ = global_vault
        vm.set("DB_PASS", "global-only")

        env_file = tmp_path / ".env"
        env_file.write_text('DATABASE_URL=vault("DB_PASS")\n')

        # Explicitly ensure no project vault is found
        with patch(
            "ownlock.resolver.VaultManager.find_project_vault",
            return_value=None,
        ):
            resolved, secret_names = resolve_env_file(env_file, PASSPHRASE)
        assert resolved["DATABASE_URL"] == "global-only"
        assert "DATABASE_URL" in secret_names

    def test_vault_ref_with_env(self, tmp_path, global_vault):
        vm, _ = global_vault
        vm.set("API_KEY", "prod-key", env="prod")

        env_file = tmp_path / ".env"
        env_file.write_text('API_KEY=vault("API_KEY", env="prod")\n')

        with patch(
            "ownlock.resolver.VaultManager.find_project_vault",
            return_value=None,
        ):
            resolved, _ = resolve_env_file(env_file, PASSPHRASE)
        assert resolved["API_KEY"] == "prod-key"

    def test_vault_ref_project_true_explicit(self, tmp_path, project_vault, global_vault):
        proj_vm, proj_db = project_vault
        proj_vm.set("PROJ_SECRET", "proj-val")

        glob_vm, _ = global_vault
        glob_vm.set("PROJ_SECRET", "global-val")

        with patch(
            "ownlock.resolver.VaultManager.find_project_vault",
            return_value=proj_db,
        ):
            env_file = tmp_path / ".env"
            env_file.write_text('SECRET=vault("PROJ_SECRET", project=true)\n')
            resolved, secret_names = resolve_env_file(env_file, PASSPHRASE)
            assert resolved["SECRET"] == "proj-val"
            assert "SECRET" in secret_names

    def test_vault_ref_global_true_forces_global(self, tmp_path, project_vault, global_vault):
        proj_vm, proj_db = project_vault
        proj_vm.set("PROJ_SECRET", "proj-val")

        glob_vm, _ = global_vault
        glob_vm.set("PROJ_SECRET", "global-val")

        with patch(
            "ownlock.resolver.VaultManager.find_project_vault",
            return_value=proj_db,
        ):
            env_file = tmp_path / ".env"
            env_file.write_text('SECRET=vault("PROJ_SECRET", global=true)\n')
            resolved, secret_names = resolve_env_file(env_file, PASSPHRASE)
            assert resolved["SECRET"] == "global-val"
            assert "SECRET" in secret_names

    def test_invalid_vault_key_raises_keyerror(self, tmp_path, global_vault):
        """vault() with invalid key name (path-like chars) raises KeyError."""
        env_file = tmp_path / ".env"
        env_file.write_text('X=vault("../../etc/passwd")\n')
        with pytest.raises(KeyError) as exc_info:
            resolve_env_file(env_file, PASSPHRASE)
        assert "Invalid secret name" in str(exc_info.value)

    def test_missing_secret_raises_keyerror(self, tmp_path, global_vault):
        env_file = tmp_path / ".env"
        env_file.write_text('KEY=vault("NOPE")\n')
        with pytest.raises(KeyError, match="NOPE"):
            resolve_env_file(env_file, PASSPHRASE)


class TestKwargOrderInVaultRef:
    """vault() kwargs accept any order — env=, project=, global= are interchangeable."""

    def test_project_before_env(self, tmp_path, project_vault, global_vault):
        proj_vm, proj_db = project_vault
        proj_vm.set("KEY", "proj-prod-val", env="production")

        with patch(
            "ownlock.resolver.VaultManager.find_project_vault",
            return_value=proj_db,
        ):
            env_file = tmp_path / ".env"
            env_file.write_text(
                'A=vault("KEY", project=true, env="production")\n'
            )
            resolved, _ = resolve_env_file(env_file, PASSPHRASE)
            assert resolved["A"] == "proj-prod-val"

    def test_global_before_env(self, tmp_path, project_vault, global_vault):
        glob_vm, _ = global_vault
        glob_vm.set("K", "global-stage", env="staging")

        with patch(
            "ownlock.resolver.VaultManager.find_project_vault",
            return_value=None,
        ):
            env_file = tmp_path / ".env"
            env_file.write_text('B=vault("K", global=true, env="staging")\n')
            resolved, _ = resolve_env_file(env_file, PASSPHRASE)
            assert resolved["B"] == "global-stage"

    def test_kwarg_parser_accepts_arbitrary_order(self):
        from ownlock.resolver import parse_vault_kwargs

        a = parse_vault_kwargs('env="prod", project=true')
        b = parse_vault_kwargs('project=true, env="prod"')
        assert a == b == {"env": "prod", "project": "true"}


class TestSecretNames:
    def test_only_vault_resolved_keys_in_secret_names(self, tmp_path, global_vault):
        vm, _ = global_vault
        vm.set("SEC", "hidden")

        env_file = tmp_path / ".env"
        env_file.write_text('PLAIN=hello\nSECRET=vault("SEC")\n')

        with patch(
            "ownlock.resolver.VaultManager.find_project_vault",
            return_value=None,
        ):
            _, secret_names = resolve_env_file(env_file, PASSPHRASE)
        assert secret_names == ["SECRET"]

    def test_inline_values_not_in_secret_names(self, tmp_path, global_vault):
        env_file = tmp_path / ".env"
        env_file.write_text("A=1\nB=2\n")
        _, secret_names = resolve_env_file(env_file, PASSPHRASE)
        assert secret_names == []
