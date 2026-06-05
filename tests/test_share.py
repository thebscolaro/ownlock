"""Tests for ownlock share / import-share — encrypted bundle round-trip."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ownlock.cli import app
from ownlock.share import export_bundle, import_bundle
from ownlock.vault import VaultManager

PASSPHRASE = "test-pass"
BUNDLE_PP = "bundle-passphrase-y"
runner = CliRunner(env={"OWNLOCK_PASSPHRASE": PASSPHRASE})


@pytest.fixture()
def vault_a(tmp_path, monkeypatch):
    """Source vault with a few seeded secrets."""
    db = tmp_path / "vault_a" / "vault.db"
    with VaultManager(db, PASSPHRASE) as vm:
        vm.set("API_KEY", "ak-source")
        vm.set("DB_URL", "postgres://source", env="default")
        vm.set("PROD_KEY", "prod-source", env="production")
    return db


@pytest.fixture()
def vault_b(tmp_path):
    """Destination vault, initially empty."""
    db = tmp_path / "vault_b" / "vault.db"
    VaultManager.init_vault(db, PASSPHRASE).close()
    return db


class TestBundleAPI:
    def test_round_trip(self):
        secrets = [
            {"name": "K1", "env": "default", "value": "v1"},
            {"name": "K2", "env": "prod", "value": "v2"},
        ]
        bundle = export_bundle(secrets, BUNDLE_PP)
        result = import_bundle(bundle, BUNDLE_PP)
        assert result == secrets

    def test_bundle_missing_secrets_list_raises(self):
        import base64
        import json

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        from ownlock.crypto import derive_key

        good = export_bundle(
            [{"name": "A", "env": "default", "value": "v"}],
            BUNDLE_PP,
        )
        bundle = json.loads(good)
        salt = base64.b64decode(bundle["kdf_salt"])
        nonce = base64.b64decode(bundle["nonce"])
        iterations = int(bundle["kdf_iterations"])
        key = derive_key(BUNDLE_PP, salt, iterations)
        ct = AESGCM(key).encrypt(nonce, json.dumps({"wrong": []}).encode(), None)
        bundle["ciphertext"] = base64.b64encode(ct).decode()
        with pytest.raises(ValueError, match="missing 'secrets' list"):
            import_bundle(json.dumps(bundle), BUNDLE_PP)

    def test_wrong_passphrase_raises(self):
        from cryptography.exceptions import InvalidTag

        bundle = export_bundle([{"name": "X", "env": "default", "value": "y"}], BUNDLE_PP)
        with pytest.raises(InvalidTag):
            import_bundle(bundle, "wrong-pass")

    def test_unicode_values(self):
        secrets = [{"name": "U", "env": "default", "value": "café ☕ 日本語"}]
        bundle = export_bundle(secrets, BUNDLE_PP)
        assert import_bundle(bundle, BUNDLE_PP) == secrets

    def test_unsupported_version_rejected(self):
        import json

        bundle = json.loads(export_bundle([], BUNDLE_PP))
        bundle["ownlock_bundle_version"] = 99
        with pytest.raises(ValueError, match="Unsupported"):
            import_bundle(json.dumps(bundle), BUNDLE_PP)

    def test_invalid_json_rejected(self):
        with pytest.raises(ValueError, match="not valid JSON"):
            import_bundle("not-json", BUNDLE_PP)

    def test_non_object_json_rejected(self):
        with pytest.raises(ValueError, match="JSON object"):
            import_bundle("[1, 2]", BUNDLE_PP)

    def test_missing_required_field_rejected(self):
        import json

        bundle = json.loads(export_bundle([], BUNDLE_PP))
        del bundle["kdf_salt"]
        with pytest.raises(ValueError, match="missing required"):
            import_bundle(json.dumps(bundle), BUNDLE_PP)

    def test_malformed_secret_entry_rejected(self):
        import base64
        import json
        import os

        from ownlock.crypto import KDF_ITERATIONS_CURRENT, NONCE_LEN, SALT_LEN, derive_key
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        salt = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        key = derive_key(BUNDLE_PP, salt, KDF_ITERATIONS_CURRENT)
        payload = json.dumps({"secrets": [{"name": "X"}]}).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, payload, None)
        bundle = {
            "ownlock_bundle_version": 1,
            "kdf": "PBKDF2-HMAC-SHA256",
            "kdf_iterations": KDF_ITERATIONS_CURRENT,
            "kdf_salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with pytest.raises(ValueError, match="malformed secret"):
            import_bundle(json.dumps(bundle), BUNDLE_PP)


class TestShareCLI:
    def test_share_then_import_round_trip(self, tmp_path, vault_a, vault_b, monkeypatch):
        bundle_path = tmp_path / "bundle.olbundle"

        # Two devs simulated via two vault paths and two HOMEs.
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setenv("OWNLOCK_BUNDLE_PASSPHRASE", BUNDLE_PP)
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault_a,
        )
        monkeypatch.setattr(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: None),
        )

        result = runner.invoke(app, ["share", "-o", str(bundle_path), "--yes"])
        assert result.exit_code == 0, result.output
        assert bundle_path.exists()

        # Switch to the other vault and import.
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault_b,
        )
        result = runner.invoke(app, ["import-share", str(bundle_path)])
        assert result.exit_code == 0, result.output
        assert "Imported 3" in result.output

        with VaultManager(vault_b, PASSPHRASE) as vm:
            assert vm.get("API_KEY") == "ak-source"
            assert vm.get("DB_URL") == "postgres://source"
            assert vm.get("PROD_KEY", env="production") == "prod-source"

    def test_share_subset_by_name(self, tmp_path, vault_a, monkeypatch):
        bundle_path = tmp_path / "subset.olbundle"
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setenv("OWNLOCK_BUNDLE_PASSPHRASE", BUNDLE_PP)
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault_a,
        )

        result = runner.invoke(
            app, ["share", "API_KEY", "-o", str(bundle_path), "--yes"]
        )
        assert result.exit_code == 0, result.output
        secrets = import_bundle(bundle_path.read_text(), BUNDLE_PP)
        names = sorted(s["name"] for s in secrets)
        assert names == ["API_KEY"]

    def test_import_refuses_to_overwrite_without_flag(
        self, tmp_path, vault_a, vault_b, monkeypatch
    ):
        bundle_path = tmp_path / "b.olbundle"
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setenv("OWNLOCK_BUNDLE_PASSPHRASE", BUNDLE_PP)

        # Pre-populate vault_b with a conflicting key.
        with VaultManager(vault_b, PASSPHRASE) as vm:
            vm.set("API_KEY", "existing-other-value")

        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault_a,
        )
        runner.invoke(app, ["share", "-o", str(bundle_path), "--yes"])

        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault_b,
        )
        # Force non-TTY so it exits 1 instead of prompting.
        monkeypatch.setattr("ownlock.cli._is_tty", lambda: False)
        result = runner.invoke(app, ["import-share", str(bundle_path)])
        assert result.exit_code == 1
        with VaultManager(vault_b, PASSPHRASE) as vm:
            assert vm.get("API_KEY") == "existing-other-value"  # untouched

    def test_import_with_overwrite_succeeds(
        self, tmp_path, vault_a, vault_b, monkeypatch
    ):
        bundle_path = tmp_path / "b.olbundle"
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setenv("OWNLOCK_BUNDLE_PASSPHRASE", BUNDLE_PP)

        with VaultManager(vault_b, PASSPHRASE) as vm:
            vm.set("API_KEY", "existing-other-value")

        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault_a,
        )
        runner.invoke(app, ["share", "-o", str(bundle_path), "--yes"])

        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault_b,
        )
        result = runner.invoke(
            app, ["import-share", str(bundle_path), "--overwrite", "--yes"]
        )
        assert result.exit_code == 0, result.output
        with VaultManager(vault_b, PASSPHRASE) as vm:
            assert vm.get("API_KEY") == "ak-source"

    def test_import_wrong_passphrase_clean_error(self, tmp_path, vault_a, vault_b, monkeypatch):
        bundle_path = tmp_path / "b.olbundle"
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
        monkeypatch.setenv("OWNLOCK_BUNDLE_PASSPHRASE", BUNDLE_PP)

        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault_a,
        )
        runner.invoke(app, ["share", "-o", str(bundle_path), "--yes"])

        monkeypatch.setenv("OWNLOCK_BUNDLE_PASSPHRASE", "wrong")
        monkeypatch.setattr(
            "ownlock.cli._resolve_vault_path",
            lambda global_vault=False, project=False: vault_b,
        )
        result = runner.invoke(app, ["import-share", str(bundle_path)])
        assert result.exit_code == 1
        assert "wrong passphrase" in result.output.lower()
        # Destination vault unchanged.
        with VaultManager(vault_b, PASSPHRASE) as vm:
            assert vm.list_secrets() == []
