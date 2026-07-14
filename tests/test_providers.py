"""Tests for external secret provider bridges."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ownlock.providers import resolve_external_secret


def test_unknown_scheme():
    with pytest.raises(KeyError):
        resolve_external_secret("vault://nope")


def test_op_resolve(monkeypatch):
    proc = MagicMock(returncode=0, stdout="sekret\n", stderr="")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/op")
    with patch("ownlock.providers.subprocess.run", return_value=proc):
        assert resolve_external_secret("op://vault/item/field") == "sekret"


def test_aws_sm_resolve(monkeypatch):
    proc = MagicMock(
        returncode=0,
        stdout='{"SecretString": "{\\"key\\": \\"val\\"}"}',
        stderr="",
    )
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/aws")
    with patch("ownlock.providers.subprocess.run", return_value=proc):
        assert resolve_external_secret("aws-sm://my-secret#key") == "val"


def test_aws_sm_secret_binary(monkeypatch):
    import base64

    raw = base64.b64encode(b"bin-secret").decode("ascii")
    proc = MagicMock(
        returncode=0,
        stdout=f'{{"SecretString": "", "SecretBinary": "{raw}"}}',
        stderr="",
    )
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/aws")
    with patch("ownlock.providers.subprocess.run", return_value=proc):
        assert resolve_external_secret("aws-sm://bin-id") == "bin-secret"


def test_az_kv_resolve(monkeypatch):
    proc = MagicMock(returncode=0, stdout="azure-secret\n", stderr="")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/az")
    with patch("ownlock.providers.subprocess.run", return_value=proc) as run:
        assert resolve_external_secret("az-kv://myvault/db-pass") == "azure-secret"
        args = run.call_args[0][0]
        assert args[:4] == ["/usr/bin/az", "keyvault", "secret", "show"]
        assert "--vault-name" in args and "myvault" in args
        assert "--name" in args and "db-pass" in args


def test_azure_kv_alias_json_key(monkeypatch):
    proc = MagicMock(returncode=0, stdout='{"password": "p@ss"}\n', stderr="")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/az")
    with patch("ownlock.providers.subprocess.run", return_value=proc):
        assert resolve_external_secret("azure-kv://kv/app#password") == "p@ss"


def test_az_kv_bad_path(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/az")
    with pytest.raises(KeyError, match="vault-name"):
        resolve_external_secret("az-kv://only-vault")


def test_az_kv_missing_cli(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(KeyError, match="Azure CLI"):
        resolve_external_secret("az-kv://v/s")


def test_op_missing_cli(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(KeyError, match="1Password"):
        resolve_external_secret("op://v/i/f")


def test_op_cli_failure(monkeypatch):
    proc = MagicMock(returncode=1, stdout="", stderr="not signed in")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/op")
    with patch("ownlock.providers.subprocess.run", return_value=proc):
        with pytest.raises(KeyError, match="op read failed"):
            resolve_external_secret("op://v/i/f")


def test_aws_missing_cli(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(KeyError, match="AWS CLI"):
        resolve_external_secret("aws-sm://id")


def test_aws_cli_failure(monkeypatch):
    proc = MagicMock(returncode=1, stdout="", stderr="AccessDenied")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/aws")
    with patch("ownlock.providers.subprocess.run", return_value=proc):
        with pytest.raises(KeyError, match="aws secretsmanager"):
            resolve_external_secret("aws-sm://id")


def test_aws_empty_secret(monkeypatch):
    proc = MagicMock(
        returncode=0,
        stdout='{"SecretString": "", "SecretBinary": null}',
        stderr="",
    )
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/aws")
    with patch("ownlock.providers.subprocess.run", return_value=proc):
        with pytest.raises(KeyError, match="empty"):
            resolve_external_secret("aws-sm://id")


def test_maybe_json_key_missing(monkeypatch):
    proc = MagicMock(returncode=0, stdout='{"SecretString": "{\\"a\\": 1}"}', stderr="")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/aws")
    with patch("ownlock.providers.subprocess.run", return_value=proc):
        with pytest.raises(KeyError, match="not in"):
            resolve_external_secret("aws-sm://id#missing")
