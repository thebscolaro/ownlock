"""Tests for ownlock.keyring_util — passphrase resolution and keyring helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ownlock import keyring_util


class TestStorePassphrase:
    def test_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_kr = MagicMock()
        monkeypatch.setitem(
            __import__("sys").modules,
            "keyring",
            mock_kr,
        )
        ok, err = keyring_util.store_passphrase("secret")
        assert ok is True
        assert err is None
        mock_kr.set_password.assert_called_once_with(
            keyring_util.SERVICE_NAME, keyring_util.ACCOUNT_NAME, "secret"
        )

    def test_failure_returns_message(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_kr = MagicMock()
        mock_kr.set_password.side_effect = RuntimeError("keyring unavailable")
        monkeypatch.setitem(__import__("sys").modules, "keyring", mock_kr)
        ok, err = keyring_util.store_passphrase("secret")
        assert ok is False
        assert "keyring unavailable" in err


class TestGetPassphrase:
    def test_returns_stored_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_kr = MagicMock()
        mock_kr.get_password.return_value = "from-keyring"
        monkeypatch.setitem(__import__("sys").modules, "keyring", mock_kr)
        assert keyring_util.get_passphrase() == "from-keyring"

    def test_returns_none_on_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_kr = MagicMock()
        mock_kr.get_password.side_effect = RuntimeError("no backend")
        monkeypatch.setitem(__import__("sys").modules, "keyring", mock_kr)
        assert keyring_util.get_passphrase() is None


class TestDeletePassphrase:
    def test_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_kr = MagicMock()
        monkeypatch.setitem(__import__("sys").modules, "keyring", mock_kr)
        assert keyring_util.delete_passphrase() is True

    def test_failure_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_kr = MagicMock()
        mock_kr.delete_password.side_effect = RuntimeError("missing")
        monkeypatch.setitem(__import__("sys").modules, "keyring", mock_kr)
        assert keyring_util.delete_passphrase() is False


class TestResolvePassphrase:
    def test_env_var_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", "from-env")
        assert keyring_util.resolve_passphrase(prompt=False) == "from-env"

    def test_keyring_when_no_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
        with patch.object(keyring_util, "get_passphrase", return_value="from-kr"):
            assert keyring_util.resolve_passphrase(prompt=False) == "from-kr"

    def test_getpass_when_prompt_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
        with patch.object(keyring_util, "get_passphrase", return_value=None):
            with patch(
                "ownlock.keyring_util.getpass.getpass",
                return_value="typed",
            ):
                assert keyring_util.resolve_passphrase(prompt=True) == "typed"

    def test_raises_when_nothing_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
        with patch.object(keyring_util, "get_passphrase", return_value=None):
            with pytest.raises(ValueError, match="No vault passphrase"):
                keyring_util.resolve_passphrase(prompt=False)
