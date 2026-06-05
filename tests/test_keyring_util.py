"""Tests for ownlock.keyring_util — passphrase resolution and keyring helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ownlock import keyring_util
from ownlock.keyring_util import passphrase_session, prompt_passphrase_session


def _passphrase_text(pp) -> str:
    return bytes(pp.material()).decode()


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


class TestKeyringHasPassphrase:
    def test_true_when_stored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with patch.object(keyring_util, "get_passphrase", return_value="stored"):
            assert keyring_util.keyring_has_passphrase() is True

    def test_false_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with patch.object(keyring_util, "get_passphrase", return_value=None):
            assert keyring_util.keyring_has_passphrase() is False

    def test_scrubs_keyring_str_ref(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with patch.object(keyring_util, "get_passphrase", return_value="secret"):
            with patch.object(keyring_util.gc, "collect") as mock_gc:
                assert keyring_util.keyring_has_passphrase() is True
                mock_gc.assert_called_once()


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
        pp = keyring_util.resolve_passphrase(prompt=False)
        assert _passphrase_text(pp) == "from-env"

    def test_env_var_removed_from_process_after_session(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", "from-env")
        with passphrase_session(prompt=False):
            pass
        assert "OWNLOCK_PASSPHRASE" not in __import__("os").environ

    def test_env_var_arg_does_not_unset_ownlock_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
        pp = keyring_util.resolve_passphrase("from-arg", prompt=False)
        assert _passphrase_text(pp) == "from-arg"
        assert "OWNLOCK_PASSPHRASE" not in __import__("os").environ

    def test_keyring_when_no_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
        with patch.object(keyring_util, "get_passphrase", return_value="from-kr"):
            pp = keyring_util.resolve_passphrase(prompt=False)
            assert _passphrase_text(pp) == "from-kr"

    def test_getpass_when_prompt_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
        with patch.object(keyring_util, "get_passphrase", return_value=None):
            with patch(
                "ownlock.keyring_util.getpass.getpass",
                return_value="typed",
            ):
                pp = keyring_util.resolve_passphrase(prompt=True)
                assert _passphrase_text(pp) == "typed"

    def test_returns_wipeable_buffer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", "wipe-test")
        pp = keyring_util.resolve_passphrase(prompt=False)
        assert bytes(pp.material()) == b"wipe-test"
        pp.clear()
        assert not pp

    def test_passphrase_session_clears_on_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", "session-test")
        with passphrase_session(prompt=False) as pp:
            assert bytes(pp.material()) == b"session-test"
        assert not pp

    def test_passphrase_session_collects_after_clear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", "gc-test")
        with patch.object(keyring_util.gc, "collect") as mock_gc:
            with passphrase_session(prompt=False):
                pass
            assert mock_gc.call_count >= 1

    def test_prompt_passphrase_session_clears_on_exit(self) -> None:
        with prompt_passphrase_session("prompted") as pp:
            assert bytes(pp.material()) == b"prompted"
        assert not pp

    def test_passphrase_session_clears_on_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", "boom")
        pp_ref = None
        with pytest.raises(RuntimeError):
            with passphrase_session(prompt=False) as pp:
                pp_ref = pp
                raise RuntimeError("fail")
        assert pp_ref is not None
        assert not pp_ref

    def test_raises_when_nothing_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)
        with patch.object(keyring_util, "get_passphrase", return_value=None):
            with pytest.raises(ValueError, match="No vault passphrase"):
                keyring_util.resolve_passphrase(prompt=False)
