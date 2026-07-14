"""Tests for per-secret access policies."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from ownlock.policy import (
    POLICY_CONFIRM,
    POLICY_OPEN,
    POLICY_SESSION,
    check_policy_access,
    clear_session_cache,
    is_session_unlocked,
    normalize_policy,
    unlock_session,
)


def test_normalize_policy_defaults():
    assert normalize_policy(None) == POLICY_OPEN
    assert normalize_policy("bogus") == POLICY_OPEN


def test_normalize_policy_strict():
    assert normalize_policy(None) == POLICY_OPEN
    with pytest.raises(ValueError):
        normalize_policy(None, strict=True)
    with pytest.raises(ValueError, match="Invalid policy"):
        normalize_policy("bogus", strict=True)
    assert normalize_policy("confirm", strict=True) == POLICY_CONFIRM


def test_session_policy_unlock(tmp_path, monkeypatch):
    monkeypatch.setenv("OWNLOCK_SESSION_STORE", str(tmp_path / "session.json"))
    clear_session_cache()
    assert not is_session_unlocked("k", "default")
    unlock_session("k", "default")
    assert is_session_unlocked("k", "default")


def test_session_unlock_persists_across_clear_process_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("OWNLOCK_SESSION_STORE", str(tmp_path / "session.json"))
    clear_session_cache()
    unlock_session("k", "default")
    from ownlock import policy as policy_mod

    policy_mod._session_unlocked.clear()
    assert is_session_unlocked("k", "default")


def test_open_policy_always_allows():
    assert check_policy_access("k", "default", POLICY_OPEN, is_tty=False)


def test_session_policy_denies_non_tty(tmp_path, monkeypatch):
    monkeypatch.setenv("OWNLOCK_SESSION_STORE", str(tmp_path / "session.json"))
    clear_session_cache()
    with pytest.raises(PermissionError):
        check_policy_access("k", "default", POLICY_SESSION, is_tty=False)


def test_confirm_policy_denies_non_tty():
    with pytest.raises(PermissionError):
        check_policy_access("k", "default", POLICY_CONFIRM, is_tty=False)


def test_session_policy_tty_confirm(tmp_path, monkeypatch):
    monkeypatch.setenv("OWNLOCK_SESSION_STORE", str(tmp_path / "session.json"))
    clear_session_cache()
    with patch("typer.confirm", return_value=True) as confirm:
        assert check_policy_access("k", "default", POLICY_SESSION, is_tty=True)
        assert confirm.call_args.kwargs.get("default") is False
    assert is_session_unlocked("k", "default")


def test_confirm_policy_default_declines():
    with patch("typer.confirm", return_value=False) as confirm:
        assert not check_policy_access("k", "default", POLICY_CONFIRM, is_tty=True)
        assert confirm.call_args.kwargs.get("default") is False


def test_session_store_ignores_corrupt_and_expired(tmp_path, monkeypatch):
    store = tmp_path / "session.json"
    monkeypatch.setenv("OWNLOCK_SESSION_STORE", str(store))
    clear_session_cache()
    store.write_text("{not-json", encoding="utf-8")
    assert not is_session_unlocked("k", "default")

    store.write_text('{"default\\u0000k": 1}', encoding="utf-8")  # expired wall time
    assert not is_session_unlocked("k", "default")


def test_clear_session_cache_removes_store_file(tmp_path, monkeypatch):
    store = tmp_path / "session.json"
    monkeypatch.setenv("OWNLOCK_SESSION_STORE", str(store))
    clear_session_cache()
    unlock_session("k", "default")
    assert store.exists()
    clear_session_cache()
    assert not store.exists()


def test_session_reason_included_in_prompt(tmp_path, monkeypatch):
    monkeypatch.setenv("OWNLOCK_SESSION_STORE", str(tmp_path / "s.json"))
    clear_session_cache()
    with patch("typer.confirm", return_value=False) as confirm:
        assert not check_policy_access(
            "k", "default", POLICY_SESSION, reason="mcp", is_tty=True
        )
        assert "mcp" in confirm.call_args.args[0]
