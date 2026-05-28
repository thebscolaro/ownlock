"""Tests for ownlock MCP server (subprocess delegation, no vault in process)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("mcp.server.fastmcp", reason="install ownlock[mcp] for MCP tests")

from ownlock import mcp_server


@pytest.fixture
def mock_run() -> MagicMock:
    with patch.object(mcp_server, "_run_ownlock") as m:
        yield m


def test_ownlock_run_builds_args_and_returns_truncated_io(mock_run: MagicMock) -> None:
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="ok\n",
        stderr="",
    )
    out = mcp_server.ownlock_run(
        command=["python", "-c", "print(1)"],
        cwd="/tmp",
        env_file=".env.local",
        vault_env="production",
    )
    assert out["exit_code"] == 0
    assert out["stdout"] == "ok\n"
    mock_run.assert_called_once()
    call_args = mock_run.call_args
    assert call_args[0][0] == [
        "run",
        "-f",
        ".env.local",
        "-e",
        "production",
        "--",
        "python",
        "-c",
        "print(1)",
    ]


def test_ownlock_run_empty_command(mock_run: MagicMock) -> None:
    out = mcp_server.ownlock_run(command=[])
    assert out["exit_code"] == 1
    mock_run.assert_not_called()


def test_ownlock_list_secret_names_on_failure(mock_run: MagicMock) -> None:
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="no vault")
    text = mcp_server.ownlock_list_secret_names()
    assert "no vault" in text


def test_ownlock_list_secret_names_passes_flags(mock_run: MagicMock) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout="Name  Env\n", stderr="")
    mcp_server.ownlock_list_secret_names(env="staging", global_vault=True)
    args = mock_run.call_args[0][0]
    assert args == ["list", "--env", "staging", "--global"]


def test_ownlock_version() -> None:
    v = mcp_server.ownlock_version()
    assert v and len(v) >= 3


def test_ownlock_doctor_returns_parsed_json(mock_run: MagicMock) -> None:
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout='{"ownlock_version": "0.2.0", "global_vault": {"exists": true}}',
        stderr="",
    )
    out = mcp_server.ownlock_doctor()
    assert out["ownlock_version"] == "0.2.0"
    assert out["global_vault"]["exists"] is True
    assert mock_run.call_args[0][0] == ["doctor", "--json"]


def test_ownlock_doctor_handles_failure(mock_run: MagicMock) -> None:
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="oh no")
    out = mcp_server.ownlock_doctor()
    assert "error" in out
    assert "oh no" in out["stderr"]


def test_ownlock_status_combines_doctor_and_list(mock_run: MagicMock) -> None:
    list_json = '[{"name": "A", "env": "default"}, {"name": "B", "env": "prod"}]'
    doctor_json = (
        '{"global_vault": {"path": "/g/v.db", "exists": true, '
        '"schema_version": 2, "kdf_iterations": 600000, "kdf_stale": false}, '
        '"project_vault": {"path": null, "exists": false}, '
        '"passphrase_source": "env var"}'
    )
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout=list_json, stderr=""),
        MagicMock(returncode=0, stdout=doctor_json, stderr=""),
    ]
    out = mcp_server.ownlock_status()
    assert out["secret_count"] == 2
    assert out["environments"] == ["default", "prod"]
    assert out["passphrase_source"] == "env var"
    assert out["kdf_stale"] is False
    assert out["selected_vault"] == "global"


def test_ownlock_doctor_does_not_decrypt() -> None:
    """Sanity check: ``ownlock_doctor`` only ever invokes the CLI subprocess."""
    with patch.object(mcp_server, "_run_ownlock") as mock:
        mock.return_value = MagicMock(returncode=0, stdout="{}", stderr="")
        mcp_server.ownlock_doctor()
        # Must call subprocess, never crypto/vault directly.
        assert mock.called
        assert mock.call_args[0][0][0] == "doctor"
