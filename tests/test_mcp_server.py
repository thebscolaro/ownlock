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
