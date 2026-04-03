"""Security-focused tests: path safety, crypto, injection-style inputs, subprocess discipline.

These complement (not replace) SAST, dependency scanning, and professional assessments — see SECURITY_TESTING.md.
"""

from __future__ import annotations

import base64
import io
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from cryptography.exceptions import InvalidTag

from ownlock.cli import _validate_env_file, _validate_scan_dir
from ownlock.crypto import decrypt, encrypt
from ownlock.redactor import SecretRedactor
from ownlock.resolver import resolve_env_file


class TestPathTraversalRelativePaths:
    """OWASP-style path abuse: relative paths must stay under cwd (A01)."""

    def test_env_file_rejects_parent_traversal(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        nested = tmp_path / "proj"
        nested.mkdir()
        monkeypatch.chdir(nested)
        with pytest.raises(typer.Exit):
            _validate_env_file(Path("../outside.env"))

    def test_env_file_accepts_sibling_under_cwd(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        nested = tmp_path / "proj"
        nested.mkdir()
        f = nested / ".env"
        f.write_text("X=1")
        monkeypatch.chdir(nested)
        out = _validate_env_file(Path(".env"))
        assert out == f.resolve()

    def test_scan_dir_rejects_traversal(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        nested = tmp_path / "scan_here"
        nested.mkdir()
        monkeypatch.chdir(nested)
        with pytest.raises(typer.Exit):
            _validate_scan_dir(Path("../etc"))


class TestCryptographicControls:
    """A02: encryption misuse and integrity."""

    def test_decrypt_wrong_passphrase_fails(self) -> None:
        token = encrypt("secret-value", "correct-passphrase")
        with pytest.raises(InvalidTag):
            decrypt(token, "wrong-passphrase")

    def test_tampered_ciphertext_rejected(self) -> None:
        token = encrypt("data", "pw")
        raw = bytearray(base64.b64decode(token))
        raw[-1] ^= 0xFF
        corrupted = base64.b64encode(bytes(raw)).decode("ascii")
        with pytest.raises(InvalidTag):
            decrypt(corrupted, "pw")

    def test_unique_nonces_per_encryption(self) -> None:
        a = encrypt("x", "pw")
        b = encrypt("x", "pw")
        assert a != b


class TestResolverInjectionStyle:
    """vault() references: strict pattern, no arbitrary code (A03)."""

    def test_invalid_vault_key_name_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / ".env"
        bad.write_text('FOO=vault("../../etc", global=true)\n')
        with pytest.raises(KeyError, match="Invalid secret name"):
            resolve_env_file(bad, "pass", env="default")


class TestSubprocessWithoutShell:
    """A03: avoid shell injection — use argv lists."""

    def test_redactor_popen_no_shell(self) -> None:
        with patch("ownlock.redactor.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.stdout = io.StringIO("")
            mock_proc.stderr = io.StringIO("")
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            red = SecretRedactor({})
            red.run_process(["echo", "hi"], {"A": "b"})
            mock_popen.assert_called_once()
            pos, kwargs = mock_popen.call_args
            assert kwargs.get("shell") in (None, False)
            assert pos[0] == ["echo", "hi"]


class TestMcpDelegatesSubprocess:
    """MCP server must not invoke a shell when forwarding to ownlock."""

    def test_run_ownlock_uses_argv_list(self) -> None:
        pytest.importorskip("mcp.server.fastmcp", reason="ownlock[mcp]")
        from ownlock import mcp_server

        with patch("ownlock.mcp_server.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            mcp_server._run_ownlock(["version"])
            mock_run.assert_called_once()
            _args, kwargs = mock_run.call_args
            assert kwargs.get("shell") in (None, False)
            assert isinstance(_args[0], list)
