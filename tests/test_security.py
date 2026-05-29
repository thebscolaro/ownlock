"""Security-focused tests: path safety, crypto, injection-style inputs, subprocess discipline.

These complement (not replace) SAST, dependency scanning, and professional assessments — see SECURITY_TESTING.md.
"""

from __future__ import annotations

import base64
import io
import shutil
import sys
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
            ca = mock_popen.call_args
            cmd = ca.args[0]
            kwargs = ca.kwargs
            assert kwargs.get("shell") in (None, False)
            assert isinstance(cmd, list)
            assert cmd[1:] == ["hi"]
            merged_path = kwargs["env"].get("PATH")
            if sys.platform == "win32":
                resolved = shutil.which("echo", path=merged_path)
                assert cmd[0] == (resolved if resolved else "echo")
            else:
                assert cmd == ["echo", "hi"]


class TestPassphraseNotInheritedByChild:
    """OWNLOCK_PASSPHRASE must never reach a child process spawned by run."""

    def test_passphrase_stripped_from_child_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OWNLOCK_PASSPHRASE", "super-secret-passphrase")
        monkeypatch.setenv("OWNLOCK_NEW_PASSPHRASE", "rotation-target")
        monkeypatch.setenv("PATH", "/usr/bin")

        with patch("ownlock.redactor.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.stdout = io.StringIO("")
            mock_proc.stderr = io.StringIO("")
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            red = SecretRedactor({"API_KEY": "resolved-secret-value"})
            red.run_process(["echo", "hi"], {"API_KEY": "resolved-secret-value"})

        env_passed = mock_popen.call_args.kwargs["env"]
        assert "OWNLOCK_PASSPHRASE" not in env_passed
        assert "OWNLOCK_NEW_PASSPHRASE" not in env_passed
        # Resolved secrets the user wanted to inject still get through.
        assert env_passed["API_KEY"] == "resolved-secret-value"
        # Non-sensitive parent env is preserved.
        assert env_passed.get("PATH") == "/usr/bin"

    def test_explicit_env_can_set_ownlock_passphrase_for_legitimate_use(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Phase 1.1 strips the parent env only; a caller that explicitly passes
        OWNLOCK_PASSPHRASE in *env* (e.g. ownlock spawning ownlock for rekey)
        still gets it through. The strip is about inheritance, not censorship."""
        monkeypatch.delenv("OWNLOCK_PASSPHRASE", raising=False)

        with patch("ownlock.redactor.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.stdout = io.StringIO("")
            mock_proc.stderr = io.StringIO("")
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            red = SecretRedactor({})
            red.run_process(["echo", "hi"], {"OWNLOCK_PASSPHRASE": "explicit"})

        env_passed = mock_popen.call_args.kwargs["env"]
        assert env_passed["OWNLOCK_PASSPHRASE"] == "explicit"


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
