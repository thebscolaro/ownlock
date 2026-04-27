"""Tests for ownlock.redactor — secret value redaction."""

import io
import sys
from unittest.mock import MagicMock, patch

import pytest

from ownlock.redactor import SecretRedactor


class TestRedact:
    def test_replaces_known_value(self):
        r = SecretRedactor({"DB_PASS": "s3cr3t"})
        assert r.redact("password is s3cr3t ok") == "password is [REDACTED:DB_PASS] ok"

    def test_multiple_secrets_in_one_line(self):
        r = SecretRedactor({"A": "aaa", "B": "bbb"})
        result = r.redact("values: aaa and bbb done")
        assert result == "values: [REDACTED:A] and [REDACTED:B] done"

    def test_secret_appearing_multiple_times(self):
        r = SecretRedactor({"TOKEN": "xyz"})
        assert r.redact("xyz-xyz-xyz") == "[REDACTED:TOKEN]-[REDACTED:TOKEN]-[REDACTED:TOKEN]"

    def test_empty_secrets_no_redaction(self):
        r = SecretRedactor({})
        text = "nothing to hide"
        assert r.redact(text) == text

    def test_longer_secrets_replaced_first(self):
        r = SecretRedactor({"SHORT": "abc", "LONG": "abcdef"})
        result = r.redact("prefix abcdef suffix")
        assert "[REDACTED:LONG]" in result
        assert "[REDACTED:SHORT]" not in result


class TestRunProcess:
    def test_echo_command_redacted(self):
        r = SecretRedactor({"SECRET": "hunter2"})
        out = io.StringIO()
        err = io.StringIO()
        exit_code = r.run_process(
            ["echo", "my password is hunter2"],
            env={},
            stdout=out,
            stderr=err,
        )
        assert exit_code == 0
        assert "[REDACTED:SECRET]" in out.getvalue()
        assert "hunter2" not in out.getvalue()

    def test_exit_code_forwarded(self):
        r = SecretRedactor({})
        out = io.StringIO()
        err = io.StringIO()
        exit_code = r.run_process(
            [sys.executable, "-c", "raise SystemExit(42)"],
            env={},
            stdout=out,
            stderr=err,
        )
        assert exit_code == 42

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows PATHEXT resolution via shutil.which")
    def test_windows_resolves_argv0_with_which(self) -> None:
        fake_npm = r"C:\fake\npm.cmd"
        mock_proc = MagicMock()
        mock_proc.stdout = io.StringIO("")
        mock_proc.stderr = io.StringIO("")
        mock_proc.wait.return_value = 0

        with (
            patch("ownlock.redactor.shutil.which", return_value=fake_npm) as mock_which,
            patch("ownlock.redactor.subprocess.Popen", return_value=mock_proc) as mock_popen,
        ):
            r = SecretRedactor({})
            exit_code = r.run_process(["npm", "--version"], env={"PATH": r"C:\fake\bin"}, stdout=io.StringIO(), stderr=io.StringIO())

        assert exit_code == 0
        mock_which.assert_called_once_with("npm", path=r"C:\fake\bin")
        mock_popen.assert_called_once()
        ca = mock_popen.call_args
        cmd = ca.args[0]
        assert cmd[0] == fake_npm
        assert cmd[1:] == ["--version"]
        assert ca.kwargs["env"]["PATH"] == r"C:\fake\bin"

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows uses shutil.which for argv0; this guards other platforms")
    def test_non_windows_does_not_call_which(self) -> None:
        def _fail_which(*_a: object, **_k: object) -> None:
            raise AssertionError("shutil.which should not be used on non-Windows")

        r = SecretRedactor({})
        out = io.StringIO()
        err = io.StringIO()
        with patch("ownlock.redactor.shutil.which", side_effect=_fail_which):
            exit_code = r.run_process(
                [sys.executable, "-c", "print('ok')"],
                env={},
                stdout=out,
                stderr=err,
            )
        assert exit_code == 0
        assert "ok" in out.getvalue()
