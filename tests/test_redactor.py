"""Tests for ownlock.redactor — secret value redaction."""

import io
import sys
from unittest.mock import MagicMock, patch

import pytest

from ownlock.redactor import CommandNotFoundError, SecretRedactor


class TestRedact:
    def test_replaces_known_value(self):
        r = SecretRedactor({"DB_PASS": "super-secret-value"})
        assert (
            r.redact("password is super-secret-value ok")
            == "password is [REDACTED:DB_PASS] ok"
        )

    def test_multiple_secrets_in_one_line(self):
        r = SecretRedactor({"A": "aaaaaaaaa", "B": "bbbbbbbbb"})
        result = r.redact("values: aaaaaaaaa and bbbbbbbbb done")
        assert result == "values: [REDACTED:A] and [REDACTED:B] done"

    def test_secret_appearing_multiple_times(self):
        r = SecretRedactor({"TOKEN": "xyz12345abc"})
        assert (
            r.redact("xyz12345abc-xyz12345abc-xyz12345abc")
            == "[REDACTED:TOKEN]-[REDACTED:TOKEN]-[REDACTED:TOKEN]"
        )

    def test_empty_secrets_no_redaction(self):
        r = SecretRedactor({})
        text = "nothing to hide"
        assert r.redact(text) == text

    def test_inline_env_literals_redacted_when_registered(self):
        """ownlock run registers every injected env value, not only vault() refs."""
        r = SecretRedactor({"LEGACY_API_KEY": "sk-live-migration-secret"})
        assert (
            r.redact("token=sk-live-migration-secret")
            == "token=[REDACTED:LEGACY_API_KEY]"
        )

    def test_longer_secrets_replaced_first(self):
        r = SecretRedactor({"SHORT": "abcd1234", "LONG": "abcd1234efgh"})
        result = r.redact("prefix abcd1234efgh suffix")
        assert "[REDACTED:LONG]" in result
        assert "[REDACTED:SHORT]" not in result

    def test_short_values_below_threshold_skipped(self):
        """Sub-threshold values like 'ok' or 'true' must not be redacted."""
        r = SecretRedactor({"FOO": "ok"})
        # Long enough sentence; should pass through unchanged.
        text = "everything is ok and the build is green"
        assert r.redact(text) == text


class TestVariantEncodings:
    """Common encodings of secret values are also redacted."""

    def test_base64_form_redacted(self):
        import base64 as _b64

        secret = "my-secret-token-1234"
        b64 = _b64.b64encode(secret.encode()).decode()
        r = SecretRedactor({"TOK": secret})
        result = r.redact(f"Authorization: Basic {b64}")
        assert b64 not in result
        assert "[REDACTED:TOK]" in result

    def test_url_encoded_form_redacted(self):
        secret = "p@ssword/with+special=chars"
        import urllib.parse as _u

        encoded = _u.quote(secret, safe="")
        r = SecretRedactor({"PWD": secret})
        result = r.redact(f"https://x.example/u?token={encoded}&ok=1")
        assert encoded not in result
        assert "[REDACTED:PWD]" in result

    def test_json_escaped_form_redacted(self):
        secret = 'val"with"quotes\nand\\backslash'
        encoded = secret.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        r = SecretRedactor({"X": secret})
        result = r.redact(f'{{"x": "{encoded}"}}')
        assert "[REDACTED:X]" in result
        assert encoded not in result

    def test_raw_value_still_redacted_alongside_variants(self):
        secret = "looooooong-secret-12345"
        r = SecretRedactor({"S": secret})
        # Raw form
        assert r.redact(f"value={secret}") == "value=[REDACTED:S]"

    def test_short_secrets_have_no_variants(self):
        """Skipping short secrets also skips their variants."""
        r = SecretRedactor({"S": "abc"})
        assert r._replacements == []


class TestRunProcess:
    def test_echo_command_redacted(self):
        r = SecretRedactor({"SECRET": "hunter2-very-long-password"})
        out = io.StringIO()
        err = io.StringIO()
        exit_code = r.run_process(
            ["echo", "my password is hunter2-very-long-password"],
            env={},
            stdout=out,
            stderr=err,
        )
        assert exit_code == 0
        assert "[REDACTED:SECRET]" in out.getvalue()
        assert "hunter2-very-long-password" not in out.getvalue()

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

    def test_command_not_found_raises(self) -> None:
        r = SecretRedactor({})
        with pytest.raises(CommandNotFoundError, match="missing-cmd"):
            r.run_process(
                ["missing-cmd"],
                env={},
                stdout=io.StringIO(),
                stderr=io.StringIO(),
            )
