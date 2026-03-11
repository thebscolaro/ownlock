"""Tests for ownlock.redactor — secret value redaction."""

import io
import sys

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
