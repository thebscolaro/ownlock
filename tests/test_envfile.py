"""Tests for ownlock.envfile — pure parsing/rewriting, no CLI / vault coupling."""

from __future__ import annotations

from pathlib import Path

from ownlock.envfile import (
    DEFAULT_ENV_FILE_CANDIDATES,
    classify_env_file,
    format_vault_expr,
    iter_env_kv_pairs,
    rewrite_env_lines_to_vault_syntax,
)


class TestClassifyEnvFile:
    def test_missing_file_is_empty(self, tmp_path: Path) -> None:
        assert classify_env_file(tmp_path / "nope.env") == "empty"

    def test_blank_or_comment_only_file_is_empty(self, tmp_path: Path) -> None:
        p = tmp_path / ".env"
        p.write_text("# header\n\n# nothing here\n")
        assert classify_env_file(p) == "empty"

    def test_plain_kv_classifies_as_seed(self, tmp_path: Path) -> None:
        p = tmp_path / ".env"
        p.write_text("FOO=bar\nDB_PASS=hunter2longer\n")
        assert classify_env_file(p) == "seed"

    def test_vault_ref_classifies_as_bootstrap(self, tmp_path: Path) -> None:
        p = tmp_path / ".env"
        p.write_text('FOO=vault("FOO")\n')
        assert classify_env_file(p) == "bootstrap"

    def test_mixed_file_classifies_as_bootstrap(self, tmp_path: Path) -> None:
        """Vault refs win when both shapes are present (teammate-clone case)."""
        p = tmp_path / ".env"
        p.write_text('FOO=vault("FOO")\nLEFTOVER=plain-value\n')
        assert classify_env_file(p) == "bootstrap"

    def test_vault_with_kwargs_still_classifies_as_bootstrap(self, tmp_path: Path) -> None:
        p = tmp_path / ".env"
        p.write_text('PROD_KEY=vault("PROD_KEY", env="production")\n')
        assert classify_env_file(p) == "bootstrap"

    def test_word_vault_in_value_is_not_a_vault_call(self, tmp_path: Path) -> None:
        """Bare ``vault`` words shouldn't trigger bootstrap routing."""
        p = tmp_path / ".env"
        p.write_text("HASHICORP_VAULT_TOKEN=hvs.abcdefghij\n")
        assert classify_env_file(p) == "seed"

    def test_comment_with_vault_example_does_not_trigger_bootstrap(self, tmp_path: Path) -> None:
        """A commented-out vault() example must not flip routing to bootstrap."""
        p = tmp_path / ".env"
        p.write_text(
            "# TOKEN=vault(\"TOKEN\")\n"
            "REAL_KEY=real-value\n"
        )
        assert classify_env_file(p) == "seed"


def test_default_env_candidates_is_a_tuple_of_strings() -> None:
    assert isinstance(DEFAULT_ENV_FILE_CANDIDATES, tuple)
    assert all(isinstance(name, str) and name.startswith(".env") for name in DEFAULT_ENV_FILE_CANDIDATES)


def test_format_vault_expr_default_env_omits_kwarg() -> None:
    assert format_vault_expr("API_KEY") == 'vault("API_KEY")'


def test_format_vault_expr_non_default_env_emits_kwarg() -> None:
    assert format_vault_expr("API_KEY", "production") == 'vault("API_KEY", env="production")'


def test_iter_env_kv_pairs_skips_comments_blanks_and_invalid_keys(tmp_path: Path) -> None:
    p = tmp_path / ".env"
    p.write_text(
        "\n".join(
            [
                "# header comment",
                "",
                "FOO=bar",
                "BAD KEY=skipped",  # invalid (space in key)
                "EMPTY=",  # empty value -> skipped
                "DB_PASS=hunter2longer",
            ]
        )
    )
    pairs = list(iter_env_kv_pairs(p))
    assert pairs == [("FOO", "bar"), ("DB_PASS", "hunter2longer")]


def test_iter_env_kv_pairs_missing_file_yields_nothing(tmp_path: Path) -> None:
    assert list(iter_env_kv_pairs(tmp_path / "nope.env")) == []


def test_rewrite_preserves_comments_blanks_and_existing_vault_calls() -> None:
    lines = [
        "# comment",
        "",
        "FOO=plain",
        'BAR=vault("BAR")',
        "SKIP=keep",
    ]
    existing = {"FOO": "plain", "SKIP": "keep"}
    out, changed = rewrite_env_lines_to_vault_syntax(lines, existing, "production")
    assert changed == 2
    joined = "\n".join(out)
    assert 'FOO=vault("FOO", env="production")' in joined
    assert 'SKIP=vault("SKIP", env="production")' in joined
    assert "# comment" in joined
    assert 'BAR=vault("BAR")' in joined  # already vault() — left untouched


def test_rewrite_default_env_omits_env_kwarg() -> None:
    out, changed = rewrite_env_lines_to_vault_syntax(["X=v"], {"X": "v"}, "default")
    assert changed == 1
    assert out == ['X=vault("X")']


def test_rewrite_skips_keys_not_in_vault() -> None:
    out, changed = rewrite_env_lines_to_vault_syntax(["X=v", "Y=w"], {"X": "v"}, "default")
    assert changed == 1
    assert out[1] == "Y=w"


def test_rewrite_skips_invalid_key_names() -> None:
    out, changed = rewrite_env_lines_to_vault_syntax(["BAD KEY=value"], {"BAD KEY": "value"}, "default")
    assert changed == 0
    assert out == ["BAD KEY=value"]
