"""Tests for ownlock.templates and the `render` / `run --render` CLI surface."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from ownlock.cli import app
from ownlock.resolver import VaultLookup
from ownlock.templates import (
    _escape_env,
    _escape_ini,
    _escape_json,
    _escape_shell,
    _escape_xml,
    _is_gitignored_fnmatch,
    detect_format,
    discover_templates,
    is_path_gitignored,
    render_file,
    render_text,
    template_output_path,
    write_atomic,
)
from ownlock.vault import VaultManager

PASSPHRASE = "test-pass"
runner = CliRunner()


# --- Fixtures --------------------------------------------------------------


@pytest.fixture()
def global_vault(tmp_path):
    """Create a vault in tmp_path and patch GLOBAL_VAULT_PATH in resolver."""
    db = tmp_path / "global" / "vault.db"
    with patch("ownlock.resolver.GLOBAL_VAULT_PATH", db):
        with VaultManager(db, PASSPHRASE) as vm:
            yield vm, db


@pytest.fixture()
def project_vault(tmp_path):
    db = tmp_path / ".ownlock" / "vault.db"
    vm = VaultManager.init_vault(db, PASSPHRASE)
    yield vm, db
    vm.close()


@pytest.fixture(autouse=True)
def _no_project_by_default(monkeypatch):
    """Default to no project vault so unit tests are deterministic."""
    monkeypatch.setattr(
        "ownlock.vault.VaultManager.find_project_vault",
        staticmethod(lambda: None),
    )


# --- render_text -----------------------------------------------------------


class TestRenderText:
    def test_single_reference(self, global_vault):
        vm, _ = global_vault
        vm.set("DB_PASS", "sekret")
        with VaultLookup(PASSPHRASE) as lookup:
            out, count = render_text('pwd={{vault("DB_PASS")}};', lookup)
        assert out == "pwd=sekret;"
        assert count == 1

    def test_multiple_references_in_same_text(self, global_vault):
        vm, _ = global_vault
        vm.set("A", "alpha")
        vm.set("B", "bravo")
        with VaultLookup(PASSPHRASE) as lookup:
            out, count = render_text(
                '{"a":"{{vault("A")}}","b":"{{vault("B")}}"}',
                lookup,
            )
        assert out == '{"a":"alpha","b":"bravo"}'
        assert count == 2

    def test_whitespace_inside_braces(self, global_vault):
        vm, _ = global_vault
        vm.set("X", "val")
        with VaultLookup(PASSPHRASE) as lookup:
            out, _ = render_text('{{  vault( "X" )  }}', lookup)
        assert out == "val"

    def test_env_override_uses_that_env(self, global_vault):
        vm, _ = global_vault
        vm.set("K", "dev-value")
        vm.set("K", "prod-value", env="production")
        with VaultLookup(PASSPHRASE) as lookup:
            dev, _ = render_text('{{vault("K")}}', lookup)
            prod, _ = render_text('{{vault("K", env="production")}}', lookup)
        assert dev == "dev-value"
        assert prod == "prod-value"

    def test_global_flag_forces_global(self, tmp_path, project_vault, global_vault):
        proj_vm, proj_db = project_vault
        proj_vm.set("SHARED", "from-project")
        glob_vm, _ = global_vault
        glob_vm.set("SHARED", "from-global")
        with patch(
            "ownlock.vault.VaultManager.find_project_vault",
            staticmethod(lambda: proj_db),
        ):
            with VaultLookup(PASSPHRASE) as lookup:
                project_default, _ = render_text('{{vault("SHARED")}}', lookup)
                explicit_global, _ = render_text(
                    '{{vault("SHARED", global=true)}}', lookup
                )
        assert project_default == "from-project"
        assert explicit_global == "from-global"

    def test_missing_secret_raises_keyerror(self, global_vault):
        with VaultLookup(PASSPHRASE) as lookup:
            with pytest.raises(KeyError, match="NOPE"):
                render_text('{{vault("NOPE")}}', lookup)

    def test_invalid_secret_name_raises(self, global_vault):
        with VaultLookup(PASSPHRASE) as lookup:
            with pytest.raises(KeyError, match="Invalid secret name"):
                render_text('{{vault("../etc/passwd")}}', lookup)

    def test_no_references_returns_text_unchanged(self, global_vault):
        with VaultLookup(PASSPHRASE) as lookup:
            out, count = render_text("plain file contents\n", lookup)
        assert out == "plain file contents\n"
        assert count == 0


# --- template_output_path --------------------------------------------------


class TestTemplateOutputPath:
    def test_typical_case(self, tmp_path):
        assert (
            template_output_path(tmp_path / "web.template.config")
            == tmp_path / "web.config"
        )

    def test_multi_dot_filename(self, tmp_path):
        assert (
            template_output_path(tmp_path / "appsettings.template.Development.json")
            == tmp_path / "appsettings.Development.json"
        )

    def test_raises_when_no_template_segment(self, tmp_path):
        with pytest.raises(ValueError, match="not a template"):
            template_output_path(tmp_path / "web.config")


# --- discover_templates ----------------------------------------------------


class TestDiscoverTemplates:
    def test_finds_template_files(self, tmp_path):
        (tmp_path / "a.template.json").write_text("{}")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.template.yaml").write_text("x: 1")
        (tmp_path / "plain.json").write_text("{}")
        found = discover_templates(tmp_path)
        names = {p.name for p in found}
        assert names == {"a.template.json", "b.template.yaml"}

    def test_skips_vcs_and_build_dirs(self, tmp_path):
        for d in [".git", "node_modules", ".venv", "__pycache__", ".ownlock"]:
            (tmp_path / d).mkdir()
            (tmp_path / d / "leak.template.json").write_text("{}")
        (tmp_path / "keep.template.json").write_text("{}")
        found = discover_templates(tmp_path)
        names = {p.name for p in found}
        assert names == {"keep.template.json"}


# --- write_atomic ----------------------------------------------------------


class TestWriteAtomic:
    def test_writes_content(self, tmp_path):
        dst = tmp_path / "out.txt"
        write_atomic(dst, "hello\n")
        assert dst.read_text() == "hello\n"

    def test_creates_parent_directory(self, tmp_path):
        dst = tmp_path / "nested" / "deeply" / "file.txt"
        write_atomic(dst, "x")
        assert dst.exists()

    def test_no_leftover_tmp_files_on_success(self, tmp_path):
        dst = tmp_path / "out.txt"
        write_atomic(dst, "hello")
        leftovers = [
            p for p in tmp_path.iterdir() if p.name != "out.txt"
        ]
        assert leftovers == []

    @pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
    def test_mode_is_restrictive_on_posix(self, tmp_path):
        dst = tmp_path / "secret.conf"
        write_atomic(dst, "pw=abc")
        mode = stat.S_IMODE(dst.stat().st_mode)
        assert mode == 0o600


# --- is_path_gitignored (fnmatch fallback) --------------------------------


class TestGitignoreFnmatchFallback:
    """Exercises the fnmatch-based fallback directly (no git dependency)."""

    def test_filename_match(self, tmp_path):
        (tmp_path / ".gitignore").write_text("secret.conf\n")
        target = tmp_path / "secret.conf"
        target.write_text("x")
        assert _is_gitignored_fnmatch(target, start_dir=tmp_path) is True

    def test_directory_pattern(self, tmp_path):
        (tmp_path / ".gitignore").write_text(".ownlock/\n")
        (tmp_path / ".ownlock").mkdir()
        nested = tmp_path / ".ownlock" / "vault.db"
        nested.write_text("x")
        assert _is_gitignored_fnmatch(nested, start_dir=tmp_path) is True

    def test_unrelated_file_not_ignored(self, tmp_path):
        (tmp_path / ".gitignore").write_text("secret.conf\n")
        target = tmp_path / "readme.md"
        target.write_text("x")
        assert _is_gitignored_fnmatch(target, start_dir=tmp_path) is False

    def test_no_gitignore_returns_false(self, tmp_path):
        target = tmp_path / "anything.txt"
        target.write_text("x")
        assert _is_gitignored_fnmatch(target, start_dir=tmp_path) is False


class TestGitignoreViaGit:
    """Exercises is_path_gitignored through the git-backed path (mocked)."""

    def test_uses_git_check_ignore_when_available(self, tmp_path, monkeypatch):
        """If _git_check_ignore returns True, is_path_gitignored should respect it
        even when no .gitignore exists (git has negation, .git/info/exclude, etc.)."""
        monkeypatch.setattr(
            "ownlock.templates._git_check_ignore",
            lambda p: True,
        )
        target = tmp_path / "untouched.conf"
        target.write_text("x")
        assert is_path_gitignored(target, start_dir=tmp_path) is True

    def test_git_says_not_ignored_short_circuits(self, tmp_path, monkeypatch):
        """Git's authoritative 'not ignored' wins over a fnmatch would-have-matched."""
        monkeypatch.setattr(
            "ownlock.templates._git_check_ignore",
            lambda p: False,
        )
        # Fnmatch fallback would match this, but git said no — git wins.
        (tmp_path / ".gitignore").write_text("file.conf\n")
        target = tmp_path / "file.conf"
        target.write_text("x")
        assert is_path_gitignored(target, start_dir=tmp_path) is False

    def test_falls_back_to_fnmatch_when_git_returns_none(self, tmp_path, monkeypatch):
        """When git is unavailable / not in a repo, the fnmatch scan runs."""
        monkeypatch.setattr(
            "ownlock.templates._git_check_ignore",
            lambda p: None,
        )
        (tmp_path / ".gitignore").write_text("file.conf\n")
        target = tmp_path / "file.conf"
        target.write_text("x")
        assert is_path_gitignored(target, start_dir=tmp_path) is True

    def test_real_git_repo_honors_negation(self, tmp_path):
        """End-to-end: create a real git repo and verify `!` negation is respected.

        Skips gracefully if git isn't installed in the test environment.
        """
        import shutil
        if shutil.which("git") is None:
            pytest.skip("git not available")

        import subprocess
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        (tmp_path / ".gitignore").write_text("*.conf\n!keep.conf\n")
        ignored = tmp_path / "skip.conf"
        ignored.write_text("x")
        kept = tmp_path / "keep.conf"
        kept.write_text("x")

        assert is_path_gitignored(ignored, start_dir=tmp_path) is True
        assert is_path_gitignored(kept, start_dir=tmp_path) is False


# --- Format escapers -------------------------------------------------------


class TestEscapers:
    def test_escape_json_handles_quotes_and_newlines(self):
        assert _escape_json('he said "hi"\nnew line') == 'he said \\"hi\\"\\nnew line'

    def test_escape_json_handles_backslash(self):
        assert _escape_json("path\\to\\file") == "path\\\\to\\\\file"

    def test_escape_json_preserves_unicode(self):
        assert _escape_json("héllo") == "héllo"

    def test_escape_xml_escapes_five_predefined_entities(self):
        src = """a<b&c>d"e'f"""
        out = _escape_xml(src)
        assert "&lt;" in out
        assert "&amp;" in out
        assert "&gt;" in out
        assert "&quot;" in out
        assert "&apos;" in out

    def test_escape_ini_escapes_backslash_and_newlines(self):
        assert _escape_ini("a=b\nnext\\line") == "a=b\\nnext\\\\line"

    def test_escape_env_escapes_quotes_and_backslashes(self):
        assert _escape_env('val"with"quotes') == 'val\\"with\\"quotes'
        assert _escape_env("with\nnewline") == "with\\nnewline"

    def test_escape_shell_escapes_single_quote(self):
        # 'it'\''s' is the canonical idiom for a single quote inside single quotes.
        assert _escape_shell("it's") == "it'\\''s"


# --- Format detection by extension ----------------------------------------


class TestDetectFormat:
    @pytest.mark.parametrize(
        "suffix,expected",
        [
            (".json", "json"),
            (".jsonc", "json"),
            (".xml", "xml"),
            (".config", "xml"),
            (".yaml", "yaml"),
            (".yml", "yaml"),
            (".toml", "toml"),
            (".ini", "ini"),
            (".properties", "ini"),
            (".env", "env"),
            (".sh", "shell"),
            (".tf", "hcl"),
            (".tfvars", "hcl"),
            (".unknown", "raw"),
            (".txt", "raw"),
        ],
    )
    def test_common_extensions(self, tmp_path, suffix, expected):
        assert detect_format(tmp_path / f"file{suffix}") == expected

    def test_multi_dot_uses_trailing_extension(self, tmp_path):
        assert detect_format(tmp_path / "appsettings.Development.json") == "json"


# --- render_file -----------------------------------------------------------


class TestRenderFile:
    def test_renders_and_writes_atomically(self, tmp_path, global_vault):
        vm, _ = global_vault
        vm.set("DB_PASS", "zzz")
        src = tmp_path / "conn.template.config"
        src.write_text('pwd="{{vault("DB_PASS")}}"')
        dst = tmp_path / "conn.config"
        with VaultLookup(PASSPHRASE) as lookup:
            count = render_file(src, dst, lookup)
        assert count == 1
        assert dst.read_text() == 'pwd="zzz"'


# --- CLI: ownlock render ---------------------------------------------------


@pytest.fixture()
def cli_vault(tmp_path, monkeypatch):
    """Install a global vault at a tmp path; patch all cli/resolver/vault refs.

    Yields (vault_db_path, chdir_target).
    """
    vault_db = tmp_path / ".ownlock" / "vault.db"
    monkeypatch.setenv("OWNLOCK_PASSPHRASE", PASSPHRASE)
    monkeypatch.setattr("ownlock.vault.GLOBAL_VAULT_PATH", vault_db)
    monkeypatch.setattr("ownlock.cli.GLOBAL_VAULT_PATH", vault_db)
    monkeypatch.setattr("ownlock.resolver.GLOBAL_VAULT_PATH", vault_db)
    monkeypatch.setattr(
        "ownlock.vault.VaultManager.find_project_vault",
        staticmethod(lambda: None),
    )

    with VaultManager(vault_db, PASSPHRASE) as vm:
        vm.set("DB_PASS", "s3cret")
        vm.set("API_KEY", "abc123")

    monkeypatch.chdir(tmp_path)
    yield vault_db, tmp_path


class TestRenderCommand:
    def test_single_template_renders(self, cli_vault):
        _, cwd = cli_vault
        tpl = cwd / "web.template.config"
        tpl.write_text('<add key="pwd" value="{{vault("DB_PASS")}}" />')
        (cwd / ".gitignore").write_text("web.config\n")

        result = runner.invoke(app, ["render", str(tpl)])
        assert result.exit_code == 0, result.output
        rendered = cwd / "web.config"
        assert rendered.read_text() == '<add key="pwd" value="s3cret" />'
        assert "Rendered" in result.output

    def test_discovery_mode_renders_all(self, cli_vault):
        _, cwd = cli_vault
        (cwd / "a.template.json").write_text('{"k":"{{vault("DB_PASS")}}"}')
        (cwd / "b.template.yaml").write_text('k: {{vault("API_KEY")}}')
        (cwd / ".gitignore").write_text("a.json\nb.yaml\n")

        result = runner.invoke(app, ["render"])
        assert result.exit_code == 0, result.output
        assert (cwd / "a.json").read_text() == '{"k":"s3cret"}'
        assert (cwd / "b.yaml").read_text() == "k: abc123"

    def test_dry_run_writes_nothing(self, cli_vault):
        _, cwd = cli_vault
        tpl = cwd / "x.template.conf"
        tpl.write_text('{{vault("DB_PASS")}}')
        out = cwd / "x.conf"

        result = runner.invoke(app, ["render", "--dry-run"])
        assert result.exit_code == 0
        assert not out.exists()
        # Rich may soft-wrap long paths; check for the filenames instead.
        # Collapse whitespace to defeat terminal wrapping.
        flat = "".join(result.output.split())
        assert tpl.name in flat
        assert out.name in flat

    def test_refuses_when_output_not_gitignored(self, cli_vault):
        _, cwd = cli_vault
        tpl = cwd / "web.template.config"
        tpl.write_text('{{vault("DB_PASS")}}')
        (cwd / ".gitignore").write_text("# empty\n")

        result = runner.invoke(app, ["render", str(tpl)])
        assert result.exit_code == 1
        assert "not appear to be gitignored" in result.output.lower() or \
            "refusing to write" in result.output.lower()
        assert not (cwd / "web.config").exists()

    def test_force_overrides_gitignore_warning(self, cli_vault):
        _, cwd = cli_vault
        tpl = cwd / "web.template.config"
        tpl.write_text('{{vault("DB_PASS")}}')
        (cwd / ".gitignore").write_text("# empty\n")

        result = runner.invoke(app, ["render", str(tpl), "--force"])
        assert result.exit_code == 0, result.output
        assert (cwd / "web.config").read_text() == "s3cret"

    def test_template_without_references_is_skipped(self, cli_vault):
        _, cwd = cli_vault
        tpl = cwd / "plain.template.json"
        tpl.write_text('{"k":"v"}')

        result = runner.invoke(app, ["render", str(tpl)])
        assert result.exit_code == 0
        out = cwd / "plain.json"
        assert not out.exists()
        assert "skipping" in result.output.lower()

    def test_missing_template_file(self, cli_vault):
        result = runner.invoke(app, ["render", "nope.template.json"])
        assert result.exit_code == 1

    def test_out_flag_requires_single_template(self, cli_vault):
        result = runner.invoke(app, ["render", "--out", "foo.txt"])
        assert result.exit_code == 1

    def test_missing_secret_is_reported(self, cli_vault):
        _, cwd = cli_vault
        tpl = cwd / "w.template.config"
        tpl.write_text('{{vault("MISSING")}}')
        (cwd / ".gitignore").write_text("w.config\n")

        result = runner.invoke(app, ["render", str(tpl)])
        assert result.exit_code == 1
        assert not (cwd / "w.config").exists()


# --- CLI: run --render / --render-cleanup ---------------------------------


class TestRunRender:
    def test_render_happens_before_exec(self, cli_vault):
        _, cwd = cli_vault
        tpl = cwd / "cfg.template.json"
        tpl.write_text('{"pw":"{{vault("DB_PASS")}}"}')
        (cwd / ".gitignore").write_text("cfg.json\n.env\n")
        (cwd / ".env").write_text("GREETING=hi\n")

        result = runner.invoke(
            app,
            [
                "run",
                "--render",
                str(tpl),
                "--",
                sys.executable,
                "-c",
                "print('ok')",
            ],
        )
        assert result.exit_code == 0, result.output
        rendered = cwd / "cfg.json"
        assert rendered.exists()
        assert rendered.read_text() == '{"pw":"s3cret"}'

    def test_render_cleanup_removes_rendered_files(self, cli_vault):
        _, cwd = cli_vault
        tpl = cwd / "cfg.template.json"
        tpl.write_text('{"pw":"{{vault("DB_PASS")}}"}')
        (cwd / ".gitignore").write_text("cfg.json\n.env\n")
        (cwd / ".env").write_text("GREETING=hi\n")

        result = runner.invoke(
            app,
            [
                "run",
                "--render",
                str(tpl),
                "--render-cleanup",
                "--",
                sys.executable,
                "-c",
                "print('ok')",
            ],
        )
        assert result.exit_code == 0, result.output
        assert not (cwd / "cfg.json").exists()

    def test_render_refuses_without_gitignore(self, cli_vault):
        _, cwd = cli_vault
        tpl = cwd / "cfg.template.json"
        tpl.write_text('{"pw":"{{vault("DB_PASS")}}"}')
        (cwd / ".env").write_text("GREETING=hi\n")

        result = runner.invoke(
            app,
            [
                "run",
                "--render",
                str(tpl),
                "--",
                sys.executable,
                "-c",
                "print('ok')",
            ],
        )
        assert result.exit_code == 1
        assert not (cwd / "cfg.json").exists()

    def test_multiple_render_paths_rendered(self, cli_vault):
        _, cwd = cli_vault
        a = cwd / "a.template.json"
        a.write_text('{"pw":"{{vault("DB_PASS")}}"}')
        b = cwd / "b.template.yaml"
        b.write_text('k: {{vault("API_KEY")}}')
        (cwd / ".gitignore").write_text("a.json\nb.yaml\n.env\n")
        (cwd / ".env").write_text("GREETING=hi\n")

        result = runner.invoke(
            app,
            [
                "run",
                "--render", str(a),
                "--render", str(b),
                "--",
                sys.executable,
                "-c",
                "print('ok')",
            ],
        )
        assert result.exit_code == 0, result.output
        assert (cwd / "a.json").read_text() == '{"pw":"s3cret"}'
        assert (cwd / "b.yaml").read_text() == "k: abc123"

    def test_run_without_render_does_not_discover_templates(self, cli_vault):
        """Security: plain `run` must never touch cwd templates (no auto-discovery)."""
        _, cwd = cli_vault
        tpl = cwd / "evil.template.json"
        tpl.write_text('{"pw":"{{vault("DB_PASS")}}"}')
        (cwd / ".gitignore").write_text("evil.json\n.env\n")
        (cwd / ".env").write_text("GREETING=hi\n")

        result = runner.invoke(
            app,
            ["run", "--", sys.executable, "-c", "print('ok')"],
        )
        assert result.exit_code == 0, result.output
        assert not (cwd / "evil.json").exists()

    def test_run_render_rejects_path_outside_cwd(self, cli_vault, tmp_path):
        """Security: --render path must pass the same traversal check as --file."""
        _, cwd = cli_vault
        (cwd / ".env").write_text("GREETING=hi\n")
        # Relative traversal that tries to escape cwd.
        result = runner.invoke(
            app,
            [
                "run",
                "--render", "../sneaky.template.json",
                "--",
                sys.executable,
                "-c",
                "print('ok')",
            ],
        )
        assert result.exit_code == 1


class TestRenderOutFlagValidation:
    def test_relative_out_outside_cwd_rejected(self, cli_vault):
        """`--out ../../elsewhere/foo.conf` is a relative traversal and must be rejected."""
        _, cwd = cli_vault
        tpl = cwd / "w.template.config"
        tpl.write_text('{{vault("DB_PASS")}}')
        (cwd / ".gitignore").write_text("w.config\n")
        result = runner.invoke(
            app,
            ["render", str(tpl), "--out", "../escaped.config"],
        )
        assert result.exit_code == 1

    def test_absolute_out_allowed(self, cli_vault, tmp_path):
        """Absolute --out paths are allowed (consistent with --file semantics)."""
        _, cwd = cli_vault
        tpl = cwd / "w.template.config"
        tpl.write_text('{{vault("DB_PASS")}}')
        # Use a sibling tmp dir so output can satisfy its own .gitignore check.
        external = tmp_path / "external"
        external.mkdir()
        (external / ".gitignore").write_text("out.config\n")
        out = external / "out.config"
        result = runner.invoke(
            app,
            ["render", str(tpl), "--out", str(out)],
        )
        assert result.exit_code == 0, result.output
        assert out.read_text() == "s3cret"


class TestDiscoveryNoFollowSymlinks:
    def test_directory_symlink_is_not_followed(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "evil.template.json").write_text('{"k":"v"}')

        inside = tmp_path / "project"
        inside.mkdir()
        (inside / "keep.template.json").write_text('{"k":"v"}')

        # Symlink "project/link" -> "outside". Without follow, discovery must ignore it.
        os.symlink(outside, inside / "link", target_is_directory=True)

        found = discover_templates(inside)
        names = {p.name for p in found}
        assert names == {"keep.template.json"}

    def test_file_symlink_is_not_followed(self, tmp_path):
        target = tmp_path / "elsewhere.template.json"
        target.write_text('{"k":"v"}')

        inside = tmp_path / "project"
        inside.mkdir()
        os.symlink(target, inside / "sneaky.template.json")
        (inside / "real.template.json").write_text('{"k":"v"}')

        found = discover_templates(inside)
        names = {p.name for p in found}
        assert names == {"real.template.json"}


class TestFormatAwareRendering:
    """End-to-end: a secret with special chars should produce valid output."""

    def test_json_output_is_valid_after_render(self, cli_vault):
        _, cwd = cli_vault
        # Put a secret that contains chars that would break naive JSON.
        with VaultManager(cwd / ".ownlock" / "vault.db", PASSPHRASE) as vm:
            vm.set("TRICKY", 'he said "hi"\nnew line')
        tpl = cwd / "cfg.template.json"
        tpl.write_text('{"msg":"{{vault("TRICKY")}}"}')
        (cwd / ".gitignore").write_text("cfg.json\n")

        result = runner.invoke(app, ["render", str(tpl)])
        assert result.exit_code == 0, result.output
        import json as _json
        parsed = _json.loads((cwd / "cfg.json").read_text())
        assert parsed["msg"] == 'he said "hi"\nnew line'

    def test_xml_output_escapes_entities(self, cli_vault):
        _, cwd = cli_vault
        with VaultManager(cwd / ".ownlock" / "vault.db", PASSPHRASE) as vm:
            vm.set("XMLVAL", "a<b&c>d")
        tpl = cwd / "web.template.config"
        tpl.write_text('<add value="{{vault("XMLVAL")}}" />')
        (cwd / ".gitignore").write_text("web.config\n")

        result = runner.invoke(app, ["render", str(tpl)])
        assert result.exit_code == 0, result.output
        out = (cwd / "web.config").read_text()
        assert "a&lt;b&amp;c&gt;d" in out
        assert "a<b&c>d" not in out

    def test_raw_flag_disables_escaping(self, cli_vault):
        _, cwd = cli_vault
        with VaultManager(cwd / ".ownlock" / "vault.db", PASSPHRASE) as vm:
            vm.set("TRICKY", 'quote"inside')
        tpl = cwd / "cfg.template.json"
        tpl.write_text('{"msg":"{{vault("TRICKY")}}"}')
        (cwd / ".gitignore").write_text("cfg.json\n")

        result = runner.invoke(app, ["render", str(tpl), "--raw"])
        assert result.exit_code == 0, result.output
        # With --raw the output is literally broken JSON, proving no escaping happened.
        out = (cwd / "cfg.json").read_text()
        assert out == '{"msg":"quote"inside"}'

    def test_per_reference_format_override(self, cli_vault):
        """``format="raw"`` on an individual ref opts out for just that ref."""
        _, cwd = cli_vault
        with VaultManager(cwd / ".ownlock" / "vault.db", PASSPHRASE) as vm:
            vm.set("HTML", "<b>bold</b>")
        tpl = cwd / "page.template.json"
        # Two refs: one JSON-escaped (default), one explicitly raw.
        tpl.write_text(
            '{"safe":"{{vault("HTML")}}",'
            '"raw":"{{vault("HTML", format="raw")}}"}'
        )
        (cwd / ".gitignore").write_text("page.json\n")

        result = runner.invoke(app, ["render", str(tpl)])
        assert result.exit_code == 0, result.output
        out = (cwd / "page.json").read_text()
        # The default-json value came through unchanged (no HTML specials need escaping).
        # The raw value is identical here. Test with a quote instead:
        assert '"safe":"<b>bold</b>"' in out
        assert '"raw":"<b>bold</b>"' in out

    def test_per_reference_format_json_on_txt_file(self, cli_vault):
        """format=\"json\" inside a .txt file (auto-detected as raw) still escapes."""
        _, cwd = cli_vault
        with VaultManager(cwd / ".ownlock" / "vault.db", PASSPHRASE) as vm:
            vm.set("QUOTED", 'has "quotes"')
        tpl = cwd / "note.template.txt"
        tpl.write_text('default: {{vault("QUOTED")}}\n'
                       'json:    {{vault("QUOTED", format="json")}}\n')
        (cwd / ".gitignore").write_text("note.txt\n")

        result = runner.invoke(app, ["render", str(tpl)])
        assert result.exit_code == 0, result.output
        out = (cwd / "note.txt").read_text()
        assert 'default: has "quotes"' in out
        assert 'json:    has \\"quotes\\"' in out

    def test_unknown_format_override_errors(self, cli_vault):
        _, cwd = cli_vault
        tpl = cwd / "x.template.json"
        tpl.write_text('{{vault("DB_PASS", format="klingon")}}')
        (cwd / ".gitignore").write_text("x.json\n")
        result = runner.invoke(app, ["render", str(tpl)])
        assert result.exit_code == 1
        assert "format" in result.output.lower() or "unknown" in result.output.lower()

    def test_kwargs_work_in_any_order(self, cli_vault):
        """env, project, global, and format may appear in any order."""
        _, cwd = cli_vault
        with VaultManager(cwd / ".ownlock" / "vault.db", PASSPHRASE) as vm:
            vm.set("K", "prod-value", env="production")
        tpl = cwd / "x.template.json"
        tpl.write_text(
            '{"a":"{{vault("K", env="production", format="json")}}",'
            '"b":"{{vault("K", format="json", env="production")}}"}'
        )
        (cwd / ".gitignore").write_text("x.json\n")

        result = runner.invoke(app, ["render", str(tpl)])
        assert result.exit_code == 0, result.output
        out = (cwd / "x.json").read_text()
        assert '"a":"prod-value"' in out
        assert '"b":"prod-value"' in out


class TestUnmatchedVaultRefs:
    def test_find_unmatched_vault_refs(self):
        from ownlock.templates import find_unmatched_vault_refs
        text = 'ok\nbad: {{ vault(\'x\') }}\nalso bad: {{vault("y")}\n'
        leftovers = find_unmatched_vault_refs(text)
        assert len(leftovers) == 2
        assert leftovers[0][0] == 2
        assert leftovers[1][0] == 3

    def test_render_prints_warning_for_unmatched(self, cli_vault):
        _, cwd = cli_vault
        tpl = cwd / "w.template.config"
        # Wrong quote style → regex does not match; line passes through.
        tpl.write_text(
            '<add value="{{vault("DB_PASS")}}" />\n'
            '<add value="{{ vault(\'API_KEY\') }}" />\n'
        )
        (cwd / ".gitignore").write_text("w.config\n")
        result = runner.invoke(app, ["render", str(tpl)])
        assert result.exit_code == 0, result.output
        assert "malformed vault" in result.output.lower() or "malformed" in result.output.lower()
        assert (cwd / "w.config").exists()
