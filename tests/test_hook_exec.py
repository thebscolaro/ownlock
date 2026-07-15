"""Execute the emitted shield/guard hook scripts with synthetic payloads.

Every other shield test asserts on file contents; these actually run the
scripts (bash on POSIX, pwsh/powershell where available) and check the
allow/deny answer, because a hook that emits the wrong shape locks the agent.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from ownlock import hookutil
from ownlock.guard import install_guard_hook
from ownlock.shield import install_shield

BASH = hookutil.find_bash()
POWERSHELL = hookutil.find_powershell()

needs_bash = pytest.mark.skipif(BASH is None, reason="bash not on PATH")
needs_powershell = pytest.mark.skipif(
    POWERSHELL is None, reason="pwsh/powershell not on PATH"
)


@pytest.fixture()
def shielded_project(tmp_path: Path) -> Path:
    install_shield(tmp_path, hermes_home=tmp_path / "hermes-home")
    return tmp_path


def _script(project: Path, agent: str, suffix: str) -> Path:
    rel = {
        "claude": f".claude/hooks/ownlock-shield{suffix}",
        "cursor": f".cursor/hooks/ownlock-shield{suffix}",
        "hermes": f".ownlock/hooks/ownlock-hermes-shield{suffix}",
    }[agent]
    return project / rel


def _case_params() -> list:
    params = []
    for agent, cases in hookutil.CASES_BY_AGENT.items():
        for case_name, payload, expect in cases:
            params.append(
                pytest.param(agent, payload, expect, id=f"{agent}-{case_name}")
            )
    return params


@needs_bash
@pytest.mark.parametrize("agent,payload,expect", _case_params())
def test_sh_hooks_answer_correctly(shielded_project, agent, payload, expect):
    script = _script(shielded_project, agent, ".sh")
    if not script.exists():
        pytest.skip(f"{script.name} not installed for this agent")
    exit_code, stdout = hookutil.run_hook(script, payload)
    failure = hookutil.evaluate(agent, expect, exit_code, stdout)
    assert failure is None, failure


@needs_powershell
@pytest.mark.parametrize("agent,payload,expect", _case_params())
def test_ps1_hooks_answer_correctly(shielded_project, agent, payload, expect):
    script = _script(shielded_project, agent, ".ps1")
    if not script.exists():
        pytest.skip(f"{script.name} not installed for this agent")
    exit_code, stdout = hookutil.run_hook(script, payload)
    failure = hookutil.evaluate(agent, expect, exit_code, stdout)
    assert failure is None, failure


@needs_bash
@pytest.mark.skipif(os.name == "nt", reason="POSIX-only PATH stub")
class TestCursorWithoutJq:
    """Cursor bash hook must still answer when jq is missing from PATH."""

    @pytest.fixture()
    def stub_path(self, tmp_path: Path) -> str:
        """A bin dir with everything the hook needs except jq."""
        stub = tmp_path / "stub-bin"
        stub.mkdir()
        for tool in ("cat", "grep", "printf", "sh", "bash", "env"):
            import shutil as _shutil

            src = _shutil.which(tool)
            if src:
                (stub / tool).symlink_to(src)
        return str(stub)

    def _run(self, project: Path, payload: str, stub_path: str) -> tuple[int, str]:
        script = _script(project, "cursor", ".sh")
        env = {**os.environ, "PATH": stub_path}
        proc = subprocess.run(
            [BASH, str(script)],
            input=payload.encode("utf-8"),
            capture_output=True,
            env=env,
            timeout=60,
        )
        return proc.returncode, proc.stdout.decode("utf-8")

    def test_allows_benign_payload(self, shielded_project, stub_path):
        code, out = self._run(
            shielded_project, json.dumps({"file_path": "src/app.py"}), stub_path
        )
        assert code == 0
        assert json.loads(out)["permission"] == "allow"

    def test_allows_foo_env_without_jq(self, shielded_project, stub_path):
        # Word-boundary shell rule must not run on raw JSON (false deny).
        code, out = self._run(
            shielded_project, json.dumps({"file_path": "foo.env"}), stub_path
        )
        assert code == 0
        assert json.loads(out)["permission"] == "allow"

    def test_denies_env_payload(self, shielded_project, stub_path):
        code, out = self._run(
            shielded_project, json.dumps({"file_path": ".env"}), stub_path
        )
        assert code == 2
        assert json.loads(out)["permission"] == "deny"

    def test_denies_ownlock_payload(self, shielded_project, stub_path):
        code, out = self._run(
            shielded_project,
            json.dumps({"file_path": "x/.ownlock/vault.db"}),
            stub_path,
        )
        assert code == 2
        assert json.loads(out)["permission"] == "deny"

    def test_denies_shell_cat_env_without_jq(self, shielded_project, stub_path):
        code, out = self._run(
            shielded_project, json.dumps({"command": "cat .env"}), stub_path
        )
        assert code == 2
        assert json.loads(out)["permission"] == "deny"


@needs_bash
@pytest.mark.skipif(os.name == "nt", reason="POSIX-only PATH stub")
class TestClaudeWithoutJq:
    """Claude bash hook must deny when jq is missing (not silently allow)."""

    @pytest.fixture()
    def stub_path(self, tmp_path: Path) -> str:
        stub = tmp_path / "stub-bin"
        stub.mkdir()
        for tool in ("cat", "grep", "printf", "sh", "bash", "env"):
            import shutil as _shutil

            src = _shutil.which(tool)
            if src:
                (stub / tool).symlink_to(src)
        return str(stub)

    def _run(self, project: Path, payload: str, stub_path: str) -> tuple[int, str]:
        script = _script(project, "claude", ".sh")
        proc = subprocess.run(
            [BASH, str(script)],
            input=payload.encode("utf-8"),
            capture_output=True,
            env={**os.environ, "PATH": stub_path},
            timeout=60,
        )
        return proc.returncode, proc.stdout.decode("utf-8")

    def test_denies_env_read(self, shielded_project, stub_path):
        code, out = self._run(
            shielded_project,
            json.dumps({"tool_name": "Read", "tool_input": {"file_path": ".env"}}),
            stub_path,
        )
        assert code == 0
        data = json.loads(out)
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_allows_foo_env(self, shielded_project, stub_path):
        code, out = self._run(
            shielded_project,
            json.dumps({"tool_name": "Read", "tool_input": {"file_path": "foo.env"}}),
            stub_path,
        )
        assert code == 0
        assert "deny" not in out.lower() or "permissionDecision" not in out


@needs_bash
@pytest.mark.skipif(os.name == "nt", reason="bash guard hook is POSIX-only")
class TestGuardHookExec:
    """Run ownlock-guard.sh with a fake `ownlock` binary on PATH."""

    @pytest.fixture()
    def guard_project(self, tmp_path: Path, monkeypatch) -> Path:
        monkeypatch.setattr(os, "name", "posix", raising=False)
        install_guard_hook(tmp_path)
        return tmp_path

    def _fake_ownlock(self, tmp_path: Path, body: str) -> str:
        """Create a PATH dir with a fake `ownlock` plus the tools the hook needs."""
        bin_dir = tmp_path / "fake-bin"
        bin_dir.mkdir(exist_ok=True)
        fake = bin_dir / "ownlock"
        fake.write_text(body, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        return f"{bin_dir}{os.pathsep}{os.environ['PATH']}"

    def _run(self, project: Path, payload: str, path_env: str) -> tuple[int, str]:
        script = project / ".claude" / "hooks" / "ownlock-guard.sh"
        proc = subprocess.run(
            [BASH, str(script)],
            input=payload.encode("utf-8"),
            capture_output=True,
            env={**os.environ, "PATH": path_env},
            timeout=60,
        )
        return proc.returncode, proc.stdout.decode("utf-8")

    def test_redaction_emits_updated_output(self, guard_project, tmp_path):
        path_env = self._fake_ownlock(
            tmp_path,
            "#!/usr/bin/env bash\nsed 's/sekret-value/[REDACTED]/g'\n",
        )
        payload = json.dumps({"tool_response": "token=sekret-value ok"})
        code, out = self._run(guard_project, payload, path_env)
        assert code == 0
        data = json.loads(out)
        assert (
            data["hookSpecificOutput"]["updatedToolOutput"] == "token=[REDACTED] ok"
        )

    def test_unchanged_output_stays_silent(self, guard_project, tmp_path):
        path_env = self._fake_ownlock(tmp_path, "#!/usr/bin/env bash\ncat\n")
        payload = json.dumps({"tool_response": "nothing secret here"})
        code, out = self._run(guard_project, payload, path_env)
        assert code == 0
        assert out.strip() == ""

    def test_guard_failure_fails_closed(self, guard_project, tmp_path):
        path_env = self._fake_ownlock(tmp_path, "#!/usr/bin/env bash\nexit 1\n")
        payload = json.dumps({"tool_response": "token=sekret-value"})
        code, _ = self._run(guard_project, payload, path_env)
        assert code == 1


def test_selftest_passes_on_fresh_install(shielded_project):
    if BASH is None and POWERSHELL is None:
        pytest.skip("no hook interpreter available")
    results = hookutil.run_selftest(shielded_project)
    assert results, "selftest found no runnable hooks"
    failures = [r for r in results if not r.ok]
    assert not failures, "\n".join(
        f"{r.agent} {r.script} [{r.case}]: {r.detail}" for r in failures
    )


def test_selftest_reports_empty_without_shield(tmp_path):
    assert hookutil.run_selftest(tmp_path) == []


def test_selftest_marker_roundtrip(tmp_path):
    assert not hookutil.selftest_marker_exists(tmp_path)
    assert not hookutil.selftest_passed(tmp_path)
    hookutil.write_selftest_marker(tmp_path, [])
    assert hookutil.selftest_marker_exists(tmp_path)
    assert hookutil.selftest_passed(tmp_path)
    data = json.loads(
        (tmp_path / ".ownlock" / "selftest.json").read_text(encoding="utf-8")
    )
    assert data["failed"] == 0


def test_selftest_marker_failed_is_not_ok(tmp_path):
    hookutil.write_selftest_marker(
        tmp_path,
        [hookutil.SelftestResult("cursor", "x", "deny .env", False, "boom")],
    )
    assert hookutil.selftest_marker_exists(tmp_path)
    assert not hookutil.selftest_passed(tmp_path)
