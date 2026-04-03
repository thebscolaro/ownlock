"""End-to-end smoke tests: real CLI via subprocess, isolated HOME.

These complement unit tests (CliRunner) by exercising `python -m ownlock` as users do.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from ownlock.vault import VaultManager

PASS = "smoke-e2e-passphrase-xx"


def _fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    return home


def _subprocess_env(home: Path, passphrase: str = PASS) -> dict[str, str]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env["OWNLOCK_PASSPHRASE"] = passphrase
    # Rich tables use Unicode; Windows defaults (cp1252) break decode and can leave stdout None.
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _run_cli(
    *args: str,
    cwd: Path,
    home: Path,
    passphrase: str = PASS,
    timeout: float = 60.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ownlock", *args],
        cwd=str(cwd),
        env=_subprocess_env(home, passphrase),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _cli_output(proc: subprocess.CompletedProcess[str]) -> str:
    """Stdout + stderr (Rich may use either; decode-safe on Windows)."""
    return (proc.stdout or "") + (proc.stderr or "")


@pytest.mark.smoke
def test_smoke_global_vault_get(tmp_path: Path) -> None:
    home = _fake_home(tmp_path)
    vault_path = home / ".ownlock" / "vault.db"
    vault_path.parent.mkdir(parents=True)
    with VaultManager.init_vault(vault_path, PASS) as vm:
        vm.set("SMOKE_KEY", "smoke-value-xyz")

    work = tmp_path / "workdir"
    work.mkdir()
    proc = _run_cli("get", "SMOKE_KEY", "--global", cwd=work, home=home)
    assert proc.returncode == 0, _cli_output(proc)
    assert "smoke-value-xyz" in _cli_output(proc)


@pytest.mark.smoke
def test_smoke_project_vault_list(tmp_path: Path) -> None:
    home = _fake_home(tmp_path)
    project = tmp_path / "myapp"
    project.mkdir()
    pv = project / ".ownlock" / "vault.db"
    pv.parent.mkdir(parents=True)
    with VaultManager.init_vault(pv, PASS) as vm:
        vm.set("LISTED", "v", env="default")

    proc = _run_cli("list", cwd=project, home=home)
    assert proc.returncode == 0, _cli_output(proc)
    assert "LISTED" in _cli_output(proc)


@pytest.mark.smoke
def test_smoke_run_injects_env_without_printing_secret(tmp_path: Path) -> None:
    """Resolver + run: FOO injected; child exits 0 without echoing secret to stdout."""
    home = _fake_home(tmp_path)
    project = tmp_path / "runproj"
    project.mkdir()
    pv = project / ".ownlock" / "vault.db"
    pv.parent.mkdir(parents=True)
    with VaultManager.init_vault(pv, PASS) as vm:
        vm.set("MYKEY", "ultra-secret-do-not-print")

    env_file = project / ".env"
    env_file.write_text('FOO=vault("MYKEY")\n', encoding="utf-8")

    code = (
        "import os, sys\n"
        "v = os.environ.get('FOO', '')\n"
        "sys.exit(0 if v == 'ultra-secret-do-not-print' else 1)\n"
    )
    proc = _run_cli(
        "run",
        "-f",
        ".env",
        "--",
        sys.executable,
        "-c",
        code,
        cwd=project,
        home=home,
    )
    assert proc.returncode == 0, _cli_output(proc)


@pytest.mark.smoke
def test_smoke_mcp_version_matches_package() -> None:
    """MCP tool reports same version as package metadata (requires ownlock[mcp])."""
    pytest.importorskip("mcp.server.fastmcp", reason="ownlock[mcp]")
    from importlib.metadata import version as pkg_version

    from ownlock.mcp_server import ownlock_version

    assert ownlock_version() == pkg_version("ownlock")
