"""Tests for ownlock.scanner — pure scan logic, no CLI / vault coupling."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ownlock.scanner import (
    DEFAULT_MAX_FILES,
    is_dangerous_scan_root,
    scan_directory,
)


def test_finds_secret_value_with_line_number(tmp_path: Path) -> None:
    f = tmp_path / "config.txt"
    f.write_text("key=plain\npassword=longsecretvalueA\nother=ok\n")
    result = scan_directory(tmp_path, {"DB_PASS": "longsecretvalueA"})
    assert result.has_leak
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.path == f
    assert finding.line_number == 2
    assert finding.secret_name == "DB_PASS"


def test_skips_legacy_backup_pattern_and_lists_separately(tmp_path: Path) -> None:
    bak = tmp_path / ".env.ownlock.bak"
    bak.write_text("OLD_KEY=stale-value\n")
    result = scan_directory(tmp_path, {"X": "no-match-anywhere"})
    assert not result.findings
    assert bak in result.legacy_backups
    assert result.has_leak  # legacy backups alone count as a finding


def test_clean_directory_no_findings(tmp_path: Path) -> None:
    (tmp_path / "readme.md").write_text("nothing sensitive here\n")
    result = scan_directory(tmp_path, {"K": "longsecretvalueA"})
    assert result.findings == []
    assert result.legacy_backups == []
    assert not result.has_leak


def test_skips_dirs(tmp_path: Path) -> None:
    leak = tmp_path / "node_modules" / "leak.txt"
    leak.parent.mkdir()
    leak.write_text("longsecretvalueA")
    result = scan_directory(tmp_path, {"K": "longsecretvalueA"})
    assert result.findings == []


def test_scans_ownlock_backups_directory(tmp_path: Path) -> None:
    """Plaintext env backups under .ownlock/backups/ must not be skipped."""
    backup_dir = tmp_path / ".ownlock" / "backups"
    backup_dir.mkdir(parents=True)
    backup = backup_dir / ".env.20260101T000000Z.bak"
    backup.write_text("LEAKED=longsecretvalueA\n")
    result = scan_directory(tmp_path, {"API": "longsecretvalueA"})
    assert result.has_leak
    assert any(f.path == backup for f in result.findings)


def test_skips_ownlock_vault_db_but_not_backups(tmp_path: Path) -> None:
    ownlock_dir = tmp_path / ".ownlock"
    ownlock_dir.mkdir()
    vault_db = ownlock_dir / "vault.db"
    vault_db.write_text("longsecretvalueA inside sqlite\n")
    result = scan_directory(tmp_path, {"K": "longsecretvalueA"})
    assert not any(f.path == vault_db for f in result.findings)


def test_max_file_bytes_skips_oversized(tmp_path: Path) -> None:
    big = tmp_path / "big.txt"
    big.write_text("x" * 200 + "longsecretvalueA")
    result = scan_directory(
        tmp_path, {"K": "longsecretvalueA"}, max_file_bytes=100
    )
    assert result.findings == []


def test_max_files_caps_iteration(tmp_path: Path) -> None:
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_text("nothing")
    result = scan_directory(
        tmp_path, {"K": "x" * 12}, max_files=2
    )
    assert result.files_scanned <= 2


def test_empty_secrets_returns_empty_result(tmp_path: Path) -> None:
    (tmp_path / "anything.txt").write_text("data")
    result = scan_directory(tmp_path, {})
    assert result.findings == []
    assert result.files_scanned == 0


def test_default_max_files_constant_exposed() -> None:
    assert DEFAULT_MAX_FILES > 0


class TestDangerousScanRoot:
    def test_subdir_is_safe(self, tmp_path: Path) -> None:
        d = tmp_path / "proj"
        d.mkdir()
        assert is_dangerous_scan_root(d) is False

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX root")
    def test_posix_root_is_dangerous(self) -> None:
        assert is_dangerous_scan_root(Path("/")) is True
