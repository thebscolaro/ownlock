"""Filesystem scan for leaked secret values.

Used by ``ownlock scan`` (and the install-hook'd pre-commit). The scan walks
*directory* and reports two kinds of finding:

* **Leaked-value findings**: a file whose contents include a current vault
  value verbatim. Reported as ``(path, line_number, secret_name)``; the value
  itself is never printed.
* **Legacy backups**: ``*.ownlock.bak`` files predating the 0.2.0 backup
  relocation. Even if the values inside no longer match the live vault, the
  filename pattern alone is worth surfacing so the user can clean up.

Designed to be cheap to run in a pre-commit hook on a typical repo:

* Skips known noisy directories (``.git``, ``node_modules`` …) up front.
* Skips files larger than a configurable cap before reading them, so
  binaries / build artifacts don't pull megabytes through the linear value
  check.
* Caps the total file count and recursion depth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ownlock.backups import LEGACY_BACKUP_SUFFIX

DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_DEPTH = 20
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB — skip huge files before reading

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", ".ownlock", ".env"}
_SKIP_EXTENSIONS = {
    ".db",
    ".sqlite",
    ".pyc",
    ".whl",
    ".tar",
    ".gz",
    ".zip",
    ".png",
    ".jpg",
}


def _should_skip_path(file_path: Path) -> bool:
    """Return True if *file_path* should be excluded from the value scan."""
    parts = file_path.parts
    if not any(part in _SKIP_DIRS for part in parts):
        return False
    # Plaintext env backups live under .ownlock/backups/ — scan those even
    # though the parent .ownlock/ dir is otherwise skipped (vault.db, etc.).
    if ".ownlock" in parts and "backups" in parts:
        try:
            backups_idx = parts.index("backups")
            return backups_idx != len(parts) - 2
        except ValueError:
            pass
    return True


@dataclass
class ScanFinding:
    """One file/line that contains a vault value."""

    path: Path
    line_number: int
    secret_name: str


@dataclass
class ScanResult:
    """Aggregate output of a scan run."""

    findings: list[ScanFinding] = field(default_factory=list)
    legacy_backups: list[Path] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def has_leak(self) -> bool:
        """True if anything worth blocking a commit for was found."""
        return bool(self.findings) or bool(self.legacy_backups)


def scan_directory(
    directory: Path,
    secrets: dict[str, str],
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> ScanResult:
    """Walk *directory* looking for vault values in plaintext.

    *secrets* is a ``{name: value}`` map of decrypted vault entries. The
    scanner returns a structured :class:`ScanResult` instead of printing —
    callers (CLI / pre-commit) format it however they like.

    Legacy ``*.ownlock.bak`` files are always collected, even when *secrets*
    is empty — those backups may contain rotated secrets the live vault no
    longer holds.
    """
    result = ScanResult()
    scan_values = bool(secrets)

    for file_path in directory.rglob("*"):
        try:
            rel = file_path.relative_to(directory)
            depth = len(rel.parts) - 1 if rel.parts else 0
        except ValueError:
            depth = 0
        if depth > max_depth or not file_path.is_file():
            continue

        if file_path.name.endswith(LEGACY_BACKUP_SUFFIX) and not _should_skip_path(
            file_path
        ):
            result.legacy_backups.append(file_path)

        if not scan_values or result.files_scanned >= max_files:
            continue
        if _should_skip_path(file_path):
            continue
        if file_path.name.endswith(LEGACY_BACKUP_SUFFIX):
            continue
        if file_path.suffix in _SKIP_EXTENSIONS:
            continue

        try:
            if file_path.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue

        result.files_scanned += 1
        try:
            content = file_path.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        lines = content.splitlines()
        for secret_name, secret_value in secrets.items():
            if secret_value and secret_value in content:
                for i, line in enumerate(lines, 1):
                    if secret_value in line:
                        result.findings.append(
                            ScanFinding(
                                path=file_path,
                                line_number=i,
                                secret_name=secret_name,
                            )
                        )

    return result


def is_dangerous_scan_root(directory: Path) -> bool:
    """Return True if *directory* is a filesystem root we shouldn't scan blindly.

    Posix ``/`` and Windows drive roots (``C:\\``, ``D:\\``) qualify. Used by
    the CLI to gate an extra confirmation prompt before ``ownlock scan /``.
    """
    try:
        resolved = directory.resolve()
    except OSError:
        return False
    if resolved == resolved.parent:
        return True
    return resolved == Path("/")
