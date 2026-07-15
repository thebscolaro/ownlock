"""Bridge vault secrets to GitHub Actions secrets via the ``gh`` CLI.

Push-only in the value direction: secret values travel to GitHub over
``gh secret set`` **stdin** (never argv, so they can't leak via process
listings). GitHub never returns secret values, so "pull" is a names-only
diff against ``gh secret list``.

No new dependencies — everything shells out to the user's authenticated
``gh`` binary and fails cleanly when it's missing or logged out.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Optional

from ownlock.paths import SECRET_NAME_RE

# owner/name — keep characters that cannot become new argv flags.
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GH_ENV_RE = re.compile(r"^[A-Za-z0-9_./-]+$")


class GhSyncError(RuntimeError):
    """User-facing failure (gh missing, unauthenticated, command failed)."""


def find_gh() -> Optional[str]:
    """Absolute path to the ``gh`` binary, or None."""
    return shutil.which("gh")


def require_gh() -> str:
    """Return the gh path or raise with an actionable message."""
    gh = find_gh()
    if gh is None:
        raise GhSyncError(
            "GitHub CLI (gh) not found — install it from https://cli.github.com "
            "and run `gh auth login`."
        )
    return gh


def check_authenticated(gh: str) -> None:
    """Raise unless ``gh auth status`` reports a logged-in account."""
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no user input
            [gh, "auth", "status"],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GhSyncError(f"could not run `gh auth status`: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise GhSyncError(
            "gh is not authenticated — run `gh auth login` first."
            + (f"\n{detail}" if detail else "")
        )


def validate_sync_targets(
    name: Optional[str] = None,
    *,
    repo: Optional[str] = None,
    gh_env: Optional[str] = None,
) -> None:
    """Reject values that could be misparsed as ``gh`` flags or invalid names."""
    if name is not None:
        if not SECRET_NAME_RE.match(name) or name.startswith("-"):
            raise GhSyncError(
                f"invalid secret name {name!r} — use letters, digits, _ or -"
            )
    if repo is not None:
        if not repo or repo.startswith("-") or not _REPO_RE.match(repo):
            raise GhSyncError(
                f"invalid --repo {repo!r} — expected owner/name "
                "(alphanumeric, ., _, -)"
            )
    if gh_env is not None:
        if not gh_env or gh_env.startswith("-") or not _GH_ENV_RE.match(gh_env):
            raise GhSyncError(
                f"invalid --gh-env {gh_env!r} — use letters, digits, _, ., /, -"
            )


def _repo_env_args(repo: Optional[str], gh_env: Optional[str]) -> list[str]:
    validate_sync_targets(repo=repo, gh_env=gh_env)
    args: list[str] = []
    if repo:
        args += ["--repo", repo]
    if gh_env:
        args += ["--env", gh_env]
    return args


def push_secret(
    gh: str,
    name: str,
    value: str,
    *,
    repo: Optional[str] = None,
    gh_env: Optional[str] = None,
) -> None:
    """Set one GitHub Actions secret, piping the value via stdin."""
    validate_sync_targets(name, repo=repo, gh_env=gh_env)
    argv = [gh, "secret", "set", name] + _repo_env_args(repo, gh_env)
    try:
        proc = subprocess.run(  # noqa: S603 — value on stdin, never argv
            argv,
            input=value.encode("utf-8"),
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GhSyncError(f"failed to run gh secret set {name}: {exc}") from exc
    if proc.returncode != 0:
        # Truncate stderr — never echo a long blob that might echo the body.
        detail = proc.stderr.decode("utf-8", errors="replace").strip()[:400]
        raise GhSyncError(f"gh secret set {name} failed: {detail or 'unknown error'}")


def list_remote_secret_names(
    gh: str,
    *,
    repo: Optional[str] = None,
    gh_env: Optional[str] = None,
) -> list[str]:
    """Names of GitHub Actions secrets (values are not retrievable by design)."""
    argv = [gh, "secret", "list", "--json", "name"] + _repo_env_args(repo, gh_env)
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv plus validated options
            argv,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GhSyncError(f"failed to run gh secret list: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()[:400]
        raise GhSyncError(f"gh secret list failed: {detail or 'unknown error'}")
    try:
        rows = json.loads(proc.stdout.decode("utf-8", errors="replace") or "[]")
    except json.JSONDecodeError as exc:
        raise GhSyncError("gh secret list returned unparseable JSON") from exc
    return sorted(
        row["name"] for row in rows if isinstance(row, dict) and isinstance(row.get("name"), str)
    )
