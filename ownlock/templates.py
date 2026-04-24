"""Render config files with ``{{vault(...)}}`` references.

This is the companion to the ``.env`` + ``vault()`` flow for apps whose
configuration is consumed as files on disk (classic ASP.NET ``web.config``,
``appsettings.*.json``, kubeconfig, etc.) rather than as environment variables.

A template is any file named ``<stem>.template.<ext>``; it renders to
``<stem>.<ext>`` in the same directory. Inside, ``{{vault("name")}}`` is
replaced with the decrypted value from the vault, **escaped for the output
file's format** (JSON, XML, YAML, TOML, INI, .env, shell, HCL). Per-reference
overrides are available via ``format="json"`` etc.; pass ``format="raw"`` or
the CLI ``--raw`` flag to insert values verbatim.

Supported kwargs inside ``{{vault(...)}}``:

- ``env="production"`` — vault environment.
- ``project=true`` / ``project=false`` — force project vault.
- ``global=true`` / ``global=false`` — force global vault.
- ``format="json"`` — override the auto-detected format.

Kwargs may appear in any order.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.sax.saxutils
from pathlib import Path
from typing import Callable, List, Optional

from ownlock.resolver import VaultLookup

# Outer match: {{ vault( "name" [ , ARGS ] ) }}
# ARGS is captured as a single blob and parsed by _KWARG_RE below so kwargs
# may appear in any order and we can add new kwargs without touching the regex.
_TEMPLATE_RE = re.compile(
    r'\{\{\s*vault\(\s*"([^"]+)"\s*(?:,\s*([^)]+?))?\s*\)\s*\}\}'
)
_KWARG_RE = re.compile(
    r'(\w+)\s*=\s*(?:"([^"]*)"|(true|false))'
)

_TEMPLATE_SEGMENT = "template"
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", ".ownlock"}

# Catches stray ``{{vault(`` fragments that didn't parse — e.g. a wrong quote
# style or a missing closing brace. The canonical form is always consumed by
# _TEMPLATE_RE first, so anything matching this after rendering is a sign of a
# malformed reference.
_UNMATCHED_RE = re.compile(r"\{\{\s*vault\s*\(")


# --- Format escapers -------------------------------------------------------
#
# Each function takes a raw secret value and returns the form safe to insert
# INSIDE a string literal of the target format. The user writes the template
# with their own quote characters around the placeholder; the escaper handles
# the interior only.


def _escape_json(value: str) -> str:
    """Escape for inside a JSON/TOML/YAML/HCL double-quoted string."""
    return json.dumps(value, ensure_ascii=False)[1:-1]


def _escape_xml(value: str) -> str:
    """Escape for XML text content and attribute values (quotes included)."""
    return xml.sax.saxutils.escape(
        value, {'"': "&quot;", "'": "&apos;"}
    )


def _escape_ini(value: str) -> str:
    """Escape for INI / Java properties value position.

    Java .properties semantics: backslash and newlines must be escaped.
    """
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _escape_env(value: str) -> str:
    """Escape for inside a double-quoted value in a ``.env`` file."""
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _escape_shell(value: str) -> str:
    """Escape for inside single-quoted shell string (``'...'``).

    The only character that needs special handling is the single quote itself,
    which is terminated and reopened around an escaped literal.
    """
    return value.replace("'", "'\\''")


def _escape_raw(value: str) -> str:
    return value


_ESCAPERS: dict[str, Callable[[str], str]] = {
    "json": _escape_json,
    "toml": _escape_json,
    "yaml": _escape_json,
    "hcl": _escape_json,
    "xml": _escape_xml,
    "ini": _escape_ini,
    "env": _escape_env,
    "shell": _escape_shell,
    "raw": _escape_raw,
}


_FORMAT_BY_EXT: dict[str, str] = {
    ".json": "json",
    ".jsonc": "json",
    ".xml": "xml",
    ".config": "xml",
    ".xaml": "xml",
    ".csproj": "xml",
    ".resx": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".properties": "ini",
    ".env": "env",
    ".envrc": "env",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".tf": "hcl",
    ".tfvars": "hcl",
}


def detect_format(dst: Path) -> str:
    """Pick an escape format for *dst* based on its extension. Defaults to ``raw``."""
    return _FORMAT_BY_EXT.get(dst.suffix.lower(), "raw")


def _parse_kwargs(args_str: str) -> dict[str, str]:
    """Parse a comma-separated ``k=v`` kwargs blob.

    Accepts ``k="string"`` and ``k=true``/``k=false`` (for project/global
    flags). Unrecognized tokens are silently ignored rather than raising so
    a stray comma doesn't turn a render into a hard error.
    """
    kwargs: dict[str, str] = {}
    if not args_str:
        return kwargs
    for m in _KWARG_RE.finditer(args_str):
        k = m.group(1)
        v = m.group(2) if m.group(2) is not None else m.group(3)
        kwargs[k] = v
    return kwargs


def render_text(
    text: str,
    lookup: VaultLookup,
    *,
    default_env: str = "default",
    default_format: str = "raw",
) -> tuple[str, int]:
    """Replace every ``{{vault(...)}}`` in *text*. Returns ``(rendered, count)``.

    Raises ``KeyError`` if a reference is invalid, the secret is missing, or
    the ``format="..."`` override names a format that isn't supported.
    """
    count = 0

    def _replace(match: re.Match[str]) -> str:
        nonlocal count
        key = match.group(1)
        args_str = match.group(2) or ""
        kwargs = _parse_kwargs(args_str)

        env = kwargs.get("env", default_env)
        project_flag = kwargs.get("project")
        global_flag = kwargs.get("global")
        fmt = kwargs.get("format", default_format)

        if fmt not in _ESCAPERS:
            raise KeyError(
                f"Unknown format '{fmt}' in vault() reference (key='{key}'). "
                f"Supported: {', '.join(sorted(_ESCAPERS))}."
            )

        project: Optional[bool] = (project_flag == "true") if project_flag else None
        use_global: Optional[bool] = (global_flag == "true") if global_flag else None

        value = lookup.lookup(key, env, project=project, use_global=use_global)
        count += 1
        return _ESCAPERS[fmt](value)

    return _TEMPLATE_RE.sub(_replace, text), count


def template_output_path(template_path: Path) -> Path:
    """Convert ``foo.template.ext`` to ``foo.ext`` (same directory)."""
    parts = template_path.name.split(".")
    if _TEMPLATE_SEGMENT not in parts:
        raise ValueError(
            f"{template_path} is not a template file (missing '.template.' segment)"
        )
    new_parts: list[str] = []
    removed = False
    for part in parts:
        if not removed and part == _TEMPLATE_SEGMENT:
            removed = True
            continue
        new_parts.append(part)
    return template_path.with_name(".".join(new_parts))


def discover_templates(root: Path) -> list[Path]:
    """Find all ``*.template.*`` files under *root*.

    Uses ``os.walk(..., followlinks=False)`` to avoid following directory
    symlinks (which could escape the project tree or create cycles). Skips
    common VCS / build dirs in-place and symlinked files. Results are
    returned in sorted order for stable output.
    """
    results: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if fnmatch.fnmatchcase(fname, "*.template.*"):
                candidate = Path(dirpath) / fname
                if candidate.is_file() and not candidate.is_symlink():
                    results.append(candidate)
    return sorted(results)


def find_unmatched_vault_refs(text: str) -> list[tuple[int, str]]:
    """Return ``(line, excerpt)`` for ``{{vault(`` fragments left after rendering."""
    warnings: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), 1):
        if _UNMATCHED_RE.search(line):
            excerpt = line.strip()
            if len(excerpt) > 120:
                excerpt = excerpt[:117] + "..."
            warnings.append((i, excerpt))
    return warnings


def write_atomic(path: Path, content: str) -> None:
    """Write *content* to *path* atomically with restrictive permissions.

    - Writes to a sibling temp file, fsyncs, then ``os.replace`` (atomic on
      POSIX and Windows as long as source and destination share a volume).
    - Applies mode ``0o600`` on POSIX. On Windows, relies on inherited ACLs.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".ownlock-tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        if os.name == "posix":
            try:
                os.chmod(tmp_name, 0o600)
            except OSError:
                pass
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


# --- Gitignore detection ---------------------------------------------------


def _git_check_ignore(path: Path) -> Optional[bool]:
    """Ask ``git check-ignore`` whether *path* is ignored.

    Returns ``True`` / ``False`` when git answered authoritatively,
    or ``None`` if git is not available, the path is not inside a
    git repo, or the tool failed for any other reason.

    Uses ``subprocess.run`` with a literal argv list (no shell) and a short
    timeout so a hung git cannot stall ownlock.
    """
    git = shutil.which("git")
    if not git:
        return None

    probe_dir = path.parent if path.parent.exists() else Path.cwd()

    try:
        repo_check = subprocess.run(  # noqa: S603 (argv list, no shell)
            [git, "-C", str(probe_dir), "rev-parse", "--git-dir"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if repo_check.returncode != 0:
        return None

    try:
        result = subprocess.run(  # noqa: S603 (argv list, no shell)
            [git, "-C", str(probe_dir), "check-ignore", "-q", "--no-index", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    # Documented exit codes: 0 = ignored, 1 = not ignored, 128 = fatal error.
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


def _is_gitignored_fnmatch(path: Path, *, start_dir: Optional[Path] = None) -> bool:
    """Fallback best-effort gitignore check using fnmatch.

    Walks up from the file's directory to *start_dir* (or filesystem root),
    reading each ``.gitignore``. Matches by filename and by the path relative
    to each gitignore's directory, using simple fnmatch semantics. Full
    gitignore syntax (negation, anchored ``**`` patterns, ``.git/info/exclude``)
    is not supported here; use the git-backed path instead when possible.
    """
    try:
        abspath = path.resolve()
    except OSError:
        return False

    stop_at = (start_dir or Path.cwd()).resolve()

    current = abspath.parent
    while True:
        gi = current / ".gitignore"
        if gi.exists():
            try:
                rel = abspath.relative_to(current)
                rel_str = str(rel).replace(os.sep, "/")
            except ValueError:
                rel_str = ""

            try:
                lines = gi.read_text(encoding="utf-8").splitlines()
            except OSError:
                lines = []

            for line in lines:
                raw = line.strip()
                if not raw or raw.startswith("#") or raw.startswith("!"):
                    continue
                pat = raw.rstrip("/").lstrip("/")
                if not pat:
                    continue
                if fnmatch.fnmatch(abspath.name, pat):
                    return True
                if rel_str and (
                    fnmatch.fnmatch(rel_str, pat)
                    or fnmatch.fnmatch(rel_str, f"{pat}/*")
                    or rel_str.startswith(pat + "/")
                    or rel_str == pat
                ):
                    return True
                if raw.endswith("/") and any(part == pat for part in abspath.parts):
                    return True

        if current == stop_at or current.parent == current:
            break
        current = current.parent

    return False


def is_path_gitignored(path: Path, *, start_dir: Optional[Path] = None) -> bool:
    """Return True if *path* is covered by a gitignore rule.

    Prefers ``git check-ignore`` (full gitignore semantics: negation, anchored
    patterns, nested ``.gitignore``, ``.git/info/exclude``, global ignore).
    Falls back to a best-effort fnmatch scan when git is unavailable or the
    path isn't inside a repository.
    """
    authoritative = _git_check_ignore(path)
    if authoritative is not None:
        return authoritative
    return _is_gitignored_fnmatch(path, start_dir=start_dir)


def render_file(
    src: Path,
    dst: Path,
    lookup: VaultLookup,
    *,
    default_env: str = "default",
    raw: bool = False,
) -> int:
    """Render *src* to *dst* using *lookup*. Returns the number of refs replaced.

    Unless *raw* is True, the default format is auto-detected from the
    extension of *dst* via :func:`detect_format`. Per-reference
    ``format="..."`` overrides always win.
    """
    text = src.read_text(encoding="utf-8")
    default_format = "raw" if raw else detect_format(dst)
    rendered, count = render_text(
        text, lookup, default_env=default_env, default_format=default_format
    )
    write_atomic(dst, rendered)
    return count
