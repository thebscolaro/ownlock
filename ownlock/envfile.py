"""Parse / import / rewrite ``.env`` files.

Three entry points used by ``ownlock import``, ``ownlock auto``, and
``ownlock rewrite-env``:

* :func:`iter_env_kv_pairs` — generator of ``(key, value)`` tuples from a
  ``.env`` file. Skips comments, blank lines, lines without ``=``, and keys
  that fail :func:`ownlock.paths.is_valid_secret_name`.
* :func:`import_env_file_into_vault` — pump those pairs straight into a
  :class:`VaultManager`. Used by ``import`` and ``auto``'s import phase.
* :func:`rewrite_env_lines_to_vault_syntax` — rewrite known keys to
  ``vault("KEY"[, env="..."])``. Used by both ``auto`` and ``rewrite-env``
  so they produce identical output for the same input.
* :func:`format_vault_expr` — single source of truth for how a
  ``vault(...)`` reference is spelled in generated env / template content,
  shared with ``ownlock export --example``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ownlock.paths import is_valid_secret_name
from ownlock.vault import VaultManager


def iter_env_kv_pairs(env_file: Path) -> Iterator[tuple[str, str]]:
    """Yield ``(key, value)`` for valid ``KEY=value`` lines in *env_file*.

    Skips:
    * empty lines
    * comments (``# ...``)
    * lines without ``=``
    * keys that don't match :data:`ownlock.paths.SECRET_NAME_RE`
    * empty values
    """
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip()
        if key and value and is_valid_secret_name(key):
            yield key, value


def import_env_file_into_vault(env_file: Path, env: str, vm: VaultManager) -> int:
    """Bulk-import KEY=VALUE lines from *env_file* into *vm*; returns count written."""
    count = 0
    for key, value in iter_env_kv_pairs(env_file):
        vm.set(key, value, env)
        count += 1
    return count


def format_vault_expr(key: str, env: str = "default") -> str:
    """Return the canonical ``vault(...)`` expression for *key* + *env*.

    Default env emits ``vault("KEY")``; non-default adds the ``env="..."``
    kwarg. Centralized so rewrite, ``--example`` exports, and any future
    template-emitting code stay in sync.
    """
    if env == "default":
        return f'vault("{key}")'
    return f'vault("{key}", env="{env}")'


def rewrite_env_lines_to_vault_syntax(
    lines: list[str],
    existing: dict[str, str],
    env: str,
) -> tuple[list[str], int]:
    """Rewrite *lines* so keys present in *existing* use ``vault()``.

    Returns ``(new_lines, changed_count)``. Comments, blank lines, invalid
    key names, lines already using ``vault(...)``, and keys not in
    *existing* are left unchanged.
    """
    new_lines: list[str] = []
    changed = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        raw_value = value.strip()
        if not is_valid_secret_name(key):
            new_lines.append(line)
            continue
        if raw_value.startswith('vault("'):
            new_lines.append(line)
            continue
        if key not in existing:
            new_lines.append(line)
            continue
        new_lines.append(f"{key}={format_vault_expr(key, env)}")
        changed += 1
    return new_lines, changed


# Default list of env files ``ownlock auto`` and ``ownlock bootstrap`` will
# consider when no -f was given. Keeps the two commands looking at the same
# set of files so user expectations match.
DEFAULT_ENV_FILE_CANDIDATES: tuple[str, ...] = (
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
)
