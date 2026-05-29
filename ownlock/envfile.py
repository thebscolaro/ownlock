"""Parse / classify / import / rewrite ``.env`` files.

Entry points used by ``ownlock import`` and ``ownlock rewrite-env``:

* :func:`iter_env_kv_pairs` — generator of ``(key, value)`` tuples from a
  ``.env`` file. Skips comments, blank lines, lines without ``=``, and keys
  that fail :func:`ownlock.paths.is_valid_secret_name`.
* :func:`classify_env_file` — decide whether a file should be treated as
  ``"vault_refs"`` (already contains ``vault(...)`` references; we should
  prompt for missing keys) or ``"seed"`` (plain ``KEY=VALUE``; we should
  add the values to the vault). Drives ``ownlock import``'s auto-routing.
* :func:`import_env_file_into_vault` — pump KV pairs straight into a
  :class:`VaultManager`. Used by ``import``'s seed flow.
* :func:`rewrite_env_lines_to_vault_syntax` — rewrite known keys to
  ``vault("KEY"[, env="..."])``. Used by both ``import --rewrite`` and
  ``rewrite-env`` so they produce identical output for the same input.
* :func:`format_vault_expr` — single source of truth for how a
  ``vault(...)`` reference is spelled in generated env / template content,
  shared with ``ownlock export --example``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ownlock.paths import is_valid_secret_name
from ownlock.vault import VaultManager

# Loose pattern kept for documentation; classification uses
# :func:`ownlock.resolver.collect_vault_refs` for accuracy.
_VAULT_CALL_HINT = re.compile(r"\bvault\s*\(")


def classify_env_file(env_file: Path) -> str:
    """Return ``"vault_refs"``, ``"seed"``, or ``"empty"``.

    Drives ``ownlock import``'s automatic routing:

    * ``"vault_refs"`` — file has at least one ``vault(...)`` reference.
      The file is what a teammate sees after cloning a repo that's already
      on ownlock; we should compute which references aren't in their vault
      yet and prompt only for those.
    * ``"seed"`` — file has plain ``KEY=VALUE`` pairs but no ``vault(...)``
      calls. The author wants to seed their fresh vault from this file.
    * ``"empty"`` — neither shape applies; nothing useful to do.

    Mixed files (both vault refs *and* loose ``KEY=VALUE`` lines) classify
    as ``"vault_refs"``: the vault references are the source of truth, and
    any plain values are likely leftover or unrelated config that should be
    edited by hand rather than swept into the vault wholesale.
    """
    if not env_file.exists():
        return "empty"
    from ownlock.resolver import collect_vault_refs

    if collect_vault_refs(env_file):
        return "vault_refs"
    for _ in iter_env_kv_pairs(env_file):
        return "seed"
    return "empty"


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


# Default env files ``ownlock import`` considers when no path was given.
DEFAULT_ENV_FILE_CANDIDATES: tuple[str, ...] = (
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
)
