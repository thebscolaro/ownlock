"""Parse .env files and resolve vault() references."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ownlock import vault as _vault_module
from ownlock.vault import VaultManager

# vault() reference: "vault(" + quoted name + optional kwargs blob + ")"
# Kwargs are parsed by KWARG_RE so they may appear in any order. The outer
# match is non-greedy on the kwargs blob and rejects nested parentheses.
_VAULT_RE = re.compile(
    r'^vault\(\s*"([^"]+)"\s*(?:,\s*([^)]+?))?\s*\)$'
)
KWARG_RE = re.compile(
    r'(\w+)\s*=\s*(?:"([^"]*)"|(true|false))'
)
_SECRET_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def parse_vault_kwargs(args_str: Optional[str]) -> dict[str, str]:
    """Parse a comma-separated ``k=v`` blob from inside a ``vault(...)`` call.

    Accepts ``key="string"`` and ``key=true`` / ``key=false`` (for the
    ``project`` / ``global`` flags). Order is irrelevant. Unknown tokens are
    silently ignored so a stray comma doesn't turn a resolve into a hard
    error; missing required keys still surface as KeyErrors at lookup time.

    Shared by ``ownlock.resolver`` (for ``.env`` ``vault(...)`` calls) and
    ``ownlock.templates`` (for ``{{vault(...)}}`` calls), so both surfaces
    accept identical kwarg syntax.
    """
    if not args_str:
        return {}
    kwargs: dict[str, str] = {}
    for m in KWARG_RE.finditer(args_str):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        kwargs[key] = val
    return kwargs


class VaultLookup:
    """Resolve vault references with lazy connections to project + global vaults.

    Shared by the .env resolver and the template renderer so both use identical
    vault-selection semantics:

    - ``global=True`` always forces the global vault.
    - Otherwise if a project vault exists and either ``project=True`` or no flag
      is set, the project vault is used.
    - Otherwise the global vault is used.
    """

    def __init__(self, passphrase: str) -> None:
        self._passphrase = passphrase
        self._project_path = VaultManager.find_project_vault()
        self._global_vm: Optional[VaultManager] = None
        self._project_vm: Optional[VaultManager] = None

    def lookup(
        self,
        name: str,
        env: str = "default",
        *,
        project: Optional[bool] = None,
        use_global: Optional[bool] = None,
    ) -> str:
        if not _SECRET_NAME_RE.match(name):
            raise KeyError(f"Invalid secret name '{name}' in vault() reference")

        if use_global is True:
            pick_project = False
        elif self._project_path and (project is True or (project is None and use_global is None)):
            pick_project = True
        else:
            pick_project = False

        if pick_project:
            if self._project_vm is None:
                # pick_project can only be True when self._project_path is truthy,
                # but we re-check at runtime so this is safe under python -O where
                # asserts are stripped.
                if self._project_path is None:
                    raise RuntimeError(
                        "project vault path unexpectedly missing after selection"
                    )
                self._project_vm = VaultManager(self._project_path, self._passphrase)
                self._project_vm.open()
            value = self._project_vm.get(name, env)
        else:
            if self._global_vm is None:
                self._global_vm = VaultManager(
                    _vault_module.GLOBAL_VAULT_PATH, self._passphrase
                )
                self._global_vm.open()
            value = self._global_vm.get(name, env)

        if value is None:
            raise KeyError(f"Secret '{name}' (env={env}) not found in vault")
        return value

    def close(self) -> None:
        if self._global_vm is not None:
            self._global_vm.close()
            self._global_vm = None
        if self._project_vm is not None:
            self._project_vm.close()
            self._project_vm = None

    def __enter__(self) -> "VaultLookup":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def collect_vault_refs(env_path: Path) -> list[dict[str, Optional[str]]]:
    """Scan *env_path* and return every ``vault(...)`` reference it contains.

    Each entry is a dict with keys ``key``, ``env_arg`` (the explicit
    ``env="..."`` from the call, or ``None``), ``project``, ``use_global``.
    Used by ``ownlock import`` (vault_refs flow) to figure out which secrets a project's
    ``.env`` expects without decrypting anything.
    """
    refs: list[dict[str, Optional[str]]] = []
    if not env_path.exists():
        return refs
    for line in env_path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        _, _, raw_value = stripped.partition("=")
        match = _VAULT_RE.match(raw_value.strip())
        if not match:
            continue
        kwargs = parse_vault_kwargs(match.group(2))
        refs.append(
            {
                "key": match.group(1),
                "env_arg": kwargs.get("env"),
                "project": kwargs.get("project"),
                "use_global": kwargs.get("global"),
            }
        )
    return refs


def resolve_env_file(
    env_path: Path,
    passphrase: str,
    *,
    env: str = "default",
) -> tuple[dict[str, str], list[str]]:
    """Resolve a .env file, replacing vault() refs with decrypted values.

    Returns (resolved_vars, secret_names) where secret_names lists the
    env var names whose values came from the vault (for redaction).
    """
    resolved: dict[str, str] = {}
    secret_names: list[str] = []

    if not env_path.exists():
        return resolved, secret_names

    with VaultLookup(passphrase) as lookup:
        for line in env_path.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if "=" not in stripped:
                continue

            key, _, raw_value = stripped.partition("=")
            key = key.strip()
            raw_value = raw_value.strip()

            match = _VAULT_RE.match(raw_value)
            if match:
                vault_key = match.group(1)
                kwargs = parse_vault_kwargs(match.group(2))

                vault_env = kwargs.get("env", env)
                project_flag = kwargs.get("project")
                global_flag = kwargs.get("global")

                project_bool: Optional[bool] = (
                    (project_flag == "true") if project_flag else None
                )
                global_bool: Optional[bool] = (
                    (global_flag == "true") if global_flag else None
                )

                value = lookup.lookup(
                    vault_key,
                    vault_env,
                    project=project_bool,
                    use_global=global_bool,
                )
                resolved[key] = value
                secret_names.append(key)
            else:
                resolved[key] = raw_value

    return resolved, secret_names
