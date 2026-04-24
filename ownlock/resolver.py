"""Parse .env files and resolve vault() references."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ownlock.vault import VaultManager, GLOBAL_VAULT_PATH

# Pattern: vault("key"[, env="envname"][, project=true|false|global=true|false])
_VAULT_RE = re.compile(
    r'^vault\(\s*"([^"]+)"'  # vault("key-name"
    r'(?:\s*,\s*env\s*=\s*"([^"]+)")?'  # optional env="prod"
    r'(?:\s*,\s*(?:project\s*=\s*(true|false)'  # optional project=true/false
    r'|global\s*=\s*(true|false)))?'  # or global=true/false
    r'\s*\)$'  # )
)
_SECRET_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


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
                self._global_vm = VaultManager(GLOBAL_VAULT_PATH, self._passphrase)
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
                vault_env = match.group(2) or env
                project_flag = match.group(3)  # "true"/"false"/None
                global_flag = match.group(4)  # "true"/"false"/None

                project_bool: Optional[bool] = (project_flag == "true") if project_flag else None
                global_bool: Optional[bool] = (global_flag == "true") if global_flag else None

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
