"""Parse .env files and resolve vault() references."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ownlock.vault import VaultManager, GLOBAL_VAULT_PATH

_VAULT_RE = re.compile(
    r'^vault\(\s*"([^"]+)"'       # vault("key-name"
    r'(?:\s*,\s*env\s*=\s*"([^"]+)")?' # optional env="prod"
    r'(?:\s*,\s*project\s*=\s*(true|false))?' # optional project=true
    r'\s*\)$'                     # )
)
_SECRET_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


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

    project_vault_path = VaultManager.find_project_vault()

    global_vm: Optional[VaultManager] = None
    project_vm: Optional[VaultManager] = None

    try:
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
                if not _SECRET_NAME_RE.match(vault_key):
                    raise KeyError(
                        f"Invalid secret name '{vault_key}' in vault() reference"
                    )
                vault_env = match.group(2) or env
                use_project = match.group(3) == "true"

                value = None
                if use_project and project_vault_path:
                    if project_vm is None:
                        project_vm = VaultManager(project_vault_path, passphrase)
                        project_vm.open()
                    value = project_vm.get(vault_key, vault_env)
                else:
                    if global_vm is None:
                        global_vm = VaultManager(GLOBAL_VAULT_PATH, passphrase)
                        global_vm.open()
                    value = global_vm.get(vault_key, vault_env)

                if value is None:
                    raise KeyError(
                        f"Secret '{vault_key}' (env={vault_env}) not found in vault"
                    )
                resolved[key] = value
                secret_names.append(key)
            else:
                resolved[key] = raw_value

    finally:
        if global_vm:
            global_vm.close()
        if project_vm:
            project_vm.close()

    return resolved, secret_names
