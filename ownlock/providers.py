"""Resolve secrets from external providers (1Password, AWS, Azure)."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional


def resolve_external_secret(ref: str) -> Optional[str]:
    """Resolve *ref* when it uses an external URI scheme.

    Supported:
    - ``op://vault/item/field`` — 1Password CLI (``op read``)
    - ``aws-sm://secret-id`` or ``aws-sm://secret-id#json-key``
    - ``az-kv://vault-name/secret-name`` or ``az-kv://vault-name/secret-name#json-key``
      (Azure Key Vault via ``az keyvault secret show``)
    - ``azure-kv://...`` — alias for ``az-kv://``
    """
    if ref.startswith("op://"):
        return _resolve_op(ref[len("op://") :])
    if ref.startswith("aws-sm://"):
        return _resolve_aws_sm(ref[len("aws-sm://") :])
    if ref.startswith("az-kv://"):
        return _resolve_az_kv(ref[len("az-kv://") :])
    if ref.startswith("azure-kv://"):
        return _resolve_az_kv(ref[len("azure-kv://") :])
    raise KeyError(f"Unknown external secret reference: {ref}")


def _resolve_op(path: str) -> str:
    op = shutil.which("op")
    if not op:
        raise KeyError("1Password CLI (op) not found on PATH for op:// reference")
    proc = subprocess.run(
        [op, "read", f"op://{path}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise KeyError(f"op read failed for op://{path}: {proc.stderr.strip()}")
    return proc.stdout.rstrip("\n")


def _resolve_aws_sm(spec: str) -> str:
    aws = shutil.which("aws")
    if not aws:
        raise KeyError("AWS CLI not found on PATH for aws-sm:// reference")
    json_key: Optional[str] = None
    if "#" in spec:
        secret_id, json_key = spec.split("#", 1)
    else:
        secret_id = spec
    proc = subprocess.run(
        [aws, "secretsmanager", "get-secret-value", "--secret-id", secret_id],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise KeyError(f"aws secretsmanager get-secret-value failed: {proc.stderr.strip()}")
    payload = json.loads(proc.stdout)
    value = payload.get("SecretString") or ""
    if not value:
        binary = payload.get("SecretBinary")
        if binary:
            import base64

            try:
                value = base64.b64decode(binary).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as e:
                raise KeyError(
                    f"AWS secret '{secret_id}' SecretBinary is not valid UTF-8 text"
                ) from e
    if not value:
        raise KeyError(f"AWS secret '{secret_id}' has empty SecretString/SecretBinary")
    return _maybe_json_key(value, json_key, label=f"AWS secret '{secret_id}'")


def _resolve_az_kv(spec: str) -> str:
    """Resolve ``vault-name/secret-name`` via Azure CLI.

    Optional ``#json-key`` extracts a field when the secret value is JSON.
    """
    az = shutil.which("az")
    if not az:
        raise KeyError("Azure CLI (az) not found on PATH for az-kv:// reference")
    json_key: Optional[str] = None
    if "#" in spec:
        path, json_key = spec.split("#", 1)
    else:
        path = spec
    path = path.strip("/")
    if "/" not in path:
        raise KeyError(
            "az-kv:// references must be az-kv://<vault-name>/<secret-name>"
        )
    vault_name, secret_name = path.split("/", 1)
    if not vault_name or not secret_name or "/" in secret_name:
        raise KeyError(
            "az-kv:// references must be az-kv://<vault-name>/<secret-name>"
        )
    proc = subprocess.run(
        [
            az,
            "keyvault",
            "secret",
            "show",
            "--vault-name",
            vault_name,
            "--name",
            secret_name,
            "--query",
            "value",
            "-o",
            "tsv",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise KeyError(
            f"az keyvault secret show failed for {vault_name}/{secret_name}: "
            f"{proc.stderr.strip()}"
        )
    value = proc.stdout.rstrip("\n")
    return _maybe_json_key(
        value, json_key, label=f"Azure Key Vault secret '{vault_name}/{secret_name}'"
    )


def _maybe_json_key(value: str, json_key: Optional[str], *, label: str) -> str:
    if not json_key:
        return value
    if not value:
        raise KeyError(f"{label} is empty; cannot extract key '{json_key}'")
    try:
        data = json.loads(value)
    except json.JSONDecodeError as e:
        raise KeyError(f"{label} is not JSON; cannot extract key") from e
    if json_key not in data:
        raise KeyError(f"Key '{json_key}' not in {label}")
    return str(data[json_key])
