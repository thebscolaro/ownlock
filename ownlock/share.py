"""Encrypted secret bundles for sharing vault contents between machines.

Used by ``ownlock share`` (export) and ``ownlock import-share`` (import).
The bundle file is JSON for inspectability; only the ``ciphertext`` field
contains the actual secret material, encrypted with AES-256-GCM keyed off a
passphrase via PBKDF2-HMAC-SHA256.

The bundle passphrase is **independent** from the vault passphrase: a team
might want to share secrets without distributing the passphrase that unlocks
each developer's local vault.

Bundle wire format (JSON object, base64 fields are ASCII-safe):

.. code-block:: json

    {
      "ownlock_bundle_version": 1,
      "kdf": "PBKDF2-HMAC-SHA256",
      "kdf_iterations": 600000,
      "kdf_salt": "<base64 16 bytes>",
      "nonce":    "<base64 12 bytes>",
      "ciphertext": "<base64 of AES-GCM(JSON({secrets: [...]}))>",
      "created_at": "<ISO 8601>"
    }
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, UTC
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ownlock.crypto import (
    KDF_ITERATIONS_CURRENT,
    NONCE_LEN,
    SALT_LEN,
    derive_key,
)

BUNDLE_VERSION = 1


def export_bundle(
    secrets: list[dict[str, str]],
    passphrase: str,
    *,
    iterations: int = KDF_ITERATIONS_CURRENT,
) -> str:
    """Encode *secrets* into an encrypted bundle string.

    Each entry in *secrets* must have ``name``, ``env``, and ``value`` keys.
    """
    payload = json.dumps({"secrets": secrets}, ensure_ascii=False).encode("utf-8")
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(passphrase, salt, iterations)
    ciphertext = AESGCM(key).encrypt(nonce, payload, None)
    return json.dumps(
        {
            "ownlock_bundle_version": BUNDLE_VERSION,
            "kdf": "PBKDF2-HMAC-SHA256",
            "kdf_iterations": iterations,
            "kdf_salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "created_at": datetime.now(UTC).isoformat(),
        },
        indent=2,
    )


def import_bundle(text: str, passphrase: str) -> list[dict[str, str]]:
    """Decode and decrypt a bundle. Returns the list of secrets.

    Raises ``ValueError`` if the bundle format is malformed or the version is
    not supported. Authentication failure (wrong passphrase / tampered
    ciphertext) raises :class:`cryptography.exceptions.InvalidTag`.
    """
    try:
        bundle: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Bundle is not valid JSON: {e}") from e

    if not isinstance(bundle, dict):
        raise ValueError("Bundle must be a JSON object.")
    version = bundle.get("ownlock_bundle_version")
    if version != BUNDLE_VERSION:
        raise ValueError(
            f"Unsupported bundle version {version!r}; expected {BUNDLE_VERSION}."
        )

    try:
        salt = base64.b64decode(bundle["kdf_salt"])
        nonce = base64.b64decode(bundle["nonce"])
        ciphertext = base64.b64decode(bundle["ciphertext"])
        iterations = int(bundle["kdf_iterations"])
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"Bundle missing required field or malformed: {e}") from e

    key = derive_key(passphrase, salt, iterations)
    payload = AESGCM(key).decrypt(nonce, ciphertext, None)
    data = json.loads(payload.decode("utf-8"))

    secrets = data.get("secrets")
    if not isinstance(secrets, list):
        raise ValueError("Decrypted bundle missing 'secrets' list.")
    for entry in secrets:
        if not (
            isinstance(entry, dict)
            and isinstance(entry.get("name"), str)
            and isinstance(entry.get("env"), str)
            and isinstance(entry.get("value"), str)
        ):
            raise ValueError("Bundle contains a malformed secret entry.")
    return secrets
