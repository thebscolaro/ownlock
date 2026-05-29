"""AES-256-GCM encryption for ownlock vault secrets.

Token formats:

* **v1** (legacy, written by ownlock < 0.2.0): base64 of
  ``salt(16) | nonce(12) | ciphertext+tag``. Always uses 200 000 PBKDF2-SHA256
  iterations.
* **v2** (current): base64 of
  ``"v2"(2) | iterations(uint32 BE) | salt(16) | nonce(12) | ciphertext+tag``.
  The iteration count travels with the ciphertext so a vault can hold a mix of
  v1 and v2 tokens during a partial migration; ``decrypt`` auto-detects.

``encrypt`` always writes v2 with the current default iterations (600 000,
matching OWASP guidance for PBKDF2-SHA256). Older tokens keep decrypting until
``ownlock rekey`` re-encrypts them.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

# Iteration counts:
#   - LEGACY: only used to decrypt v1 tokens written before ownlock 0.2.0.
#   - CURRENT: default for new encrypts; raised to match OWASP 2023 guidance
#     for PBKDF2-SHA256.
KDF_ITERATIONS_LEGACY = 200_000
KDF_ITERATIONS_CURRENT = 600_000
# Sanity cap for v2 tokens — rejects corrupt/malicious DB rows that would
# trigger unbounded PBKDF2 work on every get/decrypt.
_MAX_KDF_ITERATIONS = 2_000_000

# Domain-separated salt for deriving the HMAC key used to index secrets by
# (name, env) without storing plaintext names in SQLite.
_NAME_LOOKUP_KEY_SALT = b"ownlock-v3-name-lookup-key-v1"

# Public alias kept for back-compat with anything that imported this constant
# from older versions; the real default is KDF_ITERATIONS_CURRENT.
KDF_ITERATIONS = KDF_ITERATIONS_CURRENT

_V2_PREFIX = b"v2"


def derive_key(passphrase: str, salt: bytes, iterations: int = KDF_ITERATIONS_CURRENT) -> bytes:
    """Derive a 256-bit key from a passphrase and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(plaintext: str, passphrase: str, *, iterations: int = KDF_ITERATIONS_CURRENT) -> str:
    """Encrypt *plaintext* and return a base64-encoded v2 token.

    A fresh random salt and nonce are generated for every call. *iterations*
    is embedded in the token so future ``decrypt`` calls don't need to know
    what default was in effect when the value was written.
    """
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(passphrase, salt, iterations)
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    body = (
        _V2_PREFIX
        + iterations.to_bytes(4, "big")
        + salt
        + nonce
        + ciphertext_and_tag
    )
    return base64.b64encode(body).decode("ascii")


def decrypt(token: str, passphrase: str) -> str:
    """Decrypt a base64-encoded token. Auto-detects v1 vs v2 format."""
    raw = base64.b64decode(token)
    if raw[:2] == _V2_PREFIX:
        iterations = int.from_bytes(raw[2:6], "big")
        if iterations <= 0 or iterations > _MAX_KDF_ITERATIONS:
            raise ValueError("Invalid KDF iteration count in token")
        body = raw[6:]
    else:
        iterations = KDF_ITERATIONS_LEGACY
        body = raw
    salt = body[:SALT_LEN]
    nonce = body[SALT_LEN : SALT_LEN + NONCE_LEN]
    ciphertext_and_tag = body[SALT_LEN + NONCE_LEN :]
    key = derive_key(passphrase, salt, iterations)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext_and_tag, None)
    return plaintext.decode("utf-8")


def token_iterations(token: str) -> int:
    """Return the KDF iterations embedded in *token*.

    v2 tokens carry their iteration count explicitly; v1 tokens are assumed
    to be at the legacy 200 000 default. Useful for ``rekey --upgrade-kdf``
    to skip secrets that are already at the current target.
    """
    raw = base64.b64decode(token)
    if raw[:2] == _V2_PREFIX:
        iters = int.from_bytes(raw[2:6], "big")
        if iters <= 0 or iters > _MAX_KDF_ITERATIONS:
            raise ValueError("Invalid KDF iteration count in token")
        return iters
    return KDF_ITERATIONS_LEGACY


def name_lookup_key(passphrase: str) -> bytes:
    """Derive the vault-specific HMAC key for secret-name indexing.

    Separate from value-encryption keys so name lookups never reuse a salt
    that also protects a ciphertext block. The derivation uses the current
    KDF iteration count; ``rekey`` recomputes every ``name_lookup`` when the
    passphrase rotates.
    """
    return derive_key(passphrase, _NAME_LOOKUP_KEY_SALT, KDF_ITERATIONS_CURRENT)


def secret_name_lookup(passphrase: str, name: str, env: str) -> str:
    """Return a deterministic, passphrase-bound lookup id for *(name, env)*.

    Stored as the primary key in schema v3 vaults so ``get`` / ``set`` /
    ``delete`` can find rows without persisting cleartext secret names.
    Without the passphrase the lookup ids are unlinkable to human-readable
    names.
    """
    import hmac
    import hashlib

    key = name_lookup_key(passphrase)
    msg = f"{name}\0{env}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def encrypt_name(name: str, passphrase: str) -> str:
    """Encrypt a secret name for storage (same v2 token format as values)."""
    return encrypt(name, passphrase, iterations=KDF_ITERATIONS_CURRENT)


def decrypt_name(token: str, passphrase: str) -> str:
    """Decrypt a stored secret name."""
    return decrypt(token, passphrase)
