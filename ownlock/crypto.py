"""AES-256-GCM encryption for ownlock vault secrets.

Wire format (base64-encoded):
    salt (16 bytes) | nonce (12 bytes) | ciphertext | tag (16 bytes)

Key derivation: PBKDF2-HMAC-SHA256, 200 000 iterations.
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
KDF_ITERATIONS = 200_000


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a passphrase and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(plaintext: str, passphrase: str) -> str:
    """Encrypt *plaintext* and return a base64-encoded token.

    A fresh random salt and nonce are generated for every call.
    """
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(passphrase, salt)
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(salt + nonce + ciphertext_and_tag).decode("ascii")


def decrypt(token: str, passphrase: str) -> str:
    """Decrypt a base64-encoded token produced by :func:`encrypt`."""
    raw = base64.b64decode(token)
    salt = raw[:SALT_LEN]
    nonce = raw[SALT_LEN : SALT_LEN + NONCE_LEN]
    ciphertext_and_tag = raw[SALT_LEN + NONCE_LEN :]
    key = derive_key(passphrase, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext_and_tag, None)
    return plaintext.decode("utf-8")
