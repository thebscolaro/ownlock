"""Tests for ownlock.crypto — AES-256-GCM encrypt/decrypt."""

import base64
import os

import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ownlock.crypto import (
    KDF_ITERATIONS_CURRENT,
    KDF_ITERATIONS_LEGACY,
    NONCE_LEN,
    SALT_LEN,
    decrypt,
    derive_key,
    encrypt,
    token_iterations,
)


PASSPHRASE = "test-pass"


class TestEncryptDecryptRoundtrip:
    def test_basic_roundtrip(self):
        plaintext = "hello world"
        token = encrypt(plaintext, PASSPHRASE)
        assert decrypt(token, PASSPHRASE) == plaintext

    def test_empty_string(self):
        token = encrypt("", PASSPHRASE)
        assert decrypt(token, PASSPHRASE) == ""

    def test_unicode_text(self):
        plaintext = "café ☕ naïve 日本語 🎉"
        token = encrypt(plaintext, PASSPHRASE)
        assert decrypt(token, PASSPHRASE) == plaintext


class TestDifferentPassphrases:
    def test_different_passphrases_produce_different_ciphertexts(self):
        plaintext = "same-secret"
        token_a = encrypt(plaintext, "pass-a")
        token_b = encrypt(plaintext, "pass-b")
        assert token_a != token_b

    def test_wrong_passphrase_raises(self):
        token = encrypt("secret", "correct-pass")
        with pytest.raises(InvalidTag):
            decrypt(token, "wrong-pass")


class TestRandomness:
    def test_two_encryptions_differ(self):
        plaintext = "deterministic?"
        token1 = encrypt(plaintext, PASSPHRASE)
        token2 = encrypt(plaintext, PASSPHRASE)
        assert token1 != token2
        assert decrypt(token1, PASSPHRASE) == plaintext
        assert decrypt(token2, PASSPHRASE) == plaintext


class TestTokenFormat:
    def test_encrypt_writes_v2_token_with_current_iterations(self):
        token = encrypt("hello", PASSPHRASE)
        assert token_iterations(token) == KDF_ITERATIONS_CURRENT

    def test_v1_legacy_token_decrypts(self):
        """A hand-crafted v1 token (no prefix) must still decrypt."""
        plaintext = "legacy-data"
        salt = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        key = derive_key(PASSPHRASE, salt, KDF_ITERATIONS_LEGACY)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
        v1_token = base64.b64encode(salt + nonce + ct).decode("ascii")

        assert decrypt(v1_token, PASSPHRASE) == plaintext
        assert token_iterations(v1_token) == KDF_ITERATIONS_LEGACY

    def test_v2_with_custom_iterations_roundtrips(self):
        token = encrypt("x", PASSPHRASE, iterations=210_000)
        assert token_iterations(token) == 210_000
        assert decrypt(token, PASSPHRASE) == "x"
