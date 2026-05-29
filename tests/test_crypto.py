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

    def test_secret_name_lookup_is_passphrase_bound(self):
        from ownlock.crypto import secret_name_lookup

        a = secret_name_lookup(PASSPHRASE, "API_KEY", "default")
        b = secret_name_lookup(PASSPHRASE, "API_KEY", "production")
        c = secret_name_lookup("other-pass", "API_KEY", "default")
        assert a != b
        assert a != c
        assert secret_name_lookup(PASSPHRASE, "API_KEY", "default") == a

    def test_encrypt_decrypt_name_roundtrip(self):
        from ownlock.crypto import decrypt_name, encrypt_name

        token = encrypt_name("MY_SECRET", PASSPHRASE)
        assert decrypt_name(token, PASSPHRASE) == "MY_SECRET"

    def test_rejects_absurd_iteration_count_in_v2_token(self):
        """Corrupt tokens must not trigger unbounded PBKDF2 work."""
        raw = b"v2" + (99_999_999).to_bytes(4, "big") + os.urandom(SALT_LEN + NONCE_LEN + 32)
        token = base64.b64encode(raw).decode("ascii")
        with pytest.raises(ValueError, match="Invalid KDF iteration"):
            decrypt(token, PASSPHRASE)
        with pytest.raises(ValueError, match="Invalid KDF iteration"):
            token_iterations(token)
