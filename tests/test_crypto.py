"""Tests for ownlock.crypto — AES-256-GCM encrypt/decrypt."""

import pytest

from cryptography.exceptions import InvalidTag

from ownlock.crypto import encrypt, decrypt


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
