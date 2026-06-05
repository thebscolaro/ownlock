"""Tests for ownlock.passphrase — wipeable passphrase buffer."""

from ownlock.crypto import decrypt, encrypt
from ownlock.passphrase import Passphrase


class TestPassphrase:
    def test_clear_zeroes_buffer(self):
        pp = Passphrase.from_str("wipe-me")
        assert bytes(pp.material()) == b"wipe-me"
        pp.clear()
        assert not pp

    def test_replace_from_str(self):
        pp = Passphrase.from_str("old")
        pp.replace_from_str("new")
        assert bytes(pp.material()) == b"new"

    def test_bytearray_roundtrip_with_crypto(self):
        pp = Passphrase.from_str("test-pass")
        token = encrypt("secret", pp.material())
        assert decrypt(token, pp.material()) == "secret"
