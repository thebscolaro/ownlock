"""Wipeable in-process storage for vault passphrases.

Python ``str`` values are immutable and may leave copies in memory that cannot
be zeroed. :class:`Passphrase` keeps UTF-8 bytes in a mutable
:class:`bytearray` and overwrites them in :meth:`clear` (called from
:meth:`ownlock.vault.VaultManager.close`).

This does **not** remove copies created earlier (``getpass``, ``OWNLOCK_PASSPHRASE``,
keyring, or ``.encode()`` inside PBKDF2). It shortens the lifetime of the copy
held for an open vault session.
"""

from __future__ import annotations

from typing import Union

PassphraseInput = Union[str, "Passphrase"]


class Passphrase:
    """Mutable UTF-8 passphrase buffer with explicit wiping."""

    __slots__ = ("_buf",)

    @classmethod
    def from_str(cls, value: str) -> Passphrase:
        return cls(value.encode("utf-8"))

    @classmethod
    def copy(cls, other: Passphrase) -> Passphrase:
        return cls(other.material())

    def __init__(self, utf8: bytes | bytearray) -> None:
        self._buf = bytearray(utf8)

    def material(self) -> bytearray:
        """Passphrase bytes for crypto (do not retain references)."""
        return self._buf

    def replace_from_str(self, value: str) -> None:
        self.clear()
        self._buf.extend(value.encode("utf-8"))

    def clear(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._buf.clear()

    def __bool__(self) -> bool:
        return bool(self._buf)
