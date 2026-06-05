"""System keyring integration for vault passphrase storage.

Uses the `keyring` library which wraps:
  - macOS: Keychain
  - Linux: SecretService (GNOME Keyring)
  - Windows: Windows Credential Locker
"""

from __future__ import annotations

import gc
import getpass
from contextlib import contextmanager
from typing import Iterator, Optional

from ownlock.passphrase import Passphrase

SERVICE_NAME = "ownlock"
ACCOUNT_NAME = "vault-passphrase"


def _scrub_str_ref(value: str) -> None:
    """Drop a transient ``str`` ref and encourage immediate collection.

    Best-effort only: does not zero freed heap blocks.
    """
    del value
    gc.collect()


def _passphrase_from_str(value: str) -> Passphrase:
    """Copy *value* into a wipeable buffer and scrub the source ``str`` ref."""
    pp = Passphrase.from_str(value)
    _scrub_str_ref(value)
    return pp


def store_passphrase(passphrase: str) -> tuple[bool, Optional[str]]:
    """Store the vault passphrase in the system keyring.

    Returns (True, None) on success, or (False, error_message) on failure.
    """
    try:
        import keyring

        keyring.set_password(SERVICE_NAME, ACCOUNT_NAME, passphrase)
        return True, None
    except Exception as e:
        return False, str(e)


def get_passphrase() -> Optional[str]:
    """Retrieve the vault passphrase from the system keyring.

    Returns None if not stored or keyring is unavailable.
    """
    try:
        import keyring
        return keyring.get_password(SERVICE_NAME, ACCOUNT_NAME)
    except Exception:
        return None


def keyring_has_passphrase() -> bool:
    """Return whether a vault passphrase is stored in the keyring.

    Does not expose the secret to callers; transient keyring ``str`` refs are
    scrubbed before return.
    """
    stored = get_passphrase()
    if not stored:
        return False
    _scrub_str_ref(stored)
    return True


def delete_passphrase() -> bool:
    """Remove the vault passphrase from the system keyring."""
    try:
        import keyring
        keyring.delete_password(SERVICE_NAME, ACCOUNT_NAME)
        return True
    except Exception:
        return False


def resolve_passphrase(
    env_var: Optional[str] = None,
    *,
    prompt: bool = True,
) -> Passphrase:
    """Resolve the vault passphrase using this priority order:

    1. OWNLOCK_PASSPHRASE environment variable
    2. System keyring (macOS Keychain, etc.)
    3. Interactive prompt (if *prompt* is True)

    Returns a wipeable :class:`~ownlock.passphrase.Passphrase` buffer.
    Raises ValueError if no passphrase can be obtained.
    """
    import os

    value = os.environ.get("OWNLOCK_PASSPHRASE") or env_var
    if value:
        return _passphrase_from_str(value)

    stored = get_passphrase()
    if stored:
        return _passphrase_from_str(stored)

    if prompt:
        typed = getpass.getpass("Vault passphrase: ")
        if typed:
            return _passphrase_from_str(typed)

    raise ValueError(
        "No vault passphrase found. Set OWNLOCK_PASSPHRASE, "
        "store in keyring via 'ownlock init', or provide interactively."
    )


@contextmanager
def passphrase_session(
    env_var: Optional[str] = None,
    *,
    prompt: bool = True,
) -> Iterator[Passphrase]:
    """Resolve the vault passphrase and zero the buffer when the scope exits."""
    import os

    pp = resolve_passphrase(env_var, prompt=prompt)
    try:
        yield pp
    finally:
        pp.clear()
        os.environ.pop("OWNLOCK_PASSPHRASE", None)
        gc.collect()


@contextmanager
def prompt_passphrase_session(passphrase: str) -> Iterator[Passphrase]:
    """Copy a prompted ``str`` into a wipeable buffer for the scope duration."""
    pp = _passphrase_from_str(passphrase)
    try:
        yield pp
    finally:
        pp.clear()
        gc.collect()
