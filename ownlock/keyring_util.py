"""System keyring integration for vault passphrase storage.

Uses the `keyring` library which wraps:
  - macOS: Keychain
  - Linux: SecretService (GNOME Keyring)
  - Windows: Windows Credential Locker
"""

from __future__ import annotations

import getpass
from typing import Optional

SERVICE_NAME = "ownlock"
ACCOUNT_NAME = "vault-passphrase"


def store_passphrase(passphrase: str) -> bool:
    """Store the vault passphrase in the system keyring.

    Returns True on success, False if keyring is unavailable.
    """
    try:
        import keyring
        keyring.set_password(SERVICE_NAME, ACCOUNT_NAME, passphrase)
        return True
    except Exception:
        return False


def get_passphrase() -> Optional[str]:
    """Retrieve the vault passphrase from the system keyring.

    Returns None if not stored or keyring is unavailable.
    """
    try:
        import keyring
        return keyring.get_password(SERVICE_NAME, ACCOUNT_NAME)
    except Exception:
        return None


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
) -> str:
    """Resolve the vault passphrase using this priority order:

    1. OWNLOCK_PASSPHRASE environment variable
    2. System keyring (macOS Keychain, etc.)
    3. Interactive prompt (if *prompt* is True)

    Raises ValueError if no passphrase can be obtained.
    """
    import os

    value = os.environ.get("OWNLOCK_PASSPHRASE") or env_var
    if value:
        return value

    stored = get_passphrase()
    if stored:
        return stored

    if prompt:
        value = getpass.getpass("Vault passphrase: ")
        if value:
            return value

    raise ValueError(
        "No vault passphrase found. Set OWNLOCK_PASSPHRASE, "
        "store in keyring via 'ownlock init', or provide interactively."
    )
