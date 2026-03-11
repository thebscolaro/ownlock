"""SQLite-backed encrypted secret storage."""

from __future__ import annotations

import sqlite3
from datetime import datetime, UTC
from pathlib import Path
from typing import Optional

from ownlock.crypto import encrypt, decrypt

GLOBAL_VAULT_DIR = Path.home() / ".ownlock"
GLOBAL_VAULT_PATH = GLOBAL_VAULT_DIR / "vault.db"
PROJECT_VAULT_DIR = ".ownlock"
PROJECT_VAULT_DB = "vault.db"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS secrets (
    name       TEXT NOT NULL,
    env        TEXT NOT NULL DEFAULT 'default',
    value_enc  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (name, env)
);
"""


class VaultManager:
    """Manage secrets in an encrypted SQLite vault."""

    def __init__(self, db_path: Path, passphrase: str) -> None:
        self._db_path = db_path
        self._passphrase = passphrase
        self._conn: Optional[sqlite3.Connection] = None

    @property
    def db_path(self) -> Path:
        return self._db_path

    def open(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_CREATE_TABLE)
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> VaultManager:
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Vault is not open. Use 'with VaultManager(...) as vm:'")
        return self._conn

    def set(self, name: str, value: str, env: str = "default") -> None:
        """Store or update a secret."""
        conn = self._require_conn()
        now = datetime.now(UTC).isoformat()
        enc = encrypt(value, self._passphrase)
        conn.execute(
            """INSERT INTO secrets (name, env, value_enc, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (name, env) DO UPDATE SET value_enc = ?, updated_at = ?""",
            (name, env, enc, now, now, enc, now),
        )
        conn.commit()

    def get(self, name: str, env: str = "default") -> Optional[str]:
        """Retrieve and decrypt a secret. Returns None if not found."""
        conn = self._require_conn()
        row = conn.execute(
            "SELECT value_enc FROM secrets WHERE name = ? AND env = ?",
            (name, env),
        ).fetchone()
        if row is None:
            return None
        return decrypt(row["value_enc"], self._passphrase)

    def delete(self, name: str, env: str = "default") -> bool:
        """Delete a secret. Returns True if it existed."""
        conn = self._require_conn()
        cursor = conn.execute(
            "DELETE FROM secrets WHERE name = ? AND env = ?",
            (name, env),
        )
        conn.commit()
        return cursor.rowcount > 0

    def list_secrets(self, env: Optional[str] = None) -> list[dict[str, str]]:
        """List secret names (never values). Optionally filter by env."""
        conn = self._require_conn()
        if env:
            rows = conn.execute(
                "SELECT name, env, created_at, updated_at FROM secrets WHERE env = ? ORDER BY name",
                (env,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT name, env, created_at, updated_at FROM secrets ORDER BY name, env"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_decrypted(self, env: str = "default") -> dict[str, str]:
        """Decrypt all secrets for an env. Used by the resolver."""
        conn = self._require_conn()
        rows = conn.execute(
            "SELECT name, value_enc FROM secrets WHERE env = ?",
            (env,),
        ).fetchall()
        return {row["name"]: decrypt(row["value_enc"], self._passphrase) for row in rows}

    @staticmethod
    def find_project_vault() -> Optional[Path]:
        """Walk up from cwd to find a .ownlock/vault.db."""
        current = Path.cwd()
        for parent in [current, *current.parents]:
            candidate = parent / PROJECT_VAULT_DIR / PROJECT_VAULT_DB
            if candidate.exists():
                return candidate
        return None

    @staticmethod
    def init_vault(path: Path, passphrase: str) -> VaultManager:
        """Create a new vault at *path*."""
        vm = VaultManager(path, passphrase)
        vm.open()
        return vm
