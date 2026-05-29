"""SQLite-backed encrypted secret storage."""

from __future__ import annotations

import sqlite3
from datetime import datetime, UTC
from pathlib import Path
from typing import Optional

from ownlock.crypto import (
    KDF_ITERATIONS_CURRENT,
    KDF_ITERATIONS_LEGACY,
    decrypt,
    encrypt,
    token_iterations,
)

GLOBAL_VAULT_DIR = Path.home() / ".ownlock"
GLOBAL_VAULT_PATH = GLOBAL_VAULT_DIR / "vault.db"
PROJECT_VAULT_DIR = ".ownlock"
PROJECT_VAULT_DB = "vault.db"

# Schema versions:
#   1 — pre-0.2.0 vaults; no meta table; secrets stored as v1 tokens (no
#       iteration count, decrypts at the legacy 200_000 default).
#   2 — 0.2.0+; meta table present; new secrets written as v2 tokens carrying
#       their iteration count. v1 tokens still decrypt fine until rekeyed.
SCHEMA_VERSION_CURRENT = 2

_CREATE_SECRETS = """
CREATE TABLE IF NOT EXISTS secrets (
    name       TEXT NOT NULL,
    env        TEXT NOT NULL DEFAULT 'default',
    value_enc  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (name, env)
);
"""

_CREATE_META = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
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
        is_new = not self._db_path.exists() or self._db_path.stat().st_size == 0
        # ``timeout=5.0`` is the connection-level lock wait; a separate
        # ``busy_timeout`` PRAGMA below covers WAL-specific waits. Belt and
        # suspenders so a competing ``ownlock set`` from another shell waits
        # rather than crashing with "database is locked".
        self._conn = sqlite3.connect(str(self._db_path), timeout=5.0)
        self._conn.row_factory = sqlite3.Row
        self._apply_concurrency_pragmas()
        self._conn.execute(_CREATE_SECRETS)
        self._conn.execute(_CREATE_META)
        self._conn.commit()
        self._ensure_meta(is_new=is_new)

    def _apply_concurrency_pragmas(self) -> None:
        """Switch SQLite to WAL with a generous busy-timeout.

        WAL (write-ahead log) lets one writer and many readers proceed in
        parallel from separate processes without corrupting the file —
        critical for the "agent calls ``ownlock set`` while a dev runs
        ``ownlock run`` in another terminal" case. ``synchronous=NORMAL``
        is the WAL-recommended setting (full ``fsync`` on every commit is
        overkill for a personal vault). ``busy_timeout`` makes a competing
        writer wait up to 5 seconds for the lock instead of erroring.

        These are session-level pragmas with one exception: ``journal_mode``
        is persisted by SQLite into the database header, so the very first
        successful WAL switch sticks for every future open of this file.
        """
        conn = self._conn
        if conn is None:
            return
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")

    def close(self) -> None:
        if self._conn:
            # Checkpoint WAL into the main DB so the file on disk is
            # self-contained when no one's holding it open. Best-effort:
            # if checkpointing fails for any reason (e.g. another writer
            # currently holds the lock), close the connection anyway.
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.DatabaseError:
                pass
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

    def _ensure_meta(self, *, is_new: bool) -> None:
        """Populate the ``meta`` table if it's empty.

        For brand-new vaults, write current defaults (schema v2, current KDF
        iterations). For existing vaults that predate the meta table, infer v1
        / legacy iterations and write them so subsequent reads are stable.
        """
        conn = self._require_conn()
        existing = {
            row["key"]: row["value"]
            for row in conn.execute("SELECT key, value FROM meta").fetchall()
        }
        if existing:
            return

        now = datetime.now(UTC).isoformat()
        if is_new:
            schema_version = SCHEMA_VERSION_CURRENT
            kdf_iterations = KDF_ITERATIONS_CURRENT
        else:
            # Vault file existed before meta; treat as schema v1 / legacy KDF
            # so future reads correctly describe what's on disk.
            schema_version = 1
            kdf_iterations = KDF_ITERATIONS_LEGACY

        rows = [
            ("schema_version", str(schema_version)),
            ("kdf_algo", "PBKDF2-HMAC-SHA256"),
            ("kdf_iterations", str(kdf_iterations)),
            ("created_at", now),
        ]
        conn.executemany(
            "INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)", rows
        )
        conn.commit()

    def get_meta(self) -> dict[str, str]:
        """Return the meta table as a plain dict.

        Includes ``schema_version``, ``kdf_algo``, ``kdf_iterations``,
        ``created_at``.
        """
        conn = self._require_conn()
        return {
            row["key"]: row["value"]
            for row in conn.execute("SELECT key, value FROM meta").fetchall()
        }

    def schema_version(self) -> int:
        """Return the on-disk schema version (1 for pre-meta vaults)."""
        meta = self.get_meta()
        return int(meta.get("schema_version", "1"))

    def kdf_iterations(self) -> int:
        """Return the KDF iterations advertised by the vault meta."""
        meta = self.get_meta()
        return int(meta.get("kdf_iterations", str(KDF_ITERATIONS_LEGACY)))

    def _upsert_meta_row(self, key: str, value: str) -> None:
        """Insert/update a single meta row inside the caller's transaction.

        Private because callers must commit explicitly; ``rekey`` batches
        several of these together and commits once at the end.
        """
        self._require_conn().execute(
            """INSERT INTO meta (key, value) VALUES (?, ?)
               ON CONFLICT (key) DO UPDATE SET value = ?""",
            (key, value, value),
        )

    def set(self, name: str, value: str, env: str = "default") -> None:
        """Store or update a secret. New writes use the current KDF default."""
        conn = self._require_conn()
        now = datetime.now(UTC).isoformat()
        enc = encrypt(value, self._passphrase, iterations=KDF_ITERATIONS_CURRENT)
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

    def secret_iterations_summary(self) -> dict[int, int]:
        """Return a histogram of KDF iterations across stored ciphertexts.

        Maps ``iterations -> count``. Useful for ``rekey --upgrade-kdf`` and
        ``ownlock doctor`` to show how many secrets are still on the legacy
        KDF setting.
        """
        conn = self._require_conn()
        rows = conn.execute("SELECT value_enc FROM secrets").fetchall()
        summary: dict[int, int] = {}
        for row in rows:
            try:
                iters = token_iterations(row["value_enc"])
            except Exception:
                continue
            summary[iters] = summary.get(iters, 0) + 1
        return summary

    def rekey(
        self,
        new_passphrase: str,
        *,
        target_iterations: int = KDF_ITERATIONS_CURRENT,
    ) -> int:
        """Re-encrypt every secret with *new_passphrase* and *target_iterations*.

        Runs inside a single SQL transaction: either all secrets re-encrypt
        successfully, or the vault is left untouched. Updates the ``meta``
        table to reflect the new KDF parameters and bumps ``schema_version``
        to the current value. Returns the number of secrets re-encrypted.
        """
        conn = self._require_conn()
        rows = conn.execute(
            "SELECT name, env, value_enc FROM secrets"
        ).fetchall()

        re_enc: list[tuple[str, str, str, str]] = []
        now = datetime.now(UTC).isoformat()
        for row in rows:
            plaintext = decrypt(row["value_enc"], self._passphrase)
            new_token = encrypt(
                plaintext, new_passphrase, iterations=target_iterations
            )
            re_enc.append((new_token, now, row["name"], row["env"]))

        try:
            conn.execute("BEGIN IMMEDIATE")
            for token, ts, name, env in re_enc:
                conn.execute(
                    "UPDATE secrets SET value_enc = ?, updated_at = ? "
                    "WHERE name = ? AND env = ?",
                    (token, ts, name, env),
                )
            self._upsert_meta_row("schema_version", str(SCHEMA_VERSION_CURRENT))
            self._upsert_meta_row("kdf_iterations", str(target_iterations))
            conn.commit()
        except Exception:
            conn.rollback()
            raise

        self._passphrase = new_passphrase
        return len(re_enc)

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
