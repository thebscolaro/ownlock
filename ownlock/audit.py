"""Opt-in audit log: one JSONL line per vault operation, never values.

Enabled by setting ``OWNLOCK_AUDIT=1`` in the environment. When unset, every
function in this module is a no-op so the hot path doesn't even open a file.

Records what changed, when, and from which command — but never *what value
was set*. The log lives next to the vault as ``.ownlock/audit.log`` (project
or global to match the active vault). On POSIX the file is mode ``0600``.

Schema (one JSON object per line, sorted keys for stable diffs):

.. code-block:: json

    {
      "ts": "2026-05-28T05:00:00.123456+00:00",
      "op": "set",
      "name": "API_KEY",
      "env": "production",
      "vault": "/Users/me/.ownlock/vault.db",
      "actor": "ownlock"
    }

Operations: ``init``, ``set``, ``delete``, ``import``, ``rekey``, ``share``,
``import-share``, ``sync-gh-push``. The CLI calls :func:`record` at the
boundary so all vault-state-changing commands flow through one place.
Read-only commands (``get``, ``list``, ``run``, ``scan``, ``doctor``,
``sync gh pull``) and .env file rewrites that don't touch the vault
(``rewrite-env``) are intentionally **not** logged.

Failure mode: any IOError / permission error during logging is swallowed —
ownlock will not fail a successful vault operation because the audit log
couldn't be written. Critical errors are surfaced via the return value so
the CLI can hint at fixing config when running with ``OWNLOCK_AUDIT=1``.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Optional


def is_enabled() -> bool:
    """True when ``OWNLOCK_AUDIT`` is set, or when an AI agent is in the process tree."""
    val = os.environ.get("OWNLOCK_AUDIT", "").strip().lower()
    if val in {"1", "true", "yes", "on"}:
        return True
    if val in {"0", "false", "no", "off"}:
        return False
    from ownlock.agent import detect_agent_actor

    return detect_agent_actor() is not None


def _audit_log_path(vault_path: Path) -> Path:
    """Resolve the audit log path for *vault_path*.

    Sibling of the ``vault.db`` file inside the same ``.ownlock/`` directory,
    so a per-project vault gets per-project history and the global vault gets
    its own.
    """
    return vault_path.parent / "audit.log"


def record(
    op: str,
    *,
    vault_path: Path,
    name: Optional[str] = None,
    env: Optional[str] = None,
    actor: str = "ownlock",
    extra: Optional[dict[str, Any]] = None,
) -> bool:
    """Append one JSONL audit record. Returns True if a line was written.

    No-op (returns False) when ``OWNLOCK_AUDIT`` isn't set. Quietly returns
    False on any I/O failure — the audit log is best-effort and must not
    block a successful vault operation.
    """
    if not is_enabled():
        return False

    from ownlock.agent import resolve_actor

    effective_actor = resolve_actor(None if actor == "ownlock" else actor)

    record_data: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "op": op,
        "actor": effective_actor,
        "vault": str(vault_path),
    }
    if name is not None:
        record_data["name"] = name
    if env is not None:
        record_data["env"] = env
    if extra:
        # Whitelist-friendly: caller controls which extra fields land in the
        # log. We never read .value or similar from arbitrary objects.
        for k, v in extra.items():
            if k in record_data:
                continue
            record_data[k] = v

    line = json.dumps(record_data, sort_keys=True, separators=(",", ":")) + "\n"

    log_path = _audit_log_path(vault_path)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        existed = log_path.exists()
        with log_path.open("a", encoding="utf-8") as f:
            f.write(line)
        if not existed and os.name == "posix":
            try:
                os.chmod(log_path, 0o600)
            except OSError:
                pass
        return True
    except OSError:
        return False
