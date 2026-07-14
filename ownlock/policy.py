"""Per-secret access policies (open, session, confirm)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

POLICY_OPEN = "open"
POLICY_SESSION = "session"
POLICY_CONFIRM = "confirm"
VALID_POLICIES = frozenset({POLICY_OPEN, POLICY_SESSION, POLICY_CONFIRM})

# Process-local cache; also mirrored to a user file so unlocks survive
# short-lived CLI process boundaries within SESSION_TTL_SECONDS.
_session_unlocked: dict[tuple[str, str], float] = {}
SESSION_TTL_SECONDS = 1800  # 30 minutes


def normalize_policy(policy: Optional[str], *, strict: bool = False) -> str:
    """Normalize a policy string.

    When *strict* is True, unknown values raise ``ValueError`` (bundle import).
    Otherwise unknown/missing values become ``open``.
    """
    if not policy:
        if strict:
            raise ValueError("Missing policy")
        return POLICY_OPEN
    if policy not in VALID_POLICIES:
        if strict:
            raise ValueError(
                f"Invalid policy {policy!r}; expected one of: "
                f"{', '.join(sorted(VALID_POLICIES))}"
            )
        return POLICY_OPEN
    return policy


def _session_store_path() -> Path:
    override = os.environ.get("OWNLOCK_SESSION_STORE")
    if override:
        return Path(override)
    return Path.home() / ".ownlock" / "session-unlock.json"


def _load_session_store() -> dict[str, float]:
    path = _session_store_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            out: dict[str, float] = {}
            now = time.time()
            for k, v in data.items():
                try:
                    expiry = float(v)
                except (TypeError, ValueError):
                    continue
                if expiry > now:
                    out[str(k)] = expiry
            return out
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _save_session_store(store: dict[str, float]) -> None:
    path = _session_store_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(store, sort_keys=True), encoding="utf-8")
        if os.name == "posix":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except OSError:
        pass


def unlock_session(name: str, env: str) -> None:
    expiry_mono = time.monotonic() + SESSION_TTL_SECONDS
    _session_unlocked[(name, env)] = expiry_mono
    key = f"{env}\0{name}"
    store = _load_session_store()
    store[key] = time.time() + SESSION_TTL_SECONDS
    _save_session_store(store)


def is_session_unlocked(name: str, env: str) -> bool:
    expiry = _session_unlocked.get((name, env))
    if expiry is not None:
        if time.monotonic() <= expiry:
            return True
        del _session_unlocked[(name, env)]

    key = f"{env}\0{name}"
    store = _load_session_store()
    wall = store.get(key)
    if wall is None:
        return False
    if time.time() > wall:
        store.pop(key, None)
        _save_session_store(store)
        return False
    # Refresh process cache from durable store.
    _session_unlocked[(name, env)] = time.monotonic() + max(1.0, wall - time.time())
    return True


def clear_session_cache() -> None:
    _session_unlocked.clear()
    path = _session_store_path()
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def check_policy_access(
    name: str,
    env: str,
    policy: str,
    *,
    reason: Optional[str] = None,
    is_tty: bool = True,
) -> bool:
    """Return True if *policy* allows reading *name* now.

    Non-TTY callers cannot satisfy ``session`` / ``confirm`` (returns False
    after raising is avoided — raises PermissionError for clear CLI errors).
    """
    policy = normalize_policy(policy)
    if policy == POLICY_OPEN:
        return True

    import typer

    if policy == POLICY_SESSION:
        if is_session_unlocked(name, env):
            return True
        if not is_tty:
            raise PermissionError(
                f"Secret '{name}' (env={env}) requires session unlock; run interactively."
            )
        prompt = (
            f"Unlock '{name}' (env={env}) for {SESSION_TTL_SECONDS // 60} minutes?"
        )
        if reason:
            prompt += f" Reason: {reason}"
        if typer.confirm(prompt, default=False):
            unlock_session(name, env)
            return True
        return False

    # confirm — every access needs an explicit yes
    if not is_tty:
        raise PermissionError(
            f"Secret '{name}' (env={env}) requires confirmation; run interactively."
        )
    msg = f"Allow access to secret '{name}' (env={env})?"
    if reason:
        msg += f" ({reason})"
    return bool(typer.confirm(msg, default=False))
