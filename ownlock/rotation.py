"""Secret rotation-age helpers for the `list` Age column and `doctor` nudge.

Ages are computed from the vault's plaintext ``updated_at`` column, so both
callers work without decrypting anything. The staleness threshold defaults to
90 days and can be overridden with ``OWNLOCK_ROTATION_DAYS``.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Optional

DEFAULT_ROTATION_DAYS = 90


def rotation_days() -> int:
    """Staleness threshold in days (OWNLOCK_ROTATION_DAYS override, min 1)."""
    raw = os.environ.get("OWNLOCK_ROTATION_DAYS", "").strip()
    if raw:
        try:
            value = int(raw)
            if value >= 1:
                return value
        except ValueError:
            pass
    return DEFAULT_ROTATION_DAYS


def age_days(timestamp: str, *, now: Optional[datetime] = None) -> Optional[int]:
    """Whole days since *timestamp* (ISO-8601), or None when unparseable."""
    try:
        then = datetime.fromisoformat(timestamp)
    except (ValueError, TypeError):
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=UTC)
    current = now if now is not None else datetime.now(UTC)
    delta = current - then
    return max(0, delta.days)


def format_age(days: Optional[int]) -> str:
    """Render an age for the `list` table (empty when unknown)."""
    if days is None:
        return ""
    return f"{days}d"
