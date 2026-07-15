"""Console encoding helpers for Windows-safe CLI output."""

from __future__ import annotations

import os
import sys


def configure_stdio() -> None:
    """Best-effort UTF-8 stdout/stderr on Windows (errors replaced)."""
    if os.name != "nt":
        return
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError, AttributeError):
            # Console encoding is best-effort; keep going with the existing stream.
            continue


def console_can_encode(text: str) -> bool:
    """Return True when *text* can be encoded with the current stdout encoding."""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        text.encode(enc)
        return True
    except (LookupError, UnicodeEncodeError):
        return False


def fail_mark() -> str:
    """Failure marker: Unicode ballot X, or ASCII ``[x]`` on limited consoles."""
    return "✗" if console_can_encode("✗") else "[x]"


def bullet_mark() -> str:
    """Bullet marker: Unicode bullet, or ASCII ``-`` on limited consoles."""
    return "•" if console_can_encode("•") else "-"
