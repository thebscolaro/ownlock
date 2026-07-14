"""Detect AI coding agents in the process tree for audit attribution."""

from __future__ import annotations

import os
from typing import Optional

# Process basename fragments (lowercase) → stable actor id for audit logs.
# Longer / more specific needles first. Matching is basename-only (never a
# raw cmdline substring) so a path like ``.../docs/cursor-notes.md`` in argv
# cannot flip audit auto-on.
_AGENT_MARKERS: tuple[tuple[str, str], ...] = (
    ("claude-code", "claude-code"),
    ("claude", "claude-code"),
    ("cursor-agent", "cursor"),
    ("cursor", "cursor"),
    ("codex", "codex"),
    ("github-copilot", "github-copilot"),
    ("copilot", "github-copilot"),
    ("windsurf", "windsurf"),
    ("hermes-agent", "hermes"),
    ("hermes", "hermes"),
    ("pi-coding-agent", "pi"),
    ("openclaw", "openclaw"),
    ("aider", "aider"),
    ("continue", "continue"),
    ("cody", "cody"),
    ("gemini", "gemini-cli"),
    ("amp", "amp"),
    ("pi", "pi"),  # exact / prefix basename only (see _match_basename)
)


def detect_agent_actor() -> Optional[str]:
    """Walk the process tree and return an agent id if found.

    Returns a stable string like ``claude-code`` or ``None`` for human/unknown
    callers. Best-effort: never raises.
    """
    try:
        return _detect_agent_actor_impl()
    except Exception:
        return None


def _detect_agent_actor_impl() -> Optional[str]:
    if os.name == "nt":
        return _detect_windows()
    return _detect_posix()


def _process_basename(comm: str) -> str:
    base = comm.lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if base.endswith(".exe"):
        base = base[:-4]
    # Drop trailing nulls / whitespace from /proc/comm.
    return base.strip()


def _match_basename(base: str) -> Optional[str]:
    """Match an agent marker against a single process basename."""
    if not base:
        return None
    for needle, actor in _AGENT_MARKERS:
        if len(needle) <= 3:
            if base == needle or base.startswith(f"{needle}-"):
                return actor
            continue
        if base == needle or base.startswith(f"{needle}-"):
            return actor
        # Linux /proc/comm truncates to 15 chars (e.g. ``claude-code-hel``).
        if len(base) == 15 and base.startswith(needle):
            return actor
    return None


def _match_comm(comm: str) -> Optional[str]:
    """Match against argv0 / process name only — never full cmdline text."""
    if not comm:
        return None
    # If a full cmdline was passed, only consider argv0.
    argv0 = comm.split(None, 1)[0]
    return _match_basename(_process_basename(argv0))


def _detect_posix() -> Optional[str]:
    pid = os.getpid()
    seen: set[int] = set()
    while pid > 0 and pid not in seen:
        seen.add(pid)
        # Prefer argv0 from cmdline (Linux); fall back to /proc/comm; then ps.
        for label in (_posix_argv0(pid), _posix_comm(pid), _posix_ps_comm(pid)):
            if label:
                actor = _match_comm(label)
                if actor:
                    return actor
        ppid = _posix_ppid(pid)
        if ppid is None or ppid == pid:
            break
        pid = ppid
    return None


def _posix_comm(pid: int) -> Optional[str]:
    try:
        with open(f"/proc/{pid}/comm", encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError:
        return None


def _posix_argv0(pid: int) -> Optional[str]:
    """Return argv[0] only (not the full cmdline) from ``/proc/<pid>/cmdline``."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
        if not raw:
            return None
        # cmdline is NUL-separated; first field is argv0.
        argv0 = raw.split(b"\x00", 1)[0].decode("utf-8", errors="ignore").strip()
        return argv0 or None
    except OSError:
        return None


def _posix_ppid(pid: int) -> Optional[int]:
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    # macOS / BSD fallback via ps
    try:
        import shutil
        import subprocess

        ps = shutil.which("ps")
        if not ps:
            return None
        out = subprocess.check_output(
            [ps, "-p", str(pid), "-o", "ppid="],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        return int(out) if out else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _posix_ps_comm(pid: int) -> Optional[str]:
    """macOS/BSD: prefer ``command`` (full path) argv0, then ``comm``."""
    try:
        import shutil
        import subprocess

        ps = shutil.which("ps")
        if not ps:
            return None
        for fmt in ("command=", "comm="):
            try:
                out = subprocess.check_output(
                    [ps, "-p", str(pid), "-o", fmt],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()
            except (OSError, subprocess.SubprocessError):
                continue
            if out:
                # ``command=`` may include args — take argv0 only.
                return out.split(None, 1)[0]
        return None
    except OSError:
        return None


def _walk_named_process_tree(
    start_pid: int,
    pid_to_parent: dict[int, int],
    pid_to_name: dict[int, str],
) -> Optional[str]:
    """Walk *start_pid* → parents using name maps; return first agent match."""
    pid = start_pid
    seen: set[int] = set()
    while pid in pid_to_parent and pid not in seen:
        seen.add(pid)
        name = pid_to_name.get(pid, "")
        actor = _match_comm(name)
        if actor:
            return actor
        pid = pid_to_parent[pid]
    return None


def _detect_windows() -> Optional[str]:
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None

    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return None

    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE = -1

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    kernel32 = windll.kernel32
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE:
        return None
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        pid_to_parent: dict[int, int] = {}
        pid_to_name: dict[int, str] = {}
        if not kernel32.Process32First(snap, ctypes.byref(entry)):
            return None
        while True:
            pid = int(entry.th32ProcessID)
            pid_to_parent[pid] = int(entry.th32ParentProcessID)
            pid_to_name[pid] = entry.szExeFile.decode("utf-8", errors="ignore")
            if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                break
        return _walk_named_process_tree(os.getpid(), pid_to_parent, pid_to_name)
    finally:
        kernel32.CloseHandle(snap)


def resolve_actor(explicit: Optional[str] = None) -> str:
    """Return *explicit* actor, detected agent id, or ``ownlock``."""
    if explicit:
        return explicit
    agent = detect_agent_actor()
    if agent:
        return agent
    return "ownlock"
