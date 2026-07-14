"""Tests for AI agent process-tree detection."""

from __future__ import annotations

from unittest.mock import MagicMock, mock_open, patch

import pytest

from ownlock.agent import (
    _detect_posix,
    _match_basename,
    _match_comm,
    _posix_argv0,
    _posix_comm,
    _posix_ppid,
    _posix_ps_comm,
    _process_basename,
    detect_agent_actor,
    resolve_actor,
)


def test_resolve_actor_explicit():
    assert resolve_actor("human") == "human"


def test_resolve_actor_fallback():
    with patch("ownlock.agent.detect_agent_actor", return_value=None):
        assert resolve_actor() == "ownlock"


def test_resolve_actor_detected():
    with patch("ownlock.agent.detect_agent_actor", return_value="cursor"):
        assert resolve_actor() == "cursor"


def test_match_comm_claude():
    assert _match_comm("claude") == "claude-code"
    assert _match_comm("/usr/local/bin/claude") == "claude-code"


def test_match_comm_hermes_and_pi():
    assert _match_comm("hermes") == "hermes"
    assert _match_comm("hermes-agent") == "hermes"
    assert _match_comm("pi") == "pi"
    assert _match_comm("pi-coding-agent") == "pi"


def test_match_comm_pi_does_not_match_python():
    assert _match_comm("python") is None
    assert _match_comm("python3.12") is None
    assert _match_comm("pip") is None


def test_match_comm_ignores_cmdline_substring():
    """A path arg containing 'cursor' must not count as the Cursor agent."""
    assert _match_comm("python /tmp/cursor-notes.md") is None
    assert _match_comm("vim docs/claude-review.txt") is None


def test_match_comm_argv0_only():
    assert _match_comm("cursor --help") == "cursor"
    assert _match_comm("/Applications/Cursor.app/Contents/MacOS/Cursor") == "cursor"


def test_match_comm_empty():
    assert _match_comm("") is None


def test_process_basename_strips_exe_and_path():
    assert _process_basename(r"C:\Tools\cursor.exe") == "cursor"
    assert _process_basename("/usr/bin/codex") == "codex"


def test_match_basename_truncated_linux_comm():
    # /proc/comm truncates to 15 chars
    assert _match_basename("claude-code-hel") == "claude-code"


def test_match_basename_empty():
    assert _match_basename("") is None


def test_detect_agent_never_raises():
    with patch("ownlock.agent._detect_agent_actor_impl", side_effect=RuntimeError("boom")):
        assert detect_agent_actor() is None


def test_detect_impl_dispatches_windows(monkeypatch):
    monkeypatch.setattr("ownlock.agent.os.name", "nt")
    with patch("ownlock.agent._detect_windows", return_value="codex") as win:
        from ownlock.agent import _detect_agent_actor_impl

        assert _detect_agent_actor_impl() == "codex"
        win.assert_called_once()


def test_detect_impl_dispatches_posix(monkeypatch):
    monkeypatch.setattr("ownlock.agent.os.name", "posix")
    with patch("ownlock.agent._detect_posix", return_value="aider") as posix:
        from ownlock.agent import _detect_agent_actor_impl

        assert _detect_agent_actor_impl() == "aider"
        posix.assert_called_once()


def test_posix_argv0_reads_nul_separated(tmp_path, monkeypatch):
    proc = tmp_path / "proc" / "42"
    proc.mkdir(parents=True)
    (proc / "cmdline").write_bytes(b"/usr/bin/cursor\x00--flag\x00")
    monkeypatch.setattr(
        "builtins.open",
        lambda path, *a, **k: mock_open(
            read_data=(proc / "cmdline").read_bytes()
            if str(path).endswith("cmdline")
            else b""
        )(path, *a, **k),
    )
    # Direct unit test via real temp file open
    with patch("builtins.open", mock_open(read_data=b"/usr/bin/cursor\x00--flag\x00")):
        assert _posix_argv0(42) == "/usr/bin/cursor"


def test_posix_argv0_empty_and_oserror():
    with patch("builtins.open", mock_open(read_data=b"")):
        assert _posix_argv0(1) is None
    with patch("builtins.open", side_effect=OSError("nope")):
        assert _posix_argv0(1) is None


def test_posix_comm_and_oserror():
    with patch("builtins.open", mock_open(read_data="cursor\n")):
        assert _posix_comm(1) == "cursor"
    with patch("builtins.open", mock_open(read_data="\n")):
        assert _posix_comm(1) is None
    with patch("builtins.open", side_effect=OSError):
        assert _posix_comm(1) is None


def test_posix_ppid_from_status():
    with patch("builtins.open", mock_open(read_data="Name:\tpython\nPPid:\t99\n")):
        assert _posix_ppid(1) == 99


def test_posix_ppid_falls_back_to_ps(monkeypatch):
    with patch("builtins.open", side_effect=OSError):
        with patch("subprocess.check_output", return_value=" 7\n") as ps:
            assert _posix_ppid(1) == 7
            ps.assert_called()


def test_posix_ppid_ps_failure():
    with patch("builtins.open", side_effect=OSError):
        with patch("subprocess.check_output", side_effect=OSError):
            assert _posix_ppid(1) is None


def test_posix_ps_comm_prefers_command():
    def fake_check_output(argv, **kwargs):
        if "command=" in argv:
            return "/Applications/Cursor.app/Contents/MacOS/Cursor --foo\n"
        return "Cursor\n"

    with patch("subprocess.check_output", side_effect=fake_check_output):
        assert _posix_ps_comm(1) == "/Applications/Cursor.app/Contents/MacOS/Cursor"


def test_posix_ps_comm_falls_back_to_comm():
    def fake_check_output(argv, **kwargs):
        if "command=" in argv:
            raise OSError("no")
        return "codex\n"

    with patch("subprocess.check_output", side_effect=fake_check_output):
        assert _posix_ps_comm(1) == "codex"


def test_posix_ps_comm_all_fail():
    with patch("subprocess.check_output", side_effect=OSError):
        assert _posix_ps_comm(1) is None


def test_detect_posix_walks_parents_until_agent():
    calls = {"n": 0}

    def fake_argv0(pid):
        calls["n"] += 1
        return None

    def fake_comm(pid):
        return "zsh" if pid == 100 else None

    def fake_ps(pid):
        return "cursor" if pid == 50 else None

    def fake_ppid(pid):
        return {100: 50, 50: 0}.get(pid)

    with patch("ownlock.agent.os.getpid", return_value=100):
        with patch("ownlock.agent._posix_argv0", side_effect=fake_argv0):
            with patch("ownlock.agent._posix_comm", side_effect=fake_comm):
                with patch("ownlock.agent._posix_ps_comm", side_effect=fake_ps):
                    with patch("ownlock.agent._posix_ppid", side_effect=fake_ppid):
                        assert _detect_posix() == "cursor"


def test_detect_posix_stops_on_cycle():
    with patch("ownlock.agent.os.getpid", return_value=10):
        with patch("ownlock.agent._posix_argv0", return_value=None):
            with patch("ownlock.agent._posix_comm", return_value="bash"):
                with patch("ownlock.agent._posix_ps_comm", return_value=None):
                    with patch("ownlock.agent._posix_ppid", return_value=10):
                        assert _detect_posix() is None


def test_walk_named_process_tree_finds_parent_agent():
    from ownlock.agent import _walk_named_process_tree

    assert (
        _walk_named_process_tree(
            100,
            {100: 50, 50: 1, 1: 0},
            {100: "python.exe", 50: "Cursor.exe", 1: "System"},
        )
        == "cursor"
    )


def test_walk_named_process_tree_no_agent():
    from ownlock.agent import _walk_named_process_tree

    assert (
        _walk_named_process_tree(
            10,
            {10: 1, 1: 0},
            {10: "python.exe", 1: "System"},
        )
        is None
    )


def test_walk_named_process_tree_cycle_safe():
    from ownlock.agent import _walk_named_process_tree

    assert _walk_named_process_tree(5, {5: 5}, {5: "bash.exe"}) is None


def test_detect_windows_without_windll_returns_none():
    import ctypes

    from ownlock.agent import _detect_windows

    # macOS has no windll; create=True keeps the patch portable.
    with patch.object(ctypes, "windll", None, create=True):
        assert _detect_windows() is None


def test_detect_windows_invalid_snapshot_handle():
    import ctypes

    from ownlock.agent import _detect_windows

    kernel32 = MagicMock()
    kernel32.CreateToolhelp32Snapshot.return_value = -1
    windll = MagicMock()
    windll.kernel32 = kernel32
    with patch.object(ctypes, "windll", windll, create=True):
        assert _detect_windows() is None
    kernel32.CloseHandle.assert_not_called()


def test_detect_windows_process32_first_fails():
    import ctypes

    from ownlock.agent import _detect_windows

    kernel32 = MagicMock()
    kernel32.CreateToolhelp32Snapshot.return_value = 42
    kernel32.Process32First.return_value = False
    windll = MagicMock()
    windll.kernel32 = kernel32
    with patch.object(ctypes, "windll", windll, create=True):
        assert _detect_windows() is None
    kernel32.CloseHandle.assert_called_once_with(42)


def _install_fake_toolhelp(kernel32: MagicMock, processes: list[tuple[int, int, bytes]]):
    """Wire Process32First/Next to feed *processes* into the real ctypes entry."""
    state = {"i": 0}

    def _fill(pref) -> None:
        entry = pref._obj
        pid, ppid, name = processes[state["i"]]
        entry.th32ProcessID = pid
        entry.th32ParentProcessID = ppid
        padded = name[:259] + b"\x00"
        entry.szExeFile = padded.ljust(260, b"\x00")

    def process32_first(_snap, pref):
        state["i"] = 0
        if not processes:
            return False
        _fill(pref)
        return True

    def process32_next(_snap, pref):
        state["i"] += 1
        if state["i"] >= len(processes):
            return False
        _fill(pref)
        return True

    kernel32.Process32First.side_effect = process32_first
    kernel32.Process32Next.side_effect = process32_next


def test_detect_windows_finds_cursor_in_parent(monkeypatch):
    import ctypes

    from ownlock.agent import _detect_windows

    monkeypatch.setattr("ownlock.agent.os.getpid", lambda: 100)
    kernel32 = MagicMock()
    kernel32.CreateToolhelp32Snapshot.return_value = 7
    _install_fake_toolhelp(
        kernel32,
        [
            (100, 50, b"python.exe"),
            (50, 1, b"Cursor.exe"),
            (1, 0, b"System"),
        ],
    )
    windll = MagicMock()
    windll.kernel32 = kernel32
    with patch.object(ctypes, "windll", windll, create=True):
        assert _detect_windows() == "cursor"
    kernel32.CloseHandle.assert_called_once_with(7)


def test_detect_windows_no_agent_in_tree(monkeypatch):
    import ctypes

    from ownlock.agent import _detect_windows

    monkeypatch.setattr("ownlock.agent.os.getpid", lambda: 100)
    kernel32 = MagicMock()
    kernel32.CreateToolhelp32Snapshot.return_value = 7
    _install_fake_toolhelp(
        kernel32,
        [
            (100, 50, b"python.exe"),
            (50, 1, b"cmd.exe"),
            (1, 0, b"System"),
        ],
    )
    windll = MagicMock()
    windll.kernel32 = kernel32
    with patch.object(ctypes, "windll", windll, create=True):
        assert _detect_windows() is None


def test_detect_windows_matches_codex_exe(monkeypatch):
    import ctypes

    from ownlock.agent import _detect_windows

    monkeypatch.setattr("ownlock.agent.os.getpid", lambda: 20)
    kernel32 = MagicMock()
    kernel32.CreateToolhelp32Snapshot.return_value = 9
    _install_fake_toolhelp(
        kernel32,
        [
            (20, 0, b"codex.exe"),
        ],
    )
    windll = MagicMock()
    windll.kernel32 = kernel32
    with patch.object(ctypes, "windll", windll, create=True):
        assert _detect_windows() == "codex"


def test_detect_windows_ctypes_import_error(monkeypatch):
    import builtins

    from ownlock.agent import _detect_windows

    real_import = builtins.__import__

    def blocked(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "ctypes" or name.startswith("ctypes."):
            raise ImportError("ctypes blocked for test")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked)
    assert _detect_windows() is None


def test_match_basename_truncated_starts_with_needle():
    # 15-char /proc/comm truncation that still starts with a short needle
    assert len("copilot12345678") == 15
    assert _match_basename("copilot12345678") == "github-copilot"
    assert _match_basename("cursor-agent-helper") == "cursor"


def test_posix_ps_comm_outer_oserror(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def blocked(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "subprocess":
            raise OSError("subprocess blocked")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked)
    assert _posix_ps_comm(1) is None
