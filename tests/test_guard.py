"""Tests for ownlock guard."""

from __future__ import annotations

import json
from pathlib import Path

from ownlock.guard import guard_stdin, install_guard_hook, redact_text


def test_redact_text():
    out = redact_text("token=supersecret", {"TOKEN": "supersecret"})
    assert "supersecret" not in out
    assert "[REDACTED" in out


def test_guard_stdin(monkeypatch):
    import io
    import sys

    secret = "abc12345"
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"leak: {secret}"))
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    code = guard_stdin({"LEAK": secret})
    assert code == 0
    assert secret not in buf.getvalue()


def test_install_guard_hook(tmp_path: Path):
    assert install_guard_hook(tmp_path) is True
    hook = tmp_path / ".claude" / "hooks" / "ownlock-guard.sh"
    assert hook.exists()
    script = hook.read_text()
    assert "refusing to pass unredacted" in script
    assert "|| printf '%s' \"$TEXT\"" not in script
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert "PostToolUse" in settings["hooks"]


def test_install_guard_hook_idempotent(tmp_path: Path):
    assert install_guard_hook(tmp_path) is True
    assert install_guard_hook(tmp_path) is False


def test_install_guard_hook_recovers_bad_settings_json(tmp_path: Path):
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text("{not-json")
    assert install_guard_hook(tmp_path) is True
    data = json.loads((claude / "settings.json").read_text())
    assert "PostToolUse" in data["hooks"]


def test_install_guard_hook_windows_uses_ps1(tmp_path: Path, monkeypatch):
    import ownlock.guard as guard

    monkeypatch.setattr(guard.os, "name", "nt")
    assert guard.install_guard_hook(tmp_path) is True
    assert (tmp_path / ".claude" / "hooks" / "ownlock-guard.ps1").exists()
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    cmd = settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    assert cmd.startswith("powershell -NoProfile -File")
    assert "ownlock-guard.ps1" in cmd
