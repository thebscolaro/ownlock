"""Tests for ownlock shield."""

from __future__ import annotations

import json
from pathlib import Path

from ownlock.shield import install_shield, verify_shield, SHIELD_MARKER


def test_install_shield_writes_ignore_files(tmp_path: Path):
    results = install_shield(tmp_path)
    assert results[".cursorignore"] is True
    assert (tmp_path / ".cursorignore").read_text().count(SHIELD_MARKER) == 1
    assert ".env" in (tmp_path / ".cursorignore").read_text()


def test_install_shield_idempotent(tmp_path: Path):
    install_shield(tmp_path)
    results = install_shield(tmp_path)
    assert results[".cursorignore"] is False


def test_verify_shield_ok_after_install(tmp_path: Path):
    install_shield(tmp_path)
    assert verify_shield(tmp_path) == []


def test_verify_shield_missing(tmp_path: Path):
    issues = verify_shield(tmp_path)
    assert any("cursorignore" in i.lower() for i in issues)


def test_claude_settings_deny_rules(tmp_path: Path):
    install_shield(tmp_path)
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    deny = settings["permissions"]["deny"]
    assert any("Read(./.env" in d for d in deny)


def test_verify_shield_requires_pretooluse_wiring(tmp_path: Path):
    install_shield(tmp_path)
    settings_path = tmp_path / ".claude" / "settings.json"
    data = json.loads(settings_path.read_text())
    data["hooks"]["PreToolUse"] = []
    settings_path.write_text(json.dumps(data))
    issues = verify_shield(tmp_path)
    assert any("PreToolUse" in i for i in issues)


def test_shield_hook_checks_glob_fields(tmp_path: Path):
    install_shield(tmp_path)
    hook = (tmp_path / ".claude" / "hooks" / "ownlock-shield.sh").read_text()
    assert "tool_input.pattern" in hook or "pattern" in hook
    assert "path_haystack" in hook.lower() or "Get-PathHaystack" in hook or "path" in hook


def test_simulate_agent_env_read_detects_plaintext(tmp_path: Path):
    from ownlock.shield import simulate_agent_env_read

    (tmp_path / ".env").write_text("API_KEY=plaintextsecret\n")
    assert simulate_agent_env_read(tmp_path) is not None


def test_simulate_agent_env_read_ignores_vault_refs(tmp_path: Path):
    from ownlock.shield import simulate_agent_env_read

    (tmp_path / ".env").write_text('API_KEY=vault("API_KEY")\n')
    assert simulate_agent_env_read(tmp_path) is None


def test_simulate_agent_env_read_ignores_non_secrets(tmp_path: Path):
    from ownlock.shield import simulate_agent_env_read

    (tmp_path / ".env").write_text("NODE_ENV=development\nLOG_LEVEL=info\n")
    assert simulate_agent_env_read(tmp_path) is None


def test_simulate_agent_env_read_detects_sk_prefix(tmp_path: Path):
    from ownlock.shield import simulate_agent_env_read

    (tmp_path / ".env").write_text("OPENAI=sk-abcdefghijklmnopqrstuvwxyz\n")
    assert simulate_agent_env_read(tmp_path) is not None


def test_install_shield_windows_uses_ps1(tmp_path: Path, monkeypatch):
    import ownlock.shield as shield

    monkeypatch.setattr(shield.os, "name", "nt")
    results = shield.install_shield(tmp_path)
    assert results[".claude/hooks/ownlock-shield.ps1"] is True
    assert (tmp_path / ".claude" / "hooks" / "ownlock-shield.ps1").exists()
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    cmd = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert cmd.startswith("powershell -NoProfile -File")
    assert "ownlock-shield.ps1" in cmd
    assert shield.verify_shield(tmp_path) == []


def test_verify_shield_bad_json(tmp_path: Path):
    install_shield(tmp_path)
    settings = tmp_path / ".claude" / "settings.json"
    settings.write_text("{bad")
    issues = verify_shield(tmp_path)
    assert any("valid JSON" in i for i in issues)
