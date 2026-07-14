"""Tests for ownlock shield."""

from __future__ import annotations

import json
import re
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
    assert results[".claude/settings.json"] is False
    assert results[".cursor/hooks.json"] is False


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
    import os

    install_shield(tmp_path)
    name = "ownlock-shield.ps1" if os.name == "nt" else "ownlock-shield.sh"
    hook = (tmp_path / ".claude" / "hooks" / name).read_text()
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

    (tmp_path / ".env").write_text(
        "NODE_ENV=development\nLOG_LEVEL=info\n"
        "CUSTOM_TOKENIZER=bert-base\nSECRETARY=alice\n"
    )
    assert simulate_agent_env_read(tmp_path) is None


def test_simulate_agent_env_read_detects_sk_prefix(tmp_path: Path):
    from ownlock.shield import simulate_agent_env_read

    (tmp_path / ".env").write_text("OPENAI=sk-abcdefghijklmnopqrstuvwxyz\n")
    assert simulate_agent_env_read(tmp_path) is not None


def test_install_shield_windows_uses_ps1(tmp_path: Path, monkeypatch):
    import ownlock.shield as shield

    monkeypatch.setattr(shield.os, "name", "nt")
    no_hermes = tmp_path / "no-hermes"
    results = shield.install_shield(tmp_path, hermes_home=no_hermes)
    assert results[".claude/hooks/ownlock-shield.ps1"] is True
    assert (tmp_path / ".claude" / "hooks" / "ownlock-shield.ps1").exists()
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    ownlock_cmds = [
        h["command"]
        for e in settings["hooks"]["PreToolUse"]
        for h in e.get("hooks") or []
        if "ownlock-shield" in h.get("command", "")
    ]
    assert len(ownlock_cmds) == 1
    assert ownlock_cmds[0].startswith("powershell -NoProfile -File")
    assert "ownlock-shield.ps1" in ownlock_cmds[0]
    assert shield.verify_shield(tmp_path, hermes_home=no_hermes) == []


def test_verify_accepts_other_os_hook_file(tmp_path: Path, monkeypatch):
    """Settings wired to .sh still verify on Windows if the .sh file exists."""
    import ownlock.shield as shield

    no_hermes = tmp_path / "no-hermes"
    install_shield(tmp_path, hermes_home=no_hermes)
    monkeypatch.setattr(shield.os, "name", "nt")
    assert shield.verify_shield(tmp_path, hermes_home=no_hermes) == []


def test_cross_os_install_upserts_single_pretooluse(tmp_path: Path, monkeypatch):
    import ownlock.shield as shield

    no_hermes = tmp_path / "no-hermes"
    monkeypatch.setattr(shield.os, "name", "posix")
    shield.install_shield(tmp_path, hermes_home=no_hermes)
    monkeypatch.setattr(shield.os, "name", "nt")
    shield.install_shield(tmp_path, hermes_home=no_hermes)
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    ownlock = [
        e
        for e in settings["hooks"]["PreToolUse"]
        if any(
            "ownlock-shield" in str(h.get("command", ""))
            for h in (e.get("hooks") or [])
        )
    ]
    assert len(ownlock) == 1
    cmd = ownlock[0]["hooks"][0]["command"]
    assert "ownlock-shield.ps1" in cmd
    assert cmd.startswith("powershell")


def test_cursor_hooks_json_installed(tmp_path: Path):
    install_shield(tmp_path)
    hooks = json.loads((tmp_path / ".cursor" / "hooks.json").read_text())
    assert hooks["version"] == 1
    assert "beforeReadFile" in hooks["hooks"]
    assert "beforeShellExecution" in hooks["hooks"]
    assert "preToolUse" in hooks["hooks"]
    pre = hooks["hooks"]["preToolUse"][0]
    assert "matcher" not in pre  # all tools incl. MCP / Glob / Search
    cmd = hooks["hooks"]["beforeReadFile"][0]["command"]
    assert "ownlock-shield" in cmd
    assert (tmp_path / ".cursor" / "hooks" / "ownlock-shield.sh").exists()
    assert (tmp_path / ".cursor" / "hooks" / "ownlock-shield.ps1").exists()
    sh = (tmp_path / ".cursor" / "hooks" / "ownlock-shield.sh").read_text()
    assert "permission" in sh
    assert "target_directory" in sh
    assert "working_directory" in sh
    assert ".cwd // empty" in sh
    ps1 = (tmp_path / ".cursor" / "hooks" / "ownlock-shield.ps1").read_text()
    assert "target_directory" in ps1
    assert "working_directory" in ps1


def test_hermes_emitter_writes_snippet_and_merges_config(tmp_path: Path, monkeypatch):
    hermes = tmp_path / "hermes_home"
    hermes.mkdir()
    (hermes / "config.yaml").write_text("model: test\n", encoding="utf-8")
    results = install_shield(tmp_path, hermes_home=hermes)
    assert (tmp_path / ".ownlock" / "hooks" / "ownlock-hermes-shield.sh").exists()
    assert (tmp_path / ".ownlock" / "hermes-hooks.snippet.yaml").exists()
    assert results["~/.hermes/config.yaml"] is True
    cfg = (hermes / "config.yaml").read_text()
    assert "ownlock-shield-begin" in cfg
    assert "ownlock-hermes-shield" in cfg
    # Single-quoted YAML so Windows backslashes are literal.
    assert "command: '" in cfg or "command: '" in (tmp_path / ".ownlock" / "hermes-hooks.snippet.yaml").read_text()
    assert verify_shield(tmp_path, hermes_home=hermes) == []


def test_hermes_yaml_single_quotes_windows_path():
    from ownlock.shield import _hermes_hook_item, _yaml_single_quoted

    win = r"C:\Users\tmp\tools\ownlock-hermes-shield.ps1"
    assert _yaml_single_quoted(win) == f"'{win}'"
    item = _hermes_hook_item(Path(win))
    assert r"\tools" in item
    assert 'command: "' not in item
    assert f"command: '{win}'" in item


def test_hermes_merge_does_not_orphan_when_already_configured(tmp_path: Path):
    from ownlock.shield import _merge_hermes_config

    hermes = tmp_path / "hermes_home"
    hermes.mkdir()
    script = tmp_path / ".ownlock" / "hooks" / "ownlock-hermes-shield.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    cfg = hermes / "config.yaml"
    cfg.write_text(
        "hooks:\n"
        "  pre_tool_call:\n"
        f"    - matcher: \".*\"\n"
        f"      command: '{script.resolve()}'\n"
        "      timeout: 5\n",
        encoding="utf-8",
    )
    before = cfg.read_text()
    assert _merge_hermes_config(cfg, script.resolve()) is False
    after = cfg.read_text()
    assert after == before
    assert after.count("ownlock-hermes-shield") == 1
    assert after.count("ownlock-shield-begin") == 0


def test_hermes_merge_nests_under_existing_hooks_key(tmp_path: Path):
    from ownlock.shield import _merge_hermes_config

    hermes = tmp_path / "hermes_home"
    hermes.mkdir()
    script = tmp_path / ".ownlock" / "hooks" / "ownlock-hermes-shield.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    cfg = hermes / "config.yaml"
    cfg.write_text("model: test\nhooks:\n  on_session_start: []\n", encoding="utf-8")
    assert _merge_hermes_config(cfg, script.resolve()) is True
    text = cfg.read_text()
    # pre_tool_call must sit under hooks:, not as an orphan after unrelated keys.
    hooks_idx = text.index("hooks:")
    ptc_idx = text.index("pre_tool_call:")
    assert ptc_idx > hooks_idx
    assert "on_session_start" in text
    # The block after hooks: should include pre_tool_call before EOF junk patterns.
    after_hooks = text[hooks_idx:]
    assert "pre_tool_call:" in after_hooks
    assert not re.search(r"(?m)^pre_tool_call:", text)


def test_hermes_merge_refreshes_stale_command_path(tmp_path: Path):
    from ownlock.shield import _merge_hermes_config

    hermes = tmp_path / "hermes_home"
    hermes.mkdir()
    script = tmp_path / ".ownlock" / "hooks" / "ownlock-hermes-shield.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    cfg = hermes / "config.yaml"
    cfg.write_text(
        "hooks:\n"
        "  pre_tool_call:\n"
        "    - matcher: \".*\"\n"
        "      command: '/old/path/ownlock-hermes-shield.sh'\n"
        "      timeout: 5\n",
        encoding="utf-8",
    )
    assert _merge_hermes_config(cfg, script.resolve()) is True
    text = cfg.read_text()
    assert str(script.resolve()) in text
    assert "/old/path/" not in text
    assert text.count("ownlock-hermes-shield") == 1


def test_hermes_hooks_join_all_path_fields(tmp_path: Path):
    install_shield(tmp_path, hermes_home=tmp_path / "no-hermes")
    sh = (tmp_path / ".ownlock" / "hooks" / "ownlock-hermes-shield.sh").read_text()
    assert "map(select(length > 0))" in sh
    assert "target_directory" in sh
    # First-only // chain would stop early; joined array must list every field.
    assert ".tool_input.file_path // empty" in sh
    assert ".tool_input.glob // empty" in sh
    ps1 = (tmp_path / ".ownlock" / "hooks" / "ownlock-hermes-shield.ps1").read_text()
    assert "$parts +=" in ps1
    assert "target_directory" in ps1


def test_hermes_tip_when_home_missing(tmp_path: Path):
    missing = tmp_path / "no-hermes"
    results = install_shield(tmp_path, hermes_home=missing)
    assert results.get("hermes_tip") is True
    assert results["~/.hermes/config.yaml"] is False


def test_pi_emitter_writes_extension_and_settings(tmp_path: Path):
    install_shield(tmp_path)
    ext = tmp_path / ".ownlock" / "pi" / "ownlock-shield.js"
    assert ext.exists()
    assert "tool_call" in ext.read_text()
    settings = json.loads((tmp_path / ".pi" / "settings.json").read_text())
    assert any("ownlock-shield" in e for e in settings["extensions"])


def test_verify_shield_bad_json(tmp_path: Path):
    install_shield(tmp_path)
    settings = tmp_path / ".claude" / "settings.json"
    settings.write_text("{bad")
    issues = verify_shield(tmp_path)
    assert any("valid JSON" in i for i in issues)
