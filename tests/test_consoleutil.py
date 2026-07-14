"""Tests for Windows-safe console markers."""

from __future__ import annotations


def test_fail_mark_ascii_when_cp1252(monkeypatch):
    import ownlock.consoleutil as cu

    class FakeStdout:
        encoding = "cp1252"

    monkeypatch.setattr(cu.sys, "stdout", FakeStdout())
    # ✗ is not in cp1252; • (U+2022) is at 0x95 and still encodes.
    assert cu.fail_mark() == "[x]"
    assert cu.bullet_mark() == "•"


def test_markers_ascii_when_ascii_stdout(monkeypatch):
    import ownlock.consoleutil as cu

    class FakeStdout:
        encoding = "ascii"

    monkeypatch.setattr(cu.sys, "stdout", FakeStdout())
    assert cu.fail_mark() == "[x]"
    assert cu.bullet_mark() == "-"


def test_fail_mark_unicode_when_utf8(monkeypatch):
    import ownlock.consoleutil as cu

    class FakeStdout:
        encoding = "utf-8"

    monkeypatch.setattr(cu.sys, "stdout", FakeStdout())
    assert cu.fail_mark() == "✗"
    assert cu.bullet_mark() == "•"


def test_configure_stdio_reconfigure_on_windows(monkeypatch):
    import ownlock.consoleutil as cu

    calls: list[dict] = []

    class FakeStream:
        def reconfigure(self, **kwargs):
            calls.append(kwargs)

    monkeypatch.setattr(cu.os, "name", "nt")
    monkeypatch.setattr(cu.sys, "stdout", FakeStream())
    monkeypatch.setattr(cu.sys, "stderr", FakeStream())
    cu.configure_stdio()
    assert calls == [
        {"encoding": "utf-8", "errors": "replace"},
        {"encoding": "utf-8", "errors": "replace"},
    ]
