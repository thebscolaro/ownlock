"""Rotation reminders: helpers, list Age column, doctor nudge."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from ownlock.cli import app
from ownlock.rotation import age_days, format_age, rotation_days
from ownlock.vault import VaultManager

PASSPHRASE = "rotation-pass"
runner = CliRunner(env={"OWNLOCK_PASSPHRASE": PASSPHRASE, "OWNLOCK_AUDIT": "0"})


class TestHelpers:
    def test_rotation_days_default(self, monkeypatch):
        monkeypatch.delenv("OWNLOCK_ROTATION_DAYS", raising=False)
        assert rotation_days() == 90

    def test_rotation_days_override(self, monkeypatch):
        monkeypatch.setenv("OWNLOCK_ROTATION_DAYS", "30")
        assert rotation_days() == 30

    @pytest.mark.parametrize("bad", ["", "abc", "0", "-5"])
    def test_rotation_days_invalid_falls_back(self, monkeypatch, bad):
        monkeypatch.setenv("OWNLOCK_ROTATION_DAYS", bad)
        assert rotation_days() == 90

    def test_age_days(self):
        now = datetime(2026, 7, 14, tzinfo=UTC)
        then = (now - timedelta(days=91)).isoformat()
        assert age_days(then, now=now) == 91

    def test_age_days_naive_timestamp_treated_utc(self):
        now = datetime(2026, 7, 14, tzinfo=UTC)
        assert age_days("2026-07-04T00:00:00", now=now) == 10

    def test_age_days_unparseable(self):
        assert age_days("not-a-date") is None
        assert age_days(None) is None  # type: ignore[arg-type]

    def test_format_age(self):
        assert format_age(None) == ""
        assert format_age(0) == "0d"
        assert format_age(120) == "120d"


@pytest.fixture()
def stale_vault(tmp_path, monkeypatch):
    """Project vault with one fresh and one 100-day-old secret."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / ".ownlock" / "vault.db"
    with VaultManager(db, PASSPHRASE) as vm:
        vm.set("FRESH_KEY", "freshvalue123")
        vm.set("OLD_KEY", "oldvalue12345")
        old_ts = (datetime.now(UTC) - timedelta(days=100)).isoformat()
        conn = vm._require_conn()
        rows = conn.execute("SELECT name_lookup FROM secrets").fetchall()
        # Backdate one row (name_enc is encrypted, so just pick the first).
        conn.execute(
            "UPDATE secrets SET updated_at = ? WHERE name_lookup = ?",
            (old_ts, rows[0]["name_lookup"]),
        )
        conn.commit()
    return db


class TestListAgeColumn:
    def test_age_column_and_stale_nudge(self, stale_vault):
        result = runner.invoke(app, ["list", "--project"])
        assert result.exit_code == 0, result.output
        assert "Age" in result.output
        assert "100d" in result.output
        assert "not rotated in 90+ days" in result.output

    def test_no_nudge_when_fresh(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        db = tmp_path / ".ownlock" / "vault.db"
        with VaultManager(db, PASSPHRASE) as vm:
            vm.set("FRESH_KEY", "freshvalue123")
        result = runner.invoke(app, ["list", "--project"])
        assert result.exit_code == 0, result.output
        assert "not rotated" not in result.output

    def test_threshold_override(self, stale_vault, monkeypatch):
        monkeypatch.setenv("OWNLOCK_ROTATION_DAYS", "365")
        result = runner.invoke(
            app,
            ["list", "--project"],
            env={
                "OWNLOCK_PASSPHRASE": PASSPHRASE,
                "OWNLOCK_AUDIT": "0",
                "OWNLOCK_ROTATION_DAYS": "365",
            },
        )
        assert result.exit_code == 0, result.output
        assert "not rotated" not in result.output


class TestDoctorRotation:
    def test_vault_health_counts_stale(self, stale_vault):
        from ownlock.doctor import vault_health

        info = vault_health(stale_vault)
        assert info["stale_rotation_count"] == 1

    def test_doctor_renders_nudge(self, stale_vault):
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0, result.output
        assert "not rotated in 90+ days" in result.output

    def test_doctor_json_includes_counts(self, stale_vault):
        import json

        result = runner.invoke(app, ["doctor", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["rotation_days"] == 90
        assert payload["project_vault"]["stale_rotation_count"] == 1
