"""Readiness state module: marks, snapshot, reset.

Targets: mcp-gmail/src/mcp_gmail/health.py
"""

from __future__ import annotations

from mcp_gmail import health as health_module


def test_initial_state_not_ready():
    snapshot = health_module.snapshot()
    assert snapshot["ready"] is False
    assert snapshot["settings_loaded"] is False
    assert snapshot["db_ready"] is False
    assert snapshot["jwks_warm"] is False


def test_partial_marks_not_ready():
    health_module.mark_settings_loaded()
    health_module.mark_db_ready()
    # jwks_warm still false
    snap = health_module.snapshot()
    assert snap["ready"] is False
    assert snap["settings_loaded"] is True
    assert snap["db_ready"] is True
    assert snap["jwks_warm"] is False


def test_all_marks_ready():
    health_module.mark_settings_loaded()
    health_module.mark_db_ready()
    health_module.mark_jwks_warm()
    assert health_module.is_ready() is True
    assert health_module.snapshot()["ready"] is True


def test_record_failure_visible_in_snapshot():
    health_module.record_failure("db", "ConnectionRefused")
    snap = health_module.snapshot()
    assert snap["failures"]["db"] == "ConnectionRefused"


def test_mark_after_failure_clears_that_failure():
    health_module.record_failure("db", "ConnectionRefused")
    health_module.mark_db_ready()
    snap = health_module.snapshot()
    assert "db" not in snap["failures"]


def test_reset_for_tests_wipes_state():
    health_module.mark_settings_loaded()
    health_module.mark_db_ready()
    health_module.reset_for_tests()
    assert health_module.is_ready() is False
    snap = health_module.snapshot()
    assert snap["settings_loaded"] is False
    assert snap["db_ready"] is False
