"""PRIOR_ENCRYPTION_KEYS parsing + validation at config load.

Targets: mcp-gmail/src/mcp_gmail/config.py:load
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from mcp_gmail import config as config_module


def test_prior_keys_default_is_empty(monkeypatch):
    """Absent env var produces an empty tuple."""
    monkeypatch.delenv("PRIOR_ENCRYPTION_KEYS", raising=False)
    settings = config_module.load()
    assert settings.prior_encryption_keys == ()


def test_prior_keys_parses_comma_separated(monkeypatch):
    """Multiple keys separated by commas are split, stripped, ordered."""
    k1 = Fernet.generate_key().decode("ascii")
    k2 = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("PRIOR_ENCRYPTION_KEYS", f"{k1}, {k2}")
    settings = config_module.load()
    assert settings.prior_encryption_keys == (k1, k2)


def test_prior_keys_rejects_malformed_value(monkeypatch):
    monkeypatch.setenv("PRIOR_ENCRYPTION_KEYS", "not-a-key")
    with pytest.raises(RuntimeError, match="PRIOR_ENCRYPTION_KEYS"):
        config_module.load()


def test_prior_key_equal_to_primary_rejected(monkeypatch):
    primary = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("ENCRYPTION_KEY", primary)
    monkeypatch.setenv("PRIOR_ENCRYPTION_KEYS", primary)
    with pytest.raises(RuntimeError, match="equals ENCRYPTION_KEY"):
        config_module.load()


def test_prior_key_equal_to_state_signing_rejected(monkeypatch):
    state_key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("STATE_SIGNING_KEY", state_key)
    monkeypatch.setenv("PRIOR_ENCRYPTION_KEYS", state_key)
    with pytest.raises(RuntimeError, match="equals STATE_SIGNING_KEY"):
        config_module.load()


def test_duplicate_prior_keys_rejected(monkeypatch):
    k = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("PRIOR_ENCRYPTION_KEYS", f"{k},{k}")
    with pytest.raises(RuntimeError, match="duplicated"):
        config_module.load()


def test_empty_string_in_list_skipped(monkeypatch):
    """Trailing comma or blank entry is forgiving (operator typo safety)."""
    k = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("PRIOR_ENCRYPTION_KEYS", f"{k},,")
    settings = config_module.load()
    assert settings.prior_encryption_keys == (k,)
