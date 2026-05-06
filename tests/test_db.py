"""Database URL normalization and engine wiring.

Targets: mcp-gmail/src/mcp_gmail/db.py:_normalize_database_url

The helper rewrites bare `postgresql://` and legacy `postgres://` URL
schemes to `postgresql+psycopg://` so SQLAlchemy binds to psycopg v3
(the driver we actually ship). Anything that already names a driver,
or is not a Postgres URL at all, is passed through unchanged.

These tests are the durable regression guard against the original
ImportError ("No module named 'psycopg2'") that surfaced on Railway
in production.
"""

from __future__ import annotations

import pytest

from mcp_gmail.db import _normalize_database_url


@pytest.mark.parametrize(
    "given, expected",
    [
        # Bare postgresql:// gets rewritten.
        (
            "postgresql://u:p@h/d",
            "postgresql+psycopg://u:p@h/d",
        ),
        # Legacy postgres:// (Railway-style) gets rewritten.
        (
            "postgres://u:p@h/d",
            "postgresql+psycopg://u:p@h/d",
        ),
        # Already on psycopg v3: idempotent.
        (
            "postgresql+psycopg://u:p@h/d",
            "postgresql+psycopg://u:p@h/d",
        ),
        # Operator explicitly chose psycopg2: respect it.
        (
            "postgresql+psycopg2://u:p@h/d",
            "postgresql+psycopg2://u:p@h/d",
        ),
        # Operator explicitly chose asyncpg: respect it (defensive).
        (
            "postgresql+asyncpg://u:p@h/d",
            "postgresql+asyncpg://u:p@h/d",
        ),
        # SQLite passes through unchanged.
        (
            "sqlite:///:memory:",
            "sqlite:///:memory:",
        ),
        # Empty string passes through; SQLAlchemy raises its own clear error.
        ("", ""),
        # URL-encoded password (`%40` == `@`) survives byte-exact, scheme
        # is still rewritten. This is the regression test that justified
        # using `str.replace` on the prefix instead of urlsplit/urlunsplit.
        (
            "postgresql://u:p%40ss@h/d",
            "postgresql+psycopg://u:p%40ss@h/d",
        ),
    ],
)
def test_normalize_database_url(given: str, expected: str) -> None:
    assert _normalize_database_url(given) == expected


def test_normalize_database_url_no_scheme_passthrough() -> None:
    """Bare hostnames (no scheme) pass through so SQLAlchemy raises its own error.

    The helper deliberately does not invent a scheme. Garbage in, garbage
    out, with the error surfaced by SQLAlchemy at create_engine time.
    """
    assert _normalize_database_url("not-a-url") == "not-a-url"


def test_normalize_database_url_preserves_query_and_options() -> None:
    """Query string and connection options ride along untouched.

    SQLAlchemy URLs commonly carry sslmode, application_name, and other
    parameters after the database name. The helper must not mangle them.
    """
    given = "postgresql://u:p@h:5432/d?sslmode=require&application_name=mcp-gmail"
    expected = "postgresql+psycopg://u:p@h:5432/d?sslmode=require&application_name=mcp-gmail"
    assert _normalize_database_url(given) == expected


def test_normalize_database_url_is_case_sensitive() -> None:
    """Match is case-sensitive by contract (see helper docstring).

    Operators using non-standard casing get the SQLAlchemy default
    behavior. Documenting the contract is preferred over silently
    second-guessing input.
    """
    # Mixed-case scheme is not rewritten.
    assert _normalize_database_url("Postgresql://u:p@h/d") == "Postgresql://u:p@h/d"
