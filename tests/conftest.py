"""Shared test fixtures for mcp-gmail.

Targets: mcp-gmail/src/mcp_gmail/config.py:load
Targets: mcp-gmail/src/mcp_gmail/db.py:init_engine

We use SQLite in-memory (one shared connection so the schema persists
across the test) for storage tests. The migration is exercised against
SQLite to keep CI fast; the production target is Postgres, and the
Postgres-specific CHECK constraint is verified separately by a string
match in the migration test (since SQLite parses but does not enforce
CHECK on writes the same way Postgres does).
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mcp_gmail import auth as auth_module
from mcp_gmail import config as config_module
from mcp_gmail import db as db_module
from mcp_gmail import health as health_module
from mcp_gmail import token_store as token_store_module
from mcp_gmail.db import Base


TEST_KID = "test-kid-1"
TEST_ISSUER = "https://issuer.test.local"
TEST_RESOURCE = "https://mcp-gmail.test.local"
TEST_JWKS_URL = "https://issuer.test.local/.well-known/jwks.json"

# Two distinct Fernet keys, one for encryption and one for state signing.
TEST_ENCRYPTION_KEY = Fernet.generate_key().decode("ascii")
TEST_STATE_SIGNING_KEY = Fernet.generate_key().decode("ascii")


@pytest.fixture(scope="session")
def rsa_keypair():
    """Generate an RSA key once per test session."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_numbers = key.public_key().public_numbers()

    def int_to_b64url(n: int) -> str:
        import base64

        length = (n.bit_length() + 7) // 8
        data = n.to_bytes(length, "big")
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": TEST_KID,
        "n": int_to_b64url(public_numbers.n),
        "e": int_to_b64url(public_numbers.e),
    }
    return {"private_pem": private_pem, "jwk": jwk}


@pytest.fixture(autouse=True)
def env(monkeypatch, rsa_keypair) -> Iterator[None]:
    """Set a consistent env for every test."""
    monkeypatch.setenv("OAUTH_ISSUER_URL", TEST_ISSUER)
    monkeypatch.setenv("OAUTH_JWKS_URL", TEST_JWKS_URL)
    monkeypatch.setenv("MCP_RESOURCE_URL", TEST_RESOURCE)
    monkeypatch.setenv("MCP_EXPECTED_SCOPES", "")
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "false")
    monkeypatch.setenv("JWKS_CACHE_TTL_SECONDS", "300")
    monkeypatch.setenv("HTTP_TIMEOUT_SECONDS", "5")
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)
    # explicitly clear so a host env var leaking in
    # cannot accidentally activate MultiFernet for unrelated tests.
    monkeypatch.setenv("PRIOR_ENCRYPTION_KEYS", "")
    monkeypatch.setenv("STATE_SIGNING_KEY", TEST_STATE_SIGNING_KEY)
    # default the allowlist to the standard test
    # principal "user-abc" used across the suite. Tests that exercise
    # allowlist-rejection paths override this via monkeypatch within
    # the test body.
    # default test allowlist holds the single
    # principal "user-abc" matching the signed_jwt fixture default.
    # Tests that exercise multi-user-mode flows or specific
    # allowlist behavior override this via monkeypatch within their
    # bodies. Single entry keeps `requires_confirm_page=False` so
    #  tests (which expect inline persistence on the
    # callback) continue to pass.
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "user-abc")
    monkeypatch.setenv("MCP_ALLOW_ANY_AUTH0_SUB", "false")
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    monkeypatch.setenv("PORT", "8000")
    # Google OAuth. All three are required at config load time.
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("GOOGLE_OAUTH_REDIRECT_URL", "https://mcp-gmail.test.local/oauth2callback")
    monkeypatch.setenv(
        "GMAIL_OAUTH_SCOPES",
        "openid email https://www.googleapis.com/auth/gmail.readonly",
    )
    auth_module.reset_cache_for_tests()
    db_module.reset_for_tests()
    token_store_module.reset_locks_for_tests()
    health_module.reset_for_tests()
    yield
    auth_module.reset_cache_for_tests()
    db_module.reset_for_tests()
    token_store_module.reset_locks_for_tests()
    health_module.reset_for_tests()


@pytest.fixture
def settings():
    return config_module.load()


@pytest.fixture
def signed_jwt(rsa_keypair):
    """Factory that signs a JWT with the session RSA key."""
    import jwt

    def _make(claims: dict | None = None, headers: dict | None = None) -> str:
        now = int(time.time())
        base = {
            "iss": TEST_ISSUER,
            "aud": TEST_RESOURCE,
            "sub": "user-abc",
            "iat": now,
            "exp": now + 3600,
        }
        if claims:
            base.update(claims)
        hdr = {"kid": TEST_KID, "alg": "RS256"}
        if headers:
            hdr.update(headers)
        return jwt.encode(
            base,
            rsa_keypair["private_pem"],
            algorithm="RS256",
            headers=hdr,
        )

    return _make


@pytest.fixture
def jwks_document(rsa_keypair):
    return {"keys": [rsa_keypair["jwk"]]}


@pytest.fixture
def in_memory_session():
    """Yield a SQLAlchemy session against an isolated in-memory SQLite database.

    StaticPool + a single connection across the engine keeps the schema
    in scope for the entire test (default SQLite in-memory throws away
    its data the moment the connection closes).
    """
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
