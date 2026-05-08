"""PKCE (RFC 7636) primitives.

Targets: mcp-gmail/src/mcp_gmail/pkce.py:generate_verifier
Targets: mcp-gmail/src/mcp_gmail/pkce.py:compute_challenge

The first case pins the implementation to the RFC 7636 §4.6 published
test vector. A regression that breaks SHA-256 hashing or the
base64url-no-pad output will fail this case loudly.
"""

from __future__ import annotations

import re

import pytest

from mcp_gmail.pkce import compute_challenge, generate_verifier


# RFC 7636 §4.6 published test vector.
# Verifier:
#   dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
# Expected S256 challenge:
#   E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
RFC_7636_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_7636_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_compute_challenge_rfc_7636_section_4_6_vector():
    """Anchor the S256 transform to the RFC's published test vector."""
    assert compute_challenge(RFC_7636_VERIFIER) == RFC_7636_CHALLENGE


def test_generate_verifier_length_and_charset():
    """Verifier must be 64 chars from the URL-safe base64 unreserved set.

    secrets.token_urlsafe(48) yields 64 base64url chars. The character
    class is a strict subset of RFC 7636 §4.1's unreserved set
    (A-Z / a-z / 0-9 / '-' / '.' / '_' / '~'); we never emit '.' or '~'
    so the regex below is tight.
    """
    v = generate_verifier()
    assert len(v) == 64
    assert re.fullmatch(r"[A-Za-z0-9_-]+", v) is not None


def test_generate_verifier_entropy_smoke():
    """Ten draws must all be distinct. 384-bit entropy makes a collision
    over ten draws astronomically unlikely; this catches a swap to a
    deterministic generator."""
    seen = {generate_verifier() for _ in range(10)}
    assert len(seen) == 10


def test_compute_challenge_rejects_empty_verifier():
    """Empty input must raise ValueError, not return SHA-256 of empty.

    Real callers always pass generate_verifier() output, so this is
    structural prevention against a bug that bypasses minting and
    feeds an empty string.
    """
    with pytest.raises(ValueError):
        compute_challenge("")


def test_compute_challenge_pure_function():
    """Same input must produce same output every time (regression guard
    against an accidental introduction of randomness)."""
    a = compute_challenge("some-stable-verifier-string")
    b = compute_challenge("some-stable-verifier-string")
    assert a == b
