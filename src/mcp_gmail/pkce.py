"""PKCE (RFC 7636) primitives for the Google OAuth authorization-code flow.

Pure functions, no I/O. Generates a cryptographically random code_verifier
and computes the S256 code_challenge per RFC 7636 sections 4.1 and 4.2.

This module exists separately from oauth_state.py to keep that file
under the 300-LOC project cap. We do NOT support the `plain` method;
S256 is the only RFC-compliant choice for a server with SHA-256
available (which is everywhere this code runs).
"""

from __future__ import annotations

import base64
import hashlib
import secrets


# RFC 7636 §4.1 allows 43 to 128 chars from the unreserved set.
# secrets.token_urlsafe(48) -> 64 base64url chars, 384 bits of entropy.
# 64 sits comfortably mid-range; 128 would add ~64 bytes to state with
# no meaningful security gain.
_VERIFIER_BYTES = 48  # -> 64 base64url chars


def generate_verifier() -> str:
    """Return a fresh per-flow PKCE code_verifier.

    Output: 64-character URL-safe base64 string. Within RFC 7636 §4.1's
    43-128 range with margin; 384 bits of entropy via secrets.token_urlsafe.
    The character set is the URL-safe base64 alphabet (A-Z, a-z, 0-9, '-',
    '_'), which is a strict subset of the unreserved set RFC 7636 §4.1
    permits.
    """
    return secrets.token_urlsafe(_VERIFIER_BYTES)


def compute_challenge(verifier: str) -> str:
    """Compute the S256 code_challenge per RFC 7636 §4.2.

    Definition: BASE64URL-ENCODE(SHA256(ASCII(verifier))). Output is
    base64url with no padding. The encoding is RFC 4648 §5 with the
    trailing '=' bytes stripped, per RFC 7636 §3 (which references
    RFC 4648 and §B.1 for the no-pad form).

    Empty input is rejected with ValueError to fail loudly rather than
    return the SHA-256 of the empty string, which would be a usable
    challenge that fails on Google's side in a confusing way. Real
    callers always feed the output of generate_verifier(), so the
    empty-string path is structural prevention only.
    """
    if not verifier:
        raise ValueError("verifier is required")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
