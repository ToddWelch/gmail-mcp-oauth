"""Fernet symmetric encryption for OAuth tokens at rest.

The Google OAuth refresh token is the most sensitive secret this
service holds. A leaked database row that contains the plaintext
refresh token would let an attacker pull the user's mail indefinitely
without re-prompting. Fernet provides AES-128-CBC + HMAC-SHA256
authenticated encryption with a built-in timestamp.

The module supports `cryptography.fernet.MultiFernet`
so an operator can rotate `ENCRYPTION_KEY` without forcing every
existing user to re-link their mailbox. The signature is a backward-
compatible varargs extension: `encrypt(plaintext, key)` and
`decrypt(ciphertext, key)` continue to work; passing one or more
`*prior` keys after the primary signals "decrypt with the primary if
possible, otherwise fall back to a prior key, and on the next encrypt
re-encrypt under the primary." That last property is what
`MultiFernet` calls "rotate" and is the underlying primitive a future
re-encryption pass can call.

This module is deliberately tiny. The wrapper exists so callers don't
import `cryptography.fernet` directly; that gives us one place to
change the encryption primitive if we ever need to rotate or migrate.

Key format
----------
ENCRYPTION_KEY (and any PRIOR_ENCRYPTION_KEYS entries) must each be a
Fernet key: 32 bytes, URL-safe base64-encoded (44 ASCII chars).
Generate one with:

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Any other input shape raises `cryptography.fernet.InvalidKey` (or our
wrapped CryptoError) at construction time, so a misconfigured operator
finds out at boot, not at the first OAuth callback.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet


class CryptoError(Exception):
    """Raised when encryption or decryption fails."""


def _fernet(key: str) -> Fernet:
    """Build a Fernet instance from the configured key.

    Fernet itself raises ValueError on a malformed key; we wrap that in
    CryptoError so callers see a single exception type.
    """
    try:
        return Fernet(key.encode("utf-8") if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"ENCRYPTION_KEY is not a valid Fernet key: {exc}") from exc


def _make_engine(key: str, *prior: str) -> Fernet | MultiFernet:
    """Return Fernet for single-key, MultiFernet when prior keys are present.

    MultiFernet decrypts with the first key whose key matches; encrypts
    only with the first (primary) key. The `prior` ordering matters:
    older keys go later. Operators rotate by prepending a fresh primary
    and pushing the previous primary into the prior tuple.

    Returning a plain Fernet for the single-key case keeps the hot path
    cheap and avoids a MultiFernet wrapper allocation when no rotation
    is configured (the overwhelming majority of callers in practice).
    """
    primary = _fernet(key)
    if not prior:
        return primary
    # MultiFernet([primary, *prior_fernets]) decrypts in order; encrypts
    # always with the first entry. That matches the rotation semantic
    # we want: new ciphertext under the new key, old ciphertext still
    # readable until a re-encrypt pass runs.
    return MultiFernet([primary, *(_fernet(k) for k in prior)])


def encrypt(plaintext: str, key: str, *prior: str) -> bytes:
    """Encrypt plaintext with the configured Fernet key.

    Returns the ciphertext as bytes (the Fernet token format, which
    includes version, timestamp, IV, ciphertext, and HMAC). Storing as
    bytes lets the database column be `BYTEA`, which is more compact
    and keeps non-ASCII data out of TEXT columns.

    `*prior` is accepted but unused on the encrypt path: MultiFernet
    always encrypts under the primary (first) key. The signature is
    kept symmetric with `decrypt` so the call sites can pass the same
    settings tuple to both without branching on which is which.
    """
    engine = _make_engine(key, *prior)
    return engine.encrypt(plaintext.encode("utf-8"))


def decrypt(ciphertext: bytes, key: str, *prior: str) -> str:
    """Decrypt ciphertext with the configured Fernet key.

    When `*prior` keys are passed, MultiFernet attempts each in order.
    First match wins. Returns the plaintext string.

    Raises CryptoError on any of: malformed token, tampered HMAC,
    expired token (Fernet has a built-in TTL we don't currently use,
    but the surface is the same), or wrong key (no key in the chain
    decrypted successfully).
    """
    engine = _make_engine(key, *prior)
    try:
        return engine.decrypt(ciphertext).decode("utf-8")
    except InvalidToken as exc:
        raise CryptoError("decrypt failed: token is invalid or no key matched") from exc
