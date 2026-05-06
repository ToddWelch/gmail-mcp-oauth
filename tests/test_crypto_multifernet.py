"""MultiFernet rotation behavior on the crypto wrapper.

Targets: mcp-gmail/src/mcp_gmail/crypto.py:encrypt
Targets: mcp-gmail/src/mcp_gmail/crypto.py:decrypt

when prior keys are passed, MultiFernet:
- always encrypts with the primary (first) key
- decrypts with the first matching key in the chain
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from mcp_gmail.crypto import CryptoError, decrypt, encrypt


def test_decrypt_with_prior_key_after_rotation():
    """Token written under the old key still decrypts after key rotation."""
    old_key = Fernet.generate_key().decode("ascii")
    new_key = Fernet.generate_key().decode("ascii")
    plaintext = "1//refresh-token"

    # Encrypt under old key, simulating "this row was written before
    # rotation"
    blob = encrypt(plaintext, old_key)

    # After rotation the operator config is: primary = new_key,
    # prior = (old_key,). The crypto layer routes through MultiFernet.
    assert decrypt(blob, new_key, old_key) == plaintext


def test_encrypt_after_rotation_uses_new_key_only():
    """Post-rotation encrypt produces ciphertext readable by new key alone."""
    old_key = Fernet.generate_key().decode("ascii")
    new_key = Fernet.generate_key().decode("ascii")

    blob = encrypt("rt-after-rotation", new_key, old_key)

    # Single-key decrypt under new_key works (proves new ciphertext was
    # written with new_key, not old_key).
    assert decrypt(blob, new_key) == "rt-after-rotation"


def test_decrypt_no_match_raises():
    """Ciphertext under an unrelated key fails through the whole chain."""
    rogue_key = Fernet.generate_key().decode("ascii")
    primary = Fernet.generate_key().decode("ascii")
    prior = Fernet.generate_key().decode("ascii")

    blob = encrypt("secret", rogue_key)
    with pytest.raises(CryptoError):
        decrypt(blob, primary, prior)


def test_round_trip_with_no_prior_keys_unchanged():
    """The default (no-prior) signature still works (regression guard)."""
    key = Fernet.generate_key().decode("ascii")
    blob = encrypt("rt", key)
    assert decrypt(blob, key) == "rt"


def test_multifernet_chain_supports_multiple_priors():
    """Chain of N prior keys decrypts ciphertext written under any of them."""
    keys = [Fernet.generate_key().decode("ascii") for _ in range(4)]
    primary = keys[0]
    priors = keys[1:]

    # Each old key encrypted some ciphertext historically. After
    # rotation the primary is the freshest and the chain goes
    # newest-first.
    for old_key in priors:
        blob = encrypt(f"rt-{old_key[:6]}", old_key)
        plaintext = decrypt(blob, primary, *priors)
        assert plaintext == f"rt-{old_key[:6]}"


def test_two_argument_signature_still_works_for_callers():
    """Per the rotation contract: existing two-argument callsites must keep working.

    Specifically tests/test_gmail_tools_dispatch.py:51 calls
    encrypt(plaintext, settings.encryption_key) and
    tests/test_token_store.py:51,84 calls
    decrypt(row.encrypted_refresh_token, encryption_key). The default
    `prior=()` keeps these unchanged.
    """
    key = Fernet.generate_key().decode("ascii")
    # Two-arg encrypt (no prior)
    blob = encrypt("plain", key)
    # Two-arg decrypt (no prior)
    assert decrypt(blob, key) == "plain"
