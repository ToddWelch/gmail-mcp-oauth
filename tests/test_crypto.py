"""Fernet encrypt/decrypt wrapper.

Targets: mcp-gmail/src/mcp_gmail/crypto.py:encrypt
Targets: mcp-gmail/src/mcp_gmail/crypto.py:decrypt
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from mcp_gmail.crypto import CryptoError, decrypt, encrypt


def test_round_trip():
    key = Fernet.generate_key().decode("ascii")
    plaintext = "1//refresh-token-secret"
    blob = encrypt(plaintext, key)
    assert isinstance(blob, bytes)
    assert plaintext.encode() not in blob  # never store cleartext
    assert decrypt(blob, key) == plaintext


def test_round_trip_unicode():
    """Refresh tokens are ASCII but the contract should not rely on it.

    A future caller might encrypt notes / metadata; failing on
    non-ASCII would be a foot-gun.
    """
    key = Fernet.generate_key().decode("ascii")
    plaintext = "héllo 世界"
    blob = encrypt(plaintext, key)
    assert decrypt(blob, key) == plaintext


def test_decrypt_wrong_key_raises():
    key1 = Fernet.generate_key().decode("ascii")
    key2 = Fernet.generate_key().decode("ascii")
    blob = encrypt("secret", key1)
    with pytest.raises(CryptoError):
        decrypt(blob, key2)


def test_decrypt_tampered_raises():
    key = Fernet.generate_key().decode("ascii")
    blob = bytearray(encrypt("secret", key))
    # Flip a byte deep inside the ciphertext segment, where Fernet's
    # HMAC will catch it without our test landing on the version byte.
    blob[20] ^= 0x01
    with pytest.raises(CryptoError):
        decrypt(bytes(blob), key)


def test_invalid_key_raises():
    with pytest.raises(CryptoError):
        encrypt("secret", "not-a-valid-fernet-key")
