"""Cryptographic key-shape validators used by config.load().

Encapsulates the Fernet-shape validation logic for ENCRYPTION_KEY,
STATE_SIGNING_KEY, and each entry of PRIOR_ENCRYPTION_KEYS. Isolating
this in its own module lets future operators audit "what does Fernet-
shape validation actually do" in a small focused file rather than
inside the 245-LOC config.py orchestration.

Canonical home for `_validate_fernet_key`. Re-exported from
`config.py` so the existing `from mcp_gmail.config import
_validate_fernet_key` import path keeps working for test scaffolding
and DR-runbook tooling that may monkeypatch the validator.
"""

from __future__ import annotations

import base64


def _validate_fernet_key(value: str, name: str) -> None:
    """Reject keys that are not 32-byte URL-safe base64 (the Fernet shape).

    A misshapen key would surface much later: the first refresh-token
    encrypt for ENCRYPTION_KEY, or the first /oauth/start for
    STATE_SIGNING_KEY. Validating at load time means a misconfigured
    operator finds out at boot, not at the first user-facing error.

    The Fernet key spec is exactly 32 bytes after URL-safe base64
    decoding (44 ASCII chars including the trailing `=`). We accept
    both with and without padding so operators who paste the output of
    `Fernet.generate_key().decode()` directly into Railway's env editor
    don't trip on padding handling.
    """
    if not value:
        raise RuntimeError(f"{name} is empty")
    try:
        # base64.urlsafe_b64decode requires correct padding; pad to a
        # multiple of 4 if missing.
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise RuntimeError(
            f"{name} is not valid URL-safe base64: {exc}. "
            'Generate with python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        ) from exc
    if len(decoded) != 32:
        raise RuntimeError(
            f"{name} must decode to exactly 32 bytes (Fernet shape), got {len(decoded)}. "
            'Generate with python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        )
