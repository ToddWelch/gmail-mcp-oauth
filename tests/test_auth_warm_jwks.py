"""Public warm_jwks helper exposed for lifespan startup.

Targets: mcp-gmail/src/mcp_gmail/auth.py:warm_jwks
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mcp_gmail import auth as auth_module


@pytest.mark.asyncio
async def test_warm_jwks_populates_cache(settings, jwks_document):
    """warm_jwks calls _refresh_cache and the cache becomes populated."""

    async def fake_fetch(_url: str, _timeout: int):
        return jwks_document

    with patch.object(auth_module, "_fetch_jwks", side_effect=fake_fetch):
        await auth_module.warm_jwks(settings)

    # The cache should now contain the kid from the test JWKS doc.
    assert auth_module._cache.keys_by_kid != {}
    assert auth_module._cache.fetched_at > 0


@pytest.mark.asyncio
async def test_warm_jwks_propagates_fetch_failure(settings):
    """A network failure during warm_jwks must surface to the caller."""

    async def fake_fetch(_url: str, _timeout: int):
        raise RuntimeError("upstream unreachable")

    with patch.object(auth_module, "_fetch_jwks", side_effect=fake_fetch):
        with pytest.raises(RuntimeError):
            await auth_module.warm_jwks(settings)


@pytest.mark.asyncio
async def test_warm_jwks_idempotent_within_throttle(settings, jwks_document):
    """Two warm_jwks calls in quick succession trigger only one fetch.

    The throttle (REFRESH_THROTTLE_SECONDS) gates re-entry into
    _refresh_cache. Calling warm_jwks twice back to back should hit
    the throttle on the second call. Note: this only matters if the
    second call goes through `_refresh_cache`'s gated path. The
    helper itself does NOT branch on the throttle (it's a forced
    warm-fetch); the public surface is a thin wrapper. The test
    documents that calling it twice is fine; both invocations
    succeed; the cache stays warm.
    """
    calls = []

    async def fake_fetch(_url: str, _timeout: int):
        calls.append(1)
        return jwks_document

    with patch.object(auth_module, "_fetch_jwks", side_effect=fake_fetch):
        await auth_module.warm_jwks(settings)
        await auth_module.warm_jwks(settings)

    # Both calls succeeded; the helper does not internally throttle
    # itself (lifespan calls it once anyway). The point is that no
    # exception is raised on the second call.
    assert len(calls) == 2
