"""Tests for the create_attachment_upload_slot tool via dispatch_tool_call.

Exercises scope enforcement (readonly link -> scope_insufficient;
send / compose links succeed), the returned slot descriptor, and the
per-user slot-count cap surfacing as bad_request.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from mcp_gmail import attachment_upload_store as store
from mcp_gmail import config as config_module
from mcp_gmail import db as db_module
from mcp_gmail import token_manager
from mcp_gmail.crypto import encrypt
from mcp_gmail.db import Base
from mcp_gmail.gmail_tools.attachment_source import EFFECTIVE_MAX_ATTACHMENT_BYTES
from mcp_gmail.gmail_tools.dispatch import dispatch_tool_call
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.token_store import GmailOAuthToken

SUB = "user-abc"
EMAIL = "alice@example.com"
READONLY = "https://www.googleapis.com/auth/gmail.readonly"
SEND = "https://www.googleapis.com/auth/gmail.send"
COMPOSE = "https://www.googleapis.com/auth/gmail.compose"


@pytest.fixture(autouse=True)
def _engine():
    db_module.reset_for_tests()
    token_manager.reset_cache_for_tests()
    engine = db_module.init_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield
    db_module.reset_for_tests()
    token_manager.reset_cache_for_tests()


def _seed_token(scope: str):
    settings = config_module.load()
    now = datetime.now(timezone.utc)
    with db_module.session_scope() as session:
        session.add(
            GmailOAuthToken(
                auth0_sub=SUB,
                account_email=EMAIL,
                encrypted_refresh_token=encrypt("rt", settings.encryption_key),
                scope=scope,
                created_at=now,
                updated_at=now,
            )
        )
    return settings


def _stub_access_token():
    async def fake(**_kwargs):
        return "access-token"

    from mcp_gmail.gmail_tools import dispatch as dispatch_mod

    return patch.object(dispatch_mod, "get_access_token", side_effect=fake)


async def _mint(settings):
    return await dispatch_tool_call(
        tool_name="create_attachment_upload_slot",
        arguments={"account_email": EMAIL},
        claims={"sub": SUB},
        settings=settings,
    )


@pytest.mark.asyncio
async def test_readonly_link_gets_scope_insufficient():
    settings = _seed_token(READONLY)
    result = await _mint(settings)
    assert result["code"] == ToolErrorCode.SCOPE_INSUFFICIENT


@pytest.mark.asyncio
async def test_send_link_mints_slot_descriptor():
    settings = _seed_token(SEND)
    with _stub_access_token():
        result = await _mint(settings)
    assert set(result) >= {"upload_token", "upload_url", "expires_at", "max_bytes"}
    assert result["upload_url"].endswith("/attachments/upload")
    # Advertises the EFFECTIVE send-through cap (~18.7 MiB), not the
    # 25 MiB streaming hard cap.
    assert result["max_bytes"] == EFFECTIVE_MAX_ATTACHMENT_BYTES
    assert result["max_bytes"] < store.MAX_UPLOAD_BYTES
    with db_module.session_scope() as session:
        assert store.count_active_slots(session, SUB) == 1


@pytest.mark.asyncio
async def test_compose_only_link_can_mint():
    settings = _seed_token(COMPOSE)
    with _stub_access_token():
        result = await _mint(settings)
    assert "upload_token" in result


@pytest.mark.asyncio
async def test_slot_count_cap_surfaces_bad_request():
    settings = _seed_token(SEND)
    with db_module.session_scope() as session:
        for _ in range(store.MAX_ACTIVE_SLOTS_PER_USER):
            store.create_slot(session, auth0_sub=SUB, account_email=EMAIL)
    with _stub_access_token():
        result = await _mint(settings)
    assert result["code"] == ToolErrorCode.BAD_REQUEST
