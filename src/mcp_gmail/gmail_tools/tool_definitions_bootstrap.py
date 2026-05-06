"""TOOL_DEFINITIONS_BOOTSTRAP: 1 tool, the connect_gmail_account
bootstrap tool.

Split from tool_definitions.py / tool_definitions_write.py because
the bootstrap tool is structurally different: it does NOT operate on
an already-linked Gmail account. It MINTS the link. Wiring its
manifest entry in either of the existing manifest files would invite
a future maintainer to drop it into the wrong scope_check tier.

Tool name MUST match `bootstrap._BOOTSTRAP_TOOL_NAMES` AND
`scope_check.TOOL_SCOPE_REQUIREMENTS["connect_gmail_account"]` AND
the bootstrap branch in `dispatch.py`.
"""

from __future__ import annotations

from typing import Any


# Email property is duplicated rather than imported from
# tool_definitions.py because the bootstrap tool is the only one that
# the user calls BEFORE a Gmail account is linked. tool_definitions.py
# bills the property as "the linked Gmail account to act against",
# which is misleading here. Inlining the property keeps the bootstrap
# manifest self-describing.
_BOOTSTRAP_ACCOUNT_EMAIL_PROP: dict[str, Any] = {
    "type": "string",
    "description": (
        "Lowercased email address of the Gmail mailbox the user wants "
        "to link. Required. The OAuth handshake will pre-fill Google's "
        "account selector with this hint via Google's `login_hint` "
        "parameter."
    ),
    "format": "email",
    "minLength": 3,
    "maxLength": 320,
}


TOOL_DEFINITIONS_BOOTSTRAP: list[dict[str, Any]] = [
    {
        "name": "connect_gmail_account",
        "description": (
            "Begin a Google OAuth handshake to link a Gmail mailbox to "
            "this MCP connector. Returns an authorization_url that the "
            "user must open in a browser to grant consent. After Google "
            "redirects them back, the linked account is available to "
            "every other Gmail tool. Use this BEFORE calling any other "
            "Gmail tool when no account has been linked yet."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_email": _BOOTSTRAP_ACCOUNT_EMAIL_PROP,
            },
            "required": ["account_email"],
            "additionalProperties": False,
        },
    },
]


# Sanity check at the bootstrap-side level: 1 entry. The composite
# 30 assertion lives in __init__.py.
assert len(TOOL_DEFINITIONS_BOOTSTRAP) == 1, (
    f"tool_definitions_bootstrap.py must have 1 entry, got {len(TOOL_DEFINITIONS_BOOTSTRAP)}"
)
