"""Gmail MCP tools package.

The combined manifests export 32 tools, grouped for users as:
  - 13 read tools (read, search, multi_search, batch_read,
    download, get_thread, list_inbox_threads, get_inbox_with_threads,
    modify_thread, list_email_labels, list_filters, get_filter)
  - 14 write tools (send_email, drafts, label CRUD,
    modify_email_labels, filter CRUD, delete_email, batch_delete_emails)
  -  4 cleanup tools (reply_all, batch_modify_emails,
     get_or_create_label, create_filter_from_template)
  -  1 bootstrap tool (connect_gmail_account)

The same 32 entries are split across four manifest files for
file-size discipline:
  - `tool_definitions.py` hosts 11 single-shot read tools.
  - `tool_definitions_extras.py` hosts the 2 fanout read tools
    (`multi_search_emails`, `batch_read_emails`).
  - `tool_definitions_write.py` hosts 18 entries (the 14 write tools
    plus 4 cleanup tools), splicing in `tool_definitions_admin.py`
    and `tool_definitions_admin_cleanup.py`.
  - `tool_definitions_bootstrap.py` hosts the 1 bootstrap tool.

This module concatenates them into the public TOOL_DEFINITIONS list
and asserts the expected total.

The TOOL_DEFINITIONS list follows the standard MCP JSON Schema shape:
each tool entry has `name`, `description`, and `inputSchema`.
mcp_protocol.py imports this list verbatim so the JSON-RPC tools/list
response is built from one source.
"""

from __future__ import annotations

from .dispatch import dispatch_tool_call
from .scope_check import EXPECTED_TOOL_COUNT
from .tool_definitions import TOOL_DEFINITIONS as _READ_DEFS
from .tool_definitions_bootstrap import TOOL_DEFINITIONS_BOOTSTRAP as _BOOTSTRAP_DEFS
from .tool_definitions_extras import TOOL_DEFINITIONS_EXTRAS as _EXTRAS_DEFS
from .tool_definitions_write import TOOL_DEFINITIONS_WRITE as _WRITE_DEFS


# Concatenate read + write + bootstrap + extras manifests into the
# single public list. Order: 11 read, 18 write, 1 bootstrap, 2 fanout
# extras. The combined list is the source of truth for tools/list and
# tools/call validation in mcp_protocol.py.
TOOL_DEFINITIONS: list = (
    list(_READ_DEFS) + list(_WRITE_DEFS) + list(_BOOTSTRAP_DEFS) + list(_EXTRAS_DEFS)
)


# Tool-count assertion. EXPECTED_TOOL_COUNT lives in scope_check.py
# (= 32). Drift in any of the four manifests or the count constant
# fails fast at import time.
assert len(TOOL_DEFINITIONS) == EXPECTED_TOOL_COUNT, (
    f"TOOL_DEFINITIONS must be {EXPECTED_TOOL_COUNT} entries, got {len(TOOL_DEFINITIONS)}"
)


__all__ = ["TOOL_DEFINITIONS", "dispatch_tool_call"]
