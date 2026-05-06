"""Write-side Gmail API methods for GmailClient (split into per-section mixins).

This package replaces the former single-file `gmail_client_write.py`.
The motivation is the project's 300-LOC-per-file rule plus the
public-extraction prep that wants each module to read as a single
responsibility on its own. The previous file had grown to ~310 LOC with
five distinct responsibility seams (messages, threads, labels, filters,
drafts) marked by section-header comments; each seam now has its own
module.

Why a mixin layered as one composite + four sections
----------------------------------------------------
GmailClient is the public surface. Splitting write methods into a
sibling class would force callers to construct two objects and reason
about which is which. The composite mixin `_GmailWriteMixin` keeps a
single client surface from the caller's perspective while honoring the
size rule. Each per-section mixin is a narrow class containing the
methods that share a Gmail API resource path (messages, threads,
labels+filters, drafts); the composite inherits all four.

The mixin contract: each per-section mixin expects the host class to
provide `_get`, `_post`, `_put`, `_delete` async helpers. Static type
checkers will not like that contract since the mixins have no `_post`
attribute of their own; we accept the mypy noise rather than introduce
a Protocol that adds no runtime value.

TRASH-vs-permanent reminder
---------------------------
`delete_message` calls users.messages.delete (PERMANENT delete, requires
mail.google.com/ scope). `trash_message` calls users.messages.trash
(recoverable, requires gmail.modify). the tool layer decides which
of these the user-facing `delete_email` tool maps to. the read-side
TOOL_SCOPE_REQUIREMENTS provisionally maps `delete_email` to
gmail.modify (i.e. trash semantics). If this code switches to permanent
delete, both the scope_check table and the tool docstrings change in
the write side.

Backward compatibility
----------------------
The composite mixin is re-exported here so the existing import path
(`from mcp_gmail.gmail_tools.gmail_client_write import _GmailWriteMixin`,
used by `gmail_client.py:56`) continues to resolve byte-for-byte.
"""

from __future__ import annotations

from ._drafts import _DraftsWriteMixin
from ._labels_filters import _LabelsFiltersWriteMixin
from ._messages import _MessagesWriteMixin
from ._threads import _ThreadsWriteMixin


class _GmailWriteMixin(
    _MessagesWriteMixin,
    _ThreadsWriteMixin,
    _LabelsFiltersWriteMixin,
    _DraftsWriteMixin,
):
    """Composite write-side mixin. See package docstring for layering."""

    pass
