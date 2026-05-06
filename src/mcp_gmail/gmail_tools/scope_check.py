"""Per-tool OAuth scope requirements + scope-set comparison.

Default linked-account scope (config.gmail_oauth_scopes) is narrow:
openid + email + gmail.readonly. Write tools require broader scopes
(gmail.modify, gmail.send, gmail.compose, gmail.settings.basic,
mail.google.com/).

This module: given a tool name and the granted scope string, decide
whether the operation is authorized. If not, raise ScopeInsufficient
with required/granted lists plus a list of sufficient alternatives.
The dispatcher surfaces that as an standard-shape scope_insufficient error.

Decision 3 (Option C): we do NOT widen the OAuth default scope set.
Users discover broader requirements at tool-call time and re-link
with a precise grant; read-only consenters are not prompted for
write scopes.

Scope hierarchy (scope-hierarchy refinement). SCOPE_HIERARCHY models Google's
documented per-method authorization tables (key = granted scope,
value = scopes it subsumes). Walk is single-level; the table bakes
in full transitive expansion at definition time. Filter management
is OUTSIDE the hierarchy: users.settings.filters.* accept ONLY
gmail.settings.basic, so the table does not list settings.basic as
a child of any other scope.

TRASH-semantics design: delete_email and batch_delete_emails ship as
TRASH semantics (gmail.modify, recoverable); permanent delete is
deferred.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Gmail scope URIs
# ---------------------------------------------------------------------------

SCOPE_OPENID = "openid"
SCOPE_EMAIL = "email"
SCOPE_READONLY = "https://www.googleapis.com/auth/gmail.readonly"
SCOPE_MODIFY = "https://www.googleapis.com/auth/gmail.modify"
SCOPE_SEND = "https://www.googleapis.com/auth/gmail.send"
SCOPE_COMPOSE = "https://www.googleapis.com/auth/gmail.compose"
SCOPE_SETTINGS_BASIC = "https://www.googleapis.com/auth/gmail.settings.basic"
SCOPE_FULL = "https://mail.google.com/"


# ---------------------------------------------------------------------------
# SCOPE_HIERARCHY: granted scope -> set of scopes it subsumes.
# ---------------------------------------------------------------------------
# Key = scope an operator granted; value = scopes Google's per-method
# authorization tables document the granted scope as accepting. Each
# entry bakes in the full transitive expansion (single-level walk).
# Citations per entry reference the specific Google Gmail API endpoints
# at developers.google.com/gmail/api/reference/rest. Filter management
# (users.settings.filters.*) is deliberately omitted: those endpoints
# accept ONLY gmail.settings.basic; mail.google.com/ does NOT subsume.
# ---------------------------------------------------------------------------

SCOPE_HIERARCHY: dict[str, frozenset[str]] = {
    SCOPE_FULL: frozenset(
        {
            SCOPE_READONLY,
            SCOPE_MODIFY,
            SCOPE_COMPOSE,
            SCOPE_SEND,
            # mail.google.com/ accepted everywhere readonly/modify/compose/send is per
            # users.messages.get, users.threads.list, users.labels.create, users.messages.send,
            # users.drafts.create. NOT settings.basic (filters.create/delete reject everything
            # except settings.basic; deliberate gap, see comment block above).
        }
    ),
    SCOPE_MODIFY: frozenset(
        {
            SCOPE_READONLY,
            SCOPE_COMPOSE,
            SCOPE_SEND,
            # gmail.modify accepted alongside readonly at users.messages.get etc., alongside
            # compose at users.drafts.create/update/delete, alongside send at users.messages.send
            # and users.drafts.send.
        }
    ),
    SCOPE_COMPOSE: frozenset(
        {
            SCOPE_SEND,
            # gmail.compose accepted alongside send at users.messages.send and
            # users.drafts.send. Asymmetric: send does NOT subsume compose because
            # users.drafts.create/update/delete reject send.
        }
    ),
    # SCOPE_SEND: no entry. Send is the narrowest write scope; subsumes nothing.
    # SCOPE_READONLY: no entry. Readonly subsumes nothing.
    # SCOPE_SETTINGS_BASIC: no entry. Orthogonal; users.settings.filters.create and
    # users.settings.filters.delete only accept gmail.settings.basic, NOT mail.google.com/,
    # NOT gmail.modify. Deliberate gap.
}


# TOOL_SCOPE_REQUIREMENTS: tool name -> minimum scope set required.
# Tuples; authorized when every entry passes `_satisfies` (direct
# grant or SCOPE_HIERARCHY subsumption). Filter tools stay exact-match
# (settings.basic is not a child of any other scope; do not add it
# without re-checking Google's per-method docs).

TOOL_SCOPE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    # ------------------------------------------------------------------
    # Read tools (scope = readonly)
    # ------------------------------------------------------------------
    "read_email": (SCOPE_READONLY,),
    "search_emails": (SCOPE_READONLY,),
    "download_attachment": (SCOPE_READONLY,),
    "download_email": (SCOPE_READONLY,),
    "get_thread": (SCOPE_READONLY,),
    "list_inbox_threads": (SCOPE_READONLY,),
    "get_inbox_with_threads": (SCOPE_READONLY,),
    # modify_thread mutates labels on a thread; gmail.modify required.
    # The read/write split groups it with read tools by result shape,
    # but the scope requirement reflects what Gmail's API demands.
    "modify_thread": (SCOPE_MODIFY,),
    "list_email_labels": (SCOPE_READONLY,),
    "list_filters": (SCOPE_READONLY,),
    "get_filter": (SCOPE_READONLY,),
    # fanout convenience tools. Read-side; gmail.readonly suffices.
    "multi_search_emails": (SCOPE_READONLY,),
    "batch_read_emails": (SCOPE_READONLY,),
    # ------------------------------------------------------------------
    # Write tools.
    # ------------------------------------------------------------------
    # Sending and drafting
    "send_email": (SCOPE_SEND,),
    "create_draft": (SCOPE_COMPOSE,),
    "update_draft": (SCOPE_COMPOSE,),
    "list_drafts": (SCOPE_COMPOSE,),
    "send_draft": (SCOPE_SEND,),
    "delete_draft": (SCOPE_COMPOSE,),
    # Label management
    "create_label": (SCOPE_MODIFY,),
    "update_label": (SCOPE_MODIFY,),
    "delete_label": (SCOPE_MODIFY,),
    "modify_email_labels": (SCOPE_MODIFY,),
    # Filter management
    "create_filter": (SCOPE_SETTINGS_BASIC,),
    "delete_filter": (SCOPE_SETTINGS_BASIC,),
    # Delete tools. Both ship as TRASH semantics (recoverable),
    # implemented via users.messages.trash and users.messages.batchModify
    # respectively. Both require gmail.modify.
    "delete_email": (SCOPE_MODIFY,),
    "batch_delete_emails": (SCOPE_MODIFY,),
    # ------------------------------------------------------------------
    # Cleanup tools.
    # ------------------------------------------------------------------
    # reply_all: needs gmail.send (sends reply) AND gmail.readonly
    # (reads original headers). check_scopes ANDs the tuple.
    "reply_all": (SCOPE_SEND, SCOPE_READONLY),
    # batch_modify_emails: bulk add/remove labels; gmail.modify.
    "batch_modify_emails": (SCOPE_MODIFY,),
    # get_or_create_label: list+create; fail fast at scope check rather
    # than half-execute on the create branch.
    "get_or_create_label": (SCOPE_MODIFY,),
    # create_filter_from_template: filter creation; gmail.settings.basic.
    "create_filter_from_template": (SCOPE_SETTINGS_BASIC,),
    # ------------------------------------------------------------------
    # Bootstrap tool.
    # ------------------------------------------------------------------
    # connect_gmail_account: bootstrap handshake; dispatcher short-circuits
    # before check_scopes runs (see bootstrap.is_bootstrap_tool and
    # dispatch.dispatch_tool_call). Empty tuple is a presence marker for
    # test_table_has_exactly_30_tools, NOT "any scope is sufficient".
    "connect_gmail_account": (),
}


# Total tool count: 32 (11 read + 14 write + 4 cleanup + 1 bootstrap + 2 fanout).
# Single source of truth for the canonical-count assertion in __init__.py;
# tests reference this so drift in the manifest, dispatch table, or count
# assertion fails fast.
EXPECTED_TOOL_COUNT = 32


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ScopeInsufficient(Exception):
    """Raised when the granted OAuth scope cannot satisfy a tool's requirements.

    Carries the lists the dispatcher needs to build an standard-shape
    scope_insufficient response: the required scopes (per the
    TOOL_SCOPE_REQUIREMENTS table), the actual granted scope string
    on the token row, and an optional list of sufficient alternatives
    (scopes that, if granted alone, would satisfy the missing
    requirement; useful so the operator UI can suggest "or grant
    mail.google.com/ instead" without re-running the matcher).
    """

    def __init__(
        self,
        *,
        required_scopes: list[str],
        granted_scope: str,
        sufficient_alternatives: list[str] | None = None,
    ):
        super().__init__(f"insufficient scope: required={required_scopes}")
        self.required_scopes = required_scopes
        self.granted_scope = granted_scope
        self.sufficient_alternatives = sufficient_alternatives


class UnknownTool(Exception):
    """Raised when a tool name is not in TOOL_SCOPE_REQUIREMENTS."""


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def _granted_set(granted_scope: str) -> set[str]:
    """Tokenize the granted_scope string into a set of scopes.

    Gmail returns scope as whitespace-separated. Empty / None safe.
    """
    if not granted_scope:
        return set()
    return {s for s in granted_scope.split() if s}


def _satisfies(required: str, granted: set[str]) -> bool:
    """Single-level walk: required is satisfied if directly granted,
    or if any granted scope subsumes it per SCOPE_HIERARCHY.
    """
    if required in granted:
        return True
    for g in granted:
        if required in SCOPE_HIERARCHY.get(g, frozenset()):
            return True
    return False


def granted_scope_satisfies(*, required: str, granted_scope: str) -> bool:
    """Public version of `_satisfies` over a raw granted-scope string.

    send_draft uses this to decide whether the caller's granted
    scope covers the gmail.modify requirement of the optional post-
    send actions, before the send is dispatched. Returns True when
    the required scope is directly granted or subsumed via
    SCOPE_HIERARCHY.
    """
    return _satisfies(required, _granted_set(granted_scope))


def _sufficient_alternatives(required: str) -> list[str]:
    """Sorted list of scopes that, if granted alone, would satisfy `required`.

    Returns the required scope itself plus every scope that subsumes it
    per SCOPE_HIERARCHY. The dispatcher surfaces this list to the
    operator so the re-link UI can offer broader alternatives (e.g.
    "grant mail.google.com/ to satisfy multiple read tools at once").
    """
    out = [required]
    for parent, children in SCOPE_HIERARCHY.items():
        if required in children:
            out.append(parent)
    return sorted(out)


def check_scopes(*, tool_name: str, granted_scope: str) -> None:
    """Verify that `granted_scope` covers every scope required by `tool_name`.

    Raises ScopeInsufficient if any required scope is missing, with
    the FIRST missing scope's sufficient alternatives attached.
    Raises UnknownTool if the tool name is not registered.

    Satisfaction follows Google's documented per-method authorization
    tables via SCOPE_HIERARCHY: a required scope is satisfied if it is
    directly granted OR if any granted scope subsumes it. A token
    granted gmail.modify therefore satisfies tools that require
    gmail.readonly (users.messages.get accepts either). This aligns
    the matcher with what Google enforces at the HTTP layer.

    Filter tools (create_filter, delete_filter, create_filter_from_template)
    correctly remain exact-match: SCOPE_HIERARCHY does not list
    gmail.settings.basic as a child of any other scope, so granting
    mail.google.com/ alone still fails for those tools.

    No HTTP call. No DB call. Pure function over two strings.
    """
    required = TOOL_SCOPE_REQUIREMENTS.get(tool_name)
    if required is None:
        raise UnknownTool(tool_name)
    granted = _granted_set(granted_scope)
    missing = [s for s in required if not _satisfies(s, granted)]
    if missing:
        raise ScopeInsufficient(
            required_scopes=list(required),
            granted_scope=granted_scope,
            sufficient_alternatives=_sufficient_alternatives(missing[0]),
        )
