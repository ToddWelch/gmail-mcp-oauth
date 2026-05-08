"""Happy-path argument fixtures for `test_schema_validation.py`.

One representative valid `arguments` dict per tool. Drift between this
mapping and `TOOL_DEFINITIONS` is asserted by
`test_happy_fixtures_cover_every_registered_tool`: a new tool added
to the manifest without a fixture entry here breaks that test, which
is the intended drift surface.

Lives in a sibling test-data module rather than inline in
`test_schema_validation.py` because the 32 fixtures push the test
module over the 300 LOC project rule even after trimming.
"""

from __future__ import annotations

# Plausible Gmail-shaped IDs that satisfy the canonical pattern
# `^[A-Za-z0-9_\-]{1,256}$`. attachment_id needs {16,128} chars.
GMAIL_ID = "MSG_1A2B3C"
THREAD_ID = "THR_X"
LABEL_ID = "Label_42"
DRAFT_ID = "DRFT_1"
FILTER_ID = "FLT_1"
ATTACH_ID = "att_aaaaaaaaaaaaaaaaaa"  # 22 chars, satisfies {16,128}
EMAIL = "user@example.com"


HAPPY_FIXTURES: dict[str, dict] = {
    # Read tools (8 message+thread + 3 labels/filters)
    "read_email": {"account_email": EMAIL, "message_id": GMAIL_ID, "format": "full"},
    "search_emails": {"account_email": EMAIL, "q": "from:boss"},
    "download_attachment": {
        "account_email": EMAIL,
        "message_id": GMAIL_ID,
        "attachment_id": ATTACH_ID,
    },
    "download_email": {"account_email": EMAIL, "message_id": GMAIL_ID},
    "get_thread": {"account_email": EMAIL, "thread_id": THREAD_ID},
    "list_inbox_threads": {"account_email": EMAIL, "max_results": 25},
    "get_inbox_with_threads": {"account_email": EMAIL, "max_results": 25},
    "modify_thread": {
        "account_email": EMAIL,
        "thread_id": THREAD_ID,
        "add_label_ids": ["INBOX"],
        "remove_label_ids": ["UNREAD"],
    },
    "list_email_labels": {"account_email": EMAIL},
    "list_filters": {"account_email": EMAIL},
    "get_filter": {"account_email": EMAIL, "filter_id": FILTER_ID},
    # Write tools (7 send/draft + 11 admin)
    "send_email": {
        "account_email": EMAIL,
        "sender": EMAIL,
        "to": [EMAIL],
        "subject": "hi",
        "body_text": "body",
    },
    "create_draft": {
        "account_email": EMAIL,
        "sender": EMAIL,
        "to": [EMAIL],
        "subject": "hi",
        "body_text": "body",
    },
    "update_draft": {
        "account_email": EMAIL,
        "draft_id": DRAFT_ID,
        "sender": EMAIL,
        "to": [EMAIL],
        "subject": "hi",
        "body_text": "body",
    },
    "list_drafts": {"account_email": EMAIL},
    "send_draft": {"account_email": EMAIL, "draft_id": DRAFT_ID},
    "delete_draft": {"account_email": EMAIL, "draft_id": DRAFT_ID},
    "reply_all": {
        "account_email": EMAIL,
        "message_id": GMAIL_ID,
        "body_text": "body",
    },
    "create_label": {"account_email": EMAIL, "name": "Test"},
    "update_label": {"account_email": EMAIL, "label_id": LABEL_ID, "name": "Test"},
    "delete_label": {"account_email": EMAIL, "label_id": LABEL_ID},
    "modify_email_labels": {
        "account_email": EMAIL,
        "message_id": GMAIL_ID,
        "add_label_ids": ["STARRED"],
    },
    "create_filter": {
        "account_email": EMAIL,
        "criteria": {"from": "boss@example.com"},
        "action": {"addLabelIds": ["IMPORTANT"]},
    },
    "delete_filter": {"account_email": EMAIL, "filter_id": FILTER_ID},
    "delete_email": {"account_email": EMAIL, "message_id": GMAIL_ID},
    "batch_delete_emails": {
        "account_email": EMAIL,
        "message_ids": [GMAIL_ID, "MSG_2"],
    },
    "batch_modify_emails": {
        "account_email": EMAIL,
        "message_ids": [GMAIL_ID],
        "add_label_ids": ["STARRED"],
    },
    "get_or_create_label": {"account_email": EMAIL, "name": "Test"},
    "create_filter_from_template": {
        "account_email": EMAIL,
        "template": "auto_archive_sender",
        "sender_email": EMAIL,
    },
    # Bootstrap (1)
    "connect_gmail_account": {"account_email": EMAIL},
    # Fanout extras (2)
    "multi_search_emails": {
        "account_email": EMAIL,
        "queries": ["from:boss", "subject:urgent"],
        "max_results_per_query": 25,
    },
    "batch_read_emails": {
        "account_email": EMAIL,
        "message_ids": [GMAIL_ID, "MSG_2"],
        "format": "metadata",
        "metadata_headers": ["From", "Subject", "Date"],
    },
}
