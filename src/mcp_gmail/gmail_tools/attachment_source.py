"""Load + consume tagged attachment inputs for the write tools.

Every attachment-accepting write tool (send_email, create_draft,
update_draft, reply_all) accepts each attachment in exactly one of two
shapes: inline ({filename, mime_type, data_base64url}) or upload-handle
({source:"upload", upload_token, filename?, mime_type?}). The JSON
Schema `oneOf` at the dispatch boundary is the primary discriminator;
`_classify` (in attachment_input) is the backstop for callers that
bypass the schema.

Input-shape validation, inline decode, and control-char rejection live
in attachment_input.py (pure, DB-free); this module owns the DB-backed
half: loading/decrypting upload slots and consuming them. It re-exports
the input helpers so `attachment_source.is_safe_filename` /
`send._decode_attachment` and friends keep resolving.

Consume-after-build
-------------------
Slot consumption is split from loading so it runs AFTER a successful
`build_email_message`, gated on the EXACT rendered `.as_bytes()` size
rather than any size estimate. This module cannot see the
caller-controlled To/Cc/Bcc/Subject/References headers (up to ~94 KB,
schema-unbounded), so no estimate from this vantage point can be a true
upper bound on the assembled message. Instead:

  1. `load_attachments` classifies, inline-decodes, owner-scoped-loads
     and decrypts upload bytes, and returns (attachments, token_hashes).
     A cheap raw-sum memory gate runs BEFORE decrypt to bound RAM; it is
     NOT the oversize gate.
  2. The handler calls `build_email_message`, which raises
     OversizeMessage on the real rendered size. An oversize/malformed
     message is rejected here with NO slot consumed (retry-safe).
  3. On a successful build the handler calls `consume_slots` (atomic,
     all-or-nothing) BEFORE the Gmail POST, so single-use stays airtight.

send.py re-exports `_decode_attachment` for backward compatibility.
"""

from __future__ import annotations

from typing import Any

from .. import attachment_upload_store as store
from ..crypto import CryptoError, decrypt_bytes
from ..db import session_scope
from .attachment_input import (
    MAX_ATTACHMENT_COUNT,  # noqa: F401  re-exported for send.py back-compat
    _classify,
    _decode_attachment,
    _validate_attachments_pre_decode,
    is_safe_filename,
    is_safe_mime,
)
from .errors import bad_request_error
from .message_format import MAX_ENCODED_BYTES, Attachment


# ADVISORY single-attachment raw cap surfaced in the mint response's
# `max_bytes` (~18.5 MiB): base64 4/3 expansion plus RFC 2045 76-char
# line-wrapping under Gmail's 25 MiB encoded ceiling, ignoring headers.
# It is guidance only; the real gate is build_email_message's assembled
# 25 MiB cap enforced at send/draft time on the exact rendered bytes.
EFFECTIVE_MAX_ATTACHMENT_BYTES = MAX_ENCODED_BYTES * 3 // 4 * 76 // 77


class _ConsumeRace(Exception):
    """A slot was consumed concurrently; roll the consume transaction back."""


def load_attachments(
    *,
    raw: list[dict[str, Any]] | None,
    auth0_sub: str,
    account_email: str,
    encryption_key: str | None,
    prior_encryption_keys: tuple[str, ...] = (),
) -> tuple[list[Attachment], list[str]] | dict[str, Any]:
    """Decode inline + load/decrypt upload attachments WITHOUT consuming.

    Returns (attachments, token_hashes) on success or a bad_request_error
    dict on malformed / unavailable input. `token_hashes` are the owned
    upload slots to consume AFTER a successful build_email_message; nothing
    is consumed here, so a build that rejects an oversize/malformed message
    leaves every slot intact for a retry.

    A cheap raw-sum memory gate (inline decoded + stored upload sizes <=
    MAX_ENCODED_BYTES) runs BEFORE any decrypt so transient plaintext stays
    bounded. It is NOT the oversize gate; the assembled 25 MiB cap that
    build_email_message enforces on the real rendered bytes is.
    """
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return bad_request_error("attachments must be a list")
    pre_err = _validate_attachments_pre_decode(raw)
    if pre_err is not None:
        return pre_err

    kinds: list[str] = []
    for i, att in enumerate(raw):
        kind = _classify(att, index=i)
        if isinstance(kind, dict):
            return kind
        kinds.append(kind)

    # Reject the SAME upload_token referenced twice in one message BEFORE
    # any load/decrypt/consume. Otherwise both references pass load+build,
    # then consume_slots consumes that one row twice in a single txn: the
    # 2nd conditional UPDATE sees consumed_at and raises the concurrent-
    # consume error, rejecting a valid-looking request with a confusing
    # race (the txn rolls back, so the slot is not burned, but the caller
    # gets a misleading message). Each upload handle is single-use.
    seen_tokens: set[str] = set()
    for i, kind in enumerate(kinds):
        if kind != "upload":
            continue
        token = raw[i]["upload_token"]
        if token in seen_tokens:
            return bad_request_error(
                f"attachments[{i}].upload_token is referenced more than once in this "
                "message; each upload handle is single-use, so upload the file again "
                "to attach a second copy"
            )
        seen_tokens.add(token)

    # Decode inline first (no DB); collect raw sizes for the memory gate.
    out: list[Attachment | None] = [None] * len(raw)
    raw_total = 0
    for i, att in enumerate(raw):
        if kinds[i] != "inline":
            continue
        dec = _decode_attachment(att, index=i)
        if isinstance(dec, dict):
            return dec
        out[i] = dec
        raw_total += len(dec.data)

    upload_indexes = [i for i, k in enumerate(kinds) if k == "upload"]
    if not upload_indexes:
        return [a for a in out if a is not None], []

    if not encryption_key:
        return bad_request_error("server is not configured to resolve upload attachments")

    loaded: dict[int, tuple[str, bytes, str | None, str | None]] = {}
    decrypted: dict[int, bytes] = {}
    with session_scope() as session:
        for i in upload_indexes:
            override = raw[i].get("filename")
            if isinstance(override, str) and override and not is_safe_filename(override):
                return bad_request_error(f"attachments[{i}].filename contains control characters")
            mime_override = raw[i].get("mime_type")
            if isinstance(mime_override, str) and mime_override and not is_safe_mime(mime_override):
                return bad_request_error(f"attachments[{i}].mime_type contains control characters")
            token_hash = store.hash_token(raw[i]["upload_token"])
            row = store.load_for_consume(
                session,
                token_hash=token_hash,
                auth0_sub=auth0_sub,
                account_email=account_email,
            )
            if row is None:
                return bad_request_error(
                    "an upload slot referenced by this message is not "
                    "available (unknown, expired, already used, or not "
                    "owned by this account); mint a new slot with "
                    "create_attachment_upload_slot"
                )
            loaded[i] = (token_hash, row.encrypted_bytes, row.filename, row.mime_type)
            raw_total += row.size_bytes or 0
        # BLOCKER-4 memory gate: reject before decrypt so RAM stays bounded
        # (total decrypted plaintext <= MAX_ENCODED_BYTES).
        if raw_total > MAX_ENCODED_BYTES:
            return bad_request_error(f"attachments exceed the {MAX_ENCODED_BYTES}-byte message cap")
        for i, (_th, enc, _fn, _mt) in loaded.items():
            try:
                decrypted[i] = decrypt_bytes(enc, encryption_key, *prior_encryption_keys)
            except CryptoError:
                return bad_request_error(
                    "a stored attachment could not be decrypted; mint a new slot"
                )

    token_hashes: list[str] = []
    for i in upload_indexes:
        token_hash, _enc, stored_name, stored_mime = loaded[i]
        entry = raw[i]
        filename = entry.get("filename") or stored_name or "attachment"
        mime_type = entry.get("mime_type") or stored_mime or "application/octet-stream"
        out[i] = Attachment(filename=filename, mime_type=mime_type, data=decrypted[i])
        token_hashes.append(token_hash)

    return [a for a in out if a is not None], token_hashes


def consume_slots(
    *, token_hashes: list[str], auth0_sub: str, account_email: str
) -> dict[str, Any] | None:
    """Atomically consume all token_hashes (all-or-nothing). None on success.

    Called AFTER build_email_message succeeds and BEFORE the Gmail POST:
    an oversize/malformed message is rejected at build with no slot spent,
    and single-use stays airtight because the owner-scoped conditional
    consume serializes concurrent references (a losing race rolls back all
    and returns an error, so the caller does NOT POST).
    """
    if not token_hashes:
        return None
    try:
        with session_scope() as session:
            for token_hash in token_hashes:
                if not store.consume(
                    session,
                    token_hash=token_hash,
                    auth0_sub=auth0_sub,
                    account_email=account_email,
                ):
                    raise _ConsumeRace()
    except _ConsumeRace:
        return bad_request_error(
            "an upload slot was consumed concurrently; mint a new slot and retry"
        )
    return None
