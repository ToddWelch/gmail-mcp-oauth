"""download_attachment implementation: selector resolution + enrichment.

Extracted from messages.py under the 300-LOC / distinct-responsibility
hard rule. The other read tools (read_email, search_emails,
download_email) are thin pass-through wrappers around a single
GmailClient call; download_attachment is materially different: it
resolves one of three selection modes (attachment_id | filename |
part_index), walks the message payload to enumerate selectable
attachment parts, fetches the bytes, and returns an enriched object.
That selector-resolution + parts-walking + enrichment logic is a
separate responsibility and lives here.

messages.py re-exports `download_attachment` so the router's
`messages.download_attachment` reference and existing test imports keep
working unchanged; this split is pure code organization with no
behavior change.

Output contract and selection-mode / failure semantics are documented
on `download_attachment` itself.
"""

from __future__ import annotations

from typing import Any

from .errors import bad_request_error, not_found_error
from .gmail_client import GmailApiError, GmailClient
from .gmail_id import _ATTACHMENT_VALIDATION_PATTERN


# Maximum MIME nesting depth the walker will descend before bailing out.
# The payload tree is sender-influenced, so an unbounded recursive walk
# over a pathologically deep message could raise RecursionError. 100 is
# far above any real Gmail message (a handful of multipart levels) yet
# far below Python's default ~1000 recursion limit, so the walker stops
# with a typed signal long before the interpreter's own limit.
_MAX_MIME_DEPTH = 100


class _MimeTooDeepError(Exception):
    """Payload MIME nesting exceeded `_MAX_MIME_DEPTH`.

    A module-local sentinel (not a caller-facing error shape). The
    load-bearing filename/part_index path translates it into a typed
    bad_request_error; the id-path enrichment swallows it via its broad
    best-effort except (bytes still ship).
    """


def _enumerate_attachment_parts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Walk a Gmail `payload` tree and list its downloadable attachment parts.

    Depth-first PREORDER over `payload` then each nested `parts` entry,
    so the returned list is in message document order. A part counts as
    downloadable when it has a `body.attachmentId` (a server-side
    attachment reference), REGARDLESS of whether it has a filename:
    inline/related parts (e.g. embedded images) often carry an
    attachmentId with no filename and are legitimately downloadable, so
    they must remain reachable by part_index (and by their raw
    attachment_id). Their `filename` is stored as None. Parts with NO
    attachmentId (small inline `body.data`) are excluded: they are not
    server-side downloadable.

    Returns a list of `{attachment_id, filename, mime_type}` dicts
    (filename may be None). This is the single source of truth backing
    both the part_index lookup and the ambiguous-filename candidate list;
    filename selection is an exact match over the enumerated filenames, so
    nameless parts never match a filename query.

    Raises `_MimeTooDeepError` if the payload nests deeper than
    `_MAX_MIME_DEPTH` (a bounded guard against RecursionError on a
    pathologically deep, sender-influenced MIME tree). Callers translate
    or swallow that sentinel per their contract.
    """
    out: list[dict[str, Any]] = []

    def _walk(part: dict[str, Any], depth: int) -> None:
        if depth > _MAX_MIME_DEPTH:
            raise _MimeTooDeepError(f"MIME nesting exceeded {_MAX_MIME_DEPTH} levels")
        body = part.get("body") or {}
        attachment_id = body.get("attachmentId")
        if attachment_id:
            out.append(
                {
                    "attachment_id": attachment_id,
                    "filename": part.get("filename") or None,
                    "mime_type": part.get("mimeType"),
                }
            )
        for child in part.get("parts") or []:
            if isinstance(child, dict):
                _walk(child, depth + 1)

    if isinstance(payload, dict):
        _walk(payload, 0)
    return out


def _attachment_result(
    *,
    filename: str | None,
    mime_type: str | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the enriched download_attachment output object.

    `size` and `data` come from Gmail's raw attachment response; `data`
    stays base64url (unchanged encoding).
    """
    return {
        "filename": filename,
        "mime_type": mime_type,
        "size": payload.get("size"),
        "data": payload.get("data"),
    }


async def download_attachment(
    *,
    client: GmailClient,
    message_id: str,
    attachment_id: str | None = None,
    filename: str | None = None,
    part_index: int | None = None,
) -> dict[str, Any]:
    """Return one attachment, enriched, selected by one of three modes.

    Output contract (success):
        {
            "filename": str | None,   # from the matched message part
            "mime_type": str | None,  # from the matched message part
            "size": int,              # attachment byte size (Gmail)
            "data": str,              # base64url-encoded bytes (Gmail)
        }

    Selection modes: supply EXACTLY ONE of
      - `attachment_id`: Gmail's opaque attachment reference (from
        read_email's payload.parts[*].body.attachmentId). The bytes are
        fetched directly; metadata is best-effort enrichment.
      - `filename`: exact, case-sensitive match against the message's
        attachment filenames. Ambiguous (multiple parts share the name)
        -> bad_request listing the candidate part_index values. Nameless
        inline parts have no filename and are not reachable this way.
      - `part_index`: 0-based index into the ordered list of downloadable
        parts (document order over every part that has a server-side
        attachmentId; a part's filename may be absent for inline
        attachments, in which case the enriched `filename` is null).
    Parts with no attachmentId (small inline body.data) are not
    downloadable and are never enumerated. Zero or more-than-one
    selector -> bad_request.

    Fetch order and failure semantics:
      - attachment_id mode: after the malformed-id early reject,
        get_attachment (the return-critical bytes) is called FIRST, then
        get_message(format="full") is best-effort enrichment. If that
        enrichment call errors OR no enumerated part matches the id, the
        bytes are still returned with filename/mime_type = null.
      - filename / part_index mode: get_message(format="full") is
        load-bearing (it resolves the attachmentId) and is called first;
        its GmailApiError surfaces as the mapped typed error.
    """
    selectors = [attachment_id is not None, filename is not None, part_index is not None]
    supplied = sum(1 for s in selectors if s)
    if supplied == 0:
        return bad_request_error(
            "exactly one of attachment_id, filename, part_index is required; got none"
        )
    if supplied > 1:
        names = [n for n, s in zip(("attachment_id", "filename", "part_index"), selectors) if s]
        return bad_request_error(
            f"exactly one of attachment_id, filename, part_index is allowed; got {names}"
        )

    try:
        if attachment_id is not None:
            # Early reject a malformed id against the canonical attachment
            # pattern (defined once in gmail_id) so a bad id surfaces as
            # bad_request with NO upstream round trip. fullmatch (not
            # match) for consistency with validate_attachment_id: match's
            # `$` accepts a trailing newline, which the fullmatch gates
            # downstream reject, so rejecting it here keeps the handler's
            # clean bad_request_error the single source of the verdict.
            if not _ATTACHMENT_VALIDATION_PATTERN.fullmatch(attachment_id):
                return bad_request_error(
                    f"attachment_id does not match Gmail attachment ID pattern: {attachment_id!r}"
                )
            # Bytes are return-critical: fetch them first.
            att = await client.get_attachment(message_id=message_id, attachment_id=attachment_id)
            # Enrichment is best-effort and MUST NOT drop the bytes. Once
            # get_attachment has returned, the id-path contract is "bytes
            # always win": ANY enrichment failure (a GmailApiError on the
            # extra get_message, OR a non-HTTP error such as the walker
            # tripping on a malformed/deeply-nested payload, OR simply no
            # matching part) degrades to null metadata while the bytes
            # still ship. We catch broad `Exception` deliberately here:
            # it excludes BaseException (asyncio.CancelledError,
            # KeyboardInterrupt), so cancellation still propagates. This
            # is not a stray bare-except; the wide scope is the contract.
            match_filename: str | None = None
            match_mime: str | None = None
            try:
                full = await client.get_message(message_id=message_id, format="full")
                parts = _enumerate_attachment_parts(full.get("payload") or {})
                match = next((p for p in parts if p["attachment_id"] == attachment_id), None)
                if match is not None:
                    match_filename = match["filename"]
                    match_mime = match["mime_type"]
            except Exception:  # broad by contract (see note above); excludes BaseException
                pass
            return _attachment_result(filename=match_filename, mime_type=match_mime, payload=att)

        # filename / part_index: the message fetch is load-bearing.
        full = await client.get_message(message_id=message_id, format="full")
        try:
            parts = _enumerate_attachment_parts(full.get("payload") or {})
        except _MimeTooDeepError:
            # On the load-bearing path the walker result is required to
            # resolve the selector; surface a typed, actionable error
            # rather than letting a RecursionError-class failure escape
            # route_tool as an untyped internal error.
            return bad_request_error(
                "message MIME structure is too deeply nested to resolve the "
                "filename/part_index selector; download by attachment_id instead"
            )

        if filename is not None:
            candidates = [i for i, p in enumerate(parts) if p["filename"] == filename]
            if not candidates:
                available = [p["filename"] for p in parts]
                return bad_request_error(
                    f"no attachment named {filename!r}; available filenames: {available}"
                )
            if len(candidates) > 1:
                return bad_request_error(
                    f"filename {filename!r} matches multiple attachment parts at "
                    f"part_index {candidates}; disambiguate with part_index"
                )
            match = parts[candidates[0]]
        else:
            # part_index: explicit bounds check. Do NOT rely on Python
            # negative indexing (part_index=-1 must NOT return the last
            # attachment).
            assert part_index is not None  # narrowed by the selector count
            if not (0 <= part_index < len(parts)):
                return bad_request_error(
                    f"part_index {part_index} out of range; message has "
                    f"{len(parts)} attachment part(s)"
                )
            match = parts[part_index]

        att = await client.get_attachment(
            message_id=message_id, attachment_id=match["attachment_id"]
        )
        return _attachment_result(
            filename=match["filename"], mime_type=match["mime_type"], payload=att
        )
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"attachment or message not found: message={message_id}")
        raise
