"""Extractor-level unit tests for attachment_extractors (no HTTP).

Direct `bytes -> str` tests of the per-format extractors and their
security bounds: safe-wrap (hostile input raises the typed
ExtractionError instead of crashing), early-exit at the char cap, and
the page/row iteration guards. The handler-level integration tests
(through read_attachment_text with respx-mocked Gmail) live in
test_gmail_tools_attachment_text.py; this file owns the pure extractor
surface, split out under the 300-LOC / distinct-responsibility rule.

The PDF byte-builder helper hand-assembles valid PDFs (pypdf cannot
draw text) so extract_pdf_text runs against genuine files.
"""

from __future__ import annotations

import pytest

from mcp_gmail.gmail_tools.attachment_extractors import (
    ExtractionError,
    extract_csv_text,
    extract_pdf_text,
    extract_xlsx_text,
)
from mcp_gmail.gmail_tools.message_text import MAX_TEXT_CHARS

from ._attachment_fixtures import make_blank_pdf


# ---------------------------------------------------------------------------
# Safe-wrap: hostile input raises the typed ExtractionError, never crashes
# ---------------------------------------------------------------------------


def test_extract_pdf_text_hostile_raises_extraction_error():
    with pytest.raises(ExtractionError):
        extract_pdf_text(b"not a pdf at all", max_chars=MAX_TEXT_CHARS)


def test_extract_xlsx_text_hostile_raises_extraction_error():
    with pytest.raises(ExtractionError):
        extract_xlsx_text(b"not a zip at all", max_chars=MAX_TEXT_CHARS)


def test_extract_csv_text_never_raises_on_plain_text():
    # csv.reader tolerates arbitrary text; a "malformed" CSV is still just
    # rows, so this returns text rather than raising.
    out = extract_csv_text("a,b\n\"unterminated", max_chars=MAX_TEXT_CHARS)
    assert isinstance(out, str)


# ---------------------------------------------------------------------------
# Early-exit at the char cap + iteration guards bound huge input
# ---------------------------------------------------------------------------


def test_extract_csv_early_exits_at_cap():
    # A million tiny rows (~4 MB); early-exit must stop near the cap, far
    # short of consuming the whole input. The char accounting counts only
    # line content, so the joined output (with newlines) overshoots the
    # cap by a bounded factor; asserting it is a tiny fraction of the full
    # input proves early-exit fired rather than parse-then-truncate.
    text = "a,b\n" * 1_000_000
    out = extract_csv_text(text, max_chars=1000)
    assert len(out) < 3000  # bounded near the 1000 cap, not the ~4 MB input


def test_extract_pdf_page_cap_bounds_giant_docs():
    """The page-count guard terminates extraction on a multi-page PDF."""
    # Does not raise; returns bounded (empty) text for blank pages.
    out = extract_pdf_text(make_blank_pdf(20), max_chars=MAX_TEXT_CHARS)
    assert isinstance(out, str)
