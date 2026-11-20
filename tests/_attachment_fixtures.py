"""Shared byte-builders for the read_attachment_text test modules.

test_gmail_tools_attachment_text.py (handler-level, respx) and
test_attachment_extractors.py (extractor-level, direct) both need real
PDF/XLSX bytes to run the parsers against genuine files rather than
stubs. These builders live here (mirroring tests/_schema_fixtures.py)
so neither test module duplicates them and each stays under the 300-LOC
rule.

pypdf cannot draw text, so _build_pdf_with_text hand-assembles a valid
PDF (correct cross-reference offsets + trailer) with a Tj content
stream; _make_blank_pdf uses pypdf's blank-page writer for the
page-count / no-text cases.
"""

from __future__ import annotations

import base64
import io


def b64url(raw: bytes) -> str:
    """base64url WITHOUT padding, matching what Gmail returns."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_blank_pdf(pages: int = 1) -> bytes:
    """Generate a minimal PDF with `pages` blank pages (no text)."""
    from pypdf import PdfWriter

    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def build_pdf_with_text(text_run: str) -> bytes:
    """Build a byte-correct single-page PDF whose page shows `text_run`.

    pypdf cannot draw text, so we hand-assemble a valid PDF (correct
    cross-reference offsets + trailer) with a Tj content stream so
    extract_text() returns real glyphs without a rendering dependency.
    """
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    content = b"BT /F1 24 Tf 20 60 Td (" + text_run.encode("latin-1") + b") Tj ET"
    stream_obj = (
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream"
    )
    objs.append(stream_obj)

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(out.tell())
        out.write(str(i).encode() + b" 0 obj\n" + body + b"\nendobj\n")
    xref_pos = out.tell()
    n = len(objs) + 1
    out.write(b"xref\n0 " + str(n).encode() + b"\n")
    out.write(b"0000000000 65535 f \n")
    for off in offsets:
        out.write(("%010d 00000 n \n" % off).encode())
    out.write(b"trailer\n<< /Size " + str(n).encode() + b" /Root 1 0 R >>\n")
    out.write(b"startxref\n" + str(xref_pos).encode() + b"\n%%EOF")
    return out.getvalue()


def make_xlsx(rows: list[list]) -> bytes:
    """Build an XLSX workbook (single sheet) from a list of row lists."""
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "Sheet1"
    for row in rows:
        ws.append(row)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
