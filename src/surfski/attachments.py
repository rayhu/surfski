"""Attachment text extraction with hard limits (#9).

Supported: text-like types (text/*, JSON, XML, CSV, HTML), PDF (pypdf), and the
Office Open XML formats DOCX / XLSX / PPTX, parsed directly from the zip with
defusedxml (no DTDs, no entities). Everything else returns metadata only.

All extractors are bounded: zip entry count, declared and actual uncompressed
bytes, compression ratio, PDF page count and a wall-clock budget, plus an early
stop once enough text has been collected."""

from __future__ import annotations

import io
import time
import zipfile
from dataclasses import dataclass

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from .gmail import html_to_text

# Zip (DOCX/XLSX/PPTX) limits.
ZIP_MAX_ENTRIES = 2000
ZIP_MAX_MEMBER_BYTES = 8 * 1024 * 1024  # per XML part, decompressed
ZIP_MAX_TOTAL_BYTES = 60 * 1024 * 1024
ZIP_MAX_RATIO = 150  # uncompressed / compressed, for members over 1 MB
# XML parts are stream-parsed; this caps elements seen per document.
XML_MAX_ELEMENTS = 500_000
# PDF limits.
PDF_MAX_PAGES = 200
PDF_MAX_STREAM_BYTES = 20 * 1024 * 1024  # pypdf decompression limits (default 75 MB)
TIME_BUDGET_SECONDS = 15.0

TEXT_MIME = {"application/json", "application/xml", "application/csv", "application/x-yaml",
             "application/yaml", "application/javascript", "application/x-sh", "application/sql"}
TEXT_EXT = {".txt", ".md", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".log", ".ini",
            ".cfg", ".toml", ".py", ".js", ".ts", ".sql", ".sh", ".ics", ".vcf", ".eml"}
HTML_EXT = {".html", ".htm"}
OOXML = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
}

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"


class ExtractError(Exception):
    """User-facing extraction failure (safe to display)."""


@dataclass
class Extracted:
    text: str | None
    method: str
    note: str | None = None


def _ext(filename: str) -> str:
    name = (filename or "").lower()
    return name[name.rfind("."):] if "." in name else ""


def detect_method(mime_type: str, filename: str) -> str:
    mime = (mime_type or "").lower().split(";")[0].strip()
    ext = _ext(filename)
    if mime == "text/html" or ext in HTML_EXT:
        return "html"
    if mime in OOXML:
        return OOXML[mime]
    if ext in (".docx", ".xlsx", ".pptx"):
        return ext[1:]
    if mime == "application/pdf" or ext == ".pdf":
        return "pdf"
    if mime.startswith("text/") or mime in TEXT_MIME or mime.endswith(("+json", "+xml")) or ext in TEXT_EXT:
        return "text"
    return "none"


def _decode(data: bytes, charset: str | None) -> str:
    for enc in (charset, "utf-8"):
        if not enc:
            continue
        try:
            return data.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


class _Budget:
    def __init__(self, seconds: float):
        self.deadline = time.monotonic() + seconds

    def check(self, what: str) -> None:
        if time.monotonic() > self.deadline:
            raise ExtractError(f"extraction took too long ({what}); open the file in Gmail instead")


# ---------------------------------------------------------------- OOXML (zip)


class _SafeZip:
    def __init__(self, data: bytes):
        try:
            self.zf = zipfile.ZipFile(io.BytesIO(data))
            infos = self.zf.infolist()
        except (zipfile.BadZipFile, ValueError, OSError) as e:
            raise ExtractError("this file is damaged or not a valid Office document") from e
        if len(infos) > ZIP_MAX_ENTRIES:
            raise ExtractError(f"the document has too many parts ({len(infos)}); refusing to open it")
        declared = sum(i.file_size for i in infos)
        if declared > ZIP_MAX_TOTAL_BYTES:
            raise ExtractError("the document expands to too much data; refusing to open it (zip bomb guard)")
        self.names = {i.filename: i for i in infos}
        self.read_total = 0

    def read(self, name: str) -> bytes | None:
        info = self.names.get(name)
        if info is None:
            return None
        if info.file_size > ZIP_MAX_MEMBER_BYTES or (
            info.file_size > 1024 * 1024 and info.file_size > ZIP_MAX_RATIO * max(info.compress_size, 1)
        ):
            raise ExtractError("the document expands to too much data; refusing to open it (zip bomb guard)")
        try:
            with self.zf.open(info) as f:
                # Don't trust the declared size: stop reading past the limit.
                data = f.read(ZIP_MAX_MEMBER_BYTES + 1)
        except (zipfile.BadZipFile, OSError, EOFError, RuntimeError, NotImplementedError) as e:
            raise ExtractError("this file is damaged or not a valid Office document") from e
        self.read_total += len(data)
        if len(data) > ZIP_MAX_MEMBER_BYTES or self.read_total > ZIP_MAX_TOTAL_BYTES:
            raise ExtractError("the document expands to too much data; refusing to open it (zip bomb guard)")
        return data


def _part_number(name: str) -> int:
    digits = "".join(ch for ch in name if ch.isdigit())[:9]  # avoid int() digit-limit errors
    return int(digits or 0)


class _Collector:
    """Accumulates extracted text, stopping at max_chars."""

    def __init__(self, max_chars: int):
        self.max_chars = max_chars
        self.lines: list[str] = []
        self.buf: list[str] = []
        self.size = 0
        self.full = False

    def add(self, text: str) -> None:
        if text and not self.full:
            self.buf.append(text)
            self.size += len(text)
            self.full = self.size > self.max_chars

    def line(self, text: str | None = None) -> None:
        if text is not None:
            self.add(text)
        if not self.buf:
            return  # empty paragraphs/rows add nothing (and can't be used to pad)
        self.lines.append("".join(self.buf))
        self.buf = []
        self.size += 1
        self.full = self.full or self.size > self.max_chars

    def text(self) -> str:
        if self.buf:
            self.lines.append("".join(self.buf))
            self.buf = []
        return "\n".join(self.lines).strip()


class _XmlStream:
    """Streaming, entity-free XML parse that drops every element once it has ended,
    so memory stays flat no matter how many elements a part has."""

    def __init__(self, budget: _Budget):
        self.budget = budget
        self.elements = 0
        self.capped = False

    def ends(self, data: bytes):
        stack = []
        try:
            for event, el in SafeET.iterparse(io.BytesIO(data), events=("start", "end"),
                                              forbid_dtd=True, forbid_entities=True, forbid_external=True):
                if event == "start":
                    self.elements += 1
                    if self.elements > XML_MAX_ELEMENTS:
                        self.capped = True
                        return
                    if self.elements % 20_000 == 0:
                        self.budget.check("xml")
                    stack.append(el)
                    continue
                stack.pop()
                yield el
                el.clear()
                if stack:
                    try:
                        stack[-1].remove(el)
                    except ValueError:
                        pass
        except (DefusedXmlException, SafeET.ParseError) as e:
            raise ExtractError("the document contains invalid or unsafe XML") from e


def _cap_note(xs: _XmlStream) -> str | None:
    return (f"stopped after {XML_MAX_ELEMENTS:,} XML elements; the rest of the document was not read"
            if xs.capped else None)


def _docx(z: _SafeZip, budget: _Budget, max_chars: int) -> tuple[str, str | None]:
    data = z.read("word/document.xml")
    if data is None:
        raise ExtractError("this doesn't look like a Word document (no word/document.xml)")
    xs, out = _XmlStream(budget), _Collector(max_chars)
    for el in xs.ends(data):
        tag = el.tag
        if tag == f"{W}t":
            out.add(el.text or "")
        elif tag == f"{W}tab":
            out.add("\t")
        elif tag in (f"{W}br", f"{W}cr"):
            out.add("\n")
        elif tag == f"{W}p":
            out.line()
        if out.full:
            break
    return out.text(), _cap_note(xs)


def _xlsx(z: _SafeZip, budget: _Budget, max_chars: int) -> tuple[str, str | None]:
    xs = _XmlStream(budget)
    shared: list[str] = []
    shared_size = 0
    sst = z.read("xl/sharedStrings.xml")
    if sst is not None:
        parts: list[str] = []
        for el in xs.ends(sst):
            if el.tag == f"{S}t":
                parts.append(el.text or "")
            elif el.tag == f"{S}si":
                shared.append("".join(parts))
                shared_size += len(shared[-1])
                parts = []
                if shared_size > ZIP_MAX_MEMBER_BYTES:
                    raise ExtractError("the workbook's shared strings are too large")
    sheets = sorted((n for n in z.names if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")),
                    key=_part_number)
    if not sheets:
        raise ExtractError("this doesn't look like an Excel workbook (no worksheets)")
    out = _Collector(max_chars)
    for idx, name in enumerate(sheets, 1):
        out.line(f"# Sheet {idx}")
        cells: list[str] = []
        value, inline = "", []
        for el in xs.ends(z.read(name) or b"<x/>"):
            tag = el.tag
            if tag == f"{S}v":
                value = el.text or ""
            elif tag == f"{S}t":
                inline.append(el.text or "")
            elif tag == f"{S}c":
                t = el.get("t")
                if t == "inlineStr":
                    val = "".join(inline)
                elif t == "s" and value.isdigit() and len(value) < 10 and int(value) < len(shared):
                    val = shared[int(value)]
                else:
                    val = value
                cells.append(val)
                value, inline = "", []
            elif tag == f"{S}row":
                out.line("\t".join(cells).rstrip("\t"))
                cells = []
            if out.full:
                return out.text(), _cap_note(xs)
        if xs.capped:
            break
    return out.text(), _cap_note(xs)


def _pptx(z: _SafeZip, budget: _Budget, max_chars: int) -> tuple[str, str | None]:
    slides = sorted((n for n in z.names if n.startswith("ppt/slides/slide") and n.endswith(".xml")),
                    key=_part_number)
    if not slides:
        raise ExtractError("this doesn't look like a PowerPoint deck (no slides)")
    xs, out = _XmlStream(budget), _Collector(max_chars)
    for idx, name in enumerate(slides, 1):
        out.line(f"# Slide {idx}")
        for el in xs.ends(z.read(name) or b"<x/>"):
            if el.tag == f"{A}t":
                out.add(el.text or "")
            elif el.tag == f"{A}p":
                if out.buf:
                    out.line()
            if out.full:
                return out.text(), _cap_note(xs)
        if xs.capped:
            break
    return out.text(), _cap_note(xs)


# ---------------------------------------------------------------- PDF


def _pdf(data: bytes, budget: _Budget, max_chars: int) -> tuple[str, str | None]:
    import pypdf

    limit = PDF_MAX_STREAM_BYTES
    # Lower pypdf's decompression limits for this extraction only (context-local).
    with pypdf.apply_configuration(
        maximum_declared_stream_length=limit,
        array_based_stream_maximum_output_length=limit,
        jbig2_maximum_output_length=limit,
        lzw_maximum_output_length=limit,
        run_length_maximum_output_length=limit,
        zlib_maximum_output_length=limit,
        image_maximum_buffer_size=limit,
    ):
        return _pdf_inner(data, budget, max_chars)


def _pdf_inner(data: bytes, budget: _Budget, max_chars: int) -> tuple[str, str | None]:
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted and not reader.decrypt(""):
            raise ExtractError("this PDF is password-protected")
        pages = reader.pages
        n = len(pages)
    except ExtractError:
        raise
    except (PdfReadError, ValueError, KeyError, TypeError, OSError, RecursionError) as e:
        raise ExtractError("this PDF is damaged or can't be read") from e
    except Exception as e:  # noqa: BLE001  pypdf raises many types on hostile input
        raise ExtractError("this PDF is damaged or can't be read") from e
    out, size, note = [], 0, None
    for i in range(min(n, PDF_MAX_PAGES)):
        budget.check(f"pdf page {i + 1}")
        try:
            text = pages[i].extract_text() or ""
        except Exception:  # noqa: BLE001
            text = "[page could not be read]"
        out.append(text.strip())
        size += len(text)
        if size > max_chars:
            break
    if n > PDF_MAX_PAGES:
        note = f"only the first {PDF_MAX_PAGES} of {n} pages were read"
    text = "\n\n".join(t for t in out if t)
    if not text:
        note = (note + "; " if note else "") + "no text layer found (scanned PDF?)"
    return text, note


# ---------------------------------------------------------------- entry point


def extract_text(data: bytes, mime_type: str, filename: str, *, charset: str | None, max_chars: int,
                 time_budget: float = TIME_BUDGET_SECONDS) -> Extracted:
    method = detect_method(mime_type, filename)
    budget = _Budget(time_budget)
    if method == "text":
        return Extracted(_decode(data, charset), method)
    if method == "html":
        return Extracted(html_to_text(_decode(data, charset)), method)
    if method == "pdf":
        text, note = _pdf(data, budget, max_chars)
        return Extracted(text, method, note)
    if method in ("docx", "xlsx", "pptx"):
        z = _SafeZip(data)
        fn = {"docx": _docx, "xlsx": _xlsx, "pptx": _pptx}[method]
        text, note = fn(z, budget, max_chars)
        if not text and note:
            raise ExtractError("the document is too complex to read (" + note + ")")
        return Extracted(text, method, note)
    return Extracted(None, "none", f"no text extraction for {mime_type or 'this type'}; open it in Gmail")
