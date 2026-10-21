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
ZIP_MAX_MEMBER_BYTES = 25 * 1024 * 1024
ZIP_MAX_TOTAL_BYTES = 60 * 1024 * 1024
ZIP_MAX_RATIO = 150  # uncompressed / compressed, for members over 1 MB
# PDF limits.
PDF_MAX_PAGES = 200
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


def _xml(data: bytes):
    try:
        return SafeET.fromstring(data, forbid_dtd=True)
    except (DefusedXmlException, SafeET.ParseError) as e:
        raise ExtractError("the document contains invalid or unsafe XML") from e


def _docx(z: _SafeZip, budget: _Budget, max_chars: int) -> str:
    data = z.read("word/document.xml")
    if data is None:
        raise ExtractError("this doesn't look like a Word document (no word/document.xml)")
    root = _xml(data)
    paras, size = [], 0
    for p in root.iter(f"{W}p"):
        parts = []
        for el in p.iter():
            if el.tag == f"{W}t" and el.text:
                parts.append(el.text)
            elif el.tag == f"{W}tab":
                parts.append("\t")
            elif el.tag in (f"{W}br", f"{W}cr"):
                parts.append("\n")
        line = "".join(parts)
        paras.append(line)
        size += len(line) + 1
        if size > max_chars:
            break
        budget.check("docx")
    return "\n".join(paras).strip()


def _xlsx(z: _SafeZip, budget: _Budget, max_chars: int) -> str:
    shared: list[str] = []
    sst = z.read("xl/sharedStrings.xml")
    if sst is not None:
        for si in _xml(sst).iter(f"{S}si"):
            shared.append("".join(t.text or "" for t in si.iter(f"{S}t")))
    sheets = sorted(
        (n for n in z.names if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")),
        key=lambda n: int("".join(ch for ch in n if ch.isdigit()) or 0),
    )
    if not sheets:
        raise ExtractError("this doesn't look like an Excel workbook (no worksheets)")
    out, size = [], 0
    for idx, name in enumerate(sheets, 1):
        out.append(f"# Sheet {idx}")
        for row in _xml(z.read(name) or b"<x/>").iter(f"{S}row"):
            cells = []
            for c in row.iter(f"{S}c"):
                t = c.get("t")
                if t == "inlineStr":
                    val = "".join(x.text or "" for x in c.iter(f"{S}t"))
                else:
                    v = c.find(f"{S}v")
                    val = v.text if v is not None and v.text else ""
                    if t == "s" and val.isdigit() and int(val) < len(shared):
                        val = shared[int(val)]
                cells.append(val)
            line = "\t".join(cells).rstrip("\t")
            out.append(line)
            size += len(line) + 1
            if size > max_chars:
                return "\n".join(out)
        budget.check("xlsx")
    return "\n".join(out).strip()


def _pptx(z: _SafeZip, budget: _Budget, max_chars: int) -> str:
    slides = sorted(
        (n for n in z.names if n.startswith("ppt/slides/slide") and n.endswith(".xml")),
        key=lambda n: int("".join(ch for ch in n if ch.isdigit()) or 0),
    )
    if not slides:
        raise ExtractError("this doesn't look like a PowerPoint deck (no slides)")
    out, size = [], 0
    for idx, name in enumerate(slides, 1):
        out.append(f"# Slide {idx}")
        for p in _xml(z.read(name) or b"<x/>").iter(f"{A}p"):
            line = "".join(t.text or "" for t in p.iter(f"{A}t"))
            if line:
                out.append(line)
                size += len(line) + 1
        if size > max_chars:
            break
        budget.check("pptx")
    return "\n".join(out).strip()


# ---------------------------------------------------------------- PDF


def _pdf(data: bytes, budget: _Budget, max_chars: int) -> tuple[str, str | None]:
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
        return Extracted(fn(z, budget, max_chars), method)
    return Extracted(None, "none", f"no text extraction for {mime_type or 'this type'}; open it in Gmail")
