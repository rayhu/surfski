"""get_attachment (#9): resolution, size limit before download, extraction per type,
and the safety limits. Fixtures are generated in-test."""

import base64
import io
import zipfile

import pytest
from fastmcp.exceptions import ToolError

from surfski import attachments as att
from surfski.server import create_app

from .fakes import StrictGmail
from .test_server import ALICE, BOB, call, who  # noqa: F401  (fixture re-export)

DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
S_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_pdf(pages: list[str]) -> bytes:
    n = len(pages)
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            f"<< /Type /Pages /Kids [{' '.join(f'{4 + 2 * i} 0 R' for i in range(n))}] /Count {n} >>".encode(),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    for i, text in enumerate(pages):
        content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> "
                    f"/Contents {5 + 2 * i} 0 R >>".encode())
        objs.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
    out, offsets = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{off:010d} 00000 n \n".encode() for off in offsets)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return out


def make_zip(files: dict[str, bytes | str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def make_docx(paragraphs: list[str]) -> bytes:
    body = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    return make_zip({"[Content_Types].xml": "<Types/>",
                     "word/document.xml": f'<w:document xmlns:w="{W_NS}"><w:body>{body}</w:body></w:document>'})


def make_xlsx() -> bytes:
    return make_zip({
        "xl/sharedStrings.xml": f'<sst xmlns="{S_NS}"><si><t>Name</t></si><si><t>Total</t></si>'
                                f'<si><t>华东</t></si></sst>',
        "xl/worksheets/sheet1.xml": f'<worksheet xmlns="{S_NS}"><sheetData>'
                                    '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>'
                                    '<row r="2"><c r="A2" t="s"><v>2</v></c><c r="B2"><v>42.5</v></c></row>'
                                    '</sheetData></worksheet>',
        "xl/worksheets/sheet2.xml": f'<worksheet xmlns="{S_NS}"><sheetData><row r="1">'
                                    '<c r="A1" t="inlineStr"><is><t>inline</t></is></c></row></sheetData></worksheet>',
    })


def make_pptx() -> bytes:
    def slide(text):
        return f'<p:sld xmlns:p="x" xmlns:a="{A_NS}"><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:sld>'
    return make_zip({"ppt/slides/slide1.xml": slide("Roadmap Q3"), "ppt/slides/slide2.xml": slide("Thanks")})


FILES = {
    "notes.txt": ("text/plain", "plain 文本".encode("gb2312"), [{"name": "Content-Type", "value": 'text/plain; charset="gb2312"'}]),
    "data.csv": ("text/csv", b"a,b\n1,2\n", None),
    "cfg.json": ("application/json", b'{"k": "v"}', None),
    "page.html": ("text/html", b"<p>Hello <b>html</b></p><script>x()</script>", None),
    "report.pdf": ("application/pdf", make_pdf(["Hello PDF page one", "Second page"]), None),
    "memo.docx": (DOCX, make_docx(["First paragraph", "第二段"]), None),
    "sheet.xlsx": (XLSX, make_xlsx(), None),
    "deck.pptx": (PPTX, make_pptx(), None),
    "photo.png": ("image/png", b"\x89PNG\r\n\x1a\nxx", None),
}


def message(files: dict) -> dict:
    parts = [{"partId": "0", "mimeType": "text/plain", "body": {"data": b64(b"see attached")}}]
    for i, (name, (mime, data, headers)) in enumerate(files.items(), 1):
        part = {"partId": str(i), "mimeType": mime, "filename": name,
                "body": {"size": len(data), "attachmentId": f"att-{i}"}}
        if headers:
            part["headers"] = headers
        parts.append(part)
    return {"id": "m1", "threadId": "t1", "payload": {"mimeType": "multipart/mixed", "headers": [], "parts": parts}}


class Mailbox:
    def __init__(self, files):
        self.files = dict(files)
        self.msg = message(self.files)

    def set_files(self, files):
        self.files = dict(files)
        self.msg = message(self.files)

    def attachment(self, **kw):
        idx = int(kw["id"].split("-")[1])
        data = list(self.files.values())[idx - 1][1]
        return {"size": len(data), "data": b64(data)}

    def service(self):
        return StrictGmail({
            "users.messages.get": lambda **kw: self.msg,
            "users.messages.attachments.get": self.attachment,
        })


@pytest.fixture
def box():
    return Mailbox(FILES)


@pytest.fixture
def services():
    return []


@pytest.fixture
def app(config, storage, box, services):
    storage.upsert_account(ALICE, "work", "alice@work.com", "rt", "s")
    storage.upsert_account(BOB, "secret", "bob@work.com", "rt", "s")

    def factory(owner, alias):
        svc = box.service()
        services.append(svc)
        return svc

    return create_app(config, storage=storage, with_auth=False, service_factory=factory)


async def get(app, ref, **kw):
    return await call(app, "get_attachment", alias="work", message_id="m1", attachment=ref, **kw)


@pytest.mark.parametrize("name,method,expected", [
    ("notes.txt", "text", "plain 文本"),
    ("data.csv", "text", "a,b\n1,2"),
    ("cfg.json", "text", '{"k": "v"}'),
    ("page.html", "html", "Hello html"),
    ("report.pdf", "pdf", "Hello PDF page one"),
    ("memo.docx", "docx", "First paragraph\n第二段"),
    ("sheet.xlsx", "xlsx", "# Sheet 1\nName\tTotal\n华东\t42.5\n# Sheet 2\ninline"),
    ("deck.pptx", "pptx", "# Slide 1\nRoadmap Q3\n# Slide 2\nThanks"),
])
async def test_extracts_each_type(app, who, name, method, expected):
    r = await get(app, name)
    assert r["method"] == method and r["filename"] == name and r["truncated"] is False
    assert expected in r["text"], r["text"]
    assert r["size"] == len(FILES[name][1]) and r["mime_type"] == FILES[name][0]
    if name == "page.html":
        assert "x()" not in r["text"]
    if name == "report.pdf":
        assert "Second page" in r["text"]


async def test_binary_types_return_metadata_only(app, who):
    r = await get(app, "photo.png")
    assert r["text"] is None and r["method"] == "none" and "open it in Gmail" in r["note"]
    assert "PNG" not in str(r)


async def test_resolve_by_part_id_and_attachment_id(app, who, services):
    r = await get(app, "5")
    assert r["filename"] == "report.pdf"
    r = await get(app, "att-6")
    assert r["filename"] == "memo.docx"
    assert services[-1].calls_to("users.messages.attachments.get") == [
        {"userId": "me", "messageId": "m1", "id": "att-6"}]
    assert services[-1].calls_to("users.messages.get") == [{"userId": "me", "id": "m1", "format": "full"}]


async def test_get_message_lists_attachment_ids(config, storage, box, who):
    storage.upsert_account(ALICE, "work", "alice@work.com", "rt", "s")
    app = create_app(config, storage=storage, with_auth=False, service_factory=lambda o, a: box.service())
    r = await call(app, "get_message", alias="work", message_id="m1")
    pdf = next(a for a in r["attachments"] if a["filename"] == "report.pdf")
    assert pdf["part_id"] == "5" and pdf["attachment_id"] == "att-5"


async def test_filename_ambiguity(app, who, box):
    box.set_files({"report.pdf": FILES["report.pdf"], "b.txt": FILES["data.csv"]})
    box.msg["payload"]["parts"].append(
        {"partId": "9", "mimeType": "application/pdf", "filename": "report.pdf", "body": {"size": 3, "attachmentId": "att-1"}})
    with pytest.raises(ToolError, match=r"2 attachments are named 'report.pdf'; pass a part_id instead: .*part_id 1.*part_id 9"):
        await get(app, "report.pdf")
    with pytest.raises(ToolError, match=r"no attachment 'nope.doc' in this message. Attachments: report.pdf \[part_id 1"):
        await get(app, "nope.doc")
    assert (await get(app, "1"))["method"] == "pdf"


async def test_size_limit_before_download(app, who, box, services):
    box.msg["payload"]["parts"][5]["body"]["size"] = 16 * 1024 * 1024
    with pytest.raises(ToolError, match=r"16.0 MB, over this server's 15 MB limit"):
        await get(app, "report.pdf")
    assert services[-1].calls_to("users.messages.attachments.get") == []


async def test_truncation(app, who, box):
    box.set_files({"long.txt": ("text/plain", b"x" * 1000, None)})
    r = await get(app, "long.txt", max_chars=100)
    assert r["truncated"] is True and r["text"].startswith("x" * 100) and len(r["text"]) < 130


async def test_zip_bomb_guards(app, who, box):
    bomb = make_zip({"word/document.xml": b"<a>" + b"0" * (30 * 1024 * 1024) + b"</a>"})
    assert len(bomb) < 200_000
    box.set_files({"bomb.docx": (DOCX, bomb, None)})
    with pytest.raises(ToolError, match="zip bomb guard"):
        await get(app, "bomb.docx")
    many = make_zip({f"f{i}.xml": "x" for i in range(att.ZIP_MAX_ENTRIES + 1)})
    box.set_files({"many.docx": (DOCX, many, None)})
    with pytest.raises(ToolError, match="too many parts"):
        await get(app, "many.docx")


async def test_ratio_guard_on_lying_member(monkeypatch):
    # A member over 1 MB with an extreme compression ratio is refused even under the size cap.
    monkeypatch.setattr(att, "ZIP_MAX_MEMBER_BYTES", 50 * 1024 * 1024)
    data = make_zip({"word/document.xml": b"0" * (2 * 1024 * 1024)})
    with pytest.raises(att.ExtractError, match="zip bomb guard"):
        att.extract_text(data, DOCX, "x.docx", charset=None, max_chars=100)


@pytest.mark.parametrize("name,mime,data,msg", [
    ("bad.pdf", "application/pdf", b"%PDF-1.4 garbage \x00\x01", "damaged or can't be read"),
    ("bad.docx", DOCX, b"not a zip at all", "damaged or not a valid Office document"),
    ("nodoc.docx", DOCX, make_zip({"x.xml": "<x/>"}), "no word/document.xml"),
    ("xxe.docx", DOCX, make_zip({"word/document.xml":
        '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><d>&x;</d>'}),
     "invalid or unsafe XML"),
    ("lol.docx", DOCX, make_zip({"word/document.xml":
        '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><l>&b;</l>'}),
     "invalid or unsafe XML"),
    ("broken.xlsx", XLSX, make_zip({"xl/worksheets/sheet1.xml": "<worksheet><unclosed>"}), "invalid or unsafe XML"),
])
async def test_malformed_files_give_clear_errors(app, who, box, name, mime, data, msg):
    box.set_files({name: (mime, data, None)})
    with pytest.raises(ToolError, match=msg):
        await get(app, name)


def test_pdf_page_cap_and_time_budget(monkeypatch):
    pdf = make_pdf(["one", "two", "three"])
    monkeypatch.setattr(att, "PDF_MAX_PAGES", 2)
    ex = att.extract_text(pdf, "application/pdf", "a.pdf", charset=None, max_chars=10_000)
    assert "one" in ex.text and "two" in ex.text and "three" not in ex.text
    assert "first 2 of 3 pages" in ex.note
    with pytest.raises(att.ExtractError, match="took too long"):
        att.extract_text(pdf, "application/pdf", "a.pdf", charset=None, max_chars=10_000, time_budget=-1)


def test_detect_method_by_extension():
    assert att.detect_method("application/octet-stream", "Q3.PDF") == "pdf"
    assert att.detect_method("application/octet-stream", "notes.md") == "text"
    assert att.detect_method("application/octet-stream", "x.docx") == "docx"
    assert att.detect_method("application/zip", "x.zip") == "none"
    assert att.detect_method("application/ld+json", "x") == "text"


async def test_audit_has_no_filename(app, who, storage):
    await get(app, "memo.docx")
    row = storage.audit_rows(ALICE)[-1]
    assert row["tool"] == "get_attachment" and row["ok"] == 1
    assert row["detail"] == f"message=m1 size={len(FILES['memo.docx'][1])} method=docx"
    assert "memo" not in row["detail"]


async def test_owner_isolation(app, who):
    with pytest.raises(ToolError, match="no linked account 'secret'"):
        await call(app, "get_attachment", alias="secret", message_id="m1", attachment="1")


def test_strict_fake_attachments_get():
    svc = StrictGmail({"users.messages.attachments.get": lambda **kw: {}})
    with pytest.raises(TypeError, match="unexpected keyword argument format"):
        svc.users().messages().attachments().get(userId="me", messageId="m", id="a", format="raw")


def _docx_with_body(body: bytes) -> bytes:
    return make_zip({"word/document.xml": f'<w:document xmlns:w="{W_NS}"><w:body>'.encode()
                     + body + b"</w:body></w:document>"})


def test_element_bomb_is_bounded_in_memory():
    """The reviewer's DoS: millions of tiny elements with random padding to keep the
    compression ratio under the cap."""
    import os
    import tracemalloc
    pad = os.urandom(150_000).hex().encode()
    big = _docx_with_body(b"<w:p/>" * 3_966_000 + b"<w:p><w:r><w:t>" + pad + b"</w:t></w:r></w:p>")
    assert len(big) < 600_000
    with pytest.raises(att.ExtractError, match="zip bomb guard"):  # 23.8 MB part: over the per-part cap
        att.extract_text(big, DOCX, "x.docx", charset=None, max_chars=50_000)

    under = _docx_with_body(b"<w:p/>" * 1_300_000 + b"<w:p><w:r><w:t>" + pad + b"</w:t></w:r></w:p>")
    info = zipfile.ZipFile(io.BytesIO(under)).getinfo("word/document.xml")
    assert info.file_size < att.ZIP_MAX_MEMBER_BYTES and info.file_size / info.compress_size < att.ZIP_MAX_RATIO
    tracemalloc.start()
    try:
        with pytest.raises(att.ExtractError, match="too complex to read"):
            att.extract_text(under, DOCX, "x.docx", charset=None, max_chars=50_000)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 100 * 1024 * 1024, peak


def test_huge_paragraph_stops_at_max_chars():
    import tracemalloc
    runs = b"".join(b"<w:r><w:t>%08x</w:t></w:r>" % (i * 2654435761 % 2**32) for i in range(200_000))
    doc = _docx_with_body(b"<w:p>" + runs + b"</w:p>")
    tracemalloc.start()
    try:
        ex = att.extract_text(doc, DOCX, "x.docx", charset=None, max_chars=1000)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert 1000 < len(ex.text) < 1100 and ex.note is None, len(ex.text)
    assert peak < 30 * 1024 * 1024, peak


def test_element_cap_keeps_partial_text(monkeypatch):
    monkeypatch.setattr(att, "XML_MAX_ELEMENTS", 50)
    doc = _docx_with_body(b"".join(b"<w:p><w:r><w:t>line%d</w:t></w:r></w:p>" % i for i in range(100)))
    ex = att.extract_text(doc, DOCX, "x.docx", charset=None, max_chars=50_000)
    assert ex.text.startswith("line0\nline1") and "line99" not in ex.text
    assert "stopped after 50 XML elements" in ex.note


def test_huge_part_numbers_do_not_crash():
    slide = f'<p:sld xmlns:p="x" xmlns:a="{A_NS}"><a:p><a:r><a:t>ok</a:t></a:r></a:p></p:sld>'
    deck = make_zip({"ppt/slides/slide" + "9" * 5000 + ".xml": slide, "ppt/slides/slide1.xml": slide})
    ex = att.extract_text(deck, PPTX, "d.pptx", charset=None, max_chars=1000)
    assert ex.text.count("ok") == 2


def test_pdf_decompression_limits_applied(monkeypatch):
    import pypdf
    seen = {}
    real = pypdf.apply_configuration

    def spy(**kw):
        seen.update(kw)
        return real(**kw)
    monkeypatch.setattr(pypdf, "apply_configuration", spy)
    att.extract_text(make_pdf(["x"]), "application/pdf", "a.pdf", charset=None, max_chars=100)
    assert seen["zlib_maximum_output_length"] == 20 * 1024 * 1024
    assert seen["lzw_maximum_output_length"] == seen["maximum_declared_stream_length"] == 20 * 1024 * 1024


def test_deep_nesting_refused():
    deep = b"<w:p>" * 300 + b"<w:r><w:t>x</w:t></w:r>" + b"</w:p>" * 300
    with pytest.raises(att.ExtractError, match="nests deeper than 256 levels"):
        att.extract_text(_docx_with_body(deep), DOCX, "d.docx", charset=None, max_chars=1000)
    ok = b"<w:p>" * 200 + b"<w:r><w:t>fine</w:t></w:r>" + b"</w:p>" * 200
    assert "fine" in att.extract_text(_docx_with_body(ok), DOCX, "d.docx", charset=None, max_chars=1000).text


def test_attribute_heavy_element_refused():
    attrs = b" ".join(b'a%d="v"' % i for i in range(1001))
    doc = _docx_with_body(b"<w:p " + attrs + b"><w:r><w:t>x</w:t></w:r></w:p>")
    with pytest.raises(att.ExtractError, match="too many attributes"):
        att.extract_text(doc, DOCX, "d.docx", charset=None, max_chars=1000)
    attrs = b" ".join(b'a%d="v"' % i for i in range(1000))
    doc = _docx_with_body(b"<w:p " + attrs + b"><w:r><w:t>ok</w:t></w:r></w:p>")
    assert att.extract_text(doc, DOCX, "d.docx", charset=None, max_chars=1000).text == "ok"
