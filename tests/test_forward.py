"""forward_message (#15) against a discovery-validated StrictGmail."""

import base64
import email
from email import policy

import pytest
from fastmcp.exceptions import ToolError

from surfski import gmail as g
from surfski.server import create_app

from .fakes import StrictGmail
from .test_send_from import IDENTITIES
from .test_server import ALICE, BOB, call, who  # noqa: F401  (fixture re-export)

PDF = b"%PDF-1.4 fake pdf bytes \x00\x01\x02"
PNG = b"\x89PNG\r\n\x1a\n fake image"


def b64(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def original(subject="Quarterly report", big=0):
    return {
        "id": "m1", "threadId": "t-orig",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "From", "value": "Carol <carol@x.com>"},
                {"name": "To", "value": "Sales Team <sales@work.org>"},
                {"name": "Cc", "value": "dave@x.com"},
                {"name": "Date", "value": "Tue, 3 Feb 2026 09:00:00 +0000"},
                {"name": "Subject", "value": subject},
                {"name": "Message-ID", "value": "<orig@x.com>"},
            ],
            "parts": [
                {"mimeType": "multipart/related", "parts": [
                    {"mimeType": "multipart/alternative", "parts": [
                        {"mimeType": "text/plain", "body": {"data": b64("Numbers attached.\r\nCarol")}},
                        {"mimeType": "text/html", "body": {"data": b64("<p>Numbers attached.</p>")}},
                    ]},
                    {"mimeType": "image/png", "filename": "",
                     "headers": [{"name": "Content-ID", "value": "<logo>"}],
                     "body": {"size": len(PNG), "data": b64(PNG)}},
                ]},
                {"mimeType": "application/pdf", "filename": "Q1 报告.pdf",
                 "body": {"size": big or len(PDF), "attachmentId": "att-pdf"}},
            ],
        },
    }


class Mailbox:
    def __init__(self, address):
        self.address = address
        self.message = original()
        self.created: list[dict] = []

    def create(self, **kw):
        if "media_body" in kw:
            media = kw["media_body"]
            assert media.mimetype() == "message/rfc822"
            raw = media.getbytes(0, media.size())
            self.created.append({"media": True, "raw": raw, "body": kw["body"]})
        else:
            raw = base64.urlsafe_b64decode(kw["body"]["message"]["raw"])
            self.created.append({"media": False, "raw": raw, "body": kw["body"]})
        return {"id": "fwd1"}

    def attachment(self, **kw):
        assert kw["messageId"] == "m1" and kw["id"] == "att-pdf"
        return {"size": len(PDF), "data": b64(PDF)}

    def service(self):
        return StrictGmail({
            "users.settings.sendAs.list": lambda **kw: {"sendAs": IDENTITIES[self.address]},
            "users.messages.get": lambda **kw: self.message,
            "users.messages.attachments.get": self.attachment,
            "users.drafts.create": self.create,
        })


@pytest.fixture
def boxes():
    return {}


@pytest.fixture
def services():
    return []


@pytest.fixture
def app(config, storage, boxes, services):
    storage.upsert_account(ALICE, "work", "alice@work.com", "rt", "s")
    storage.upsert_account(BOB, "secret", "bob@work.com", "rt", "s")
    for a in ("alice@work.com", "bob@work.com"):
        boxes[a] = Mailbox(a)

    def factory(owner, alias):
        svc = boxes[storage.get_account(owner, alias).email].service()
        services.append(svc)
        return svc

    return create_app(config, storage=storage, with_auth=False, service_factory=factory)


def parsed(box, i=-1):
    return email.message_from_bytes(box.created[i]["raw"], policy=policy.default)


@pytest.mark.parametrize("subject,expected", [
    ("Quarterly report", "Fwd: Quarterly report"),
    ("Fwd: Quarterly report", "Fwd: Quarterly report"),
    ("FW: report", "FW: report"),
    ("fwd：报价", "fwd：报价"),
    ("转发：报价单", "转发：报价单"),
    ("转发: 报价单", "转发: 报价单"),
    ("Re: 报价单", "Fwd: Re: 报价单"),
    ("Forward planning", "Fwd: Forward planning"),
    ("", "Fwd:"),
])
def test_forward_subject(subject, expected):
    assert g.forward_subject(subject) == expected


async def test_forward_body_attachments_and_from(app, who, boxes, services, storage):
    r = await call(app, "forward_message", alias="work", message_id="m1", to="erin@x.com",
                   note="FYI, see below.", bcc="boss@x.com")
    assert r == {
        "draft_id": "fwd1", "gmail_url": "https://mail.google.com/mail/u/alice@work.com/#drafts",
        "from": "sales@work.org", "from_source": "reply",  # original was sent to the sales alias
        "attachments": ["inline-1.png", "Q1 报告.pdf"], "attachment_bytes": len(PNG) + len(PDF),
    }
    box = boxes["alice@work.com"]
    created = box.created[-1]
    assert created["media"] is False
    assert created["body"]["message"].keys() == {"raw"}  # new thread: no threadId
    m = parsed(box)
    assert m["Subject"] == "Fwd: Quarterly report"
    assert m["From"].addresses[0].display_name == "张三"
    assert m["To"] == "erin@x.com" and m["Bcc"] == "boss@x.com"
    assert m["In-Reply-To"] is None and m["References"] is None
    text = m.get_body(preferencelist=("plain",)).get_content()
    assert text.replace("\r\n", "\n").rstrip() == (
        "FYI, see below.\n\n"
        "---------- Forwarded message ---------\n"
        "From: Carol <carol@x.com>\n"
        "Date: Tue, 3 Feb 2026 09:00:00 +0000\n"
        "Subject: Quarterly report\n"
        "To: Sales Team <sales@work.org>\n"
        "Cc: dave@x.com\n\n"
        "Numbers attached.\nCarol"
    )
    atts = {a.get_filename(): a for a in m.iter_attachments()}
    assert atts["Q1 报告.pdf"].get_content_type() == "application/pdf"
    assert atts["Q1 报告.pdf"].get_content() == PDF
    assert atts["inline-1.png"].get_content_type() == "image/png"
    assert atts["inline-1.png"].get_content() == PNG
    svc = services[-1]
    assert svc.calls_to("users.messages.get") == [{"userId": "me", "id": "m1", "format": "full"}]
    assert svc.calls_to("users.messages.attachments.get") == [
        {"userId": "me", "messageId": "m1", "id": "att-pdf"}]
    row = storage.audit_rows(ALICE)[-1]
    assert row["tool"] == "forward_message" and row["ok"] == 1
    assert "erin" not in row["detail"] and "FYI" not in row["detail"]


async def test_forward_explicit_from_and_signature(app, who, boxes):
    r = await call(app, "forward_message", alias="work", message_id="m1", to="erin@x.com",
                   from_address="alice@work.com", include_signature=True)
    assert r["from"] == "alice@work.com" and r["from_source"] == "explicit"
    text = parsed(boxes["alice@work.com"]).get_body(preferencelist=("plain",)).get_content()
    assert text.startswith("-- \nAlice Wong\n\n---------- Forwarded message ---------")
    with pytest.raises(ToolError, match="not verified for sending"):
        await call(app, "forward_message", alias="work", message_id="m1", to="e@x.com",
                   from_address="pending@work.org")


async def test_forward_html_only_original(app, who, boxes):
    box = boxes["alice@work.com"]
    box.message = {"id": "m1", "payload": {
        "mimeType": "text/html",
        "headers": [{"name": "From", "value": "c@x.com"}, {"name": "Subject", "value": "转发：价格"},
                    {"name": "To", "value": "alice@work.com"}],
        "body": {"data": b64("<p>Hello <b>there</b></p>")},
    }}
    r = await call(app, "forward_message", alias="work", message_id="m1", to="e@x.com")
    assert r["attachments"] == [] and r["from_source"] == "reply"
    m = parsed(box)
    assert m["Subject"] == "转发：价格"
    text = m.get_content()
    assert text.startswith("---------- Forwarded message ---------\nFrom: c@x.com\nDate: \n")
    assert "Cc:" not in text and "Hello there" in text and "<b>" not in text


async def test_forward_size_limit(app, who, boxes, services):
    boxes["alice@work.com"].message = original(big=21 * 1024 * 1024)
    with pytest.raises(ToolError, match=r"attachments total 21\.0 MB, over the 20\.0 MB forward limit: "
                                        r"inline-1\.png \(0\.0 MB\), Q1 报告\.pdf \(21\.0 MB\)"):
        await call(app, "forward_message", alias="work", message_id="m1", to="e@x.com")
    assert boxes["alice@work.com"].created == []
    assert not services[-1].calls_to("users.messages.attachments.get")


async def test_forward_large_message_uses_media_upload(app, who, boxes, monkeypatch):
    monkeypatch.setattr(g, "RAW_JSON_LIMIT", 10)
    await call(app, "forward_message", alias="work", message_id="m1", to="e@x.com")
    created = boxes["alice@work.com"].created[-1]
    assert created["media"] is True and created["body"] == {"message": {}}
    assert parsed(boxes["alice@work.com"])["Subject"] == "Fwd: Quarterly report"


async def test_forward_skips_unavailable_attachment(app, who, boxes):
    msg = original()
    msg["payload"]["parts"][1]["body"] = {"size": 5}  # neither data nor attachmentId
    boxes["alice@work.com"].message = msg
    r = await call(app, "forward_message", alias="work", message_id="m1", to="e@x.com")
    assert r["attachments"] == ["inline-1.png"]
    assert r["skipped"] == [{"filename": "Q1 报告.pdf", "reason": "no content available"}]


async def test_forward_owner_isolation(app, who, boxes):
    with pytest.raises(ToolError, match="no linked account 'secret'"):
        await call(app, "forward_message", alias="secret", message_id="m1", to="e@x.com")
    assert boxes["bob@work.com"].created == []


async def test_forward_rejects_header_injection(app, who, boxes):
    with pytest.raises(ToolError, match="'to' must not contain line breaks"):
        await call(app, "forward_message", alias="work", message_id="m1", to="e@x.com\r\nBcc: x@y.z")


def test_strict_fake_validates_attachments_get():
    svc = StrictGmail({"users.messages.attachments.get": lambda **kw: {}})
    svc.users().messages().attachments().get(userId="me", messageId="m1", id="a1").execute()
    with pytest.raises(TypeError, match='Missing required parameter "messageId"'):
        svc.users().messages().attachments().get(userId="me", id="a1")
    with pytest.raises(TypeError, match="unexpected keyword argument format"):
        svc.users().messages().attachments().get(userId="me", messageId="m1", id="a1", format="full")
    with pytest.raises(TypeError, match="unexpected keyword argument media_body"):
        svc.users().drafts().get(userId="me", id="d", media_body=None)


async def test_forward_attached_email_and_filename_crlf(app, who, boxes):
    msg = original()
    msg["payload"]["parts"].append({
        "mimeType": "message/rfc822", "filename": "",
        "body": {"size": 40, "data": b64("Subject: inner\r\n\r\ninner body")},
        "parts": [{"mimeType": "text/plain", "body": {"data": b64("inner body")}},
                  {"mimeType": "image/gif", "filename": "inner.gif", "body": {"size": 3, "data": b64("GIF")}}],
    })
    msg["payload"]["parts"][1]["filename"] = "Q1\r\nBcc: x@y.z.pdf"
    boxes["alice@work.com"].message = msg
    r = await call(app, "forward_message", alias="work", message_id="m1", to="e@x.com")
    # The attached email is one attachment; its inner parts are not walked.
    assert r["attachments"] == ["inline-1.png", "Q1 Bcc: x@y.z.pdf", "attached-message-3.eml"]
    m = parsed(boxes["alice@work.com"])
    assert m["Bcc"] is None
    atts = {a.get_filename(): a for a in m.iter_attachments()}
    assert atts["attached-message-3.eml"].get_content_type() == "application/octet-stream"
    assert atts["attached-message-3.eml"].get_content() == b"Subject: inner\r\n\r\ninner body"
    text = m.get_body(preferencelist=("plain",)).get_content()
    assert "inner body" not in text
