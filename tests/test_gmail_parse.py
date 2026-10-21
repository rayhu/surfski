import base64
import email
from email import policy

import pytest

from surfski import gmail as g

from .fakes import StrictGmail


def b64(s: str, enc="utf-8") -> str:
    return base64.urlsafe_b64encode(s.encode(enc)).decode().rstrip("=")


def hdrs(**kw):
    return [{"name": k.replace("_", "-"), "value": v} for k, v in kw.items()]


def test_multipart_prefers_plain():
    payload = {
        "mimeType": "multipart/mixed",
        "headers": hdrs(Subject="Hi", From="Bob <bob@x.com>", To="me@x.com", Date="Mon"),
        "parts": [
            {
                "mimeType": "multipart/alternative",
                "parts": [
                    {"mimeType": "text/plain", "body": {"data": b64("plain body")}},
                    {"mimeType": "text/html", "body": {"data": b64("<p>html body</p>")}},
                ],
            },
            {"mimeType": "application/pdf", "filename": "a.pdf", "body": {"size": 1234, "attachmentId": "x"}},
        ],
    }
    m = g.parse_message({"id": "m1", "threadId": "t1", "payload": payload}, 8000)
    assert m["body"] == "plain body"
    assert m["subject"] == "Hi" and m["from"] == "Bob <bob@x.com>"
    assert m["attachments"] == [{"filename": "a.pdf", "mime_type": "application/pdf", "size": 1234,
                                 "part_id": None, "attachment_id": "x"}]


def test_html_only():
    html = "<html><head><style>p{}</style></head><body><p>Hello&nbsp;<b>there</b></p><p>Line 2<br>Line 3</p><script>x()</script></body></html>"
    payload = {"mimeType": "text/html", "body": {"data": b64(html)}}
    body = g.extract_body(payload)
    assert "Hello" in body and "there" in body and "Line 3" in body
    assert "x()" not in body and "p{}" not in body and "<" not in body


def test_non_utf8_charset():
    payload = {
        "mimeType": "text/plain",
        "headers": [{"name": "Content-Type", "value": 'text/plain; charset="gb2312"'}],
        "body": {"data": b64("你好，世界", "gb2312")},
    }
    assert g.extract_body(payload) == "你好，世界"


def test_truncation():
    payload = {"mimeType": "text/plain", "body": {"data": b64("a" * 100)}}
    m = g.parse_message({"payload": payload}, 10)
    assert m["body_truncated"] and m["body"].startswith("a" * 10)


def test_chinese_subject_and_body_mime_roundtrip():
    m = g.build_mime(
        from_addr="alice@x.com", to="张三 <zhang@x.com>, li@x.com",
        subject="关于合同的问题", body="您好，\n请查收附件。",
    )
    raw = base64.urlsafe_b64decode(g.encode_raw(m))
    assert "关于合同的问题".encode() not in raw.split(b"\n\n", 1)[0]  # header is RFC2047-encoded
    parsed = email.message_from_bytes(raw, policy=policy.default)
    assert parsed["Subject"] == "关于合同的问题"
    assert parsed.get_content().strip() == "您好，\n请查收附件。"
    assert "zhang@x.com" in parsed["To"] and "li@x.com" in parsed["To"]


def test_reply_subject_no_double_re():
    assert g.reply_subject("Hello") == "Re: Hello"
    assert g.reply_subject("Re: Hello") == "Re: Hello"
    assert g.reply_subject("RE:Hello") == "RE:Hello"
    assert g.reply_subject("回复：你好") == "回复：你好"
    assert g.reply_subject("") == "Re:"


def test_reply_headers():
    orig = {
        "threadId": "t9",
        "payload": {"headers": hdrs(Subject="Plans", Message_ID="<b@x>", References="<a@x>")},
    }
    rh = g.reply_headers(orig)
    assert rh == {"thread_id": "t9", "in_reply_to": "<b@x>", "references": "<a@x> <b@x>", "subject": "Re: Plans"}


def test_create_draft_reply_uses_thread():
    captured = {}
    svc = StrictGmail({
        "users.messages.get": lambda **kw: {
            "threadId": "t1", "payload": {"headers": hdrs(Subject="Re: 报价", Message_ID="<m@x>", To="me@x.com")}},
        "users.drafts.create": lambda **kw: captured.update(kw["body"]) or {"id": "d1"},
    })
    seen = {}

    def choose(recipients):
        seen["recipients"] = recipients
        return {"address": "me@x.com", "display_name": ""}, "account"

    r = g.op_create_draft(svc, choose_from=choose, to="a@x.com", subject="", body="好的",
                          cc=None, bcc=None, reply_to_message_id="m1")
    assert r == {"draft_id": "d1", "thread_id": "t1", "from": "me@x.com", "from_source": "account"}
    assert seen["recipients"] == ["me@x.com"]
    assert svc.calls_to("users.messages.get")[0]["metadataHeaders"][-3:] == ["To", "Cc", "Delivered-To"]
    msg = captured["message"]
    assert msg["threadId"] == "t1"
    parsed = email.message_from_bytes(base64.urlsafe_b64decode(msg["raw"]), policy=policy.default)
    assert parsed["Subject"] == "Re: 报价"
    assert parsed["In-Reply-To"] == "<m@x>" and parsed["References"] == "<m@x>"
    assert parsed["From"] == "me@x.com"


def test_summarize_thread():
    t = {"id": "t1", "messages": [
        {"labelIds": ["INBOX"], "snippet": "first", "payload": {"headers": hdrs(Subject="S", From="a@x", Date="D1")}},
        {"labelIds": ["UNREAD", "INBOX"], "snippet": "last", "payload": {"headers": hdrs(Date="D2")}},
    ]}
    s = g.summarize_thread(t)
    assert s == {"id": "t1", "subject": "S", "from": "a@x", "date": "D2", "snippet": "last",
                 "label_ids": ["INBOX", "UNREAD"], "message_count": 2}


def test_invalid_grant_mapping():
    from google.auth.exceptions import RefreshError
    e = g.map_google_error(RefreshError("invalid_grant: Token has been expired or revoked."), "work")
    assert "relink_account('work')" in str(e)


def test_drafts_url():
    assert g.gmail_drafts_url("me@x.com") == "https://mail.google.com/mail/u/me@x.com/#drafts"


def test_snippet_html_unescaped():
    t = {"id": "t", "messages": [{"snippet": "doesn&#39;t &amp; won&#39;t &lt;b&gt;", "payload": {"headers": []}}]}
    assert g.summarize_thread(t)["snippet"] == "doesn't & won't <b>"


def test_inline_parts_count_as_attachments():
    payload = {
        "mimeType": "multipart/related",
        "parts": [
            {"mimeType": "text/plain", "body": {"data": b64("body"), "attachmentId": "big"}},
            {"mimeType": "image/png", "headers": hdrs(Content_ID="<i1>"), "body": {"size": 5}},
            {"mimeType": "image/gif", "body": {"size": 7, "attachmentId": "a2"}},
        ],
    }
    assert g.extract_body(payload) == "body"
    assert g.extract_attachments(payload) == [
        {"filename": "", "mime_type": "image/png", "size": 5, "part_id": None, "attachment_id": None},
        {"filename": "", "mime_type": "image/gif", "size": 7, "part_id": None, "attachment_id": "a2"},
    ]
