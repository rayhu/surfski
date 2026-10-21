"""Attachments on drafts (#16): create_draft, update_draft, send_email and forward_message
copy attachments from messages in the same mailbox. Gmail is a stateful,
discovery-validated StrictGmail that stores drafts the way Gmail returns them."""

import base64
import copy
import email
from dataclasses import replace
from email import policy

import httplib2
import pytest
from fastmcp.exceptions import ToolError
from googleapiclient.errors import HttpError

import surfski.gmail as g
from surfski.server import create_app

from .fakes import StrictGmail
from .test_elicitation import Human, call_with
from .test_send_from import IDENTITIES
from .test_server import ALICE, BOB, call, who  # noqa: F401  (fixture re-export)

PDF = b"%PDF-1.4 report bytes"
PNG = b"\x89PNG\r\n\x1a\n inline image"
CSV = b"a,b\n1,2\n"
MB = 1024 * 1024


def b64(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def hdrs(**kw):
    return [{"name": k.replace("_", "-"), "value": v} for k, v in kw.items()]


def source_messages():
    return {
        "m1": {"id": "m1", "threadId": "t1", "payload": {
            "mimeType": "multipart/mixed",
            "headers": hdrs(From="Carol <carol@x.com>", To="alice@work.com", Subject="Report",
                            Message_ID="<m1@x.com>", Date="Mon"),
            "parts": [
                {"partId": "0", "mimeType": "text/plain", "body": {"data": b64("see attached")}},
                {"partId": "1", "mimeType": "application/pdf", "filename": "报告 Q1.pdf",
                 "body": {"size": len(PDF), "attachmentId": "att-pdf"}},
                {"partId": "2", "mimeType": "image/png", "filename": "",
                 "headers": [{"name": "Content-ID", "value": "<logo>"}],
                 "body": {"size": len(PNG), "data": b64(PNG)}},
            ]}},
        "m2": {"id": "m2", "threadId": "t2", "payload": {
            "mimeType": "multipart/mixed", "headers": hdrs(From="d@x.com", To="alice@work.com", Subject="Data"),
            "parts": [
                {"partId": "0", "mimeType": "text/plain", "body": {"data": b64("data")}},
                {"partId": "1", "mimeType": "text/csv", "filename": "data.csv",
                 "body": {"size": len(CSV), "attachmentId": "att-csv"}},
            ]}},
        "big": {"id": "big", "threadId": "t3", "payload": {
            "mimeType": "multipart/mixed", "headers": hdrs(From="d@x.com", To="alice@work.com", Subject="Big"),
            "parts": [
                {"partId": "1", "mimeType": "video/mp4", "filename": "a.mp4",
                 "body": {"size": 12 * MB, "attachmentId": "att-a"}},
                {"partId": "2", "mimeType": "video/mp4", "filename": "b.mp4",
                 "body": {"size": 9 * MB, "attachmentId": "att-b"}},
            ]}},
    }


def not_found():
    return HttpError(httplib2.Response({"status": 404}), b"not found")


class Mailbox:
    """Messages, attachment bytes and drafts of one mailbox."""

    def __init__(self, address, messages=None):
        self.address = address
        self.messages = messages if messages is not None else source_messages()
        self.blobs = {("m1", "att-pdf"): PDF, ("m2", "att-csv"): CSV}
        self.drafts: dict[str, dict] = {}
        self.writes: list[tuple[str, dict]] = []
        self.sent: list[dict] = []
        self.n = 0
        self.svc = None

    # -- helpers
    def to_payload(self, raw: bytes, msg_id: str) -> dict:
        m = email.message_from_bytes(raw, policy=policy.default)
        parts = [{"partId": "0", "mimeType": "text/plain",
                  "body": {"data": b64(m.get_body(preferencelist=("plain",)).get_content())}}]
        for i, a in enumerate(m.iter_attachments(), 1):
            data = a.get_payload(decode=True)
            aid = f"{msg_id}-att{i}"
            self.blobs[(msg_id, aid)] = data
            parts.append({"partId": str(i), "mimeType": a.get_content_type(), "filename": a.get_filename() or "",
                          "body": {"size": len(data), "attachmentId": aid}})
        return {"mimeType": "multipart/mixed", "headers": [{"name": k, "value": str(v)} for k, v in m.items()],
                "parts": parts}

    def _store(self, did: str, kw: dict) -> dict:
        if "media_body" in kw:
            media = kw["media_body"]
            assert media.mimetype() == "message/rfc822"
            raw = media.getbytes(0, media.size())
            assert "raw" not in kw["body"]["message"]
        else:
            raw = base64.urlsafe_b64decode(kw["body"]["message"]["raw"])
        self.n += 1
        msg_id = f"msg-{did}-v{self.n}"  # Gmail gives an updated draft a new message id
        self.drafts[did] = {"id": did, "raw": raw, "message": {
            "id": msg_id, "threadId": kw["body"]["message"].get("threadId"), "payload": self.to_payload(raw, msg_id)}}
        return {"id": did, "message": {"id": msg_id}}

    def parsed(self, did):
        return email.message_from_bytes(self.drafts[did]["raw"], policy=policy.default)

    def attached(self, did) -> dict[str, bytes]:
        return {a.get_filename(): a.get_payload(decode=True) for a in self.parsed(did).iter_attachments()}

    def downloads(self):
        return self.svc.calls_to("users.messages.attachments.get") if self.svc else []

    # -- Gmail handlers
    def msg_get(self, **kw):
        if kw["id"] not in self.messages:
            raise not_found()
        return copy.deepcopy(self.messages[kw["id"]])

    def att_get(self, **kw):
        return {"data": b64(self.blobs[(kw["messageId"], kw["id"])])}

    def create(self, **kw):
        self.writes.append(("create", kw))
        return self._store(f"new{len(self.drafts) + 1}", kw)

    def update(self, **kw):
        self.writes.append(("update", kw))
        assert kw["body"]["id"] == kw["id"]
        return self._store(kw["id"], kw)

    def draft_get(self, **kw):
        d = self.drafts.get(kw["id"])
        if d is None:
            raise not_found()
        return {"id": d["id"], "message": copy.deepcopy(d["message"])}

    def send(self, **kw):
        self.sent.append(kw)
        return {"id": "sent-1", "threadId": "t-s"}

    def service(self):
        self.svc = StrictGmail({
            "users.messages.get": self.msg_get,
            "users.messages.attachments.get": self.att_get,
            "users.drafts.create": self.create,
            "users.drafts.update": self.update,
            "users.drafts.get": self.draft_get,
            "users.drafts.send": self.send,
            "users.settings.sendAs.list": lambda **kw: {"sendAs": copy.deepcopy(
                IDENTITIES.get(self.address, [{"sendAsEmail": self.address, "isPrimary": True}]))},
        })
        return self.svc


@pytest.fixture
def boxes():
    personal = Mailbox("alice@gmail.com", {"p1": source_messages()["m2"] | {"id": "p1"}})
    personal.blobs = {("p1", "att-csv"): CSV}
    return {
        "alice@work.com": Mailbox("alice@work.com"),
        "alice@gmail.com": personal,
        "bob@work.com": Mailbox("bob@work.com", {}),
    }


def make(config, storage, boxes, **over):
    def factory(owner, alias):
        return boxes[storage.get_account(owner, alias).email].service()

    return create_app(replace(config, **over), storage=storage, with_auth=False, service_factory=factory)


@pytest.fixture
def app(config, storage, boxes):
    storage.upsert_account(ALICE, "work", "alice@work.com", "rt", "s")
    storage.upsert_account(ALICE, "personal", "alice@gmail.com", "rt", "s")
    storage.upsert_account(BOB, "secret", "bob@work.com", "rt", "s")
    return make(config, storage, boxes, sending_enabled=True)


def audit(storage, tool, owner=ALICE):
    return [r["detail"] for r in storage.audit_rows(owner) if r["tool"] == tool]


PDF_REF = {"message_id": "m1", "part_id": "1"}
PNG_REF = {"message_id": "m1", "part_id": "2"}
CSV_REF = {"message_id": "m2", "part_id": "1"}


async def new_draft(app, attachments=(PDF_REF,), **kw):
    return await call(app, "create_draft", alias="work", to="erin@x.com", subject="Files",
                      body="Here you go.", attachments=list(attachments), **kw)


# ---------------------------------------------------------------- create


async def test_create_with_attachments_dedupes_and_audits_counts(app, who, boxes, storage):
    r = await new_draft(app, [PDF_REF, PNG_REF, PDF_REF, {"message_id": "m1", "part_id": "1"}])
    box = boxes["alice@work.com"]
    assert r["attachments"] == ["报告 Q1.pdf", "inline-2.png"]
    assert r["attachment_bytes"] == len(PDF) + len(PNG)
    assert box.attached(r["draft_id"]) == {"报告 Q1.pdf": PDF, "inline-2.png": PNG}
    raw = box.drafts[r["draft_id"]]["raw"].decode()
    assert "filename*=utf-8''" in raw  # RFC 2231 for the non-ASCII name
    assert box.parsed(r["draft_id"]).get_body(preferencelist=("plain",)).get_content().strip() == "Here you go."
    # m1 fetched once, the pdf downloaded once (the png was inline data)
    assert len(box.svc.calls_to("users.messages.get")) == 1 and len(box.downloads()) == 1
    [row] = audit(storage, "create_draft")
    assert row == f"new attachments=2 bytes={len(PDF) + len(PNG)}"


async def test_create_reply_keeps_thread_with_attachment(app, who, boxes):
    r = await new_draft(app, [CSV_REF], reply_to_message_id="m1")
    d = boxes["alice@work.com"].drafts[r["draft_id"]]
    assert d["message"]["threadId"] == "t1" and r["attachments"] == ["data.csv"]


async def test_create_without_attachments_unchanged(app, who, boxes, storage):
    r = await call(app, "create_draft", alias="work", to="erin@x.com", subject="s", body="b")
    assert "attachments" not in r and audit(storage, "create_draft") == ["new"]


async def test_size_limit_checked_before_download(app, who, boxes):
    with pytest.raises(ToolError, match=r"attachments total 21\.0 MB, over the 20\.0 MB attachment limit"):
        await new_draft(app, [{"message_id": "big", "part_id": "1"}, {"message_id": "big", "part_id": "2"}])
    box = boxes["alice@work.com"]
    assert box.downloads() == [] and box.writes == []


async def test_unknown_part_lists_attachments(app, who, boxes):
    with pytest.raises(ToolError, match="no attachment '9'.*报告 Q1.pdf"):
        await new_draft(app, [{"message_id": "m1", "part_id": "9"}])
    assert boxes["alice@work.com"].writes == []


async def test_too_many_refs_rejected(app, who, boxes):
    with pytest.raises(ToolError):
        await new_draft(app, [{"message_id": "m1", "part_id": str(i)} for i in range(21)])
    assert boxes["alice@work.com"].svc is None


# ---------------------------------------------------------------- isolation


async def test_cross_mailbox_reference_refused(app, who, boxes):
    # p1 lives in Alice's *personal* mailbox; drafting in *work* can't reach it.
    with pytest.raises(ToolError, match="'p1' isn't in this mailbox.*same mailbox"):
        await new_draft(app, [{"message_id": "p1", "part_id": "1"}])
    assert boxes["alice@gmail.com"].svc is None  # the other mailbox is never touched
    assert boxes["alice@work.com"].writes == []
    # ... while drafting in personal works.
    r = await call(app, "create_draft", alias="personal", to="erin@x.com", subject="s", body="b",
                   attachments=[{"message_id": "p1", "part_id": "1"}])
    assert r["attachments"] == ["data.csv"]


async def test_owner_isolation(app, who, boxes, storage):
    who["claims"] = {"email": BOB}
    with pytest.raises(ToolError, match="no linked account 'work'"):
        await new_draft(app)
    with pytest.raises(ToolError, match="'m1' isn't in this mailbox"):
        await call(app, "create_draft", alias="secret", to="x@y.com", subject="s", body="b",
                   attachments=[PDF_REF])
    assert boxes["alice@work.com"].svc is None and boxes["bob@work.com"].writes == []
    assert audit(storage, "create_draft") == []


# ---------------------------------------------------------------- update


async def test_update_preserves_existing_attachments(app, who, boxes, storage):
    did = (await new_draft(app, [PDF_REF, PNG_REF]))["draft_id"]
    box = boxes["alice@work.com"]
    r = await call(app, "update_draft", alias="work", draft_id=did, body="New text")
    assert r["attachments"] == ["报告 Q1.pdf", "inline-2.png"]
    assert box.attached(did) == {"报告 Q1.pdf": PDF, "inline-2.png": PNG}
    assert box.parsed(did).get_body(preferencelist=("plain",)).get_content().strip() == "New text"
    # the kept parts were downloaded from the draft's own message
    assert {c["messageId"] for c in box.downloads()} == {box.drafts[did]["message"]["id"].replace("-v2", "-v1")}
    assert audit(storage, "update_draft")[-1] == f"draft={did} fields=body attachments=2 bytes={len(PDF) + len(PNG)}"


async def test_update_add_and_remove(app, who, boxes):
    did = (await new_draft(app, [PDF_REF]))["draft_id"]
    box = boxes["alice@work.com"]
    r = await call(app, "update_draft", alias="work", draft_id=did, add_attachments=[CSV_REF, CSV_REF])
    assert r["attachments"] == ["报告 Q1.pdf", "data.csv"]
    r = await call(app, "update_draft", alias="work", draft_id=did, remove_attachments=["报告 Q1.pdf"])
    assert r["attachments"] == ["data.csv"] and r["removed_attachments"] == ["报告 Q1.pdf"]
    assert box.attached(did) == {"data.csv": CSV}
    # remove by part_id (data.csv is part 1 of the current draft message), add another
    r = await call(app, "update_draft", alias="work", draft_id=did, remove_attachments=["1"],
                   add_attachments=[PNG_REF])
    assert r["attachments"] == ["inline-1.png"] and box.attached(did) == {"inline-1.png": PNG}


async def test_update_remove_unknown_lists_current(app, who, boxes):
    did = (await new_draft(app, [PDF_REF]))["draft_id"]
    with pytest.raises(ToolError, match=r"no attachment 'nope.txt' on this draft.*报告 Q1.pdf \[part_id 1\]"):
        await call(app, "update_draft", alias="work", draft_id=did, remove_attachments=["nope.txt"])
    assert [w for w, _ in boxes["alice@work.com"].writes] == ["create"]


async def test_update_size_limit_counts_kept_and_added(app, who, boxes):
    box = boxes["alice@work.com"]
    did = (await new_draft(app, [PDF_REF]))["draft_id"]
    box.drafts[did]["message"]["payload"]["parts"][1]["body"]["size"] = 15 * MB
    with pytest.raises(ToolError, match="over the 20.0 MB attachment limit"):
        await call(app, "update_draft", alias="work", draft_id=did,
                   add_attachments=[{"message_id": "big", "part_id": "1"}])
    assert box.downloads() == [] and [w for w, _ in box.writes] == ["create"]
    # dropping the big one makes room
    r = await call(app, "update_draft", alias="work", draft_id=did, remove_attachments=["报告 Q1.pdf"],
                   add_attachments=[CSV_REF])
    assert r["attachments"] == ["data.csv"]


async def test_update_keeps_inline_image_as_attachment(app, who, boxes):
    box = boxes["alice@work.com"]
    box.drafts["d1"] = {"id": "d1", "message": {"id": "dm1", "threadId": "t9", "payload": {
        "mimeType": "multipart/related",
        "headers": hdrs(From="alice@work.com", To="bob@x.com", Subject="Logo"),
        "parts": [
            {"partId": "0", "mimeType": "text/html", "body": {"data": b64('<p>hi <img src="cid:i1"></p>')}},
            {"partId": "1", "mimeType": "image/png", "filename": "",
             "headers": [{"name": "Content-ID", "value": "<i1>"}],
             "body": {"size": len(PNG), "attachmentId": "att-i1"}},
        ]}}}
    box.blobs[("dm1", "att-i1")] = PNG
    r = await call(app, "update_draft", alias="work", draft_id="d1", subject="Logo v2")
    assert r["attachments"] == ["inline-1.png"] and r["flattened_html"] is True
    assert box.attached("d1") == {"inline-1.png": PNG} and box.drafts["d1"]["message"]["threadId"] == "t9"


async def test_update_cross_mailbox_add_refused(app, who, boxes):
    did = (await new_draft(app, [PDF_REF]))["draft_id"]
    with pytest.raises(ToolError, match="'p1' isn't in this mailbox"):
        await call(app, "update_draft", alias="work", draft_id=did, add_attachments=[{"message_id": "p1",
                                                                                      "part_id": "1"}])


# ---------------------------------------------------------------- large upload path


async def test_large_drafts_use_media_upload(app, who, boxes, monkeypatch):
    monkeypatch.setattr(g, "RAW_JSON_LIMIT", 200)
    r = await new_draft(app, [PDF_REF], reply_to_message_id="m2")
    box = boxes["alice@work.com"]
    kind, kw = box.writes[-1]
    assert kind == "create" and "media_body" in kw and kw["body"] == {"message": {"threadId": "t2"}}
    await call(app, "update_draft", alias="work", draft_id=r["draft_id"], add_attachments=[CSV_REF])
    kind, kw = box.writes[-1]
    assert kind == "update" and "media_body" in kw
    assert kw["body"] == {"id": r["draft_id"], "message": {"threadId": "t2"}}
    assert box.attached(r["draft_id"]) == {"报告 Q1.pdf": PDF, "data.csv": CSV}


# ---------------------------------------------------------------- send_email / forward


async def test_send_email_auto_with_attachment(app, who, boxes, storage):
    storage.set_send_policy(ALICE, "work", "auto")
    r = await call(app, "send_email", alias="work", to="erin@x.com", subject="s", body="b",
                   attachments=[PDF_REF])
    box = boxes["alice@work.com"]
    assert r["status"] == "sent" and r["attachments"] == ["报告 Q1.pdf"]
    assert box.sent == [{"userId": "me", "body": {"id": r["draft_id"]}}]
    assert box.attached(r["draft_id"]) == {"报告 Q1.pdf": PDF}
    assert any(d.endswith(f"attachments=1 bytes={len(PDF)}") for d in audit(storage, "send_email"))


async def test_attachment_names_shown_for_confirmation(app, who, boxes, storage):
    storage.set_send_policy(ALICE, "work", "confirm")
    human = Human("decline")
    r = await call_with(app, human, "send_email", alias="work", to="erin@x.com", subject="s", body="b",
                        attachments=[PDF_REF, CSV_REF])
    assert r["status"] == "declined"
    [prompt] = human.prompts
    assert "Attachments: 报告 Q1.pdf, data.csv" in prompt
    # the link channel's page uses the same summary source
    info = g.op_draft_for_send(boxes["alice@work.com"].service(), r["draft_id"])
    assert info["attachments"] == ["报告 Q1.pdf", "data.csv"]


async def test_forward_with_extra_attachments(app, who, boxes, storage):
    r = await call(app, "forward_message", alias="work", message_id="m1", to="erin@x.com",
                   attachments=[CSV_REF, PDF_REF])  # PDF_REF is already part of m1: deduped
    box = boxes["alice@work.com"]
    assert r["attachments"] == ["报告 Q1.pdf", "inline-2.png", "data.csv"]
    assert box.attached(r["draft_id"])["data.csv"] == CSV and len(box.attached(r["draft_id"])) == 3
    assert audit(storage, "forward_message")[-1].endswith(
        f"attachments=3 bytes={len(PDF) + len(PNG) + len(CSV)}")


async def test_forward_extra_counts_toward_limit(app, who, boxes):
    box = boxes["alice@work.com"]
    box.messages["m1"]["payload"]["parts"][1]["body"]["size"] = 19 * MB
    with pytest.raises(ToolError, match="over the 20.0 MB forward limit"):
        await call(app, "forward_message", alias="work", message_id="m1", to="erin@x.com",
                   attachments=[{"message_id": "big", "part_id": "2"}])
    assert box.downloads() == [] and box.writes == []


async def test_forward_cross_mailbox_refused(app, who, boxes):
    with pytest.raises(ToolError, match="'p1' isn't in this mailbox"):
        await call(app, "forward_message", alias="work", message_id="m1", to="erin@x.com",
                   attachments=[{"message_id": "p1", "part_id": "1"}])
    assert boxes["alice@work.com"].writes == []
