"""Draft management tools (list/get/update/delete) against an in-memory fake."""

import base64
import email
from email import policy
from types import SimpleNamespace

import httplib2
import pytest
from fastmcp.exceptions import ToolError
from googleapiclient.errors import HttpError

from surfski.server import create_app

from .test_server import ALICE, BOB, call, who  # noqa: F401  (fixture re-export)


def b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def hdrs(**kw):
    return [{"name": k.replace("_", "-"), "value": v} for k, v in kw.items()]


def decode_raw(raw: str):
    return email.message_from_bytes(base64.urlsafe_b64decode(raw), policy=policy.default)


def reply_draft(draft_id="d1", **extra_headers):
    headers = dict(
        From="Alice <alice@work.com>",
        To="bob@x.com",
        Cc="carol@x.com",
        Subject="Re: Plan",
        In_Reply_To="<m1@x.com>",
        References="<m0@x.com> <m1@x.com>",
        Date="Mon, 1 Jan 2026 10:00:00 +0000",
    )
    headers.update(extra_headers)
    return {
        "id": draft_id,
        "message": {
            "id": f"msg-{draft_id}",
            "threadId": "t-77",
            "snippet": "Let&#39;s meet",
            "labelIds": ["DRAFT"],
            "payload": {
                "mimeType": "text/plain",
                "headers": hdrs(**headers),
                "body": {"data": b64("Let's meet Tuesday.")},
            },
        },
    }


def not_found():
    return HttpError(httplib2.Response({"status": 404}), b"not found")


class FakeDrafts:
    def __init__(self, store: dict, mailbox: str):
        self.store = store.setdefault(mailbox, {})
        self.calls: list = []

    def _exec(self, fn):
        return SimpleNamespace(execute=fn)

    def list(self, **kw):
        self.calls.append(("list", kw))
        ids = sorted(self.store)
        return self._exec(lambda: {
            "drafts": [{"id": i, "message": {"id": f"msg-{i}"}} for i in ids],
            "nextPageToken": "next" if not kw.get("pageToken") else None,
        })

    def get(self, **kw):
        self.calls.append(("get", kw))

        def run():
            if kw["id"] not in self.store:
                raise not_found()
            return self.store[kw["id"]]
        return self._exec(run)

    def update(self, **kw):
        self.calls.append(("update", kw))

        def run():
            if kw["id"] not in self.store:
                raise not_found()
            self.store[kw["id"]]["_last_update"] = kw["body"]
            return {"id": kw["id"], "message": {"id": "new-msg"}}
        return self._exec(run)

    def delete(self, **kw):
        self.calls.append(("delete", kw))

        def run():
            if kw["id"] not in self.store:
                raise not_found()
            del self.store[kw["id"]]
            return ""
        return self._exec(run)


class FakeGmail:
    def __init__(self, store, mailbox):
        self._drafts = FakeDrafts(store, mailbox)

    def users(self):
        return self

    def drafts(self):
        return self._drafts


@pytest.fixture
def store():
    return {}


@pytest.fixture
def app(config, storage, store):
    storage.upsert_account(ALICE, "work", "alice@work.com", "rt", "s")
    storage.upsert_account(BOB, "secret", "bob@secret.com", "rt", "s")
    store["alice@work.com"] = {"d1": reply_draft("d1"), "d2": reply_draft("d2", Subject="周报")}
    store["bob@secret.com"] = {"b1": reply_draft("b1")}

    def factory(owner, alias):
        return FakeGmail(store, storage.get_account(owner, alias).email)

    return create_app(config, storage=storage, with_auth=False, service_factory=factory)


async def test_list_drafts(app, who):
    r = await call(app, "list_drafts", alias="work")
    assert r["next_page_token"] == "next"
    assert [d["draft_id"] for d in r["drafts"]] == ["d1", "d2"]
    d = r["drafts"][0]
    assert d == {
        "draft_id": "d1", "message_id": "msg-d1", "thread_id": "t-77", "subject": "Re: Plan",
        "to": "bob@x.com", "date": "Mon, 1 Jan 2026 10:00:00 +0000", "snippet": "Let's meet",
    }
    assert r["drafts"][1]["subject"] == "周报"


async def test_list_drafts_max_results_bounded(app, who):
    with pytest.raises(ToolError):
        await call(app, "list_drafts", alias="work", max_results=51)


async def test_get_draft(app, who):
    r = await call(app, "get_draft", alias="work", draft_id="d1")
    assert r["draft_id"] == "d1" and r["id"] == "msg-d1" and r["thread_id"] == "t-77"
    assert r["body"] == "Let's meet Tuesday." and r["subject"] == "Re: Plan"
    assert r["cc"] == "carol@x.com" and r["label_ids"] == ["DRAFT"]


async def test_update_draft_keeps_threading_and_unspecified(app, who, store, storage):
    r = await call(app, "update_draft", alias="work", draft_id="d1",
                   subject="回复：计划", body="周二见。\n谢谢")
    assert r == {"draft_id": "d1", "gmail_url": "https://mail.google.com/mail/u/alice@work.com/#drafts"}
    sent = store["alice@work.com"]["d1"]["_last_update"]
    assert sent["id"] == "d1" and sent["message"]["threadId"] == "t-77"
    m = decode_raw(sent["message"]["raw"])
    assert m["From"] == "Alice <alice@work.com>"
    assert m["To"] == "bob@x.com" and m["Cc"] == "carol@x.com"
    assert m["In-Reply-To"] == "<m1@x.com>"
    assert m["References"] == "<m0@x.com> <m1@x.com>"
    assert m["Subject"] == "回复：计划"
    assert m.get_content_type() == "text/plain" and m.get_content_charset() == "utf-8"
    assert m.get_content().strip() == "周二见。\n谢谢"
    rows = storage.audit_rows(ALICE)
    assert rows[-1]["tool"] == "update_draft" and rows[-1]["ok"] == 1
    assert "fields=subject,body" in rows[-1]["detail"]
    assert "周二" not in rows[-1]["detail"] and "计划" not in rows[-1]["detail"]


async def test_update_draft_keeps_body_and_clears_cc(app, who, store):
    await call(app, "update_draft", alias="work", draft_id="d1", to="dave@x.com", cc="")
    m = decode_raw(store["alice@work.com"]["d1"]["_last_update"]["message"]["raw"])
    assert m["To"] == "dave@x.com" and m["Cc"] is None
    assert m["Subject"] == "Re: Plan"
    assert m.get_content().strip() == "Let's meet Tuesday."


async def test_update_draft_refuses_attachments(app, who, store):
    d = store["alice@work.com"]["d1"]
    d["message"]["payload"] = {
        "mimeType": "multipart/mixed",
        "headers": d["message"]["payload"]["headers"],
        "parts": [
            {"mimeType": "text/plain", "body": {"data": b64("hi")}},
            {"mimeType": "application/pdf", "filename": "a.pdf", "body": {"size": 9, "attachmentId": "x"}},
        ],
    }
    with pytest.raises(ToolError, match="attachments"):
        await call(app, "update_draft", alias="work", draft_id="d1", body="new")
    assert "_last_update" not in d


async def test_update_draft_without_recipients_needs_to(app, who, store):
    store["alice@work.com"]["d3"] = reply_draft("d3", To="")
    with pytest.raises(ToolError, match="pass 'to'"):
        await call(app, "update_draft", alias="work", draft_id="d3", body="x")
    await call(app, "update_draft", alias="work", draft_id="d3", to="bob@x.com")


async def test_delete_draft(app, who, store, storage):
    r = await call(app, "delete_draft", alias="work", draft_id="d2")
    assert r == {"ok": True}
    assert set(store["alice@work.com"]) == {"d1"}
    assert storage.audit_rows(ALICE)[-1]["tool"] == "delete_draft"


async def test_delete_draft_is_destructive(app):
    from fastmcp import Client
    async with Client(app) as c:
        tools = {t.name: t for t in await c.list_tools()}
    assert tools["delete_draft"].annotations.destructive_hint is True
    assert tools["list_drafts"].annotations.read_only_hint is True
    assert tools["get_draft"].annotations.read_only_hint is True


@pytest.mark.parametrize("tool,args", [
    ("get_draft", {"draft_id": "missing"}),
    ("update_draft", {"draft_id": "missing", "body": "x"}),
    ("delete_draft", {"draft_id": "missing"}),
])
async def test_missing_draft_maps_404(app, who, storage, tool, args):
    with pytest.raises(ToolError, match="not found"):
        await call(app, tool, alias="work", **args)
    row = storage.audit_rows(ALICE)[-1]
    assert row["tool"] == tool and row["ok"] == 0


@pytest.mark.parametrize("tool,args", [
    ("list_drafts", {}),
    ("get_draft", {"draft_id": "b1"}),
    ("update_draft", {"draft_id": "b1", "body": "pwned"}),
    ("delete_draft", {"draft_id": "b1"}),
])
async def test_owner_isolation(app, who, store, tool, args):
    with pytest.raises(ToolError, match="no linked account 'secret'"):
        await call(app, tool, alias="secret", **args)
    assert set(store["bob@secret.com"]) == {"b1"}
    assert "_last_update" not in store["bob@secret.com"]["b1"]
