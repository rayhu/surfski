"""Address aliases and send-from (#1): list_addresses, labels, default From and
from_address on create_draft/update_draft. Gmail is a discovery-validated StrictGmail."""

import base64
import email
from email import policy

import httplib2
import pytest
from fastmcp.exceptions import ToolError
from googleapiclient.errors import HttpError

from surfski.server import create_app

from .fakes import StrictGmail
from .test_server import ALICE, BOB, call, who  # noqa: F401  (fixture re-export)

IDENTITIES = {
    "alice@work.com": [
        {"sendAsEmail": "alice@work.com", "displayName": "Alice", "isPrimary": True, "isDefault": True},
        {"sendAsEmail": "Sales@Work.org", "displayName": "张三", "verificationStatus": "accepted",
         "signature": "<div>张三<br>Sales &amp; Support</div>"},
        {"sendAsEmail": "pending@work.org", "displayName": "P", "verificationStatus": "pending"},
    ],
    "bob@work.com": [
        {"sendAsEmail": "bob@work.com", "displayName": "Bob", "isPrimary": True, "isDefault": True},
        {"sendAsEmail": "boss@work.com", "displayName": "The Boss", "verificationStatus": "accepted"},
    ],
}


def b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def raw_bytes(body: dict) -> bytes:
    return base64.urlsafe_b64decode(body["message"]["raw"])


def parse(body: dict):
    return email.message_from_bytes(raw_bytes(body), policy=policy.default)


class Mailbox:
    def __init__(self, address: str):
        self.address = address
        self.created: list[dict] = []
        self.updated: list[dict] = []
        self.drafts: dict[str, dict] = {}
        self.send_as_error: Exception | None = None
        self.original = {
            "id": "m1", "threadId": "t1",
            "payload": {"headers": [
                {"name": "Subject", "value": "Pricing"},
                {"name": "Message-ID", "value": "<orig@x.com>"},
                {"name": "To", "value": "Sales Team <sales@work.org>"},
                {"name": "Delivered-To", "value": self.address},
            ]},
        }

    def send_as(self, **kw):
        if self.send_as_error:
            raise self.send_as_error
        return {"sendAs": IDENTITIES[self.address]}

    def create(self, **kw):
        self.created.append(kw["body"])
        return {"id": f"d{len(self.created)}"}

    def get_draft(self, **kw):
        return self.drafts[kw["id"]]

    def update(self, **kw):
        self.updated.append(kw["body"])
        self.drafts[kw["id"]]["message"]["payload"] = {
            "mimeType": "text/plain",
            "headers": [{"name": k, "value": v} for k, v in parse(kw["body"]).items()],
            "body": {"data": b64(parse(kw["body"]).get_content())},
        }
        return {"id": kw["id"]}

    def service(self):
        return StrictGmail({
            "users.settings.sendAs.list": self.send_as,
            "users.messages.get": lambda **kw: self.original,
            "users.drafts.create": self.create,
            "users.drafts.get": self.get_draft,
            "users.drafts.update": self.update,
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
    storage.upsert_account(BOB, "work", "bob@work.com", "rt", "s")
    for a in ("alice@work.com", "bob@work.com"):
        boxes[a] = Mailbox(a)

    def factory(owner, alias):
        svc = boxes[storage.get_account(owner, alias).email].service()
        services.append(svc)
        return svc

    return create_app(config, storage=storage, with_auth=False, service_factory=factory)


def send_as_calls(services):
    return sum(len(s.calls_to("users.settings.sendAs.list")) for s in services)


async def test_list_addresses_and_cache(app, who, services):
    r = await call(app, "list_addresses", alias="work")
    assert [a["address"] for a in r["addresses"]] == ["alice@work.com", "sales@work.org", "pending@work.org"]
    sales = r["addresses"][1]
    assert sales == {"address": "sales@work.org", "display_name": "张三", "label": None, "is_default": False,
                     "is_primary": False, "verification_status": "accepted", "verified": True,
                     "has_signature": True}
    assert r["addresses"][0]["verified"] and not r["addresses"][2]["verified"]
    assert send_as_calls(services) == 1
    await call(app, "list_addresses", alias="work")
    assert send_as_calls(services) == 1  # cached
    await call(app, "list_addresses", alias="work", refresh=True)
    assert send_as_calls(services) == 2


async def test_from_explicit_with_chinese_display_name(app, who, boxes):
    r = await call(app, "create_draft", alias="work", to="c@x.com", subject="报价", body="好的",
                   from_address="SALES@work.org")
    assert r["from"] == "sales@work.org" and r["from_source"] == "explicit"
    body = boxes["alice@work.com"].created[-1]
    from_line = [l for l in raw_bytes(body).split(b"\n") if l.startswith(b"From:")][0]
    assert b"=?utf-8?" in from_line and b"<sales@work.org>" in from_line
    addr = parse(body)["From"].addresses[0]
    assert addr.display_name == "张三" and addr.addr_spec == "sales@work.org"


@pytest.mark.parametrize("value,msg", [
    ("pending@work.org", "not verified for sending"),
    ("nobody@work.org", "not a send-as address"),
    ("nolabel", "label 'nolabel' is not a send-as address"),
])
async def test_invalid_from_rejected_with_choices(app, who, boxes, value, msg):
    with pytest.raises(ToolError, match=msg) as e:
        await call(app, "create_draft", alias="work", to="c@x.com", subject="s", body="b", from_address=value)
    assert "Valid choices: alice@work.com, sales@work.org" in str(e.value)
    assert "pending@work.org," not in str(e.value).split("Valid choices:")[1]
    assert boxes["alice@work.com"].created == []


async def test_label_resolves(app, who, boxes, storage):
    r = await call(app, "set_address_label", alias="work", address="Sales@work.org", label="Sales")
    assert r == {"ok": True, "address": "sales@work.org", "label": "sales"}
    r = await call(app, "create_draft", alias="work", to="c@x.com", subject="s", body="b", from_address="sales")
    assert r["from"] == "sales@work.org" and r["from_source"] == "label"
    with pytest.raises(ToolError, match="Valid choices: alice@work.com, sales@work.org \\(label 'sales'\\)"):
        await call(app, "create_draft", alias="work", to="c@x.com", subject="s", body="b", from_address="x@y.z")
    # label rules
    with pytest.raises(ToolError, match="label must match"):
        await call(app, "set_address_label", alias="work", address="sales@work.org", label="bad label")
    with pytest.raises(ToolError, match="not verified"):
        await call(app, "set_address_label", alias="work", address="pending@work.org", label="p")
    with pytest.raises(ToolError, match="already used for sales@work.org"):
        await call(app, "set_address_label", alias="work", address="alice@work.com", label="sales")
    # empty label removes
    await call(app, "set_address_label", alias="work", address="sales@work.org", label="")
    assert storage.get_address_labels(ALICE, "work") == {}


async def test_reply_defaults_to_original_recipient_alias(app, who, boxes):
    r = await call(app, "create_draft", alias="work", to="c@x.com", subject="", body="ok",
                   reply_to_message_id="m1")
    assert r["from"] == "sales@work.org" and r["from_source"] == "reply"
    m = parse(boxes["alice@work.com"].created[-1])
    assert m["From"].addresses[0].addr_spec == "sales@work.org"
    assert m["In-Reply-To"] == "<orig@x.com>" and m["Subject"] == "Re: Pricing"
    # explicit beats reply
    r = await call(app, "create_draft", alias="work", to="c@x.com", subject="", body="ok",
                   reply_to_message_id="m1", from_address="alice@work.com")
    assert r["from"] == "alice@work.com" and r["from_source"] == "explicit"


async def test_default_chain(app, who, boxes, storage):
    r = await call(app, "create_draft", alias="work", to="c@x.com", subject="s", body="b")
    assert r["from"] == "alice@work.com" and r["from_source"] == "gmail_default"
    assert parse(boxes["alice@work.com"].created[-1])["From"] == "Alice <alice@work.com>"
    r = await call(app, "set_default_from", alias="work", address="sales@work.org")
    assert r == {"ok": True, "default_from": "sales@work.org"}
    r = await call(app, "create_draft", alias="work", to="c@x.com", subject="s", body="b")
    assert r["from"] == "sales@work.org" and r["from_source"] == "stored_default"
    with pytest.raises(ToolError, match="not verified"):
        await call(app, "set_default_from", alias="work", address="pending@work.org")
    r = await call(app, "set_default_from", alias="work", address="")
    assert r["default_from"] is None and storage.get_account(ALICE, "work").default_from is None


async def test_send_as_failure_falls_back_unless_requested(app, who, boxes):
    boxes["alice@work.com"].send_as_error = HttpError(httplib2.Response({"status": 403}), b"")
    r = await call(app, "create_draft", alias="work", to="c@x.com", subject="s", body="b")
    assert r["from"] == "alice@work.com" and r["from_source"] == "account"
    with pytest.raises(ToolError, match="Google denied access"):
        await call(app, "create_draft", alias="work", to="c@x.com", subject="s", body="b",
                   from_address="sales@work.org")


async def test_signature_appended(app, who, boxes):
    await call(app, "create_draft", alias="work", to="c@x.com", subject="s", body="Hello",
               from_address="sales@work.org", include_signature=True)
    content = parse(boxes["alice@work.com"].created[-1]).get_content()
    assert content.rstrip("\n") == "Hello\n\n-- \n张三\nSales & Support"


async def test_update_draft_from_and_signature(app, who, boxes):
    box = boxes["alice@work.com"]
    box.drafts["d9"] = {"id": "d9", "message": {"id": "m9", "threadId": "t1", "payload": {
        "mimeType": "text/plain",
        "headers": [{"name": "From", "value": "Alice <alice@work.com>"}, {"name": "To", "value": "c@x.com"},
                    {"name": "Subject", "value": "Re: Pricing"}, {"name": "In-Reply-To", "value": "<orig@x.com>"},
                    {"name": "References", "value": "<orig@x.com>"}],
        "body": {"data": b64("Draft text")},
    }}}
    r = await call(app, "update_draft", alias="work", draft_id="d9", from_address="sales@work.org",
                   include_signature=True)
    assert r["from"] == "sales@work.org" and r["from_source"] == "explicit"
    sent = box.updated[-1]
    assert sent["message"]["threadId"] == "t1"
    m = parse(sent)
    assert m["From"].addresses[0].display_name == "张三"
    assert m["In-Reply-To"] == "<orig@x.com>" and m["To"] == "c@x.com"
    assert m.get_content().count("-- \n张三") == 1
    # signature again, From kept: not duplicated
    r = await call(app, "update_draft", alias="work", draft_id="d9", include_signature=True)
    assert r["from_source"] == "current"
    assert parse(box.updated[-1]).get_content().count("-- \n张三") == 1
    # no from/signature params: no sendAs needed, From untouched
    await call(app, "update_draft", alias="work", draft_id="d9", subject="x")
    assert parse(box.updated[-1])["From"].addresses[0].addr_spec == "sales@work.org"
    with pytest.raises(ToolError, match="not verified"):
        await call(app, "update_draft", alias="work", draft_id="d9", from_address="pending@work.org")


async def test_list_accounts_reads_db_and_cache_only(app, who, services):
    r = await call(app, "list_accounts")
    assert r[0]["addresses"] is None and r[0]["addresses_loaded"] is False
    assert "list_addresses('work')" in r[0]["addresses_hint"]
    assert services == []  # no Gmail service was even built
    await call(app, "set_address_label", alias="work", address="sales@work.org", label="sales")
    await call(app, "set_default_from", alias="work", address="sales")
    n = len(services)
    r = await call(app, "list_accounts")
    assert len(services) == n
    row = r[0]
    assert row["addresses_loaded"] is True and row["default_from"] == "sales@work.org"
    assert row["address_labels"] == {"sales": "sales@work.org"}
    assert [a["label"] for a in row["addresses"]] == [None, "sales", None]


async def test_owner_isolation_labels_defaults_cache(app, who, boxes):
    who["claims"] = {"email": BOB}
    await call(app, "set_address_label", alias="work", address="boss@work.com", label="boss")
    await call(app, "set_default_from", alias="work", address="boss")
    await call(app, "list_addresses", alias="work")

    who["claims"] = {"email": ALICE}
    [row] = await call(app, "list_accounts")
    assert row["address_labels"] == {} and row["default_from"] is None
    assert row["addresses_loaded"] is False  # Bob's cached identities are not Alice's
    with pytest.raises(ToolError, match="label 'boss' is not a send-as address"):
        await call(app, "create_draft", alias="work", to="c@x.com", subject="s", body="b", from_address="boss")
    with pytest.raises(ToolError, match="not a send-as address"):
        await call(app, "create_draft", alias="work", to="c@x.com", subject="s", body="b",
                   from_address="boss@work.com")
    with pytest.raises(ToolError, match="not a send-as address"):
        await call(app, "set_address_label", alias="work", address="boss@work.com", label="mine")
    r = await call(app, "create_draft", alias="work", to="c@x.com", subject="s", body="b")
    assert r["from"] == "alice@work.com"  # Bob's default is not applied
    assert boxes["bob@work.com"].created == []
    with pytest.raises(ToolError, match="no linked account 'secret'"):
        await call(app, "set_default_from", alias="secret", address="x@y.z")


async def test_labels_follow_rename_and_unlink(app, who, storage):
    await call(app, "set_address_label", alias="work", address="sales@work.org", label="sales")
    await call(app, "set_default_from", alias="work", address="sales")
    await call(app, "rename_account", old_alias="work", new_alias="job")
    [row] = await call(app, "list_accounts")
    assert row["alias"] == "job" and row["address_labels"] == {"sales": "sales@work.org"}
    assert row["default_from"] == "sales@work.org"
    assert row["addresses_loaded"] is False  # cache dropped on rename
    storage.delete_account(ALICE, "job")
    storage.upsert_account(ALICE, "job", "alice@work.com", "rt", "s")
    assert storage.get_address_labels(ALICE, "job") == {}


def test_relink_to_other_mailbox_clears_settings(storage):
    storage.upsert_account(ALICE, "work", "alice@work.com", "rt", "s")
    storage.set_address_label(ALICE, "work", "sales@work.org", "sales")
    storage.set_default_from(ALICE, "work", "sales@work.org")
    storage.upsert_account(ALICE, "work", "alice@work.com", "rt2", "s")  # same mailbox: kept
    assert storage.get_address_labels(ALICE, "work") == {"sales": "sales@work.org"}
    storage.upsert_account(ALICE, "work", "other@else.com", "rt3", "s")  # different mailbox
    assert storage.get_address_labels(ALICE, "work") == {}
    assert storage.get_account(ALICE, "work").default_from is None


def test_strict_fake_send_as_list_params():
    svc = StrictGmail({"users.settings.sendAs.list": lambda **kw: {}})
    svc.users().settings().sendAs().list(userId="me").execute()
    with pytest.raises(TypeError):
        svc.users().settings().sendAs().list(userId="me", maxResults=5)
