"""Tool-level tests via FastMCP's in-memory client. Identity is injected by
monkeypatching get_access_token; Gmail and Google token endpoints are mocked."""

import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from starlette.testclient import TestClient

import surfski.server as srv
from surfski.server import create_app

ALICE, BOB = "alice@example.com", "bob@example.com"


class FakeGmail:
    """Minimal fake of the googleapiclient Gmail service, tagged by mailbox."""

    def __init__(self, mailbox):
        self.mailbox = mailbox

    def users(self):
        return self

    def threads(self):
        return self

    def list(self, **kw):
        return SimpleNamespace(execute=lambda: {"threads": [{"id": f"{self.mailbox}-t1"}]})

    def get(self, **kw):
        return SimpleNamespace(execute=lambda: {
            "id": kw["id"],
            "messages": [{"labelIds": ["INBOX"], "snippet": "hi",
                          "payload": {"headers": [{"name": "Subject", "value": f"from {self.mailbox}"}]}}],
        })


@pytest.fixture
def who(monkeypatch):
    state = {"claims": {"email": ALICE, "email_verified": True}}
    monkeypatch.setattr(srv, "get_access_token", lambda: SimpleNamespace(claims=state["claims"]))
    return state


@pytest.fixture
def app(config, storage):
    def factory(owner, alias):
        return FakeGmail(storage.get_account(owner, alias).email)

    storage.upsert_account(ALICE, "work", "alice@work.com", "rt", "s")
    storage.upsert_account(ALICE, "personal", "alice@gmail.com", "rt", "s")
    storage.upsert_account(BOB, "work", "bob@work.com", "rt", "s")
    storage.upsert_account(BOB, "secret", "bob@secret.com", "rt", "s")
    return create_app(config, storage=storage, with_auth=False, service_factory=factory)


async def call(app, tool, **args):
    async with Client(app) as c:
        r = await c.call_tool(tool, args)
        return r.data if r.data is not None else r.structured_content


async def test_list_accounts_scoped(app, who):
    accts = await call(app, "list_accounts")
    assert {a["alias"] for a in accts} == {"work", "personal"}
    who["claims"] = {"email": BOB}
    accts = await call(app, "list_accounts")
    assert {a["alias"] for a in accts} == {"work", "secret"}


async def test_cross_owner_alias_rejected(app, who):
    with pytest.raises(ToolError, match="no linked account 'secret'"):
        await call(app, "get_thread", alias="secret", thread_id="t1")


async def test_same_alias_resolves_to_own_mailbox(app, who):
    r = await call(app, "get_thread", alias="work", thread_id="t1")
    assert r["messages"][0]["subject"] == "from alice@work.com"


async def test_search_all_accounts_only_own(app, who):
    r = await call(app, "search_all_accounts", query="x")
    assert set(r["results"]) == {"work", "personal"}
    subjects = {t["subject"] for v in r["results"].values() for t in v["threads"]}
    assert subjects == {"from alice@work.com", "from alice@gmail.com"}


async def test_search_all_accounts_partial_failure(config, storage, who):
    storage.upsert_account(ALICE, "good", "alice@good.com", "rt", "s")
    storage.upsert_account(ALICE, "bad", "alice@bad.com", "rt", "s")

    def factory(owner, alias):
        if alias == "bad":
            from google.auth.exceptions import RefreshError
            raise RefreshError("invalid_grant")
        return FakeGmail(alias)

    app = create_app(config, storage=storage, with_auth=False, service_factory=factory)
    r = await call(app, "search_all_accounts", query="x")
    assert "relink_account('bad')" in r["results"]["bad"]["error"]
    assert r["results"]["good"]["threads"]


@pytest.mark.parametrize("claims,msg", [
    ({"email": "mallory@example.com", "email_verified": True}, "not allowed"),
    ({"email": ALICE, "email_verified": "false"}, "not verified"),
    ({}, "no email"),
])
async def test_rejected_callers(app, who, claims, msg):
    who["claims"] = claims
    with pytest.raises(ToolError, match=msg):
        await call(app, "list_accounts")


async def test_string_true_email_verified_accepted(app, who):
    who["claims"] = {"email": "ALICE@example.com", "email_verified": "true"}
    assert await call(app, "list_accounts")


async def test_audit_has_no_bodies(app, who, storage):
    await call(app, "get_thread", alias="work", thread_id="t1")
    rows = storage.audit_rows(ALICE)
    assert rows[-1]["tool"] == "get_thread" and rows[-1]["ok"] == 1
    assert "hi" not in rows[-1]["detail"]


async def test_rate_limit(config, storage, who):
    from dataclasses import replace
    app = create_app(replace(config, rate_limit_per_minute=2), storage=storage, with_auth=False)
    await call(app, "list_accounts")
    await call(app, "list_accounts")
    with pytest.raises(ToolError, match="rate limit"):
        await call(app, "list_accounts")


# ---------------------------------------------------------------- linking flow


def google_mock(refresh_token="rt-new", profile="alice.work@corp.com"):
    seen = {}

    def handler(req: httpx.Request):
        if req.url.host == "oauth2.googleapis.com" and req.url.path == "/token":
            seen["token_form"] = parse_qs(req.content.decode())
            body = {"access_token": "at", "expires_in": 3600,
                    "scope": "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.compose"}
            if refresh_token:
                body["refresh_token"] = refresh_token
            return httpx.Response(200, json=body)
        if req.url.path.endswith("/profile"):
            return httpx.Response(200, json={"emailAddress": profile})
        if req.url.path == "/revoke":
            seen["revoked"] = True
            return httpx.Response(200)
        return httpx.Response(404)

    return seen, (lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))


async def test_link_flow_end_to_end(config, storage, who):
    seen, http = google_mock()
    app = create_app(config, storage=storage, with_auth=False, http_factory=http)
    r = await call(app, "link_account", alias="corp")
    state = parse_qs(urlparse(r["url"]).query)["state"][0]

    web = TestClient(app.http_app())
    resp = web.get("/gmail/callback", params={"code": "c0de", "state": state})
    assert resp.status_code == 200 and "Linked" in resp.text and "alice.work@corp.com" in resp.text
    assert seen["token_form"]["code_verifier"][0]
    assert storage.get_refresh_token(ALICE, "corp") == "rt-new"

    # replay is rejected
    resp = web.get("/gmail/callback", params={"code": "c0de", "state": state})
    assert resp.status_code == 400

    # unlink revokes
    r = await call(app, "unlink_account", alias="corp")
    assert r == {"ok": True, "revoked_at_google": True} and seen["revoked"]
    assert not any(a.alias == "corp" for a in storage.list_accounts(ALICE))


async def test_link_without_refresh_token_rejected(config, storage, who):
    _, http = google_mock(refresh_token=None)
    app = create_app(config, storage=storage, with_auth=False, http_factory=http)
    r = await call(app, "link_account", alias="corp")
    state = parse_qs(urlparse(r["url"]).query)["state"][0]
    resp = TestClient(app.http_app()).get("/gmail/callback", params={"code": "c", "state": state})
    assert resp.status_code == 400 and "myaccount.google.com/permissions" in resp.text
    assert storage.list_accounts(ALICE) == []


def test_healthz(config, storage):
    app = create_app(config, storage=storage, with_auth=False)
    resp = TestClient(app.http_app()).get("/healthz")
    assert resp.status_code == 200 and resp.text == "ok"


def test_app_with_real_auth_builds(config, storage):
    """GoogleProvider + encrypted FileTree client storage construct without network."""
    app = create_app(config, storage=storage, with_auth=True)
    assert (config.data_dir / "oauth").is_dir()
    resp = TestClient(app.http_app()).get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    assert resp.json()["issuer"].startswith("http://localhost:8000")
    resp = TestClient(app.http_app()).post("/mcp", json={})
    assert resp.status_code == 401


async def test_rename_account_tool(app, who, storage):
    r = await call(app, "rename_account", old_alias="work", new_alias="job")
    assert r == {"ok": True, "alias": "job"}
    assert {a["alias"] for a in await call(app, "list_accounts")} == {"job", "personal"}
    r = await call(app, "get_thread", alias="job", thread_id="t1")
    assert r["messages"][0]["subject"] == "from alice@work.com"
    # cannot rename another owner's alias
    with pytest.raises(ToolError, match="no linked account 'secret'"):
        await call(app, "rename_account", old_alias="secret", new_alias="mine")
