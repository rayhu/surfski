"""ALLOWED_DOMAINS (#6): whole Workspace domains, primary addresses, exact match only.
Every allowlist check goes through Config.is_allowed."""

import time
from dataclasses import replace

import pytest
from fastmcp.exceptions import ToolError

from surfski.config import ConfigError, load_config
from surfski.server import create_app

from .conftest import make_env
from .test_sending import (  # noqa: F401  (fixtures)
    Mailbox,
    accounts,
    boxes,
    google,
    make_app,
    sign_in,
    token_of,
    web,
)
from .test_server import ALICE, call, who  # noqa: F401

CAROL = "carol@corp.com"


# ---------------------------------------------------------------- config


def allowed(c, email, verified=True, hd="corp.com"):
    return c.is_allowed(email, email_verified=verified, hd=hd)


def test_domain_parsing_and_match(tmp_path):
    c = load_config(make_env(tmp_path, ALLOWED_DOMAINS=" Corp.com , example.org ,"))
    assert c.allowed_domains == {"corp.com", "example.org"}
    assert allowed(c, "carol@corp.com") and allowed(c, " Carol@CORP.com ", hd="CORP.com")
    assert allowed(c, "dan@example.org", verified="true", hd="example.org")
    for bad in ("carol@sub.corp.com", "carol@corp.com.evil.io", "carol@xcorp.com", "corp.com",
                "@corp.com", "", None, "carol@evilcorp.com", "a@b@corp.com", "carol@"):
        assert not allowed(c, bad), bad


def test_domain_match_requires_matching_hd_and_verified(tmp_path):
    c = load_config(make_env(tmp_path, ALLOWED_DOMAINS="corp.com"))
    assert allowed(c, CAROL, hd="corp.com")
    assert not allowed(c, CAROL, hd=None)  # personal Google account on a company address
    assert not allowed(c, CAROL, hd="")
    assert not allowed(c, CAROL, hd="other.com")  # managed by another org
    assert not allowed(c, CAROL, hd="sub.corp.com")
    for v in (None, False, "false", 1):
        assert not allowed(c, CAROL, verified=v), v
    # Explicit ALLOWED_USERS entries don't need hd (or a verified claim here).
    assert allowed(c, ALICE, verified=None, hd=None) and allowed(c, ALICE, hd="other.com")


def test_users_only_or_domains_only(tmp_path):
    c = load_config(make_env(tmp_path, ALLOWED_USERS="", ALLOWED_DOMAINS="corp.com"))
    assert c.allowed_users == frozenset() and allowed(c, CAROL) and not allowed(c, ALICE, hd=None)
    c = load_config(make_env(tmp_path))
    assert c.allowed_domains == frozenset() and not allowed(c, CAROL)


def test_punycode_domains(tmp_path):
    c = load_config(make_env(tmp_path, ALLOWED_DOMAINS="xn--bcher-kva.example,corp.xn--p1ai"))
    assert c.allowed_domains == {"xn--bcher-kva.example", "corp.xn--p1ai"}
    assert allowed(c, "ivan@corp.xn--p1ai", hd="corp.xn--p1ai")


def test_fail_closed_when_both_empty(tmp_path):
    with pytest.raises(ConfigError, match="ALLOWED_USERS and ALLOWED_DOMAINS are both empty"):
        load_config(make_env(tmp_path, ALLOWED_USERS=" , ", ALLOWED_DOMAINS=""))


@pytest.mark.parametrize("domain", ["gmail.com", "GoogleMail.com", "outlook.com", "hotmail.com",
                                    "yahoo.com", "icloud.com"])
def test_consumer_domains_rejected(tmp_path, domain):
    with pytest.raises(ConfigError, match="public mail provider.*ALLOWED_USERS"):
        load_config(make_env(tmp_path, ALLOWED_DOMAINS=f"corp.com,{domain}"))


@pytest.mark.parametrize("bad", ["@corp.com", "*.corp.com", "corp", "corp..com", "-corp.com",
                                 "corp.com/x", "co rp.com", "a@corp.com"])
def test_bad_domain_syntax_rejected(tmp_path, bad):
    with pytest.raises(ConfigError, match="ALLOWED_DOMAINS"):
        load_config(make_env(tmp_path, ALLOWED_DOMAINS=bad))


# ---------------------------------------------------------------- tools


@pytest.fixture
def dconfig(config):
    return replace(config, allowed_domains=frozenset({"corp.com"}))


def carol(**extra):
    return {"email": CAROL, "email_verified": True, **extra}


async def test_domain_user_with_matching_hd_can_use_tools(dconfig, storage, who):
    app = create_app(dconfig, storage=storage, with_auth=False)
    # fastmcp's Google provider puts userinfo (with hd) under google_user_data.
    who["claims"] = {"email": "Carol@Corp.com", "email_verified": True,
                     "google_user_data": {"email": "carol@corp.com", "hd": "corp.com"}}
    assert await call(app, "list_accounts") == []
    who["claims"] = carol(hd="corp.com")
    assert await call(app, "list_accounts") == []
    who["claims"] = {"email": CAROL, "upstream_claims": {"email_verified": True, "hd": "corp.com"}}
    with pytest.raises(ToolError):  # verified must be on the same claims as the email
        await call(app, "list_accounts")


@pytest.mark.parametrize("claims", [carol(), carol(google_user_data={"email": CAROL}),
                                    carol(hd="other.com"), carol(google_user_data={"hd": "evil.io"})])
async def test_domain_user_without_matching_hd_refused(dconfig, storage, who, claims):
    app = create_app(dconfig, storage=storage, with_auth=False)
    who["claims"] = claims
    with pytest.raises(ToolError, match="Workspace accounts managed by"):
        await call(app, "list_accounts")


async def test_other_callers_refused(dconfig, storage, who):
    app = create_app(dconfig, storage=storage, with_auth=False)
    for email in ("carol@sub.corp.com", "carol@gmail.com"):
        who["claims"] = {"email": email, "email_verified": True, "hd": "corp.com"}
        with pytest.raises(ToolError, match="not allowed to use this server"):
            await call(app, "list_accounts")
    for claims in ({"email": CAROL, "hd": "corp.com"}, carol(email_verified=False, hd="corp.com")):
        who["claims"] = claims
        with pytest.raises(ToolError, match="not verified"):
            await call(app, "list_accounts")


async def test_explicit_user_without_hd_still_allowed(dconfig, storage, who):
    app = create_app(dconfig, storage=storage, with_auth=False)
    who["claims"] = {"email": ALICE}  # no hd, no email_verified: unchanged behaviour
    assert await call(app, "list_accounts") == []


async def test_link_state_carries_hd_and_callback_rechecks(dconfig, storage, who):
    from urllib.parse import parse_qs, urlparse

    from surfski.linking import start_link, verify_state

    app = create_app(dconfig, storage=storage, with_auth=False)
    who["claims"] = carol(hd="corp.com")
    r = await call(app, "link_account", alias="work")
    state = parse_qs(urlparse(r["url"]).query)["state"][0]
    assert verify_state(dconfig.state_secret, state)["hd"] == "corp.com"
    # A state for a domain user without hd is refused before any code exchange.
    ls = start_link(storage, state_secret=dconfig.state_secret, client_id="c",
                    redirect_uri=dconfig.gmail_redirect_uri, owner=CAROL, alias="home")
    bad = parse_qs(urlparse(ls.url).query)["state"][0]
    resp = web(app).get("/gmail/callback", params={"code": "c", "state": bad})
    assert resp.status_code == 400 and "not allowed" in resp.text


# ---------------------------------------------------------------- sending sessions


def carol_app(config, storage, boxes, google):
    cfg = replace(config, allowed_domains=frozenset({"corp.com"}))
    boxes["carol@corp.com"] = Mailbox("carol@corp.com")
    storage.upsert_account(CAROL, "work", "carol@corp.com", "rt", "s")
    storage.set_send_policy(CAROL, "work", "confirm")
    return cfg, make_app(cfg, storage, boxes, google)


async def test_domain_user_sending_session_and_pruning(config, storage, boxes, google, who):
    cfg, app = carol_app(config, storage, boxes, google)
    who["claims"] = carol(hd="corp.com")
    r = await call(app, "send_draft", alias="work", draft_id="d1")
    assert r["status"] == "confirmation_required"
    client = web(app)
    google.email, google.claims_override = CAROL, {"hd": "corp.com"}
    sign_in(client, google, token_of(r["confirm_url"]))  # the id_token's hd is stored on the session
    resp = client.post("/send/confirm", data={"token": token_of(r["confirm_url"])})
    assert resp.status_code == 200 and "Sent" in resp.text
    assert len(boxes["carol@corp.com"].sent) == 1

    # The domain is removed: startup prunes Carol's sessions, and her links stop working.
    sid = storage.create_owner_session(CAROL, 3600, int(time.time()), hd="corp.com")
    keep = storage.create_owner_session(ALICE, 3600, int(time.time()))
    create_app(replace(cfg, allowed_domains=frozenset()), storage=storage, with_auth=False)
    assert storage.get_owner_session(sid, int(time.time())) is None
    assert storage.get_owner_session(keep, int(time.time()))[0] == ALICE

    r = await call(app, "send_draft", alias="work", draft_id="d1")
    gone = make_app(replace(cfg, allowed_domains=frozenset()), storage, boxes, google)
    resp = web(gone).post("/send/confirm", data={"token": token_of(r["confirm_url"])})
    assert resp.status_code == 400 and "no longer allowed" in resp.text


@pytest.mark.parametrize("hd", [None, "other.com"])
async def test_reauth_without_matching_hd_creates_no_session(config, storage, boxes, google, who, hd):
    cfg, app = carol_app(config, storage, boxes, google)
    who["claims"] = carol(hd="corp.com")
    r = await call(app, "send_draft", alias="work", draft_id="d1")
    client = web(app)
    google.email, google.claims_override = CAROL, ({"hd": hd} if hd else {})
    resp = sign_in(client, google, token_of(r["confirm_url"]), expect_ok=False)
    assert resp.status_code == 400 and "not allowed" in resp.text
    assert "set-cookie" not in resp.headers
    resp = client.post("/send/confirm", data={"token": token_of(r["confirm_url"])})
    assert resp.status_code == 400 and boxes["carol@corp.com"].sent == []


async def test_domain_session_without_hd_is_invalid(config, storage, boxes, google, who):
    cfg, app = carol_app(config, storage, boxes, google)
    who["claims"] = carol(hd="corp.com")
    r = await call(app, "send_draft", alias="work", draft_id="d1")
    client = web(app)
    sid = storage.create_owner_session(CAROL, 3600, int(time.time()))  # e.g. made before #6 hardening
    client.cookies.set("surfski_owner", sid, path="/send")
    page = client.get(f"/send/confirm?token={token_of(r['confirm_url'])}")
    assert page.status_code == 401 and "Sign in with Google" in page.text
    resp = client.post("/send/confirm", data={"token": token_of(r["confirm_url"])})
    assert resp.status_code == 400 and boxes["carol@corp.com"].sent == []
    create_app(cfg, storage=storage, with_auth=False)  # startup prunes it
    assert storage.get_owner_session(sid, int(time.time())) is None


async def test_domain_kept_session_survives_startup(dconfig, storage):
    sid = storage.create_owner_session(CAROL, 3600, int(time.time()), hd="corp.com")
    alice = storage.create_owner_session(ALICE, 3600, int(time.time()))
    create_app(dconfig, storage=storage, with_auth=False)
    assert storage.get_owner_session(sid, int(time.time())) == (CAROL, pytest.approx(time.time(), abs=5),
                                                                 "corp.com")
    assert storage.get_owner_session(alice, int(time.time()))[0] == ALICE


def test_every_allowlist_check_uses_the_helper():
    """Guard against a new `x in config.allowed_users` check that ignores ALLOWED_DOMAINS
    or skips the hd/email_verified arguments."""
    import pathlib
    import re

    src = pathlib.Path(__file__).parents[1] / "src" / "surfski"
    hits = [(f.name, line.strip()) for f in src.glob("*.py") if f.name != "config.py"
            for line in f.read_text().splitlines() if re.search(r"allowed_users", line)]
    # The only direct use picks the error message after is_allowed already refused.
    assert hits == [("server.py", 'if email not in config.allowed_users and email.rpartition("@")[2] '
                                  "in config.allowed_domains:")]
    text = (src / "server.py").read_text()
    calls = re.findall(r"config\.is_allowed\(([^)]*)\)", text)
    assert len(calls) >= 8 and all("email_verified=" in c and "hd=" in c for c in calls), calls
