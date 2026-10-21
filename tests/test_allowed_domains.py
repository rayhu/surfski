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


def test_domain_parsing_and_match(tmp_path):
    c = load_config(make_env(tmp_path, ALLOWED_DOMAINS=" Corp.com , example.org ,"))
    assert c.allowed_domains == {"corp.com", "example.org"}
    assert c.is_allowed("carol@corp.com") and c.is_allowed(" Carol@CORP.com ")
    assert c.is_allowed("alice@example.com")  # ALLOWED_USERS still works
    for bad in ("carol@sub.corp.com", "carol@corp.com.evil.io", "carol@xcorp.com", "corp.com",
                "@corp.com", "", None, "carol@evilcorp.com"):
        assert not c.is_allowed(bad), bad


def test_users_only_or_domains_only(tmp_path):
    c = load_config(make_env(tmp_path, ALLOWED_USERS="", ALLOWED_DOMAINS="corp.com"))
    assert c.allowed_users == frozenset() and c.is_allowed(CAROL) and not c.is_allowed(ALICE)
    c = load_config(make_env(tmp_path))
    assert c.allowed_domains == frozenset() and not c.is_allowed(CAROL)


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


async def test_domain_user_can_use_tools(dconfig, storage, who):
    app = create_app(dconfig, storage=storage, with_auth=False)
    who["claims"] = {"email": "Carol@Corp.com", "email_verified": True}
    assert await call(app, "list_accounts") == []
    for email in ("carol@sub.corp.com", "carol@gmail.com"):
        who["claims"] = {"email": email, "email_verified": True}
        with pytest.raises(ToolError, match="not allowed"):
            await call(app, "list_accounts")


async def test_domain_user_needs_explicit_email_verified(dconfig, storage, who):
    app = create_app(dconfig, storage=storage, with_auth=False)
    for claims in ({"email": CAROL}, {"email": CAROL, "email_verified": False}):
        who["claims"] = claims
        with pytest.raises(ToolError, match="not verified"):
            await call(app, "list_accounts")


# ---------------------------------------------------------------- sending sessions


async def test_domain_user_sending_session_and_pruning(config, storage, boxes, google, who):
    cfg = replace(config, allowed_domains=frozenset({"corp.com"}))
    boxes["carol@corp.com"] = Mailbox("carol@corp.com")
    storage.upsert_account(CAROL, "work", "carol@corp.com", "rt", "s")
    storage.set_send_policy(CAROL, "work", "confirm")
    app = make_app(cfg, storage, boxes, google)
    who["claims"] = {"email": CAROL, "email_verified": True}
    r = await call(app, "send_draft", alias="work", draft_id="d1")
    assert r["status"] == "confirmation_required"
    client = web(app)
    google.email = CAROL
    sign_in(client, google, token_of(r["confirm_url"]))  # /send/auth/callback allows the domain
    resp = client.post("/send/confirm", data={"token": token_of(r["confirm_url"])})
    assert resp.status_code == 200 and "Sent" in resp.text
    assert len(boxes["carol@corp.com"].sent) == 1

    # The domain is removed: startup prunes Carol's sessions, and her links stop working.
    sid = storage.create_owner_session(CAROL, 3600, int(time.time()))
    keep = storage.create_owner_session(ALICE, 3600, int(time.time()))
    create_app(replace(cfg, allowed_domains=frozenset()), storage=storage, with_auth=False)
    assert storage.get_owner_session(sid, int(time.time())) is None
    assert storage.get_owner_session(keep, int(time.time()))[0] == ALICE

    r = await call(app, "send_draft", alias="work", draft_id="d1")
    gone = make_app(replace(cfg, allowed_domains=frozenset()), storage, boxes, google)
    resp = web(gone).post("/send/confirm", data={"token": token_of(r["confirm_url"])})
    assert resp.status_code == 400 and "no longer allowed" in resp.text


async def test_domain_kept_session_survives_startup(dconfig, storage):
    sid = storage.create_owner_session(CAROL, 3600, int(time.time()))
    create_app(dconfig, storage=storage, with_auth=False)
    assert storage.get_owner_session(sid, int(time.time()))[0] == CAROL


def test_every_allowlist_check_uses_the_helper():
    """Guard against a new `x in config.allowed_users` check that ignores ALLOWED_DOMAINS."""
    import pathlib
    import re

    src = pathlib.Path(__file__).parents[1] / "src" / "surfski"
    hits = [(f.name, line.strip()) for f in src.glob("*.py") if f.name != "config.py"
            for line in f.read_text().splitlines() if re.search(r"allowed_users", line)]
    # The only direct use: domain-matched callers must carry email_verified=true.
    assert hits == [("server.py", "if email not in config.allowed_users and not _is_true(verified):")]
    assert (src / "server.py").read_text().count("config.is_allowed(") >= 7
