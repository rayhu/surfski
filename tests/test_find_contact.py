"""find_contact (#18): resolve a person to addresses from the caller's own mail headers.
Gmail is a discovery-validated StrictGmail."""

import time

import pytest
from fastmcp.exceptions import ToolError

import surfski.contacts as cts
from surfski.server import create_app

from .fakes import StrictGmail
from .test_server import ALICE, BOB, call, who  # noqa: F401

DAY_MS = 86_400_000
NOW_MS = int(time.time() * 1000)

SEND_AS = {
    "alice@work.com": [{"sendAsEmail": "alice@work.com", "isPrimary": True},
                       {"sendAsEmail": "Sales@Work.org", "verificationStatus": "accepted"}],
    "alice@gmail.com": [{"sendAsEmail": "alice@gmail.com", "isPrimary": True}],
    "bob@secret.com": [{"sendAsEmail": "bob@secret.com", "isPrimary": True}],
}


def msg(days_ago=1, sent=False, **headers):
    hs = []
    for k, v in headers.items():
        for value in (v if isinstance(v, list) else [v]):
            hs.append({"name": k.replace("_", "-"), "value": value})
    return {"id": f"m{len(hs)}{days_ago}", "internalDate": str(NOW_MS - days_ago * DAY_MS),
            "labelIds": ["SENT"] if sent else ["INBOX"], "payload": {"headers": hs}}


class Box:
    """A mailbox whose threads.list returns `threads` (lists of messages)."""

    def __init__(self, address, threads):
        self.address, self.threads = address, threads
        self.svc = None

    def service(self):
        threads = self.threads

        def tlist(**kw):
            n = kw.get("maxResults", 100)
            return {"threads": [{"id": f"t{i}"} for i in range(min(n, len(threads)))]}

        def tget(**kw):
            assert kw["format"] == "metadata"
            assert kw["metadataHeaders"] == cts.CONTACT_HEADERS
            return {"id": kw["id"], "messages": threads[int(kw["id"][1:])]}

        self.svc = StrictGmail({
            "users.threads.list": tlist,
            "users.threads.get": tget,
            "users.settings.sendAs.list": lambda **kw: {"sendAs": SEND_AS.get(self.address, [])},
        })
        return self.svc


@pytest.fixture
def boxes():
    return {
        "alice@work.com": Box("alice@work.com", [
            [msg(2, From="Alice <alice@work.com>", To="Wang Wei <wei@acme.com>", sent=True),
             msg(1, From="王伟 <wei@acme.com>", To="alice@work.com")],
            [msg(40, From="Wei Chen <chen.wei@other.com>", To=["alice@work.com", "Sales <sales@work.org>"],
                 Cc="wei.noreply@x.com, Weird Al <al@weird.com>")],
            [msg(300, From="no-reply@wei-shop.com", To="alice@work.com")],
        ]),
        "alice@gmail.com": Box("alice@gmail.com", [
            [msg(5, From="Wei <wei@acme.com>", To="alice@gmail.com", Reply_To="Wei W. <wei@acme.com>")],
        ]),
        "bob@secret.com": Box("bob@secret.com", [
            [msg(1, From="Wei Secret <wei@bob-only.com>", To="bob@secret.com")],
        ]),
    }


@pytest.fixture
def app(config, storage, boxes):
    storage.upsert_account(ALICE, "work", "alice@work.com", "rt", "s")
    storage.upsert_account(ALICE, "personal", "alice@gmail.com", "rt", "s")
    storage.upsert_account(BOB, "secret", "bob@secret.com", "rt", "s")
    return create_app(config, storage=storage, with_auth=False,
                      service_factory=lambda o, a: boxes[storage.get_account(o, a).email].service())


async def test_ranking_merge_and_fields(app, who, boxes):
    r = await call(app, "find_contact", name_or_partial="wei")
    contacts = r["contacts"]
    addrs = [c["address"] for c in contacts]
    # wei@acme.com: 3 messages over 2 mailboxes, recent, and Alice wrote to it -> first.
    assert addrs[0] == "wei@acme.com"
    top = contacts[0]
    assert top["count"] == 3 and top["sent_to"] is True
    assert top["mailboxes"] == ["personal", "work"]
    assert set(top["display_names"]) == {"Wang Wei", "王伟", "Wei", "Wei W."}
    assert top["last_seen"].endswith("Z")
    assert set(addrs[1:3]) == {"chen.wei@other.com", "al@weird.com"}  # tie: same message
    assert addrs[1] == "al@weird.com"  # ties break by address
    assert all(c["sent_to"] is False for c in contacts[1:])
    # "Weird Al" matches the substring "wei"; own addresses and no-reply are excluded.
    assert "al@weird.com" in addrs
    for gone in ("alice@work.com", "sales@work.org", "no-reply@wei-shop.com", "wei.noreply@x.com"):
        assert gone not in addrs
    assert r["messages_scanned"] == {"personal": 1, "work": 4}
    assert "wei@bob-only.com" not in addrs  # Bob's mailbox is never searched


async def test_gmail_query_and_bounds(app, who, boxes):
    many = [[msg(i, From=f"Wei {i} <w{i}@acme.com>") for _ in range(6)] for i in range(80)]
    boxes["alice@work.com"].threads = many
    r = await call(app, "find_contact", name_or_partial='Wei "(x)" {y}', aliases=["work"])
    svc = boxes["alice@work.com"].svc
    [lst] = svc.calls_to("users.threads.list")
    assert lst["q"] == 'from:("Wei" "x" "y") OR to:("Wei" "x" "y") OR cc:("Wei" "x" "y")'
    assert lst["maxResults"] == cts.MAX_THREADS
    gets = svc.calls_to("users.threads.get")
    assert len(gets) == cts.MAX_MESSAGES // 6 + 1 <= cts.MAX_THREADS  # stops at the message cap
    assert r["messages_scanned"] == {"work": cts.MAX_MESSAGES}


async def test_term_matching_name_address_cjk_and_word_order(app, who):
    r = await call(app, "find_contact", name_or_partial="王伟")
    assert [c["address"] for c in r["contacts"]] == ["wei@acme.com"]
    r = await call(app, "find_contact", name_or_partial="ＡＣＭＥ")  # fullwidth: NFKC folds it
    assert [c["address"] for c in r["contacts"]] == ["wei@acme.com"]
    r = await call(app, "find_contact", name_or_partial="wang WEI")
    assert r["contacts"][0]["address"] == "wei@acme.com"
    r = await call(app, "find_contact", name_or_partial="chen wei")  # word order doesn't matter
    assert [c["address"] for c in r["contacts"]] == ["chen.wei@other.com"]
    r = await call(app, "find_contact", name_or_partial="nobody-here")
    assert r["contacts"] == []
    with pytest.raises(ToolError, match="give a name"):
        await call(app, "find_contact", name_or_partial=' "() ')


async def test_include_self_and_noreply_flags(app, who):
    r = await call(app, "find_contact", name_or_partial="work", include_self=True, max_results=50)
    addrs = {c["address"] for c in r["contacts"]}
    assert {"alice@work.com", "sales@work.org"} <= addrs
    r = await call(app, "find_contact", name_or_partial="reply", include_noreply=True)
    assert {c["address"] for c in r["contacts"]} == {"no-reply@wei-shop.com", "wei.noreply@x.com"}
    r = await call(app, "find_contact", name_or_partial="reply")
    assert r["contacts"] == []
    # Own addresses stay excluded even when only one mailbox is searched.
    r = await call(app, "find_contact", name_or_partial="alice", aliases=["personal"])
    assert r["contacts"] == []


async def test_max_results(app, who):
    r = await call(app, "find_contact", name_or_partial="w", max_results=2)
    assert len(r["contacts"]) == 2


async def test_owner_isolation(app, who, boxes):
    with pytest.raises(ToolError, match="no linked account 'secret'"):
        await call(app, "find_contact", name_or_partial="wei", aliases=["secret"])
    assert boxes["bob@secret.com"].svc is None  # never touched
    who["claims"] = {"email": BOB}
    r = await call(app, "find_contact", name_or_partial="wei")
    assert [c["address"] for c in r["contacts"]] == ["wei@bob-only.com"]
    assert r["contacts"][0]["mailboxes"] == ["secret"]


async def test_one_failing_mailbox_does_not_fail_the_rest(app, who, boxes):
    def broken():
        raise RuntimeError("boom")

    boxes["alice@gmail.com"].service = broken
    r = await call(app, "find_contact", name_or_partial="wei")
    assert "personal" in r["errors"] and r["contacts"][0]["mailboxes"] == ["work"]


async def test_audit_has_counts_only(app, who, storage):
    await call(app, "find_contact", name_or_partial="王伟")
    rows = [x for x in storage.audit_rows(ALICE) if x["tool"] == "find_contact"]
    assert {x["alias"] for x in rows} == {"work", "personal"}
    for x in rows:
        assert x["detail"].startswith("lookup threads=") and "messages=" in x["detail"]
        for leak in ("王伟", "wei", "acme", "alice"):
            assert leak not in x["detail"].lower()


def test_rank_unit():
    now = NOW_MS / 1000
    acc = {
        "old@x.com": {"address": "old@x.com", "display_names": [], "count": 6,
                      "last_seen_ms": NOW_MS - 900 * DAY_MS, "mailboxes": ["a"], "sent_to": False},
        "new@x.com": {"address": "new@x.com", "display_names": [], "count": 2,
                      "last_seen_ms": NOW_MS - DAY_MS, "mailboxes": ["a"], "sent_to": False},
        "sent@x.com": {"address": "sent@x.com", "display_names": [], "count": 1,
                       "last_seen_ms": NOW_MS - 400 * DAY_MS, "mailboxes": ["a"], "sent_to": True},
    }
    order = [c["address"] for c in cts.rank(acc, exclude=set(), include_noreply=False, max_results=5, now=now)]
    assert order[0] == "new@x.com"  # recent beats an old frequent correspondent
    assert cts.is_noreply("noreply@x.com") and cts.is_noreply("do-not-reply+1@x.com")
    assert cts.is_noreply("MAILER-DAEMON@x.com") and cts.is_noreply("wei.noreply@x.com")
    assert cts.is_noreply("bounces+abc@x.com") and not cts.is_noreply("norah@x.com")
    assert not cts.is_noreply("bouncer@x.com") and not cts.is_noreply("replyall@x.com")


# ---------------------------------------------------------------- #18 review leftovers


@pytest.mark.parametrize("raw,clean,query", [
    ("x OR in:anywhere", "x in anywhere",
     'from:("x" "in" "anywhere") OR to:("x" "in" "anywhere") OR cc:("x" "in" "anywhere")'),
    ("-alice", "alice", 'from:("alice") OR to:("alice") OR cc:("alice")'),
    ("wei chen", "wei chen", 'from:("wei" "chen") OR to:("wei" "chen") OR cc:("wei" "chen")'),
    ("a* AND --b -", "a b", 'from:("a" "b") OR to:("a" "b") OR cc:("a" "b")'),
    ("wei@acme.com", "wei@acme.com",
     'from:("wei@acme.com") OR to:("wei@acme.com") OR cc:("wei@acme.com")'),
])
def test_clean_term_neutralizes_operators(raw, clean, query):
    assert cts.clean_term(raw) == clean
    assert cts.gmail_query(cts.clean_term(raw)) == query


@pytest.mark.parametrize("raw", ["OR", " - AND * ", ": *", "-"])
def test_clean_term_operator_only_is_rejected(raw):
    with pytest.raises(ValueError):
        cts.clean_term(raw)


async def test_operator_terms_do_not_broaden_or_negate(app, who, boxes):
    for term, words in (("x OR in:anywhere", '"x" "in" "anywhere"'), ("-alice", '"alice"')):
        await call(app, "find_contact", name_or_partial=term, aliases=["work"])
        [lst] = boxes["alice@work.com"].svc.calls_to("users.threads.list")
        assert lst["q"] == f"from:({words}) OR to:({words}) OR cc:({words})"
        assert " OR in:" not in lst["q"] and "-" not in lst["q"]


@pytest.mark.parametrize("value,expected", [
    ("a@b.com, , <c@d.com>", ["a@b.com", "c@d.com"]),
    ("Wei <w@x.com> junk, c@d.com", ["w@x.com", "c@d.com"]),  # strict gives up; lenient retry
    ("<a@b.com> <c@d.com>", ["a@b.com", "c@d.com"]),
])
def test_parse_addresses_lenient_retry(value, expected):
    got = [a for _, a in cts.parse_addresses(value) if "@" in a]
    assert got == expected


def test_collect_uses_lenient_retry():
    acc: dict = {}
    m = {"headers": [{"name": "To", "value": "Wei <wei@acme.com> junk, c@d.com"}], "internal_date": 1}
    cts.collect([m], "wei", "work", acc)
    assert "wei@acme.com" in acc
