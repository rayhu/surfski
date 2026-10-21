"""unsubscribe (#17): List-Unsubscribe parsing, the hardened RFC 8058 one-click POST (an
httpx.MockTransport plus a fake resolver, so no real DNS or network), mailto via the
send policy, and the manual-link case. Gmail is a discovery-validated StrictGmail."""

import base64
from dataclasses import replace

import httpx
import pytest
from fastmcp.exceptions import ToolError

import surfski.unsubscribe as unsub
from surfski.server import create_app

from . import test_sending as ts
from .test_server import ALICE, BOB, call, who  # noqa: F401  (fixture re-export)

PUBLIC = "93.184.216.34"
PUBLIC2 = "93.184.216.35"
ONE_CLICK_URL = "https://news.example.com/u/SECRETTOKEN123?list=7"

DNS = {
    "news.example.com": [PUBLIC],
    "other.example.net": [PUBLIC2],
    "loop.example.com": ["127.0.0.1"],
    "ten.example.com": ["10.1.2.3"],
    "meta.example.com": ["169.254.169.254"],
    "v6loop.example.com": ["::1"],
    "mapped.example.com": ["::ffff:127.0.0.1"],
    "cgnat.example.com": ["100.100.100.200"],
    "mixed.example.com": [PUBLIC, "192.168.1.10"],
}


def hdrs(*pairs):
    return [{"name": n, "value": v} for n, v in pairs]


ONE_CLICK = hdrs(
    ("List-Unsubscribe", f"<mailto:leave@lists.example.com?subject=unsub>, <{ONE_CLICK_URL}>"),
    ("List-Unsubscribe-Post", "List-Unsubscribe=One-Click"),
    ("To", "Sales <sales@work.org>"),
)
MAILTO_ONLY = hdrs(
    ("List-Unsubscribe",
     "<mailto:leave@lists.example.com?subject=Remove%20me&body=please%0D%0Aremove&cc=evil@x.com&bcc=spy@x.com>"),
    ("To", "Sales <sales@work.org>"),
)
PAGE_ONLY = hdrs(("List-Unsubscribe", "<https://news.example.com/prefs?id=SECRETTOKEN123>"))
NONE = hdrs(("To", "alice@work.com"))


class Box(ts.Mailbox):
    def __init__(self, address):
        super().__init__(address)
        self.messages = {"m-oc": ONE_CLICK, "m-mailto": MAILTO_ONLY, "m-page": PAGE_ONLY, "m-none": NONE}
        self.svc = None

    def service(self):
        svc = super().service()

        def get(**kw):
            assert kw["format"] == "metadata"  # the body is never fetched
            return {"id": kw["id"], "payload": {"headers": self.messages[kw["id"]]}}

        svc.handlers["users.messages.get"] = get
        self.svc = svc
        return svc


class Body(httpx.AsyncByteStream):
    """A streamed response body (like a real socket), counting what was read."""

    def __init__(self, data: bytes):
        self.data, self.read = data, 0

    async def __aiter__(self):
        for i in range(0, len(self.data), 4096):
            self.read += 4096
            yield self.data[i:i + 4096]


class Net:
    """Fake network: records every request, answers by (host header, path)."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.routes: dict[tuple[str, str], httpx.Response] = {}
        self.default = httpx.Response(200, text="unsubscribed")

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        r = self.routes.get((req.headers["host"], req.url.path), self.default)
        self.last_body = Body(r.content)
        return httpx.Response(r.status_code, headers=r.headers, stream=self.last_body)

    def transport(self):
        return httpx.MockTransport(self.handler)


async def resolver(host, port):
    if host not in DNS:
        raise OSError("NXDOMAIN")
    return DNS[host]


@pytest.fixture
def net():
    return Net()


@pytest.fixture
def boxes():
    return {"alice@work.com": Box("alice@work.com"), "bob@work.com": Box("bob@work.com")}


def make(config, storage, boxes, net, **over):
    def factory(owner, alias):
        return boxes[storage.get_account(owner, alias).email].service()

    return create_app(replace(config, **over), storage=storage, with_auth=False, service_factory=factory,
                      http_factory=ts.Google().factory, unsubscribe_transport=net.transport(),
                      unsubscribe_resolver=resolver)


@pytest.fixture
def app(config, storage, boxes, net):
    storage.upsert_account(ALICE, "work", "alice@work.com", "rt", "s")
    storage.upsert_account(BOB, "secret", "bob@work.com", "rt", "s")
    return make(config, storage, boxes, net, sending_enabled=True)


def audit(storage, owner=ALICE):
    return [r["detail"] for r in storage.audit_rows(owner) if r["tool"] == "unsubscribe"]


def assert_audit_clean(storage):
    for d in audit(storage):
        for leak in ("http", "https", "example", "SECRETTOKEN", "leave@", "mailto:", "@"):
            assert leak not in d, d


def gmail_writes(box):
    return [p for p, _ in box.svc.calls if p != "users.messages.get"] if box.svc else []


# ---------------------------------------------------------------- parsing


def test_parse_multiple_occurrences_and_case():
    f = unsub.parse_headers(hdrs(
        ("list-unsubscribe", "<mailto:a@x.com>"),
        ("LIST-UNSUBSCRIBE", "<https://x.com/u?t=1>,\r\n <https://x.com/u2>"),
        ("List-Unsubscribe-Post", "  List-Unsubscribe=One-Click "),
    ))
    assert f.mailto == ["mailto:a@x.com"] and f.https == ["https://x.com/u?t=1", "https://x.com/u2"]
    assert f.one_click and f.method == "one_click"


@pytest.mark.parametrize("value", [
    "https://x.com/no-brackets",
    "<>, < >, <ftp://x.com/f>, <javascript:alert(1)>",
    "<https://x.com/" + "a" * 3000 + ">",
    "garbage <<<",
])
def test_parse_malformed_ignored(value):
    f = unsub.parse_headers(hdrs(("List-Unsubscribe", value), ("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")))
    assert f.https == [] and f.mailto == [] and f.method == "none"


def test_parse_folded_uri_dedup_and_cap():
    many = ", ".join(f"<https://x.com/{i}>" for i in range(30))
    f = unsub.parse_headers(hdrs(("List-Unsubscribe", "<https://x.com/\r\n a>, <https://x.com/a>, " + many)))
    assert f.https[0] == "https://x.com/a" and len(f.https) == unsub.MAX_URIS


@pytest.mark.parametrize("post,method", [
    ("List-Unsubscribe=One-Click", "one_click"),
    ("list-unsubscribe=one-click", "one_click"),
    ("List-Unsubscribe=One-Click&x=1", "mailto"),
    ("", "mailto"),
])
def test_one_click_needs_exact_post_value(post, method):
    f = unsub.parse_headers(hdrs(("List-Unsubscribe", "<mailto:a@x.com>, <https://x.com/u>"),
                                 ("List-Unsubscribe-Post", post)))
    assert f.method == method


def test_one_click_needs_https():
    f = unsub.parse_headers(hdrs(("List-Unsubscribe", "<http://x.com/u>"),
                                 ("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")))
    assert f.http == ["http://x.com/u"] and f.method == "manual"


def test_parse_mailto():
    m = unsub.parse_mailto("mailto:leave@x.com?Subject=Bye%0D%0ABcc:%20evil@x.com&body=a%0D%0Ab&cc=c@x.com")
    assert m == {"to": "leave@x.com", "subject": "Bye Bcc: evil@x.com", "body": "a\nb"}
    assert unsub.parse_mailto("mailto:leave%40x.com") == {"to": "leave@x.com", "subject": "Unsubscribe",
                                                          "body": "Unsubscribe"}
    for bad in ("mailto:a@x.com,b@x.com", "mailto:", "mailto:not-an-address", "https://x.com"):
        with pytest.raises(ValueError):
            unsub.parse_mailto(bad)


# ---------------------------------------------------------------- preview


@pytest.mark.parametrize("mid,method", [("m-oc", "one_click"), ("m-mailto", "mailto"),
                                        ("m-page", "manual"), ("m-none", "none")])
async def test_preview_changes_nothing(app, who, boxes, net, storage, mid, method):
    r = await call(app, "unsubscribe", alias="work", message_id=mid)
    assert r["status"] == "preview" and r["method"] == method
    assert net.requests == [] and gmail_writes(boxes["alice@work.com"]) == []
    assert audit(storage) == [f"message={mid} preview method={method} outcome=preview"]


# ---------------------------------------------------------------- one-click


async def test_one_click_post(app, who, boxes, net, storage):
    r = await call(app, "unsubscribe", alias="work", message_id="m-oc", confirm=True)
    assert r["status"] == "unsubscribed" and r["method"] == "one_click" and r["http_status"] == 200
    [req] = net.requests
    assert req.method == "POST" and req.content == b"List-Unsubscribe=One-Click"
    assert str(req.url) == f"https://{PUBLIC}/u/SECRETTOKEN123?list=7"  # pinned to the vetted IP
    assert req.headers["host"] == "news.example.com"
    assert req.extensions["sni_hostname"] == "news.example.com"  # TLS still checks the name
    assert req.headers["content-type"] == "application/x-www-form-urlencoded"
    assert req.headers["user-agent"] == unsub.USER_AGENT
    assert "cookie" not in req.headers and "authorization" not in req.headers
    assert gmail_writes(boxes["alice@work.com"]) == []  # no draft for one-click
    assert app.surfski["metrics"]._counters["unsubscribe"] == {("one_click", "ok"): 1}
    assert audit(storage) == ["message=m-oc confirm method=one_click outcome=checked",
                              "message=m-oc method=one_click outcome=ok status=200"]
    assert_audit_clean(storage)


async def test_confirm_rereads_headers(app, who, boxes, net):
    # The preview offered one-click; the message changed since. Confirm uses the fresh headers.
    await call(app, "unsubscribe", alias="work", message_id="m-oc")
    boxes["alice@work.com"].messages["m-oc"] = PAGE_ONLY
    r = await call(app, "unsubscribe", alias="work", message_id="m-oc", confirm=True)
    assert r["status"] == "manual" and net.requests == []


async def test_one_click_failure_is_audited_without_url(app, who, net, storage):
    net.default = httpx.Response(500)
    with pytest.raises(ToolError, match="HTTP 500"):
        await call(app, "unsubscribe", alias="work", message_id="m-oc", confirm=True)
    assert "method=one_click outcome=failed" in audit(storage)[-1]
    assert_audit_clean(storage)


async def test_ssrf_via_tool(app, who, boxes, net, storage):
    boxes["alice@work.com"].messages["m-oc"] = hdrs(
        ("List-Unsubscribe", "<https://meta.example.com/latest/meta-data>"),
        ("List-Unsubscribe-Post", "List-Unsubscribe=One-Click"))
    with pytest.raises(ToolError, match="private or internal"):
        await call(app, "unsubscribe", alias="work", message_id="m-oc", confirm=True)
    assert net.requests == []
    assert_audit_clean(storage)


async def post(net, url, ports=frozenset()):
    return await unsub.one_click_post(url, allowed_ports=ports, resolve=resolver, transport=net.transport())


@pytest.mark.parametrize("url", [
    "https://127.0.0.1/u", "https://[::1]/u", "https://10.0.0.8/u", "https://169.254.169.254/latest",
    "https://[::ffff:127.0.0.1]/u", "https://0.0.0.0/u",
    "https://loop.example.com/u", "https://ten.example.com/u", "https://meta.example.com/u",
    "https://v6loop.example.com/u", "https://mapped.example.com/u", "https://cgnat.example.com/u",
    "https://mixed.example.com/u",  # any private answer refuses, not just the first
])
async def test_ssrf_refused(net, url):
    with pytest.raises(unsub.UnsubscribeError, match="private or internal"):
        await post(net, url)
    assert net.requests == []


@pytest.mark.parametrize("url,match", [
    ("http://news.example.com/u", "only https"),
    ("https://news.example.com:8443/u", "port 8443"),
    ("https://user:pw@news.example.com/u", "credentials"),
    ("https://nxdomain.example.com/u", "resolve"),
])
async def test_refused_urls(net, url, match):
    with pytest.raises(unsub.UnsubscribeError, match=match):
        await post(net, url)
    assert net.requests == []


async def test_allowed_port(net):
    r = await post(net, "https://news.example.com:8443/u", ports=frozenset({8443}))
    assert r["status"] == 200 and net.requests[0].headers["host"] == "news.example.com:8443"


@pytest.mark.parametrize("target", [
    "https://127.0.0.1/x", "https://[::1]/x", "https://10.0.0.1/x", "https://169.254.169.254/x",
    "https://loop.example.com/x", "http://other.example.net/x", "https://other.example.net:8080/x",
])
async def test_redirect_to_internal_or_insecure_refused(net, target):
    net.routes[("news.example.com", "/u")] = httpx.Response(307, headers={"location": target})
    with pytest.raises(unsub.UnsubscribeError):
        await post(net, "https://news.example.com/u")
    assert len(net.requests) == 1  # the refused hop is never requested


async def test_redirects_followed_and_rechecked(net):
    net.routes[("news.example.com", "/u")] = httpx.Response(308, headers={"location": "https://other.example.net/a"})
    net.routes[("other.example.net", "/a")] = httpx.Response(303, headers={"location": "/done"})
    r = await post(net, "https://news.example.com/u")
    assert r == {"status": 200, "redirects": 2}
    a, b, c = net.requests
    assert (a.method, b.method, c.method) == ("POST", "POST", "GET")  # 307/308 keep POST; 303 -> GET
    assert b.content == b"List-Unsubscribe=One-Click" and c.content == b""
    assert str(b.url).startswith(f"https://{PUBLIC2}/") and c.headers["host"] == "other.example.net"


async def test_redirect_limit(net):
    for i in range(10):
        net.routes[("news.example.com", f"/r{i}")] = httpx.Response(302, headers={"location": f"/r{i + 1}"})
    with pytest.raises(unsub.UnsubscribeError, match="too many redirects"):
        await post(net, "https://news.example.com/r0")
    assert len(net.requests) == unsub.MAX_REDIRECTS + 1


async def test_no_cookies_between_hops(net):
    net.routes[("news.example.com", "/u")] = httpx.Response(
        302, headers={"location": "/next", "set-cookie": "sid=abc; Path=/"})
    await post(net, "https://news.example.com/u")
    assert "cookie" not in net.requests[1].headers


async def test_large_response_is_capped(net):
    net.default = httpx.Response(200, content=b"x" * (unsub.MAX_RESPONSE_BYTES * 20))
    assert (await post(net, "https://news.example.com/u"))["status"] == 200
    assert net.last_body.read <= unsub.MAX_RESPONSE_BYTES + 4096  # stopped reading early


async def test_transport_error_message_has_no_url(net):
    def boom(req):
        raise httpx.ConnectError(f"cannot connect to {req.url}")

    with pytest.raises(unsub.UnsubscribeError) as e:
        await unsub.one_click_post("https://news.example.com/u/SECRETTOKEN123", resolve=resolver,
                                   transport=httpx.MockTransport(boom))
    assert "SECRETTOKEN" not in str(e.value) and "ConnectError" in str(e.value)


def test_check_ip_allows_public():
    unsub.check_ip(PUBLIC)
    unsub.check_ip("2606:4700:4700::1111")
    for bad in ("fd00:ec2::254", "fe80::1", "224.0.0.1", "240.0.0.1", "not-an-ip"):
        with pytest.raises(unsub.UnsubscribeError):
            unsub.check_ip(bad)


# ---------------------------------------------------------------- manual / none


async def test_plain_https_is_returned_not_opened(app, who, boxes, net, storage):
    r = await call(app, "unsubscribe", alias="work", message_id="m-page", confirm=True)
    assert r["status"] == "manual" and r["url"] == "https://news.example.com/prefs?id=SECRETTOKEN123"
    assert net.requests == [] and gmail_writes(boxes["alice@work.com"]) == []
    assert audit(storage) == ["message=m-page confirm method=manual outcome=link_returned"]
    assert_audit_clean(storage)


async def test_no_header(app, who, net):
    r = await call(app, "unsubscribe", alias="work", message_id="m-none", confirm=True)
    assert r["status"] == "not_available" and net.requests == []


# ---------------------------------------------------------------- mailto + send policy


def draft_of(box, did="new1"):
    d = box.drafts[did]["message"]["payload"]
    return {h["name"].lower(): h["value"] for h in d["headers"]}, base64.urlsafe_b64decode(
        d["body"]["data"] + "==").decode()


def check_draft(box):
    h, body = draft_of(box)
    assert h["to"] == "leave@lists.example.com" and h["subject"] == "Remove me"
    assert "cc" not in h and "bcc" not in h  # hfields from the sender are ignored
    assert "sales@work.org" in h["from"].lower()  # from the address the list mail went to
    assert body.strip() == "please\nremove"


async def test_mailto_policy_off_keeps_draft(app, who, boxes, net, storage):
    r = await call(app, "unsubscribe", alias="work", message_id="m-mailto", confirm=True)
    box = boxes["alice@work.com"]
    assert r["status"] == "draft_created" and r["sent"] is False and r["draft_id"] == "new1"
    assert box.sent == [] and net.requests == []
    check_draft(box)
    assert audit(storage) == ["message=m-mailto confirm method=mailto outcome=draft_created"]
    assert_audit_clean(storage)


async def test_mailto_sending_disabled_keeps_draft(config, storage, boxes, net, who):
    storage.upsert_account(ALICE, "work", "alice@work.com", "rt", "s")
    storage.set_send_policy(ALICE, "work", "auto")
    app = make(config, storage, boxes, net)  # SENDING_ENABLED off
    r = await call(app, "unsubscribe", alias="work", message_id="m-mailto", confirm=True)
    assert r["status"] == "draft_created" and boxes["alice@work.com"].sent == []


async def test_mailto_policy_auto_sends(app, who, boxes, storage):
    storage.set_send_policy(ALICE, "work", "auto")
    r = await call(app, "unsubscribe", alias="work", message_id="m-mailto", confirm=True)
    box = boxes["alice@work.com"]
    assert r["status"] == "sent" and r["method"] == "mailto"
    assert box.sent == [{"userId": "me", "body": {"id": "new1"}}]
    check_draft(box)
    assert "method=mailto outcome=sent" in audit(storage)[-1]
    assert_audit_clean(storage)


async def test_mailto_policy_confirm_uses_confirm_flow(app, who, boxes, storage):
    storage.set_send_policy(ALICE, "work", "confirm")
    r = await call(app, "unsubscribe", alias="work", message_id="m-mailto", confirm=True)
    assert r["status"] == "confirmation_required" and r["confirm_channel"] == "link"
    assert r["draft_id"] == "new1" and "/send/confirm?token=" in r["confirm_url"]
    assert boxes["alice@work.com"].sent == []
    assert any("method=mailto outcome=pending" in d for d in audit(storage))
    assert_audit_clean(storage)


async def test_mailto_cap_refusal_keeps_draft(config, storage, boxes, net, who):
    storage.upsert_account(ALICE, "work", "alice@work.com", "rt", "s")
    storage.set_send_policy(ALICE, "work", "auto")
    app = make(config, storage, boxes, net, sending_enabled=True,
               allowed_recipient_domains=frozenset({"work.org"}))
    r = await call(app, "unsubscribe", alias="work", message_id="m-mailto", confirm=True)
    assert r["status"] == "draft_created" and "not allowed" in r["instructions"]
    assert boxes["alice@work.com"].sent == []


# ---------------------------------------------------------------- isolation


async def test_owner_isolation(app, who, boxes, net, storage):
    who["claims"] = {"email": BOB}
    for confirm in (False, True):
        with pytest.raises(ToolError, match="no linked account 'work'"):
            await call(app, "unsubscribe", alias="work", message_id="m-oc", confirm=confirm)
    assert boxes["alice@work.com"].svc is None and net.requests == []
    assert audit(storage, ALICE) == [] and audit(storage, BOB) == []
    # Bob's own mailbox works and touches only Bob's Gmail.
    r = await call(app, "unsubscribe", alias="secret", message_id="m-oc")
    assert r["method"] == "one_click" and boxes["alice@work.com"].svc is None



async def test_idn_host_uses_punycode_for_dns_and_sni(net):
    DNS["xn--bcher-kva.example"] = [PUBLIC]
    try:
        r = await post(net, "https://bücher.example/u")
    finally:
        del DNS["xn--bcher-kva.example"]
    assert r["status"] == 200
    [req] = net.requests
    assert req.extensions["sni_hostname"] == "xn--bcher-kva.example"
    assert req.headers["host"] == "xn--bcher-kva.example"


async def test_no_keepalive_pool(net, monkeypatch):
    # Pinned requests share one pool keyed by IP; keep-alive would let a later hop for a
    # different hostname reuse an earlier TLS connection. The client must disable it.
    seen = {}
    real = httpx.AsyncClient

    class Spy(real):
        def __init__(self, *a, **kw):
            seen.update(kw)
            super().__init__(*a, **kw)

    monkeypatch.setattr(unsub.httpx, "AsyncClient", Spy)
    await post(net, "https://news.example.com/u")
    assert seen["limits"].max_keepalive_connections == 0
    assert seen["trust_env"] is False and seen["follow_redirects"] is False
