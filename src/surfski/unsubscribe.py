"""List-Unsubscribe parsing and the RFC 8058 one-click POST (#17).

Only the message's List-Unsubscribe / List-Unsubscribe-Post headers are used, never
links in the body. The one-click POST is hardened against SSRF: https only, port 443
unless the operator allows another, every resolved address must be public (checked
again on each redirect hop), the connection is pinned to the vetted address (TLS is
still verified against the hostname), no cookies, auth, proxies or env settings, a
fixed User-Agent, a hop limit, a response size limit and an overall deadline."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

import anyio
import httpx

ONE_CLICK_BODY = b"List-Unsubscribe=One-Click"
USER_AGENT = "surfski-unsubscribe/1.0 (+https://github.com/rayhu/surfski)"
MAX_URIS = 10
MAX_URI_CHARS = 2048
MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 64 * 1024
TIMEOUT_SECONDS = 10.0
DEADLINE_SECONDS = 20.0
SUBJECT_MAX = 200
BODY_MAX = 2000
UNSUBSCRIBE_HEADERS = ["List-Unsubscribe", "List-Unsubscribe-Post"]

_URI_RE = re.compile(r"<([^<>]*)>")
_ADDR_RE = re.compile(r"^[^@\s<>(),;:\\\"\[\]]+@[A-Za-z0-9.-]+\.[A-Za-z0-9-]+$")

Resolver = Callable[[str, int], Awaitable[list[str]]]


class UnsubscribeError(Exception):
    """User-facing reason the one-click request was refused or failed (no URL in it)."""


@dataclass
class Found:
    https: list[str] = field(default_factory=list)
    mailto: list[str] = field(default_factory=list)
    http: list[str] = field(default_factory=list)  # never used: RFC 8058 requires https
    one_click: bool = False

    @property
    def method(self) -> str:
        """one_click > mailto > manual (an https page for the user to open) > none."""
        if self.one_click and self.https:
            return "one_click"
        if self.mailto:
            return "mailto"
        if self.https or self.http:
            return "manual"
        return "none"


def parse_headers(headers: list[dict]) -> Found:
    """Every occurrence of List-Unsubscribe (case-insensitive), `<...>` URIs only.
    One-click needs List-Unsubscribe-Post to be exactly `List-Unsubscribe=One-Click`."""
    found = Found()
    seen: set[str] = set()
    for h in headers or []:
        name = (h.get("name") or "").strip().lower()
        value = h.get("value") or ""
        if name == "list-unsubscribe-post":
            if " ".join(value.split()).lower() == "list-unsubscribe=one-click":
                found.one_click = True
        elif name == "list-unsubscribe":
            for raw in _URI_RE.findall(value):
                uri = "".join(raw.split())  # unfold; URIs carry no whitespace
                if not uri or len(uri) > MAX_URI_CHARS or uri in seen or len(seen) >= MAX_URIS:
                    continue
                scheme = uri.split(":", 1)[0].lower()
                bucket = {"https": found.https, "http": found.http, "mailto": found.mailto}.get(scheme)
                if bucket is not None:
                    seen.add(uri)
                    bucket.append(uri)
    return found


def _flatten(text: str, limit: int) -> str:
    return " ".join("".join(" " if ord(c) < 32 or ord(c) == 127 else c for c in text).split())[:limit]


def parse_mailto(uri: str) -> dict:
    """{"to", "subject", "body"} from a mailto URI. Only the single path address is used:
    to/cc/bcc hfields are ignored so a sender can't add recipients. Raises ValueError."""
    if not uri.lower().startswith("mailto:"):
        raise ValueError("not a mailto URI")
    path, _, query = uri[7:].partition("?")
    addrs = [unquote(a).strip() for a in path.split(",") if a.strip()]
    if len(addrs) != 1 or not _ADDR_RE.match(addrs[0]):
        raise ValueError("the mailto unsubscribe address isn't a single valid address")
    params = {k.lower(): v for k, v in parse_qsl(query, keep_blank_values=True)}
    subject = _flatten(params.get("subject", ""), SUBJECT_MAX) or "Unsubscribe"
    body = (params.get("body", "") or "").replace("\r\n", "\n")[:BODY_MAX] or "Unsubscribe"
    return {"to": addrs[0], "subject": subject, "body": body}


# ---------------------------------------------------------------- one-click POST


def check_ip(ip: str) -> None:
    """Refuse anything that isn't a public unicast address: loopback, private, link-local
    (incl. 169.254.169.254 metadata), CGNAT, multicast, reserved, unspecified, and
    IPv4-mapped IPv6 forms of those."""
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        raise UnsubscribeError("the unsubscribe host has an invalid address") from None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if not addr.is_global or addr.is_multicast or addr.is_reserved or addr.is_loopback \
            or addr.is_link_local or addr.is_private or addr.is_unspecified:
        raise UnsubscribeError("the unsubscribe host resolves to a private or internal address; refused")


async def system_resolve(host: str, port: int) -> list[str]:
    infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


async def _vet(url: str, allowed_ports: frozenset[int], resolve: Resolver) -> tuple[httpx.URL, str]:
    """(parsed URL, vetted IP to connect to) or UnsubscribeError."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise UnsubscribeError("only https unsubscribe URLs are used; refused")
    if parts.username or parts.password:
        raise UnsubscribeError("the unsubscribe URL carries credentials; refused")
    try:
        u = httpx.URL(url)
    except Exception:  # noqa: BLE001
        raise UnsubscribeError("the unsubscribe URL is malformed") from None
    host = u.host
    if not host:
        raise UnsubscribeError("the unsubscribe URL has no host")
    port = u.port or 443
    if port != 443 and port not in allowed_ports:
        raise UnsubscribeError(f"port {port} isn't allowed for unsubscribe requests; refused")
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        try:
            ips = await resolve(host, port)
        except (OSError, UnicodeError):
            raise UnsubscribeError("couldn't resolve the unsubscribe host") from None
    if not ips:
        raise UnsubscribeError("couldn't resolve the unsubscribe host")
    for ip in ips:  # every address must be public, not just the first
        check_ip(ip)
    return u, ips[0]


def _pinned(u: httpx.URL, ip: str, method: str, body: bytes | None) -> httpx.Request:
    """A request to the vetted IP that still presents (and verifies TLS against) the hostname."""
    target = u.copy_with(host=ip)
    headers = {"Host": u.netloc.decode("ascii"), "User-Agent": USER_AGENT, "Accept": "*/*",
               "Accept-Encoding": "identity"}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return httpx.Request(method, target, headers=headers, content=body,
                         extensions={"sni_hostname": u.host})


async def one_click_post(
    url: str,
    *,
    allowed_ports: frozenset[int] = frozenset(),
    resolve: Resolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict:
    """POST `List-Unsubscribe=One-Click` (RFC 8058). Returns {"status", "redirects"}.
    Raises UnsubscribeError (no URL in the message) on refusal or failure."""
    resolve = resolve or system_resolve
    method, body, redirects = "POST", ONE_CLICK_BODY, 0
    try:
        with anyio.fail_after(DEADLINE_SECONDS):
            async with httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False,
                                         timeout=TIMEOUT_SECONDS,
                                         limits=httpx.Limits(max_keepalive_connections=0)) as client:
                while True:
                    u, ip = await _vet(url, allowed_ports, resolve)
                    resp = await client.send(_pinned(u, ip, method, body), stream=True)
                    try:
                        read = 0
                        async for chunk in resp.aiter_raw():
                            read += len(chunk)
                            if read > MAX_RESPONSE_BYTES:
                                break  # we never use the body; just stop reading
                    finally:
                        await resp.aclose()
                    client.cookies.clear()  # never carry cookies between hops
                    if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                        if redirects >= MAX_REDIRECTS:
                            raise UnsubscribeError(f"too many redirects (over {MAX_REDIRECTS})")
                        redirects += 1
                        url = urljoin(str(u), resp.headers["location"])
                        if resp.status_code in (301, 302, 303):
                            method, body = "GET", None
                        continue
                    if not 200 <= resp.status_code < 300:
                        raise UnsubscribeError(f"the sender's server answered HTTP {resp.status_code}")
                    return {"status": resp.status_code, "redirects": redirects}
    except TimeoutError:
        raise UnsubscribeError("the unsubscribe request timed out") from None
    except httpx.HTTPError as e:
        raise UnsubscribeError(f"the unsubscribe request failed ({type(e).__name__})") from None
