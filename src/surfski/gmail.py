"""Gmail client factory, message parsing and MIME building.

All functions here are synchronous and meant to run in a worker thread
(anyio.to_thread.run_sync). A fresh service object is built per call because
googleapiclient services are not thread-safe."""

from __future__ import annotations

import base64
import calendar
import io
import mimetypes
import re
import threading
import time
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import formataddr, getaddresses, parseaddr
from html import unescape
from html.parser import HTMLParser
from collections.abc import Callable
from typing import Any

from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload

TOKEN_URI = "https://oauth2.googleapis.com/token"
SUMMARY_HEADERS = ["Subject", "From", "Date"]


class GmailError(Exception):
    """User-facing Gmail failure."""


# ---------------------------------------------------------------- credentials


class AccessTokenCache:
    """In-memory only access-token cache, keyed by (owner, alias)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: dict[tuple[str, str], tuple[str, float]] = {}

    def get(self, owner: str, alias: str) -> str | None:
        with self._lock:
            item = self._data.get((owner, alias))
        if item and item[1] - 60 > time.time():
            return item[0]
        return None

    def put(self, owner: str, alias: str, token: str, expiry_ts: float) -> None:
        with self._lock:
            self._data[(owner, alias)] = (token, expiry_ts)

    def drop(self, owner: str, alias: str) -> None:
        with self._lock:
            self._data.pop((owner, alias), None)

    def drop_owner(self, owner: str) -> None:
        with self._lock:
            for key in [k for k in self._data if k[0] == owner]:
                del self._data[key]


def build_service(
    *,
    refresh_token: str,
    client_id: str,
    client_secret: str,
    scopes: list[str],
    cache: AccessTokenCache,
    owner: str,
    alias: str,
):
    creds = Credentials(
        token=cache.get(owner, alias),
        refresh_token=refresh_token,
        token_uri=TOKEN_URI,
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
    )
    if not creds.token:
        from google.auth.transport.requests import Request

        creds.refresh(Request())
        # creds.expiry is a naive UTC datetime
        expiry = (
            calendar.timegm(creds.expiry.utctimetuple()) if creds.expiry else time.time() + 3000
        )
        cache.put(owner, alias, creds.token, expiry)
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def map_google_error(exc: Exception, alias: str) -> GmailError:
    if isinstance(exc, RefreshError):
        if "invalid_grant" in str(exc):
            return GmailError(
                f"account '{alias}' needs relinking: call relink_account('{alias}')"
            )
        return GmailError(f"could not refresh access for '{alias}'; try relink_account('{alias}')")
    if isinstance(exc, HttpError):
        status = getattr(exc.resp, "status", None)
        if status == 404:
            return GmailError("not found (check the id belongs to this account)")
        if status in (401,):
            return GmailError(f"account '{alias}' needs relinking: call relink_account('{alias}')")
        if status == 403:
            return GmailError(
                f"Google denied access for '{alias}' (permission or Workspace policy). "
                f"Try relink_account('{alias}')."
            )
        if status == 429:
            return GmailError("Gmail rate limit hit; try again shortly")
        if status == 400:
            return GmailError("Gmail rejected the request (bad query or id)")
        return GmailError(f"Gmail API error ({status})")
    if isinstance(exc, GmailError):
        return exc
    return GmailError(f"unexpected error talking to Gmail: {type(exc).__name__}")


# ---------------------------------------------------------------- parsing


class _HTMLToText(HTMLParser):
    BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote"}
    SKIP = {"script", "style", "head", "title"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    p = _HTMLToText()
    try:
        p.feed(html)
        p.close()
        text = "".join(p.parts)
    except Exception:  # noqa: BLE001
        text = unescape(re.sub(r"<[^>]+>", " ", html))
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _decode_b64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _charset(part: dict) -> str:
    for h in part.get("headers", []) or []:
        if h.get("name", "").lower() == "content-type":
            m = re.search(r'charset="?([\w.-]+)"?', h.get("value", ""), re.I)
            if m:
                return m.group(1)
    return "utf-8"


def _decode_part(part: dict) -> str:
    data = (part.get("body") or {}).get("data")
    if not data:
        return ""
    raw = _decode_b64(data)
    try:
        return raw.decode(_charset(part), errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _walk(part: dict):
    """Depth-first over MIME parts, without descending into attached messages
    (message/*): an attached email is one attachment, not more body text."""
    yield part
    if (part.get("mimeType") or "").lower().startswith("message/"):
        return
    for sub in part.get("parts", []) or []:
        yield from _walk(sub)


def extract_body(payload: dict) -> str:
    plain, html = [], []
    for part in _walk(payload):
        mime = (part.get("mimeType") or "").lower()
        if _is_attachment(part):
            continue
        if mime == "text/plain":
            plain.append(_decode_part(part))
        elif mime == "text/html":
            html.append(_decode_part(part))
    if any(p.strip() for p in plain):
        return "\n".join(plain).strip()
    if html:
        return html_to_text("\n".join(html))
    return ""


def _is_attachment(part: dict) -> bool:
    """A named part, or a non-text leaf that is inline (Content-ID) or stored
    out-of-line (body.attachmentId), e.g. an embedded image."""
    if part.get("filename"):
        return True
    mime = (part.get("mimeType") or "").lower()
    if mime.startswith("message/"):
        return True
    if not mime or mime.startswith(("text/", "multipart/")):
        return False
    has_cid = any(h.get("name", "").lower() == "content-id" for h in part.get("headers", []) or [])
    return has_cid or bool((part.get("body") or {}).get("attachmentId"))


def extract_attachments(payload: dict) -> list[dict]:
    out = []
    for part in _walk(payload):
        if _is_attachment(part):
            out.append(
                {
                    "filename": part.get("filename") or "",
                    "mime_type": part.get("mimeType"),
                    "size": (part.get("body") or {}).get("size", 0),
                    # part_id is stable; Gmail may issue a new attachmentId per fetch.
                    "part_id": part.get("partId"),
                    "attachment_id": (part.get("body") or {}).get("attachmentId"),
                }
            )
    return out


def headers_map(payload: dict) -> dict[str, str]:
    """Case-insensitive header lookup (first occurrence wins). Gmail returns
    already-decoded header values (RFC 2047 encoded words are decoded)."""
    out: dict[str, str] = {}
    for h in payload.get("headers", []) or []:
        out.setdefault(h.get("name", "").lower(), h.get("value", ""))
    return out


def truncate(text: str, limit: int) -> tuple[str, bool]:
    if limit and len(text) > limit:
        return text[:limit] + "\n…[truncated]", True
    return text, False


def parse_message(msg: dict, max_body_chars: int) -> dict:
    payload = msg.get("payload") or {}
    h = headers_map(payload)
    body, truncated = truncate(extract_body(payload), max_body_chars)
    return {
        "id": msg.get("id"),
        "thread_id": msg.get("threadId"),
        "from": h.get("from", ""),
        "to": h.get("to", ""),
        "cc": h.get("cc", ""),
        "date": h.get("date", ""),
        "subject": h.get("subject", ""),
        "label_ids": msg.get("labelIds", []),
        "body": body,
        "body_truncated": truncated,
        "attachments": extract_attachments(payload),
    }


def summarize_thread(thread: dict) -> dict:
    msgs = thread.get("messages", []) or []
    first = (msgs[0].get("payload") if msgs else {}) or {}
    last = msgs[-1] if msgs else {}
    h = headers_map(first)
    lh = headers_map(last.get("payload") or {})
    labels: set[str] = set()
    for m in msgs:
        labels.update(m.get("labelIds", []) or [])
    return {
        "id": thread.get("id"),
        "subject": h.get("subject", ""),
        "from": h.get("from", ""),
        "date": lh.get("date", h.get("date", "")),
        # Gmail returns snippets HTML-escaped (e.g. "&#39;").
        "snippet": unescape(last.get("snippet") or thread.get("snippet", "")),
        "label_ids": sorted(labels),
        "message_count": len(msgs),
    }


# ---------------------------------------------------------------- MIME


def reply_subject(subject: str) -> str:
    subject = (subject or "").strip()
    if re.match(r"^\s*(re|回复|答复)\s*[:：]", subject, re.I):
        return subject
    return f"Re: {subject}" if subject else "Re:"


def _addr_list(value: str | None) -> str | None:
    if not value:
        return None
    pairs = getaddresses([value])
    cleaned = [formataddr((n, a)) for n, a in pairs if a]
    return ", ".join(cleaned) if cleaned else None


def _reject_line_breaks(**fields: str | None) -> None:
    for name, value in fields.items():
        if value and ("\r" in value or "\n" in value):
            raise GmailError(f"'{name}' must not contain line breaks")


def build_mime(
    *,
    from_addr: str,
    to: str,
    subject: str,
    body: str,
    cc: str | None = None,
    bcc: str | None = None,
    in_reply_to: str | None = None,
    references: str | None = None,
) -> EmailMessage:
    _reject_line_breaks(**{"from": from_addr}, to=to, subject=subject, cc=cc, bcc=bcc)
    m = EmailMessage()
    m["From"] = from_addr
    to_v = _addr_list(to)
    if not to_v:
        raise GmailError("'to' must contain at least one email address")
    m["To"] = to_v
    if (v := _addr_list(cc)):
        m["Cc"] = v
    if (v := _addr_list(bcc)):
        m["Bcc"] = v
    m["Subject"] = subject
    if in_reply_to:
        m["In-Reply-To"] = in_reply_to
    if references:
        m["References"] = references
    m.set_content(body, subtype="plain", charset="utf-8")
    return m


def encode_raw(m: EmailMessage) -> str:
    return base64.urlsafe_b64encode(m.as_bytes()).decode()


def reply_headers(original: dict) -> dict:
    """Given a Gmail message (format=metadata/full), compute reply threading fields."""
    h = headers_map(original.get("payload") or {})
    mid = h.get("message-id", "")
    refs = h.get("references", "")
    references = f"{refs} {mid}".strip() if mid else refs
    return {
        "thread_id": original.get("threadId"),
        "in_reply_to": mid or None,
        "references": references or None,
        "subject": reply_subject(h.get("subject", "")),
    }


# ---------------------------------------------------------------- send-as identities


def is_verified(identity: dict) -> bool:
    """Gmail accepts a From only for the primary address or an accepted custom alias
    (verificationStatus only applies to custom "from" aliases)."""
    return bool(identity.get("is_primary")) or identity.get("verification_status") == "accepted"


def op_list_send_as(svc) -> list[dict]:
    resp = svc.users().settings().sendAs().list(userId="me").execute()
    out = []
    for i in resp.get("sendAs", []) or []:
        out.append(
            {
                "address": (i.get("sendAsEmail") or "").lower(),
                "display_name": i.get("displayName") or "",
                "is_default": bool(i.get("isDefault")),
                "is_primary": bool(i.get("isPrimary")),
                "verification_status": i.get("verificationStatus")
                or ("accepted" if i.get("isPrimary") else None),
                "signature": i.get("signature") or "",
            }
        )
    return [i for i in out if i["address"]]


def public_identity(identity: dict, labels: dict[str, str]) -> dict:
    by_addr = {a: l for l, a in labels.items()}
    return {
        "address": identity["address"],
        "display_name": identity["display_name"],
        "label": by_addr.get(identity["address"]),
        "is_default": identity["is_default"],
        "is_primary": identity["is_primary"],
        "verification_status": identity["verification_status"],
        "verified": is_verified(identity),
        "has_signature": bool(identity.get("signature")),
    }


def _choices(identities: list[dict], labels: dict[str, str]) -> str:
    by_addr = {a: l for l, a in labels.items()}
    items = [
        f"{i['address']} (label '{by_addr[i['address']]}')" if i["address"] in by_addr else i["address"]
        for i in identities
        if is_verified(i)
    ]
    return ", ".join(items) or "none"


def match_identity(identities: list[dict], requested: str, labels: dict[str, str]) -> tuple[dict, str]:
    """Resolve an address or label to a verified identity. Returns (identity, source)."""
    req = (requested or "").strip().lower()
    _, addr = parseaddr(req)
    source = "explicit"
    if "@" not in req:
        source = "label"
        addr = labels.get(req, "")
    for i in identities:
        if addr and i["address"] == addr.lower():
            if is_verified(i):
                return i, source
            raise GmailError(
                f"{addr} is not verified for sending (status: {i['verification_status']}). "
                f"Valid choices: {_choices(identities, labels)}"
            )
    what = f"label '{req}'" if source == "label" else f"'{requested}'"
    raise GmailError(
        f"{what} is not a send-as address of this mailbox. Valid choices: {_choices(identities, labels)}. "
        "New addresses are added in Gmail → Settings → Accounts → Send mail as."
    )


def recipient_addresses(headers: dict[str, str]) -> list[str]:
    """Addresses a message was sent to: To, then Cc, then Delivered-To."""
    vals = [headers.get(k, "") for k in ("to", "cc", "delivered-to")]
    return [a.lower() for _, a in getaddresses([v for v in vals if v]) if a]


def resolve_identity(
    identities: list[dict],
    *,
    requested: str | None,
    labels: dict[str, str],
    default_from: str | None,
    reply_recipients: list[str],
    account_email: str,
) -> tuple[dict, str]:
    """explicit/label → original recipient (replies) → stored default → Gmail default
    → account email. Returns (identity, source)."""
    if requested:
        return match_identity(identities, requested, labels)
    verified = {i["address"]: i for i in identities if is_verified(i)}
    for a in reply_recipients:
        if a in verified:
            return verified[a], "reply"
    if default_from and default_from.lower() in verified:
        return verified[default_from.lower()], "stored_default"
    for i in verified.values():
        if i["is_default"]:
            return i, "gmail_default"
    account_email = account_email.lower()
    return verified.get(account_email) or {
        "address": account_email, "display_name": "", "signature": "",
        "is_default": False, "is_primary": True, "verification_status": "accepted",
    }, "account"


def from_header(identity: dict) -> str:
    """Formatted From value; the email policy RFC 2047-encodes non-ASCII names."""
    name = identity.get("display_name") or ""
    if "\r" in name or "\n" in name:
        name = ""
    return str(Address(display_name=name, addr_spec=identity["address"]))


def signature_text(identity: dict) -> str:
    return html_to_text(identity.get("signature") or "")


def strip_signature(body: str, candidates: list[dict]) -> tuple[str, bool]:
    """Remove one trailing '-- \n<signature>' block whose signature belongs to one of
    the candidate identities (checked in order). Returns (body, stripped)."""
    trimmed = body.rstrip()
    for ident in candidates:
        sig = signature_text(ident)
        if not sig:
            continue
        block = f"-- \n{sig}"
        if trimmed == block:
            return "", True
        if trimmed.endswith("\n" + block):
            return trimmed[: -len(block)].rstrip(), True
    return body, False


def append_signature(body: str, identity: dict) -> str:
    """Append the identity's signature unless the body already ends with exactly
    that signature block."""
    sig = signature_text(identity)
    if not sig:
        return body
    trimmed = body.rstrip()
    block = f"-- \n{sig}"
    if trimmed == block or trimmed.endswith("\n" + block):
        return body
    return f"{trimmed}\n\n{block}" if trimmed else block


# ---------------------------------------------------------------- operations


def op_search_threads(svc, query: str, max_results: int, page_token: str | None) -> dict:
    users = svc.users()
    kwargs: dict[str, Any] = {"userId": "me", "q": query, "maxResults": max_results}
    if page_token:
        kwargs["pageToken"] = page_token
    resp = users.threads().list(**kwargs).execute()
    threads = []
    for t in resp.get("threads", []) or []:
        full = (
            users.threads()
            .get(userId="me", id=t["id"], format="metadata", metadataHeaders=SUMMARY_HEADERS)
            .execute()
        )
        threads.append(summarize_thread(full))
    return {"threads": threads, "next_page_token": resp.get("nextPageToken")}


def op_get_thread(svc, thread_id: str, max_body_chars: int) -> dict:
    t = svc.users().threads().get(userId="me", id=thread_id, format="full").execute()
    return {
        "id": t.get("id"),
        "messages": [parse_message(m, max_body_chars) for m in t.get("messages", []) or []],
    }


def op_get_message(svc, message_id: str, max_body_chars: int) -> dict:
    m = svc.users().messages().get(userId="me", id=message_id, format="full").execute()
    return parse_message(m, max_body_chars)


UNSUBSCRIBE_METADATA = ["List-Unsubscribe", "List-Unsubscribe-Post", "To", "Cc", "Delivered-To"]


def op_unsubscribe_headers(svc, message_id: str) -> list[dict]:
    """The headers unsubscribe (#17) needs, every occurrence. Metadata format: the body is
    never fetched, so links in it can't be followed."""
    m = svc.users().messages().get(userId="me", id=message_id, format="metadata",
                                   metadataHeaders=UNSUBSCRIBE_METADATA).execute()
    return (m.get("payload") or {}).get("headers") or []


def op_list_labels(svc) -> list[dict]:
    resp = svc.users().labels().list(userId="me").execute()
    return [
        {"id": l.get("id"), "name": l.get("name"), "type": l.get("type")}
        for l in resp.get("labels", []) or []
    ]


def op_create_draft(
    svc,
    *,
    choose_from: Callable[[list[str]], tuple[dict, str]],
    to: str,
    subject: str,
    body: str,
    cc: str | None,
    bcc: str | None,
    reply_to_message_id: str | None,
    include_signature: bool = False,
) -> dict:
    """choose_from(reply_recipient_addresses) picks the sending identity."""
    users = svc.users()
    thread_id = in_reply_to = references = None
    recipients: list[str] = []
    if reply_to_message_id:
        orig = (
            users.messages()
            .get(
                userId="me",
                id=reply_to_message_id,
                format="metadata",
                metadataHeaders=["Subject", "Message-ID", "References", "To", "Cc", "Delivered-To"],
            )
            .execute()
        )
        rh = reply_headers(orig)
        recipients = recipient_addresses(headers_map(orig.get("payload") or {}))
        thread_id, in_reply_to, references = rh["thread_id"], rh["in_reply_to"], rh["references"]
        subject = reply_subject(subject or rh["subject"])
    identity, source = choose_from(recipients)
    if include_signature:
        body = append_signature(body, identity)
    mime = build_mime(
        from_addr=from_header(identity),
        to=to,
        subject=subject,
        body=body,
        cc=cc,
        bcc=bcc,
        in_reply_to=in_reply_to,
        references=references,
    )
    message: dict[str, Any] = {"raw": encode_raw(mime)}
    if thread_id:
        message["threadId"] = thread_id
    draft = users.drafts().create(userId="me", body={"message": message}).execute()
    return {
        "draft_id": draft.get("id"),
        "thread_id": thread_id,
        "from": identity["address"],
        "from_source": source,
    }


def op_list_drafts(svc, max_results: int, page_token: str | None) -> dict:
    drafts = svc.users().drafts()
    kwargs: dict[str, Any] = {"userId": "me", "maxResults": max_results}
    if page_token:
        kwargs["pageToken"] = page_token
    resp = drafts.list(**kwargs).execute()
    out = []
    for d in resp.get("drafts", []) or []:
        full = (
            # drafts.get takes no metadataHeaders; format=metadata returns all headers.
            drafts.get(userId="me", id=d["id"], format="metadata").execute()
        )
        msg = full.get("message") or {}
        h = headers_map(msg.get("payload") or {})
        out.append(
            {
                "draft_id": full.get("id", d["id"]),
                "message_id": msg.get("id"),
                "thread_id": msg.get("threadId"),
                "subject": h.get("subject", ""),
                "to": h.get("to", ""),
                "date": h.get("date", ""),
                # Gmail returns snippets HTML-escaped (e.g. "&#39;").
                "snippet": unescape(msg.get("snippet") or ""),
            }
        )
    return {"drafts": out, "next_page_token": resp.get("nextPageToken")}


def op_get_draft(svc, draft_id: str, max_body_chars: int) -> dict:
    d = svc.users().drafts().get(userId="me", id=draft_id, format="full").execute()
    return {"draft_id": d.get("id", draft_id), **parse_message(d.get("message") or {}, max_body_chars)}


def op_update_draft(
    svc,
    *,
    draft_id: str,
    default_from: str,
    choose_from: Callable[[str], tuple[dict, str] | None] | None = None,
    include_signature: bool = False,
    known_identities: list[dict] | None = None,
    to: str | None,
    subject: str | None,
    body: str | None,
    cc: str | None,
    bcc: str | None,
) -> dict:
    """Rebuild a draft's MIME. None keeps the current value; "" clears cc/bcc.
    threadId, In-Reply-To and References are always preserved. From is kept unless
    choose_from(current_from_address) returns an identity."""
    drafts = svc.users().drafts()
    current = drafts.get(userId="me", id=draft_id, format="full").execute()
    msg = current.get("message") or {}
    payload = msg.get("payload") or {}
    if extract_attachments(payload):
        raise GmailError(
            "this draft has attachments, which update_draft would drop; edit it in Gmail instead"
        )
    parts = list(_walk(payload))
    if body is None and any(
        (p.get("mimeType") or "").lower().startswith("text/")
        and (p.get("body") or {}).get("attachmentId")
        and not (p.get("body") or {}).get("data")
        for p in parts
    ):
        raise GmailError("this draft's body is too large to read back; pass 'body' to replace it")
    flattened_html = any((p.get("mimeType") or "").lower() == "text/html" for p in parts)
    h = headers_map(payload)
    _reject_line_breaks(to=to, subject=subject, cc=cc, bcc=bcc)
    if to is not None and not _addr_list(to):
        raise GmailError("'to' can't be empty; omit it to keep the current recipients")
    new_to = h.get("to", "") if to is None else to
    if not _addr_list(new_to):
        raise GmailError("the draft has no recipients; pass 'to'")
    from_value = h.get("from") or default_from
    prev_addr = parseaddr(from_value)[1].lower()
    chosen = choose_from(prev_addr) if choose_from else None
    new_body = (extract_body(payload) if body is None else body).replace("\r\n", "\n")
    signature_replaced: bool | None = None
    if chosen:
        from_value = from_header(chosen[0])
        if chosen[0]["address"] != prev_addr or include_signature:
            # Drop the previous identity's signature block (or, failing that, any known
            # identity's) so a sender switch doesn't leave the old signature behind.
            known = known_identities or []
            prev = [i for i in known if i["address"] == prev_addr]
            new_body, stripped = strip_signature(new_body, prev + known)
            if chosen[0]["address"] != prev_addr:
                if stripped:
                    signature_replaced = True
                elif prev and signature_text(prev[0]):
                    # The old sender has a signature but its block wasn't found.
                    signature_replaced = False
        if include_signature:
            new_body = append_signature(new_body, chosen[0])
    mime = build_mime(
        from_addr=from_value,
        to=new_to,
        subject=h.get("subject", "") if subject is None else subject,
        body=new_body,
        cc=h.get("cc") if cc is None else cc,
        bcc=h.get("bcc") if bcc is None else bcc,
        in_reply_to=h.get("in-reply-to") or None,
        references=h.get("references") or None,
    )
    message: dict[str, Any] = {"raw": encode_raw(mime)}
    if msg.get("threadId"):
        # Without threadId Gmail silently detaches the draft from its thread.
        message["threadId"] = msg["threadId"]
    updated = drafts.update(userId="me", id=draft_id, body={"id": draft_id, "message": message}).execute()
    out: dict[str, Any] = {"draft_id": updated.get("id", draft_id)}
    if chosen:
        out["from"], out["from_source"] = chosen[0]["address"], chosen[1]
    if signature_replaced is not None:
        out["signature_replaced"] = signature_replaced
    if flattened_html:
        out["flattened_html"] = True
    return out


FORWARD_MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024
# Above this encoded size the draft is uploaded as message/rfc822 media instead of
# a JSON 'raw' field (Gmail recommends media upload for messages over ~5 MB).
RAW_JSON_LIMIT = 4 * 1024 * 1024


def forward_subject(subject: str) -> str:
    subject = (subject or "").strip()
    if re.match(r"^\s*(fwd?|转发)\s*[:：]", subject, re.I):
        return subject
    return f"Fwd: {subject}" if subject else "Fwd:"


def forward_header_block(h: dict[str, str]) -> str:
    lines = ["---------- Forwarded message ---------"]
    for name in ("From", "Date", "Subject", "To", "Cc"):
        value = h.get(name.lower(), "")
        if value or name != "Cc":
            lines.append(f"{name}: {value}")
    return "\n".join(lines)


def _mb(n: int) -> str:
    return f"{n / (1024 * 1024):.1f} MB"


def _attachment_name(part: dict, index: int) -> str:
    name = re.sub(r"[\r\n]+", " ", part.get("filename") or "").strip()
    if name:
        return name
    mime = (part.get("mimeType") or "").lower()
    if mime.startswith("message/"):
        return f"attached-message-{index}.eml"
    ext = mimetypes.guess_extension(mime) or ".bin"
    return f"inline-{index}{ext}"


def op_forward_message(
    svc,
    *,
    message_id: str,
    choose_from: Callable[[list[str]], tuple[dict, str]],
    to: str,
    note: str | None,
    cc: str | None,
    bcc: str | None,
    include_signature: bool = False,
    max_attachment_bytes: int = FORWARD_MAX_ATTACHMENT_BYTES,
) -> dict:
    """Save a forward of message_id as a new draft (new thread), re-attaching the
    original's attachments."""
    users = svc.users()
    orig = users.messages().get(userId="me", id=message_id, format="full").execute()
    payload = orig.get("payload") or {}
    h = headers_map(payload)
    parts = [p for p in _walk(payload) if _is_attachment(p)]
    sizes = [(_attachment_name(p, i), int((p.get("body") or {}).get("size") or 0)) for i, p in enumerate(parts, 1)]
    total = sum(n for _, n in sizes)
    if total > max_attachment_bytes:
        listing = ", ".join(f"{name} ({_mb(n)})" for name, n in sizes)
        raise GmailError(
            f"attachments total {_mb(total)}, over the {_mb(max_attachment_bytes)} forward limit: "
            f"{listing}. Forward it from Gmail instead."
        )

    identity, source = choose_from(recipient_addresses(h))
    intro = (note or "").strip()
    if include_signature:
        intro = append_signature(intro, identity)
    original_body = extract_body(payload).replace("\r\n", "\n")
    text = "\n\n".join(x for x in (intro, forward_header_block(h), original_body) if x)

    mime = build_mime(
        from_addr=from_header(identity),
        to=to,
        subject=forward_subject(h.get("subject", "")),
        body=text,
        cc=cc,
        bcc=bcc,
    )
    attached, skipped = [], []
    for (name, _), part in zip(sizes, parts):
        pbody = part.get("body") or {}
        data = pbody.get("data")
        if not data and pbody.get("attachmentId"):
            data = (
                users.messages().attachments()
                .get(userId="me", messageId=message_id, id=pbody["attachmentId"])
                .execute()
                .get("data")
            )
        if not data:
            skipped.append({"filename": name, "reason": "no content available"})
            continue
        mime_type = (part.get("mimeType") or "application/octet-stream").lower()
        maintype, _, subtype = mime_type.partition("/")
        # An attached email goes out as an opaque .eml (octet-stream): the email
        # package is strict about transfer encodings inside message/rfc822.
        if maintype in ("multipart", "message") or not subtype:
            maintype, subtype = "application", "octet-stream"
        mime.add_attachment(_decode_b64(data), maintype=maintype, subtype=subtype, filename=name)
        attached.append(name)

    raw_bytes = mime.as_bytes()
    drafts = users.drafts()
    if len(raw_bytes) * 4 // 3 > RAW_JSON_LIMIT:
        media = MediaIoBaseUpload(io.BytesIO(raw_bytes), mimetype="message/rfc822", resumable=True)
        draft = drafts.create(userId="me", body={"message": {}}, media_body=media).execute()
    else:
        raw = base64.urlsafe_b64encode(raw_bytes).decode()
        draft = drafts.create(userId="me", body={"message": {"raw": raw}}).execute()
    out: dict[str, Any] = {
        "draft_id": draft.get("id"),
        "from": identity["address"],
        "from_source": source,
        "attachments": attached,
    }
    if skipped:
        out["skipped"] = skipped
    return out


def op_draft_for_send(svc, draft_id: str) -> dict:
    """Everything a send decision needs about a draft (format=full)."""
    d = svc.users().drafts().get(userId="me", id=draft_id, format="full").execute()
    msg = d.get("message") or {}
    payload = msg.get("payload") or {}
    return {
        "draft_id": d.get("id", draft_id),
        "message_id": msg.get("id"),
        "thread_id": msg.get("threadId"),
        "headers": headers_map(payload),
        "raw_headers": payload.get("headers", []) or [],
        "body": extract_body(payload),
        "attachments": [a["filename"] or a["mime_type"] for a in extract_attachments(payload)],
    }


def op_draft_message_id(svc, draft_id: str) -> str | None:
    d = svc.users().drafts().get(userId="me", id=draft_id, format="minimal").execute()
    return (d.get("message") or {}).get("id")


def op_send_draft(svc, draft_id: str) -> dict:
    sent = svc.users().drafts().send(userId="me", body={"id": draft_id}).execute()
    return {"message_id": sent.get("id"), "thread_id": sent.get("threadId")}


def find_attachment(payload: dict, ref: str) -> dict:
    """Resolve an attachment part by attachmentId, partId or exact filename."""
    parts = [p for p in _walk(payload) if _is_attachment(p)]
    ref = (ref or "").strip()
    for key in (lambda p: (p.get("body") or {}).get("attachmentId"), lambda p: p.get("partId")):
        hit = [p for p in parts if ref and key(p) == ref]
        if hit:
            return hit[0]
    by_name = [p for p in parts if (p.get("filename") or "") == ref]
    if not by_name:
        by_name = [p for p in parts if (p.get("filename") or "").lower() == ref.lower() and ref]
    if len(by_name) == 1:
        return by_name[0]
    listing = "; ".join(
        f"{p.get('filename') or '(unnamed)'} [part_id {p.get('partId')}, {p.get('mimeType')}, "
        f"{(p.get('body') or {}).get('size', 0)} bytes]"
        for p in (by_name or parts)
    )
    if by_name:
        raise GmailError(f"{len(by_name)} attachments are named '{ref}'; pass a part_id instead: {listing}")
    raise GmailError(f"no attachment '{ref}' in this message. Attachments: {listing or 'none'}")


def op_get_attachment_bytes(svc, message_id: str, ref: str, max_bytes: int) -> tuple[dict, bytes]:
    """(part metadata, raw bytes). The size limit is checked from body.size before
    anything is downloaded."""
    users = svc.users()
    msg = users.messages().get(userId="me", id=message_id, format="full").execute()
    part = find_attachment(msg.get("payload") or {}, ref)
    body = part.get("body") or {}
    size = int(body.get("size") or 0)
    name = part.get("filename") or ""
    meta = {"filename": name, "mime_type": part.get("mimeType") or "", "size": size,
            "part_id": part.get("partId"), "charset": _charset(part) if part.get("headers") else None}
    if size > max_bytes:
        raise GmailError(
            f"attachment is {size / (1024 * 1024):.1f} MB, over this server's "
            f"{max_bytes / (1024 * 1024):.0f} MB limit; open it in Gmail instead"
        )
    data = body.get("data")
    if not data and body.get("attachmentId"):
        data = (
            users.messages().attachments()
            .get(userId="me", messageId=message_id, id=body["attachmentId"])
            .execute()
            .get("data")
        )
    raw = _decode_b64(data or "")
    if len(raw) > max_bytes:  # body.size was wrong
        raise GmailError("attachment is over this server's size limit; open it in Gmail instead")
    return meta, raw


def op_delete_draft(svc, draft_id: str) -> dict:
    svc.users().drafts().delete(userId="me", id=draft_id).execute()
    return {"ok": True}


def gmail_drafts_url(email: str) -> str:
    return f"https://mail.google.com/mail/u/{parseaddr(email)[1] or email}/#drafts"


def op_contact_messages(svc, query: str, max_threads: int, max_messages: int,
                        headers: list[str]) -> dict:
    """Header metadata of recent messages matching `query` (#18): at most `max_threads`
    threads.get calls and `max_messages` messages. Returns {"messages": [...],
    "threads": n} with each message as {"headers", "internal_date", "sent"}."""
    users = svc.users()
    resp = users.threads().list(userId="me", q=query, maxResults=max_threads).execute()
    out: list[dict] = []
    fetched = 0
    for t in (resp.get("threads", []) or [])[:max_threads]:
        if len(out) >= max_messages:
            break
        full = users.threads().get(userId="me", id=t["id"], format="metadata",
                                   metadataHeaders=headers).execute()
        fetched += 1
        for m in full.get("messages", []) or []:
            if len(out) >= max_messages:
                break
            out.append({
                "headers": (m.get("payload") or {}).get("headers") or [],
                "internal_date": int(m.get("internalDate") or 0),
                "sent": "SENT" in (m.get("labelIds") or []),
            })
    return {"messages": out, "threads": fetched}
