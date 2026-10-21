"""Gmail client factory, message parsing and MIME building.

All functions here are synchronous and meant to run in a worker thread
(anyio.to_thread.run_sync). A fresh service object is built per call because
googleapiclient services are not thread-safe."""

from __future__ import annotations

import base64
import calendar
import re
import threading
import time
from email.message import EmailMessage
from email.utils import formataddr, getaddresses, parseaddr
from html import unescape
from html.parser import HTMLParser
from typing import Any

from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

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
    yield part
    for sub in part.get("parts", []) or []:
        yield from _walk(sub)


def extract_body(payload: dict) -> str:
    plain, html = [], []
    for part in _walk(payload):
        mime = (part.get("mimeType") or "").lower()
        if part.get("filename"):
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


def extract_attachments(payload: dict) -> list[dict]:
    out = []
    for part in _walk(payload):
        if part.get("filename"):
            out.append(
                {
                    "filename": part["filename"],
                    "mime_type": part.get("mimeType"),
                    "size": (part.get("body") or {}).get("size", 0),
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


def op_list_labels(svc) -> list[dict]:
    resp = svc.users().labels().list(userId="me").execute()
    return [
        {"id": l.get("id"), "name": l.get("name"), "type": l.get("type")}
        for l in resp.get("labels", []) or []
    ]


def op_create_draft(
    svc,
    *,
    from_addr: str,
    to: str,
    subject: str,
    body: str,
    cc: str | None,
    bcc: str | None,
    reply_to_message_id: str | None,
) -> dict:
    users = svc.users()
    thread_id = in_reply_to = references = None
    if reply_to_message_id:
        orig = (
            users.messages()
            .get(
                userId="me",
                id=reply_to_message_id,
                format="metadata",
                metadataHeaders=["Subject", "Message-ID", "References"],
            )
            .execute()
        )
        rh = reply_headers(orig)
        thread_id, in_reply_to, references = rh["thread_id"], rh["in_reply_to"], rh["references"]
        subject = reply_subject(subject or rh["subject"])
    mime = build_mime(
        from_addr=from_addr,
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
    return {"draft_id": draft.get("id"), "thread_id": thread_id}


def gmail_drafts_url(email: str) -> str:
    return f"https://mail.google.com/mail/u/{parseaddr(email)[1] or email}/#drafts"
