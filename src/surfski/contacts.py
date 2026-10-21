"""Recipient lookup from the caller's own mail headers (#18). Pure functions: the Gmail
calls live in gmail.op_contact_messages, the tool in server.find_contact."""

from __future__ import annotations

import math
import re
import time
import unicodedata
from datetime import UTC, datetime
from email.utils import getaddresses

# Bounds per mailbox: threads fetched (one metadata call each) and messages scanned.
MAX_THREADS = 50
MAX_MESSAGES = 200
MAX_TERM_CHARS = 100
MAX_DISPLAY_NAMES = 5
# Headers read from each message. Bcc only exists on mail the mailbox sent.
CONTACT_HEADERS = ["From", "To", "Cc", "Reply-To", "Bcc"]
RECIPIENT_HEADERS = ("to", "cc", "bcc")

_ADDR_RE = re.compile(r"^[^@\s<>(),;:\"\[\]]+@[^@\s<>(),;:\"\[\]]+\.[^@\s<>(),;:\"\[\]]+$")
# "noreply" anywhere in the local part (wei.noreply@, do-not-reply+x@), or a system mailbox.
_NOREPLY_RE = re.compile(
    r"no[-_.]?reply|do[-_.]?not[-_.]?reply|^(?:mailer[-_.]daemon|postmaster|bounces?)(?:[-+_.]|$)"
)


def norm(text: str) -> str:
    """Case- and width-insensitive form for matching (NFKC + casefold)."""
    return " ".join(unicodedata.normalize("NFKC", text or "").casefold().split())


_STRIP_CHARS = set('"(){}:*')
_OPERATOR_WORDS = {"OR", "AND"}


def clean_term(term: str) -> str:
    """The user's search text as plain words, safe to quote into a Gmail `q` group: no
    quotes, parens, braces, colons (field operators like in:), wildcards, control
    characters, leading '-' (negation) or standalone OR/AND. Raises ValueError if nothing
    is left."""
    t = "".join(" " if (unicodedata.category(c)[0] == "C" or c in _STRIP_CHARS) else c for c in term or "")
    words = [w.lstrip("-") for w in t.split()]
    t = " ".join(w for w in words if w and w not in _OPERATOR_WORDS)[:MAX_TERM_CHARS].strip()
    if not t:
        raise ValueError("give a name or part of an address to look up")
    return t


def gmail_query(term: str) -> str:
    """Each word quoted, so nothing in it can act as a Gmail operator."""
    q = " ".join(f'"{w}"' for w in term.split())
    return f"from:({q}) OR to:({q}) OR cc:({q})"


def parse_addresses(value: str) -> list[tuple[str, str]]:
    """getaddresses, retried leniently when the strict parser gives up on the whole
    header (it returns only empty pairs for e.g. `Wei <w@x.com> junk, c@d.com`)."""
    pairs = getaddresses([value])
    if all(not n and not a for n, a in pairs):
        try:
            pairs = getaddresses([value], strict=False)
        except TypeError:  # Python without the strict parameter: already lenient
            pass
    return pairs


def matches(term_n: str, name: str, address: str) -> bool:
    """term_n (normalized) is a substring of the address or display name, or every word
    of it appears in the name/address (so "smith john" finds "John Smith")."""
    name_n, addr_n = norm(name), norm(address)
    if term_n in addr_n or term_n in name_n:
        return True
    hay = f"{name_n} {addr_n}"
    words = term_n.split()
    return len(words) > 1 and all(w in hay for w in words)


def is_noreply(address: str) -> bool:
    return bool(_NOREPLY_RE.search(address.split("@", 1)[0].lower()))


def _clean_name(name: str, address: str) -> str:
    name = " ".join((name or "").split()).strip("'\" ")
    return "" if not name or norm(name) == norm(address) else name


def collect(messages: list[dict], term: str, alias: str, acc: dict[str, dict]) -> int:
    """Fold one mailbox's messages into `acc` (address -> stats). Each message is
    {"headers": [{"name", "value"}], "internal_date": ms, "sent": bool}. Every
    occurrence of each header is parsed. Returns the number of matching addresses seen."""
    term_n = norm(term)
    hits = 0
    for m in messages:
        seen_here: set[str] = set()
        for h in m.get("headers") or []:
            hname = (h.get("name") or "").lower()
            if hname not in ("from", "to", "cc", "reply-to", "bcc"):
                continue
            for name, addr in parse_addresses(h.get("value") or ""):
                addr = addr.strip().lower()
                if not _ADDR_RE.match(addr) or not matches(term_n, name, addr):
                    continue
                hits += 1
                c = acc.setdefault(addr, {"address": addr, "display_names": [], "count": 0,
                                          "last_seen_ms": 0, "mailboxes": [], "sent_to": False})
                display = _clean_name(name, addr)
                if display and display not in c["display_names"] and len(c["display_names"]) < MAX_DISPLAY_NAMES:
                    c["display_names"].append(display)
                if addr not in seen_here:  # count messages, not header occurrences
                    seen_here.add(addr)
                    c["count"] += 1
                    c["last_seen_ms"] = max(c["last_seen_ms"], int(m.get("internal_date") or 0))
                if alias not in c["mailboxes"]:
                    c["mailboxes"].append(alias)
                if m.get("sent") and hname in RECIPIENT_HEADERS:
                    c["sent_to"] = True
    return hits


def score(c: dict, now: float) -> float:
    """Frequency (log-damped) + recency (halves every 90 days) + a bonus if the caller
    has written to the address."""
    age_days = max(0.0, (now * 1000 - c["last_seen_ms"]) / 86_400_000) if c["last_seen_ms"] else 3650
    return math.log2(1 + c["count"]) * 2 + 3 * 0.5 ** (age_days / 90) + (3 if c["sent_to"] else 0)


def rank(acc: dict[str, dict], *, exclude: set[str], include_noreply: bool, max_results: int,
         now: float | None = None) -> list[dict]:
    now = time.time() if now is None else now
    rows = [c for a, c in acc.items() if a not in exclude and (include_noreply or not is_noreply(a))]
    rows.sort(key=lambda c: (-score(c, now), -c["last_seen_ms"], c["address"]))
    out = []
    for c in rows[:max_results]:
        last = (datetime.fromtimestamp(c["last_seen_ms"] / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                if c["last_seen_ms"] else None)
        out.append({"address": c["address"], "display_names": c["display_names"], "count": c["count"],
                    "last_seen": last, "mailboxes": sorted(c["mailboxes"]), "sent_to": c["sent_to"]})
    return out
