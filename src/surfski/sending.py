"""Opt-in sending (#2): signed single-use action links, send caps, and the
owner re-authentication used to raise a mailbox's send policy.

Action tokens are signed with a key derived from STATE_SECRET that differs from the
linking-state key, and carry a purpose, so a token minted for one flow can never be
replayed against another (or against /gmail/callback)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from email.utils import getaddresses
from typing import Any
from urllib.parse import urlencode

import httpx

from .linking import AUTH_ENDPOINT, TOKEN_ENDPOINT, pkce_pair
from .storage import SEND_POLICIES, Storage

ACTION_TTL_SECONDS = 600
SESSION_TTL_SECONDS = 12 * 3600
SESSION_COOKIE = "surfski_owner"
# Raising a policy needs a session created this recently (fresh Google sign-in).
RAISE_SESSION_MAX_AGE = 600
# The id_token must have been issued this recently.
ID_TOKEN_MAX_AGE = 300
TOKENINFO_ENDPOINT = "https://oauth2.googleapis.com/tokeninfo"
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")

PURPOSE_SEND = "send-confirm"
PURPOSE_RAISE = "policy-raise"
PURPOSE_AUTH = "owner-auth"


class ActionError(Exception):
    """User-facing failure of a confirmation/approval link (safe to display)."""


def policy_rank(policy: str) -> int:
    return SEND_POLICIES.index(policy)


# ---------------------------------------------------------------- tokens


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _action_key(state_secret: bytes) -> bytes:
    return hmac.new(state_secret, b"surfski/action-token/v1", hashlib.sha256).digest()


def sign_action(state_secret: bytes, payload: dict) -> str:
    body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = _b64e(hmac.new(_action_key(state_secret), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_action(state_secret: bytes, token: str, purpose: str, now: float | None = None) -> dict:
    try:
        body, sig = (token or "").split(".", 1)
    except ValueError:
        raise ActionError("this link is invalid") from None
    expected = _b64e(hmac.new(_action_key(state_secret), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, sig):
        raise ActionError("this link is invalid")
    try:
        payload = json.loads(_b64d(body))
    except Exception:  # noqa: BLE001
        raise ActionError("this link is invalid") from None
    if not isinstance(payload, dict) or not {"p", "o", "a", "e", "n", "x"} <= payload.keys():
        raise ActionError("this link is invalid")
    if payload["p"] != purpose:
        raise ActionError("this link is not valid for this page")
    if (now or time.time()) > int(payload["x"]):
        raise ActionError("this link has expired; ask Claude for a new one")
    return payload


def issue_action(
    storage: Storage,
    state_secret: bytes,
    *,
    owner: str,
    alias: str,
    email: str,
    purpose: str,
    data: dict,
    ttl: int = ACTION_TTL_SECONDS,
    now: float | None = None,
) -> str:
    """Store a single-use nonce (with server-side data) and return the signed token."""
    nonce = secrets.token_urlsafe(24)
    exp = int(now or time.time()) + ttl
    storage.add_action_token(nonce, owner, alias, purpose, exp, json.dumps(data))
    return sign_action(
        state_secret,
        {"p": purpose, "o": owner.lower(), "a": alias, "e": email.lower(), "n": nonce, "x": exp},
    )


def token_data(raw: str | None) -> dict | None:
    return None if raw is None else json.loads(raw or "{}")


# ---------------------------------------------------------------- caps


RECIPIENT_HEADERS = ("to", "cc", "bcc")
RESENT_HEADERS = ("resent-to", "resent-cc", "resent-bcc")
_ADDR_RE = re.compile(r"^[^@\s<>(),;:\\\"\[\]]+@[A-Za-z0-9.-]+\.[A-Za-z0-9-]+$")


def recipient_values(raw_headers: list[dict]) -> dict[str, list[str]]:
    """Every occurrence of To/Cc/Bcc (case-insensitive), not just the first."""
    out: dict[str, list[str]] = {k: [] for k in RECIPIENT_HEADERS}
    for h in raw_headers or []:
        name = (h.get("name") or "").lower()
        if name in out:
            out[name].append(h.get("value") or "")
        elif name in RESENT_HEADERS:
            raise ValueError(f"the message has a {h.get('name')} header, which isn't allowed")
    return out


def collect_recipients(values: dict[str, list[str]]) -> list[str]:
    """Unique lowercased addresses over all recipient header occurrences. Raises
    ValueError if any entry is empty or not a single plain address."""
    seen: list[str] = []
    for vals in values.values():
        for v in vals:
            if not v.strip():
                continue
            pairs = getaddresses([v])
            if not pairs:
                raise ValueError(f"can't parse recipient header value {v!r}")
            for _, addr in pairs:
                addr = addr.strip().lower()
                if not addr or not _ADDR_RE.match(addr):
                    raise ValueError(f"invalid recipient in {v!r}")
                if addr not in seen:
                    seen.append(addr)
    return seen


def check_recipients(recipients: list[str], *, max_recipients: int, allowed_domains: frozenset[str]) -> None:
    """Raise ValueError (user-facing text) if the recipient list breaks a cap."""
    if not recipients:
        raise ValueError("the message has no recipients")
    if len(recipients) > max_recipients:
        raise ValueError(
            f"{len(recipients)} recipients (to+cc+bcc) is over this server's limit of {max_recipients}"
        )
    if allowed_domains:
        bad = sorted({a.rsplit("@", 1)[-1] for a in recipients if a.rsplit("@", 1)[-1] not in allowed_domains})
        if bad:
            raise ValueError(
                "recipient domain(s) not allowed by this server: " + ", ".join(bad)
                + f" (allowed: {', '.join(sorted(allowed_domains))})"
            )


def checked_recipients(raw_headers: list[dict], *, max_recipients: int, allowed_domains: frozenset[str]) -> list[str]:
    """All recipients of a message, after every cap check (ValueError on failure)."""
    recipients = collect_recipients(recipient_values(raw_headers))
    check_recipients(recipients, max_recipients=max_recipients, allowed_domains=allowed_domains)
    return recipients


# ---------------------------------------------------------------- owner re-auth


def reauth_url(
    *, client_id: str, redirect_uri: str, state: str, challenge: str, login_hint: str, nonce: str
) -> str:
    # Google documents only none/consent/select_account for prompt and returns no
    # auth_time claim, so prompt=login/max_age can't be used or verified here.
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email",
        "prompt": "select_account",
        "login_hint": login_hint,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{AUTH_ENDPOINT}?{urlencode(params)}"


def new_pkce() -> tuple[str, str]:
    return pkce_pair()


async def reauth_email(
    http: httpx.AsyncClient,
    *,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
    nonce: str,
    now: float | None = None,
) -> tuple[str, str | None]:
    """Exchange the code, verify the id_token with Google's tokeninfo endpoint
    (signature checked by Google; we check aud, iss, exp, iat, nonce, email_verified
    and auth_time if present) and return (lowercased email, hosted domain `hd` or None)."""
    resp = await http.post(
        TOKEN_ENDPOINT,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
    )
    tokens = resp.json() if resp.status_code == 200 else {}
    id_token = tokens.get("id_token")
    if not id_token:
        raise ActionError("Google rejected the sign-in; start again from the link")
    info = await http.get(TOKENINFO_ENDPOINT, params={"id_token": id_token})
    if info.status_code != 200:
        raise ActionError("Google could not verify the sign-in; start again from the link")
    claims: dict[str, Any] = info.json()
    now = now or time.time()
    try:
        exp, iat = int(claims.get("exp", 0)), int(claims.get("iat", 0))
    except (TypeError, ValueError):
        raise ActionError("invalid sign-in token") from None
    if claims.get("aud") != client_id or claims.get("iss") not in GOOGLE_ISSUERS:
        raise ActionError("the sign-in token was not issued for this server")
    if exp < now or now - iat > ID_TOKEN_MAX_AGE:
        raise ActionError("the sign-in is too old; start again from the link")
    if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise ActionError("the sign-in doesn't match this request; start again from the link")
    if "auth_time" in claims and now - int(claims["auth_time"]) > ID_TOKEN_MAX_AGE:
        raise ActionError("please sign in again (your Google sign-in is too old)")
    email = str(claims.get("email") or "").strip().lower()
    if not email or str(claims.get("email_verified")).lower() != "true":
        raise ActionError("your Google email is not verified")
    hd = str(claims.get("hd") or "").strip().lower() or None
    if tokens.get("access_token"):
        try:  # best effort: we only needed the identity
            await http.post("https://oauth2.googleapis.com/revoke", data={"token": tokens["access_token"]})
        except httpx.HTTPError:
            pass
    return email, hd
