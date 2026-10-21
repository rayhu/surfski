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
import secrets
import time
from email.utils import getaddresses
from typing import Any
from urllib.parse import urlencode

import httpx

from .linking import AUTH_ENDPOINT, TOKEN_ENDPOINT, pkce_pair
from .storage import SEND_POLICIES, Storage

ACTION_TTL_SECONDS = 600
APPLY_TTL_SECONDS = 300
USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"

PURPOSE_SEND = "send-confirm"
PURPOSE_RAISE = "policy-raise"
PURPOSE_AUTH = "policy-auth"
PURPOSE_APPLY = "policy-apply"


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


def unique_recipients(headers: dict[str, str]) -> list[str]:
    vals = [headers.get(k, "") for k in ("to", "cc", "bcc")]
    seen: list[str] = []
    for _, addr in getaddresses([v for v in vals if v]):
        addr = addr.strip().lower()
        if addr and addr not in seen:
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


# ---------------------------------------------------------------- owner re-auth


def policy_auth_url(*, client_id: str, redirect_uri: str, state: str, challenge: str, login_hint: str) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email",
        "prompt": "select_account",
        "login_hint": login_hint,
        "state": state,
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
) -> str:
    """Exchange the code (back channel, TLS) and return the verified, lowercased email."""
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
    if resp.status_code != 200 or not resp.json().get("access_token"):
        raise ActionError("Google rejected the sign-in; open the approval link again")
    access = resp.json()["access_token"]
    info = await http.get(USERINFO_ENDPOINT, headers={"Authorization": f"Bearer {access}"})
    if info.status_code != 200:
        raise ActionError("could not read your Google identity; try again")
    data: dict[str, Any] = info.json()
    email = (data.get("email") or "").strip().lower()
    verified = data.get("email_verified")
    if not email or not (verified is True or str(verified).lower() == "true"):
        raise ActionError("your Google email is not verified")
    # Best effort: don't keep a token we no longer need.
    try:
        await http.post("https://oauth2.googleapis.com/revoke", data={"token": access})
    except httpx.HTTPError:
        pass
    return email
