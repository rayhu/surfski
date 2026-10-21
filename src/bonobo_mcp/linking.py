"""Gmail account linking (auth layer B): signed single-use state, PKCE auth URL,
code exchange, profile lookup and revocation. Uses httpx directly instead of
oauthlib's Flow so the callback is easy to test and has no transport quirks."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from .storage import Storage, validate_alias

GMAIL_SCOPES = (
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose",
)
AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"
PROFILE_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
STATE_TTL_SECONDS = 600


class LinkError(Exception):
    """User-facing linking failure (message is safe to display)."""


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_state(secret: bytes, payload: dict) -> str:
    body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = _b64e(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_state(secret: bytes, state: str, now: float | None = None) -> dict:
    try:
        body, sig = state.split(".", 1)
    except ValueError as e:
        raise LinkError("invalid state") from e
    expected = _b64e(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, sig):
        raise LinkError("invalid state signature")
    try:
        payload = json.loads(_b64d(body))
    except Exception as e:  # noqa: BLE001
        raise LinkError("invalid state") from e
    if not isinstance(payload, dict) or not {"owner", "alias", "nonce", "exp"} <= payload.keys():
        raise LinkError("invalid state")
    if (now or time.time()) > int(payload["exp"]):
        raise LinkError("link expired; ask Claude to start linking again")
    return payload


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = _b64e(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


@dataclass(frozen=True)
class LinkStart:
    url: str
    expires_in: int


def start_link(
    storage: Storage,
    *,
    state_secret: bytes,
    client_id: str,
    redirect_uri: str,
    owner: str,
    alias: str,
    login_hint: str | None = None,
    now: float | None = None,
) -> LinkStart:
    alias = validate_alias(alias)
    owner = owner.lower()
    nonce = secrets.token_urlsafe(24)
    exp = int(now or time.time()) + STATE_TTL_SECONDS
    verifier, challenge = pkce_pair()
    storage.add_pending_link(nonce, owner, alias, exp, verifier)
    state = sign_state(state_secret, {"owner": owner, "alias": alias, "nonce": nonce, "exp": exp})
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(GMAIL_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "false",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if login_hint:
        params["login_hint"] = login_hint
    return LinkStart(url=f"{AUTH_ENDPOINT}?{urlencode(params)}", expires_in=STATE_TTL_SECONDS)


def consume_state(storage: Storage, state_secret: bytes, state: str) -> tuple[dict, str]:
    """Verify signature/expiry and burn the nonce. Returns (payload, code_verifier)."""
    payload = verify_state(state_secret, state)
    verifier = storage.consume_pending_link(payload["nonce"], payload["owner"], payload["alias"])
    if verifier is None:
        raise LinkError("this link was already used or is unknown; start linking again")
    return payload, verifier


async def exchange_code(
    http: httpx.AsyncClient,
    *,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
) -> dict:
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
    if resp.status_code != 200:
        raise LinkError("Google rejected the authorization code; start linking again")
    tokens = resp.json()
    if not tokens.get("refresh_token"):
        raise LinkError(
            "Google did not return a refresh token. Remove this app at "
            "https://myaccount.google.com/permissions and link again."
        )
    granted = set((tokens.get("scope") or "").split())
    missing = [s for s in GMAIL_SCOPES if s not in granted]
    if granted and missing:
        raise LinkError(
            "Not all Gmail permissions were granted (need read and compose). Link again "
            "and tick every checkbox on the consent screen."
        )
    return tokens


async def fetch_profile_email(http: httpx.AsyncClient, access_token: str) -> str:
    resp = await http.get(PROFILE_ENDPOINT, headers={"Authorization": f"Bearer {access_token}"})
    if resp.status_code != 200:
        raise LinkError("could not read the Gmail profile for this account")
    email = resp.json().get("emailAddress")
    if not email:
        raise LinkError("Gmail profile has no address")
    return email.lower()


async def revoke_token(http: httpx.AsyncClient, token: str) -> bool:
    try:
        resp = await http.post(REVOKE_ENDPOINT, data={"token": token})
        return resp.status_code == 200
    except httpx.HTTPError:
        return False
