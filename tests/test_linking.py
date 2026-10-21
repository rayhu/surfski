import time
from urllib.parse import parse_qs, urlparse

import pytest

from surfski.linking import (
    LinkError,
    consume_state,
    sign_state,
    start_link,
    verify_state,
)

SECRET = b"x" * 40
A = "alice@example.com"


def _start(storage, **kw):
    ls = start_link(
        storage,
        state_secret=SECRET,
        client_id="cid",
        redirect_uri="https://mcp.example.com/gmail/callback",
        owner=A,
        alias="work",
        **kw,
    )
    return ls, parse_qs(urlparse(ls.url).query)


def test_auth_url_params(storage):
    ls, q = _start(storage, login_hint="me@work.com")
    assert ls.expires_in == 600
    assert q["access_type"] == ["offline"]
    assert q["prompt"] == ["consent"]
    assert q["include_granted_scopes"] == ["false"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["redirect_uri"] == ["https://mcp.example.com/gmail/callback"]
    assert q["login_hint"] == ["me@work.com"]
    assert set(q["scope"][0].split()) == {
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.compose",
    }


def test_valid_state_consumed_once(storage):
    _, q = _start(storage)
    payload, verifier = consume_state(storage, SECRET, q["state"][0])
    assert payload["owner"] == A and payload["alias"] == "work" and verifier
    with pytest.raises(LinkError, match="already used"):
        consume_state(storage, SECRET, q["state"][0])


def test_tampered_signature_rejected(storage):
    _, q = _start(storage)
    body, sig = q["state"][0].split(".")
    forged = sign_state(b"wrong-secret" * 4, {"owner": "bob@example.com", "alias": "work", "nonce": "n", "exp": 9e9})
    with pytest.raises(LinkError, match="signature"):
        verify_state(SECRET, forged)
    with pytest.raises(LinkError):
        verify_state(SECRET, body + "." + sig[:-2] + "AA")
    with pytest.raises(LinkError):
        verify_state(SECRET, "garbage")


def test_owner_swap_rejected(storage):
    """A validly signed state whose payload doesn't match the stored nonce is rejected."""
    _, q = _start(storage)
    payload = verify_state(SECRET, q["state"][0])
    swapped = sign_state(SECRET, {**payload, "owner": "bob@example.com"})
    with pytest.raises(LinkError):
        consume_state(storage, SECRET, swapped)


def test_expired_state_rejected(storage):
    _, q = _start(storage, now=time.time() - 601)
    with pytest.raises(LinkError, match="expired"):
        consume_state(storage, SECRET, q["state"][0])


def test_unknown_nonce_rejected(storage):
    st = sign_state(SECRET, {"owner": A, "alias": "work", "nonce": "never-issued", "exp": int(time.time()) + 60})
    with pytest.raises(LinkError):
        consume_state(storage, SECRET, st)
