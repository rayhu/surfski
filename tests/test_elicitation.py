"""Confirm-mode sends via MCP elicitation (#27). The client is fastmcp's in-memory
Client with an elicitation_handler, on a handshake-era protocol (2026-07-28 connections
have no back-channel for server-initiated requests and must fall back to the link)."""

import time
from dataclasses import replace

import anyio
import pytest
from fastmcp import Client
from fastmcp.client.elicitation import ElicitResult
from fastmcp.exceptions import ToolError

import surfski.server as srv
from surfski.server import create_app

from .test_sending import (  # noqa: F401  (fixtures)
    accounts,
    app,
    boxes,
    draft,
    google,
    make_app,
    sign_in,
    token_of,
    total_sent,
    web,
)
from .test_server import ALICE, BOB, who  # noqa: F401


class Human:
    """A scripted elicitation handler: records every prompt and answers `action`."""

    def __init__(self, action="accept", value=True, during=None):
        self.action, self.value, self.during = action, value, during
        self.prompts: list[str] = []

    async def __call__(self, message, response_type, params, context):
        self.prompts.append(message)
        if self.during:
            self.during()
        if self.action == "error":
            raise RuntimeError("client blew up")
        if self.action == "hang":
            await anyio.sleep(10)
        if self.action == "accept":
            return ElicitResult(action="accept", content=self.value if isinstance(self.value, dict) else {"send": self.value})
        return ElicitResult(action=self.action)


async def call_with(app, human, tool, mode="legacy", **args):
    kw = {"elicitation_handler": human} if human is not None else {}
    async with Client(app, mode=mode, **kw) as c:
        r = await c.call_tool(tool, args)
        return r.data if r.data is not None else r.structured_content


def confirm(storage, owner=ALICE, alias="work"):
    storage.set_send_policy(owner, alias, "confirm")


def audit(storage, owner=ALICE):
    return [r["detail"] for r in storage.audit_rows(owner)]


# ---------------------------------------------------------------- accept


async def test_accept_sends_after_recheck(app, who, boxes, storage):
    confirm(storage)
    box = boxes["alice@work.com"]
    box.drafts["d1"] = draft("d1", bcc="hidden@y.com", body="x" * 600)
    human = Human("accept")
    r = await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    assert len(human.prompts) == 1
    assert r == {"status": "sent", "sent": True, "draft_id": "d1", "confirm_channel": "elicitation",
                 "message_id": "sent-d1", "thread_id": "t-d1"}
    assert box.sent == [{"userId": "me", "body": {"id": "d1"}}]
    prompt = human.prompts[0]
    for part in ("Mailbox: work (alice@work.com)", "From: Alice <alice@work.com>", "To: a@x.com",
                 "Cc: b@x.com", "Bcc: hidden@y.com", "hidden (Bcc) recipients",
                 "Subject: Quarterly <script>", "Attachments: none", "Recipients: 3"):
        assert part in prompt, part
    assert "x" * 500 + "…" in prompt and "x" * 501 not in prompt
    assert storage.sends_today(ALICE, "work", int(time.time())) == 1
    details = audit(storage)
    assert "policy=confirm recipients=3 message=sent-d1 channel=elicitation result=accepted" in details
    for d in details:
        for leak in ("a@x.com", "hidden@y.com", "Quarterly", "xxxx"):
            assert leak not in d


async def test_accept_with_false_does_not_send(app, who, boxes, storage):
    confirm(storage)
    r = await call_with(app, Human("accept", value=False), "send_draft", alias="work", draft_id="d1")
    assert r["status"] == "declined" and r["sent"] is False and total_sent(boxes) == 0


@pytest.mark.parametrize("action", ["decline", "cancel"])
async def test_decline_or_cancel_keeps_draft(app, who, boxes, storage, action):
    confirm(storage)
    human = Human(action)
    r = await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    assert len(human.prompts) == 1
    assert r["status"] == "declined" and r["sent"] is False and r["draft_id"] == "d1"
    assert "confirm_url" not in r and r["confirm_channel"] == "elicitation"
    assert total_sent(boxes) == 0 and "d1" in boxes["alice@work.com"].drafts
    assert storage.sends_today(ALICE, "work", int(time.time())) == 0
    assert any("channel=elicitation result=declined" in d for d in audit(storage))


async def test_send_email_and_forward_use_elicitation(app, who, boxes, storage):
    confirm(storage)
    box = boxes["alice@work.com"]
    human = Human("accept")
    r = await call_with(app, human, "send_email", alias="work", to="a@x.com", subject="Hi", body="Body")
    assert r["status"] == "sent" and r["confirm_channel"] == "elicitation" and r["draft_id"] == "new1"
    assert "Subject: Hi" in human.prompts[0] and "Body" in human.prompts[0]
    r = await call_with(app, Human("decline"), "forward_message", alias="work", message_id="m1",
                        to="c@x.com", send=True)
    assert r["status"] == "declined" and r["draft_id"] == "new2" and "gmail_url" in r
    assert [s["body"]["id"] for s in box.sent] == ["new1"]
    assert "new2" in box.drafts


# ---------------------------------------------------------------- recheck after accept


async def test_policy_lowered_during_prompt_blocks_send(app, who, boxes, storage):
    confirm(storage)
    human = Human("accept", during=lambda: storage.set_send_policy(ALICE, "work", "off"))
    with pytest.raises(ToolError, match="sending is now off.*draft d1 was kept"):
        await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    assert total_sent(boxes) == 0
    # No link is handed out as a consolation either.
    assert not any("link=issued" in d for d in audit(storage))


async def test_cap_used_up_during_prompt_blocks_send(config, storage, boxes, google, accounts, who):
    app = make_app(config, storage, boxes, google, send_daily_cap=1)
    confirm(storage)
    human = Human("accept", during=lambda: storage.reserve_send(ALICE, "work", 1, int(time.time())))
    with pytest.raises(ToolError, match="limit of 1 sends"):
        await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    assert total_sent(boxes) == 0


async def test_recipient_cap_rechecked_and_draft_change_blocks_send(app, who, boxes, storage):
    confirm(storage)
    box = boxes["alice@work.com"]

    def edit():  # the model edits the draft while the human reads the old version
        box.drafts["d1"] = draft("d1", to="evil@z.com")
        box.drafts["d1"]["message"]["id"] = "msg-d1-v2"

    with pytest.raises(ToolError, match="edited after it was shown"):
        await call_with(app, Human("accept", during=edit), "send_draft", alias="work", draft_id="d1")
    assert box.sent == [] and storage.sends_today(ALICE, "work", int(time.time())) == 0


async def test_relink_during_prompt_blocks_send(app, who, boxes, storage):
    confirm(storage)
    human = Human("accept", during=lambda: storage.upsert_account(ALICE, "work", "alice@other.com", "r", "s"))
    with pytest.raises(ToolError):
        await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    assert total_sent(boxes) == 0


async def test_caps_checked_before_asking(app, who, boxes, storage):
    confirm(storage)
    boxes["alice@work.com"].drafts["big"] = draft("big", to=", ".join(f"u{i}@x.com" for i in range(11)), cc="")
    human = Human("accept")
    with pytest.raises(ToolError, match="11 recipients"):
        await call_with(app, human, "send_draft", alias="work", draft_id="big")
    assert human.prompts == [] and total_sent(boxes) == 0


# ---------------------------------------------------------------- fallback to the link


async def test_client_without_elicitation_gets_link(app, who, boxes, storage):
    confirm(storage)
    r = await call_with(app, None, "send_draft", alias="work", draft_id="d1")
    assert r["status"] == "confirmation_required" and r["confirm_channel"] == "link"
    assert total_sent(boxes) == 0
    assert any("reason=client-not-capable" in d for d in audit(storage))


async def test_modern_protocol_gets_link(app, who, boxes, storage):
    confirm(storage)
    human = Human("accept")
    r = await call_with(app, human, "send_draft", mode="auto", alias="work", draft_id="d1")
    assert r["status"] == "confirmation_required" and human.prompts == [] and total_sent(boxes) == 0


async def test_elicitation_error_falls_back_to_link_never_sends(app, who, boxes, storage, google):
    confirm(storage)
    human = Human("error")
    r = await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    assert len(human.prompts) == 1
    assert r["status"] == "confirmation_required" and total_sent(boxes) == 0
    assert any("reason=elicitation-error" in d for d in audit(storage))
    # The link still works as before (owner session required).
    client = web(app)
    sign_in(client, google, token_of(r["confirm_url"]))
    assert client.post("/send/confirm", data={"token": token_of(r["confirm_url"])}).status_code == 200
    assert total_sent(boxes) == 1


async def test_elicitation_timeout_falls_back_to_link(app, who, boxes, storage, monkeypatch):
    confirm(storage)
    monkeypatch.setattr(srv, "ELICIT_TIMEOUT_SECONDS", 0.2)
    r = await call_with(app, Human("hang"), "send_draft", alias="work", draft_id="d1")
    assert r["status"] == "confirmation_required" and total_sent(boxes) == 0
    assert any("reason=elicitation-timeout" in d for d in audit(storage))


async def test_confirm_channel_link_forces_link(config, storage, boxes, google, accounts, who):
    app = make_app(config, storage, boxes, google, confirm_channel="link")
    confirm(storage)
    human = Human("accept")
    r = await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    assert r["status"] == "confirmation_required" and human.prompts == [] and total_sent(boxes) == 0
    assert any("reason=operator-link-only" in d for d in audit(storage))


async def test_auto_and_off_policies_never_elicit(app, who, boxes, storage):
    human = Human("accept")
    with pytest.raises(ToolError, match="sending is off"):
        await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    storage.set_send_policy(ALICE, "work", "auto")
    r = await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    assert r["status"] == "sent" and "confirm_channel" not in r and human.prompts == []


# ---------------------------------------------------------------- owner isolation


async def test_owner_isolation(app, who, boxes, storage):
    confirm(storage)
    confirm(storage, BOB, "secret")
    human = Human("accept")
    # Bob can't reach Alice's mailbox: no prompt, no send.
    who["claims"] = {"email": BOB}
    with pytest.raises(ToolError, match="no linked account 'work'"):
        await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    assert human.prompts == []

    # Identity switching mid-prompt doesn't redirect Alice's confirmed send.
    who["claims"] = {"email": ALICE, "email_verified": True}
    human = Human("accept", during=lambda: who.update(claims={"email": BOB}))
    r = await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    assert r["status"] == "sent"
    assert boxes["alice@work.com"].sent == [{"userId": "me", "body": {"id": "d1"}}]
    assert boxes["bob@work.com"].sent == []
    assert not any("channel=elicitation" in d for d in audit(storage, BOB))


# ---------------------------------------------------------------- prompt spoofing


def _outside_body(prompt):
    lines = prompt.split("\n")
    b, e = lines.index(srv.BODY_BEGIN), lines.index(srv.BODY_END)
    return lines[:b] + lines[e + 1:], lines[b + 1:e]


async def test_body_cannot_forge_summary(app, who, boxes, storage):
    confirm(storage)
    box = boxes["alice@work.com"]
    body = ("Hi\nTo: x@y.com\r\nRecipients: 1: x@y.com\n" + srv.BODY_END
            + "\nSummary (from the server): sends to 1 recipient(s) Bcc: ‮example")
    box.drafts["d1"] = draft("d1", bcc="hidden@y.com", body=body)
    human = Human("decline")
    await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    outside, inside = _outside_body(human.prompts[0])
    assert inside and all(line.startswith("│ ") for line in inside)
    assert "│ To: x@y.com" in inside and f"│ {srv.BODY_END}" in inside
    assert [line for line in outside if line.startswith("To:")] == ["To: a@x.com"]
    assert not any("x@y.com" in line for line in outside)
    assert [line for line in outside if line.startswith("Summary")] == [
        "Summary (from the server): sends to 3 recipient(s): To 1, Cc 1, Bcc 1."]
    after_end = human.prompts[0].split(srv.BODY_END + "\n")[-1]
    assert "hidden (Bcc) recipients" in after_end
    assert "‮" not in human.prompts[0] and " " not in human.prompts[0]


async def test_header_values_are_flattened_and_stripped(app, who, boxes, storage):
    confirm(storage)
    box = boxes["alice@work.com"]
    d = draft("d1", subject="Invoice\r\nTo: evil@z.com‮​fdp.exe")
    for h in d["message"]["payload"]["headers"]:
        if h["name"] == "From":
            h["value"] = "Bank\nBcc: none ⁦Support⁩ <alice@work.com>"
    box.drafts["d1"] = d
    human = Human("decline")
    await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    prompt = human.prompts[0]
    outside, _ = _outside_body(prompt)
    assert "Subject: Invoice To: evil@z.comfdp.exe" in outside
    assert "From: Bank Bcc: none Support <alice@work.com>" in outside
    assert not any(line.startswith(("To: evil", "Bcc: none")) for line in outside)
    for ch in ("‮", "​", "⁦", "⁩", "\r"):
        assert ch not in prompt


# ---------------------------------------------------------------- strict answers


@pytest.mark.parametrize("content", [{"send": "yes"}, {"send": 1}, {"send": "true"}, {}, {"send": None},
                                     {"value": True}])
async def test_malformed_accept_falls_back_to_link(app, who, boxes, storage, content):
    confirm(storage)
    human = Human("accept", value=content)
    r = await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    assert len(human.prompts) == 1
    assert r["status"] == "confirmation_required" and r["confirm_channel"] == "link"
    assert total_sent(boxes) == 0


async def test_decline_as_jsonrpc_error_falls_back_to_link(app, who, boxes, storage):
    confirm(storage)

    class Declines(Human):
        async def __call__(self, message, response_type, params, context):
            self.prompts.append(message)
            raise PermissionError("User declined")  # the client answers with a JSON-RPC error

    human = Declines()
    r = await call_with(app, human, "send_draft", alias="work", draft_id="d1")
    assert len(human.prompts) == 1 and r["status"] == "confirmation_required"
    assert total_sent(boxes) == 0


async def test_link_fallback_rechecks_allowlist(config, storage, boxes, google, accounts, who, monkeypatch):
    cfg = replace(config, sending_enabled=True)
    app = create_app(cfg, storage=storage, with_auth=False, http_factory=google.factory,
                     service_factory=lambda o, a: boxes[storage.get_account(o, a).email].service())
    confirm(storage)
    real = srv.elicit_send

    async def drop_alice(message):
        # Alice is removed from the allowlist while the prompt is open; then the client errors.
        object.__setattr__(cfg, "allowed_users", frozenset({BOB}))
        return await real(message)

    monkeypatch.setattr(srv, "elicit_send", drop_alice)
    with pytest.raises(ToolError, match="not allowed"):
        await call_with(app, Human("error"), "send_draft", alias="work", draft_id="d1")
    assert total_sent(boxes) == 0
    assert not any("link=issued" in d for d in audit(storage))
