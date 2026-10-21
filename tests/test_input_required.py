"""Confirm-mode sends and calendar writes on 2026-07-28 connections (#33): the tool returns
an InputRequiredResult (SEP-2322) with the confirmation form, the client asks the human
and re-calls the tool with the answer; the middleware completes that second round with a
single-use continuation bound to the owner, the tool and its exact arguments."""

import time
from dataclasses import replace

import mcp_types as mt
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

import surfski.sending as snd
import surfski.server as srv

from .test_elicitation import Human, audit, confirm
from .test_sending import (  # noqa: F401  (fixtures)
    accounts,
    app,
    boxes,
    draft,
    google,
    make_app,
    total_sent,
)
from .test_server import ALICE, BOB, who  # noqa: F401

MODERN = "2026-07-28"
pytestmark = pytest.mark.skipif(not srv.INPUT_REQUIRED_SUPPORTED, reason="SDK lacks SEP-2322 support")


async def modern(app, human, tool, **args):
    kw = {"elicitation_handler": human} if human is not None else {}
    async with Client(app, mode=MODERN, **kw) as c:
        r = await c.call_tool(tool, args)
        return r.data if r.data is not None else r.structured_content


@pytest.fixture
def minted(monkeypatch):
    """Our continuation tokens as minted in round 1 (inside the SDK's sealed requestState)."""
    out = []
    real = snd.issue_action

    def spy(*a, **kw):
        token = real(*a, **kw)
        out.append((kw["purpose"], token))
        return token

    monkeypatch.setattr(snd, "issue_action", spy)
    return out


def accept(field="send", value=True):
    return {"confirm": mt.ElicitResult(action="accept", content={field: value})}


# ---------------------------------------------------------------- mail


async def test_accept_sends_after_recheck(app, who, boxes, storage):
    confirm(storage)
    box = boxes["alice@work.com"]
    box.drafts["d1"] = draft("d1", bcc="hidden@y.com")
    human = Human("accept")
    r = await modern(app, human, "send_draft", alias="work", draft_id="d1")
    assert r == {"status": "sent", "sent": True, "draft_id": "d1", "confirm_channel": "input-required",
                 "message_id": "sent-d1", "thread_id": "t-d1"}
    assert len(human.prompts) == 1 and box.sent == [{"userId": "me", "body": {"id": "d1"}}]
    for part in ("Mailbox: work (alice@work.com)", "Bcc: hidden@y.com", "hidden (Bcc) recipients",
                 srv.BODY_BEGIN, "Summary (from the server)"):
        assert part in human.prompts[0], part
    details = audit(storage)
    assert any("channel=input-required asked" in d for d in details)
    assert any("channel=input-required result=accepted" in d for d in details)
    assert not any("hidden@y.com" in d or "Quarterly" in d for d in details)
    m = app.surfski["metrics"].render(0, 0)
    assert 'surfski_sends_total{policy="confirm",outcome="input_requested"} 1' in m


async def test_send_email_and_forward_create_one_draft(app, who, boxes, storage):
    confirm(storage)
    box = boxes["alice@work.com"]
    r = await modern(app, Human("accept"), "send_email", alias="work", to="a@x.com", subject="Hi", body="B")
    assert r["status"] == "sent" and r["draft_id"] == "new1" and "gmail_url" in r
    r = await modern(app, Human("accept"), "forward_message", alias="work", message_id="m1", to="c@x.com",
                     send=True)
    assert r["status"] == "sent" and r["draft_id"] == "new2"
    # The second round never re-ran the tool body: no extra drafts.
    assert [s["body"]["id"] for s in box.sent] == ["new1", "new2"]
    assert "new3" not in box.drafts


@pytest.mark.parametrize("action", ["decline", "cancel"])
async def test_decline_keeps_draft(app, who, boxes, storage, action):
    confirm(storage)
    r = await modern(app, Human(action), "send_draft", alias="work", draft_id="d1")
    assert r["status"] == "declined" and r["sent"] is False and r["confirm_channel"] == "input-required"
    assert "confirm_url" not in r and total_sent(boxes) == 0 and "d1" in boxes["alice@work.com"].drafts
    assert any("channel=input-required result=declined" in d for d in audit(storage))


@pytest.mark.parametrize("content", [{"send": "yes"}, {"send": 1}, {}, {"value": True}, {"send": None}])
async def test_malformed_answer_falls_back_to_link(app, who, boxes, storage, content):
    confirm(storage)
    r = await modern(app, Human("accept", value=content), "send_draft", alias="work", draft_id="d1")
    assert r["status"] == "confirmation_required" and r["confirm_channel"] == "link"
    assert total_sent(boxes) == 0
    assert any("reason=input-malformed" in d for d in audit(storage))


async def test_draft_edited_or_policy_lowered_between_rounds(app, who, boxes, storage):
    confirm(storage)
    box = boxes["alice@work.com"]

    def edit():
        box.drafts["d1"] = draft("d1", to="evil@z.com")
        box.drafts["d1"]["message"]["id"] = "msg-d1-v2"

    with pytest.raises(ToolError, match="edited after it was shown"):
        await modern(app, Human("accept", during=edit), "send_draft", alias="work", draft_id="d1")
    box.drafts["d2"] = draft("d2")
    with pytest.raises(ToolError, match="sending is now off"):
        await modern(app, Human("accept", during=lambda: storage.set_send_policy(ALICE, "work", "off")),
                     "send_draft", alias="work", draft_id="d2")
    assert total_sent(boxes) == 0 and storage.sends_today(ALICE, "work", int(time.time())) == 0


async def test_replayed_continuation_is_refused(app, who, boxes, storage):
    confirm(storage)
    args = {"alias": "work", "draft_id": "d1"}
    async with Client(app, mode=MODERN, elicitation_handler=Human()) as c:
        first = await c.session.call_tool("send_draft", args, allow_input_required=True)
        assert isinstance(first, mt.InputRequiredResult)
        assert set(first.input_requests) == {"confirm"}
        schema = first.input_requests["confirm"].params.requested_schema
        assert schema["properties"]["send"]["type"] == "boolean" and schema["required"] == ["send"]
        ok = await c.session.call_tool("send_draft", args, input_responses=accept(),
                                       request_state=first.request_state)
        assert ok.structured_content["status"] == "sent"
        # The SDK's sealed requestState doesn't stop a replay; our single-use token does.
        again = await c.session.call_tool("send_draft", args, input_responses=accept(),
                                          request_state=first.request_state)
    assert again.is_error and "already used" in again.content[0].text
    assert total_sent(boxes) == 1


async def test_continuation_for_another_draft_or_owner_is_refused(app, who, boxes, storage, minted):
    confirm(storage)
    boxes["alice@work.com"].drafts["d2"] = draft("d2")
    async with Client(app, mode=MODERN, elicitation_handler=Human()) as c:
        first = await c.session.call_tool("send_draft", {"alias": "work", "draft_id": "d1"},
                                          allow_input_required=True)
    assert isinstance(first, mt.InputRequiredResult)
    [(purpose, token)] = minted
    assert purpose == snd.PURPOSE_SEND_INPUT
    state = srv.STATE_PREFIX + token
    resume = app.surfski["resumers"]["send_draft"]
    # The SDK seal already binds the arguments; this checks our own binding behind it.
    with pytest.raises(ToolError, match="invalid, expired or already used"):
        await resume(ALICE, "send_draft", {"alias": "work", "draft_id": "d2"}, state, accept())
    with pytest.raises(ToolError, match="invalid, expired or already used"):
        await resume(ALICE, "send_email", {"alias": "work", "draft_id": "d1"}, state, accept())
    with pytest.raises(ToolError, match="invalid, expired or already used"):
        await resume(BOB, "send_draft", {"alias": "work", "draft_id": "d1"}, state, accept())
    with pytest.raises(ToolError, match="invalid"):
        await resume(ALICE, "send_draft", {"alias": "work", "draft_id": "d1"}, state + "x", accept())
    assert total_sent(boxes) == 0
    # Refusals didn't burn it: the matching call still works once.
    r = await resume(ALICE, "send_draft", {"alias": "work", "draft_id": "d1"}, state, accept())
    assert r["status"] == "sent" and [s["body"]["id"] for s in boxes["alice@work.com"].sent] == ["d1"]
    # A continuation is never a /send/confirm link token (different purpose).
    with pytest.raises(snd.ActionError):
        snd.verify_action(app.surfski["config"].state_secret, token, snd.PURPOSE_SEND)


async def test_link_when_not_applicable(config, storage, boxes, google, accounts, who, monkeypatch):
    app = make_app(config, storage, boxes, google)
    confirm(storage)
    r = await modern(app, None, "send_draft", alias="work", draft_id="d1")  # no elicitation capability
    assert r["status"] == "confirmation_required"
    assert any("reason=client-not-capable" in d for d in audit(storage))
    link_only = make_app(config, storage, boxes, google, confirm_channel="link")
    human = Human("accept")
    r = await modern(link_only, human, "send_draft", alias="work", draft_id="d1")
    assert r["status"] == "confirmation_required" and human.prompts == []
    monkeypatch.setattr(srv, "INPUT_REQUIRED_SUPPORTED", False)  # an SDK without SEP-2322
    r = await modern(app, human, "send_draft", alias="work", draft_id="d1")
    assert r["status"] == "confirmation_required" and human.prompts == []
    assert any("reason=sdk-unsupported" in d for d in audit(storage))
    assert total_sent(boxes) == 0


def test_resumable_tools_and_answer_parsing():
    assert "unsubscribe" not in srv.RESUMABLE_TOOLS  # mailto unsubscribe stays on the link
    ok = srv.input_answer(accept(), srv.SendDecision, "send")
    assert ok == "accept"
    for bad in (None, {}, {"confirm": accept()["confirm"], "extra": accept()["confirm"]},
                {"other": accept()["confirm"]}, {"confirm": {"action": "accept"}},
                accept(value="true"), accept(field="value")):
        assert srv.input_answer(bad, srv.SendDecision, "send") == "malformed", bad
    assert srv.input_answer(accept(value=False), srv.SendDecision, "send") == "decline"
    assert srv.input_answer({"confirm": mt.ElicitResult(action="cancel")}, srv.SendDecision, "send") == "decline"
