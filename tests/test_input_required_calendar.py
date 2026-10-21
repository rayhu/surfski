"""Calendar writes confirmed with an input-required result on 2026-07-28 connections (#33)."""

import mcp_types as mt
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

import surfski.sending as snd
import surfski.server as srv

from .test_calendar import CREATE, accounts, all_writes, app, cals, google  # noqa: F401
from .test_elicitation import Human
from .test_input_required import MODERN, accept, minted, modern  # noqa: F401
from .test_server import ALICE, who  # noqa: F401

pytestmark = pytest.mark.skipif(not srv.INPUT_REQUIRED_SUPPORTED, reason="SDK lacks SEP-2322 support")


async def test_calendar_accept_and_decline(app, who, cals, storage):
    human = Human(value={"confirm": True})
    r = await modern(app, human, "create_event", **CREATE)
    assert r["status"] == "done" and r["written"] is True and r["confirm_channel"] == "input-required"
    assert "Lunch with Bob" in human.prompts[0]
    [(path, _kw)] = all_writes(cals)
    assert path == "events.insert"
    r = await modern(app, Human(action="decline"), "delete_event", alias="work", event_id="e1")
    assert r["status"] == "declined" and r["written"] is False
    r = await modern(app, Human(value={"confirm": "yes"}), "delete_event", alias="work", event_id="e1")
    assert r["status"] == "confirmation_required"
    assert len(all_writes(cals)) == 1


async def test_calendar_event_changed_between_rounds(app, who, cals):
    def edit():
        cals["alice@work.com"].events["e1"]["etag"] = '"edited"'
    with pytest.raises(ToolError, match="event changed after it was shown"):
        await modern(app, Human(value={"confirm": True}, during=edit), "update_event",
                     alias="work", event_id="e1", summary="moved")
    assert all_writes(cals) == []


async def test_mail_continuation_cannot_resume_calendar(app, who, cals, storage, minted):
    async with Client(app, mode=MODERN, elicitation_handler=Human()) as c:
        first = await c.session.call_tool("create_event", CREATE, allow_input_required=True)
    assert isinstance(first, mt.InputRequiredResult)
    [(purpose, token)] = minted
    assert purpose == snd.PURPOSE_CAL_INPUT
    secret = app.surfski["config"].state_secret
    for other in (snd.PURPOSE_SEND_INPUT, snd.PURPOSE_CAL_CONFIRM, snd.PURPOSE_SEND):
        with pytest.raises(snd.ActionError):
            snd.verify_action(secret, token, other)
    assert "send_draft" not in app.surfski["resumers"]  # sending disabled on this app


async def test_calendar_continuation_rejected_by_send_resumer(config, storage, cals, google, accounts,  # noqa: F811
                                                             who, minted):  # noqa: F811
    from .test_calendar import make
    both = make(config, storage, cals, google.factory, sending_enabled=True)
    async with Client(both, mode=MODERN, elicitation_handler=Human()) as c:
        first = await c.session.call_tool("create_event", CREATE, allow_input_required=True)
    assert isinstance(first, mt.InputRequiredResult)
    [(purpose, token)] = minted
    assert purpose == snd.PURPOSE_CAL_INPUT
    resume = both.surfski["resumers"]["send_draft"]  # registered: sending is on
    with pytest.raises(ToolError, match="invalid"):
        await resume(ALICE, "send_draft", dict(CREATE), srv.STATE_PREFIX + token, accept())
    assert all_writes(cals) == []
