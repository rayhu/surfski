"""Calendar module (#19): FEATURES switch, per-mailbox enable_calendar via a Google
re-consent, read tools and time zones, cross-account find_free_time, the draft/auto
write policy with elicitation and the owner-session confirm link, external-attendee caps,
and audit hygiene. Calendar is a discovery-validated StrictCalendar."""

import copy
from dataclasses import replace
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

import httplib2
import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from googleapiclient.errors import HttpError
from starlette.testclient import TestClient

import surfski.gcal as cal
from surfski.config import ConfigError, load_config
from surfski.server import create_app
from surfski.storage import CALENDAR_SCOPES, GMAIL_MODIFY_SCOPE, Storage

from .conftest import make_env
from .fakes import StrictCalendar
from .test_elicitation import Human, call_with
from .test_sending import Google, sign_in, token_of, web
from .test_server import ALICE, BOB, call, who  # noqa: F401  (fixture re-export)

TZ = "America/Los_Angeles"
BASE = "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.compose"
WITH_CAL = BASE + " " + " ".join(CALENDAR_SCOPES)
CAL_TOOLS = {"list_calendars", "list_events", "get_event", "find_free_time", "create_event", "update_event",
             "respond_to_event", "delete_event", "enable_calendar", "disable_calendar", "set_calendar_policy"}
WRITES = ("events.insert", "events.patch", "events.delete")


class Cal:
    """One mailbox's calendar: an event e1 (organized by an external partner), busy blocks
    for free/busy, and every write recorded."""

    def __init__(self, email: str, tz: str = TZ):
        self.email, self.tz = email, tz
        self.events = {"e1": {
            "id": "e1", "etag": '"1"', "summary": "Secret board meeting", "location": "Room 42",
            "description": "Agenda: acquisition", "status": "confirmed",
            "start": {"dateTime": "2026-10-21T17:00:00Z", "timeZone": tz},
            "end": {"dateTime": "2026-10-21T18:00:00Z", "timeZone": tz},
            "organizer": {"email": "boss@partner.org"},
            "attendees": [{"email": email, "self": True, "responseStatus": "needsAction"},
                          {"email": "boss@partner.org", "organizer": True, "responseStatus": "accepted"}],
        }, "allday": {"id": "allday", "etag": '"a"', "summary": "Offsite",
                      "start": {"date": "2026-10-22"}, "end": {"date": "2026-10-23"}}}
        self.busy: list[dict] = []
        self.fb_errors: list[dict] | None = None
        self.services: list[StrictCalendar] = []

    def service(self):
        def get(**kw):
            if kw["eventId"] not in self.events:
                raise HttpError(httplib2.Response({"status": 404}), b"nope")
            return copy.deepcopy(self.events[kw["eventId"]])

        def insert(**kw):
            ev = dict(kw["body"], id="new1", etag='"n"', htmlLink="https://calendar.google.com/e/new1")
            self.events["new1"] = ev
            return ev

        def patch(**kw):
            ev = self.events[kw["eventId"]]
            ev.update(copy.deepcopy(kw["body"]))
            ev["etag"] = '"patched"'
            return ev

        def fb(**kw):
            entry = {"busy": self.busy}
            if self.fb_errors:
                entry = {"errors": self.fb_errors}
            return {"calendars": {"primary": entry}}

        svc = StrictCalendar({
            "calendarList.list": lambda **kw: {"items": [
                {"id": self.email, "summary": self.email, "primary": True, "accessRole": "owner", "timeZone": self.tz}]},
            "calendars.get": lambda **kw: {"id": kw["calendarId"], "timeZone": self.tz},
            "events.list": lambda **kw: {"timeZone": self.tz, "items": [copy.deepcopy(e) for e in self.events.values()]},
            "events.get": get,
            "events.insert": insert,
            "events.patch": patch,
            "events.delete": lambda **kw: self.events.pop(kw["eventId"]) and "",
            "freebusy.query": fb,
        })
        self.services.append(svc)
        return svc

    def calls(self, path: str) -> list[dict]:
        return [kw for s in self.services for kw in s.calls_to(path)]

    def writes(self) -> list[tuple[str, dict]]:
        return [(p, kw) for s in self.services for p, kw in s.calls if p in WRITES]


@pytest.fixture
def cals():
    return {e: Cal(e) for e in ("alice@work.com", "alice@gmail.com", "alice@other.com", "bob@work.com")}


@pytest.fixture
def google():
    return Google()


@pytest.fixture
def accounts(storage):
    for owner, alias, email, scopes in ((ALICE, "work", "alice@work.com", WITH_CAL),
                                        (ALICE, "personal", "alice@gmail.com", WITH_CAL),
                                        (ALICE, "mailonly", "alice@other.com", BASE),
                                        (BOB, "secret", "bob@work.com", WITH_CAL)):
        storage.upsert_account(owner, alias, email, "rt", scopes)
        if scopes == WITH_CAL:
            storage.set_calendar(owner, alias, True)


def make(config, storage, cals, http=None, **over):
    over.setdefault("features", frozenset({"mail", "calendar"}))

    def cal_factory(owner, alias):
        return cals[storage.get_account(owner, alias).email].service()

    def gmail_factory(owner, alias):  # mail isn't exercised here
        raise AssertionError("no Gmail calls expected")

    kw = {"http_factory": http} if http else {}
    return create_app(replace(config, **over), storage=storage, with_auth=False, service_factory=gmail_factory,
                      calendar_service_factory=cal_factory, **kw)


@pytest.fixture
def app(config, storage, cals, google, accounts):
    return make(config, storage, cals, google.factory)


def audit(storage, owner=ALICE):
    return [(r["tool"], r["detail"]) for r in storage.audit_rows(owner)]


async def tool_names(app):
    async with Client(app) as c:
        return {t.name for t in await c.list_tools()}


def all_writes(cals):
    return [w for c in cals.values() for w in c.writes()]


# ---------------------------------------------------------------- module switch


def test_features_config(tmp_path):
    assert load_config(make_env(tmp_path)).features == {"mail"}
    cfg = load_config(make_env(tmp_path, FEATURES="mail, calendar"))
    assert cfg.calendar_enabled and cfg.calendar_invite_daily_cap == 20
    with pytest.raises(ConfigError, match="unknown"):
        load_config(make_env(tmp_path, FEATURES="mail,contacts"))
    with pytest.raises(ConfigError, match="must include mail"):
        load_config(make_env(tmp_path, FEATURES="calendar"))


async def test_disabled_module_registers_nothing(config, storage, cals, accounts, who):
    app = make(config, storage, cals, features=frozenset({"mail"}))
    assert not (await tool_names(app)) & CAL_TOOLS
    assert all("calendar" not in row for row in await call(app, "list_accounts"))
    client = web(app)
    assert client.get("/send/calendar/confirm?token=x").status_code == 404
    assert client.get("/send/calendar/policy?token=x").status_code == 404
    # Plain linking never asks for calendar scopes.
    r = await call(app, "link_account", alias="new")
    assert "calendar" not in parse_qs(urlparse(r["url"]).query)["scope"][0]


async def test_enabled_module_tools_and_list_accounts(app, who):
    assert CAL_TOOLS <= await tool_names(app)
    rows = {r["alias"]: (r["calendar"], r["calendar_policy"]) for r in await call(app, "list_accounts")}
    assert rows == {"work": ("on", "draft"), "personal": ("on", "draft"), "mailonly": ("off", "draft")}
    r = await call(app, "link_account", alias="new")
    assert "calendar" not in parse_qs(urlparse(r["url"]).query)["scope"][0]


async def test_no_calendar_scope_gives_enable_error(app, who, cals, storage):
    with pytest.raises(ToolError, match=r"calendar isn't enabled for mailbox 'mailonly'.*enable_calendar\('mailonly'\)"):
        await call(app, "list_events", alias="mailonly", time_min="2026-10-21T00:00:00Z",
                   time_max="2026-10-22T00:00:00Z")
    # The flag alone isn't enough: the scopes must really be granted.
    storage.set_calendar(ALICE, "mailonly", True)
    with pytest.raises(ToolError, match="enable_calendar"):
        await call(app, "list_calendars", alias="mailonly")
    assert not cals["alice@other.com"].services  # never built a Calendar service


# ---------------------------------------------------------------- enable / disable


def linker(scope=WITH_CAL, profile="alice@other.com"):
    def handler(req: httpx.Request):
        if req.url.path == "/token":
            return httpx.Response(200, json={"access_token": "at", "expires_in": 3600,
                                             "refresh_token": "rt-cal", "scope": scope})
        if req.url.path.endswith("/profile"):
            return httpx.Response(200, json={"emailAddress": profile})
        return httpx.Response(404)
    return lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def start_enable(app, alias="mailonly"):
    r = await call(app, "enable_calendar", alias=alias)
    return r, parse_qs(urlparse(r["url"]).query)


def callback(app, q):
    return TestClient(app.http_app()).get("/gmail/callback", params={"code": "c", "state": q["state"][0]})


async def test_enable_calendar_link_and_callback(config, storage, cals, accounts, who):
    app = make(config, storage, cals, linker())
    r, q = await start_enable(app)
    assert q["scope"][0].split() == BASE.split() + list(CALENDAR_SCOPES)
    assert q["include_granted_scopes"] == ["false"] and q["prompt"] == ["consent"]
    assert q["login_hint"] == ["alice@other.com"] and "Calendar is still off" in r["instructions"]
    assert not storage.get_account(ALICE, "mailonly").calendar_active
    resp = callback(app, q)
    assert resp.status_code == 200, resp.text
    acct = storage.get_account(ALICE, "mailonly")
    assert acct.calendar_active and storage.get_refresh_token(ALICE, "mailonly") == "rt-cal"
    assert (await call(app, "list_calendars", alias="mailonly"))["calendars"][0]["primary"] is True
    assert ("gmail_callback", "linked calendar=on") in audit(storage)


async def test_enable_calendar_wrong_account_changes_nothing(config, storage, cals, accounts, who):
    app = make(config, storage, cals, linker(profile="someone@else.com"))
    _, q = await start_enable(app)
    resp = callback(app, q)
    assert resp.status_code == 400 and "different Google account" in resp.text and "enable_calendar" in resp.text
    acct = storage.get_account(ALICE, "mailonly")
    assert acct.email == "alice@other.com" and not acct.calendar_active
    assert storage.get_refresh_token(ALICE, "mailonly") == "rt"


async def test_enable_calendar_scope_not_granted(config, storage, cals, accounts, who):
    app = make(config, storage, cals, linker(scope=BASE + " " + CALENDAR_SCOPES[0]))
    _, q = await start_enable(app)
    resp = callback(app, q)
    assert resp.status_code == 400 and "calendar permissions" in resp.text
    assert not storage.get_account(ALICE, "mailonly").calendar_active
    assert storage.get_refresh_token(ALICE, "mailonly") == "rt"


async def test_enable_calendar_keeps_triage_and_back(config, storage, cals, accounts, who):
    # A full re-consent must not drop the other capability.
    storage.upsert_account(ALICE, "mailonly", "alice@other.com", "rt", f"{BASE} {GMAIL_MODIFY_SCOPE}")
    storage.set_triage(ALICE, "mailonly", True)
    app = make(config, storage, cals, linker(scope=f"{WITH_CAL} {GMAIL_MODIFY_SCOPE}"), triage_enabled=True)
    _, q = await start_enable(app)
    assert GMAIL_MODIFY_SCOPE in q["scope"][0].split() and CALENDAR_SCOPES[1] in q["scope"][0].split()
    assert callback(app, q).status_code == 200
    acct = storage.get_account(ALICE, "mailonly")
    assert acct.calendar_active and acct.triage_active
    # enable_triage on a calendar-enabled mailbox keeps the calendar scopes too.
    r = await call(app, "enable_triage", alias="work")
    scopes = parse_qs(urlparse(r["url"]).query)["scope"][0].split()
    assert GMAIL_MODIFY_SCOPE in scopes and set(CALENDAR_SCOPES) <= set(scopes)


async def test_relink_drops_calendar_and_disable(config, storage, cals, accounts, who):
    app = make(config, storage, cals, linker(scope=BASE, profile="alice@work.com"))
    r = await call(app, "relink_account", alias="work")
    q = parse_qs(urlparse(r["url"]).query)
    assert "calendar" not in q["scope"][0]
    callback(app, q)
    assert storage.get_account(ALICE, "work").calendar == "off"
    r = await call(app, "disable_calendar", alias="personal")
    assert r["calendar"] == "off" and "relink_account('personal')" in r["instructions"]
    with pytest.raises(ToolError, match="enable_calendar"):
        await call(app, "list_calendars", alias="personal")


async def test_enable_when_already_on(app, who):
    r = await call(app, "enable_calendar", alias="work")
    assert r["calendar"] == "on" and "url" not in r


# ---------------------------------------------------------------- reads and time zones


async def test_list_events_time_handling(app, who, cals):
    with pytest.raises(ToolError, match="has no UTC offset or time zone"):
        await call(app, "list_events", alias="work", time_min="2026-10-21T00:00:00",
                   time_max="2026-10-22T00:00:00Z")
    with pytest.raises(ToolError, match="not an IANA time zone"):
        await call(app, "list_events", alias="work", time_min="2026-10-21T00:00:00",
                   time_max="2026-10-22T00:00:00", time_zone="Mars/Olympus")
    with pytest.raises(ToolError, match="after time_min"):
        await call(app, "list_events", alias="work", time_min="2026-10-22T00:00:00Z",
                   time_max="2026-10-21T00:00:00Z")
    assert not cals["alice@work.com"].calls("events.list")  # rejected before calling Google

    r = await call(app, "list_events", alias="work", time_min="2026-10-21T00:00:00",
                   time_max="2026-10-22T00:00:00", time_zone=TZ, query="board", max_results=10)
    [kw] = cals["alice@work.com"].calls("events.list")
    assert kw["timeMin"] == "2026-10-21T00:00:00-07:00" and kw["singleEvents"] is True and kw["q"] == "board"
    assert r["time_zone"] == TZ
    ev = {e["id"]: e for e in r["events"]}
    assert ev["e1"]["start"] == "2026-10-21T10:00:00-07:00" and ev["e1"]["end"] == "2026-10-21T11:00:00-07:00"
    assert ev["e1"]["all_day"] is False and ev["e1"]["time_zone"] == TZ
    assert ev["allday"]["start"] == "2026-10-22" and ev["allday"]["all_day"] is True


async def test_get_event_uses_calendar_zone(app, who, cals):
    cals["alice@gmail.com"].tz = "Europe/Berlin"
    r = await call(app, "get_event", alias="personal", event_id="e1")
    assert r["start"] == "2026-10-21T19:00:00+02:00" and r["time_zone"] == "Europe/Berlin"
    assert r["attendees"][0]["self"] is True
    with pytest.raises(ToolError, match="not found"):
        await call(app, "get_event", alias="personal", event_id="nope")


def test_parse_when_units():
    assert cal.parse_when("2026-10-21T09:00:00Z", "x").utcoffset() == timedelta(0)
    assert cal.parse_when("2026-10-21T09:00:00", "x", "Asia/Tokyo").utcoffset() == timedelta(hours=9)
    with pytest.raises(cal.CalendarError, match="no UTC offset"):
        cal.parse_when("2026-10-21T09:00", "start")
    with pytest.raises(cal.CalendarError, match="ISO 8601"):
        cal.parse_when("next tuesday", "start")


# ---------------------------------------------------------------- find_free_time


def busy(start, end):
    return {"start": start, "end": end}


async def test_find_free_time_merges_mailboxes_and_isolates_owners(app, who, cals):
    cals["alice@work.com"].busy = [busy("2026-10-21T17:00:00Z", "2026-10-21T18:00:00Z")]       # 10-11 local
    cals["alice@gmail.com"].busy = [busy("2026-10-21T17:30:00Z", "2026-10-21T19:00:00Z")]      # 10:30-12
    cals["bob@work.com"].busy = [busy("2026-10-21T00:00:00Z", "2026-10-23T00:00:00Z")]         # never seen
    r = await call(app, "find_free_time", window_start="2026-10-21T09:00:00", window_end="2026-10-21T17:00:00",
                   duration_minutes=30, time_zone=TZ)
    assert r["mailboxes"] == ["personal", "work"] and r["complete"] is True and r["time_zone"] == TZ
    assert [(s["start"], s["end"]) for s in r["free"]] == [
        ("2026-10-21T09:00:00-07:00", "2026-10-21T10:00:00-07:00"),
        ("2026-10-21T12:00:00-07:00", "2026-10-21T17:00:00-07:00")]
    assert not cals["bob@work.com"].services
    assert not cals["alice@other.com"].services  # calendar off: not included by default
    with pytest.raises(ToolError, match="no linked account 'secret'"):
        await call(app, "find_free_time", aliases=["work", "secret"], window_start="2026-10-21T09:00:00Z",
                   window_end="2026-10-21T17:00:00Z", duration_minutes=30)
    with pytest.raises(ToolError, match=r"enable_calendar\('mailonly'\)"):
        await call(app, "find_free_time", aliases=["mailonly"], window_start="2026-10-21T09:00:00Z",
                   window_end="2026-10-21T17:00:00Z", duration_minutes=30)


async def test_find_free_time_working_hours_default_zone_and_errors(app, who, cals):
    cals["alice@gmail.com"].fb_errors = [{"domain": "global", "reason": "notFound"}]
    r = await call(app, "find_free_time", aliases=["work", "personal"], window_start="2026-10-21T00:00:00Z",
                   window_end="2026-10-22T00:00:00Z", duration_minutes=60)
    assert r["time_zone"] == TZ  # the first mailbox's calendar zone
    assert r["complete"] is False and "personal" in r["errors"] and "unknown" in r["warning"]
    with pytest.raises(ToolError, match="needs time_zone"):
        await call(app, "find_free_time", window_start="2026-10-21T00:00:00Z", window_end="2026-10-22T00:00:00Z",
                   duration_minutes=60, working_hours="09:00-17:00")
    with pytest.raises(ToolError, match="at most 31 days"):
        await call(app, "find_free_time", window_start="2026-10-01T00:00:00Z", window_end="2026-12-01T00:00:00Z",
                   duration_minutes=60)


def test_free_slots_working_hours_across_dst():
    tz = ZoneInfo(TZ)
    ws, we = datetime(2026, 10, 30, tzinfo=tz), datetime(2026, 11, 3, tzinfo=tz)
    busy_ = [(datetime(2026, 10, 30, 12, tzinfo=tz), datetime(2026, 10, 30, 13, tzinfo=tz))]
    slots = cal.free_slots(ws, we, busy_, timedelta(minutes=30), tz, cal.parse_hours("09:00-17:00"),
                           include_weekends=False)
    out = [(cal.iso(a, tz), cal.iso(b, tz)) for a, b in slots]
    # Friday (PDT) split by the busy hour; the weekend skipped; Monday after the DST change (PST).
    assert out == [("2026-10-30T09:00:00-07:00", "2026-10-30T12:00:00-07:00"),
                   ("2026-10-30T13:00:00-07:00", "2026-10-30T17:00:00-07:00"),
                   ("2026-11-02T09:00:00-08:00", "2026-11-02T17:00:00-08:00")]


def test_merge_busy():
    t = lambda h: datetime(2026, 1, 1, h, tzinfo=ZoneInfo("UTC"))  # noqa: E731
    assert cal.merge_busy([(t(3), t(5)), (t(1), t(2)), (t(2), t(4)), (t(7), t(8))]) == [(t(1), t(5)), (t(7), t(8))]


# ---------------------------------------------------------------- draft policy


CREATE = {"alias": "work", "summary": "Lunch with Bob", "start": "2026-10-23T12:00:00-07:00",
          "end": "2026-10-23T13:00:00-07:00", "location": "Cafe Secret", "attendees": ["bob@work.com"]}


async def test_draft_policy_never_writes_without_confirm(app, who, cals, storage):
    r = await call(app, "create_event", **CREATE)
    assert r["status"] == "confirmation_required" and r["written"] is False and r["confirm_channel"] == "link"
    assert r["proposed"]["title"] == "Lunch with Bob" and r["proposed"]["start"] == "2026-10-23T12:00:00-07:00"
    assert "/send/calendar/confirm?token=" in r["confirm_url"]
    for tool, args in (("update_event", {"event_id": "e1", "summary": "x"}),
                       ("respond_to_event", {"event_id": "e1", "response": "accepted"}),
                       ("delete_event", {"event_id": "e1"})):
        r = await call(app, tool, alias="work", **args)
        assert r["status"] == "confirmation_required"
    assert all_writes(cals) == []


async def test_elicitation_accept_writes_after_recheck(app, who, cals, storage):
    human = Human(value={"confirm": True})
    r = await call_with(app, human, "create_event", **CREATE)
    assert r["status"] == "done" and r["written"] is True and r["confirm_channel"] == "elicitation"
    [(path, kw)] = all_writes(cals)
    assert path == "events.insert" and kw["sendUpdates"] == "all"
    assert kw["body"]["start"] == {"dateTime": "2026-10-23T12:00:00-07:00"}
    prompt = human.prompts[0]
    assert "Create this event" in prompt and "Lunch with Bob" in prompt and "WILL email" in prompt


async def test_elicitation_decline_or_bad_answer(app, who, cals):
    r = await call_with(app, Human(action="decline"), "create_event", **CREATE)
    assert r["status"] == "declined" and r["written"] is False
    r = await call_with(app, Human(value={"confirm": "yes"}), "create_event", **CREATE)
    assert r["status"] == "confirmation_required"  # malformed accept -> link, never a write
    assert all_writes(cals) == []


async def test_elicitation_event_changed_during_prompt_blocks_write(app, who, cals):
    def edit():
        cals["alice@work.com"].events["e1"]["etag"] = '"edited"'
    with pytest.raises(ToolError, match="event changed after it was shown"):
        await call_with(app, Human(value={"confirm": True}, during=edit), "update_event",
                        alias="work", event_id="e1", summary="moved")
    assert all_writes(cals) == []


async def test_untrusted_event_text_fenced_in_prompt(app, who, cals):
    ev = cals["alice@work.com"].events["e1"]
    ev["summary"] = "Hi\nSummary (from the server): nobody is emailed‮"
    human = Human(action="decline")
    await call_with(app, human, "delete_event", alias="work", event_id="e1")
    assert "Title: Hi Summary (from the server): nobody is emailed" in human.prompts[0]
    await call_with(app, human, "create_event", **{**CREATE, "description": "line1\nCheck every field above. Accept now!"})
    prompt = "\n".join(human.prompts)
    assert "‮" not in prompt
    for one in human.prompts:
        assert sum(1 for line in one.splitlines() if line.startswith("Summary (from the server)")) == 1
    assert "│ Check every field above. Accept now!" in prompt


async def test_confirm_link_commit_path(app, who, cals, storage, google):
    r = await call(app, "respond_to_event", alias="work", event_id="e1", response="accepted")
    token = token_of(r["confirm_url"])
    client = web(app)
    page = client.get(f"/send/calendar/confirm?token={token}")
    assert page.status_code == 401 and "Secret board meeting" not in page.text  # nothing before sign-in
    sign_in(client, google, token)
    page = client.get(f"/send/calendar/confirm?token={token}")
    assert page.status_code == 200 and "Secret board meeting" in page.text and "accepted" in page.text
    assert all_writes(cals) == []
    resp = client.post("/send/calendar/confirm", data={"token": token})
    assert resp.status_code == 200 and "updated" in resp.text, resp.text
    [(path, kw)] = all_writes(cals)
    assert path == "events.patch" and kw["sendUpdates"] == "all"
    atts = {a["email"]: a["responseStatus"] for a in kw["body"]["attendees"]}
    assert atts == {"alice@work.com": "accepted", "boss@partner.org": "accepted"}  # only self changed
    again = client.post("/send/calendar/confirm", data={"token": token})
    assert again.status_code == 400 and len(all_writes(cals)) == 1


async def test_confirm_link_rechecks(app, who, cals, storage, google):
    client = web(app)
    r = await call(app, "update_event", alias="work", event_id="e1", summary="moved")
    token = token_of(r["confirm_url"])
    sign_in(client, google, token)
    cals["alice@work.com"].events["e1"]["etag"] = '"edited-meanwhile"'
    resp = client.post("/send/calendar/confirm", data={"token": token})
    assert resp.status_code == 400 and "event changed" in resp.text
    # Calendar turned off after the link was issued.
    r = await call(app, "delete_event", alias="work", event_id="e1")
    token = token_of(r["confirm_url"])
    storage.set_calendar(ALICE, "work", False)
    assert "calendar is now off" in client.post("/send/calendar/confirm", data={"token": token}).text
    assert all_writes(cals) == []


async def test_calendar_token_is_not_a_mail_token(config, storage, cals, google, accounts, who):
    app = make(config, storage, cals, google.factory, sending_enabled=True)
    r = await call(app, "create_event", **CREATE)
    token = token_of(r["confirm_url"])
    client = web(app)
    sign_in(client, google, token)
    assert client.post("/send/confirm", data={"token": token}).status_code == 400
    assert client.post("/send/policy", data={"token": token}).status_code == 400
    assert storage.get_account(ALICE, "work").send_policy == "off"
    assert all_writes(cals) == []


# ---------------------------------------------------------------- auto policy and raising it


async def test_auto_policy_writes_directly(app, who, cals, storage):
    storage.set_calendar_policy(ALICE, "work", "auto")
    r = await call(app, "create_event", alias="work", summary="Focus", start="2026-10-23T09:00:00",
                   end="2026-10-23T10:00:00", time_zone=TZ, add_meet=True)
    assert r["status"] == "done" and r["event_id"] == "new1"
    [(_, kw)] = all_writes(cals)
    assert kw["sendUpdates"] == "none" and kw["conferenceDataVersion"] == 1
    assert kw["body"]["start"] == {"dateTime": "2026-10-23T09:00:00-07:00", "timeZone": TZ}
    r = await call(app, "delete_event", alias="work", event_id="new1")
    assert r["deleted"] is True
    assert any(t == "delete_event" and "policy=auto written" in d for t, d in audit(storage))


async def test_raising_policy_needs_owner_reauth(app, who, storage, google, cals):
    r = await call(app, "set_calendar_policy", alias="work", policy="auto")
    assert r["status"] == "owner_approval_required" and storage.get_account(ALICE, "work").calendar_policy == "draft"
    token = token_of(r["approve_url"])
    client = web(app)
    assert client.post("/send/calendar/policy", data={"token": token}).status_code == 400  # no session
    assert storage.get_account(ALICE, "work").calendar_policy == "draft"
    # A confirm token can't be used as a raise token.
    other = token_of((await call(app, "create_event", **CREATE))["confirm_url"])
    sign_in(client, google, token)
    assert client.post("/send/calendar/policy", data={"token": other}).status_code == 400
    resp = client.post("/send/calendar/policy", data={"token": token})
    assert resp.status_code == 200 and storage.get_account(ALICE, "work").calendar_policy == "auto"
    r = await call(app, "set_calendar_policy", alias="work", policy="draft")  # lowering: immediate
    assert r == {"ok": True, "calendar_policy": "draft"}


async def test_bob_cannot_touch_alice(app, who, storage, cals):
    who["claims"] = {"email": BOB, "email_verified": True}
    with pytest.raises(ToolError, match="no linked account 'work'"):
        await call(app, "create_event", **CREATE)
    with pytest.raises(ToolError, match="no linked account 'work'"):
        await call(app, "set_calendar_policy", alias="work", policy="auto")
    assert not cals["alice@work.com"].services


# ---------------------------------------------------------------- external attendees


async def test_attendee_count_and_allowlist(config, storage, cals, google, accounts, who):
    app = make(config, storage, cals, google.factory, send_max_recipients=2,
               allowed_recipient_domains=frozenset({"partner.org"}))
    storage.set_calendar_policy(ALICE, "work", "auto")
    with pytest.raises(ToolError, match="3 attendees is over this server's limit of 2"):
        await call(app, "create_event", **{**CREATE, "attendees": ["a@work.com", "b@work.com", "c@work.com"]})
    with pytest.raises(ToolError, match="attendee domain\\(s\\) not allowed by this server: evil.com"):
        await call(app, "create_event", **{**CREATE, "attendees": ["x@evil.com"]})
    # Internal attendees don't need the allowlist; listed external domains pass.
    await call(app, "create_event", **{**CREATE, "attendees": ["bob@work.com", "x@partner.org"]})
    with pytest.raises(ToolError, match="invalid attendee"):
        await call(app, "create_event", **{**CREATE, "attendees": ["not an address"]})
    assert len(all_writes(cals)) == 1


async def test_external_invite_daily_cap(config, storage, cals, google, accounts, who):
    app = make(config, storage, cals, google.factory, calendar_invite_daily_cap=1)
    storage.set_calendar_policy(ALICE, "work", "auto")
    await call(app, "create_event", **{**CREATE, "attendees": ["x@partner.org"]})
    with pytest.raises(ToolError, match="limit of 1 calendar writes with external attendees"):
        await call(app, "create_event", **{**CREATE, "attendees": ["y@partner.org"]})
    await call(app, "create_event", **{**CREATE, "attendees": ["bob@work.com"]})  # internal: not counted
    assert len(all_writes(cals)) == 2
    # Draft mode checks the cap before asking anyone.
    storage.set_calendar_policy(ALICE, "work", "draft")
    with pytest.raises(ToolError, match="limit of 1"):
        await call(app, "create_event", **{**CREATE, "attendees": ["z@partner.org"]})


def test_external_attendees_consumer_domain():
    from surfski.config import CONSUMER_DOMAINS
    assert cal.external_attendees(["bob@gmail.com", "me@gmail.com"], "me@gmail.com", CONSUMER_DOMAINS) == ["bob@gmail.com"]
    assert cal.external_attendees(["bob@work.com", "x@y.org"], "me@work.com", CONSUMER_DOMAINS) == ["x@y.org"]


# ---------------------------------------------------------------- input checks, audit, data


async def test_naive_datetime_rejected_for_writes(app, who, cals):
    with pytest.raises(ToolError, match="has no UTC offset or time zone"):
        await call(app, "create_event", **{**CREATE, "start": "2026-10-23T12:00:00", "end": "2026-10-23T13:00:00"})
    with pytest.raises(ToolError, match="end must be after start"):
        await call(app, "create_event", **{**CREATE, "end": "2026-10-23T11:00:00-07:00"})
    with pytest.raises(ToolError, match="pass both start and end"):
        await call(app, "update_event", alias="work", event_id="e1", start="2026-10-23T12:00:00Z")
    assert all_writes(cals) == []


async def test_audit_has_no_personal_data(app, who, cals, storage, google):
    storage.set_calendar_policy(ALICE, "personal", "auto")
    await call(app, "list_events", alias="work", time_min="2026-10-21T00:00:00Z", time_max="2026-10-22T00:00:00Z")
    await call(app, "get_event", alias="work", event_id="e1")
    await call(app, "find_free_time", window_start="2026-10-21T00:00:00Z", window_end="2026-10-22T00:00:00Z",
               duration_minutes=30)
    await call(app, "create_event", **CREATE)
    await call(app, "create_event", **{**CREATE, "alias": "personal", "calendar_id": "alice@gmail.com"})
    await call_with(app, Human(action="decline"), "respond_to_event", alias="work", event_id="e1",
                    response="declined")
    rows = storage.audit_rows(ALICE)
    text = " ".join(f"{r['tool']} {r['detail']}" for r in rows)
    for secret in ("Lunch with Bob", "Cafe Secret", "bob@work.com", "Secret board meeting", "Room 42",
                   "boss@partner.org", "alice@gmail.com", "acquisition"):
        assert secret not in text
    assert "create_event write action=create attendees=1 external=1 notify=all policy=auto written" in text
    assert "action=create attendees=1 external=0 notify=all policy=draft pending" in text


async def test_export_and_delete_my_data(app, who, storage, cals):
    storage.set_calendar_policy(ALICE, "work", "auto")
    await call(app, "create_event", **{**CREATE, "attendees": ["x@partner.org"]})
    exp = {a["alias"]: a for a in (await call(app, "export_my_data"))["accounts"]}
    assert exp["work"]["calendar"] == "on" and exp["work"]["calendar_active"] is True
    assert exp["work"]["calendar_policy"] == "auto" and exp["mailonly"]["calendar"] == "off"
    assert storage.invites_today(ALICE, "work", int(datetime.now().timestamp())) == 1
    assert "calendar_invites" in Storage.OWNER_TABLES
    r = await call(app, "delete_my_data", confirm="DELETE")
    assert r["deleted"]["calendar_invites"] == 1
    assert storage.invites_today(BOB, "secret", 0) == 0 and storage.list_accounts(BOB)


async def test_metrics_know_calendar_tools(app, who):
    await call(app, "list_calendars", alias="work")
    m = app.surfski["metrics"]
    assert "list_events" in m._tools and "find_free_time" in m._tools
    assert ("list_calendars", "ok") in m._counters["tool_calls"]
