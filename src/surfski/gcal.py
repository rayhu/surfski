"""Google Calendar module (#19): time handling, event shaping, free/busy merging and the
Calendar v3 calls. Pure functions plus thin `op_*` wrappers that run in a worker thread,
like gmail.py. Named gcal so it can't shadow the stdlib `calendar` module."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

UTC = ZoneInfo("UTC")

from . import gmail as g

MAX_WINDOW_DAYS = 31
MAX_FREE_SLOTS = 50
MAX_DESCRIPTION_CHARS = 2000
MAX_LIST_RESULTS = 100
RESPONSES = {"accepted", "declined", "tentative"}
_ADDR_RE = re.compile(r"^[^@\s<>(),;:\\\"\[\]]+@[A-Za-z0-9.-]+\.[A-Za-z0-9-]+$")
_HOURS_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)-([01]\d|2[0-3]):([0-5]\d)$")


class CalendarError(g.GmailError):
    """User-facing calendar failure."""


def map_error(exc: Exception, alias: str) -> g.GmailError:
    """Gmail's mapping, reworded for Calendar; a 403 usually means a missing scope."""
    from googleapiclient.errors import HttpError

    if isinstance(exc, HttpError) and getattr(exc.resp, "status", None) == 412:
        return CalendarError("the event changed after it was shown for confirmation (Google refused the "
                             "stale version); nothing was changed. Ask again to re-confirm.")
    if isinstance(exc, HttpError) and getattr(exc.resp, "status", None) == 403:
        return CalendarError(
            f"Google denied calendar access for '{alias}' (permission, sharing or Workspace "
            f"policy). If the calendar permission was removed, call enable_calendar('{alias}').")
    err = g.map_google_error(exc, alias)
    return CalendarError(str(err).replace("Gmail", "Google Calendar"))


# ---------------------------------------------------------------- time


def zone(name: str | None, field: str = "time_zone") -> ZoneInfo:
    if not name or not isinstance(name, str):
        raise CalendarError(f"{field} must be an IANA time zone like 'America/Los_Angeles'")
    try:
        return ZoneInfo(name.strip())
    except (ZoneInfoNotFoundError, ValueError):
        raise CalendarError(f"{field} {name!r} is not an IANA time zone (e.g. 'Europe/Berlin')") from None


def parse_when(value: str, field: str, tz: str | None = None) -> datetime:
    """An ISO 8601 date-time with an explicit offset ('Z' or ±HH:MM), or a naive one
    together with an IANA `tz`. Anything else is rejected: guessing a zone would put
    events at the wrong hour."""
    try:
        dt = datetime.fromisoformat((value or "").strip())
    except ValueError:
        raise CalendarError(f"{field} {value!r} is not an ISO 8601 date-time "
                            "(e.g. 2026-10-21T09:00:00-07:00)") from None
    if dt.tzinfo is None:
        if not tz:
            raise CalendarError(
                f"{field} {value!r} has no UTC offset or time zone. Pass an explicit offset "
                "(e.g. 2026-10-21T09:00:00-07:00 or ...Z) or a time_zone like 'America/Los_Angeles'.")
        dt = dt.replace(tzinfo=zone(tz))
    return dt


def parse_day(value: str, field: str) -> date:
    try:
        return date.fromisoformat((value or "").strip())
    except ValueError:
        raise CalendarError(f"{field} {value!r} must be a date YYYY-MM-DD for an all-day event") from None


def utc(dt: datetime) -> datetime:
    """All interval arithmetic happens in UTC: subtracting two datetimes that share a
    ZoneInfo is wall-clock arithmetic in Python and is wrong across DST changes."""
    return dt.astimezone(UTC)


def minutes_between(a: datetime, b: datetime) -> int:
    return int((utc(b) - utc(a)).total_seconds() // 60)


def iso(dt: datetime, tz: ZoneInfo) -> str:
    return dt.astimezone(tz).isoformat(timespec="seconds")


def _event_time(t: dict | None, cal_tz: ZoneInfo) -> tuple[str | None, bool]:
    """(ISO string, all_day) for an event start/end. All-day events carry a date."""
    t = t or {}
    if t.get("date"):
        return t["date"], True
    if t.get("dateTime"):
        try:
            return iso(datetime.fromisoformat(t["dateTime"]), cal_tz), False
        except ValueError:
            return t["dateTime"], False
    return None, False


def _safe_zone(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name) if name else ZoneInfo("UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def public_event(ev: dict, cal_zone: str | None, max_description: int = MAX_DESCRIPTION_CHARS) -> dict:
    tz = _safe_zone(cal_zone)
    start, all_day = _event_time(ev.get("start"), tz)
    end, _ = _event_time(ev.get("end"), tz)
    desc = ev.get("description") or ""
    meet = ev.get("hangoutLink") or next(
        (e.get("uri") for e in (ev.get("conferenceData") or {}).get("entryPoints", [])
         if e.get("entryPointType") == "video"), None)
    out = {
        "id": ev.get("id"),
        "status": ev.get("status"),
        "summary": ev.get("summary") or "",
        "start": start,
        "end": end,
        "all_day": all_day,
        "time_zone": cal_zone or "UTC",
        "event_time_zone": (ev.get("start") or {}).get("timeZone"),
        "location": ev.get("location"),
        "description": desc[:max_description],
        "description_truncated": len(desc) > max_description,
        "organizer": (ev.get("organizer") or {}).get("email"),
        "attendees": [{"email": a.get("email"), "response_status": a.get("responseStatus"),
                       "organizer": bool(a.get("organizer")), "self": bool(a.get("self")),
                       "optional": bool(a.get("optional"))} for a in ev.get("attendees") or []],
        "meet_link": meet,
        "html_link": ev.get("htmlLink"),
        "recurring_event_id": ev.get("recurringEventId"),
    }
    return {k: v for k, v in out.items() if v is not None}


# ---------------------------------------------------------------- free/busy


def merge_busy(intervals: list[tuple[datetime, datetime]]) -> list[tuple[datetime, datetime]]:
    """Union of busy intervals (sorted, overlapping or touching blocks joined), in UTC."""
    merged: list[tuple[datetime, datetime]] = []
    for s, e in sorted((utc(s), utc(e)) for s, e in intervals if utc(e) > utc(s)):
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged


def parse_hours(value: str | None) -> tuple[time, time] | None:
    if value is None or not value.strip():
        return None
    m = _HOURS_RE.match(value.strip())
    if not m:
        raise CalendarError("working_hours must look like '09:00-17:00' (24 h, start before end)")
    start, end = time(int(m[1]), int(m[2])), time(int(m[3]), int(m[4]))
    if end <= start:
        raise CalendarError("working_hours must end after it starts (e.g. '09:00-17:00')")
    return start, end


def free_slots(window_start: datetime, window_end: datetime, busy: list[tuple[datetime, datetime]],
               duration: timedelta, tz: ZoneInfo, hours: tuple[time, time] | None = None,
               include_weekends: bool = True) -> list[tuple[datetime, datetime]]:
    """Free blocks of at least `duration` inside the window, as UTC datetimes. With
    working hours, each local day in `tz` contributes its own [start, end) wall-clock
    segment, so DST changes shift the UTC instants, not the local hours. Every comparison
    and subtraction is done in UTC (real elapsed time)."""
    window_start, window_end = utc(window_start), utc(window_end)
    if hours is None:
        segments = [(window_start, window_end)]
    else:
        segments = []
        day, last = window_start.astimezone(tz).date(), window_end.astimezone(tz).date()
        while day <= last:
            if include_weekends or day.weekday() < 5:
                s = max(utc(datetime.combine(day, hours[0], tzinfo=tz)), window_start)
                e = min(utc(datetime.combine(day, hours[1], tzinfo=tz)), window_end)
                if s < e:
                    segments.append((s, e))
            day += timedelta(days=1)
    merged = merge_busy(busy)
    out: list[tuple[datetime, datetime]] = []
    for s, e in segments:
        cur = s
        for bs, be in merged:
            if be <= cur:
                continue
            if bs >= e:
                break
            if bs - cur >= duration:
                out.append((cur, bs))
            cur = max(cur, be)
            if cur >= e:
                break
        if e - cur >= duration:
            out.append((cur, e))
    return out


# ---------------------------------------------------------------- attendees


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower()


def clean_attendees(raw: list[str] | None) -> list[str]:
    seen: list[str] = []
    for a in raw or []:
        a = (a or "").strip().lower()
        if not a:
            continue
        if not _ADDR_RE.match(a):
            raise CalendarError(f"invalid attendee address {a!r}")
        if a not in seen:
            seen.append(a)
    return seen


def external_attendees(attendees: list[str], mailbox: str, consumer_domains: frozenset[str]) -> list[str]:
    """Attendees outside the mailbox's own domain. On a public mail domain (gmail.com, …)
    everyone except the mailbox itself is external."""
    mailbox = mailbox.lower()
    own = domain_of(mailbox)
    return [a for a in attendees
            if a != mailbox and (own in consumer_domains or domain_of(a) != own)]


def check_attendees(attendees: list[str], external: list[str], *, max_attendees: int,
                    allowed_domains: frozenset[str]) -> None:
    if len(attendees) > max_attendees:
        raise CalendarError(f"{len(attendees)} attendees is over this server's limit of {max_attendees}")
    if allowed_domains:
        bad = sorted({domain_of(a) for a in external if domain_of(a) not in allowed_domains})
        if bad:
            raise CalendarError("attendee domain(s) not allowed by this server: " + ", ".join(bad)
                                + f" (allowed: {', '.join(sorted(allowed_domains))})")


def op_hash(op: dict) -> str:
    return hashlib.sha256(json.dumps(op, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ---------------------------------------------------------------- event bodies


def time_body(start: str, end: str, tz: str | None, all_day: bool) -> tuple[dict, dict, dict]:
    """(start, end, view) for an event body; view holds display strings for the human."""
    if all_day:
        s, e = parse_day(start, "start"), parse_day(end, "end")
        if e <= s:
            raise CalendarError("end must be after start (for all-day events, end is the day after the last day)")
        return {"date": s.isoformat()}, {"date": e.isoformat()}, {"start": s.isoformat(), "end": e.isoformat(),
                                                                  "time_zone": "all day"}
    s, e = parse_when(start, "start", tz), parse_when(end, "end", tz)
    if utc(e) <= utc(s):
        raise CalendarError("end must be after start")
    if utc(e) - utc(s) > timedelta(days=MAX_WINDOW_DAYS):
        raise CalendarError(f"an event can't be longer than {MAX_WINDOW_DAYS} days")
    out_tz = zone(tz) if tz else None
    sb = {"dateTime": s.isoformat(timespec="seconds")}
    eb = {"dateTime": e.isoformat(timespec="seconds")}
    if out_tz is not None:
        sb["timeZone"] = eb["timeZone"] = tz.strip()
    view_tz = out_tz or s.tzinfo
    return sb, eb, {"start": s.astimezone(view_tz).isoformat(timespec="seconds"),
                    "end": e.astimezone(view_tz).isoformat(timespec="seconds"),
                    "time_zone": tz.strip() if tz else "as given"}


def meet_request() -> dict:
    return {"createRequest": {"requestId": secrets.token_hex(12),
                              "conferenceSolutionKey": {"type": "hangoutsMeet"}}}


# ---------------------------------------------------------------- Calendar v3 calls


def op_list_calendars(svc) -> list[dict]:
    r = svc.calendarList().list(maxResults=250).execute()
    return [{"id": c.get("id"), "summary": c.get("summaryOverride") or c.get("summary") or "",
             "primary": bool(c.get("primary")), "access_role": c.get("accessRole"),
             "time_zone": c.get("timeZone")} for c in r.get("items", [])]


def op_calendar_zone(svc, calendar_id: str) -> str:
    return svc.calendars().get(calendarId=calendar_id).execute().get("timeZone") or "UTC"


def op_list_events(svc, calendar_id: str, tmin: datetime, tmax: datetime, query: str | None,
                   max_results: int, page_token: str | None) -> dict:
    kw: dict[str, Any] = {"calendarId": calendar_id, "timeMin": tmin.isoformat(), "timeMax": tmax.isoformat(),
                          "singleEvents": True, "orderBy": "startTime", "maxResults": max_results}
    if query:
        kw["q"] = query
    if page_token:
        kw["pageToken"] = page_token
    r = svc.events().list(**kw).execute()
    cal_zone = r.get("timeZone") or "UTC"
    out = {"calendar_id": calendar_id, "time_zone": cal_zone,
           "events": [public_event(e, cal_zone, 500) for e in r.get("items", [])]}
    if r.get("nextPageToken"):
        out["next_page_token"] = r["nextPageToken"]
    return out


def op_get_raw(svc, calendar_id: str, event_id: str) -> dict:
    return svc.events().get(calendarId=calendar_id, eventId=event_id).execute()


def op_get_event(svc, calendar_id: str, event_id: str) -> dict:
    cal_zone = op_calendar_zone(svc, calendar_id)
    return public_event(op_get_raw(svc, calendar_id, event_id), cal_zone)


def op_freebusy(svc, tmin: datetime, tmax: datetime) -> tuple[list[tuple[datetime, datetime]], list[str]]:
    """Busy blocks of the mailbox's primary calendar, plus the reasons Google gave for
    any part it couldn't read (never treated as free)."""
    r = svc.freebusy().query(body={"timeMin": tmin.isoformat(), "timeMax": tmax.isoformat(),
                                   "items": [{"id": "primary"}]}).execute()
    cal = (r.get("calendars") or {}).get("primary") or {}
    errors = [str(e.get("reason") or "unknown") for e in cal.get("errors") or []]
    if not cal and not errors:
        errors = ["no free/busy data returned"]
    busy = []
    for b in cal.get("busy") or []:
        try:
            busy.append((datetime.fromisoformat(b["start"]), datetime.fromisoformat(b["end"])))
        except (KeyError, ValueError):
            errors.append("unparseable busy block")
    return busy, errors


def _if_match(request, op: dict):
    """Make Google refuse (412) the write if the event changed since the version the
    human saw, closing the gap between the commit-time etag check and the write."""
    if op.get("etag"):
        request.headers["If-Match"] = op["etag"]
    return request


def execute(svc, op: dict) -> dict:
    """Run a checked write plan. Returns a small result (event id, link)."""
    action, cal = op["action"], op["calendar_id"]
    events = svc.events()
    if action == "create":
        kw: dict[str, Any] = {"calendarId": cal, "body": op["body"], "sendUpdates": op["send_updates"]}
        if op.get("conference"):
            kw["conferenceDataVersion"] = 1
        ev = events.insert(**kw).execute()
    elif action in ("update", "respond"):
        kw = {"calendarId": cal, "eventId": op["event_id"], "body": op["body"],
              "sendUpdates": op["send_updates"]}
        if op.get("conference"):
            kw["conferenceDataVersion"] = 1
        ev = _if_match(events.patch(**kw), op).execute()
    elif action == "delete":
        _if_match(events.delete(calendarId=cal, eventId=op["event_id"], sendUpdates=op["send_updates"]),
                  op).execute()
        return {"event_id": op["event_id"], "deleted": True}
    else:  # pragma: no cover
        raise CalendarError(f"unknown calendar action {action}")
    return {k: v for k, v in {"event_id": ev.get("id"), "html_link": ev.get("htmlLink"),
                              "meet_link": ev.get("hangoutLink")}.items() if v}
