"""Prometheus /metrics (#10): off by default, Bearer-protected, parseable, no personal data,
bounded cardinality."""

import re
from dataclasses import replace

import httplib2
import pytest
from fastmcp.exceptions import ToolError
from googleapiclient.errors import HttpError
from starlette.testclient import TestClient

from surfski.config import ConfigError, load_config
from surfski.metrics import Metrics, gmail_status_class
from surfski.server import create_app
from surfski.storage import StorageError

from .conftest import make_env
from .test_server import ALICE, BOB, FakeGmail, call, who  # noqa: F401  (fixture re-export)

TOKEN = "m" * 40
AUTH = {"Authorization": f"Bearer {TOKEN}"}
PERSONAL = (ALICE, BOB, "alice@work.com", "alice@gmail.com", "bob@work.com", "bob@secret.com",
            "work", "personal", "secret", "from:boss", "msg-123")

LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(?:[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\]|\\.)*",?)*\})? '
                  r'(-?[0-9.e+-]+|\+Inf|NaN)$')


def parse(text: str) -> dict[str, list[tuple[dict, float]]]:
    """Strict-enough parser for the text format: every sample matches the grammar, belongs to a
    family declared by # TYPE, and histogram buckets are cumulative."""
    assert text.endswith("\n")
    types: dict[str, str] = {}
    samples: dict[str, list[tuple[dict, float]]] = {}
    for line in text.splitlines():
        if line.startswith("# HELP "):
            continue
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split(" ")
            assert kind in ("counter", "gauge", "histogram") and name not in types
            types[name] = kind
            continue
        m = LINE.match(line)
        assert m, f"bad sample line: {line!r}"
        name, labels = m.group(1), dict(re.findall(r'([a-zA-Z_]\w*)="((?:[^"\\]|\\.)*)"', m.group(2) or ""))
        family = re.sub(r"_(bucket|sum|count)$", "", name) if name not in types else name
        assert family in types, f"{name} has no # TYPE"
        samples.setdefault(name, []).append((labels, float(m.group(3).replace("+Inf", "inf"))))
    for name, kind in types.items():
        if kind != "histogram":
            continue
        by_tool: dict[str, list[float]] = {}
        for labels, v in samples.get(f"{name}_bucket", []):
            by_tool.setdefault(labels["tool"], []).append(v)
        for vals in by_tool.values():
            assert vals == sorted(vals)
    return samples


def value(samples, name, **labels) -> float:
    return sum(v for lb, v in samples.get(name, []) if all(lb.get(k) == x for k, x in labels.items()))


@pytest.fixture
def mconfig(config):
    return replace(config, metrics_enabled=True, metrics_token=TOKEN)


@pytest.fixture
def mapp(mconfig, storage):
    storage.upsert_account(ALICE, "work", "alice@work.com", "rt", "s")
    storage.upsert_account(ALICE, "personal", "alice@gmail.com", "rt", "s")
    storage.upsert_account(BOB, "work", "bob@work.com", "rt", "s")
    storage.upsert_account(BOB, "secret", "bob@secret.com", "rt", "s")
    return create_app(mconfig, storage=storage, with_auth=False,
                      service_factory=lambda o, a: FakeGmail(storage.get_account(o, a).email))


def scrape(app, headers=AUTH):
    return TestClient(app.http_app()).get("/metrics", headers=headers)


# ---------------------------------------------------------------- switch and auth


def test_disabled_is_404(config, storage):
    app = create_app(config, storage=storage, with_auth=False)
    assert scrape(app).status_code == 404


def test_auth(mapp):
    r = scrape(mapp, headers={})
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
    assert scrape(mapp, headers={"Authorization": "Bearer " + "x" * 40}).status_code == 403
    assert scrape(mapp, headers={"Authorization": TOKEN}).status_code == 403  # no scheme
    assert scrape(mapp, headers={"Authorization": f"Basic {TOKEN}"}).status_code == 403
    r = scrape(mapp)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain; version=0.0.4")


def test_config_requires_token(tmp_path):
    with pytest.raises(ConfigError, match="METRICS_TOKEN"):
        load_config(make_env(tmp_path, METRICS_ENABLED="true"))
    with pytest.raises(ConfigError, match="METRICS_TOKEN"):
        load_config(make_env(tmp_path, METRICS_ENABLED="true", METRICS_TOKEN="short"))
    c = load_config(make_env(tmp_path, METRICS_ENABLED="true", METRICS_TOKEN=TOKEN))
    assert c.metrics_enabled and c.metrics_token == TOKEN
    assert not load_config(make_env(tmp_path)).metrics_enabled


# ---------------------------------------------------------------- content


async def test_counters_gauges_and_no_personal_data(mapp, who):
    await call(mapp, "list_accounts")
    await call(mapp, "search_threads", alias="work", query="from:boss")
    with pytest.raises(ToolError):
        await call(mapp, "search_threads", alias="secret", query="from:boss")  # not Alice's
    with pytest.raises(ToolError):
        await call(mapp, "get_message", alias="work", message_id="msg-123")  # fake has no such call
    r = scrape(mapp)
    s = parse(r.text)
    assert value(s, "surfski_tool_calls_total", tool="list_accounts", outcome="ok") == 1
    assert value(s, "surfski_tool_calls_total", tool="search_threads", outcome="ok") == 1
    assert value(s, "surfski_tool_calls_total", tool="search_threads", outcome="error") == 1
    assert value(s, "surfski_tool_duration_seconds_count", tool="search_threads") == 2
    assert value(s, "surfski_tool_duration_seconds_bucket", tool="search_threads", le="+Inf") == 2
    assert value(s, "surfski_linked_mailboxes") == 4 and value(s, "surfski_owners") == 2
    assert value(s, "surfski_build_info") == 1 and value(s, "surfski_uptime_seconds") >= 0
    assert value(s, "surfski_rate_limit_rejections_total") == 0
    for needle in PERSONAL:
        assert needle not in r.text, needle
    # Only bounded label values appear.
    tools = {lb["tool"] for lb, _ in s["surfski_tool_calls_total"]}
    assert tools <= {"list_accounts", "search_threads", "get_message"}


async def test_rate_limit_counted(mconfig, storage, who):
    app = create_app(replace(mconfig, rate_limit_per_minute=1), storage=storage, with_auth=False)
    await call(app, "list_accounts")
    with pytest.raises(ToolError, match="rate limit"):
        await call(app, "list_accounts")
    s = parse(scrape(app).text)
    assert value(s, "surfski_rate_limit_rejections_total") == 1
    assert value(s, "surfski_tool_calls_total", tool="list_accounts", outcome="error") == 1


async def test_gmail_errors_by_status_class(mapp, who, storage):
    def boom(o, a):
        raise HttpError(httplib2.Response({"status": 503}), b"down")
    app = create_app(mapp.surfski["config"], storage=storage, with_auth=False, service_factory=boom)
    with pytest.raises(ToolError):
        await call(app, "search_threads", alias="work", query="x")
    s = parse(scrape(app).text)
    assert value(s, "surfski_gmail_api_errors_total", status_class="5xx") == 1


def test_status_class_buckets():
    def http(status):
        return HttpError(httplib2.Response({"status": status}), b"")
    assert [gmail_status_class(http(x)) for x in (400, 401, 403, 404, 429, 418, 500, 599)] == \
        ["400", "401", "403", "404", "429", "4xx", "5xx", "5xx"]
    assert gmail_status_class(StorageError("x")) == "storage"
    assert gmail_status_class(ValueError("alice@work.com")) == "other"


def test_cardinality_bounded_and_values_escaped():
    m = Metrics(tool_names={"search_threads"})
    for i in range(500):
        m.tool_call(f"evil-{i}@x.com", "ok", 0.01)
        m.tool_call("search_threads", f"weird-{i}", 0.01)
        m.send(f"p{i}", f"o{i}")
        m.attachment(f"m{i}", "ok")
        m.unsubscribe("one_click", f"https://x/{i}")
    text = m.render(0, 0)
    parse(text)
    assert "evil" not in text and "weird" not in text and "https" not in text
    assert len(m._counters["tool_calls"]) == 2  # ("other","ok"), ("search_threads","other")
    assert len(m._counters["sends"]) == 1 and len(m._counters["unsubscribe"]) == 1
    assert len(text.splitlines()) < 120


def test_attachment_and_triage_recording():
    m = Metrics()
    m.attachment("pdf", "ok")
    m.attachment("none", "metadata_only")
    m.triage(3)
    m.triage(0)
    s = parse(m.render(1, 1))
    assert value(s, "surfski_attachment_extractions_total", method="pdf", outcome="ok") == 1
    assert value(s, "surfski_triage_modifications_total") == 3
