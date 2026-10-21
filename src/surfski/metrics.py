"""Prometheus metrics (#10), hand-rolled text exposition (format 0.0.4).

No personal data ever becomes a label value: every label has a fixed set of allowed
values, and anything else is recorded as "other". That keeps cardinality bounded too.
Gauges that count rows (mailboxes, owners) are computed from SQLite at scrape time.
Single process only (the server runs one uvicorn worker), so in-memory state is enough.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Iterable


from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware

from .version import __version__

# Seconds. Tool calls range from a cached list_accounts (ms) to a 20 MB forward (tens of s).
LATENCY_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)

TOOL_OUTCOMES = frozenset({"ok", "error", "internal_error"})
GMAIL_STATUS = frozenset({"400", "401", "403", "404", "429", "4xx", "5xx", "refresh", "storage", "other"})
SEND_POLICIES = frozenset({"auto", "confirm"})
SEND_OUTCOMES = frozenset({"sent", "failed", "declined", "link_issued"})
ATTACHMENT_METHODS = frozenset({"text", "html", "pdf", "docx", "xlsx", "pptx", "none", "unknown"})
ATTACHMENT_OUTCOMES = frozenset({"ok", "metadata_only", "error"})
UNSUB_METHODS = frozenset({"one_click", "mailto", "manual", "none"})
UNSUB_OUTCOMES = frozenset({"preview", "ok", "failed", "manual", "not_available", "draft_created",
                            "sent", "confirmation_required", "declined"})


def _bucket(value: str, allowed: Iterable[str]) -> str:
    return value if value in allowed else "other"


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(names: tuple[str, ...], values: tuple[str, ...], extra: str = "") -> str:
    parts = [f'{n}="{_esc(v)}"' for n, v in zip(names, values, strict=True)]
    if extra:
        parts.append(extra)
    return "{" + ",".join(parts) + "}" if parts else ""


def _num(x: float) -> str:
    if math.isinf(x):
        return "+Inf"
    return repr(float(x)) if not float(x).is_integer() else str(int(x))


def gmail_status_class(exc: BaseException) -> str:
    """Bucket a Gmail-side exception into a fixed status class."""
    from google.auth.exceptions import RefreshError
    from googleapiclient.errors import HttpError

    from .storage import StorageError

    if isinstance(exc, RefreshError):
        return "refresh"
    if isinstance(exc, StorageError):
        return "storage"
    if isinstance(exc, HttpError):
        status = getattr(exc.resp, "status", None)
        try:
            status = int(status)
        except (TypeError, ValueError):
            return "other"
        if str(status) in GMAIL_STATUS:
            return str(status)
        if 400 <= status < 500:
            return "4xx"
        if 500 <= status < 600:
            return "5xx"
    return "other"


class Metrics:
    def __init__(self, tool_names: Iterable[str] = ()):
        self._lock = threading.Lock()
        self._tools = frozenset(tool_names)
        self._counters: dict[str, dict[tuple[str, ...], float]] = {}
        self._hist: dict[tuple[str, ...], list[float]] = {}  # tool -> [bucket counts..., sum, count]
        self.started = time.time()
        self.version = __version__

    def set_tools(self, names: Iterable[str]) -> None:
        self._tools = frozenset(names)

    def _inc(self, name: str, labels: tuple[str, ...] = (), n: float = 1) -> None:
        with self._lock:
            series = self._counters.setdefault(name, {})
            series[labels] = series.get(labels, 0) + n

    # ---- recording (called by the server)

    def tool_call(self, tool: str, outcome: str, seconds: float) -> None:
        t = _bucket(tool, self._tools)
        self._inc("tool_calls", (t, _bucket(outcome, TOOL_OUTCOMES)))
        with self._lock:
            h = self._hist.setdefault((t,), [0.0] * (len(LATENCY_BUCKETS) + 2))
            for i, b in enumerate(LATENCY_BUCKETS):
                if seconds <= b:
                    h[i] += 1
            h[-2] += seconds
            h[-1] += 1

    def gmail_error(self, exc: BaseException) -> None:
        self._inc("gmail_errors", (gmail_status_class(exc),))

    def send(self, policy: str, outcome: str) -> None:
        self._inc("sends", (_bucket(policy, SEND_POLICIES), _bucket(outcome, SEND_OUTCOMES)))

    def triage(self, n: int) -> None:
        if n > 0:
            self._inc("triage", (), n)

    def attachment(self, method: str, outcome: str) -> None:
        self._inc("attachments", (_bucket(method, ATTACHMENT_METHODS), _bucket(outcome, ATTACHMENT_OUTCOMES)))

    def unsubscribe(self, method: str, outcome: str) -> None:
        self._inc("unsubscribe", (_bucket(method, UNSUB_METHODS), _bucket(outcome, UNSUB_OUTCOMES)))

    def rate_limited(self) -> None:
        self._inc("rate_limited")

    # ---- exposition

    _COUNTERS = (
        ("tool_calls", "surfski_tool_calls_total", "MCP tool calls by tool and outcome.", ("tool", "outcome")),
        ("gmail_errors", "surfski_gmail_api_errors_total", "Gmail API errors by status class.",
         ("status_class",)),
        ("sends", "surfski_sends_total", "Send attempts by mailbox send policy and outcome.",
         ("policy", "outcome")),
        ("triage", "surfski_triage_modifications_total", "Messages/threads changed by triage tools.", ()),
        ("attachments", "surfski_attachment_extractions_total",
         "Attachment text extractions by method and outcome.", ("method", "outcome")),
        ("unsubscribe", "surfski_unsubscribe_total", "Unsubscribe calls by method and outcome.",
         ("method", "outcome")),
        ("rate_limited", "surfski_rate_limit_rejections_total", "Tool calls rejected by the rate limit.", ()),
    )

    def render(self, mailboxes: int, owners: int) -> str:
        out: list[str] = []

        def head(name: str, help_: str, kind: str) -> None:
            out.append(f"# HELP {name} {help_}")
            out.append(f"# TYPE {name} {kind}")

        with self._lock:
            counters = {k: dict(v) for k, v in self._counters.items()}
            hist = {k: list(v) for k, v in self._hist.items()}
        for key, name, help_, label_names in self._COUNTERS:
            head(name, help_, "counter")
            series = counters.get(key, {})
            if not series and not label_names:
                series = {(): 0}
            for values, v in sorted(series.items()):
                out.append(f"{name}{_labels(label_names, values)} {_num(v)}")

        name = "surfski_tool_duration_seconds"
        head(name, "MCP tool call latency by tool.", "histogram")
        for (tool,), h in sorted(hist.items()):
            for i, b in enumerate((*LATENCY_BUCKETS, math.inf)):
                le = 'le="' + _num(b) + '"'
                count = h[i] if i < len(LATENCY_BUCKETS) else h[-1]
                out.append(f"{name}_bucket{_labels(('tool',), (tool,), le)} {_num(count)}")
            out.append(f"{name}_sum{_labels(('tool',), (tool,))} {_num(h[-2])}")
            out.append(f"{name}_count{_labels(('tool',), (tool,))} {_num(h[-1])}")

        head("surfski_linked_mailboxes", "Linked mailboxes (all owners).", "gauge")
        out.append(f"surfski_linked_mailboxes {mailboxes}")
        head("surfski_owners", "Owners with at least one linked mailbox.", "gauge")
        out.append(f"surfski_owners {owners}")
        head("surfski_build_info", "Surfski version.", "gauge")
        out.append("surfski_build_info" + _labels(("version",), (self.version,)) + " 1")
        head("surfski_process_start_time_seconds", "Start time of the process (Unix seconds).", "gauge")
        out.append(f"surfski_process_start_time_seconds {_num(round(self.started, 3))}")
        head("surfski_uptime_seconds", "Seconds since the process started.", "gauge")
        out.append(f"surfski_uptime_seconds {_num(round(time.time() - self.started, 3))}")
        return "\n".join(out) + "\n"


class ToolMetricsMiddleware(Middleware):
    """Counts and times every MCP tool call. Unknown tool names are recorded as "other"."""

    def __init__(self, mcp, metrics: Metrics):
        self._mcp = mcp
        self._metrics = metrics
        self._known: frozenset[str] | None = None

    async def on_call_tool(self, context, call_next):
        if self._known is None:
            self._known = frozenset(t.name for t in await self._mcp.list_tools(run_middleware=False))
            self._metrics.set_tools(self._known)
        tool = getattr(context.message, "name", "") or ""
        start = time.perf_counter()
        outcome = "internal_error"
        try:
            result = await call_next(context)
            outcome = "error" if getattr(result, "is_error", False) else "ok"
            return result
        except ToolError:
            outcome = "error"
            raise
        finally:
            self._metrics.tool_call(tool, outcome, time.perf_counter() - start)
