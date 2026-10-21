"""Audit logging and log redaction. Audit rows never contain message bodies."""

from __future__ import annotations

import logging
import re

from .storage import Storage

log = logging.getLogger("surfski.audit")


def write_audit(
    storage: Storage, owner: str, tool: str, alias: str | None, detail: str, ok: bool
) -> None:
    try:
        storage.audit(owner, tool, alias, detail, ok)
    except Exception:  # audit failures must never break a tool call
        log.exception("failed to write audit row")


_QUERY_RE = re.compile(r"((?:\s|^|https?://[^\s/?\"]+)/[^\s?\"]*)\?[^\s\"]*")
_SECRET_RE = re.compile(
    r"(?i)\b(code|state|access_token|refresh_token|id_token|client_secret|token)=([^&\s\"]+)"
)


def redact(text: str) -> str:
    text = _QUERY_RE.sub(r"\1?<redacted>", text)
    return _SECRET_RE.sub(r"\1=<redacted>", text)


class RedactQueryFilter(logging.Filter):
    """Strips query strings (OAuth codes/state) from every log record, incl. uvicorn access logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == "uvicorn.access" and isinstance(record.args, tuple) and len(record.args) >= 3:
            args = list(record.args)
            path = str(args[2])
            if "?" in path:
                args[2] = path.split("?", 1)[0] + "?<redacted>"
            record.args = tuple(args)
            return True
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        red = redact(msg)
        if red != msg:
            record.msg, record.args = red, None
        return True


QUIET_LOGGERS = ("httpx", "httpx2", "httpcore", "googleapiclient.discovery", "google_auth_httplib2")


def install_log_redaction() -> None:
    # Outbound HTTP clients log full URLs at INFO; keep them quiet.
    for name in QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
    f = RedactQueryFilter()
    for name in ("", "uvicorn", "uvicorn.access", "uvicorn.error", "fastmcp", "httpx", "httpx2"):
        lg = logging.getLogger(name)
        lg.addFilter(f)
        for h in lg.handlers:
            h.addFilter(f)
