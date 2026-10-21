"""Attachment extraction worker (#30): `python -I -B -m surfski.extract_worker`.

Protocol: stdin is one JSON header line, then the raw attachment bytes. stdout is one
JSON object: {"ok": true, "text", "method", "note", "skipped"} or {"ok": false,
"error": "extract", "message"} for a user-facing ExtractError, or {"ok": false,
"error": "internal", "class"} for anything else (class name only, never the message).

The worker reads the input first (so the header can say whether pypdf is needed), then
imports what parsing needs, then confines itself with Landlock and seccomp (#43, see
`confine.py`: read-only access to the Python installation only, no TCP, no `socket()`),
then lowers its own resource limits (address space, CPU seconds, open files, processes,
file size) and only then parses the untrusted bytes. With `"strict": true` in the header
it refuses to parse ({"ok": false, "error": "sandbox"}) unless the level is "full"
(Landlock filesystem confinement and a kernel-level network block). The
protection achieved is reported back in "protection". Limits the platform doesn't
support are skipped and reported back in "skipped". The
text is cut to max_chars + 1 characters so the parent can still tell it was truncated
while bounding the output size."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable


def _deny_network() -> None:
    """Python-level sockets refuse to open, with a clear message. The kernel-level block is
    Landlock (TCP, ABI 4+) and the seccomp filter on socket() (confine.py)."""
    import socket

    def refuse(*_a, **_kw):
        raise OSError("network access is disabled in the extraction sandbox")

    socket.socket = refuse  # type: ignore[assignment,misc]
    socket.create_connection = refuse  # type: ignore[assignment]
    socket.getaddrinfo = refuse  # type: ignore[assignment]


def apply_limits(memory_mb: int, cpu_seconds: int) -> list[str]:
    """Lower this process's rlimits; returns the names that couldn't be applied."""
    skipped: list[str] = []
    try:
        import resource
    except ImportError:  # Windows
        return ["resource"]

    def lower(name: str, value: int) -> None:
        res = getattr(resource, name, None)
        if res is None:
            skipped.append(name)
            return
        try:
            soft, hard = resource.getrlimit(res)
            if hard != resource.RLIM_INFINITY:
                value = min(value, hard)
            resource.setrlimit(res, (value, value))
        except (ValueError, OSError):
            skipped.append(name)

    lower("RLIMIT_AS", memory_mb * 1024 * 1024)
    lower("RLIMIT_CPU", cpu_seconds)
    lower("RLIMIT_FSIZE", 0)  # no file writes
    lower("RLIMIT_NPROC", 0)  # no fork/exec of new processes (Linux counts per user)
    lower("RLIMIT_CORE", 0)
    lower("RLIMIT_NOFILE", 16)  # stdio plus a few; no fds needed after imports
    return skipped


def _read_input() -> tuple[dict, bytes]:
    stream = sys.stdin.buffer
    header = json.loads(stream.readline())
    return header, stream.read()


def main(extract: Callable | None = None) -> int:
    from . import attachments as att
    from . import confine

    extract = extract or att.extract_text
    out = sys.stdout
    try:
        header, data = _read_input()
        if att.detect_method(header["mime_type"], header["filename"]) == "pdf":
            import pypdf  # noqa: F401  (only when needed; before the limits, imports open files)
        protection = confine.confine()
        if header.get("strict") and protection["level"] != "full":
            result = {"ok": False, "error": "sandbox", "protection": protection}
            out.write(json.dumps(result))
            out.flush()
            return 0
        skipped = apply_limits(int(header["memory_mb"]), int(header["cpu_seconds"]))
        _deny_network()
        ex = extract(data, header["mime_type"], header["filename"], charset=header.get("charset"),
                     max_chars=int(header["max_chars"]))
        text = ex.text[: int(header["max_chars"]) + 1] if ex.text is not None else None
        result = {"ok": True, "text": text, "method": ex.method, "note": ex.note, "skipped": skipped,
                  "protection": protection}
    except att.ExtractError as e:
        result = {"ok": False, "error": "extract", "message": str(e)[:300]}
    except BaseException as e:  # noqa: BLE001  (MemoryError, RecursionError, parser bugs...)
        result = {"ok": False, "error": "internal", "class": type(e).__name__}
    out.write(json.dumps(result, ensure_ascii=False))
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
