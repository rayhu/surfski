"""Run attachment extraction in a short-lived, resource-limited subprocess (#30).

Each call starts `python -I -B -m surfski.extract_worker` (never fork from the threaded
server), sends the bytes on stdin and reads one JSON result from stdout. The parent
enforces a wall-clock timeout and kills the child's whole process group; the child
lowers its own rlimits before touching the input. A semaphore caps concurrent
extractions. Failures map to a short user-facing ExtractError; the child's stderr is
discarded (only a class name such as "timeout" or "MemoryError" is ever reported)."""

from __future__ import annotations

import json
import logging
import math
import os
import signal
import subprocess
import sys
import threading
import time

from . import attachments as att

log = logging.getLogger("surfski.sandbox")

TOO_COMPLEX = "the file was too complex to read safely"
# Overridable by tests to inject a misbehaving worker.
WORKER_ARGV = [sys.executable, "-I", "-B", "-m", "surfski.extract_worker"]
_logged_skips: set[str] = set()


class Sandbox:
    def __init__(self, *, mode: str = "subprocess", timeout_s: float = 20.0, memory_mb: int = 512,
                 max_concurrent: int = 2):
        self.mode = mode
        self.timeout_s = timeout_s
        self.memory_mb = memory_mb
        self._sem = threading.BoundedSemaphore(max_concurrent)
        self._lock = threading.Lock()
        self.active = 0
        self.peak = 0

    @classmethod
    def from_config(cls, config) -> Sandbox:
        return cls(mode=config.extract_sandbox, timeout_s=config.extract_timeout_s,
                   memory_mb=config.extract_memory_mb)

    def extract(self, data: bytes, mime_type: str, filename: str, *, charset: str | None,
                max_chars: int) -> att.Extracted:
        """Same contract as attachments.extract_text: returns Extracted or raises ExtractError."""
        if self.mode == "inprocess":
            return att.extract_text(data, mime_type, filename, charset=charset, max_chars=max_chars)
        # Waiting for a slot counts against the same deadline as the extraction itself.
        if not self._sem.acquire(timeout=self.timeout_s):
            raise att.ExtractError("the server is busy reading other attachments; try again shortly")
        try:
            with self._lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
            return self._run(data, mime_type, filename, charset, max_chars)
        finally:
            with self._lock:
                self.active -= 1
            self._sem.release()

    def _run(self, data, mime_type, filename, charset, max_chars) -> att.Extracted:
        header = json.dumps({
            "mime_type": mime_type, "filename": filename, "charset": charset, "max_chars": max_chars,
            "memory_mb": self.memory_mb, "cpu_seconds": max(1, math.ceil(self.timeout_s)),
        }).encode() + b"\n"
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp", "LANG": "C.UTF-8"}
        start = time.monotonic()
        proc = subprocess.Popen(  # noqa: S603  (fixed argv, no shell)
            WORKER_ARGV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, close_fds=True, start_new_session=True, cwd="/",
        )
        try:
            out, _ = proc.communicate(header + data, timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            self._kill(proc)
            log.warning("attachment extraction killed: timeout after %.0fs", self.timeout_s)
            raise att.ExtractError(f"{TOO_COMPLEX} (timeout)") from None
        except BaseException:
            self._kill(proc)
            raise
        finally:
            if proc.poll() is None:
                self._kill(proc)
        elapsed = time.monotonic() - start
        try:
            result = json.loads(out.decode() or "null")
        except (UnicodeDecodeError, ValueError):
            result = None
        if not isinstance(result, dict):
            reason = _signal_name(proc.returncode)
            log.warning("attachment extraction failed: %s (%.2fs)", reason, elapsed)
            raise att.ExtractError(f"{TOO_COMPLEX} ({reason})")
        if not result.get("ok"):
            if result.get("error") == "extract":
                raise att.ExtractError(str(result.get("message") or "could not read the file")[:300])
            cls = str(result.get("class") or "error")
            cls = cls if cls.isidentifier() and len(cls) <= 40 else "error"
            log.warning("attachment extraction failed in worker: %s", cls)
            raise att.ExtractError(f"{TOO_COMPLEX} ({cls})")
        for name in result.get("skipped") or ():
            if name not in _logged_skips:
                _logged_skips.add(name)
                log.info("extraction sandbox: %s is not supported on this platform; skipped", name)
        log.debug("attachment extracted in subprocess in %.3fs", elapsed)
        return att.Extracted(result.get("text"), str(result.get("method") or "none"), result.get("note"))

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=5)  # reap: no zombie
        except subprocess.TimeoutExpired:  # pragma: no cover
            log.error("extraction worker %s did not exit after SIGKILL", proc.pid)


def _signal_name(code: int | None) -> str:
    if code is not None and code < 0:
        try:
            name = signal.Signals(-code).name
        except ValueError:
            name = f"signal {-code}"
        return {"SIGKILL": "killed (memory or CPU limit)", "SIGXCPU": "CPU limit",
                "SIGSEGV": "crashed", "SIGABRT": "crashed"}.get(name, name)
    return "crashed" if code else "no result"
