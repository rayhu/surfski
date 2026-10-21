"""Run attachment extraction in a short-lived, resource-limited subprocess (#30).

Each call starts `python -I -B -m surfski.extract_worker` (never fork from the threaded
server), sends the bytes on stdin and reads one JSON result from stdout. The parent
enforces a wall-clock timeout and kills the child's whole process group; the child
lowers its own rlimits before touching the input. A semaphore caps concurrent
extractions. Failures map to a short user-facing ExtractError; the child's stderr is
discarded (only a class name such as "timeout" or "MemoryError" is ever reported).

The child also confines itself with Landlock and seccomp (#43, `confine.py`). `probe()`
runs one trivial extraction at startup to learn the protection level the kernel gives;
that level, not one reported by a worker that parsed untrusted input, feeds the logs and
metrics. With `strict=True` the worker refuses to parse unless Landlock applied."""

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
SANDBOX_UNAVAILABLE = ("attachment reading is disabled: the extraction sandbox (Landlock) is not "
                       "available on this server and EXTRACT_SANDBOX_STRICT is on")


class Sandbox:
    def __init__(self, *, mode: str = "subprocess", timeout_s: float = 20.0, memory_mb: int = 512,
                 max_concurrent: int = 2, strict: bool = False):
        self.mode = mode
        self.strict = strict
        self.protection: dict | None = None  # set by probe()
        self.timeout_s = timeout_s
        self.memory_mb = memory_mb
        self._sem = threading.BoundedSemaphore(max_concurrent)
        self._lock = threading.Lock()
        self.active = 0
        self.peak = 0

    @classmethod
    def from_config(cls, config) -> Sandbox:
        return cls(mode=config.extract_sandbox, timeout_s=config.extract_timeout_s,
                   memory_mb=config.extract_memory_mb, strict=config.extract_sandbox_strict)

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
            return self._run(data, mime_type, filename, charset, max_chars)[0]
        finally:
            with self._lock:
                self.active -= 1
            self._sem.release()

    def _run(self, data, mime_type, filename, charset, max_chars) -> tuple[att.Extracted, dict]:
        header = json.dumps({
            "mime_type": mime_type, "filename": filename, "charset": charset, "max_chars": max_chars,
            "memory_mb": self.memory_mb, "cpu_seconds": max(1, math.ceil(self.timeout_s)),
            "strict": self.strict,
        }).encode() + b"\n"
        cap = output_cap(max_chars)
        start = time.monotonic()
        proc = subprocess.Popen(  # noqa: S603  (fixed argv, no shell)
            WORKER_ARGV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=worker_env(), close_fds=True, start_new_session=True, cwd="/",
        )
        chunks: list[bytes] = []
        state = {"size": 0, "flood": False}

        def feed() -> None:
            try:
                proc.stdin.write(header + data)
            except (BrokenPipeError, OSError):
                pass
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

        def drain() -> None:
            # Read incrementally and stop (killing the child) once it exceeds the cap, so a
            # flooding worker can't make the server buffer unbounded output.
            while True:
                chunk = proc.stdout.read1(65536)
                if not chunk:
                    return
                state["size"] += len(chunk)
                if state["size"] > cap:
                    state["flood"] = True
                    self._kill(proc)
                    return
                chunks.append(chunk)

        threads = [threading.Thread(target=feed, daemon=True), threading.Thread(target=drain, daemon=True)]
        for t in threads:
            t.start()
        timed_out = False
        try:
            proc.wait(timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            if proc.poll() is None:
                self._kill(proc)
            for t in threads:
                t.join(timeout=5)
            proc.stdout.close()
        elapsed = time.monotonic() - start
        if timed_out:
            log.warning("attachment extraction killed: timeout after %.0fs", self.timeout_s)
            raise att.ExtractError(f"{TOO_COMPLEX} (timeout)")
        if state["flood"]:
            log.warning("attachment extraction killed: output over %d bytes", cap)
            raise att.ExtractError(f"{TOO_COMPLEX} (output limit)")
        try:
            result = json.loads(b"".join(chunks).decode() or "null")
        except (UnicodeDecodeError, ValueError, RecursionError):
            result = None
        if not isinstance(result, dict):
            reason = _signal_name(proc.returncode)
            log.warning("attachment extraction failed: %s (%.2fs)", reason, elapsed)
            raise att.ExtractError(f"{TOO_COMPLEX} ({reason})")
        if result.get("ok") is not True:
            if result.get("error") == "sandbox":
                log.error("extraction refused: Landlock is unavailable and EXTRACT_SANDBOX_STRICT is on")
                raise att.ExtractError(SANDBOX_UNAVAILABLE)
            if result.get("error") == "extract" and isinstance(result.get("message"), str):
                raise att.ExtractError(result["message"][:300] or "could not read the file")
            cls = result.get("class")
            cls = cls if isinstance(cls, str) and cls.isidentifier() and len(cls) <= 40 else "error"
            log.warning("attachment extraction failed in worker: %s", cls)
            raise att.ExtractError(f"{TOO_COMPLEX} ({cls})")
        ex = validated(result, max_chars)
        if ex is None:
            log.warning("attachment extraction returned a malformed result")
            raise att.ExtractError(f"{TOO_COMPLEX} (malformed result)")
        for name in result.get("skipped") or ():
            if name not in _logged_skips:
                _logged_skips.add(name)
                log.info("extraction sandbox: %s is not supported on this platform; skipped", name)
        log.debug("attachment extracted in subprocess in %.3fs", elapsed)
        return ex, result

    def probe(self) -> dict:
        """Run one trivial extraction to learn the protection level this host gives the worker,
        log it and remember it in `self.protection`. Never raises."""
        if self.mode == "inprocess":
            self.protection = {"level": "none", "landlock_abi": 0, "seccomp": False}
            log.warning("extraction sandbox: off (EXTRACT_SANDBOX=inprocess)")
            return self.protection
        report: dict | None = None
        strict, self.strict = self.strict, False  # learn the level even where strict would refuse
        try:
            report = self._probe_run()
        finally:
            self.strict = strict
        self.protection = report or {"level": "unknown", "landlock_abi": 0, "seccomp": False}
        p = self.protection
        msg = ("extraction sandbox protection: %s (Landlock ABI %s, filesystem %s, TCP %s, seccomp %s)",
               p["level"], p["landlock_abi"], "restricted" if p.get("landlock_fs") else "open",
               "blocked" if p.get("landlock_net") else "open", "on" if p["seccomp"] else "off")
        if p["level"] == "full":
            log.info(*msg)
        elif self.strict and not p.get("landlock_fs"):
            log.error(*msg)
            log.error("EXTRACT_SANDBOX_STRICT is on: get_attachment will refuse to read files")
        else:
            log.warning(*msg)
            if sys.platform.startswith("linux"):
                log.warning("the extraction worker can read files this user can read (DATA_DIR "
                            "included) or reach the network; see README 'Attachments' (#43)")
        return self.protection

    def _probe_run(self) -> dict | None:
        try:
            _, result = self._run(b"probe", "text/plain", "probe.txt", None, 100)
        except Exception as e:  # noqa: BLE001
            log.warning("extraction sandbox probe failed: %s", type(e).__name__)
            return None
        return protection_of(result)

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


def output_cap(max_chars: int) -> int:
    """Largest stdout accepted from a worker: text is at most max_chars + 1 characters and
    UTF-8 JSON needs at most 6 bytes per character (\\uXXXX escapes)."""
    return max_chars * 8 + 4096


def worker_env() -> dict[str, str]:
    """The child's whole environment: no secrets, nothing inherited."""
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp", "LANG": "C.UTF-8"}


def protection_of(result: dict) -> dict | None:
    """Type-check a worker's "protection" report."""
    p = result.get("protection")
    if not isinstance(p, dict) or p.get("level") not in ("full", "filesystem", "network", "basic"):
        return None
    abi = p.get("landlock_abi")
    if not isinstance(abi, int) or isinstance(abi, bool) or not 0 <= abi < 100:
        return None
    flags = {k: p.get(k) for k in ("landlock_fs", "landlock_net", "seccomp")}
    if not all(isinstance(v, bool) for v in flags.values()):
        return None
    return {"level": p["level"], "landlock_abi": abi, **flags}


def validated(result: dict, max_chars: int) -> att.Extracted | None:
    """Type-check a worker's success result before trusting it."""
    text, method, note, skipped = (result.get(k) for k in ("text", "method", "note", "skipped"))
    if text is not None and not isinstance(text, str):
        return None
    if not isinstance(method, str) or method not in att.METHODS:
        return None
    if note is not None and not isinstance(note, str):
        return None
    if "protection" in result and protection_of(result) is None:
        return None
    if skipped is not None and not (isinstance(skipped, list) and all(isinstance(x, str) for x in skipped)):
        return None
    if text is not None and len(text) > max_chars + 1:
        return None
    return att.Extracted(text, method, note[:500] if note else note)


def harden_process() -> bool:
    """Linux: mark the server process non-dumpable (prctl PR_SET_DUMPABLE=0), so other
    processes of the same uid, such as a compromised extraction worker, can't read its
    /proc/<pid>/environ or memory, or ptrace it. Best effort; returns whether it applied."""
    if not sys.platform.startswith("linux"):
        log.info("process hardening (PR_SET_DUMPABLE) is Linux-only; skipped")
        return False
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        PR_SET_DUMPABLE = 4
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl failed")
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("could not set PR_SET_DUMPABLE=0 (%s); same-uid processes may read this "
                    "process's environment", type(e).__name__)
        return False
