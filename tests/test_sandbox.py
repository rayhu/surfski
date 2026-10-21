"""Attachment extraction sandbox (#30): subprocess per call with rlimits and a timeout."""

import os
import sys
import textwrap
import threading
import time
from dataclasses import replace

import pytest

import surfski.attachments as att
import surfski.sandbox as sb
from surfski.config import ConfigError, load_config
from surfski.sandbox import TOO_COMPLEX, Sandbox

from .conftest import make_env
from .test_attachments import DOCX, make_docx, make_pdf, make_xlsx

LINUX = sys.platform.startswith("linux")


def evil_worker(monkeypatch, body: str):
    """Inject a worker whose extract function runs `body` (after the real limits apply)."""
    script = textwrap.dedent("""
        import sys
        from surfski import extract_worker
        def extract(data, mime_type, filename, *, charset, max_chars):
        {body}
        sys.exit(extract_worker.main(extract=extract))
    """).format(body=textwrap.indent(textwrap.dedent(body), "    "))
    monkeypatch.setattr(sb, "WORKER_ARGV", [sys.executable, "-I", "-B", "-c", script])


@pytest.mark.parametrize("data,mime,name", [
    (make_pdf(["Quarterly numbers", "Page two"]), "application/pdf", "q.pdf"),
    (make_docx(["Hello", "World"]), DOCX, "x.docx"),
    (make_xlsx(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "x.xlsx"),
    (b"<p>Hi <b>there</b></p>", "text/html", "x.html"),
    ("naïve café".encode("latin-1"), "text/plain", "x.txt"),
    (b"\x89PNG", "image/png", "x.png"),
])
def test_subprocess_matches_inprocess(data, mime, name):
    charset = "latin-1" if name == "x.txt" else None
    a = Sandbox(mode="subprocess").extract(data, mime, name, charset=charset, max_chars=10_000)
    b = Sandbox(mode="inprocess").extract(data, mime, name, charset=charset, max_chars=10_000)
    assert (a.text, a.method, a.note) == (b.text, b.method, b.note)


def test_extract_error_passes_through():
    with pytest.raises(att.ExtractError, match="not a valid"):
        Sandbox().extract(b"not a zip", DOCX, "x.docx", charset=None, max_chars=100)


def test_timeout_kills_child(monkeypatch):
    evil_worker(monkeypatch, """
        import os, time
        print(os.getpid(), file=sys.stderr)
        time.sleep(60)
    """)
    seen = {}
    real_popen = sb.subprocess.Popen

    def popen(*a, **kw):
        seen["p"] = real_popen(*a, **kw)
        return seen["p"]

    monkeypatch.setattr(sb.subprocess, "Popen", popen)
    t = time.monotonic()
    with pytest.raises(att.ExtractError, match=rf"{TOO_COMPLEX} \(timeout\)"):
        Sandbox(timeout_s=1).extract(b"x", "text/plain", "a.txt", charset=None, max_chars=10)
    assert time.monotonic() - t < 8
    p = seen["p"]
    assert p.returncode is not None  # reaped: no zombie
    with pytest.raises(ProcessLookupError):
        os.kill(p.pid, 0)


def test_crash_is_clean(monkeypatch):
    evil_worker(monkeypatch, """
        import os
        sys.stderr.write("SECRET-STDERR alice@example.com\\n"); sys.stderr.flush()
        os.abort()
    """)
    with pytest.raises(att.ExtractError) as e:
        Sandbox().extract(b"x", "text/plain", "a.txt", charset=None, max_chars=10)
    msg = str(e.value)
    assert msg == f"{TOO_COMPLEX} (crashed)"
    assert "SECRET" not in msg and "alice" not in msg


def test_internal_exception_reports_class_only(monkeypatch):
    evil_worker(monkeypatch, """
        raise RuntimeError("SECRET details alice@example.com /etc/passwd")
    """)
    with pytest.raises(att.ExtractError) as e:
        Sandbox().extract(b"x", "text/plain", "a.txt", charset=None, max_chars=10)
    assert str(e.value) == f"{TOO_COMPLEX} (RuntimeError)"


def test_garbage_stdout_is_clean(monkeypatch):
    evil_worker(monkeypatch, """
        sys.stdout.write("not json SECRET"); sys.stdout.flush(); os._exit(0)
    """.replace("os._exit", "__import__('os')._exit"))
    with pytest.raises(att.ExtractError, match=rf"^{TOO_COMPLEX} \(no result\)$"):
        Sandbox().extract(b"x", "text/plain", "a.txt", charset=None, max_chars=10)


@pytest.mark.skipif(not LINUX, reason="RLIMIT_AS is only enforced on Linux")
def test_memory_limit(monkeypatch):
    evil_worker(monkeypatch, """
        blocks = []
        while True:
            blocks.append(bytearray(64 * 1024 * 1024))
    """)
    with pytest.raises(att.ExtractError, match=rf"{TOO_COMPLEX} \((MemoryError|killed)"):
        Sandbox(memory_mb=256).extract(b"x", "text/plain", "a.txt", charset=None, max_chars=10)


@pytest.mark.skipif(not LINUX, reason="rlimits differ on macOS")
def test_no_file_writes_no_fork_no_network(monkeypatch):
    evil_worker(monkeypatch, """
        import os, socket, subprocess
        from surfski.attachments import Extracted
        out = []
        probe = f"/tmp/surfski-sandbox-probe-{os.getpid()}"
        try:
            with open(probe, "wb", buffering=0) as f:  # RLIMIT_FSIZE=0: no bytes can be written
                f.write(b"x" * 10)
            out.append("write")
        except OSError:
            pass
        finally:
            try:
                os.unlink(probe)
            except OSError:
                pass
        try:
            subprocess.run(["true"])
            out.append("spawn")
        except OSError:
            pass
        try:
            socket.socket()
            out.append("socket")
        except OSError:
            pass
        return Extracted(",".join(out), "text")
    """)
    ex = Sandbox().extract(b"x", "text/plain", "a.txt", charset=None, max_chars=10)
    assert ex.text == ""


def test_concurrency_bound(monkeypatch):
    evil_worker(monkeypatch, """
        import time
        from surfski.attachments import Extracted
        time.sleep(0.6)
        return Extracted("ok", "text")
    """)
    box = Sandbox(max_concurrent=2, timeout_s=20)
    errors = []

    def run():
        try:
            box.extract(b"x", "text/plain", "a.txt", charset=None, max_chars=10)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=run) for _ in range(4)]
    t = time.monotonic()
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errors == [] and box.peak == 2 and box.active == 0
    assert time.monotonic() - t >= 1.2  # two waves


def test_busy_when_no_slot(monkeypatch):
    box = Sandbox(max_concurrent=1, timeout_s=1)
    box._sem.acquire()
    with pytest.raises(att.ExtractError, match="busy"):
        box.extract(b"x", "text/plain", "a.txt", charset=None, max_chars=10)


def test_inprocess_mode_does_not_spawn(monkeypatch):
    monkeypatch.setattr(sb.subprocess, "Popen", lambda *a, **k: pytest.fail("spawned"))
    ex = Sandbox(mode="inprocess").extract(b"hi", "text/plain", "a.txt", charset=None, max_chars=10)
    assert ex.text == "hi"


def test_worker_imports_no_google_client():
    import subprocess
    code = ("import sys, surfski.extract_worker, surfski.attachments; "
            "print(any(m.startswith(('googleapiclient', 'google.auth')) for m in sys.modules))")
    out = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True)
    assert out.stdout.strip() == "False"


def test_config(tmp_path):
    c = load_config(make_env(tmp_path))
    assert (c.extract_sandbox, c.extract_timeout_s, c.extract_memory_mb) == ("subprocess", 20.0, 512)
    c = load_config(make_env(tmp_path, EXTRACT_SANDBOX="inprocess", EXTRACT_TIMEOUT_S="5",
                             EXTRACT_MEMORY_MB="256"))
    assert Sandbox.from_config(c).mode == "inprocess" and Sandbox.from_config(c).timeout_s == 5
    for bad in ({"EXTRACT_SANDBOX": "docker"}, {"EXTRACT_TIMEOUT_S": "0"}, {"EXTRACT_MEMORY_MB": "64"},
                {"EXTRACT_TIMEOUT_S": "soon"}):
        with pytest.raises(ConfigError, match="EXTRACT_"):
            load_config(make_env(tmp_path, **bad))


async def test_tool_uses_sandbox_and_inprocess_still_works(config, storage):
    from surfski.server import create_app
    app = create_app(config, storage=storage, with_auth=False)
    assert app.surfski["sandbox"].mode == "subprocess"
    app = create_app(replace(config, extract_sandbox="inprocess"), storage=storage, with_auth=False)
    assert app.surfski["sandbox"].mode == "inprocess"


# ---------------------------------------------------------------- review hardening


def test_flooding_worker_is_killed(monkeypatch):
    evil_worker(monkeypatch, """
        chunk = b"A" * 65536
        while True:
            sys.stdout.buffer.write(chunk)
    """)
    t = time.monotonic()
    with pytest.raises(att.ExtractError, match=rf"^{TOO_COMPLEX} \(output limit\)$"):
        Sandbox(timeout_s=20).extract(b"x", "text/plain", "a.txt", charset=None, max_chars=100)
    assert time.monotonic() - t < 10  # killed at the cap, not at the timeout
    assert sb.output_cap(100) == 100 * 8 + 4096


def test_legit_output_near_the_cap_is_accepted():
    text = "\x01" * 5000  # worst case JSON escaping (6 bytes per char)
    ex = Sandbox().extract(text.encode(), "text/plain", "a.txt", charset="utf-8", max_chars=4000)
    assert ex.text == "\x01" * 4001  # max_chars + 1, so the caller still sees truncation


@pytest.mark.parametrize("result", [
    {"ok": True, "text": 42, "method": "text"},
    {"ok": True, "text": "x", "method": "evil"},
    {"ok": True, "text": "x", "method": ["text"]},
    {"ok": True, "text": "x", "method": "text", "note": {"a": 1}},
    {"ok": True, "text": "x", "method": "text", "skipped": "RLIMIT_AS"},
    {"ok": True, "text": "x" * 50, "method": "text"},  # longer than max_chars + 1
    {"ok": "yes", "text": "x", "method": "text"},
    {"ok": False, "error": "extract", "message": ["SECRET"]},
    {"ok": False, "error": "internal", "class": "Not An Identifier SECRET"},
    [1, 2, 3],
])
def test_malformed_worker_json(monkeypatch, result):
    import json
    script = f"import sys; sys.stdout.write({json.dumps(json.dumps(result))})"
    monkeypatch.setattr(sb, "WORKER_ARGV", [sys.executable, "-I", "-B", "-c", script])
    with pytest.raises(att.ExtractError) as e:
        Sandbox().extract(b"x", "text/plain", "a.txt", charset=None, max_chars=10)
    assert str(e.value).startswith(TOO_COMPLEX) and "SECRET" not in str(e.value)


def test_child_environment_has_no_secrets(monkeypatch):
    from surfski.config import SECRET_ENV
    for k in SECRET_ENV:
        monkeypatch.setenv(k, f"SECRET-VALUE-{k}")
    evil_worker(monkeypatch, """
        import json, os
        from surfski.attachments import Extracted
        return Extracted(json.dumps(dict(os.environ)), "text")
    """)
    env = __import__("json").loads(
        Sandbox().extract(b"x", "text/plain", "a.txt", charset=None, max_chars=100_000).text)
    assert not set(env) & set(SECRET_ENV)
    assert "SECRET-VALUE" not in str(env)
    # Only what the parent sets (macOS adds its own __CF_USER_TEXT_ENCODING).
    assert {k for k in env if not k.startswith("__CF_")} <= {"PATH", "HOME", "LANG", "LC_CTYPE"}


def test_scrub_secret_env(monkeypatch):
    from surfski.config import SECRET_ENV, scrub_secret_env
    monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", "k")
    monkeypatch.setenv("METRICS_TOKEN", "m")
    monkeypatch.setenv("BASE_URL", "https://x")
    removed = scrub_secret_env()
    assert set(removed) >= {"TOKEN_ENCRYPTION_KEY", "METRICS_TOKEN"}
    assert not any(k in os.environ for k in SECRET_ENV) and os.environ["BASE_URL"] == "https://x"


HARDEN_PROBE = """
import os, subprocess, sys
if sys.argv[1] == "harden":
    from surfski.sandbox import harden_process
    assert harden_process()
os.environ.clear()  # children get no env; the probe reads the parent's *initial* environ
child = (
    "import os, sys\\n"
    "try:\\n"
    "    data = open(f'/proc/{os.getppid()}/environ', 'rb').read()\\n"
    "    print('READ', b'PROBE-SECRET' in data)\\n"
    "except OSError as e:\\n"
    "    print('DENIED', type(e).__name__)\\n"
)
print(subprocess.run([sys.executable, "-I", "-c", child], capture_output=True, text=True).stdout.strip())
"""


@pytest.mark.skipif(not LINUX or os.geteuid() == 0,
                    reason="PR_SET_DUMPABLE is Linux-only; root bypasses it")
@pytest.mark.parametrize("mode,expected", [("plain", "READ True"), ("harden", "DENIED PermissionError")])
def test_child_cannot_read_hardened_parent_environ(mode, expected):
    import subprocess
    env = {**os.environ, "PROBE_TOKEN": "PROBE-SECRET"}
    out = subprocess.run([sys.executable, "-I", "-c", HARDEN_PROBE, mode], capture_output=True,
                         text=True, env=env)
    assert out.stdout.strip() == expected, out.stderr


def test_harden_process_is_safe_off_linux(monkeypatch):
    monkeypatch.setattr(sb.sys, "platform", "darwin")
    assert sb.harden_process() is False
