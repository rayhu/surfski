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


# ---------------------------------------------------------------- kernel confinement (#43)

from surfski import confine  # noqa: E402

LANDLOCK_ABI = confine.landlock_abi()


def require_landlock():
    """Skip off Linux. On Linux without Landlock, skip locally but fail in CI, so a runner
    without Landlock can't go green while enforcing nothing."""
    if not LINUX:
        pytest.skip("Landlock and seccomp are Linux-only")
    if LANDLOCK_ABI == 0:
        if os.environ.get("CI"):
            pytest.fail("Landlock is unavailable on this CI runner")
        pytest.skip("Landlock is unavailable on this kernel")


PROBE_BODY = """
    import errno, json, _socket
    from surfski.attachments import Extracted
    paths, port = json.loads(data)
    res = {}
    for p in paths:
        try:
            open(p, "rb").read(1)
            res[p] = "read"
        except OSError as e:
            res[p] = errno.errorcode.get(e.errno, str(e.errno))
    try:  # the C-level socket, bypassing the Python monkeypatch
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        try:
            s.connect(("127.0.0.1", port))
            res["connect"] = "connected"
        finally:
            s.close()
    except OSError as e:
        res["connect"] = errno.errorcode.get(e.errno, str(e.errno))
    return Extracted(json.dumps(res), "text")
"""


def test_confined_worker_cannot_read_data_dir_or_connect(monkeypatch, tmp_path):
    require_landlock()
    import json
    import socket
    import sqlite3

    data_dir = tmp_path / "data"
    (data_dir / "oauth").mkdir(parents=True)
    db = data_dir / "data.db"
    sqlite3.connect(db).execute("create table t (x)").connection.close()
    secret = data_dir / "oauth" / "client.json"
    secret.write_text('{"secret": "x"}')
    for p in (db, secret):  # the server user can read them: a denial below is the sandbox
        assert open(p, "rb").read(1)
    assert confine.exposes(data_dir) is None
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        evil_worker(monkeypatch, PROBE_BODY)
        payload = json.dumps([[str(db), str(secret)], listener.getsockname()[1]]).encode()
        ex = Sandbox().extract(payload, "text/plain", "a.txt", charset=None, max_chars=10_000)
    finally:
        listener.close()
    res = json.loads(ex.text)
    assert res[str(db)] == "EACCES" and res[str(secret)] == "EACCES"
    assert res["connect"] in ("EPERM", "EACCES")  # seccomp (socket) or Landlock (connect)


def test_confined_worker_still_reads_pdf_and_docx_strict():
    require_landlock()
    box = Sandbox(strict=True)
    ex = box.extract(make_pdf(["Quarterly numbers"]), "application/pdf", "q.pdf", charset=None,
                     max_chars=1000)
    assert "Quarterly numbers" in ex.text
    ex = box.extract(make_docx(["Hello", "World"]), DOCX, "x.docx", charset=None, max_chars=1000)
    assert "Hello" in ex.text and "World" in ex.text


def test_probe_reports_full_protection(caplog):
    require_landlock()
    import logging
    from surfski.metrics import Metrics
    from surfski.server import probe_sandbox

    caplog.set_level(logging.INFO, "surfski.sandbox")
    box = Sandbox()
    m = Metrics()
    p = probe_sandbox(type("C", (), {"data_dir": "/nonexistent-data"})(), box, m)
    assert p["level"] == "full" and p["landlock_fs"] and p["landlock_abi"] == LANDLOCK_ABI
    assert box.protection == p
    assert "extraction sandbox protection: full" in caplog.text
    assert f'surfski_extract_sandbox_info{{level="full",landlock_abi="{LANDLOCK_ABI}"' in m.render(0, 0)


STRICT_NO_LANDLOCK = """
import sys
from surfski import confine, extract_worker
confine.landlock_abi = lambda: 0  # simulate a kernel without Landlock
called = []
def extract(*a, **k):
    called.append(1)
    raise SystemExit("parsed despite strict mode")
sys.exit(extract_worker.main(extract=extract))
"""


@pytest.mark.parametrize("strict", [True, False])
def test_strict_mode_refuses_without_landlock(monkeypatch, caplog, strict):
    monkeypatch.setattr(sb, "WORKER_ARGV", [sys.executable, "-I", "-B", "-c", STRICT_NO_LANDLOCK])
    box = Sandbox(strict=strict)
    with pytest.raises(att.ExtractError) as e:
        box.extract(b"x", "text/plain", "a.txt", charset=None, max_chars=10)
    if strict:
        assert str(e.value) == sb.SANDBOX_UNAVAILABLE
        assert "EXTRACT_SANDBOX_STRICT" in caplog.text
    else:  # non-strict: degrades and parses (here the fake parser exits)
        assert str(e.value).startswith(TOO_COMPLEX)


def test_probe_without_landlock_reports_degraded_level(monkeypatch, caplog):
    import logging
    script = STRICT_NO_LANDLOCK.replace(
        "sys.exit(extract_worker.main(extract=extract))",
        "from surfski.attachments import extract_text\nsys.exit(extract_worker.main(extract=extract_text))")
    monkeypatch.setattr(sb, "WORKER_ARGV", [sys.executable, "-I", "-B", "-c", script])
    caplog.set_level(logging.INFO, "surfski.sandbox")
    box = Sandbox(strict=True)
    p = box.probe()
    assert not p["landlock_fs"] and p["level"] in ("network", "basic")
    assert box.strict is True  # restored after probing
    assert "EXTRACT_SANDBOX_STRICT is on" in caplog.text
    from surfski.metrics import Metrics
    m = Metrics()
    m.set_extract_protection(p)
    assert f'surfski_extract_sandbox_info{{level="{p["level"]}"' in m.render(0, 0)


def test_probe_inprocess_and_metrics_bucketing():
    from surfski.metrics import Metrics
    assert Sandbox(mode="inprocess").probe()["level"] == "none"
    m = Metrics()
    assert "surfski_extract_sandbox_info" not in m.render(0, 0)
    m.set_extract_protection({"level": "SECRET", "landlock_abi": "x", "seccomp": "yes"})
    assert 'surfski_extract_sandbox_info{level="other",landlock_abi="other",seccomp="0"} 1' in m.render(0, 0)


def test_forged_protection_report_is_rejected(monkeypatch):
    import json
    result = {"ok": True, "text": "x", "method": "text", "protection": {"level": "SECRET"}}
    script = f"import sys; sys.stdout.write({json.dumps(json.dumps(result))})"
    monkeypatch.setattr(sb, "WORKER_ARGV", [sys.executable, "-I", "-B", "-c", script])
    with pytest.raises(att.ExtractError, match="malformed"):
        Sandbox().extract(b"x", "text/plain", "a.txt", charset=None, max_chars=10)


def test_allowed_paths_never_include_root_or_data(tmp_path):
    paths = confine.allowed_paths()
    assert "/" not in paths and all(os.path.isabs(p) and os.path.exists(p) for p in paths)
    assert confine.exposes(tmp_path / "data") is None
    assert confine.exposes(os.path.join(sys.prefix, "x", "data.db")) is not None


def test_seccomp_filter_program_shape():
    import struct
    for machine in ("x86_64", "aarch64"):
        prog = confine.seccomp_filter(machine)
        ins = [struct.unpack("=HBBI", prog[i:i + 8]) for i in range(0, len(prog), 8)]
        assert ins[-1] == (0x06, 0, 0, confine.SECCOMP_RET_ERRNO | confine.EPERM)
        assert ins[-2] == (0x06, 0, 0, confine.SECCOMP_RET_ALLOW)
        # every conditional jump that matches lands on the final ERRNO
        for i, (code, jt, jf, _k) in enumerate(ins):
            if code in (0x15, 0x35) and i > 1:
                assert i + 1 + jt == len(ins) - 1 and jf == 0
        assert 1 + 1 + ins[1][2] == len(ins) - 1  # foreign arch -> ERRNO
    assert confine.seccomp_filter("riscv64") is None


def test_strict_config(tmp_path):
    assert load_config(make_env(tmp_path)).extract_sandbox_strict is False
    c = load_config(make_env(tmp_path, EXTRACT_SANDBOX_STRICT="true"))
    assert c.extract_sandbox_strict and Sandbox.from_config(c).strict
    for bad in ({"EXTRACT_SANDBOX_STRICT": "maybe"},
                {"EXTRACT_SANDBOX_STRICT": "true", "EXTRACT_SANDBOX": "inprocess"}):
        with pytest.raises(ConfigError, match="EXTRACT_SANDBOX_STRICT"):
            load_config(make_env(tmp_path, **bad))


# ---------------------------------------------------------------- #33 review of #43

FS_ONLY = """
import sys
from surfski import confine, extract_worker
from surfski.attachments import extract_text
confine.landlock_abi_real = confine.landlock_abi
confine.landlock_abi = lambda: min(confine.landlock_abi_real(), 3)  # no Landlock TCP rules
confine.seccomp_restrict = lambda: False  # and no seccomp: filesystem-only protection
sys.exit(extract_worker.main(extract=extract_text))
"""


@pytest.mark.parametrize("strict", [True, False])
def test_strict_requires_full_level_not_just_filesystem(monkeypatch, caplog, strict):
    require_landlock()
    import logging
    monkeypatch.setattr(sb, "WORKER_ARGV", [sys.executable, "-I", "-B", "-c", FS_ONLY])
    caplog.set_level(logging.INFO, "surfski.sandbox")
    box = Sandbox(strict=strict)
    p = box.probe()
    assert p["level"] == "filesystem" and p["landlock_fs"] and not p["seccomp"]
    if strict:
        with pytest.raises(att.ExtractError, match="not fully available"):
            box.extract(b"hi", "text/plain", "a.txt", charset=None, max_chars=10)
        assert "EXTRACT_SANDBOX_STRICT is on" in caplog.text
    else:
        assert box.extract(b"hi", "text/plain", "a.txt", charset=None, max_chars=10).text == "hi"


def test_rules_failed_is_reported_and_type_checked(monkeypatch, caplog):
    import json
    import logging
    base = {"level": "full", "landlock_abi": 5, "landlock_fs": True, "landlock_net": True, "seccomp": True}
    assert sb.protection_of({"protection": {**base, "rules_failed": 2}})["rules_failed"] == 2
    assert sb.protection_of({"protection": base})["rules_failed"] == 0
    for bad in ("2", True, -1, 10_000):
        assert sb.protection_of({"protection": {**base, "rules_failed": bad}}) is None
    result = {"ok": True, "text": "probe", "method": "text", "protection": {**base, "rules_failed": 3}}
    script = f"import sys; sys.stdout.write({json.dumps(json.dumps(result))})"
    monkeypatch.setattr(sb, "WORKER_ARGV", [sys.executable, "-I", "-B", "-c", script])
    caplog.set_level(logging.DEBUG, "surfski.sandbox")
    assert Sandbox().probe()["rules_failed"] == 3
    assert "3 Landlock path rule(s) could not be added" in caplog.text


def test_confine_counts_rule_failures(monkeypatch):
    require_landlock()
    import subprocess
    code = ("import json, surfski.confine as c\n"
            "c.allowed_paths = lambda: [c.sys.prefix, '/nonexistent-surfski-path']\n"
            "print(json.dumps(c.confine()))")
    out = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True)
    import json
    rep = json.loads(out.stdout)
    assert rep["landlock_fs"] and rep["rules_failed"] == 1, out.stderr
