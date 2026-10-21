"""CI smoke (#43): run inside the hardened container after `surfski admin list` created
/data/data.db. Fails unless the extraction worker is fully confined there: Landlock
filesystem + kernel network block, the DB unreadable from the worker (but readable by
the server user), no socket, and strict-mode extraction of real files still working."""

import json
import sys
import textwrap

import surfski.sandbox as sb
from surfski.config import load_config
from surfski.sandbox import Sandbox

DB = "/data/data.db"
config = load_config()
assert config.extract_sandbox_strict, "run with EXTRACT_SANDBOX_STRICT=true"
with open(DB, "rb") as f:  # the server user can read it, so a denial below is the sandbox
    assert f.read(16).startswith(b"SQLite format 3")

box = Sandbox.from_config(config)
protection = box.probe()
print("protection:", json.dumps(protection))
assert protection["level"] == "full", protection

ex = box.extract(b"<p>sandbox ok</p>", "text/html", "x.html", charset=None, max_chars=100)
assert ex.text == "sandbox ok", ex

body = textwrap.dedent("""
    import errno, json, _socket
    from surfski.attachments import Extracted
    res = {}
    for p in ("/data/data.db", "/data", "/etc/passwd"):
        try:
            open(p, "rb").read(1) if p != "/data" else __import__("os").listdir(p)
            res[p] = "read"
        except OSError as e:
            res[p] = errno.errorcode.get(e.errno, str(e.errno))
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        s.connect(("1.1.1.1", 443))
        res["connect"] = "connected"
    except OSError as e:
        res["connect"] = errno.errorcode.get(e.errno, str(e.errno))
    return Extracted(json.dumps(res), "text")
""")
script = ("import sys\nfrom surfski import extract_worker\n"
          "def extract(data, mime_type, filename, *, charset, max_chars):\n"
          + textwrap.indent(body, "    ") + "\nsys.exit(extract_worker.main(extract=extract))\n")
sb.WORKER_ARGV = [sys.executable, "-I", "-B", "-c", script]
res = json.loads(box.extract(b"x", "text/plain", "a.txt", charset=None, max_chars=10_000).text)
print("worker probe:", json.dumps(res))
assert res["/data/data.db"] == "EACCES", res
assert res["/data"] == "EACCES", res
assert res["/etc/passwd"] == "EACCES", res
assert res["connect"] in ("EPERM", "EACCES"), res
print("extraction worker confinement ok")
