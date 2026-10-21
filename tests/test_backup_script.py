"""scripts/backup.sh, driven offline with a fake `docker` on PATH (#5)."""

import io
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "backup.sh"
MOUNT = "/var/lib/docker/volumes/surfski_surfski-data/_data"

SHIM = r"""#!/usr/bin/env bash
printf '%s\x1f' "$@" >> "$SHIM_LOG"; printf '\x1e' >> "$SHIM_LOG"
case "$1 $2" in
  "volume inspect") [ -n "${SHIM_NO_VOLUME:-}" ] && exit 1; echo "$SHIM_MOUNT"; exit 0 ;;
esac
if [ "$1" = ps ]; then printf '%s' "${SHIM_PS:-}"; exit 0; fi
if [ "$1" = run ]; then
  for a in "$@"; do
    if [ "$a" = "SURFSKI_BACKUP_MODE=list" ]; then printf '%b' "${SHIM_LISTING:-data.db\noauth\noauth/c.json\n}"; exit 0; fi
  done
  exit "${SHIM_RUN_EXIT:-0}"
fi
exit 0
"""

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


@pytest.fixture
def sh(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    shim = bindir / "docker"
    shim.write_text(SHIM)
    shim.chmod(0o755)
    log = tmp_path / "docker.log"

    def run(*args, **env):
        e = {"PATH": f"{bindir}:{os.environ['PATH']}", "SHIM_LOG": str(log), "SHIM_MOUNT": MOUNT,
             "HOME": str(tmp_path)}
        e.update(env)
        p = subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=e, timeout=30)
        calls = [rec.split("\x1f")[:-1] for rec in log.read_text().split("\x1e") if rec] if log.exists() else []
        log.unlink(missing_ok=True)
        return p, calls

    return run


def modes(calls):
    return [next((a.split("=", 1)[1] for a in c if a.startswith("SURFSKI_BACKUP_MODE=")), c[0]) for c in calls]


def test_help_and_usage_errors(sh):
    p, calls = sh("--help")
    assert p.returncode == 0 and "--restore" in p.stdout and "--dry-run" in p.stdout and calls == []
    assert sh("--bogus")[0].returncode == 2
    assert sh("--keep", "two")[0].returncode == 2
    assert sh("--volume", "bad name;rm")[0].returncode == 2


def test_dry_run_backup_prints_commands_and_writes_nothing(sh, tmp_path):
    dest = tmp_path / "backups"
    p, calls = sh("--dry-run", "--dest", str(dest), "--keep", "7")
    assert p.returncode == 0, p.stderr
    # Only read-only inspection actually ran: volume inspect + listing.
    assert modes(calls) == ["volume", "list"]
    listing = calls[1]
    assert "surfski_surfski-data:/data:ro" in listing and "--network" in listing and "none" in listing
    assert not dest.exists()
    out = p.stdout
    assert "+ docker run --rm --network none --user 0:0 -e SURFSKI_BACKUP_MODE=backup" in out
    assert "surfski_surfski-data:/data:ro" in out and f"{dest}:/out" in out
    assert "--entrypoint python surfski:latest -I -c" in out
    assert f"+ find {dest} -maxdepth 1 -type f -name surfski-data-\\*.tgz -mtime +7 -delete" in out
    assert "src.backup(dst)" in out  # SQLite online backup, not a raw copy of a live db
    assert "does not contain your keys" in out


def test_real_run_uses_volume_ro_and_private_dest(sh, tmp_path):
    dest = tmp_path / "b"
    p, calls = sh("--dest", str(dest), "--volume", "myvol", "--image", "surfski:1.2", "--keep", "0")
    assert p.returncode == 0, p.stderr
    assert modes(calls) == ["volume", "list", "backup"]
    backup = calls[2]
    assert "myvol:/data:ro" in backup and f"{dest}:/out" in backup and "surfski:1.2" in backup
    assert any(a.startswith("OUT_NAME=surfski-data-") and a.endswith(".tgz") for a in backup)
    assert any(a.startswith("HOST_OWNER=") for a in backup)
    assert stat.S_IMODE(dest.stat().st_mode) == 0o700


@pytest.mark.parametrize("bad", ["env", ".env", "prod.env", "oauth/keys.env", "ENV", "env.bak",
                                 ".env.local", "prod.ENV", "oauth/.Env.prod"])
def test_refuses_env_files_in_volume(sh, tmp_path, bad):
    p, calls = sh("--dest", str(tmp_path / "b"), SHIM_LISTING=f"data.db\\noauth\\n{bad}\\n")
    assert p.returncode == 3 and "looks like a secrets file" in p.stderr
    assert "backup" not in modes(calls) and not (tmp_path / "b").exists()


def test_refuses_env_file_inside_volume(sh, tmp_path):
    p, calls = sh("--dest", str(tmp_path / "b"), "--env-file", f"{MOUNT}/env")
    assert p.returncode == 3 and "inside the data volume" in p.stderr
    assert modes(calls) == ["volume"]


def test_missing_volume_and_failed_backup(sh, tmp_path):
    p, _ = sh("--dest", str(tmp_path / "b"), SHIM_NO_VOLUME="1")
    assert p.returncode == 1 and "not found" in p.stderr
    p, _ = sh("--dest", str(tmp_path / "b"), SHIM_RUN_EXIT="1")
    assert p.returncode == 1 and "backup failed" in p.stderr


def test_restore_guards(sh, tmp_path):
    archive = tmp_path / "surfski-data-20260101-000000.tgz"
    archive.write_bytes(b"x")
    p, calls = sh("--restore", str(archive))
    assert p.returncode == 3 and "docker compose stop app" in p.stderr and "--yes" in p.stderr
    assert "restore" not in modes(calls)
    p, calls = sh("--restore", str(archive), "--yes", SHIM_PS="abc123\n")
    assert p.returncode == 3 and "stop it first" in p.stderr and "restore" not in modes(calls)
    p, calls = sh("--restore", str(archive), "--yes", SHIM_RUN_EXIT="4")
    assert p.returncode == 3 and "add --force" in p.stderr
    p, calls = sh("--restore", str(archive), "--yes", "--force", SHIM_RUN_EXIT="3")
    assert p.returncode == 3 and "volume was not changed" in p.stderr
    p, calls = sh("--restore", str(archive), "--yes", "--force")
    assert p.returncode == 0 and modes(calls)[-1] == "restore"
    r = calls[-1]
    assert f"{tmp_path}:/in:ro" in r and "surfski_surfski-data:/data" in r and "FORCE=1" in r
    assert sh("--restore", str(tmp_path / "missing.tgz"), "--yes")[0].returncode == 1


def test_restore_dry_run(sh, tmp_path):
    archive = tmp_path / "a.tgz"
    archive.write_bytes(b"x")
    p, calls = sh("--restore", str(archive), "--yes", "--dry-run")
    assert p.returncode == 0 and "SURFSKI_BACKUP_MODE=restore" in p.stdout
    assert "restore" not in modes(calls)
    assert "filter=" in p.stdout  # tarfile's data filter: no absolute paths, .., or links


def test_existing_dest_is_never_chmodded(sh, tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    p, calls = sh("--dest", str(shared))
    assert p.returncode == 0, p.stderr
    assert stat.S_IMODE(shared.stat().st_mode) == 0o777  # untouched
    assert "accessible to other users" in p.stderr
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    p, _ = sh("--dest", str(private))
    assert p.returncode == 0 and "accessible" not in p.stderr
    p, _ = sh("--dry-run", "--dest", str(tmp_path / "new"))
    assert "+ mkdir -p -m 700" in p.stdout and "+ chmod" not in p.stdout


def test_mount_separators_rejected(sh, tmp_path):
    assert sh("--dest", f"{tmp_path}/a:b")[0].returncode == 2
    assert sh("--dest", f"{tmp_path}/a,b")[0].returncode == 2
    assert sh("--restore", f"{tmp_path}/x:y.tgz", "--yes")[0].returncode == 2


# ---- the Python run inside the container, executed locally on temp dirs ----


def embedded(var: str) -> str:
    text = SCRIPT.read_text()
    start = text.index(f"{var}=$(cat <<'PY'\n") + len(f"{var}=$(cat <<'PY'\n")
    return text[start:text.index("\nPY\n)", start)]


def run_py(var, **env):
    import sys
    e = dict(os.environ, **env)
    return subprocess.run([sys.executable, "-I", "-c", embedded(var)], capture_output=True, text=True,
                          env=e, timeout=30)


def make_volume(path: Path):
    import sqlite3
    path.mkdir()
    c = sqlite3.connect(path / "data.db")
    c.execute("create table t(x)")
    c.executemany("insert into t values (?)", [(i,) for i in range(50)])
    c.commit()
    c.close()
    (path / "oauth").mkdir()
    (path / "oauth" / "c.json").write_text("{}")


def test_python_backup_and_restore_roundtrip(tmp_path):
    import sqlite3
    import tarfile
    vol, out, dst = tmp_path / "vol", tmp_path / "out", tmp_path / "dst"
    make_volume(vol)
    out.mkdir()
    dst.mkdir()
    owner = f"{os.getuid()}:{os.getgid()}"
    p = run_py("PY_BACKUP", DATA_DIR=str(vol), OUT_DIR=str(out), OUT_NAME="a.tgz", HOST_OWNER=owner,
               TMPDIR=str(tmp_path))
    assert p.returncode == 0, p.stderr
    archive = out / "a.tgz"
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600 and not list(out.glob("*.partial"))
    assert sorted(tarfile.open(archive).getnames()) == ["data.db", "oauth/c.json"]
    p = run_py("PY_RESTORE", DATA_DIR=str(dst), IN_DIR=str(out), ARCHIVE_NAME="a.tgz", FORCE="0")
    assert p.returncode == 0, p.stderr
    assert sqlite3.connect(dst / "data.db").execute("select count(*) from t").fetchone() == (50,)
    # Non-empty target without --force.
    p = run_py("PY_RESTORE", DATA_DIR=str(dst), IN_DIR=str(out), ARCHIVE_NAME="a.tgz", FORCE="0")
    assert p.returncode == 4


def test_python_backup_refuses_secrets_and_cleans_partial(tmp_path):
    vol, out = tmp_path / "vol", tmp_path / "out"
    make_volume(vol)
    out.mkdir()
    (vol / "oauth" / "Prod.ENV").write_text("SECRET=1")
    p = run_py("PY_BACKUP", DATA_DIR=str(vol), OUT_DIR=str(out), OUT_NAME="a.tgz", HOST_OWNER="0:0")
    assert p.returncode == 3 and "looks like a secrets file" in p.stderr and list(out.iterdir()) == []
    (vol / "oauth" / "Prod.ENV").unlink()
    p = run_py("PY_BACKUP", DATA_DIR=str(vol), OUT_DIR=str(out), OUT_NAME="a.tgz", HOST_OWNER="bad")
    assert p.returncode != 0 and list(out.iterdir()) == []  # failed late: no .partial left behind


@pytest.mark.parametrize("bad_member", ["../evil.txt", "/etc/evil", "link", "x.env"])
def test_python_restore_validates_everything_before_emptying(tmp_path, bad_member):
    import tarfile
    dst, src = tmp_path / "dst", tmp_path / "in"
    make_volume(dst)
    src.mkdir()
    with tarfile.open(src / "bad.tgz", "w:gz") as tar:
        good = tarfile.TarInfo("data.db")
        good.size = 4
        tar.addfile(good, io.BytesIO(b"abcd"))
        bad = tarfile.TarInfo(bad_member)
        if bad_member == "link":
            bad.type, bad.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tar.addfile(bad)
        else:
            bad.size = 1
            tar.addfile(bad, io.BytesIO(b"x"))
    before = sorted(str(p.relative_to(dst)) for p in dst.rglob("*"))
    p = run_py("PY_RESTORE", DATA_DIR=str(dst), IN_DIR=str(src), ARCHIVE_NAME="bad.tgz", FORCE="1")
    assert p.returncode == 3 and "volume was not changed" in p.stderr
    assert sorted(str(p.relative_to(dst)) for p in dst.rglob("*")) == before
    assert (dst / "oauth" / "c.json").read_text() == "{}"
