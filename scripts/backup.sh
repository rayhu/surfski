#!/usr/bin/env bash
# Back up (or restore) the Surfski data volume.
#
# The SQLite database is copied with Python's online backup API inside the Surfski
# image (consistent even while the server runs); oauth/ and other files are added
# as-is. Secrets (the env file, anything named env or *.env) are never archived:
# back up the env file separately, e.g. in a password manager.
#
# Exit codes: 0 ok, 1 error, 2 usage, 3 refused (secrets found, confirmation
# missing, non-empty target volume, server still running).

set -euo pipefail

VOLUME="surfski_surfski-data"
DEST="/var/backups/surfski"
KEEP=14
IMAGE="surfski:latest"
ENV_FILE="/etc/surfski/env"
DRY_RUN=0
RESTORE=""
YES=0
FORCE=0

usage() {
  cat <<'EOF'
Usage:
  backup.sh [options]                     create a backup archive
  backup.sh --restore ARCHIVE [options]   restore an archive into the volume

Backup options:
  --dest DIR        where archives go (default /var/backups/surfski)
  --keep DAYS       delete archives older than DAYS days (default 14; 0 keeps all)
Restore options:
  --restore FILE    archive to restore (stop the server first: docker compose stop app)
  --yes             confirm the restore
  --force           allow restoring over a non-empty volume (its contents are replaced)
Common options:
  --volume NAME     data volume (default surfski_surfski-data)
  --image IMAGE     Surfski image used for the copy (default surfski:latest)
  --env-file PATH   your env file, used only to make sure it can't be archived
                    (default /etc/surfski/env)
  --dry-run         print what would run; only read-only inspection is performed
  -h, --help        show this help

Archives are named surfski-data-YYYYmmdd-HHMMSS.tgz and written with mode 600.
They do NOT contain your keys: without TOKEN_ENCRYPTION_KEY and
STORAGE_ENCRYPTION_KEY a backup can't be used. Keep the env file elsewhere.
EOF
}

die() { echo "backup.sh: $1" >&2; exit "${2:-1}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --volume) VOLUME="${2:?--volume needs a value}"; shift 2 ;;
    --dest) DEST="${2:?--dest needs a value}"; shift 2 ;;
    --keep) KEEP="${2:?--keep needs a value}"; shift 2 ;;
    --image) IMAGE="${2:?--image needs a value}"; shift 2 ;;
    --env-file) ENV_FILE="${2:?--env-file needs a value}"; shift 2 ;;
    --restore) RESTORE="${2:?--restore needs an archive}"; shift 2 ;;
    --yes) YES=1; shift ;;
    --force) FORCE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" 2 ;;
  esac
done

case "$KEEP" in ''|*[!0-9]*) die "--keep must be a whole number of days" 2 ;; esac
case "$VOLUME" in ''|*[!A-Za-z0-9_.-]*) die "invalid volume name: $VOLUME" 2 ;; esac

# Runs a command, or only prints it with --dry-run.
run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '+'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

is_secret_name() {
  local base="${1##*/}"
  case "$base" in
    env|.env|*.env) return 0 ;;
  esac
  return 1
}

command -v docker >/dev/null 2>&1 || die "docker not found"

MOUNTPOINT="$(docker volume inspect -f '{{.Mountpoint}}' "$VOLUME" 2>/dev/null)" \
  || die "volume '$VOLUME' not found (see: docker volume ls)"

# The env file must never be inside the data volume.
case "$ENV_FILE" in
  "$MOUNTPOINT"/*) die "the env file $ENV_FILE is inside the data volume; move it out first" 3 ;;
esac

# Python run inside the Surfski image (it has Python, but no sqlite3 CLI).
PY_LIST=$(cat <<'PY'
import os
for root, dirs, files in os.walk("/data"):
    for name in files + dirs:
        print(os.path.relpath(os.path.join(root, name), "/data"))
PY
)

PY_BACKUP=$(cat <<'PY'
import os, sqlite3, sys, tarfile
out = "/out/" + os.environ["OUT_NAME"]
skip = {"data.db", "data.db-journal", "data.db-wal", "data.db-shm"}
def secret(name):
    b = os.path.basename(name)
    return b in ("env", ".env") or b.endswith(".env")
members = []
for root, dirs, files in os.walk("/data"):
    for name in files:
        rel = os.path.relpath(os.path.join(root, name), "/data")
        if secret(rel):
            sys.exit(f"refusing: {rel} looks like a secrets file")
        if rel not in skip:
            members.append(rel)
os.makedirs("/tmp/snap", exist_ok=True)
if os.path.exists("/data/data.db"):
    src = sqlite3.connect("file:/data/data.db?mode=ro", uri=True)
    dst = sqlite3.connect("/tmp/snap/data.db")
    with dst:
        src.backup(dst)  # online backup: a consistent snapshot even while the server writes
    dst.close(); src.close()
os.umask(0o077)
with tarfile.open(out + ".partial", "w:gz") as tar:
    if os.path.exists("/tmp/snap/data.db"):
        tar.add("/tmp/snap/data.db", arcname="data.db")
    for rel in sorted(members):
        tar.add(os.path.join("/data", rel), arcname=rel, recursive=False)
uid, gid = (int(x) for x in os.environ["HOST_OWNER"].split(":"))
os.chmod(out + ".partial", 0o600)
os.chown(out + ".partial", uid, gid)
os.replace(out + ".partial", out)
print(f"wrote {out} ({len(members) + 1} entries)")
PY
)

PY_RESTORE=$(cat <<'PY'
import os, shutil, sys, tarfile
archive, force = "/in/" + os.environ["ARCHIVE_NAME"], os.environ["FORCE"] == "1"
existing = os.listdir("/data")
if existing and not force:
    sys.exit(3)
def secret(name):
    b = os.path.basename(name)
    return b in ("env", ".env") or b.endswith(".env")
with tarfile.open(archive, "r:gz") as tar:
    members = tar.getmembers()
    for m in members:
        if secret(m.name) or not (m.isfile() or m.isdir()):
            sys.exit(f"refusing: unexpected archive entry {m.name!r}")
    for name in existing:
        p = os.path.join("/data", name)
        shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)
    tar.extractall("/data", filter="data")  # no absolute paths, no .., no links/devices
for root, dirs, files in os.walk("/data"):
    for name in dirs + files:
        os.chown(os.path.join(root, name), 10001, 10001)
        os.chmod(os.path.join(root, name), 0o700 if name in dirs else 0o600)
os.chown("/data", 10001, 10001)
print(f"restored {len(members)} entries")
PY
)

listing() {
  docker run --rm --network none --user 0:0 -e SURFSKI_BACKUP_MODE=list \
    -v "$VOLUME":/data:ro --entrypoint python "$IMAGE" -I -c "$PY_LIST"
}

# ---------------------------------------------------------------- restore

if [ -n "$RESTORE" ]; then
  [ -f "$RESTORE" ] || die "archive not found: $RESTORE"
  is_secret_name "$RESTORE" && die "refusing to restore a file named like an env file" 3
  if [ "$YES" -ne 1 ]; then
    cat >&2 <<EOF
Restore replaces the contents of volume '$VOLUME' with $RESTORE.
  1. Stop the server:      docker compose stop app
  2. Run again with --yes  (add --force if the volume is not empty)
  3. Start the server:     docker compose start app
Your env file (keys) must be the one that was in use when the backup was made.
EOF
    exit 3
  fi
  if [ -n "$(docker ps -q --filter "volume=$VOLUME")" ]; then
    die "a container is using '$VOLUME'; stop it first (docker compose stop app)" 3
  fi
  dir="$(cd "$(dirname "$RESTORE")" && pwd)"
  base="$(basename "$RESTORE")"
  set +e
  run docker run --rm --network none --user 0:0 -e SURFSKI_BACKUP_MODE=restore \
    -e ARCHIVE_NAME="$base" -e FORCE="$FORCE" \
    -v "$VOLUME":/data -v "$dir":/in:ro --entrypoint python "$IMAGE" -I -c "$PY_RESTORE"
  code=$?
  set -e
  [ "$code" -eq 3 ] && die "volume '$VOLUME' is not empty; add --force to replace its contents" 3
  [ "$code" -eq 0 ] || die "restore failed (exit $code)"
  echo "Restore done. Start the server: docker compose start app"
  exit 0
fi

# ---------------------------------------------------------------- backup

files="$(listing)" || die "could not list volume '$VOLUME' (is the image '$IMAGE' built?)"
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if is_secret_name "$f"; then
    die "refusing to back up: '$f' in the volume looks like a secrets file. Remove it from the volume; keep keys in the env file, backed up separately." 3
  fi
done <<<"$files"

umask 077
stamp="$(date +%Y%m%d-%H%M%S)"
name="surfski-data-$stamp.tgz"
run mkdir -p "$DEST"
run chmod 700 "$DEST"
if [ "$DRY_RUN" -eq 0 ]; then
  DEST="$(cd "$DEST" && pwd)"
fi
run docker run --rm --network none --user 0:0 -e SURFSKI_BACKUP_MODE=backup \
  -e OUT_NAME="$name" -e HOST_OWNER="$(id -u):$(id -g)" \
  -v "$VOLUME":/data:ro -v "$DEST":/out --entrypoint python "$IMAGE" -I -c "$PY_BACKUP" \
  || die "backup failed; nothing was written"
if [ "$KEEP" -gt 0 ]; then
  run find "$DEST" -maxdepth 1 -type f -name 'surfski-data-*.tgz' -mtime "+$KEEP" -delete
fi
echo "Backup: $DEST/$name"
echo "Reminder: this archive does not contain your keys. Back up $ENV_FILE separately (e.g. a password manager)."
