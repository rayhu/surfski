"""`surfski` command line: `serve` (the default) and local `admin` subcommands (#7).

The admin commands open the SQLite database directly. They are only reachable from a
shell on the host or inside the container (`docker compose -p surfski exec app surfski
admin ...`); there is no network admin endpoint. They never print refresh tokens,
ciphertext or keys.

Exit codes: 0 success; 1 refused or failed (unknown owner/alias, missing --yes, a failed
revocation at Google, undecryptable rows during rotation); 2 usage or configuration error.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import UTC, datetime, timedelta

import anyio
import httpx

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


def _parser() -> argparse.ArgumentParser:
    from .version import __version__

    p = argparse.ArgumentParser(prog="surfski", description="Surfski MCP server and admin tools.")
    p.add_argument("--version", action="version", version=f"surfski {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="{serve,admin}")
    sub.add_parser("serve", help="run the MCP server (the default)")

    admin = sub.add_parser("admin", help="local administration (no network endpoint)")
    admin.add_argument("--debug", action="store_true", help="show a traceback on unexpected errors")
    a = admin.add_subparsers(dest="admin_cmd", metavar="COMMAND", required=True)

    ls = a.add_parser("list", help="owners and their linked mailboxes (never tokens)")
    ls.add_argument("--json", action="store_true", help="machine-readable output")

    un = a.add_parser("unlink", help="remove one linked mailbox of one owner")
    un.add_argument("--owner", required=True)
    un.add_argument("--alias", required=True)
    un.add_argument("--revoke", action="store_true",
                    help="also revoke the refresh token at Google (needs outbound network)")

    pu = a.add_parser("purge-owner", help="erase ALL data of one owner (as delete_my_data)")
    pu.add_argument("--owner", required=True)
    pu.add_argument("--yes", action="store_true", help="confirm; without it nothing is deleted")

    ro = a.add_parser("rotate-token-key",
                      help="re-encrypt every stored refresh token with the current key")
    ro.add_argument("--dry-run", action="store_true", help="check and count, change nothing")

    au = a.add_parser("audit", help="audit row counts per tool for one owner (no details)")
    au.add_argument("--owner", required=True)
    au.add_argument("--since", default="30d",
                    help="ISO date/time (2026-10-01, 2026-10-01T12:00:00) or Nd for N days (default 30d)")
    return p


def parse_since(value: str, now: datetime | None = None) -> str:
    """ISO timestamp (UTC) comparable with audit_log.ts."""
    now = now or datetime.now(UTC)
    v = value.strip()
    m = re.fullmatch(r"(\d{1,4})d", v)
    if m:
        dt = now - timedelta(days=int(m.group(1)))
    else:
        try:
            dt = datetime.fromisoformat(v)
        except ValueError:
            raise ValueError(f"--since {value!r}: use an ISO date/time or Nd") from None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def main(argv: list[str] | None = None, *, http_factory=None) -> int:
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    if args.cmd in (None, "serve"):
        from . import server

        server.main()
        return EXIT_OK
    return admin(args, http_factory=http_factory)


def _open_storage():
    from .config import ConfigError, load_config
    from .storage import Storage, TokenCipher

    try:
        config = load_config()
    except ConfigError as e:
        print(f"error: configuration: {e}", file=sys.stderr)
        return None, None
    return config, Storage(config.db_path, TokenCipher.from_config(config))


def admin(args: argparse.Namespace, *, http_factory=None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    from .audit import install_log_redaction

    install_log_redaction()
    storage = None
    try:
        config, storage = _open_storage()
        if storage is None:
            return EXIT_USAGE
        http_factory = http_factory or (lambda: httpx.AsyncClient(timeout=15))
        return _COMMANDS[args.admin_cmd](args, config, storage, http_factory)
    except Exception as e:  # noqa: BLE001  (e.g. sqlite3.OperationalError: database is locked)
        if getattr(args, "debug", False):
            raise
        from .audit import redact

        msg = redact(" ".join(str(e).split()))[:200]
        print(f"error: {type(e).__name__}: {msg} (re-run with admin --debug for a traceback)",
              file=sys.stderr)
        return EXIT_FAIL
    finally:
        if storage is not None:
            storage.close()


def cmd_list(args, config, storage, http_factory) -> int:
    accounts = storage.admin_list_accounts()
    rows = [{"owner": a.owner, "alias": a.alias, "email": a.email, "created_at": a.created_at,
             "last_used_at": a.last_used_at, "send_policy": a.send_policy,
             "triage": "on" if a.triage_active else "off"} for a in accounts]
    if args.json:
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    if not rows:
        print("no linked mailboxes")
        return EXIT_OK
    owner = None
    for r in rows:
        if r["owner"] != owner:
            owner = r["owner"]
            print(owner)
        print(f"  {r['alias']:<16} {r['email']:<32} created={r['created_at']} "
              f"last_used={r['last_used_at'] or '-'} send_policy={r['send_policy']} triage={r['triage']}")
    owners = len({r["owner"] for r in rows})
    print(f"{owners} owner(s), {len(rows)} mailbox(es)")
    return EXIT_OK


def cmd_unlink(args, config, storage, http_factory) -> int:
    from .audit import write_audit
    from .server import unlink_mailbox
    from .storage import AccountNotFound

    owner = args.owner.strip().lower()
    try:
        revoked = anyio.run(lambda: unlink_mailbox(storage, http_factory, owner, args.alias,
                                                   revoke=args.revoke))
    except (AccountNotFound, ValueError):
        print(f"error: owner {owner} has no linked mailbox '{args.alias}'", file=sys.stderr)
        return EXIT_FAIL
    alias = args.alias.strip().lower()
    write_audit(storage, owner, "admin_unlink", alias, f"revoked={revoked}", True)
    msg = f"unlinked {owner} / {alias}"
    if args.revoke:
        msg += "; token revoked at Google" if revoked else (
            "; revocation at Google FAILED (remove it at https://myaccount.google.com/permissions)")
    print(msg)
    return EXIT_OK if (revoked or not args.revoke) else EXIT_FAIL


def cmd_purge(args, config, storage, http_factory) -> int:
    from .server import purge_owner_data

    owner = args.owner.strip().lower()
    if not args.yes:
        n = sum(1 for a in storage.admin_list_accounts() if a.owner == owner)
        print(f"refusing: this erases ALL data of {owner} ({n} linked mailbox(es)) and cannot "
              "be undone. Re-run with --yes.", file=sys.stderr)
        return EXIT_FAIL
    result = anyio.run(lambda: purge_owner_data(config, storage, http_factory, owner,
                                                tool="admin_purge_owner"))
    deleted = ", ".join(f"{t}={n}" for t, n in result["deleted"].items())
    print(f"purged {owner}: {deleted}; audit log {result['audit_log']}")
    for alias, v in result["revoked_at_google"].items():
        print(f"  {alias}: {'revoked at Google' if v is True else (v or 'revocation failed')}")
    if result["note"]:
        print(result["note"])
    # The data is gone either way; exit 1 tells a script some revocation needs a manual look.
    return EXIT_FAIL if any(v is not True for v in result["revoked_at_google"].values()) else EXIT_OK


def cmd_rotate(args, config, storage, http_factory) -> int:
    from .storage import KeyRotationError

    try:
        r = storage.admin_rotate_token_key(dry_run=args.dry_run)
    except KeyRotationError as e:
        print(f"refusing: {e}. Affected mailboxes (owner / alias):", file=sys.stderr)
        for owner, alias in e.affected:
            print(f"  {owner} / {alias}", file=sys.stderr)
        print("Set TOKEN_ENCRYPTION_KEY_OLD (or TOKEN_ENCRYPTION_KEYS_OLD) to the key they were "
              "encrypted with, or have those mailboxes relinked / unlinked.", file=sys.stderr)
        return EXIT_FAIL
    verb = "would re-encrypt" if args.dry_run else "re-encrypted"
    print(f"{verb} {r['rotated']} of {r['total']} token(s); {r['already_current']} already on the "
          "current key")
    return EXIT_OK


def cmd_audit(args, config, storage, http_factory) -> int:
    try:
        since = parse_since(args.since)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    rows = storage.admin_audit_counts(args.owner, since)
    print(f"{args.owner.strip().lower()} since {since}")
    if not rows:
        print("  no audit rows")
    for r in rows:
        print(f"  {r['tool']:<24} ok={r['ok']} failed={r['failed']}")
    return EXIT_OK


_COMMANDS = {
    "list": cmd_list,
    "unlink": cmd_unlink,
    "purge-owner": cmd_purge,
    "rotate-token-key": cmd_rotate,
    "audit": cmd_audit,
}


if __name__ == "__main__":
    sys.exit(main())
