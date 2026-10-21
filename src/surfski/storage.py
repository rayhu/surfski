"""SQLite persistence. Every `accounts` query is scoped by owner; there is no
cross-owner read path."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
import threading
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ALIAS_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
def scrub_emails(text: str) -> str:
    """Redact every whitespace-separated token containing '@' or full-width '＠'.
    Cruder than an address regex, but nothing address-like can slip through."""
    return re.sub(r"\S*[@＠]\S*", "<email>", text or "")
LABEL_RE = ALIAS_RE

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
  owner TEXT NOT NULL,
  alias TEXT NOT NULL,
  email TEXT NOT NULL,
  refresh_token_enc BLOB NOT NULL,
  scopes TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  PRIMARY KEY (owner, alias)
);
CREATE TABLE IF NOT EXISTS pending_links (
  nonce TEXT PRIMARY KEY,
  owner TEXT,
  alias TEXT,
  exp INTEGER,
  used INTEGER DEFAULT 0,
  code_verifier TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
  ts TEXT, owner TEXT, tool TEXT, alias TEXT, detail TEXT, ok INTEGER
);
CREATE TABLE IF NOT EXISTS action_tokens (
  nonce TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  alias TEXT NOT NULL,
  purpose TEXT NOT NULL,
  exp INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  data TEXT
);
CREATE TABLE IF NOT EXISTS owner_sessions (
  id_hash TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  exp INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sends (
  owner TEXT NOT NULL,
  alias TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS address_labels (
  owner TEXT NOT NULL,
  alias TEXT NOT NULL,
  address TEXT NOT NULL,
  label TEXT NOT NULL,
  PRIMARY KEY (owner, alias, address),
  UNIQUE (owner, alias, label)
);
"""

# Columns added after the first release; applied with a guarded ALTER TABLE.
MIGRATIONS = [
    ("accounts", "default_from", "TEXT"),
    ("accounts", "send_policy", "TEXT NOT NULL DEFAULT 'off'"),
]

ACCOUNT_COLS = "owner, alias, email, scopes, created_at, last_used_at, default_from, send_policy"
SEND_POLICIES = ("off", "confirm", "auto")  # ordered from least to most permissive


class StorageError(Exception):
    pass


class AccountNotFound(StorageError):
    pass


def validate_alias(alias: str) -> str:
    alias = (alias or "").strip().lower()
    if not ALIAS_RE.match(alias):
        raise ValueError("alias must match [a-z0-9_-]{1,32}")
    return alias


def validate_label(label: str) -> str:
    label = (label or "").strip().lower()
    if not LABEL_RE.match(label):
        raise ValueError("label must match [a-z0-9_-]{1,32}")
    return label


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Account:
    owner: str
    alias: str
    email: str
    scopes: str
    created_at: str
    last_used_at: str | None
    default_from: str | None = None
    send_policy: str = "off"

    def public(self) -> dict:
        return {
            "alias": self.alias,
            "email": self.email,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "default_from": self.default_from,
            "send_policy": self.send_policy,
        }


class TokenCipher:
    """Fernet encryption with optional per-owner keys."""

    def __init__(self, default_key: str, per_owner: dict[str, str] | None = None):
        self._default = Fernet(default_key.encode())
        self._per_owner = {
            o.lower(): Fernet(k.encode()) for o, k in (per_owner or {}).items()
        }

    def _for(self, owner: str) -> Fernet:
        return self._per_owner.get(owner.lower(), self._default)

    def encrypt(self, owner: str, plaintext: str) -> bytes:
        return self._for(owner).encrypt(plaintext.encode())

    def decrypt(self, owner: str, ciphertext: bytes) -> str:
        try:
            return self._for(owner).decrypt(ciphertext).decode()
        except InvalidToken as e:
            raise StorageError("stored token cannot be decrypted with current key") from e


class Storage:
    def __init__(self, db_path: Path | str, cipher: TokenCipher):
        self.db_path = str(db_path)
        self.cipher = cipher
        self._lock = threading.Lock()
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not os.path.exists(self.db_path):
                fd = os.open(self.db_path, os.O_CREAT | os.O_WRONLY, 0o600)
                os.close(fd)
            os.chmod(self.db_path, 0o600)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            for table, col, decl in MIGRATIONS:
                cols = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}
                if col not in cols:
                    self._add_column(table, col, decl)
            self._conn.commit()

    def _add_column(self, table: str, col: str, decl: str) -> None:
        """ALTER TABLE ADD COLUMN, tolerating a concurrent process that added it first."""
        try:
            self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        except sqlite3.OperationalError as e:
            if "duplicate column name" not in str(e).lower():
                raise

    @contextmanager
    def _tx(self):
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def close(self) -> None:
        self._conn.close()

    # ---- accounts (always owner-scoped) ----

    def upsert_account(
        self, owner: str, alias: str, email: str, refresh_token: str, scopes: str
    ) -> None:
        owner = owner.lower()
        alias = validate_alias(alias)
        enc = self.cipher.encrypt(owner, refresh_token)
        email = email.lower()
        with self._tx() as c:
            prev = c.execute(
                "SELECT email FROM accounts WHERE owner = ? AND alias = ?", (owner, alias)
            ).fetchone()
            if prev and prev["email"] != email:
                # A different mailbox under the same alias: its labels, default From and
                # send policy don't apply, and pending action links must die with it.
                c.execute("DELETE FROM address_labels WHERE owner = ? AND alias = ?", (owner, alias))
                c.execute(
                    "UPDATE accounts SET default_from = NULL, send_policy = 'off' "
                    "WHERE owner = ? AND alias = ?",
                    (owner, alias),
                )
                c.execute(
                    "UPDATE action_tokens SET used = 1 WHERE owner = ? AND alias = ?", (owner, alias)
                )
            c.execute(
                """INSERT INTO accounts (owner, alias, email, refresh_token_enc, scopes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(owner, alias) DO UPDATE SET
                     email=excluded.email,
                     refresh_token_enc=excluded.refresh_token_enc,
                     scopes=excluded.scopes,
                     created_at=excluded.created_at,
                     last_used_at=NULL""",
                (owner, alias, email, enc, scopes, now_iso()),
            )

    def list_accounts(self, owner: str) -> list[Account]:
        with self._tx() as c:
            rows = c.execute(
                f"SELECT {ACCOUNT_COLS} FROM accounts WHERE owner = ? ORDER BY alias",
                (owner.lower(),),
            ).fetchall()
        return [Account(**dict(r)) for r in rows]

    def get_account(self, owner: str, alias: str) -> Account:
        alias = validate_alias(alias)
        with self._tx() as c:
            row = c.execute(
                f"SELECT {ACCOUNT_COLS} FROM accounts WHERE owner = ? AND alias = ?",
                (owner.lower(), alias),
            ).fetchone()
        if not row:
            raise AccountNotFound(
                f"no linked account '{alias}'. Call list_accounts to see your accounts."
            )
        return Account(**dict(row))

    def get_refresh_token(self, owner: str, alias: str) -> str:
        owner = owner.lower()
        alias = validate_alias(alias)
        with self._tx() as c:
            row = c.execute(
                "SELECT refresh_token_enc FROM accounts WHERE owner = ? AND alias = ?",
                (owner, alias),
            ).fetchone()
        if not row:
            raise AccountNotFound(
                f"no linked account '{alias}'. Call list_accounts to see your accounts."
            )
        return self.cipher.decrypt(owner, row["refresh_token_enc"])

    def account_exists(self, owner: str, alias: str) -> bool:
        with self._tx() as c:
            return c.execute(
                "SELECT 1 FROM accounts WHERE owner = ? AND alias = ?", (owner.lower(), alias)
            ).fetchone() is not None

    def touch_account(self, owner: str, alias: str) -> bool:
        """Update last_used_at; False if the account no longer exists."""
        with self._tx() as c:
            cur = c.execute(
                "UPDATE accounts SET last_used_at = ? WHERE owner = ? AND alias = ?",
                (now_iso(), owner.lower(), alias),
            )
        return cur.rowcount > 0

    def delete_account(self, owner: str, alias: str) -> bool:
        alias = validate_alias(alias)
        with self._tx() as c:
            cur = c.execute(
                "DELETE FROM accounts WHERE owner = ? AND alias = ?",
                (owner.lower(), alias),
            )
            c.execute(
                "DELETE FROM address_labels WHERE owner = ? AND alias = ?", (owner.lower(), alias)
            )
            c.execute(
                "UPDATE action_tokens SET used = 1 WHERE owner = ? AND alias = ?", (owner.lower(), alias)
            )
        return cur.rowcount > 0

    def rename_account(self, owner: str, old_alias: str, new_alias: str) -> None:
        owner = owner.lower()
        old_alias, new_alias = validate_alias(old_alias), validate_alias(new_alias)
        with self._tx() as c:
            if not c.execute(
                "SELECT 1 FROM accounts WHERE owner = ? AND alias = ?", (owner, old_alias)
            ).fetchone():
                raise AccountNotFound(
                    f"no linked account '{old_alias}'. Call list_accounts to see your accounts."
                )
            if old_alias == new_alias:
                return
            if c.execute(
                "SELECT 1 FROM accounts WHERE owner = ? AND alias = ?", (owner, new_alias)
            ).fetchone():
                raise StorageError(f"alias '{new_alias}' is already in use")
            c.execute(
                "UPDATE accounts SET alias = ? WHERE owner = ? AND alias = ?",
                (new_alias, owner, old_alias),
            )
            c.execute(
                "UPDATE address_labels SET alias = ? WHERE owner = ? AND alias = ?",
                (new_alias, owner, old_alias),
            )
            c.execute(
                "UPDATE sends SET alias = ? WHERE owner = ? AND alias = ?", (new_alias, owner, old_alias)
            )
            # Links name the old alias; kill them rather than let them dangle.
            c.execute(
                "UPDATE action_tokens SET used = 1 WHERE owner = ? AND alias = ?", (owner, old_alias)
            )

    # ---- send-from settings (always owner-scoped) ----

    def _require_account(self, c, owner: str, alias: str) -> None:
        if not c.execute(
            "SELECT 1 FROM accounts WHERE owner = ? AND alias = ?", (owner, alias)
        ).fetchone():
            raise AccountNotFound(
                f"no linked account '{alias}'. Call list_accounts to see your accounts."
            )

    def set_default_from(self, owner: str, alias: str, address: str | None) -> None:
        owner, alias = owner.lower(), validate_alias(alias)
        with self._tx() as c:
            self._require_account(c, owner, alias)
            c.execute(
                "UPDATE accounts SET default_from = ? WHERE owner = ? AND alias = ?",
                ((address or "").lower() or None, owner, alias),
            )

    def get_address_labels(self, owner: str, alias: str) -> dict[str, str]:
        """{label: address} for one mailbox of this owner."""
        with self._tx() as c:
            rows = c.execute(
                "SELECT label, address FROM address_labels WHERE owner = ? AND alias = ? ORDER BY label",
                (owner.lower(), validate_alias(alias)),
            ).fetchall()
        return {r["label"]: r["address"] for r in rows}

    def set_address_label(self, owner: str, alias: str, address: str, label: str) -> None:
        """Set (or, with an empty label, remove) the label of one address."""
        owner, alias, address = owner.lower(), validate_alias(alias), address.strip().lower()
        label = validate_label(label) if (label or "").strip() else ""
        with self._tx() as c:
            self._require_account(c, owner, alias)
            if label:
                taken = c.execute(
                    "SELECT address FROM address_labels WHERE owner = ? AND alias = ? AND label = ?",
                    (owner, alias, label),
                ).fetchone()
                if taken and taken["address"] != address:
                    raise StorageError(f"label '{label}' is already used for {taken['address']}")
            c.execute(
                "DELETE FROM address_labels WHERE owner = ? AND alias = ? AND address = ?",
                (owner, alias, address),
            )
            if label:
                c.execute(
                    "INSERT INTO address_labels (owner, alias, address, label) VALUES (?, ?, ?, ?)",
                    (owner, alias, address, label),
                )

    # ---- sending (#2) ----

    def set_send_policy(self, owner: str, alias: str, policy: str) -> None:
        if policy not in SEND_POLICIES:
            raise ValueError(f"send policy must be one of {', '.join(SEND_POLICIES)}")
        owner, alias = owner.lower(), validate_alias(alias)
        with self._tx() as c:
            self._require_account(c, owner, alias)
            c.execute(
                "UPDATE accounts SET send_policy = ? WHERE owner = ? AND alias = ?",
                (policy, owner, alias),
            )

    def add_action_token(
        self, nonce: str, owner: str, alias: str, purpose: str, exp: int, data: str
    ) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM action_tokens WHERE exp < strftime('%s','now') - 86400")
            c.execute(
                "INSERT INTO action_tokens (nonce, owner, alias, purpose, exp, used, data) "
                "VALUES (?, ?, ?, ?, ?, 0, ?)",
                (nonce, owner.lower(), alias, purpose, exp, data),
            )

    def peek_action_token(self, nonce: str, owner: str, alias: str, purpose: str, now: int) -> str | None:
        """Return the token's data if it exists, matches and is unused and unexpired."""
        with self._tx() as c:
            row = c.execute(
                "SELECT data FROM action_tokens WHERE nonce = ? AND owner = ? AND alias = ? "
                "AND purpose = ? AND used = 0 AND exp >= ?",
                (nonce, owner.lower(), alias, purpose, now),
            ).fetchone()
        return row["data"] if row else None

    def consume_action_token(self, nonce: str, owner: str, alias: str, purpose: str, now: int) -> str | None:
        """Atomically mark a matching, unused, unexpired token used; returns its data."""
        with self._tx() as c:
            row = c.execute(
                "SELECT data FROM action_tokens WHERE nonce = ? AND owner = ? AND alias = ? "
                "AND purpose = ? AND used = 0 AND exp >= ?",
                (nonce, owner.lower(), alias, purpose, now),
            ).fetchone()
            if not row:
                return None
            cur = c.execute("UPDATE action_tokens SET used = 1 WHERE nonce = ? AND used = 0", (nonce,))
            return row["data"] if cur.rowcount == 1 else None

    def create_owner_session(self, owner: str, ttl: int, now: int) -> str:
        """New browser session for /send pages. Returns the raw id (cookie value);
        only its sha256 is stored."""
        raw = secrets.token_urlsafe(32)
        with self._tx() as c:
            c.execute("DELETE FROM owner_sessions WHERE exp < ?", (now,))
            c.execute(
                "INSERT INTO owner_sessions (id_hash, owner, created_at, exp) VALUES (?, ?, ?, ?)",
                (hashlib.sha256(raw.encode()).hexdigest(), owner.lower(), now, now + ttl),
            )
        return raw

    def delete_owner_session(self, raw: str | None) -> bool:
        if not raw:
            return False
        with self._tx() as c:
            cur = c.execute(
                "DELETE FROM owner_sessions WHERE id_hash = ?", (hashlib.sha256(raw.encode()).hexdigest(),)
            )
        return cur.rowcount > 0

    def prune_owner_sessions(self, is_allowed: Callable[[str], bool] | frozenset[str] | set[str],
                             now: int) -> int:
        """Drop expired sessions and those of owners no longer allowed (`is_allowed` is a
        predicate such as Config.is_allowed, or a set of owners)."""
        check = is_allowed if callable(is_allowed) else is_allowed.__contains__
        with self._tx() as c:
            rows = c.execute("SELECT DISTINCT owner FROM owner_sessions").fetchall()
            gone = [r["owner"] for r in rows if not check(r["owner"])]
            n = c.execute("DELETE FROM owner_sessions WHERE exp < ?", (now,)).rowcount
            for o in gone:
                n += c.execute("DELETE FROM owner_sessions WHERE owner = ?", (o,)).rowcount
        return n

    def get_owner_session(self, raw: str | None, now: int) -> tuple[str, int] | None:
        """(owner, created_at) for a live session, else None."""
        if not raw:
            return None
        with self._tx() as c:
            row = c.execute(
                "SELECT owner, created_at FROM owner_sessions WHERE id_hash = ? AND exp >= ?",
                (hashlib.sha256(raw.encode()).hexdigest(), now),
            ).fetchone()
        return (row["owner"], row["created_at"]) if row else None

    def reserve_send(self, owner: str, alias: str, cap: int, now: int) -> int | None:
        """Atomically count sends in the rolling 24 h and, if under cap, record one.
        Returns the reservation rowid, or None when the cap is reached."""
        with self._tx() as c:
            (n,) = c.execute(
                "SELECT COUNT(*) FROM sends WHERE owner = ? AND alias = ? AND ts > ?",
                (owner.lower(), alias, now - 86400),
            ).fetchone()
            if n >= cap:
                return None
            cur = c.execute(
                "INSERT INTO sends (owner, alias, ts) VALUES (?, ?, ?)", (owner.lower(), alias, now)
            )
            return cur.lastrowid

    def release_send(self, rowid: int) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM sends WHERE rowid = ?", (rowid,))

    def sends_today(self, owner: str, alias: str, now: int) -> int:
        with self._tx() as c:
            (n,) = c.execute(
                "SELECT COUNT(*) FROM sends WHERE owner = ? AND alias = ? AND ts > ?",
                (owner.lower(), alias, now - 86400),
            ).fetchone()
        return n

    # ---- the caller's own data (#3) ----

    # Every table with an owner column. tests/test_delete_my_data.py checks this
    # list against the live schema so a new owner-keyed table can't be forgotten.
    # That guard only works if the column is literally named `owner`: any new table
    # holding per-user data must use that name (see CONTRIBUTING.md).
    OWNER_TABLES = ("accounts", "address_labels", "pending_links", "action_tokens",
                    "owner_sessions", "sends", "audit_log")

    def purge_owner(
        self, owner: str, audit_pseudonym: str | None = None
    ) -> tuple[dict[str, int], list[tuple[str, str | None]]]:
        """Delete every row of this owner in one transaction and return
        (counts per table, [(alias, refresh token or None if undecryptable)]). The tokens
        are read in the same transaction, so a link completing concurrently is either
        purged and returned for revocation, or created after the purge.

        With audit_pseudonym the audit rows are kept, re-keyed to it, with alias blanked
        and any email address in detail replaced; otherwise they are deleted."""
        owner = owner.lower()
        counts: dict[str, int] = {}
        tokens: list[tuple[str, str | None]] = []
        with self._tx() as c:
            for row in c.execute(
                "SELECT alias, refresh_token_enc FROM accounts WHERE owner = ? ORDER BY alias", (owner,)
            ).fetchall():
                try:
                    tokens.append((row["alias"], self.cipher.decrypt(owner, row["refresh_token_enc"])))
                except StorageError:
                    tokens.append((row["alias"], None))
            for table in self.OWNER_TABLES:
                if table == "audit_log" and audit_pseudonym:
                    rows = c.execute(
                        "SELECT rowid, detail FROM audit_log WHERE lower(owner) = ?", (owner,)
                    ).fetchall()
                    for r in rows:
                        c.execute(
                            "UPDATE audit_log SET owner = ?, alias = NULL, detail = ? WHERE rowid = ?",
                            (audit_pseudonym, scrub_emails(r["detail"]), r["rowid"]),
                        )
                    counts[table] = len(rows)
                else:
                    counts[table] = c.execute(
                        f"DELETE FROM {table} WHERE lower(owner) = ?", (owner,)
                    ).rowcount
        return counts, tokens

    # ---- pending links ----

    def add_pending_link(
        self, nonce: str, owner: str, alias: str, exp: int, code_verifier: str
    ) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM pending_links WHERE exp < strftime('%s','now') - 86400")
            c.execute(
                "INSERT INTO pending_links (nonce, owner, alias, exp, used, code_verifier) "
                "VALUES (?, ?, ?, ?, 0, ?)",
                (nonce, owner.lower(), alias, exp, code_verifier),
            )

    def consume_pending_link(self, nonce: str, owner: str, alias: str) -> str | None:
        """Atomically mark nonce used. Returns code_verifier, or None if the nonce
        is unknown, already used, or doesn't match owner/alias."""
        with self._tx() as c:
            row = c.execute(
                "SELECT owner, alias, used, code_verifier FROM pending_links WHERE nonce = ?",
                (nonce,),
            ).fetchone()
            if not row or row["used"] or row["owner"] != owner.lower() or row["alias"] != alias:
                return None
            cur = c.execute(
                "UPDATE pending_links SET used = 1 WHERE nonce = ? AND used = 0", (nonce,)
            )
            if cur.rowcount != 1:
                return None
            return row["code_verifier"]

    # ---- audit ----

    def audit(self, owner: str, tool: str, alias: str | None, detail: str, ok: bool) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT INTO audit_log (ts, owner, tool, alias, detail, ok) VALUES (?, ?, ?, ?, ?, ?)",
                # Belt and braces: audit details never carry email addresses.
                (now_iso(), owner, tool, alias, scrub_emails(detail)[:300], 1 if ok else 0),
            )

    def audit_rows(self, owner: str) -> list[dict]:
        with self._tx() as c:
            rows = c.execute(
                "SELECT * FROM audit_log WHERE owner = ? ORDER BY rowid", (owner,)
            ).fetchall()
        return [dict(r) for r in rows]
