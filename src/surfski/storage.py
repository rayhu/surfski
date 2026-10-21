"""SQLite persistence. Every `accounts` query is scoped by owner; there is no
cross-owner read path."""

from __future__ import annotations

import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ALIAS_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
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
MIGRATIONS = [("accounts", "default_from", "TEXT")]

ACCOUNT_COLS = "owner, alias, email, scopes, created_at, last_used_at, default_from"


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

    def public(self) -> dict:
        return {
            "alias": self.alias,
            "email": self.email,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "default_from": self.default_from,
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
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            self._conn.commit()

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
                # A different mailbox under the same alias: its labels/default don't apply.
                c.execute("DELETE FROM address_labels WHERE owner = ? AND alias = ?", (owner, alias))
                c.execute(
                    "UPDATE accounts SET default_from = NULL WHERE owner = ? AND alias = ?",
                    (owner, alias),
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

    def touch_account(self, owner: str, alias: str) -> None:
        with self._tx() as c:
            c.execute(
                "UPDATE accounts SET last_used_at = ? WHERE owner = ? AND alias = ?",
                (now_iso(), owner.lower(), alias),
            )

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
                (now_iso(), owner, tool, alias, detail[:300], 1 if ok else 0),
            )

    def audit_rows(self, owner: str) -> list[dict]:
        with self._tx() as c:
            rows = c.execute(
                "SELECT * FROM audit_log WHERE owner = ? ORDER BY rowid", (owner,)
            ).fetchall()
        return [dict(r) for r in rows]
