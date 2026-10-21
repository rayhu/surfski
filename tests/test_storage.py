import os
import sqlite3
import stat

import pytest
from cryptography.fernet import Fernet

from surfski.storage import AccountNotFound, Storage, StorageError, TokenCipher

A, B = "alice@example.com", "bob@example.com"


def test_owner_isolation(storage):
    storage.upsert_account(A, "work", "alice@work.com", "rt-a", "s")
    storage.upsert_account(B, "work", "bob@work.com", "rt-b", "s")
    storage.upsert_account(B, "personal", "bob@gmail.com", "rt-b2", "s")

    assert [a.alias for a in storage.list_accounts(A)] == ["work"]
    assert {a.alias for a in storage.list_accounts(B)} == {"work", "personal"}
    assert storage.get_account(A, "work").email == "alice@work.com"
    assert storage.get_refresh_token(A, "work") == "rt-a"
    assert storage.get_refresh_token(B, "work") == "rt-b"

    # A cannot reach B's aliases in any way
    with pytest.raises(AccountNotFound):
        storage.get_account(A, "personal")
    with pytest.raises(AccountNotFound):
        storage.get_refresh_token(A, "personal")
    assert storage.delete_account(A, "personal") is False
    assert storage.get_refresh_token(B, "personal") == "rt-b2"


def test_owner_case_insensitive(storage):
    storage.upsert_account("Alice@Example.com", "work", "x@y.com", "rt", "s")
    assert storage.get_account("alice@example.com", "work").alias == "work"


def test_alias_validation(storage):
    for bad in ["", "Has Space", "a" * 33, "x;drop", "../etc"]:
        with pytest.raises(ValueError):
            storage.upsert_account(A, bad, "x@y.com", "rt", "s")
    storage.upsert_account(A, "Work_1-a", "x@y.com", "rt", "s")  # lowercased
    assert storage.get_account(A, "work_1-a")


def test_refresh_token_encrypted_at_rest(tmp_path, storage):
    storage.upsert_account(A, "work", "x@y.com", "super-secret-rt", "s")
    raw = sqlite3.connect(tmp_path / "data.db").execute(
        "SELECT refresh_token_enc FROM accounts"
    ).fetchone()[0]
    assert b"super-secret-rt" not in raw
    assert stat.S_IMODE(os.stat(tmp_path / "data.db").st_mode) == 0o600


def test_per_owner_keys(tmp_path):
    ka, kd = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    s = Storage(tmp_path / "x.db", TokenCipher(kd, {B: ka}))
    s.upsert_account(B, "work", "b@w.com", "rt-b", "s")
    s.upsert_account(A, "work", "a@w.com", "rt-a", "s")
    assert s.get_refresh_token(B, "work") == "rt-b"
    # B's token isn't decryptable with the default key
    s2 = Storage(tmp_path / "x.db", TokenCipher(kd))
    with pytest.raises(StorageError):
        s2.get_refresh_token(B, "work")
    assert s2.get_refresh_token(A, "work") == "rt-a"


def test_upsert_overwrites(storage):
    storage.upsert_account(A, "work", "old@w.com", "rt1", "s")
    storage.touch_account(A, "work")
    storage.upsert_account(A, "work", "new@w.com", "rt2", "s")
    acct = storage.get_account(A, "work")
    assert acct.email == "new@w.com" and acct.last_used_at is None
    assert storage.get_refresh_token(A, "work") == "rt2"


def test_rename_account(storage):
    storage.upsert_account(A, "aj", "a@w.com", "rt-a", "s")
    storage.upsert_account(A, "home", "a@h.com", "rt-h", "s")
    storage.upsert_account(B, "aj", "b@w.com", "rt-b", "s")

    storage.rename_account(A, "aj", "Work")
    assert storage.get_refresh_token(A, "work") == "rt-a"  # token kept, alias lowercased
    with pytest.raises(AccountNotFound):
        storage.get_account(A, "aj")
    assert storage.get_account(B, "aj").email == "b@w.com"  # other owner untouched

    with pytest.raises(StorageError, match="already in use"):
        storage.rename_account(A, "work", "home")
    with pytest.raises(AccountNotFound):
        storage.rename_account(A, "nope", "x")
    with pytest.raises(ValueError):
        storage.rename_account(A, "work", "bad alias!")


OLD_SCHEMA = """
CREATE TABLE accounts (
  owner TEXT NOT NULL, alias TEXT NOT NULL, email TEXT NOT NULL,
  refresh_token_enc BLOB NOT NULL, scopes TEXT NOT NULL, created_at TEXT NOT NULL,
  last_used_at TEXT, PRIMARY KEY (owner, alias)
);
CREATE TABLE audit_log (ts TEXT, owner TEXT, tool TEXT, alias TEXT, detail TEXT, ok INTEGER);
"""


def test_migration_on_existing_db(tmp_path):
    key = Fernet.generate_key().decode()
    cipher = TokenCipher(key)
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript(OLD_SCHEMA)
    conn.execute(
        "INSERT INTO accounts VALUES (?, ?, ?, ?, ?, ?, NULL)",
        (A, "work", "alice@work.com", cipher.encrypt(A, "rt-old"), "s", "2026-01-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()

    for _ in range(2):  # idempotent
        s = Storage(db, cipher)
        acct = s.get_account(A, "work")
        assert acct.email == "alice@work.com" and s.get_refresh_token(A, "work") == "rt-old"
        s.close()

    s = Storage(db, cipher)
    assert s.get_account(A, "work").default_from is None
    s.set_default_from(A, "work", "Sales@Work.org")
    s.set_address_label(A, "work", "sales@work.org", "sales")
    assert s.get_account(A, "work").default_from == "sales@work.org"
    assert s.get_address_labels(A, "work") == {"sales": "sales@work.org"}
    with pytest.raises(AccountNotFound):
        s.set_address_label(B, "work", "x@y.z", "x")
    assert s.get_address_labels(B, "work") == {}
    s.close()


def test_add_column_tolerates_concurrent_migration(storage):
    # Simulates two processes racing past the PRAGMA check: the second ALTER must not fail.
    storage._add_column("accounts", "default_from", "TEXT")
    storage._add_column("accounts", "default_from", "TEXT")
    with pytest.raises(sqlite3.OperationalError):
        storage._add_column("no_such_table", "x", "TEXT")
