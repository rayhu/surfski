"""delete_my_data / export_my_data (#3)."""

import time
from dataclasses import replace

import httpx
import pytest
from fastmcp.exceptions import ToolError

from surfski.server import create_app
from surfski.storage import Storage

from .test_server import ALICE, BOB, call, who  # noqa: F401  (fixture re-export)


class Revoker:
    def __init__(self, failing=()):
        self.calls: list[str] = []
        self.failing = set(failing)

    def handler(self, req: httpx.Request):
        if req.url.path == "/revoke":
            token = req.content.decode().split("token=")[1]
            self.calls.append(token)
            return httpx.Response(400 if token in self.failing else 200)
        return httpx.Response(404)

    def factory(self):
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def populate(storage: Storage):
    now = int(time.time())
    for owner, prefix in ((ALICE, "a"), (BOB, "b")):
        storage.upsert_account(owner, "work", f"{prefix}@work.com", f"rt-{prefix}1", "s")
        storage.upsert_account(owner, "personal", f"{prefix}@gmail.com", f"rt-{prefix}2", "s")
        storage.set_address_label(owner, "work", f"sales@{prefix}.org", "sales")
        storage.set_default_from(owner, "work", f"sales@{prefix}.org")
        storage.set_send_policy(owner, "work", "confirm")
        storage.add_pending_link(f"nonce-{prefix}", owner, "new", now + 600, "verifier")
        storage.add_action_token(f"act-{prefix}", owner, "work", "send-confirm", now + 600, "{}")
        storage.create_owner_session(owner, 3600, now)
        storage.reserve_send(owner, "work", 20, now)
        storage.audit(owner, "list_accounts", None, "", True)
    # Alice's third mailbox shares a token with "work" (same Google grant).
    storage.upsert_account(ALICE, "shared", "a@work.com", "rt-a1", "s")


def owner_rows(storage: Storage, owner: str) -> dict[str, int]:
    return {
        t: storage._conn.execute(f"SELECT COUNT(*) FROM {t} WHERE lower(owner) = ?", (owner,)).fetchone()[0]
        for t in Storage.OWNER_TABLES
    }


@pytest.fixture
def revoker():
    return Revoker(failing={"rt-a2"})


@pytest.fixture
def app(config, storage, revoker):
    populate(storage)
    return create_app(config, storage=storage, with_auth=False, http_factory=revoker.factory)


def test_owner_tables_cover_the_schema(storage):
    """Every table with an owner column is in OWNER_TABLES (so delete_my_data purges it)."""
    tables = [r[0] for r in storage._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    owned = {t for t in tables if any(c[1] == "owner" for c in storage._conn.execute(f"PRAGMA table_info({t})"))}
    assert owned == set(Storage.OWNER_TABLES)


async def test_confirm_guard(app, who, storage, revoker):
    before = owner_rows(storage, ALICE)
    for bad in ("delete", "yes", "", "DELETE "):
        with pytest.raises(ToolError, match='pass confirm="DELETE"'):
            await call(app, "delete_my_data", confirm=bad)
    assert owner_rows(storage, ALICE)["accounts"] == before["accounts"] == 3
    assert revoker.calls == []


async def test_delete_purges_only_the_caller(app, who, storage, revoker):
    bob_before = owner_rows(storage, BOB)
    tc, sc = app.surfski["token_cache"], app.surfski["send_as_cache"]
    for owner in (ALICE, BOB):
        tc.put(owner, "work", "at", time.time() + 3600)
        sc.put(owner, "work", [{"address": "x"}])

    r = await call(app, "delete_my_data", confirm="DELETE")
    assert r["ok"] is True and r["audit_log"] == "deleted"
    assert r["deleted"]["accounts"] == 3 and r["deleted"]["address_labels"] == 1
    assert r["deleted"]["pending_links"] == 1 and r["deleted"]["action_tokens"] == 1
    assert r["deleted"]["owner_sessions"] == 1 and r["deleted"]["sends"] == 1
    assert r["deleted"]["audit_log"] >= 1
    # Revocation: once per distinct token; a failure is reported, not fatal.
    assert sorted(revoker.calls) == ["rt-a1", "rt-a2"]
    assert r["revoked_at_google"] == {"personal": False, "shared": True, "work": True}
    assert "myaccount.google.com/permissions" in r["note"]

    assert owner_rows(storage, ALICE) == {t: 0 for t in Storage.OWNER_TABLES}
    assert owner_rows(storage, BOB) == bob_before
    assert storage.get_account(BOB, "work").send_policy == "confirm"
    assert storage.get_refresh_token(BOB, "work") == "rt-b1"
    # Caches: Alice's entries gone, Bob's kept.
    assert tc.get(ALICE, "work") is None and tc.get(BOB, "work") == "at"
    assert sc.get(ALICE, "work") is None and sc.get(BOB, "work")
    # Alice can start over.
    assert await call(app, "list_accounts") == []


async def test_undecryptable_token_reported(app, who, storage, revoker):
    storage._conn.execute("UPDATE accounts SET refresh_token_enc = ? WHERE owner = ? AND alias = 'personal'",
                          (b"garbage", ALICE))
    storage._conn.commit()
    r = await call(app, "delete_my_data", confirm="DELETE")
    assert r["revoked_at_google"]["personal"] == "not revoked: token could not be decrypted"
    assert owner_rows(storage, ALICE)["accounts"] == 0


async def test_pseudonymized_audit(config, storage, revoker, who):
    populate(storage)
    app = create_app(replace(config, audit_on_delete="pseudonymize"), storage=storage,
                     with_auth=False, http_factory=revoker.factory)
    await call(app, "list_accounts")
    n_audit = owner_rows(storage, ALICE)["audit_log"]
    r = await call(app, "delete_my_data", confirm="DELETE")
    assert r["audit_log"] == "pseudonymized" and r["deleted"]["audit_log"] == n_audit
    assert owner_rows(storage, ALICE) == {t: 0 for t in Storage.OWNER_TABLES}
    rows = storage._conn.execute("SELECT owner, tool, detail FROM audit_log WHERE owner LIKE 'deleted-%'").fetchall()
    assert len({r[0] for r in rows}) == 1 and len(rows) == n_audit + 1
    assert rows[-1][1] == "delete_my_data" and ALICE not in rows[-1][2]
    assert owner_rows(storage, BOB)["audit_log"] == 1


async def test_export_my_data(app, who):
    r = await call(app, "export_my_data")
    assert r["owner"] == ALICE
    work = next(a for a in r["accounts"] if a["alias"] == "work")
    assert work["email"] == "a@work.com" and work["send_policy"] == "confirm"
    assert work["default_from"] == "sales@a.org" and work["address_labels"] == {"sales": "sales@a.org"}
    assert {a["alias"] for a in r["accounts"]} == {"work", "personal", "shared"}
    assert "rt-a1" not in str(r) and "refresh" not in str(r)


def test_sessions_of_removed_owners_pruned_at_startup(config, storage):
    now = int(time.time())
    storage.create_owner_session(ALICE, 3600, now)
    storage.create_owner_session("mallory@example.com", 3600, now)
    storage.create_owner_session(BOB, 3600, now - 7200)  # expired
    create_app(config, storage=storage, with_auth=False)
    owners = [r[0] for r in storage._conn.execute("SELECT owner FROM owner_sessions")]
    assert owners == [ALICE]


def test_audit_on_delete_config(tmp_path):
    from surfski.config import ConfigError, load_config
    from tests.conftest import make_env
    assert load_config(make_env(tmp_path)).audit_on_delete == "delete"
    assert load_config(make_env(tmp_path, AUDIT_ON_DELETE="Pseudonymize")).audit_on_delete == "pseudonymize"
    with pytest.raises(ConfigError):
        load_config(make_env(tmp_path, AUDIT_ON_DELETE="keep"))


async def test_pseudonymized_audit_has_no_email_anywhere(config, storage, revoker, who):
    populate(storage)
    # Legacy rows written before details were scrubbed, with addresses in detail and alias.
    storage._conn.executemany(
        "INSERT INTO audit_log (ts, owner, tool, alias, detail, ok) VALUES ('t', ?, 'gmail_callback', ?, ?, 1)",
        [(ALICE, "a@work.com", "linked a@work.com"), (ALICE, "work", "to <Carol.X+tag@sub.example.co.uk>, x")],
    )
    storage._conn.commit()
    app = create_app(replace(config, audit_on_delete="pseudonymize"), storage=storage,
                     with_auth=False, http_factory=revoker.factory)
    await call(app, "delete_my_data", confirm="DELETE")
    rows = storage._conn.execute(
        "SELECT owner, alias, detail FROM audit_log WHERE owner LIKE 'deleted-%'").fetchall()
    assert rows
    for owner, alias, detail in rows:
        assert alias is None
        assert "@" not in owner and "@" not in (detail or ""), detail
    assert any("<email>" in (d or "") for _, _, d in rows)


def test_audit_details_never_store_emails(storage):
    storage.audit(ALICE, "x", "work", "linked bob@x.com and 'carol@y.org'", True)
    assert storage.audit_rows(ALICE)[-1]["detail"] == "linked <email> and '<email>'"


async def test_no_audit_row_for_account_purged_mid_call(config, storage, who):
    storage.upsert_account(ALICE, "work", "a@work.com", "rt", "s")

    def factory(owner, alias):
        storage.purge_owner(owner)  # delete_my_data lands while the Gmail call runs
        from .fakes import StrictGmail
        return StrictGmail({"users.labels.list": lambda **kw: {"labels": []}})

    app = create_app(config, storage=storage, with_auth=False, service_factory=factory)
    assert await call(app, "list_labels", alias="work") == []
    assert storage.audit_rows(ALICE) == []
