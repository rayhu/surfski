"""Admin CLI and encryption key rotation (#7)."""

import json
import sqlite3
from dataclasses import replace

import anyio
import pytest
from cryptography.fernet import Fernet
from fastmcp.exceptions import ToolError

import surfski.server as srv
from surfski import cli
from surfski.config import load_config
from surfski.server import create_app, storage_fernet
from surfski.storage import KeyRotationError, Storage, StorageError, TokenCipher

from .conftest import KEY_B, make_env
from .test_delete_my_data import Revoker
from .test_server import ALICE, BOB, FakeGmail, call, who  # noqa: F401  (fixture re-export)

NEW = Fernet.generate_key().decode()
OTHER = Fernet.generate_key().decode()


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Put a valid configuration in the process env (the CLI reads os.environ)."""
    def set_env(**over):
        for k, v in make_env(tmp_path, **over).items():
            monkeypatch.setenv(k, v)
        for k in ("TOKEN_ENCRYPTION_KEY_OLD", "TOKEN_ENCRYPTION_KEYS", "TOKEN_ENCRYPTION_KEYS_OLD"):
            if k not in over:
                monkeypatch.delenv(k, raising=False)
    set_env()
    return set_env


def seed(tmp_path, key=KEY_B, per_owner=None):
    s = Storage(tmp_path / "data.db", TokenCipher(key, per_owner))
    s.upsert_account(ALICE, "work", "alice@work.com", "rt-alice-work", "s")
    s.upsert_account(ALICE, "personal", "alice@gmail.com", "rt-alice-personal", "s")
    s.upsert_account(BOB, "work", "bob@work.com", "rt-bob-work", "s")
    s.set_send_policy(ALICE, "work", "confirm")
    return s


def ciphertexts(tmp_path) -> dict[tuple[str, str], bytes]:
    c = sqlite3.connect(tmp_path / "data.db")
    rows = c.execute("SELECT owner, alias, refresh_token_enc FROM accounts").fetchall()
    c.close()
    return {(o, a): ct for o, a, ct in rows}


async def run_cli(argv, **kw):
    """The CLI runs its own event loop, as it does in a separate process."""
    return await anyio.to_thread.run_sync(lambda: cli.main(argv, **kw))


def open_with(tmp_path, key, per_owner=None, **old):
    return Storage(tmp_path / "data.db", TokenCipher(key, per_owner, **old))


# ---------------------------------------------------------------- parsing


def test_default_is_serve(monkeypatch):
    calls = []
    monkeypatch.setattr(srv, "main", lambda: calls.append("serve"))
    assert cli.main([]) == 0
    assert cli.main(["serve"]) == 0
    assert calls == ["serve", "serve"]


@pytest.mark.parametrize("argv", [["admin"], ["admin", "nope"], ["admin", "unlink", "--owner", "x"],
                                  ["bogus"]])
def test_usage_errors_exit_2(argv):
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    assert e.value.code == 2


def test_config_error_exit_2(monkeypatch, capsys):
    monkeypatch.delenv("TOKEN_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("BASE_URL", raising=False)
    assert cli.main(["admin", "list"]) == 2
    assert "configuration" in capsys.readouterr().err


def test_parse_since():
    from datetime import UTC, datetime
    now = datetime(2026, 10, 21, tzinfo=UTC)
    assert cli.parse_since("7d", now) == "2026-10-14T00:00:00+00:00"
    assert cli.parse_since("2026-10-01", now) == "2026-10-01T00:00:00+00:00"
    with pytest.raises(ValueError):
        cli.parse_since("yesterday", now)


# ---------------------------------------------------------------- list / audit


def test_admin_list_no_secrets(tmp_path, env, capsys):
    s = seed(tmp_path)
    cts = ciphertexts(tmp_path)
    s.close()
    assert cli.main(["admin", "list"]) == 0
    out = capsys.readouterr().out
    assert "alice@example.com" in out and "bob@example.com" in out
    assert "alice@work.com" in out and "send_policy=confirm" in out and "triage=off" in out
    assert "2 owner(s), 3 mailbox(es)" in out
    assert "rt-" not in out and KEY_B not in out
    assert not any(ct.decode() in out for ct in cts.values())

    assert cli.main(["admin", "list", "--json"]) == 0
    raw = capsys.readouterr().out
    rows = json.loads(raw)
    assert {(r["owner"], r["alias"]) for r in rows} == {(ALICE, "work"), (ALICE, "personal"), (BOB, "work")}
    assert set(rows[0]) == {"owner", "alias", "email", "created_at", "last_used_at", "send_policy", "triage"}
    assert "rt-" not in raw


def test_admin_audit_counts_only(tmp_path, env, capsys):
    s = seed(tmp_path)
    s.audit(ALICE, "search_threads", "work", "max=10 secret detail", True)
    s.audit(ALICE, "search_threads", "work", "x", False)
    s.audit(BOB, "get_thread", "work", "x", True)
    s.close()
    assert cli.main(["admin", "audit", "--owner", ALICE, "--since", "1d"]) == 0
    out = capsys.readouterr().out
    assert "search_threads" in out and "ok=1 failed=1" in out
    assert "get_thread" not in out and "secret" not in out
    assert cli.main(["admin", "audit", "--owner", ALICE, "--since", "soon"]) == 2


# ---------------------------------------------------------------- unlink / purge


def test_admin_unlink(tmp_path, env, capsys):
    seed(tmp_path).close()
    rv = Revoker()
    assert cli.main(["admin", "unlink", "--owner", ALICE, "--alias", "work"], http_factory=rv.factory) == 0
    assert rv.calls == []  # no --revoke: no network
    s = open_with(tmp_path, KEY_B)
    assert [a.alias for a in s.list_accounts(ALICE)] == ["personal"]
    assert [a.alias for a in s.list_accounts(BOB)] == ["work"]
    assert s.audit_rows(ALICE)[-1]["tool"] == "admin_unlink"
    s.close()

    assert cli.main(["admin", "unlink", "--owner", ALICE, "--alias", "personal", "--revoke"],
                    http_factory=rv.factory) == 0
    assert rv.calls == ["rt-alice-personal"]
    assert "revoked at Google" in capsys.readouterr().out

    assert cli.main(["admin", "unlink", "--owner", ALICE, "--alias", "work"]) == 1
    assert "no linked mailbox" in capsys.readouterr().err


def test_admin_unlink_revoke_failure_exit_1(tmp_path, env):
    seed(tmp_path).close()
    rv = Revoker(failing={"rt-bob-work"})
    assert cli.main(["admin", "unlink", "--owner", BOB, "--alias", "work", "--revoke"],
                    http_factory=rv.factory) == 1
    s = open_with(tmp_path, KEY_B)
    assert s.list_accounts(BOB) == []  # unlinked locally regardless
    s.close()


def test_admin_purge_requires_yes(tmp_path, env, capsys):
    seed(tmp_path).close()
    assert cli.main(["admin", "purge-owner", "--owner", ALICE]) == 1
    assert "--yes" in capsys.readouterr().err
    s = open_with(tmp_path, KEY_B)
    assert len(s.list_accounts(ALICE)) == 2
    s.close()


def test_admin_purge_reuses_delete_my_data(tmp_path, env, capsys):
    seed(tmp_path).close()
    rv = Revoker()
    assert cli.main(["admin", "purge-owner", "--owner", ALICE, "--yes"], http_factory=rv.factory) == 0
    assert sorted(rv.calls) == ["rt-alice-personal", "rt-alice-work"]
    out = capsys.readouterr().out
    assert "accounts=2" in out and "rt-" not in out
    s = open_with(tmp_path, KEY_B)
    for t in Storage.OWNER_TABLES:
        n = s._conn.execute(f"SELECT COUNT(*) FROM {t} WHERE lower(owner) = ?", (ALICE,)).fetchone()[0]
        assert n == 0, t
    assert len(s.list_accounts(BOB)) == 1
    s.close()


def test_admin_purge_failed_revocation_exit_1(tmp_path, env):
    seed(tmp_path).close()
    rv = Revoker(failing={"rt-alice-work"})
    assert cli.main(["admin", "purge-owner", "--owner", ALICE, "--yes"], http_factory=rv.factory) == 1
    s = open_with(tmp_path, KEY_B)
    assert s.list_accounts(ALICE) == []  # purged regardless
    s.close()


def test_admin_purge_pseudonymizes_like_the_tool(tmp_path, env):
    env(AUDIT_ON_DELETE="pseudonymize")
    s = seed(tmp_path)
    s.audit(ALICE, "list_accounts", None, "", True)
    s.close()
    assert cli.main(["admin", "purge-owner", "--owner", ALICE, "--yes"],
                    http_factory=Revoker().factory) == 0
    config = load_config(make_env(tmp_path, AUDIT_ON_DELETE="pseudonymize"))
    s = open_with(tmp_path, KEY_B)
    owners = {r[0] for r in s._conn.execute("SELECT owner FROM audit_log")}
    assert srv.audit_pseudonym(config, ALICE) in owners and ALICE not in owners
    s.close()


async def test_running_server_sees_cli_unlink_and_purge(tmp_path, env, config, who):
    """The server's caches can't keep a mailbox alive after the CLI removed it."""
    seed(tmp_path).close()
    s = open_with(tmp_path, KEY_B)
    app = create_app(config, storage=s, with_auth=False,
                     service_factory=lambda o, a: FakeGmail(s.get_account(o, a).email))
    assert (await call(app, "search_threads", alias="work", query="x"))["threads"]
    assert await run_cli(["admin", "unlink", "--owner", ALICE, "--alias", "work"]) == 0
    with pytest.raises(ToolError, match="no linked account 'work'"):
        await call(app, "search_threads", alias="work", query="x")
    assert await run_cli(["admin", "purge-owner", "--owner", ALICE, "--yes"],
                         http_factory=Revoker().factory) == 0
    assert await call(app, "list_accounts") == []
    s.close()


# ---------------------------------------------------------------- key rotation


def test_cipher_decrypts_with_old_and_encrypts_with_new():
    old_ct = Fernet(KEY_B).encrypt(b"rt")
    c = TokenCipher(NEW, old_default=KEY_B)
    assert c.decrypt(ALICE, old_ct) == "rt"
    assert not c.is_current(ALICE, old_ct)
    new_ct = c.encrypt(ALICE, "rt2")
    assert Fernet(NEW).decrypt(new_ct) == b"rt2"
    with pytest.raises(StorageError):
        TokenCipher(NEW).decrypt(ALICE, old_ct)


def test_rotate_old_rows_readable_with_new_key_only(tmp_path, env, capsys):
    seed(tmp_path).close()  # everything under KEY_B
    env(TOKEN_ENCRYPTION_KEY=NEW, TOKEN_ENCRYPTION_KEY_OLD=KEY_B)
    assert cli.main(["admin", "rotate-token-key", "--dry-run"]) == 0
    assert "would re-encrypt 3 of 3" in capsys.readouterr().out
    assert open_with(tmp_path, NEW, old_default=KEY_B).admin_rotate_token_key(dry_run=True)["rotated"] == 3
    assert cli.main(["admin", "rotate-token-key"]) == 0
    out = capsys.readouterr().out
    assert "re-encrypted 3 of 3 token(s); 0 already on the current key" in out
    s = open_with(tmp_path, NEW)  # OLD removed
    assert s.get_refresh_token(ALICE, "work") == "rt-alice-work"
    assert s.get_refresh_token(BOB, "work") == "rt-bob-work"
    s.close()
    with pytest.raises(StorageError):
        open_with(tmp_path, KEY_B).get_refresh_token(ALICE, "work")
    # Idempotent.
    assert cli.main(["admin", "rotate-token-key"]) == 0
    assert "re-encrypted 0 of 3 token(s); 3 already" in capsys.readouterr().out


def test_rotate_mixed_rows(tmp_path):
    seed(tmp_path).close()
    s = open_with(tmp_path, NEW, old_default=KEY_B)
    s.upsert_account(ALICE, "work", "alice@work.com", "rt-new", "s")  # written under NEW
    assert s.admin_rotate_token_key() == {"total": 3, "rotated": 2, "already_current": 1}
    s.close()
    s = open_with(tmp_path, NEW)
    assert [s.get_refresh_token(o, a) for o, a in ((ALICE, "work"), (ALICE, "personal"), (BOB, "work"))] \
        == ["rt-new", "rt-alice-personal", "rt-bob-work"]
    s.close()


def test_rotate_refuses_undecryptable_with_no_partial_change(tmp_path, env, capsys):
    seed(tmp_path).close()
    stray = open_with(tmp_path, OTHER)
    stray.upsert_account(BOB, "stray", "bob@stray.com", "rt-stray", "s")  # a key nobody has
    stray.close()
    before = ciphertexts(tmp_path)
    env(TOKEN_ENCRYPTION_KEY=NEW, TOKEN_ENCRYPTION_KEY_OLD=KEY_B)
    assert cli.main(["admin", "rotate-token-key"]) == 1
    err = capsys.readouterr().err
    assert f"{BOB} / stray" in err and "alice" not in err
    assert not any(ct.decode() in err for ct in before.values()) and "rt-" not in err
    assert ciphertexts(tmp_path) == before
    with pytest.raises(KeyRotationError) as e:
        open_with(tmp_path, NEW, old_default=KEY_B).admin_rotate_token_key()
    assert e.value.affected == [(BOB, "stray")]


def test_rotate_per_owner_keys(tmp_path):
    alice_old, alice_new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    seed(tmp_path, per_owner={ALICE: alice_old}).close()
    # Rotate Alice's own key; the default key stays.
    s = open_with(tmp_path, KEY_B, {ALICE: alice_new}, old_per_owner={ALICE: alice_old})
    assert s.admin_rotate_token_key() == {"total": 3, "rotated": 2, "already_current": 1}
    s.close()
    s = open_with(tmp_path, KEY_B, {ALICE: alice_new})
    assert s.get_refresh_token(ALICE, "personal") == "rt-alice-personal"
    assert s.get_refresh_token(BOB, "work") == "rt-bob-work"
    s.close()
    # Bob's rows can't be read with Alice's key, and vice versa.
    with pytest.raises(StorageError):
        open_with(tmp_path, alice_new).get_refresh_token(BOB, "work")
    with pytest.raises(StorageError):
        open_with(tmp_path, KEY_B).get_refresh_token(ALICE, "work")


def test_rotate_moves_owner_onto_per_owner_key(tmp_path):
    seed(tmp_path).close()  # all under the default KEY_B
    bob_key = Fernet.generate_key().decode()
    # A per-owner key never silently falls back to the default key...
    with pytest.raises(StorageError):
        open_with(tmp_path, KEY_B, {BOB: bob_key}).get_refresh_token(BOB, "work")
    # ...the move is an explicit rotation with the default key as Bob's old key.
    s = open_with(tmp_path, KEY_B, {BOB: bob_key}, old_per_owner={BOB: KEY_B})
    assert s.get_refresh_token(BOB, "work") == "rt-bob-work"
    assert s.admin_rotate_token_key() == {"total": 3, "rotated": 1, "already_current": 2}
    s.close()
    assert Fernet(bob_key).decrypt(ciphertexts(tmp_path)[(BOB, "work")]) == b"rt-bob-work"


async def test_running_server_tolerates_both_keys(tmp_path, env, who):
    """Server restarted with NEW+OLD keeps working before, during and after the CLI rotation;
    afterwards a NEW-only server can read every token. Built from config like production."""
    seed(tmp_path).close()
    config = load_config(make_env(tmp_path, TOKEN_ENCRYPTION_KEY=NEW, TOKEN_ENCRYPTION_KEY_OLD=KEY_B))
    seen = []

    def factory(owner, alias):
        st = app.surfski["storage"]
        seen.append(st.get_refresh_token(owner, alias))  # the real token-reading path
        return FakeGmail(st.get_account(owner, alias).email)

    app = create_app(config, with_auth=False, service_factory=factory)
    await call(app, "search_threads", alias="work", query="x")  # pre-rotation row (OLD)
    app.surfski["storage"].upsert_account(ALICE, "new", "alice@new.com", "rt-fresh", "s")  # NEW
    env(TOKEN_ENCRYPTION_KEY=NEW, TOKEN_ENCRYPTION_KEY_OLD=KEY_B)
    assert await run_cli(["admin", "rotate-token-key"]) == 0
    await call(app, "search_threads", alias="work", query="x")
    await call(app, "search_threads", alias="new", query="x")
    assert seen == ["rt-alice-work", "rt-alice-work", "rt-fresh"]
    app.surfski["storage"].close()

    seen.clear()
    app = create_app(replace(config, token_encryption_key_old=None), with_auth=False,
                     service_factory=factory)
    await call(app, "search_threads", alias="personal", query="x")
    assert seen == ["rt-alice-personal"]
    app.surfski["storage"].close()


def test_config_old_keys(tmp_path):
    from surfski.config import ConfigError
    c = load_config(make_env(tmp_path, TOKEN_ENCRYPTION_KEY_OLD=KEY_B, STORAGE_ENCRYPTION_KEY_OLD=NEW,
                             TOKEN_ENCRYPTION_KEYS_OLD=f"{ALICE}={OTHER}"))
    assert c.token_encryption_key_old == KEY_B and c.storage_encryption_key_old == NEW
    assert c.token_encryption_keys_old == {ALICE: OTHER}
    with pytest.raises(ConfigError, match="TOKEN_ENCRYPTION_KEY_OLD"):
        load_config(make_env(tmp_path, TOKEN_ENCRYPTION_KEY_OLD="nope"))


async def test_storage_key_old_still_reads(tmp_path):
    """OAuth client store: entries written under the old STORAGE_ENCRYPTION_KEY stay readable
    while STORAGE_ENCRYPTION_KEY_OLD is set; new writes use the new key."""
    old_cfg = load_config(make_env(tmp_path))
    store = srv.build_client_storage(old_cfg)
    await store.put("client-1", {"client_id": "abc"}, collection="clients")

    rotated = replace(old_cfg, storage_encryption_key=NEW,
                      storage_encryption_key_old=old_cfg.storage_encryption_key)
    store = srv.build_client_storage(rotated)
    assert await store.get("client-1", collection="clients") == {"client_id": "abc"}
    await store.put("client-2", {"client_id": "def"}, collection="clients")

    new_only = srv.build_client_storage(replace(rotated, storage_encryption_key_old=None))
    assert await new_only.get("client-2", collection="clients") == {"client_id": "def"}
    # Without the old key the old entry reads as missing (the client must reconnect).
    assert await new_only.get("client-1", collection="clients") is None
    assert isinstance(storage_fernet(old_cfg), Fernet)
