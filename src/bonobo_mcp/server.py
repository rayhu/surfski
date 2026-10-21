"""FastMCP app: auth (layer A), tools, custom routes, main()."""

from __future__ import annotations

import html
import logging
import threading
import time
from collections.abc import Callable
from typing import Annotated, Any

import anyio
import httpx
from cryptography.fernet import Fernet
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token
from pydantic import Field
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse

from . import gmail as g
from .audit import install_log_redaction, write_audit
from .config import Config, ConfigError, load_config
from .linking import (
    GMAIL_SCOPES,
    LinkError,
    consume_state,
    exchange_code,
    fetch_profile_email,
    revoke_token,
    start_link,
)
from .storage import AccountNotFound, Storage, StorageError, TokenCipher, validate_alias

log = logging.getLogger("bonobo_mcp")

INSTRUCTIONS = (
    "Search, read and draft email across the caller's linked Gmail accounts. "
    "Each account has an alias (e.g. 'work', 'personal'). If the user hasn't named an "
    "account, call list_accounts first. Sending is NOT supported: create_draft saves a "
    "draft the user sends from Gmail. To add a mailbox, call link_account and give the "
    "user the returned URL to open."
)


# ---------------------------------------------------------------- helpers


class RateLimiter:
    """Per-owner in-memory token bucket."""

    def __init__(self, per_minute: int):
        self.capacity = float(per_minute)
        self.rate = per_minute / 60.0
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1, now)
            return True


def _is_true(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.lower() == "true")


def caller_email(claims: dict) -> tuple[str | None, Any]:
    email = claims.get("email")
    verified = claims.get("email_verified")
    upstream = claims.get("upstream_claims")
    if not email and isinstance(upstream, dict):
        email = upstream.get("email")
        verified = upstream.get("email_verified", verified)
    return (email.strip().lower() if isinstance(email, str) else None), verified


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    doc = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;"
        "padding:0 1rem;line-height:1.5}</style></head>"
        f"<body><h1>{html.escape(title)}</h1><p>{html.escape(body)}</p></body></html>"
    )
    return HTMLResponse(doc, status_code=status, headers={"Cache-Control": "no-store"})


def build_client_storage(config: Config):
    """Encrypted single-node OAuth client storage (FileTree + Fernet), mirroring
    FastMCP's internal default but rooted at DATA_DIR/oauth."""
    from key_value.aio.stores.filetree import (
        FileTreeStore,
        FileTreeV1CollectionSanitizationStrategy,
        FileTreeV1KeySanitizationStrategy,
    )
    from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

    d = config.oauth_dir
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    store = FileTreeStore(
        data_directory=d,
        key_sanitization_strategy=FileTreeV1KeySanitizationStrategy(d),
        collection_sanitization_strategy=FileTreeV1CollectionSanitizationStrategy(d),
    )
    return FernetEncryptionWrapper(
        key_value=store,
        fernet=Fernet(config.storage_encryption_key.encode()),
        raise_on_decryption_error=False,
    )


def build_auth(config: Config):
    from fastmcp.server.auth.providers.google import GoogleProvider

    return GoogleProvider(
        client_id=config.google_client_id,
        client_secret=config.google_client_secret,
        base_url=config.base_url,
        required_scopes=["openid", "https://www.googleapis.com/auth/userinfo.email"],
        jwt_signing_key=config.jwt_signing_key,
        client_storage=build_client_storage(config),
        allowed_client_redirect_uris=list(config.allowed_client_redirect_uris),
        cache_ttl_seconds=300,
    )


# ---------------------------------------------------------------- app factory


def create_app(
    config: Config,
    *,
    storage: Storage | None = None,
    with_auth: bool = True,
    http_factory: Callable[[], httpx.AsyncClient] | None = None,
    service_factory: Callable[..., Any] | None = None,
) -> FastMCP:
    storage = storage or Storage(
        config.db_path, TokenCipher(config.token_encryption_key, config.token_encryption_keys)
    )
    http_factory = http_factory or (lambda: httpx.AsyncClient(timeout=15))
    token_cache = g.AccessTokenCache()
    limiter = RateLimiter(config.rate_limit_per_minute)

    def default_service_factory(owner: str, alias: str):
        return g.build_service(
            refresh_token=storage.get_refresh_token(owner, alias),
            client_id=config.google_client_id,
            client_secret=config.google_client_secret,
            scopes=list(GMAIL_SCOPES),
            cache=token_cache,
            owner=owner,
            alias=alias,
        )

    make_service = service_factory or default_service_factory

    mcp = FastMCP(
        name="bonobo",
        instructions=INSTRUCTIONS,
        auth=build_auth(config) if with_auth else None,
    )
    mcp.bonobo = {"storage": storage, "config": config}  # handy for tests/ops

    # -- identity

    def require_owner(tool: str) -> str:
        token = get_access_token()
        if token is None:
            raise ToolError("not authenticated")
        email, verified = caller_email(token.claims or {})
        if not email:
            raise ToolError("not authenticated: no email in token")
        if verified is not None and not _is_true(verified):
            raise ToolError("your Google email is not verified")
        if email not in config.allowed_users:
            log.warning("rejected non-allowlisted caller tool=%s", tool)
            raise ToolError("this Google account is not allowed to use this server")
        if not limiter.allow(email):
            raise ToolError("rate limit exceeded; slow down and retry in a minute")
        return email

    def resolve(owner: str, alias: str):
        try:
            return storage.get_account(owner, alias)
        except (AccountNotFound, ValueError) as e:
            raise ToolError(str(e)) from None

    async def gmail_call(owner: str, alias: str, tool: str, detail: str, fn):
        """Run fn(service) in a worker thread with error mapping + audit."""
        acct = resolve(owner, alias)

        def work():
            svc = make_service(owner, acct.alias)
            return fn(svc, acct)

        try:
            result = await anyio.to_thread.run_sync(work)
        except Exception as e:  # noqa: BLE001
            if isinstance(e, StorageError):
                err = g.GmailError(str(e))
            else:
                err = g.map_google_error(e, acct.alias)
            if "relink" in str(err):
                token_cache.drop(owner, acct.alias)
            write_audit(storage, owner, tool, acct.alias, f"{detail} err={type(e).__name__}", False)
            raise ToolError(str(err)) from None
        storage.touch_account(owner, acct.alias)
        write_audit(storage, owner, tool, acct.alias, detail, True)
        return result

    # -- account tools

    @mcp.tool(annotations={"readOnlyHint": True})
    async def list_accounts() -> list[dict]:
        """List the Gmail accounts you have linked (alias + address). Call this first
        when the user hasn't said which account to use."""
        owner = require_owner("list_accounts")
        write_audit(storage, owner, "list_accounts", None, "", True)
        return [a.public() for a in storage.list_accounts(owner)]

    def _link(owner: str, tool: str, alias: str, login_hint: str | None) -> dict:
        try:
            alias = validate_alias(alias)
        except ValueError as e:
            raise ToolError(str(e)) from None
        ls = start_link(
            storage,
            state_secret=config.state_secret,
            client_id=config.google_client_id,
            redirect_uri=config.gmail_redirect_uri,
            owner=owner,
            alias=alias,
            login_hint=login_hint,
        )
        write_audit(storage, owner, tool, alias, "link started", True)
        return {
            "url": ls.url,
            "expires_in": ls.expires_in,
            "instructions": (
                f"Open this URL, choose the Gmail account to link as '{alias}', and approve "
                f"access. The link expires in {ls.expires_in // 60} minutes and works once. "
                "Google may show an 'unverified app' warning: choose Advanced → continue."
            ),
        }

    @mcp.tool
    async def link_account(
        alias: Annotated[str, Field(description="Short name for the mailbox, [a-z0-9_-]{1,32}")],
        login_hint: Annotated[str | None, Field(description="Optional email address to preselect")] = None,
    ) -> dict:
        """Start linking a Gmail account under an alias. Returns a URL the user must
        open to sign in to Google and approve read + draft access."""
        owner = require_owner("link_account")
        return _link(owner, "link_account", alias, login_hint)

    @mcp.tool
    async def relink_account(alias: str) -> dict:
        """Re-authorize an existing alias (e.g. after 'needs relinking' errors).
        Same as link_account; the new authorization overwrites the old one."""
        owner = require_owner("relink_account")
        hint = None
        try:
            hint = storage.get_account(owner, validate_alias(alias)).email
        except (AccountNotFound, ValueError):
            pass
        return _link(owner, "relink_account", alias, hint)

    @mcp.tool
    async def rename_account(old_alias: str, new_alias: str) -> dict:
        """Rename one of your linked accounts' aliases (e.g. 'aj' -> 'ray'). The Google
        authorization is kept; no relinking needed."""
        owner = require_owner("rename_account")
        try:
            storage.rename_account(owner, old_alias, new_alias)
        except (AccountNotFound, StorageError, ValueError) as e:
            raise ToolError(str(e)) from None
        old, new = old_alias.strip().lower(), new_alias.strip().lower()
        token_cache.drop(owner, old)
        write_audit(storage, owner, "rename_account", new, f"renamed from {old}", True)
        return {"ok": True, "alias": new}

    @mcp.tool(annotations={"destructiveHint": True})
    async def unlink_account(alias: str) -> dict:
        """Remove a linked Gmail account and revoke its token at Google."""
        owner = require_owner("unlink_account")
        acct = resolve(owner, alias)
        try:
            rt = storage.get_refresh_token(owner, acct.alias)
        except StorageError:
            rt = None
        revoked = False
        if rt:
            async with http_factory() as http:
                revoked = await revoke_token(http, rt)
        storage.delete_account(owner, acct.alias)
        token_cache.drop(owner, acct.alias)
        write_audit(storage, owner, "unlink_account", acct.alias, f"revoked={revoked}", True)
        return {"ok": True, "revoked_at_google": revoked}

    # -- mail tools

    @mcp.tool(annotations={"readOnlyHint": True})
    async def search_threads(
        alias: str,
        query: Annotated[str, Field(description="Gmail search syntax, e.g. 'from:bob newer_than:7d'")],
        max_results: Annotated[int, Field(ge=1, le=50)] = 10,
        page_token: str | None = None,
    ) -> dict:
        """Search threads in one linked account using Gmail query syntax.
        Call list_accounts first if the user hasn't named an account."""
        owner = require_owner("search_threads")
        return await gmail_call(
            owner, alias, "search_threads", f"max={max_results}",
            lambda svc, a: g.op_search_threads(svc, query, max_results, page_token),
        )

    @mcp.tool(annotations={"readOnlyHint": True})
    async def search_all_accounts(
        query: Annotated[str, Field(description="Gmail search syntax")],
        max_results_per_account: Annotated[int, Field(ge=1, le=25)] = 5,
    ) -> dict:
        """Run the same Gmail search across all of your linked accounts. Results are
        grouped by alias; one failing account does not fail the others."""
        owner = require_owner("search_all_accounts")
        accounts = storage.list_accounts(owner)
        results: dict[str, Any] = {}

        async def one(alias: str):
            try:
                r = await gmail_call(
                    owner, alias, "search_all_accounts", f"max={max_results_per_account}",
                    lambda svc, a: g.op_search_threads(svc, query, max_results_per_account, None),
                )
                results[alias] = dict(r)
            except ToolError as e:
                results[alias] = {"error": str(e)}

        async with anyio.create_task_group() as tg:
            for a in accounts:
                tg.start_soon(one, a.alias)
        emails = {a.alias: a.email for a in accounts}
        for alias, r in results.items():
            r["email"] = emails[alias]
        return {"results": {k: results[k] for k in sorted(results)}}

    @mcp.tool(annotations={"readOnlyHint": True})
    async def get_thread(
        alias: str,
        thread_id: str,
        max_body_chars: Annotated[int, Field(ge=0, le=100_000)] = 8000,
    ) -> dict:
        """Read every message in a thread (plain-text bodies, attachment names only)."""
        owner = require_owner("get_thread")
        return await gmail_call(
            owner, alias, "get_thread", f"thread={thread_id}",
            lambda svc, a: g.op_get_thread(svc, thread_id, max_body_chars),
        )

    @mcp.tool(annotations={"readOnlyHint": True})
    async def get_message(
        alias: str,
        message_id: str,
        max_body_chars: Annotated[int, Field(ge=0, le=200_000)] = 20000,
    ) -> dict:
        """Read one message (plain-text body, attachment names and sizes only)."""
        owner = require_owner("get_message")
        return await gmail_call(
            owner, alias, "get_message", f"message={message_id}",
            lambda svc, a: g.op_get_message(svc, message_id, max_body_chars),
        )

    @mcp.tool(annotations={"readOnlyHint": True})
    async def list_labels(alias: str) -> list[dict]:
        """List Gmail labels (id, name, type) for one linked account."""
        owner = require_owner("list_labels")
        return await gmail_call(owner, alias, "list_labels", "", lambda svc, a: g.op_list_labels(svc))

    @mcp.tool
    async def create_draft(
        alias: str,
        to: Annotated[str, Field(description="Comma-separated recipient addresses")],
        subject: str,
        body: Annotated[str, Field(description="Plain-text body")],
        cc: str | None = None,
        bcc: str | None = None,
        reply_to_message_id: Annotated[
            str | None, Field(description="Message id to reply to (threads the draft)")
        ] = None,
    ) -> dict:
        """Create a Gmail draft (new or reply) in one linked account. This does NOT
        send: the user reviews and sends it from Gmail. Call list_accounts first if the
        user hasn't said which account to draft from."""
        owner = require_owner("create_draft")

        def fn(svc, acct):
            r = g.op_create_draft(
                svc,
                from_addr=acct.email,
                to=to,
                subject=subject,
                body=body,
                cc=cc,
                bcc=bcc,
                reply_to_message_id=reply_to_message_id,
            )
            r["gmail_url"] = g.gmail_drafts_url(acct.email)
            return r

        detail = "reply" if reply_to_message_id else "new"
        return await gmail_call(owner, alias, "create_draft", detail, fn)

    # -- HTTP routes

    @mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(request: Request):
        return PlainTextResponse("ok")

    @mcp.custom_route("/gmail/callback", methods=["GET"], include_in_schema=False)
    async def gmail_callback(request: Request):
        q = request.query_params
        if q.get("error"):
            return _page("Linking cancelled", "Google reported an error or you declined access. Ask Claude to start linking again.", 400)
        code, state = q.get("code"), q.get("state")
        if not code or not state:
            return _page("Invalid request", "Missing code or state.", 400)
        try:
            payload, verifier = consume_state(storage, config.state_secret, state)
            owner, alias = payload["owner"], payload["alias"]
            if owner not in config.allowed_users:
                raise LinkError("this account is not allowed to use this server")
            async with http_factory() as http:
                tokens = await exchange_code(
                    http,
                    client_id=config.google_client_id,
                    client_secret=config.google_client_secret,
                    redirect_uri=config.gmail_redirect_uri,
                    code=code,
                    code_verifier=verifier,
                )
                email = await fetch_profile_email(http, tokens["access_token"])
            storage.upsert_account(
                owner, alias, email, tokens["refresh_token"],
                tokens.get("scope") or " ".join(GMAIL_SCOPES),
            )
            token_cache.drop(owner, alias)
            if tokens.get("expires_in"):
                token_cache.put(owner, alias, tokens["access_token"], time.time() + int(tokens["expires_in"]))
        except LinkError as e:
            log.info("gmail link failed: %s", e)
            return _page("Linking failed", str(e), 400)
        except Exception:
            log.exception("gmail link failed unexpectedly")
            return _page("Linking failed", "Unexpected error; ask Claude to start linking again.", 500)
        write_audit(storage, owner, "gmail_callback", alias, f"linked {email}", True)
        return _page("Linked ✓", f"Linked {email} as '{alias}'. You can close this tab.")

    return mcp


def main() -> None:
    try:
        config = load_config()
    except ConfigError as e:
        raise SystemExit(f"refusing to start: {e}") from None
    logging.basicConfig(
        level=config.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    install_log_redaction()
    mcp = create_app(config)
    log.info("starting bonobo-mcp on %s:%s (base_url=%s)", config.host, config.port, config.base_url)
    mcp.run(
        transport="http",
        host=config.host,
        port=config.port,
        path="/mcp",
        show_banner=False,
        uvicorn_config={"access_log": False},  # access logs would contain OAuth codes
    )


if __name__ == "__main__":
    main()
