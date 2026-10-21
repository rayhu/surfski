"""Environment loading and validation. Fail closed: missing secrets abort startup."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.fernet import Fernet

REQUIRED = (
    "BASE_URL",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "JWT_SIGNING_KEY",
    "STORAGE_ENCRYPTION_KEY",
    "TOKEN_ENCRYPTION_KEY",
    "STATE_SECRET",
)

# Claude's OAuth callbacks (Anthropic remote MCP connector docs list claude.ai and
# warn it may move to claude.com; allow both).
CLAUDE_REDIRECT_URIS = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)
LOCAL_REDIRECT_URIS = ("http://localhost:*", "http://127.0.0.1:*")


# Public mailbox providers: allowing one of these as a domain would let anyone with a free
# account in. List such users individually in ALLOWED_USERS instead.
CONSUMER_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com", "proton.me",
    "protonmail.com", "gmx.com", "gmx.net", "mail.com", "yandex.com", "qq.com", "163.com",
})
_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)


def _is_true(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


class ConfigError(RuntimeError):
    pass


def _validate_fernet_key(name: str, key: str) -> None:
    try:
        Fernet(key.encode())
    except Exception as e:  # noqa: BLE001
        raise ConfigError(f"{name} is not a valid Fernet key") from e


@dataclass(frozen=True)
class Config:
    base_url: str
    google_client_id: str
    google_client_secret: str
    allowed_users: frozenset[str]
    jwt_signing_key: str
    storage_encryption_key: str
    token_encryption_key: str
    token_encryption_keys: dict[str, str] = field(default_factory=dict)
    # Whole Google Workspace domains whose (primary) addresses may use the server (#6).
    allowed_domains: frozenset[str] = frozenset()
    state_secret: bytes = b""
    data_dir: Path = Path("/var/lib/surfski")
    log_level: str = "INFO"
    host: str = "127.0.0.1"
    port: int = 8000
    rate_limit_per_minute: int = 60
    allowed_client_redirect_uris: tuple[str, ...] = CLAUDE_REDIRECT_URIS
    # Opt-in sending (#2). Off by default: send tools and /send/* routes don't exist.
    sending_enabled: bool = False
    send_daily_cap: int = 20
    send_max_recipients: int = 10
    allowed_recipient_domains: frozenset[str] = frozenset()
    # How confirm-mode sends are confirmed (#27): "auto" = MCP elicitation when the
    # client supports it, else the confirm link; "link" = always the confirm link.
    confirm_channel: str = "auto"
    # delete_my_data: "delete" the caller's audit rows, or keep them "pseudonymize"d.
    audit_on_delete: str = "delete"
    attachment_max_bytes: int = 15 * 1024 * 1024
    # Extra https ports the one-click unsubscribe POST may use (#17); 443 is always allowed.
    unsubscribe_allowed_ports: frozenset[int] = frozenset()

    def is_allowed(self, email: str | None, *, email_verified: Any, hd: str | None) -> bool:
        """The single allowlist check. Allowed if the caller's primary address is listed in
        ALLOWED_USERS, or if its domain exactly matches ALLOWED_DOMAINS (no subdomains)
        AND Google vouches for it: email_verified is true and the hosted-domain claim
        `hd` equals that domain (so only accounts managed by that Workspace org match,
        not a personal Google account registered on a company address). Callers must
        pass both claims; pass what Google returned, or what the server recorded from it."""
        email = (email or "").strip().lower()
        if email.count("@") != 1:
            return False
        local, domain = email.split("@")
        if not local or not domain:
            return False
        if email in self.allowed_users:
            return True
        if domain not in self.allowed_domains:
            return False
        return _is_true(email_verified) and (hd or "").strip().lower() == domain

    @property
    def send_auth_redirect_uri(self) -> str:
        return f"{self.base_url}/send/auth/callback"

    @property
    def gmail_redirect_uri(self) -> str:
        return f"{self.base_url}/gmail/callback"

    @property
    def is_local(self) -> bool:
        return urlparse(self.base_url).hostname in ("localhost", "127.0.0.1")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "data.db"

    @property
    def oauth_dir(self) -> Path:
        return self.data_dir / "oauth"


def parse_allowed_domains(raw: str) -> frozenset[str]:
    out = set()
    for d in raw.split(","):
        d = d.strip().lower()
        if not d:
            continue
        if "@" in d or "*" in d:
            raise ConfigError(f"ALLOWED_DOMAINS entry {d!r}: list bare domains like example.com "
                              "(no @, no wildcards; subdomains are not matched)")
        if not _DOMAIN_RE.match(d):
            raise ConfigError(f"ALLOWED_DOMAINS entry {d!r} is not a valid domain")
        if d in CONSUMER_DOMAINS:
            raise ConfigError(f"ALLOWED_DOMAINS can't include the public mail provider {d}: that "
                              "would let anyone with a free account in. Put those users' "
                              "addresses in ALLOWED_USERS instead.")
        out.add(d)
    return frozenset(out)


def load_config(env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ if env is None else env)
    missing = [k for k in REQUIRED if not env.get(k, "").strip()]
    if missing:
        raise ConfigError(f"missing required settings: {', '.join(missing)}")

    base_url = env["BASE_URL"].strip().rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError("BASE_URL must be an http(s) URL")
    local = parsed.hostname in ("localhost", "127.0.0.1")
    if parsed.scheme != "https" and not local:
        raise ConfigError("BASE_URL must use https unless it is localhost")

    allowed = frozenset(
        e.strip().lower() for e in env.get("ALLOWED_USERS", "").split(",") if e.strip()
    )
    allowed_domains = parse_allowed_domains(env.get("ALLOWED_DOMAINS", ""))
    if not allowed and not allowed_domains:
        raise ConfigError("ALLOWED_USERS and ALLOWED_DOMAINS are both empty: set at least one")

    if len(env["JWT_SIGNING_KEY"]) < 32:
        raise ConfigError("JWT_SIGNING_KEY must be at least 32 characters")
    if len(env["STATE_SECRET"]) < 32:
        raise ConfigError("STATE_SECRET must be at least 32 characters")

    _validate_fernet_key("STORAGE_ENCRYPTION_KEY", env["STORAGE_ENCRYPTION_KEY"])
    _validate_fernet_key("TOKEN_ENCRYPTION_KEY", env["TOKEN_ENCRYPTION_KEY"])

    per_owner: dict[str, str] = {}
    for pair in env.get("TOKEN_ENCRYPTION_KEYS", "").split(","):
        if not pair.strip():
            continue
        if "=" not in pair:
            raise ConfigError("TOKEN_ENCRYPTION_KEYS must be owner=key,owner=key")
        owner, key = pair.split("=", 1)
        owner = owner.strip().lower()
        _validate_fernet_key(f"TOKEN_ENCRYPTION_KEYS[{owner}]", key.strip())
        per_owner[owner] = key.strip()

    redirect_env = env.get("ALLOWED_CLIENT_REDIRECT_URIS", "").strip()
    if redirect_env:
        redirects = tuple(u.strip() for u in redirect_env.split(",") if u.strip())
    else:
        redirects = CLAUDE_REDIRECT_URIS + (LOCAL_REDIRECT_URIS if local else ())

    sending_enabled = env.get("SENDING_ENABLED", "false").strip().lower()
    if sending_enabled not in ("true", "false", "1", "0", "yes", "no", ""):
        raise ConfigError("SENDING_ENABLED must be true or false")
    try:
        daily_cap = int(env.get("SEND_DAILY_CAP", "20"))
        max_recipients = int(env.get("SEND_MAX_RECIPIENTS", "10"))
    except ValueError as e:
        raise ConfigError("SEND_DAILY_CAP and SEND_MAX_RECIPIENTS must be integers") from e
    if daily_cap < 1 or max_recipients < 1:
        raise ConfigError("SEND_DAILY_CAP and SEND_MAX_RECIPIENTS must be at least 1")
    domains = frozenset(
        d.strip().lower().lstrip("@") for d in env.get("ALLOWED_RECIPIENT_DOMAINS", "").split(",") if d.strip()
    )

    confirm_channel = env.get("CONFIRM_CHANNEL", "auto").strip().lower() or "auto"
    if confirm_channel not in ("auto", "link"):
        raise ConfigError("CONFIRM_CHANNEL must be auto or link")

    try:
        attachment_mb = float(env.get("ATTACHMENT_MAX_MB", "15"))
    except ValueError as e:
        raise ConfigError("ATTACHMENT_MAX_MB must be a number") from e
    if not 0 < attachment_mb <= 25:
        raise ConfigError("ATTACHMENT_MAX_MB must be between 0 and 25")
    audit_on_delete = env.get("AUDIT_ON_DELETE", "delete").strip().lower() or "delete"
    if audit_on_delete not in ("delete", "pseudonymize"):
        raise ConfigError("AUDIT_ON_DELETE must be delete or pseudonymize")

    try:
        unsub_ports = frozenset(
            int(p) for p in env.get("UNSUBSCRIBE_ALLOWED_PORTS", "").split(",") if p.strip())
    except ValueError as e:
        raise ConfigError("UNSUBSCRIBE_ALLOWED_PORTS must be a comma-separated list of ports") from e
    if any(not 0 < p < 65536 for p in unsub_ports):
        raise ConfigError("UNSUBSCRIBE_ALLOWED_PORTS must be ports between 1 and 65535")

    return Config(
        base_url=base_url,
        google_client_id=env["GOOGLE_CLIENT_ID"].strip(),
        google_client_secret=env["GOOGLE_CLIENT_SECRET"].strip(),
        allowed_users=allowed,
        allowed_domains=allowed_domains,
        jwt_signing_key=env["JWT_SIGNING_KEY"],
        storage_encryption_key=env["STORAGE_ENCRYPTION_KEY"],
        token_encryption_key=env["TOKEN_ENCRYPTION_KEY"],
        token_encryption_keys=per_owner,
        state_secret=env["STATE_SECRET"].encode(),
        data_dir=Path(env.get("DATA_DIR") or "/var/lib/surfski"),
        log_level=env.get("LOG_LEVEL", "INFO").upper(),
        host=env.get("HOST", "127.0.0.1"),
        port=int(env.get("PORT", "8000")),
        rate_limit_per_minute=int(env.get("RATE_LIMIT_PER_MINUTE", "60")),
        allowed_client_redirect_uris=redirects,
        sending_enabled=sending_enabled in ("true", "1", "yes"),
        send_daily_cap=daily_cap,
        send_max_recipients=max_recipients,
        allowed_recipient_domains=domains,
        confirm_channel=confirm_channel,
        audit_on_delete=audit_on_delete,
        attachment_max_bytes=int(attachment_mb * 1024 * 1024),
        unsubscribe_allowed_ports=unsub_ports,
    )
