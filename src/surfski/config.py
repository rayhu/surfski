"""Environment loading and validation. Fail closed: missing secrets abort startup."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from cryptography.fernet import Fernet

REQUIRED = (
    "BASE_URL",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "ALLOWED_USERS",
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
    state_secret: bytes = b""
    data_dir: Path = Path("/var/lib/surfski")
    log_level: str = "INFO"
    host: str = "127.0.0.1"
    port: int = 8000
    rate_limit_per_minute: int = 60
    allowed_client_redirect_uris: tuple[str, ...] = CLAUDE_REDIRECT_URIS

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
        e.strip().lower() for e in env["ALLOWED_USERS"].split(",") if e.strip()
    )
    if not allowed:
        raise ConfigError("ALLOWED_USERS is empty")

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

    return Config(
        base_url=base_url,
        google_client_id=env["GOOGLE_CLIENT_ID"].strip(),
        google_client_secret=env["GOOGLE_CLIENT_SECRET"].strip(),
        allowed_users=allowed,
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
    )
