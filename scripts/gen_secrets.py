#!/usr/bin/env python3
"""Print fresh values for the four secrets. Needs only the `cryptography` package
(or run via `uv run python scripts/gen_secrets.py`)."""

import base64
import secrets

try:
    from cryptography.fernet import Fernet

    def fernet_key() -> str:
        return Fernet.generate_key().decode()
except ImportError:  # Fernet keys are just 32 random bytes, urlsafe-b64
    def fernet_key() -> str:
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()

print(f"JWT_SIGNING_KEY={secrets.token_urlsafe(48)}")
print(f"STORAGE_ENCRYPTION_KEY={fernet_key()}")
print(f"TOKEN_ENCRYPTION_KEY={fernet_key()}")
print(f"STATE_SECRET={secrets.token_urlsafe(48)}")
