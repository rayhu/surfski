import pytest
from cryptography.fernet import Fernet

from surfski.config import load_config
from surfski.storage import Storage, TokenCipher

KEY_A = Fernet.generate_key().decode()
KEY_B = Fernet.generate_key().decode()


def make_env(tmp_path, **over):
    env = {
        "BASE_URL": "http://localhost:8000",
        "GOOGLE_CLIENT_ID": "cid.apps.googleusercontent.com",
        "GOOGLE_CLIENT_SECRET": "GOCSPX-test",
        "ALLOWED_USERS": "alice@example.com,bob@example.com",
        "JWT_SIGNING_KEY": "j" * 43,
        "STORAGE_ENCRYPTION_KEY": KEY_A,
        "TOKEN_ENCRYPTION_KEY": KEY_B,
        "STATE_SECRET": "s" * 43,
        "DATA_DIR": str(tmp_path),
    }
    env.update(over)
    return env


@pytest.fixture
def config(tmp_path):
    return load_config(make_env(tmp_path))


@pytest.fixture
def storage(tmp_path):
    s = Storage(tmp_path / "data.db", TokenCipher(KEY_B))
    yield s
    s.close()
