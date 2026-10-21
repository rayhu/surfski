import pytest

from surfski.audit import redact
from surfski.config import CLAUDE_REDIRECT_URIS, ConfigError, load_config
from tests.conftest import make_env


@pytest.mark.parametrize("key", ["GOOGLE_CLIENT_SECRET", "JWT_SIGNING_KEY", "STATE_SECRET",
                                 "TOKEN_ENCRYPTION_KEY", "STORAGE_ENCRYPTION_KEY", "ALLOWED_USERS"])
def test_missing_secret_fails_closed(tmp_path, key):
    with pytest.raises(ConfigError, match=key):
        load_config(make_env(tmp_path, **{key: ""}))


def test_bad_fernet_key(tmp_path):
    with pytest.raises(ConfigError, match="Fernet"):
        load_config(make_env(tmp_path, TOKEN_ENCRYPTION_KEY="nope"))


def test_https_required_for_non_local(tmp_path):
    with pytest.raises(ConfigError, match="https"):
        load_config(make_env(tmp_path, BASE_URL="http://mcp.example.com"))


def test_redirect_allowlist(tmp_path):
    prod = load_config(make_env(tmp_path, BASE_URL="https://mcp.example.com/"))
    assert prod.allowed_client_redirect_uris == CLAUDE_REDIRECT_URIS
    assert prod.gmail_redirect_uri == "https://mcp.example.com/gmail/callback"
    local = load_config(make_env(tmp_path))
    assert "http://localhost:*" in local.allowed_client_redirect_uris


def test_allowed_users_normalized(tmp_path):
    c = load_config(make_env(tmp_path, ALLOWED_USERS=" Alice@Example.com , "))
    assert c.allowed_users == {"alice@example.com"}


def test_redact():
    line = '127.0.0.1 - "GET /gmail/callback?code=4/abc&state=xyz HTTP/1.1" 200'
    out = redact(line)
    assert "4/abc" not in out and "xyz" not in out and "/gmail/callback" in out


def test_redact_absolute_url_and_quiet_loggers(caplog):
    import logging

    from surfski.audit import install_log_redaction

    out = redact("HTTP Request: GET https://oauth2.googleapis.com/tokeninfo?access_token=ya29.X")
    assert "ya29.X" not in out and "oauth2.googleapis.com/tokeninfo" in out

    install_log_redaction()
    with caplog.at_level(logging.DEBUG):
        logging.getLogger("httpx2").info("HTTP Request: GET https://x/?access_token=ya29.Y")
        logging.getLogger("fastmcp").warning("callback /auth/callback?code=4/zzz&state=q")
    assert "ya29.Y" not in caplog.text and "4/zzz" not in caplog.text


def test_sending_settings(tmp_path):
    c = load_config(make_env(tmp_path))
    assert c.sending_enabled is False and c.send_daily_cap == 20 and c.send_max_recipients == 10
    assert c.allowed_recipient_domains == frozenset()
    c = load_config(make_env(tmp_path, SENDING_ENABLED="True", SEND_DAILY_CAP="5", SEND_MAX_RECIPIENTS="3",
                             ALLOWED_RECIPIENT_DOMAINS=" Example.com, @corp.org ,"))
    assert c.sending_enabled is True and c.send_daily_cap == 5 and c.send_max_recipients == 3
    assert c.allowed_recipient_domains == {"example.com", "corp.org"}
    assert c.send_auth_redirect_uri == "http://localhost:8000/send/auth/callback"
    for bad in ({"SENDING_ENABLED": "maybe"}, {"SEND_DAILY_CAP": "x"}, {"SEND_MAX_RECIPIENTS": "0"}):
        with pytest.raises(ConfigError):
            load_config(make_env(tmp_path, **bad))
