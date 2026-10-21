# Changelog

All notable changes to Surfski are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every pull request adds a line under
`[Unreleased]`; a release moves those lines into a version section (see [RELEASING.md](RELEASING.md)).

## [Unreleased]

### Added

- Versioned releases: `surfski --version`, the version in the MCP server info and in
  `surfski_build_info`, this changelog, a release workflow that checks the tag against
  `pyproject.toml` and publishes a GitHub Release from the changelog, and `RELEASING.md` (#11).

### Security

- Log redaction also hides `Authorization: …` headers and `Bearer <token>` values (#11).

## [0.1.0] - unreleased

The first release: a self-hosted remote MCP server that gives Claude access to many Gmail
mailboxes per user, with per-user isolation.

### Added

- **Multi-mailbox Gmail tools:** `link_account` / `relink_account` (Google consent per mailbox,
  PKCE, single-use state), `list_accounts`, `rename_account`, `unlink_account`, `search_threads`,
  `search_all_accounts`, `get_thread`, `get_message`, `list_labels`.
- **Drafts** (#14): `create_draft`, `list_drafts`, `get_draft`, `update_draft`, `delete_draft`.
- **Address aliases and send-from** (#1): `list_addresses`, `set_address_label`, `set_default_from`;
  drafts pick the right From address from the mailbox's verified send-as addresses.
- **`forward_message`** (#15), as a draft or sent per the send policy.
- **Opt-in sending** (#2): `SENDING_ENABLED` plus a per-mailbox `off` / `confirm` / `auto` policy,
  `send_draft` and `send_email`, daily and recipient caps, an optional recipient domain allowlist,
  and confirm links on owner-authenticated `/send` pages. Raising a policy needs a fresh Google
  sign-in by the owner.
- **Confirm via MCP elicitation** (#27): `confirm` sends are approved in the MCP client when it
  supports form elicitation (`CONFIRM_CHANNEL=auto`), with the confirm link as the fallback.
- **`get_attachment`** (#9): text from text/CSV/JSON/XML/HTML, PDF, DOCX, XLSX and PPTX attachments,
  with size, time and zip-bomb limits; never binary.
- **Attachments on drafts** (#16): `create_draft`, `update_draft`, `send_email` and `forward_message`
  attach files from messages in the same mailbox (20 MB total).
- **`delete_my_data` and `export_my_data`** (#3), with `AUDIT_ON_DELETE=delete|pseudonymize`.
- **`find_contact`** (#18): resolve a name to an address from the caller's own mail headers.
- **`unsubscribe`** (#17): `List-Unsubscribe` one-click (RFC 8058), mailto through the send policy,
  plain web links returned, always previewed before acting.
- **Opt-in mailbox triage** (#8): `TRIAGE_ENABLED` plus a per-mailbox `enable_triage` Google
  re-consent for `gmail.modify`; mark read/unread, star, archive, move to Inbox, user labels, Trash
  and untrash, with per-call and daily caps and no permanent delete.
- **`ALLOWED_DOMAINS`** (#6): allow whole Google Workspace domains, matched on the primary domain
  and Google's verified `hd` claim.
- **Admin CLI** (#7): `surfski serve` (default) and local `surfski admin list | unlink |
  purge-owner | rotate-token-key | audit`.
- **Key rotation** (#7): `TOKEN_ENCRYPTION_KEY_OLD` / `TOKEN_ENCRYPTION_KEYS_OLD` and
  `STORAGE_ENCRYPTION_KEY_OLD`, with `rotate-token-key` re-encrypting every token in one transaction.
- **Prometheus metrics** (#10): `/metrics` behind `METRICS_ENABLED` and a Bearer `METRICS_TOKEN`,
  with no personal data in any label.
- **Backups** (#5): `scripts/backup.sh` with a consistent SQLite snapshot, retention and restore.
- **CI and images** (#4): pytest, a Docker smoke test and shellcheck on every PR; multi-arch
  (amd64/arm64) images on GHCR for release tags.

### Security

- Owner isolation: every `accounts` query a tool makes is scoped to the caller, with tests per data
  path. Only the local admin CLI reads across owners.
- Refresh tokens are Fernet-encrypted at rest (optional per-owner keys); access tokens live only in
  memory. Logs and audit rows never contain tokens, auth codes, message bodies or email addresses.
- Fail-closed configuration: the server refuses to start with missing or malformed secrets or an
  empty allowlist; public mail providers can't be allowlisted as domains.
- Write features (sending, triage) are off by default and need both an operator switch and a
  per-mailbox opt-in confirmed by the owner outside the conversation.
- The unsubscribe POST is SSRF-hardened (https, public addresses only, pinned connection, redirect
  and size limits).
- Hardened container: non-root uid 10001, read-only root filesystem, `cap_drop: ALL`,
  `no-new-privileges`, published on `127.0.0.1` only.

### Changed

- Runtime standardized on Python 3.14 (Docker image and `.python-version`), with Python 3.12 as the
  supported minimum (#25).
- The project was renamed to Surfski.
