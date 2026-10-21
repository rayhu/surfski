# Security policy

This server holds OAuth refresh tokens for people's mailboxes, so we treat security reports as a
priority.

## Reporting a vulnerability

Please **don't open a public issue.** Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository instead.
Include steps to reproduce, the impact, and the affected version or commit.

We aim to acknowledge reports within 3 business days.

## Scope

Of particular interest:

- one owner reading or acting on another owner's linked mailboxes;
- bypassing the `ALLOWED_USERS` allowlist or the linking state checks (signature, expiry, replay);
- token, auth code or mailbox content leakage via logs, errors or the audit log;
- weaknesses in the default container or deployment configuration.

## Operator responsibilities

Self-hosters are responsible for keeping secrets out of backups and version control, restricting
network exposure (Docker bypasses `ufw`, so use your cloud firewall), and applying updates.
