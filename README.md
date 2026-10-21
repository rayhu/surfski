# Surfski

[![CI](https://github.com/rayhu/surfski/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rayhu/surfski/actions/workflows/ci.yml)

**Many Gmail inboxes, one Claude connector.** · [surfski.io](https://surfski.io)

Surfski is a small, self-hosted **remote MCP server**. You add it to Claude once as a custom connector.
After that, Claude can search, read and draft email across **several Gmail / Google
Workspace mailboxes** for each user, and users never see each other's mailboxes.

- Works from claude.ai on the web, desktop and mobile. Any client that speaks MCP Streamable HTTP with OAuth works too.
- Each Claude user signs in with Google, and only allowlisted addresses get in.
- Each user links any number of mailboxes under short aliases such as `work`, `personal` or `support`.
- **Drafts only** by default. Claude saves drafts and you send them from Gmail. An operator can turn on
  [opt-in sending](#sending-opt-in), and each mailbox then picks `off`, `confirm` (you click a link to
  send) or `auto`.

Tools: `list_accounts`, `link_account`, `relink_account`, `rename_account`, `unlink_account`, `search_threads`,
`search_all_accounts`, `find_contact`, `get_thread`, `get_message`, `list_labels`, `create_draft`, `list_drafts`, `get_draft`,
`update_draft`, `delete_draft`, `list_addresses`, `set_address_label`, `set_default_from`, `forward_message`,
`get_attachment`, `unsubscribe`, `export_my_data`, `delete_my_data`.
With `SENDING_ENABLED=true` also: `send_draft`, `send_email`, `set_send_policy` (and `forward_message(send=true)`).
With `TRIAGE_ENABLED=true` also: `enable_triage`, `disable_triage`, `mark_read`, `mark_unread`, `star`, `unstar`,
`archive`, `move_to_inbox`, `apply_label`, `remove_label`, `create_label`, `trash`, `untrash` (see
[Triage](#triage-opt-in)).

**Find an address.** `find_contact("Alice")` (or part of an address, or a name in any script, e.g.
`王伟`) looks through the From/To/Cc/Reply-To headers of your own recent mail in all your mailboxes (or
the `aliases` you pass) and returns likely addresses with their display names, message count, last
seen date, mailboxes and whether you've written to them, ranked by frequency, recency and that
"sent to" boost. It needs no extra Google scope. Each mailbox scans at most 50 threads / 200
messages. Your own addresses and no-reply senders are left out unless you pass `include_self` /
`include_noreply`. The audit log records only counts, never the name or addresses.

**Unsubscribe.** `unsubscribe(alias, message_id)` reads only the message's `List-Unsubscribe` and
`List-Unsubscribe-Post` headers (never links in the body) and reports what it would do; nothing
happens until it's called again with `confirm=true`, which re-reads the headers. It then uses, in
order: the RFC 8058 **one-click** POST to the sender's https endpoint; a **mailto** unsubscribe,
saved as a draft and sent only if the mailbox's [send policy](#sending-opt-in) allows it (`confirm`
goes through the usual approval; with sending off the draft is kept for you to send); or, for a
plain https link, it returns the URL for **you** to open (it never loads web pages). Unsubscribing
tells the sender the address is live, so for spam, report it instead. See
[Unsubscribe safety](#unsubscribe-safety).

**Send from an alias.** `create_draft` and `update_draft` take `from_address` (a verified "Send mail as"
address or a label set with `set_address_label`) and `include_signature`. Replies default to the address
the original was sent to; new drafts use `set_default_from`, then Gmail's default. New addresses are added in
Gmail → Settings → Accounts → Send mail as.

**Attach files from your mail.** `create_draft`, `send_email` and `forward_message` take `attachments`, and
`update_draft` takes `add_attachments`. Each entry is `{message_id, part_id}`, using the `part_id` that
`get_message` / `get_thread` list. Files can only come from messages in the **same** mailbox; a message id
from another alias fails with a clear error. There are no local or arbitrary uploads. Duplicate entries
are attached once. The total is limited to 20 MB, checked from the declared sizes before anything is
downloaded, and large drafts go up as media uploads. `update_draft` keeps the draft's current
attachments. Inline images are kept as regular attachments, as in `forward_message`. Pass
`remove_attachments` (a filename as `get_draft` lists it, which removes every attachment with that
name, or a `part_id`) to drop some. The audit log records only the attachment count and total bytes.

## Why self-host?

Gmail's read scopes are **restricted** scopes. To offer them to the public, an app needs Google
OAuth verification plus a third-party CASA security assessment that is renewed every year.
A self-hosted instance avoids all of that:

- you use **your own** Google Cloud project and OAuth client;
- an unverified app works for up to **100 users over the app's lifetime**, which is plenty for a
  person, family or small team;
- refresh tokens never leave your server.

The only cost is an "unverified app" warning on the Google consent screen. Your users click
*Advanced → continue* once per mailbox.

## How it works

```
Claude ─HTTPS─► your reverse proxy :443 ─► container :8000 (published on 127.0.0.1:38000)
                                           /mcp              MCP endpoint (bearer auth)
                                           /auth/callback    Google login for Claude users (layer A)
                                           /gmail/callback   Gmail mailbox linking (layer B)
                                           /healthz          returns "ok"
                                         volume → /data
                                           data.db           accounts (Fernet-encrypted refresh tokens), audit_log
                                           oauth/            FastMCP OAuth client storage (Fernet-encrypted)
```

There are two separate OAuth layers, and both use the same Google OAuth client:

| Layer | Proves | Scopes | Redirect URI |
|---|---|---|---|
| A. MCP login | *which Claude user* is calling, checked against `ALLOWED_USERS` / `ALLOWED_DOMAINS` | `openid`, `userinfo.email` | `https://<host>/auth/callback` |
| B. Mailbox link | access to *one mailbox* | `gmail.readonly`, `gmail.compose` | `https://<host>/gmail/callback` |

## Quickstart (self-host)

You need a Linux host with Docker and Compose, a domain name, and a TLS reverse proxy such as
Caddy, nginx or Traefik.

### 1. Google Cloud (one time)

1. Create a project and enable the **Gmail API**.
2. Google Auth Platform → **Branding**: set the app name, support email, home page, privacy policy
   link and authorized domain.
3. **Audience**: choose **External**, then click **Publish app** to move it to *In production*.
   Don't submit it for verification. In *Testing* mode Google expires refresh tokens after
   **7 days**, so you would have to relink weekly.
4. **Data Access**: add `openid`, `.../auth/userinfo.email`, `.../auth/gmail.readonly` and
   `.../auth/gmail.compose`. If you turn on [triage](#triage-opt-in), also add `.../auth/gmail.modify`.
5. **Clients** → create a **Web application** client with these redirect URIs:
   - `https://<host>/auth/callback`
   - `https://<host>/gmail/callback`
   - `https://<host>/send/auth/callback` (only needed if you set `SENDING_ENABLED=true`)
6. If you use Google Workspace, the admin should go to Admin console → Security → API controls →
   Manage third-party app access, add the app by client ID and mark it **Trusted**. Otherwise
   Workspace policy may block mailbox linking.

### 2. Configure

```bash
git clone <this repo> /opt/surfski && cd /opt/surfski
```

```bash
sudo install -d -m 700 /etc/surfski && sudo install -m 600 deploy/env.example /etc/surfski/env
```

```bash
python3 scripts/gen_secrets.py
```

Paste the four generated secrets into `/etc/surfski/env`, then fill in `BASE_URL`,
`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and `ALLOWED_USERS` (and/or `ALLOWED_DOMAINS` to allow
a whole Workspace domain). The server **refuses to start** if any secret is missing or malformed, or
if both allowlists are empty.

> **Aliases:** Google sign-in reports a user's **primary** address. If your Workspace uses alias
> domains, put the primary addresses in `ALLOWED_USERS`, or the Workspace primary domain in
> `ALLOWED_DOMAINS` (an alias domain never matches; Google's `hd` claim must equal the primary domain). Linking an alias address links the
> primary mailbox behind it.
>
> **Secondary domains:** if a user's address is on a *secondary* domain of a Workspace org, Google's
> `hd` claim may still be the org's **primary** domain, so list the primary domain in
> `ALLOWED_DOMAINS` (or list the user in `ALLOWED_USERS`). A mismatch fails closed: the user is refused.

### 3. Run

```bash
sudo docker compose -p surfski up -d --build
```

```bash
curl -s 127.0.0.1:38000/healthz
```

**Prebuilt image (optional).** Instead of building locally, you can use the multi-arch
(amd64/arm64) image published on each release. In `compose.yaml`, replace `build: .` and
`image: surfski:latest` with:

```yaml
    image: ghcr.io/rayhu/surfski:latest   # or pin a release, e.g. ghcr.io/rayhu/surfski:v0.1.0
```

Then start it without `--build`:

```bash
sudo docker compose -p surfski up -d
```

Point your reverse proxy at `127.0.0.1:38000`. `deploy/Caddyfile.snippet` is a Caddy example.
**Don't enable response compression** on this route, because the MCP stream uses SSE.

### 4. Connect Claude

In Claude, go to Settings → Connectors → Add custom connector and enter
`https://<host>/mcp`. Click Connect and sign in with an allowlisted Google account. Then say:
*"link my work Gmail as work"* and open the link Claude returns.

When you link a mailbox, sign in **as that mailbox** and tick **both** permission checkboxes.

### Upgrade

```bash
git pull && sudo docker compose -p surfski up -d --build
```

With the prebuilt image, run `git pull && sudo docker compose -p surfski pull && sudo docker compose -p surfski up -d` instead. The `git pull` picks up changes to `compose.yaml` and the env reference.

### Backups

`scripts/backup.sh` backs up the `surfski_surfski-data` volume to
`/var/backups/surfski/surfski-data-YYYYmmdd-HHMMSS.tgz` (mode 600) and deletes archives older than
14 days. It takes a consistent SQLite snapshot with Python's online backup API inside the Surfski
image, so the server can keep running, and adds `oauth/` as files. It refuses to run if anything
named `env`/`*.env` is in the volume. `--dry-run` shows what it would do; `--help` lists options
(`--dest`, `--keep`, `--volume`, `--image`).

Nightly at 03:15 from root's crontab (it uses the local `surfski:latest` image that `docker compose build` creates):

```cron
15 3 * * * /opt/surfski/scripts/backup.sh --keep 14 >> /var/log/surfski-backup.log 2>&1
```

Restore:

```bash
docker compose stop app
sudo scripts/backup.sh --restore /var/backups/surfski/surfski-data-20260101-031500.tgz --yes
# add --force if the volume isn't empty; its contents are replaced
docker compose start app
```

**The backup is useless without `TOKEN_ENCRYPTION_KEY` and `STORAGE_ENCRYPTION_KEY`, and it never
contains them. Keep the env file in a separate place, such as a password manager, never in the same
backup.** Restore with the same keys that were in use when the backup was made. If you lose the
keys, users simply relink their mailboxes.

### Administration (local CLI)

`surfski` with no arguments (or `surfski serve`) runs the server; that is what the container's
`CMD` does. The `admin` subcommands work on the database directly and run only from a shell on the
host or inside the container. There is no network admin endpoint. They never print refresh
tokens, ciphertext or keys, and they are safe to run while the server is up.

```bash
sudo docker compose -p surfski exec app surfski admin list
```

| Command | What it does |
|---|---|
| `admin list [--json]` | Every owner with their mailboxes: alias, address, created / last used, send policy, triage |
| `admin unlink --owner X --alias Y [--revoke]` | Remove one mailbox (as `unlink_account`). `--revoke` also revokes its token at Google |
| `admin purge-owner --owner X --yes` | Erase all of one owner's data, exactly as their `delete_my_data` would (revokes at Google; audit rows follow `AUDIT_ON_DELETE`). Without `--yes` nothing is deleted |
| `admin rotate-token-key [--dry-run]` | Re-encrypt every refresh token with the current key (see below) |
| `admin audit --owner X [--since 7d\|2026-10-01]` | Audit row counts per tool (ok / failed), never details |

Exit codes: `0` success; `1` refused or failed (unknown owner or alias, missing `--yes`, a failed
revocation at Google, undecryptable rows during rotation); `2` usage or configuration error. When a
revocation fails, `unlink` and `purge-owner` have still removed the data. An unexpected error (for example
`database is locked`) prints one line and exits 1; `surfski admin --debug …` shows the traceback.

### Rotating encryption keys

**`TOKEN_ENCRYPTION_KEY`** (Gmail refresh tokens in SQLite). While `TOKEN_ENCRYPTION_KEY_OLD` is set,
the server decrypts with the new key, then the old one, and always encrypts with the new one, so
it keeps working during the whole rotation:

1. Generate a key: `python3 scripts/gen_secrets.py` and take its `TOKEN_ENCRYPTION_KEY` line.
2. In `/etc/surfski/env`, move the current value to `TOKEN_ENCRYPTION_KEY_OLD` and put the new key in
   `TOKEN_ENCRYPTION_KEY`.
3. **Restart the server on the new key before rotating:** `sudo docker compose -p surfski up -d` (a
   plain `restart` doesn't reread the env file). This order matters: a server still running on the old
   key keeps writing old-key rows (every link or relink), and any it writes after step 4 stay on the old
   key. `docker compose exec` also takes the container's env, so the rotate command only sees the new
   key once the container was recreated. If you got the order wrong, restart and run step 4 again; it
   is idempotent and only touches rows that aren't on the current key yet.
4. Rotate: `sudo docker compose -p surfski exec app surfski admin rotate-token-key`. It re-encrypts
   every row in one SQLite write transaction and reports the counts. If any row can't be decrypted
   with the new or the old key, it changes nothing, lists the affected owner / alias pairs and exits 1
   (relink or `admin unlink` those, or supply the right old key, then run it again).
5. Remove `TOKEN_ENCRYPTION_KEY_OLD` and restart again.

Per-owner keys work the same way with `TOKEN_ENCRYPTION_KEYS_OLD=owner=oldkey,…`. Giving an existing
owner their own `TOKEN_ENCRYPTION_KEYS` entry is a rotation too: set
`TOKEN_ENCRYPTION_KEYS_OLD=owner=<the default key>` for it (an owner with a per-owner key never falls
back to the default key on its own). Removing an owner's entry: set `TOKEN_ENCRYPTION_KEYS_OLD` to
their former key.

**Backups after a rotation:** older backups still need the old key. Keep the old key with the backups
it protects until they expire, or take a fresh backup right after rotating.

**`STORAGE_ENCRYPTION_KEY`** (FastMCP's OAuth store under `DATA_DIR/oauth`: Claude's client
registrations and session tokens). Set `STORAGE_ENCRYPTION_KEY_OLD` to the previous key alongside the
new one and restart: existing entries stay readable and new ones are written with the new key. There
is no rewrite command, because that file store has no locking and a rewrite could race the running
server. When you finally remove `STORAGE_ENCRYPTION_KEY_OLD`, entries still under the old key read as
missing, so Claude users whose connector registration predates the rotation must reconnect the
connector (Settings → Connectors). Nothing else is lost: linked mailboxes are in SQLite.

## Configuration reference

| Variable | Required | Meaning |
|---|---|---|
| `BASE_URL` | yes | Public URL, e.g. `https://mcp.example.com`. Must be https unless it is localhost. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | yes | Web OAuth client |
| `ALLOWED_USERS` | one of these two | Comma-separated primary Google addresses allowed to use the server |
| `ALLOWED_DOMAINS` | one of these two | Comma-separated Google Workspace domains (e.g. `example.com`, no `@`) whose users may use the server. List the Workspace org's **primary** domain. A user matches only if the domain of their **primary** address equals it exactly (subdomains and alias domains never match) **and** Google's hosted-domain claim `hd` equals it too, with a verified email. So only accounts managed by that Workspace org get in: a personal Google account registered on a company address has no `hd` and is rejected by design (add it to `ALLOWED_USERS` if you really want it). Public mail providers (gmail.com, outlook.com, yahoo.com, icloud.com, …) are refused at startup: list those users in `ALLOWED_USERS` |
| `JWT_SIGNING_KEY` | yes | Signs FastMCP session tokens (≥32 chars) |
| `STORAGE_ENCRYPTION_KEY` | yes | Fernet key for the OAuth client store |
| `TOKEN_ENCRYPTION_KEY` | yes | Fernet key for stored Gmail refresh tokens |
| `STATE_SECRET` | yes | HMAC key for single-use linking state (≥32 chars) |
| `DATA_DIR` | no | Default `/var/lib/surfski`; `/data` in the container |
| `TOKEN_ENCRYPTION_KEYS` | no | Per-owner Fernet keys `owner=key,owner=key` |
| `TOKEN_ENCRYPTION_KEY_OLD` / `TOKEN_ENCRYPTION_KEYS_OLD` | no | Previous token key(s), accepted for decryption only during a [rotation](#rotating-encryption-keys) |
| `STORAGE_ENCRYPTION_KEY_OLD` | no | Previous OAuth store key, accepted for reading only during a [rotation](#rotating-encryption-keys) |
| `ALLOWED_CLIENT_REDIRECT_URIS` | no | MCP client redirect allowlist. Defaults to Claude's callbacks, plus localhost when `BASE_URL` is localhost |
| `RATE_LIMIT_PER_MINUTE` | no | Tool calls per owner per minute (default 60) |
| `SENDING_ENABLED` | no | `true` registers the send tools and `/send/*` pages (default `false`: drafts only) |
| `SEND_DAILY_CAP` | no | Sends per mailbox in a rolling 24 h, in `confirm` and `auto` (default 20) |
| `SEND_MAX_RECIPIENTS` | no | Unique to+cc+bcc recipients per message (default 10) |
| `CONFIRM_CHANNEL` | no | How `confirm` sends are approved: `auto` (default: in the MCP client via elicitation when it supports it, else the confirm link) or `link` (always the confirm link) |
| `ALLOWED_RECIPIENT_DOMAINS` | no | Comma-separated domains; if set, every recipient's domain must match one exactly |
| `ATTACHMENT_MAX_MB` | no | Largest attachment `get_attachment` will download (default 15, max 25) |
| `AUDIT_ON_DELETE` | no | What `delete_my_data` does with the caller's audit rows: `delete` (default) or `pseudonymize` (keep them under a keyed hash) |
| `TRIAGE_ENABLED` | no | `true` registers the triage tools (default `false`: no triage tools, and `gmail.modify` is never requested) |
| `TRIAGE_DAILY_CAP` | no | Triage changes (ids touched) per mailbox in a rolling 24 h (default 1000) |
| `METRICS_ENABLED` | no | `true` serves Prometheus metrics at `/metrics` (default `false`: the route doesn't exist). See [Metrics](#metrics) |
| `METRICS_TOKEN` | with metrics | Bearer token required on every `/metrics` request (≥32 chars; the server refuses to start without it when metrics are on) |
| `UNSUBSCRIBE_ALLOWED_PORTS` | no | Extra https ports the one-click unsubscribe POST may use (comma-separated; 443 is always allowed, default none) |
| `LOG_LEVEL`, `HOST`, `PORT` | no | Logging and bind address |

## Development

The runtime is **Python 3.14**: the Docker image and `.python-version` both use it. Python 3.12 and newer is supported for pip and uv installs, and CI tests 3.14 and 3.12.

```bash
uv sync
```

```bash
uv run pytest
```

The tests never contact Google. Gmail and the token endpoints are mocked, and the caller's
identity is injected.

For a local run, set `BASE_URL=http://localhost:8000` and add `http://localhost:8000/auth/callback`
and `/gmail/callback` to your OAuth client:

```bash
set -a; source ./local.env; set +a; uv run surfski
```

### Library notes

- Built on **fastmcp 4.x** (`fastmcp>=4.1,<5`) using `GoogleProvider`. Google doesn't support
  Dynamic Client Registration, so FastMCP runs an OAuth proxy that Claude registers against.
- OAuth client storage is `key_value.aio.stores.filetree.FileTreeStore` wrapped in
  `FernetEncryptionWrapper`. It's single-node, with no Redis.
- The MCP client redirect allowlist defaults to `https://claude.ai/api/mcp/auth_callback` and
  `https://claude.com/api/mcp/auth_callback`.
- Google reports `email_verified` either as the string `"true"` (tokeninfo) or as a boolean
  (userinfo), and both forms are handled.
- Mailbox linking talks to Google's token, revoke and profile endpoints directly with httpx, and
  uses PKCE (S256) with signed, single-use, 10-minute state.

## Security

- The container publishes only on `127.0.0.1`, runs as non-root uid 10001 with a read-only root
  filesystem, `cap_drop: ALL` and `no-new-privileges`, and uses its own network.
- **Docker-published ports bypass host firewalls like `ufw`.** Rely on your cloud firewall or
  security group: open 80/443 only.
- Every `accounts` query a tool makes is scoped to the caller; only the local `surfski admin` CLI reads
  across owners. Refresh tokens are Fernet-encrypted at rest.
  Access tokens live only in memory.
- Logs never contain tokens, auth codes or message bodies. Audit rows record the tool, alias and a
  short detail only.
- `get_attachment` downloads at most `ATTACHMENT_MAX_MB` (checked before download) and returns text
  only: text/CSV/JSON/XML/HTML, PDF (pypdf, first 200 pages, 15 s budget), DOCX/XLSX/PPTX (parsed from
  the zip with defusedxml; DTDs and entities refused; zip-bomb limits on entries, sizes and
  compression ratio). Other types return metadata only; binary is never passed through. Audit rows
  record message id, size and method, not the filename.
- `forward_message`, and drafts with `attachments`, hold the attachments in memory while the draft is
  built (up to the 20 MB limit, roughly 3× that at peak with the MIME encoding). Give the container
  ~150 MB of headroom per concurrent call.
- See [SECURITY.md](SECURITY.md) to report a vulnerability.

### Sending (opt-in)

The `gmail.compose` scope already lets an app send mail, so "drafts only" is enforced by this
server's code. Sending is off unless you opt in, and is built to resist prompt injection (an email
that tells Claude to forward something to an attacker):

- **Operator switch:** without `SENDING_ENABLED=true` the send tools and `/send/*` routes don't exist.
- **Per-mailbox policy**, shown by `list_accounts`: `off` (default), `confirm` (Claude prepares the
  draft and returns a one-time link; nothing is sent until you open it, sign in, review
  From/To/Cc/**Bcc**, subject, attachments and the start of the body, and press **Send**), or `auto`
  (sent directly, within the caps). MCP clients still ask you to approve each send tool call.
- **Confirming in the client (elicitation).** In `confirm` mode, if your MCP client supports
  [elicitation](https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation) (form
  mode), the server asks you directly in the client: From, To, Cc, **Bcc**, subject, attachment
  names and the first 500 characters of the body, with a single send/don't-send answer. There's no
  link for the model to leak or open. On accept the server rechecks the policy, the caps, the
  mailbox and the exact draft version (just like pressing **Send** on the link page) before sending;
  on decline or cancel it keeps the draft and returns `sent: false`. If the client doesn't support
  elicitation, the request fails or times out (5 minutes), or the connection uses the 2026-07-28
  protocol (which has no channel for server-initiated requests), it falls back to the confirm link
  below, **never** to sending. Client support varies and changes: check your client's MCP
  documentation. **Trust model:** the server can't verify that a human answered; it trusts the client
  to show the prompt to you and not let the model answer it. A client or agent SDK that
  auto-answers elicitations (or lets the model answer them) **bypasses the human entirely**. If you
  don't trust every client your users connect with, set `CONFIRM_CHANNEL=link`. The prompt flattens
  header values to one line, strips bidi and zero-width characters, fences the body excerpt between
  markers and repeats the server's recipient counts after it, but the subject and body are still
  written by whoever wrote the email: read the recipient rows, not the text.
- **Owner sign-in before any confirm or approval page.** Opening a link shows nothing about the
  email until you sign in with Google as the mailbox owner (`/send/auth/callback`, which you must
  register on your OAuth client). That sets a session cookie for `/send` pages only (HttpOnly,
  SameSite=Strict, Secure on https, 12 h, stored server-side). Send and Apply require that session
  for the same owner as the link, so **a leaked link alone can't send**. You sign in once per 12-hour session, not on every link.
- **Tool calls alone can't raise a policy.** `set_send_policy` lowers it immediately but, to raise it, returns
  a link that needs a Google sign-in from the last 10 minutes as the owner, then an **Apply** click.
- **Links** are HMAC-signed (key derived from `STATE_SECRET`, separate from linking), single-use,
  expire in 10 minutes, and are bound to the owner, alias, mailbox address and the exact draft
  version: if the draft changes after the link was made, it won't send. Opening a page (GET) never
  sends or changes anything; pages can't be framed and don't leak the link via Referer.
- **What this does not stop:** an AI agent that can drive *your own* signed-in browser could open a
  link and press Send while your session is valid (and Google re-auth may be a single click if
  you're already signed in to Google). Keep `confirm` for mailboxes where that matters and don't give
  browser-control tools to the same agent.
- **Caps** apply in `confirm` (re-checked when you press Send or accept in the client) and `auto`: daily sends per mailbox,
  recipients per message, optional recipient-domain allowlist.
- **Audit:** each send records alias, policy, recipient count and Gmail message id, never addresses
  or bodies.
- Relinking an alias to a different mailbox resets its policy to `off` and voids open links.

### Triage (opt-in)

The triage tools (mark read or unread, star, archive, move to Inbox, user labels, Trash) need Google's
`gmail.modify` scope, which normal linking never requests. Two switches have to be on:

- **Operator switch:** without `TRIAGE_ENABLED=true` the tools don't exist. The server then never asks
  Google for `gmail.modify`, even for a mailbox that granted it before.
- **Per mailbox:** `enable_triage(alias)` returns a Google link for that mailbox only. It is a full
  re-consent (`prompt=consent`, `include_granted_scopes=false`) asking for read + compose + modify, so the
  new token carries exactly those scopes. The human has to sign in to Google **as that mailbox** and
  approve. That out-of-band consent is the owner confirmation; a tool call alone can't turn triage on.
  The server checks that Google really granted `gmail.modify` and that the account that signed in is the
  linked mailbox. If either check fails, nothing changes. Like `link_account`, the consent link is only as safe as the
  browser it's opened in: an agent that drives a browser signed in to that Google account could click
  through the consent for `enable_triage` itself, the same exposure as `link_account`. `list_accounts` shows `triage: on|off`, and the
  scope and switch are rechecked before every triage call.
- **Turning it off:** `disable_triage(alias)` takes effect at once: the server stops using, and stops
  requesting, `gmail.modify` for that mailbox. The stored Google grant still includes it until you
  `relink_account(alias)`, which re-consents with read + compose only, or until you remove the app at
  <https://myaccount.google.com/permissions>. A relink without modify also turns triage off.

Guardrails:

- **Caps:** at most 50 ids per call (`messages.batchModify` for messages; one `threads.modify` per
  thread) and `TRIAGE_DAILY_CAP` changes per mailbox per 24 h. If a call fails partway through, the
  changes already made still count against the cap.
- **No permanent delete.** `trash` moves mail to Trash, where Gmail keeps it for 30 days, and `untrash`
  restores it. There is no `delete` or `batchDelete` tool, by design.
- **Labels:** `apply_label` / `remove_label` work only on your own labels, not system ones; reading,
  starring, archiving and trashing have their own tools. A label is created only with `create=true` or
  `create_label`. Names are NFC-normalized and capped at 225 characters, and refused if they contain
  control or invisible characters, have empty or space-padded `/` parts, or collide with system names
  (`INBOX`, `TRASH`, `CATEGORY_*`, …).
- Tool descriptions tell the model never to act on instructions found inside an email, and to confirm
  bulk changes with you first.
- **Audit:** each call records the action and a count (`messages=12`), never message or thread ids or
  label names.

### Metrics

With `METRICS_ENABLED=true`, `GET /metrics` returns the Prometheus text format. It is served on the
same port as everything else, which your reverse proxy makes public, so every request must carry
`Authorization: Bearer <METRICS_TOKEN>`: no header gets 401, a wrong one 403 (compared in constant
time). Generate the token with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. You
can also block `/metrics` at the proxy and scrape `127.0.0.1:38000` from the host.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: surfski
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/surfski_token   # contains METRICS_TOKEN
    static_configs:
      - targets: ["mcp.example.com"]
```

| Metric | Labels |
|---|---|
| `surfski_tool_calls_total` | `tool`, `outcome` (`ok`, `error`, `internal_error`) |
| `surfski_tool_duration_seconds` (histogram) | `tool` |
| `surfski_gmail_api_errors_total` | `status_class` (`400`, `401`, `403`, `404`, `429`, `4xx`, `5xx`, `refresh`, `storage`, `other`) |
| `surfski_sends_total` | `policy` (`auto`, `confirm`), `outcome` (`sent`, `failed`, `declined`, `link_issued`) |
| `surfski_triage_modifications_total` | none (messages/threads changed) |
| `surfski_attachment_extractions_total` | `method` (`text`, `html`, `pdf`, `docx`, `xlsx`, `pptx`, `none`), `outcome` (`ok`, `metadata_only`, `error`) |
| `surfski_unsubscribe_total` | `method` (`one_click`, `mailto`, `manual`, `none`), `outcome` |
| `surfski_rate_limit_rejections_total` | none |
| `surfski_linked_mailboxes`, `surfski_owners` (gauges) | none (counted from SQLite at scrape time) |
| `surfski_build_info`, `surfski_process_start_time_seconds`, `surfski_uptime_seconds` | `version` on build info |

**No personal data:** label values come from fixed sets (the server's own tool names and the values
above); anything else is recorded as `other`. No owner, alias, address, query, message id, label name
or URL ever appears, and cardinality is bounded.

### Unsubscribe safety

The one-click POST (RFC 8058) is the only request this server makes to a host named in an email,
so it is locked down: https only, port 443 (unless `UNSUBSCRIBE_ALLOWED_PORTS` adds one), and every
address the host resolves to must be public. Loopback, private, link-local (including the
`169.254.169.254` metadata address), CGNAT, multicast and reserved ranges are refused, also after
each redirect. The connection is pinned to the address that was checked, so DNS can't change
between the check and the request, while TLS is still verified against the hostname. At most 3
redirects, 10 s per operation and 20 s overall, the first 64 KB of the response only, no cookies,
auth, proxies or environment settings, and a fixed `User-Agent`. The body is always exactly
`List-Unsubscribe=One-Click`, so the sender learns nothing beyond "this unsubscribe link was
used". The audit log records the method and outcome only, never the URL (it often carries a token)
or the address.

## Your data

What the server stores per Claude user (the "owner"): linked mailboxes (alias, address, encrypted
refresh token, scopes, timestamps), address labels, default From, send policy, pending link and
confirmation nonces, send counts for the daily cap, `/send` browser sessions, and audit rows (tool,
alias, short detail, never bodies or email addresses). Message content is never stored.

- **`export_my_data`** returns all of it except tokens.
- **`delete_my_data(confirm="DELETE")`** erases every row above for the caller in one transaction,
  clears their in-memory caches, then revokes each mailbox's token at Google (best effort; the result
  is reported per alias, and a failed one can be removed at https://myaccount.google.com/permissions).
  Audit rows are deleted by default; set `AUDIT_ON_DELETE=pseudonymize` to keep them instead,
  with the owner replaced by a keyed hash, the alias blanked and any email address in the detail
  replaced by `<email>` (details are written without addresses in the first place). Other users'
  data is untouched.
- The operator can do the same for a user from the host with
  `surfski admin purge-owner --owner <address> --yes` (see [Administration](#administration-local-cli)).
- Not covered: Claude's MCP session tokens for this server (in the encrypted OAuth store under
  `DATA_DIR/oauth`) expire on their own; remove the connector in Claude to end them at once.
  Backups you made earlier still contain the old data.
- On the sending pages, **Sign out** ends the browser session; sessions of users removed from
  `ALLOWED_USERS` (or whose domain leaves `ALLOWED_DOMAINS`) stop working at once and are deleted at startup.

## Hosting this for the public

If you want to run this as a service for people outside your own team:

- you need Google **OAuth app verification** for restricted Gmail scopes, plus a **CASA security
  assessment** by a Google-approved lab, renewed every year;
- you need your own privacy policy and terms covering mailbox data, and you must comply with
  Google's API Services User Data Policy (Limited Use);
- you need multi-tenant features such as self-signup, data deletion and billing. These are
  tracked in [ROADMAP.md](ROADMAP.md).

One exception: Google Workspace organizations can register their **own Internal OAuth client**
and use it with a hosted instance. Internal apps don't need verification. See
[Deployment models](ROADMAP.md#deployment-models).

## License

[MIT](LICENSE)
