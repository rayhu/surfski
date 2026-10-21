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
`search_all_accounts`, `get_thread`, `get_message`, `list_labels`, `create_draft`, `list_drafts`, `get_draft`,
`update_draft`, `delete_draft`, `list_addresses`, `set_address_label`, `set_default_from`, `forward_message`,
`export_my_data`, `delete_my_data`.
With `SENDING_ENABLED=true` also: `send_draft`, `send_email`, `set_send_policy` (and `forward_message(send=true)`).

**Send from an alias.** `create_draft` and `update_draft` take `from_address` (a verified "Send mail as"
address or a label set with `set_address_label`) and `include_signature`. Replies default to the address
the original was sent to; new drafts use `set_default_from`, then Gmail's default. New addresses are added in
Gmail → Settings → Accounts → Send mail as.

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
| A. MCP login | *which Claude user* is calling, checked against `ALLOWED_USERS` | `openid`, `userinfo.email` | `https://<host>/auth/callback` |
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
   `.../auth/gmail.compose`.
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
`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and `ALLOWED_USERS`. The server **refuses to start**
if any secret is missing or malformed.

> **Aliases:** Google sign-in reports a user's **primary** address. If your Workspace uses alias
> domains, put the primary addresses in `ALLOWED_USERS`. Linking an alias address links the
> primary mailbox behind it.

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

Back up the `surfski_surfski-data` volume, for example with a nightly `tar` from a throwaway
container. **The backup is useless without `TOKEN_ENCRYPTION_KEY` and `STORAGE_ENCRYPTION_KEY`.
Keep the env file in a separate place, such as a password manager, never in the same backup.**
If you lose the keys, users simply relink their mailboxes.

## Configuration reference

| Variable | Required | Meaning |
|---|---|---|
| `BASE_URL` | yes | Public URL, e.g. `https://mcp.example.com`. Must be https unless it is localhost. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | yes | Web OAuth client |
| `ALLOWED_USERS` | yes | Comma-separated primary Google addresses allowed to use the server |
| `JWT_SIGNING_KEY` | yes | Signs FastMCP session tokens (≥32 chars) |
| `STORAGE_ENCRYPTION_KEY` | yes | Fernet key for the OAuth client store |
| `TOKEN_ENCRYPTION_KEY` | yes | Fernet key for stored Gmail refresh tokens |
| `STATE_SECRET` | yes | HMAC key for single-use linking state (≥32 chars) |
| `DATA_DIR` | no | Default `/var/lib/surfski`; `/data` in the container |
| `TOKEN_ENCRYPTION_KEYS` | no | Per-owner Fernet keys `owner=key,owner=key` |
| `ALLOWED_CLIENT_REDIRECT_URIS` | no | MCP client redirect allowlist. Defaults to Claude's callbacks, plus localhost when `BASE_URL` is localhost |
| `RATE_LIMIT_PER_MINUTE` | no | Tool calls per owner per minute (default 60) |
| `SENDING_ENABLED` | no | `true` registers the send tools and `/send/*` pages (default `false`: drafts only) |
| `SEND_DAILY_CAP` | no | Sends per mailbox in a rolling 24 h, in `confirm` and `auto` (default 20) |
| `SEND_MAX_RECIPIENTS` | no | Unique to+cc+bcc recipients per message (default 10) |
| `ALLOWED_RECIPIENT_DOMAINS` | no | Comma-separated domains; if set, every recipient's domain must match one exactly |
| `AUDIT_ON_DELETE` | no | What `delete_my_data` does with the caller's audit rows: `delete` (default) or `pseudonymize` (keep them under a keyed hash) |
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
- Every `accounts` query is scoped to the caller. Refresh tokens are Fernet-encrypted at rest.
  Access tokens live only in memory.
- Logs never contain tokens, auth codes or message bodies. Audit rows record the tool, alias and a
  short detail only.
- `forward_message` holds the original's attachments in memory while it builds the draft (up to the
  20 MB limit, roughly 3× that at peak with the MIME encoding), so give the container ~150 MB of headroom
  per concurrent forward.
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
  browser-control tools to the same agent. Confirming inside the MCP client (elicitation) is planned.
- **Caps** apply in `confirm` (re-checked when you press Send) and `auto`: daily sends per mailbox,
  recipients per message, optional recipient-domain allowlist.
- **Audit:** each send records alias, policy, recipient count and Gmail message id, never addresses
  or bodies.
- Relinking an alias to a different mailbox resets its policy to `off` and voids open links.

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
- Not covered: Claude's MCP session tokens for this server (in the encrypted OAuth store under
  `DATA_DIR/oauth`) expire on their own; remove the connector in Claude to end them at once.
  Backups you made earlier still contain the old data.
- On the sending pages, **Sign out** ends the browser session; sessions of users removed from
  `ALLOWED_USERS` stop working at once and are deleted at startup.

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
