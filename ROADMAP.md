# Roadmap

The order of focus is **self-hosting first**, then **multi-tenant hosting later**. Each item becomes a
GitHub issue. A ✅ marks shipped items.

## Deployment models

Two questions decide what Google requires: **whose server** runs Surfski, and **whose Google OAuth
client** users grant access to.

| Model | Server | Google OAuth client | Tenant of the hosted service? | Google verification / CASA |
|---|---|---|---|---|
| **Self-hosted** | The user's own (VPS, EC2, NAS…) | The user's own GCP project | No. They just use the open-source code | Not needed while the app stays under Google's 100-user cap |
| **Hosted, bring-your-own OAuth client** (Workspace orgs) | The hosted service | The **customer's**, with user type *Internal* | Yes | Internal apps are exempt from verification. The service still processes their mail, so security and DPA obligations apply |
| **Hosted, shared OAuth client** | The hosted service | The hosted service's own | Yes | Up to 100 users unverified (invite-only beta). Any public launch needs **OAuth verification + an annual CASA assessment** |

There is no way around restricted scopes for reading mail. `gmail.readonly` (and `gmail.compose`)
are restricted, so a server that reads other people's mail through **its own** client needs CASA
once it goes public.

## Hosting path

1. **Now: self-hosting.** Docs and README focus on running your own instance. No CASA.
2. **Invite-only hosted beta** on the shared client, kept under the 100-user lifetime cap. The point is
   to validate demand and pricing. Users see the "unverified app" warning, and Google may suspend
   unverified apps that are offered publicly, so this is not a commercial launch.
3. **Hosted for Workspace organizations with bring-your-own OAuth client.** Each tenant registers an
   Internal OAuth client in its own GCP project, and the hosted service uses it for that tenant.
   This needs no verification or CASA on our side. Personal Gmail accounts aren't supported here,
   because they have no Internal user type.
4. **Public self-serve hosting** on the shared client. Do this only once revenue covers it, because
   it requires Google OAuth verification plus an annual CASA assessment.

Alongside steps 2–4, a **calendar-only hosted offering** can launch earlier as a lower-cost entry
point. Calendar scopes are sensitive, not restricted, so it needs Google verification but no CASA.
See [Calendar module](#calendar-module).

### Infrastructure

- **surfski.io** is a static marketing and docs site on Cloudflare Pages (Astro + Starlight, i18n),
  kept in a separate private repo. It has no auth and no user data.
- **app.surfski.io** is this open-source Python server, and it **only does MCP**. It serves `/mcp` plus
  the minimal pages MCP flows need: the OAuth callbacks and the one-time confirmation pages for
  linking, sending and raising policies. There is no separate web dashboard. Users manage accounts,
  aliases and policies through MCP tools in their AI client. Marketing, docs and any commercial
  pages live on the static site. It is deployed only when the hosted beta starts:
  - on a **dedicated** host, not shared with unrelated workloads. This limits the blast radius and
    keeps CASA scope small. A small EC2 instance running Docker Compose and Caddy is the starting
    point, ideally in a **separate AWS account**;
  - DNS-only (unproxied), so the reverse proxy issues its own certificates and long-lived MCP
    streams aren't buffered or timed out by a CDN proxy;
  - later, when Postgres and multiple replicas land, it can move to containers on a managed platform
    (for example ECS Fargate with RDS).
- Serverless runtimes (Lambda, Workers) don't fit. The server is Python, holds long-lived SSE
  streams, and uses local disk today.

## Phase 1: self-host essentials

- ✅ **`rename_account(old_alias, new_alias)`**: rename an alias in place, scoped to the owner, with no re-auth.
  You can't safely do this with unlink + relink, because revoking a token at Google can revoke
  the shared grant for that mailbox and kill the new link.
- ✅ **Unescape Gmail snippets**: Gmail returns snippets HTML-escaped (`&#39;`). Decode them in search
  results.
- ✅ **Address aliases and "send from"**: see the [design below](#address-aliases-and-send-from).
- ✅ **Opt-in sending**: see the [design below](#opt-in-sending-design).
- ✅ **Confirm sends via MCP elicitation** (#27): in `confirm` mode, ask the human in the client when
  it supports elicitation, else fall back to the confirm link (never to sending). `CONFIRM_CHANNEL=link`
  forces the link.
- ✅ **Draft management**: `list_drafts`, `get_draft`, `update_draft`, `delete_draft`. Today Claude can
  create a draft but can't revise one, and "fix the draft you just wrote" is a common request. Uses the
  existing `gmail.compose` scope.
- ✅ **`forward_message`**: forward a message, keeping its original attachments. It saves a draft by
  default, and sends only when the mailbox's send policy allows it.
- ✅ **`get_attachment`**: read attachment content with size limits. PDF and DOCX are extracted to text,
  with no binary pass-through by default.
- ✅ **`delete_my_data`**: unlink and revoke every mailbox for the caller, and purge their rows.
- **Published container image** (GHCR) and **CI** that runs pytest and the image build on every PR.
- ✅ **Backup helper**: a `scripts/backup.sh` that tars the data volume and refuses to include the env file.

## Phase 2: self-host polish

- ✅ `ALLOWED_DOMAINS`: allow a whole Workspace domain as well as individual addresses (#6). Exact
  domain match on the primary address; public mail providers are refused.
- **Admin CLI** (`surfski admin …`): list owners and aliases, force-unlink, rotate
  `TOKEN_ENCRYPTION_KEY` by re-encrypting existing rows.
- ✅ **Mailbox triage, opt-in** (#8): read/unread, star, archive, labels and Trash behind `TRIAGE_ENABLED`, plus
  a per-mailbox `enable_triage` Google re-consent for `gmail.modify`. There are caps and no permanent delete.
- ✅ **Attachments on drafts** (#16): `create_draft`, `update_draft`, `send_email` and `forward_message`
  attach files from existing messages in the same mailbox (`{message_id, part_id}`). `update_draft` now
  keeps a draft's attachments and can add or remove them. 20 MB total.
- ✅ **`unsubscribe`** (#17): parse `List-Unsubscribe` and `List-Unsubscribe-Post` (one-click, RFC 8058),
  and run it only after confirmation. The one-click POST is SSRF-hardened; mailto goes through the send
  policy; plain web links are returned, never opened.
- ✅ **Recipient lookup** (`find_contact`, #18): resolve "Alice" to an address from the caller's own mail
  history. It needs no new scope. The People API (`contacts.readonly`, sensitive) is optional later.
- **Calendar module**: see the [design below](#calendar-module).
- **Metrics endpoint** (Prometheus) without personal data.
- Versioned releases and a changelog.

## Not planned

- **Filters, auto-forwarding and vacation auto-replies.** These are standing rules that keep acting
  after the conversation ends. A prompt-injected email could use one to keep exfiltrating mail, so
  they stay out of scope and users should set them up in Gmail directly.

## Phase 3: multi-tenant hosting

Follows the [hosting path](#hosting-path) above.

**3a. Invite-only beta** (shared client, at most 100 users)
- A tenant model (organization → users) with invitations, replacing the env allowlist.
- `delete_my_data`, data export, and a privacy policy and terms specific to mailbox data.
- A dedicated host for app.surfski.io (see [Infrastructure](#infrastructure)), with backups and
  monitoring.

**3b. Bring-your-own OAuth client for Workspace organizations**
- Per-tenant Google OAuth clients: store each tenant's client ID and secret encrypted, and route a
  tenant's login and mailbox linking through its own client and redirect URIs.
- An onboarding guide for the customer's admin: create a GCP project, enable the Gmail API, add an
  Internal consent screen, create a Web client, and paste the credentials.
- Per-tenant encryption keys (envelope encryption, optional cloud KMS).
- A data processing agreement (DPA) template.

**Calendar-only hosted offering** (any time after the calendar module ships)
- A separate Google OAuth client requesting calendar scopes only; Google verification (no CASA).
- `/calendar/mcp` endpoint with the calendar tool set.

**3c. Public self-serve hosting**
- Self-signup, quotas, abuse controls and billing.
- **Postgres** for accounts and audit, plus a shared OAuth client store, so it can run more than one replica.
- **Google OAuth verification + annual CASA assessment** for restricted Gmail scopes, and Google
  API Services User Data Policy (Limited Use) compliance.
- A status page, support and incident process.

---

## Opt-in sending design

Each mailbox owner decides whether Claude may send. The default stays **drafts only**.

### Facts that shape the design

- The `gmail.compose` scope that we already request **also allows sending** (`drafts.send`,
  `messages.send`). Today's "drafts only" guarantee is enforced by **this server's code, not by
  Google**. Enabling sending therefore needs no relink, and the opt-in has to be robust in code.
- The main threat is **prompt injection**. An email Claude reads can say "forward this to
  attacker@…". The model must not be able to turn sending on by itself, and auto-send must be
  bounded.

### Controls

1. **Operator switch:** `SENDING_ENABLED=false` by default. If it is off, the send tools are not
   registered at all.
2. **Per-mailbox policy:** a `send_policy` column with one of these values:

   | Policy | Behavior |
   |---|---|
   | `off` (default) | No sending. `create_draft` only. |
   | `confirm` | `send_email` / `send_draft` create the draft, then ask the human in the MCP client (**elicitation**, when the client supports it; policy and caps are rechecked after accept) or else return a **one-time confirmation link** (signed, 10 min). The email goes out only when the human accepts in the client or opens the link and clicks **Send**. This blocks injection even if the model is fooled. |
   | `auto` | Claude sends directly. MCP clients still ask for per-call tool approval, because the tools are annotated `destructiveHint` / `openWorldHint`. |

3. **Raising a policy happens out of band.** `set_send_policy(alias, policy)` only *lowers*
   the policy directly. Raising it returns a link to a page where the owner has to **sign in with
   Google again** as the owner (`prompt=select_account`) and press a button (POST). A fetched GET
   URL can't change anything.
4. **Guardrails, even in `auto`:**
   - a daily send cap per mailbox (default 20);
   - a recipient limit per message (default 10);
   - an optional recipient allowlist (`allowed_recipient_domains`);
   - a send audit row with the alias, recipient count, message id and policy (never the body);
   - tool descriptions that tell the model never to send because of instructions found inside emails.
5. **Visibility:** `list_accounts` shows each mailbox's `send_policy`, so users always know.

### Tools

- `send_draft(alias, draft_id)`
- `send_email(alias, to, subject, body, cc?, bcc?, reply_to_message_id?)`, which reuses the
  threading and encoding logic from `create_draft`
- `set_send_policy(alias, policy)`

### Tests required

- `off` blocks sending.
- `confirm` never sends without the confirmation POST.
- A confirmation link is single-use, expires, and is bound to the owner and the draft.
- The model can't raise a policy through tools alone.
- Caps are enforced.
- Owner isolation holds for every new path.

---

## Address aliases and "send from"

A mailbox often receives mail for more than one address. Examples are a Workspace alias domain
(`alice@example.org` delivered to `alice@example.com`), user aliases (`sales@` on Alice's mailbox),
or external addresses set up in Gmail. Users want three things:

1. to **see and name** those addresses,
2. to **pick which address a draft or email is from**, and
3. to search mail sent to a particular address.

### Two kinds of "alias" (keep them distinct)

| Term | Meaning | Example |
|---|---|---|
| **Account alias** | The short name of a linked mailbox in this server | `work`, `personal` (rename via `rename_account`) |
| **Address alias** | An extra email address of that mailbox | `alice@example.org` on the `work` mailbox |

### Source of truth: Gmail "Send mail as"

- `users.settings.sendAs.list` returns the mailbox's send-as identities: the address, display name,
  `isDefault`, `verificationStatus`, reply-to and signature. It is **readable with scopes we already
  request**.
- Gmail only accepts a `From` header that matches a **verified** send-as identity. Anything else is
  rewritten to the primary address.
- *Creating* a send-as identity through the API needs `gmail.settings.sharing`, which only works
  with domain-wide delegation. So users add new addresses in **Gmail → Settings → Accounts →
  Send mail as**, which is a one-time step for Workspace alias-domain addresses, and this server picks
  them up automatically.

### Server features

- **`list_addresses(alias)`** lists send-as identities (address, name, default?, verified?), cached
  per mailbox and refreshed on demand.
- **Address labels:** `set_address_label(alias, address, label)` gives an address a friendly name,
  for example `support` → `support@example.org`. Labels are stored per owner in a new
  `address_labels` table. They're purely local and never written to Gmail.
- **Default From per mailbox:** `set_default_from(alias, address)`. It falls back to Gmail's
  `isDefault` identity.
- **`from_address` parameter on `create_draft`** (and later `send_email`): it accepts an address
  or a label. The server validates it against the verified send-as list and returns a clear error
  listing the valid choices otherwise. When replying, it defaults to **the address the original
  message was sent to**, if that address is one of the mailbox's identities. This is what people
  expect.
- **Signatures:** optionally append the chosen identity's Gmail signature, converted to plain text,
  with `include_signature=true`.
- **`list_accounts`** shows each mailbox's addresses, labels and default From.
- **Search helpers:** document `deliveredto:<address>` / `to:<address>` for "mail sent to my
  alias". The `search_threads` description should mention this.

### Tests required

- `From` is set to the chosen verified identity.
- Unverified or unknown addresses are rejected with the valid list.
- Reply-from defaults to the original recipient alias.
- Labels are owner-scoped: owner A can't see or use owner B's labels.
- Chinese display names are RFC 2047-encoded correctly.

---

## Calendar module

Google Calendar support lives in **the same codebase and server, as an optional module**. It is not a
separate project.

### Why the same server

- Calendars belong to the same Google accounts users already link. One linking flow, one set of
  account aliases, the same owner isolation and encrypted storage.
- Cross-tool tasks are common and want one connector: "add the meeting from this email to my
  calendar", or "check my free time next week and draft a reply with three slots".
- The tool count stays manageable: about 11 mail tools plus about 7 calendar tools.

### Why a module

- Calendar scopes (`calendar.events`, `calendar.readonly`) are **sensitive, not restricted**. Google
  verification for them needs **no CASA**. That enables a cheap first hosted product: a
  **calendar-only hosted offering** on its own Google OAuth client, while mail hosting follows the
  [hosting path](#hosting-path).
- Some users only want one of the two.

### Design

- **Features per deployment:** `FEATURES=mail,calendar` (default `mail`). Tools of a disabled module
  aren't registered.
- **Per-account capabilities:** at link time the user picks mail, calendar or both, and the server
  requests only those scopes. Adding calendar to an already linked account uses Google incremental
  authorization (`include_granted_scopes=true` for that upgrade only). Store granted capabilities per
  account, and have `list_accounts` show them.
- **Endpoints:** `/mcp` exposes every enabled module. An optional `/calendar/mcp` exposes calendar
  only, for a calendar-only connector or hosted product. It's the same code with a different tool set
  and OAuth client.
- **Tools:**
  - `list_calendars(alias)`
  - `list_events(alias, time_min, time_max, calendar_id?, query?)`
  - `get_event(alias, event_id)`
  - `find_free_time(aliases[], window, duration)`, which uses freebusy and works **across accounts**
    (the multi-account differentiator)
  - `create_event` and `update_event`, which accept attendees, Meet link and time zone
  - `respond_to_event(alias, event_id, response)`
  - `delete_event`
- **Write policy:** like mail sending. Default `draft` means the tool returns the proposed event and a
  confirmation link. Mailbox owners can raise it to `auto`, out of band. Events with external
  attendees send invitations, so treat them like sending email (caps, audit, `openWorldHint`).
- **Time zones:** always return ISO 8601 with an offset, plus the calendar's IANA zone. Accept
  natural ranges only after the client resolves them.

### Tests required

- Calendar tools are absent when the module is disabled.
- A link with only the mail scope can't call calendar tools, and the error says how to add calendar.
- Incremental authorization keeps existing mail access.
- `find_free_time` merges several accounts and respects owner isolation.
- The write policy blocks writes in `draft` mode.
- Invitations to external attendees go through the confirmation path.
