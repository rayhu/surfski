# Roadmap

The order of focus is **self-hosting first**, then **multi-tenant hosting later**. Each item becomes a
GitHub issue. A ✅ marks shipped items.

## Phase 1: self-host essentials

- ✅ **`rename_account(old_alias, new_alias)`**: rename an alias in place, scoped to the owner, with no re-auth.
  You can't safely do this with unlink + relink, because revoking a token at Google can revoke
  the shared grant for that mailbox and kill the new link.
- ✅ **Unescape Gmail snippets**: Gmail returns snippets HTML-escaped (`&#39;`). Decode them in search
  results.
- **Address aliases and "send from"**: see the [design below](#address-aliases-and-send-from).
- **Opt-in sending**: see the [design below](#opt-in-sending-design).
- **`delete_my_data`**: unlink and revoke every mailbox for the caller, and purge their rows.
- **Published container image** (GHCR) and **CI** that runs pytest and the image build on every PR.
- **Backup helper**: a `scripts/backup.sh` that tars the data volume and refuses to include the env file.

## Phase 2: self-host polish

- `ALLOWED_DOMAINS`: allow a whole Workspace domain as well as individual addresses.
- **Admin CLI** (`bonobo-mcp admin …`): list owners and aliases, force-unlink, rotate
  `TOKEN_ENCRYPTION_KEY` by re-encrypting existing rows.
- **Labels and archive** (needs `gmail.modify`). This would be opt-in, like sending.
- **Attachment download** with size limits, text extraction for PDFs and docs, and no binary pass-through by default.
- **Metrics endpoint** (Prometheus) without personal data.
- Versioned releases and a changelog.

## Phase 3: multi-tenant hosting

- A tenant model (organization → users) with self-signup and invitations, replacing the env allowlist.
- Per-tenant encryption keys (envelope encryption, optional cloud KMS).
- **Postgres** for accounts and audit, plus a shared OAuth client store, so it can run more than one replica.
- Quotas, abuse controls, billing.
- Data export and deletion, a privacy policy and terms specific to mailbox data, and Google API
  Services User Data Policy (Limited Use) compliance.
- **Google OAuth verification + annual CASA assessment** for restricted Gmail scopes. You need this
  before any public offering, because unverified apps are capped at 100 users over their lifetime.
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
   | `confirm` | `send_email` / `send_draft` create the draft and return a **one-time confirmation link** (signed, 10 min). The email goes out only when the human opens the link and clicks **Send**. This blocks injection even if the model is fooled. |
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
