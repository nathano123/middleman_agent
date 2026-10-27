# Agent Access Broker (v0 prototype)

A local gate between an AI agent and a user's Gmail and Google Calendar. It is a six-week
validation prototype, not a product. Licensed Apache-2.0.

**Status (Milestone 2, in progress):** a real stdio MCP server (six tools) in front of a real
Gmail + Calendar backend, with agent identity from the launch argument, an approval queue with
a pending-and-retry fallback, and hash checks between what was approved and what is sent.
Tested offline against replayed Google HTTP responses; **the live run on a Google test account
has not been done yet** (see LIVE_RUN.md). Approvals are answered from the command line, which
is development-only (see below and THREAT_MODEL.md).

Read first: [THREAT_MODEL.md](THREAT_MODEL.md) (what this does and does not protect),
[SETUP.md](SETUP.md) (Claude Desktop / Claude Code), [LIVE_RUN.md](LIVE_RUN.md).

## What it does

Every tool call goes through `Gate.handle(session, tool, args)`. Nothing else in the package
calls the mail/calendar backend (a test enforces this).

1. **Rules.** A deny-by-default evaluator reads one YAML profile
   (`broker/rules/profiles/*.yaml`) and returns `allow`, `allow_redacted`, `ask` or `deny`.
   Anything not matched is denied; if several rules match, the strictest wins. No AI model is
   involved in the decision.
2. **Taint.** An agent becomes tainted when it sees content it cannot trust: a message (read,
   or as a search snippet) from an address that is not a known contact or one of your own
   addresses; from a known contact whose authentication failed; from a known contact whose
   Reply-To points to an outside address; or an event described by an outside organizer.
   Taint is kept **per agent**, not per connection, so reconnecting does not clear it. It
   expires after 24 quiet hours or when you run `broker taint clear`. Profiles make tainted
   sends and calendar writes ask (or deny).
3. **Approval.** For `ask`, the prompt is built only from the agent's own arguments and
   session counters: real recipients (outside and new ones flagged), subject, the first 200
   characters of the body, total length with a `[+N more characters not shown]` marker, a
   short hash of the full body, and `approval #N today`. If the agent is tainted and the
   body is over 2,000 characters, or after 10 prompts by the same agent in one day (counted
   per agent, so reconnecting does not reset it), a plain Approve is
   refused until the full body is opened. No answer, deny or timeout means no action.
4. **Backend.** Currently `FakeBackend` (in-memory). The Google backend comes in Milestone 2.
5. **Minimizer.** Returns only the fields each tool needs. Bodies are masked for emails,
   phone numbers and long digit runs under `allow_redacted`.
6. **Activity log.** Append-only SQLite, one row per call, metadata only (ids, counts,
   recipient domains, decision, approval outcome, auth result). The logger refuses content.
7. **Modes.** `enforce` (default) or `watch` (trial days 1-3: log what would have happened,
   then run the call). Set only in the config file; no tool call can change it.
8. **Counters.** `counters.json` holds per-day counts only; `broker report` prints the weekly
   summary a tester sends back.

The six v0 tools are `search_mail`, `read_message`, `list_events`, `draft_reply`,
`send_mail`, `create_event`. Forward, delete, share and attachments do not exist and are
always denied.

Profiles: `cautious` (asks more, denies tainted sends), `working` (default), `autonomous`
(asks less; never lets a tainted agent send or create events without approval).

## Approvals: phone (Telegram) or terminal (development only)

With `phone: telegram` in the config (after `broker phone setup`), each approval arrives as a
Telegram message from your own bot with **Approve** and **Deny** buttons. The message holds
the `minimal` details: recipients with OUTSIDE/NEW flags, subject, body length and short hash,
and the reason; never the body. A tap counts only from your Telegram account, once, for that
exact action, within 5 minutes. Telegram sees these messages (bot chats are not end-to-end
encrypted).

> **This is not a defense against an agent with a shell.** Such an agent runs as you and can
> read the bot token from the keychain, edit the config, or write a decision into
> `approvals.db`. The phone protects against an agent that only has this MCP server (for
> example Claude Desktop). See THREAT_MODEL.md.

> **WARNING - `broker approvals` is for development only.** Any program running as you,
> including an AI agent with a shell (for example Claude Code), can run
> `broker approvals approve <id>` and approve its own requests. While a phone is configured,
> `approve` and `deny` refuse unless the config sets `dev_cli_approvals: true`.

A tool call that needs approval waits about 45 seconds (polling the phone, if configured).
If nobody has answered by then, it returns "NOT DONE YET" (`status: pending`) with an id, and the agent repeats the identical call to get the
answer (Claude Desktop is reported to cancel tool calls after about 60 seconds). Requests
expire after 5 minutes. `broker approvals list | show <id> | approve <id> | deny <id>`;
`show` counts as opening the full body.

## Prompt budget (simulation)

`broker simulate --profile all --days 7` replays a generated workday (60 mails, 6 events, a
scripted assistant doing triage, 5 drafts, 2 sends, 2 events) through the real gate.
Measured: working 4.0 prompts/day, autonomous 4.0, cautious 6.0 (and cautious blocks both
sends every day). In this simulated day taint is on every day, because the morning search
always meets an unknown sender. The simulation is one scripted shape, not real usage.

## What "tamper-evident" means here

When the log is opened with the OS keychain (`KeyringKeyStore`), each row carries an
HMAC-SHA-256 over its fields and the previous row's value, keyed with a random key kept in
the keychain, and the newest row's id and MAC are also kept in the keychain.

- **Detected:** editing any field of any row; deleting or reordering rows; rewriting the
  whole chain without the key; deleting rows from the end.
- **Not detected:** anything done by someone who can read your keychain (same user account,
  unlocked session): they can recompute the chain and move the anchor. Deleting the whole log
  file is obvious but not "detected" by `verify`. A crash between writing a row and updating
  the anchor makes the newest row look tampered.
- Without a keychain key (`broker verify-log` warns), the log is a plain SHA-256 chain: it
  catches edits, deletions and reordering, but not a rewritten chain or rows cut from the end.

## What it does not cover

This prototype does **not** prevent prompt injection, and the tests do not show that it is
secure. They show that specific seeded attacks, against a fake backend and a scripted
approver, end in a prompt or a deny rather than a silent send. Known gaps:

- **Known contacts are trusted** unless their mail fails authentication or carries an
  outside Reply-To. A compromised real account passes. `auth_result: unknown` is trusted
  (and logged); real results only arrive with the Gmail connector.
- **Taint is almost always on.** Broad searches and a normal morning triage meet unknown
  senders, so most real sessions will be tainted. The prompt budget above already includes
  this.
- **The agent still sees injected text.** Hidden HTML, comments and encoded payloads are
  passed through (bodies only have personal data masked). The gate limits what the agent
  can *do* afterwards; it does not clean what the agent *reads*.
- **Approval fatigue.** Every send asks in the working profile. The counters, hash and
  full-view rule make autopilot approvals harder, not impossible.
- **Watch mode runs everything,** including sends the rules would have denied. It is meant
  for the first trial days only.
- **Draft replies are allowed while tainted** (except in cautious). A draft can hold copied
  data that the user later sends.
- **Clean sessions in the autonomous profile** may send to anyone without asking.
- **Agent identity** comes from the config, by MCP client name. Unregistered clients share
  one identity; a registered one cannot pick another identity, but the client name itself
  will be self-reported by the MCP client (M2).
- **Masking is regex-only.** Names, street addresses and many ID formats are not masked.
- **Agents with a shell are not contained.** An agent that can run commands as you can read
  the Google or Telegram token from the keychain, call Google directly, edit the config or
  `approvals.db`, or (without a phone, or with `dev_cli_approvals`) run
  `broker approvals approve`. THREAT_MODEL.md lists each bypass.
- **Phone approvals cannot open a full body.** At the `minimal` level a request that needs
  the full body (tainted and long, or after 10 prompts a day) can only be denied on the phone.
- **Search snippets are not masked.** `read_message` masks personal data in body and snippet,
  but `search_mail` returns the first ~90 characters unmasked.
- **Bulk mail is reported, not ruled on.** `bulk` is returned and logged; rules decide before
  a message is read, so it is not a rule condition.
- **Claude Desktop's tool timeout is unconfirmed** (user reports say ~60 s). Approvals return
  `pending` after 45 s and rely on the agent repeating the call.
- **One gate call at a time per agent process.** A call waiting for approval holds the next
  one for up to 45 s.
- **Single user.** No multi-user setup.

## Develop

```bash
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run pyright
uv run broker profiles
uv run broker simulate --profile all --days 7
uv run broker verify-log ~/.agent-broker/audit.db
uv run broker taint clear
uv run broker report
```

Config: copy `broker.example.yaml` to `~/.agent-broker/config.yaml`. No network calls are made
by the broker or its tests (the tests also never touch the real keychain). See `DECISIONS.md`
for every choice, the date, and what was rejected.
