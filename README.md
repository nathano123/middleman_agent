# Agent Access Broker (v0 prototype)

A local gate between an AI agent and a user's Gmail and Google Calendar. It is a six-week
validation prototype, not a product. **Status (Milestone 1.5):** rules, agent-level taint,
honest approval prompts, keyed audit log, watch mode, usage counters, a prompt-budget
simulation and 27 attack tests are built. There is no MCP server, no Google connection and no
phone approval yet; everything runs against an in-memory fake inbox. Licensed Apache-2.0.

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

## Approvals in Milestone 2: development only

> **WARNING - `broker approvals` is for development only.** Any program running as you,
> including an AI agent with a shell (for example Claude Code), can run
> `broker approvals approve <id>` and approve its own requests. Use it only with a test
> account. The real fix is an approval channel the agent cannot reach (phone approvals,
> Milestone 3). See THREAT_MODEL.md.

A tool call that needs approval waits about 45 seconds. If nobody has answered by then, it
returns `pending_approval` with an id, and the agent repeats the identical call to get the
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
- **Single process, single user.** No concurrency handling, no multi-user setup.

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
