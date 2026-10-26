# Agent Access Broker (v0 prototype)

A local gate between an AI agent and a user's Gmail and Google Calendar. It is a six-week
validation prototype, not a product. **Milestone 1 status:** rules, taint, audit log, fake
backend, minimizer, gate and attack tests are built. There is no MCP server, no Google
connection and no phone approval yet; everything runs against an in-memory fake inbox.

## What it does

Every tool call goes through `Gate.handle(session, tool, args)`:

1. **Rules.** A deny-by-default evaluator reads one YAML profile
   (`broker/rules/profiles/*.yaml`) and returns `allow`, `allow_redacted`, `ask` or `deny`.
   Any tool or case not matched by a rule is denied. If several rules match, the strictest
   wins. No AI model is involved in the decision.
2. **Taint.** The first time a session reads mail from an address that is not a known
   contact (or lists an event whose description was written by an outside organizer), the
   session becomes tainted for the rest of its life. The profiles make tainted sends and
   calendar writes ask (or deny).
3. **Approval.** For `ask`, a prompt is built from the agent's structured arguments only:
   recipients, subject, first 200 characters of the body. Anything but an explicit approval
   (deny, timeout) means no action.
4. **Backend.** Currently `FakeBackend` (in-memory). The Google backend comes in Milestone 2.
5. **Minimizer.** Returns only the fields each tool needs. Bodies are masked for emails,
   phone numbers and long digit runs under `allow_redacted`.
6. **Activity log.** Append-only SQLite. Each row holds a SHA-256 hash of itself plus the
   previous row's hash. Only metadata is stored (ids, counts, recipient domains, decision,
   approval outcome); message content is refused by the logger itself.

The six v0 tools are `search_mail`, `read_message`, `list_events`, `draft_reply`,
`send_mail`, `create_event`. Forward, delete and share do not exist and are always denied.

Profiles: `cautious` (asks more, denies tainted sends), `working` (default), `autonomous`
(asks less; still never lets a tainted session send or create events without approval).

## What it does not cover

This prototype does **not** prevent prompt injection, and the tests do not show that it is
secure. They show that specific seeded attacks, against a fake backend and a scripted
approver, end in a prompt or a deny rather than a silent send. Known gaps:

- **Known contacts are trusted.** Taint is based only on the sender address. An instruction
  from a known contact (or from a compromised known account) does not taint. Spoofed `From`
  headers are not checked (no SPF/DKIM/DMARC check yet).
- **Search snippets do not taint.** `search_mail` returns about 90 characters of each body,
  including from unknown senders, and does not taint the session (per the v0 tool table).
  A short instruction can arrive this way.
- **The agent still sees injected text.** Hidden HTML, comments and encoded payloads are
  passed through (bodies only have personal data masked). The gate limits what the agent
  can *do* afterwards; it does not clean what the agent *reads*.
- **Approval fatigue.** In the working profile every send asks. A user who approves without
  reading is not protected. The prompt shows only the first 200 characters of the body;
  anything after that is not shown.
- **Draft replies are always allowed**, even while tainted. They are never sent by the gate,
  but a draft can hold copied data that the user later sends.
- **Clean sessions in the autonomous profile** may send to anyone without asking.
- **Log tail truncation.** The hash chain detects edited, deleted or reordered rows, except
  rows removed from the *end* of the log, or a chain rewritten from some point onward by
  someone with write access. That needs an anchor stored elsewhere (not built).
- **Masking is regex-only.** Names, street addresses and many ID formats are not masked.
- **Single process, single user.** No concurrency handling in the log, no multi-user setup.

## Develop

```bash
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run pyright
uv run broker profiles
uv run broker verify-log path/to/audit.db
```

No network calls are made by the broker or its tests. See `DECISIONS.md` for every choice and
what was rejected.
