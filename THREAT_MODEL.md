# Threat model (v0)

Written before the Google and MCP code (Milestone 2, 2026-10-27). It states what the local gate
is for, what it cannot do, and what v0 does about each gap. It is not a claim that the gate is
secure.

## The setting

- One user, one machine, one Google test account.
- An AI agent (Claude Desktop, Claude Code, or another MCP client) talks to the broker's MCP
  server over stdio. The broker holds the Google token and calls Gmail and Calendar.
- The attacker controls text the agent reads: email bodies, subjects, snippets, sender display
  names, calendar descriptions. The attacker does not control the user's machine.

## What the gate protects

An agent whose **only** route to mail and calendar is this MCP server, and which is attacked
through text it reads. In that setting:

- The agent never holds a Google token; it can only call the six tools.
- Every call goes through rules, taint and (when needed) a human approval built from the real
  action, and every call is logged.
- Forward, delete, share and attachments do not exist as tools.

## What it does not protect

An agent that **also** has a shell, a browser, or file access as the same OS user. Claude Code
has a shell by default, so for many likely testers this is the normal case, not an edge case.
Such an agent runs with the user's own permissions; file modes do not stop it.

| Bypass | How | What v0 does |
|---|---|---|
| Read the Google token | `keyring` / `security find-generic-password` from a shell, as the same user | Token is only in the OS keychain, never in a file, log or error. macOS may show an access prompt for some keychain reads; we do not rely on it. Not prevented. |
| Call Google directly | Use the stolen token, or the user's own browser session, with `curl` or a script | Nothing. The gate is not in that path. |
| Approve its own request | Run `broker approvals approve <id>` from a shell | With `phone: telegram`, the command refuses unless the config sets `dev_cli_approvals: true`. The agent can still edit the config to set it, or write `approved` into `approvals.db` directly (same user). See "Phone approvals" below. Not prevented. |
| Use the bot token | Read `telegram-bot-token` from the keychain | With the token an agent can send messages as the bot and consume button taps before the broker sees them (which only delays or loses approvals). It cannot make Telegram report a tap from the owner's id. Not prevented, and not needed: it can edit `approvals.db` anyway. |
| Switch to watch mode | Edit `~/.agent-broker/config.yaml` (`mode: watch`) and wait for a restart | Mode is read only at start-up and no MCP tool can change it. A file edit is not prevented. |
| Loosen the rules | Edit the profile YAML in the installed package, or pick `profile: autonomous` in the config | Same as above: only file edits can change it, and those are not prevented. |
| Clear taint / approval history | `broker taint clear`, or delete or edit `taint.db` / `history.db` | `taint clear` writes a log row; direct file edits are not detected (these files are not hash-chained). |
| Rewrite the activity log | Edit `audit.db` | Detected by `broker verify-log` unless the agent also reads the HMAC key from the keychain (same user, so it can). |
| Read message content at rest | Read the SQLite files | They hold metadata only (and approved recipient addresses in `history.db`), never bodies. Gmail itself is the content store. |
| Register a new agent identity | `broker agents add` and start a second server | Possible from a shell; a new identity starts clean. Logged in the config file only. |
| Impersonate the MCP client | Report a different client name | Identity comes from the `--agent` launch argument, not from the client; the reported name is logged as a hint only. |

## Phone approvals (Milestone 3, Telegram bot)

What the phone channel protects:
- An agent **without** a shell (Claude Desktop with only this MCP server) cannot answer its own
  approval: no MCP tool decides approvals, and the terminal commands are off while a phone is
  configured.
- A tap counts only if Telegram reports it from the owner's user id (stored at setup), carries
  a nonce the broker issued, is on the message that nonce was sent in, the nonce is unused,
  the approval it belongs to still has the same action hash, is still pending, and is less than
  five minutes old. Everything else is refused and logged as metadata (`phone_reply`).
- A stranger who finds the bot, or sees a screenshot of a button, cannot approve: Telegram sets
  the sender id, not the button.

What Telegram (the operator) can see and do:
- Every approval message at the `minimal` level: tool, recipient addresses (with OUTSIDE/NEW
  flags), subject (one line, at most 120 characters), event details, body length, a 12-hex
  hash of the body, the approval number for the day and the rule's reason. Never the body.
  Bot chats are not end-to-end encrypted.
- Telegram itself could forge a tap: the owner id in a callback is whatever Telegram says.
  The bot token alone does not allow that. TLS to `api.telegram.org` is what stops a network
  attacker from feeding the broker fake updates.
- If Telegram is down or slow, approvals behave as without a phone: the call waits, returns
  pending, and the answer is picked up on the repeated call (Telegram keeps unread taps up to
  24 hours; the request itself expires after 5 minutes).

What a shell-capable agent can still do (same OS user):
- Read the bot token and owner id from the keychain.
- Set `dev_cli_approvals: true` or `phone: none` in the config and wait for a restart.
- Write a decision straight into `approvals.db`.
So the phone channel is **not** a defense against an agent with a shell. It is a defense
against an agent that only has this MCP server.

Known limit: a request that requires the full body (tainted and longer than 2000 characters,
or after 10 prompts per agent per day) cannot be approved on the phone at the `minimal` level;
the message offers only Deny.

## Mitigations in v0

- Every state file (`audit.db`, `taint.db`, `history.db`, `approvals.db`, `counters.json`,
  contacts cache) is created `0600` inside a `0700` state directory. This keeps out other OS
  users, not the same user.
- The Google token lives only in the OS keychain. It never appears in a file, log, error
  message or traceback.
- Mode and profile can only change by editing the config file; there is no tool or argument
  for them, and they are read once at start-up.
- At start-up the broker warns if the config file or its folder is writable by other users or
  owned by someone else.
- Approval requests are built only from the agent's structured arguments; `send_mail` refuses to
  send anything whose hash differs from what was approved.

## What would fix the shell case later (not built now)

- Run the agent as a separate OS user, or inside a container or VM, with no access to the
  broker's state, config, keychain or CLI. The broker keeps the token; the agent keeps a shell.
- Or a hosted relay that holds the Google token, so nothing on the agent's machine can call
  Google directly. That trades local-first for a server we would have to run and secure.
- In both cases approvals must arrive on a channel the agent cannot reach (a phone).

## What testers should be told

If your agent can run shell commands or read your files, this gate is a seatbelt against an
agent that is fooled by an email, not a wall against an agent that is actively trying to get
around it. Use it with a test account, and prefer agents without a shell (e.g. Claude Desktop
with only this MCP server) for the trial.
