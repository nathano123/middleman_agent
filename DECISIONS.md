# Decisions

Each entry: what was chosen, why, what was rejected. Newest at the bottom.

## 2026-10-26 Own git repo, pushed after every commit
- Chose: a fresh repo in `agent-broker/`, remote `github.com/nathano123/middleman_agent` (public).
- Why: the parent folder sits inside a home-directory git repo full of unrelated files; owner asked for a new repo and a push after every change.
- Rejected: committing into the home-directory repo.

## 2026-10-26 Toolchain
- Chose: uv 0.13.5, Python 3.12 (pinned in `.python-version`, `requires-python >=3.11`), ruff 0.17.2, pytest 9.1.1, pyright 1.1.414 in strict mode.
- Why: uv and ruff were required. Pyright strict catches missing hints without a plugin; it works with pydantic v2 natively.
- Rejected: mypy (would also work; pyright needs no pydantic plugin). Homebrew uv (Homebrew refused on this Mac, "Tier 3" config); installed uv from PyPI into its own venv at `~/.local/share/uv-tool-venv` instead.
- Note: the pyright pip package downloads a Node runtime on first run. That is a development-only download, not part of the broker.

## 2026-10-26 Library versions in use (Milestone 1)
- pydantic 2.14.1, PyYAML 6.0.3 (`yaml.safe_load` only; never `yaml.load`).
- None of the libraries flagged for doc checks (MCP SDK, keyring, google-api-python-client, google-auth-oauthlib, Presidio, transformers) are used in M1. They will be checked and recorded here when M2 starts.

## 2026-10-26 Rule format and evaluation
- Chose: a profile is a YAML list of rules `{tool, resource?, when?, decision, reason}`. `when` may only test four booleans the gate computes in Python: `tainted`, `outside_recipients`, `outside_attendees`, `own_calendar`. Unknown keys, unknown tools, unknown conditions and unknown verdicts all make the file refuse to load (pydantic `extra="forbid"` plus a tool-name check).
- Why: the rule file must stay readable and must not grow into a language. Refusing unknown keys stops a typo (`whne:`) from silently making a rule unconditional.
- Evaluation: collect every matching rule; none matches → deny; otherwise the strictest wins (deny > ask > allow_redacted > allow). Order in the file does not matter, so no rule can widen another rule's deny.
- Rejected: first-match-wins (order-sensitive, easy to widen a deny by inserting an allow above it); Cedar/OPA (ruled out by the brief).
- `resource` is `mail` or `calendar` for v0. Which calendar is expressed by the `own_calendar` condition; an event on any other calendar matches no allow rule and is denied.
- YAML is parsed with `yaml.safe_load` only.

## 2026-10-26 Profile readings (owner may want to revisit)
- working: exactly the brief's table. Every `send_mail` asks (tainted or not). `create_event` asks whenever the session is tainted, even with no outside attendees: the table's "needs approval if tainted" read literally. `draft_reply` stays allowed while tainted (never sends).
- cautious: tainted `send_mail` → deny; tainted invite to outsiders → deny; every `create_event` asks; tainted `draft_reply` asks.
- autonomous: clean `send_mail` and own-calendar `create_event` (outside attendees included) are allowed; anything while tainted asks.
- Tested invariant: in every profile a tainted `send_mail` is ask or deny, never allow.

## 2026-10-26 Taint
- Chose: `Session` holds `tainted` and the first `taint_reason`; `mark_tainted` has no inverse. Addresses are compared after `email.utils.parseaddr` + lowercase; display names are discarded. The user's own address counts as known. An empty or unparseable sender is unknown, so it taints.
- Why: taint must depend only on who wrote the content. That makes non-English, encoded or hidden instructions irrelevant to the decision, and makes look-alike display names useless.
- `list_events` taints if any returned event has a non-empty description and an organizer who is not known. Events with no description do not taint (no attacker text to carry).
- Rejected: per-address domain trust (e.g. "anyone @mycompany.com"): not in the brief; easy to add later as a known-domains list.

## 2026-10-26 Audit log
- Chose: SQLite table `log(id, ts, session_id, tool, decision, reason, metadata, prev_hash, hash)`. `hash` = SHA-256 of sorted compact JSON of every field except `hash` itself, with `id` and `prev_hash` included. The first row's `prev_hash` is 64 zeros. Ids are assigned explicitly (last id + 1) so the id is known before hashing.
- `verify(path)` opens the file read-only and returns the first id whose `prev_hash` or `hash` does not fit, else `None`.
- What it catches: an edit to any field of any row; a deleted first or middle row; reordered rows. An attacker who edits a row *and* recomputes its hash is caught at the following row.
- What it does not catch (tested and documented): removing rows from the end, or rewriting the whole chain from some row onward. Both need an anchor kept outside the file (e.g. last hash shown on the phone, or written to a second location). Deferred.
- Content is kept out structurally: metadata keys must be in a fixed allow-list (ids, counts, recipient/attendee *domains*, approval outcome, taint state), and strings are capped at 128 characters. Subject, body, snippet and description are not valid keys.
- Rejected: SQLite triggers blocking UPDATE/DELETE (anyone with file access can drop them; adds code without adding a guarantee).

## 2026-10-26 Fake backend and minimizer
- Chose: `Backend` is a `typing.Protocol` with six methods. `FakeBackend` holds messages and events loaded from `tests/fixtures/mailbox.json`, and records sends, drafts and created events in lists so tests can assert on them. It does no I/O beyond reading the fixture.
- Minimizer fields: search → id, sender, subject, date, snippet. read_message → the same plus body (masked under `allow_redacted`). list_events → id, title, start, end, organizer, attendee *count*, masked description. Attendee addresses are not returned.
- Masking: three regexes, applied in order: emails → `[email]`, phone-like runs (8+ chars of digits/space/()-.) → `[phone]`, 6+ digit runs → `[number]`. Placeholder until Presidio (M4). Known misses: names, street addresses, IBANs (only the digit run is masked).
- Event descriptions are returned (masked). They are the attack surface for invite injection; taint, not hiding, is what guards the follow-up action.
- Open concern (resolved 2026-10-26, see "search_mail taints" below): `search_mail` returned snippets from unknown senders without tainting.

## 2026-10-26 Gate
- Chose: `Gate(profile, backend, approver, log).handle(session, tool, args) -> Result`. Steps: unknown tool → deny; args validated by a per-tool pydantic model with `extra="forbid"` (bad args → deny); constraints computed from args + session; evaluate; deny → stop; ask → build prompt from args, approver must return `approved`; run backend; apply taint after reads; minimize; log exactly one row.
- The approval prompt holds normalized recipient addresses, subject/title, first 200 chars of the body/description the agent wants to send, and the rule reason plus the taint reason. Nothing from inbound mail can reach it except what the agent itself copies into the outgoing arguments, and that is exactly what will be sent.
- A recipient that does not parse as an address counts as outside.
- The log row stores the evaluator's verdict (`ask` stays `ask`) plus `approval: approved|denied|timeout`, so a reviewer sees both the policy and the human answer.
- `FakeApprover` answers from a script, then a default (denied). Timeout is just an outcome here; the real 5-minute clock arrives with ntfy (M3). `APPROVAL_TIMEOUT_SECONDS = 300` is defined for it.
- Rejected: a separate "connector" layer in M1. With a fake backend it would be an empty pass-through; it arrives with the Google backend.

## 2026-10-26 Attack tests
- Chose: 20 tests in `tests/attacks/`, all through `gate.handle` with the fake backend and fake approver. Each assumes a fully hijacked agent (it does what the injected text says) and checks what the gate lets through.
- A shared `world` fixture (tests/conftest.py) re-checks the acceptance bar after every test: no fixture body/subject/snippet/description bytes in the SQLite file; every sent mail and every outside-attendee event has an approved prompt equal to its real recipients/subject/body preview; every approved prompt matches a real backend effect. Two unit tests prove the checker itself fails on an unapproved send and on leaked content.
- Mutation check (manual, 2026-10-26): flipping working `send_mail` to allow → 12 attack tests failed + 12 invariant errors; disabling `mark_tainted` → 15 failed + 1 error. Both reverted.
- Test 13 is deliberately a "negative": the same Hebrew instruction from a known contact does not taint. That is the design (sender rule, no classifier), and it is a real gap: a compromised or careless known contact is trusted.

## 2026-10-26 CLI
- Chose: argparse (stdlib), two commands only. `verify-log` exits 0 intact / 1 tampered / 2 missing, and always reminds that tail truncation is not detectable. `profiles` loads all three and exits 1 if any fails to load.
- Rejected: click/typer (extra dependency for two commands).

## 2026-10-26 search_mail taints on unknown-sender snippets (departs from the brief's table)
- Chose: `search_mail` now taints the session if any returned result has a non-empty snippet from a sender that is not a known contact. Reason string: "search returned a snippet from an unknown sender". The brief's table said "Taint effect: none" for `search_mail`; the owner approved this change on 2026-10-26.
- Why: a snippet is attacker-written text (first ~90 chars of the body). An agent that only searches, never opens a message, could otherwise be steered by it while the session stays clean.
- Effect on the tool table: search_mail | allow; headers and snippet only | **taints if any result's snippet is from an unknown sender**.
- Consequence: a broad inbox search (e.g. empty query) will almost always taint, since most inboxes hold mail from unknown senders. In the working profile this changes little (every send already asks; own-calendar events now ask after such a search). In autonomous it means most sessions that search will ask before sending. Worth watching in the 14-day trial for approval fatigue.
- Rejected: dropping snippets from search results (loses the main reason to search); tainting only on snippets that "look like" instructions (would need a classifier in the decision path, which the brief rules out).
- Test: attack test 21 (`tests/attacks/test_snippet.py`) runs in the autonomous profile, where taint decides the outcome. It fails if the search-taint call is removed (checked 2026-10-26).

## 2026-10-27 Milestone 1.5, step 0: red-team tests before fixes
- Added attacks 22-27 in `tests/attacks/test_gaps.py`: taint moved to a new session, Reply-To mismatch, buried payload, 30 small approvals then a bad one, own alias, spoofed known contact. All six fail on the M1 code and are marked `xfail(strict=True)`, so each fix must flip them (a strict xfail that passes is an error).
- To let the tests be written against the intended API, inert fields were added first (no behaviour yet): `Message.reply_to/auth_result/list_unsubscribe/precedence/thread_id`, extra `ApprovalRequest` fields, `Session.agent_id/self_addresses`, `FakeApprover.views_full_body`. `auth_result` defaults to `unknown`, which keeps M1 behaviour.
- Checked with `--runxfail` that each test fails on its target assertion, not on an incidental error.
- The approval-count test (25) uses a hijacked flow that the fake approver approves 30 times; the bad send is approved without opening the body, which must be refused.
- Commits from now on use the GitHub noreply address (`48062641+nathano123@users.noreply.github.com`). Earlier commits carry the owner's university address; history was left as is by the owner's choice (it is already public).

## 2026-10-27 License, CI, pre-commit, history check
- License: Apache-2.0, confirmed by the owner on 2026-10-27. Why: explicit patent grant and patent-retaliation clause, permissive enough for an open-core model where a paid layer sits on top. Text taken verbatim from GitHub's license API (`gh api /licenses/apache-2.0`); the appendix placeholders are left as is. Rejected: MIT (no patent grant), AGPL (would push away the integrators an open core needs).
- CI (`.github/workflows/ci.yml`): `actions/checkout@v7.0.1`, `astral-sh/setup-uv@v10.3.2` (inputs `version`, `python-version` checked against its `action.yml` at that tag), uv 0.13.5, Python 3.12, `uv sync --locked`, then ruff check, ruff format --check, pyright, pytest. Read-only token permissions.
- Pre-commit: `astral-sh/ruff-pre-commit` v0.17.2 (`ruff-check`, `ruff-format`; ids checked in its hooks file), plus local `uv run pyright` and `uv run pytest -q`.
- History check (2026-10-27), over every commit's patch and metadata:
  - Email addresses not ending in `.test`: only `nathan.orlowski@post.runi.ac.il` (author line of the first 9 commits; not in any file), the new noreply address, `noreply@anthropic.com` (co-author trailer), and `@pytest` false hits.
  - The owner's surname appears only in those 9 author lines; `git grep` finds it in no tracked file.
  - Token patterns searched: `gho_`, `ghp_`, `github_pat_`, `AIza…`, `ya29.`, `sk-…`, `-----BEGIN`, `client_secret`, `refresh_token`. Only hit: the `.gitignore` line `client_secret*.json`.
  - Fixture domains are all `.test` (apparent short domains are 90-character snippet cuts); the only URL is `https://evil.test/join`.
  - Every file ever added is source, config, docs or the JSON fixture.

## 2026-10-27 Config file, agent-level taint, trust rules
- Config: `broker/config.py`, YAML at `~/.agent-broker/config.yaml` (example: `broker.example.yaml`). Holds settings only (addresses, contacts, profile, mode, agent registry, limits, state dir); rules stay in the profile YAML. Frozen pydantic model with `extra="forbid"`; unknown keys or bad values refuse to load.
- Agent identity: config maps MCP client names to agent ids; every client not listed shares `default` (owner's choice, 2026-10-27). So a hijacked agent cannot shed taint by reconnecting under a new client name; registering a separate agent is a deliberate user edit to the config. The id is chosen by the gate from config, never by the agent.
- `TaintStore` protocol (`get`, `mark`, `clear`) with `MemoryTaintStore` and `SQLiteTaintStore`, keyed by agent id. A record holds the first reason, first time and last time.
- Expiry: active while `now - last_at < quiet` (default 24 h). A new tainting event restarts the clock and keeps the first reason. Reconnecting never clears it.
- Within one live `Session`, taint never clears: once seen (or set), the session holds it even if the store record is cleared or expires. `broker taint clear` therefore takes effect on the next connection. Why: a tainted conversation still has the hostile text in its context; clearing must not re-arm that same context.
- `broker taint clear [--agent X]` deletes the record and writes a log row (`tool=taint_clear`, reason says whether there was taint).
- Trust rule (`distrust()`), in order: unknown sender → untrusted; known sender with `auth_result: fail` → untrusted; known sender whose Reply-To is a different, unknown address → untrusted. `auth_result: unknown` keeps M1 behaviour and is logged on every `read_message` row as `auth_result`.
- `self_addresses` (aliases) count as known.
- `draft_reply` now addresses the draft to Reply-To when present (what a mail client would do) and returns that address, so the agent and user see where it would go.
- Red-team tests 22 (reconnect), 26 (alias), 27 (spoof) now pass; xfail markers removed. Test 23 (Reply-To) taints and drafts correctly but still waits on the step 3 prompt field.
- Found while testing: `mark_tainted` did not pin taint to the live session until the next read; fixed.

## 2026-10-27 Approval prompt honesty
- The prompt now carries: total body length, `more_chars` (shown as `[+N more characters not shown]`), the first 12 hex of SHA-256 of the full body, `approval #N this session`, `OUTSIDE:` recipients (not known contacts), `NEW this session:` recipients (not approved earlier in this session), and whether the full body must be opened. `render_prompt()` turns this into the notification text; every line comes from request fields.
- Full-view rule: a plain Approve is refused (`approval: unviewed`) when (a) the session is tainted and the body/description is longer than `full_view_body_chars` (default 2,000), or (b) this is prompt number `full_view_after_approvals + 1` or later in the session (default: from the 11th). The approver's answer now carries `viewed_full_body`; the fake approver simulates it with `views_full_body`.
- Why a 12-hex hash: long enough to tell two bodies apart at a glance, short enough for a phone line. It identifies repeats; it is not a security control.
- Why the counter raises the bar rather than blocking: test 25 shows 30 harmless approvals; blocking the 31st would punish normal use. Requiring the full body breaks the "tap Approve on autopilot" pattern exactly when it is most likely.
- Builder input: `approval_request(session, args, decision, config)`. A test checks the signature admits only those four types (no `Message`/`Event`), and a replay test reads every fixture message and event, then checks that no inbound text (8+ chars) appears in any rendered prompt or full body.
- `send_mail` still has no attachment field; a test checks `attachments=[...]` is denied before any prompt.
- Test 24 had a construction bug (body was 49,978 chars, not 50,000); fixed in the test, not the gate.
- All six red-team tests (22-27) now pass; no xfail markers remain.

## 2026-10-27 Prompt-budget simulation
- Chose: `broker/sim.py` (in the package so `broker simulate` can import it; tests in `tests/sim/`). A seeded generator makes one workday: 60 inbound mails (36 known contacts, 12 newsletters with `List-Unsubscribe` + `Precedence: bulk`, 6 vendor invoices, 6 unknown people), 6 events (4 internal; 2 with outside attendees, one of them organized by a vendor). A scripted agent runs two sessions a day through `Gate.handle` only: morning (search 20, read top 10, list events, 5 drafts), afternoon (2 in-thread replies to known contacts, 1 internal event, 1 event with an outside attendee). The approver approves everything and opens full bodies. Taint persists across sessions and days through the agent-level store.
- "Taint-only" prompt: a prompt that the same call in a clean session would not have produced (re-evaluated with `tainted=False`). Reported as the avoidable share.
- Measured (seed 7, 7 days, every day identical in shape):
  | profile | prompts/day | taint-only | blocked/day | tainted by |
  |---|---|---|---|---|
  | cautious | 6.0 | 5 | 3 | search snippet from unknown sender |
  | working | 4.0 | 1 | 0 | same |
  | autonomous | 4.0 | 4 | 0 | same |
- Working is under the target of 5, so no change to the gate was made. Options were still measured, so the trade-offs are on record:
  1. Search snippets from bulk senders (List-Unsubscribe / Precedence bulk) do not taint. Measured: 4.0 → 4.0 in working and autonomous. Even exempting bulk mail on `read_message` too gives 4.0: vendor invoices and unknown people in the top results still taint. Cost: the header is attacker-controlled, so any injected mail could add it and reopen the snippet channel (attack 21). Rejected: no gain, real cost.
  2. One batched prompt per session. Estimated 1.0/day for working. Cost: the user approves several different actions at once, which loses per-action consent and makes the misleading-prompt and 30-approvals attacks easier. Rejected for now; revisit only if real testers exceed 5.
  3. In-thread replies to known contacts treated as lower risk (allowed without prompt). Estimated 2.0/day for working. Cost: a tainted agent can still put exfiltrated content into a reply to a real contact (and from there it may leave via that contact); "in-thread" depends on thread ids that a hostile mail can join. Not adopted; it is the most attractive lever if needed, and should come with "tainted sessions still ask".
- Findings worth stating plainly:
  - Taint is effectively always on in a realistic day: the morning search sees unknown senders, so both sessions are tainted every day. In autonomous, all 4 prompts are taint-only; autonomous behaves like working.
  - Cautious is not livable for this script: 6 prompts a day, and both sends plus the outside invite are blocked every day.
  - The simulation found a crash: cautious + tainted + `draft_reply` reached the prompt builder, which had no draft case (an M1 bug). Fixed: the draft prompt shows the target message id and the draft body, from the agent's arguments only. A new test runs every profile × tool × taint state through `handle`.
- Limits: one scripted day shape, fixed counts, one agent, approver always approves. Real inboxes and agents will differ; the trial numbers are what count.

## 2026-10-27 Watch mode and counters
- `mode: enforce | watch` in the config. The gate copies it at start-up into a read-only property; there is no setter and no tool for it. Changing mode means editing the file and restarting. Tests: tools named `set_mode`/`config` and a `mode` argument on real tools are all denied (strict argument schemas), and assigning `gate.mode` raises.
- Watch mode (owner's choice, 2026-10-27): every call the rules would allow, ask or deny is run without a prompt, logged with `would_have` and `mode: watch`; the returned Result carries `would_have`. Unknown tools and invalid arguments are still refused (there is nothing valid to run). Redaction still applies when the rule says `allow_redacted`. Taint is still tracked so the would-have record is accurate.
- Enforce guarantee, tested exhaustively (3 profiles × clean/tainted × approved/denied/timeout × 7 tools incl. an unknown one) with a spy backend: a backend method is called **if and only if** the decision was allow/allow_redacted, or ask and approved.
- Counters: `broker/counters.py` writes `counters.json` in the state dir. Per day: calls, decisions by verdict, prompts, approval outcomes (approved/denied/timeout/unviewed), watch would-have by verdict. `record()` takes only a date, enums and nothing else, so content has no path in. `broker report [--end DATE]` prints the 7-day summary a tester sends back: days with a call, calls, prompts per active day vs the target, approved vs refused, decisions, watch would-haves.
- Test: run every fixture message through search, read and draft, then send and invite to outsiders with distinctive subjects; neither the counters file nor the report contains any fixture text, any address, the test subjects, or even an `@`.
- Rejected: counting per recipient domain or per tool in the counters (more useful, but domains are personal data and the brief asks for no content; the audit log already has domains locally).

## 2026-10-27 Log anchoring (HMAC + keychain head) and architecture guard
- keyring 25.7.0 checked from the installed package: `get_password(service, username) -> str | None`, `set_password(service, username, password) -> None`, `set_keyring(backend)`; backends subclass `keyring.backend.KeyringBackend` and supply `priority`, `get_password`, `set_password`, `delete_password`.
- Implemented (about 58 lines net in `audit.py`, inside the ~60-line budget): a `KeyStore` protocol with `KeyringKeyStore` (service `agent-broker`). When the log is opened with a key store, a 32-byte random key is created once in the keychain; each row's `hash` is HMAC-SHA-256 instead of SHA-256; after every append the newest row's `id:hash` is written to the keychain as a head anchor (one entry per log file path). `verify(path, keys)` checks HMACs and that the newest row matches the anchor.
- What this adds: a full-chain rewrite by someone without the key fails at row 1 (tested with plain SHA-256 and with a wrong key); deleting rows from the end is detected and reported as the anchored row id (tested).
- What it does not cover: anyone who can read the user's keychain (same user account, unlocked session) can recompute the chain and move the anchor. A crash between the row insert and the anchor write leaves the anchor one row behind and `verify` will flag the newest row; acceptable for v0, noted. Logs written without a key store stay plain SHA-256 chains (the simulation uses an in-memory unkeyed log).
- `broker verify-log` uses the keychain key when present and says which check it ran; without a key it warns that rewrites and tail truncation cannot be detected. `broker taint clear` writes keyed rows.
- Tests never touch the real keychain: an autouse fixture installs an in-memory `KeyringBackend`, and a test asserts it is active.
- Architecture guard (`tests/unit/test_architecture.py`): parses every module in `broker/` except `gate.py` and `backends/`, and fails on any call to a `Backend` method name (read from the protocol), including `getattr(x, "send_message")`. A self-test shows it catches both forms.
