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
- Open concern: `search_mail` returns the snippet (first ~90 chars of the body) and, per the brief's table, never taints. A short injected instruction can sit inside a snippet from an unknown sender. See README "What this does not cover".

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
