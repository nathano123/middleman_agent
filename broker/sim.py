"""Prompt-budget simulation: replay deterministic fake workdays through the real gate.

Not an attack. A scripted personal-assistant agent does a typical day (triage, drafts, two
sends, two events) against a generated inbox, and we count how often the user is prompted.
Everything goes through Gate.handle; the simulation never calls the backend directly.
"""

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from broker.approvals.base import ApprovalOutcome
from broker.approvals.fake import FakeApprover
from broker.audit import AuditLog
from broker.backends.base import Event, Message
from broker.backends.fake import FakeBackend
from broker.config import BrokerConfig, ProfileName
from broker.gate import ARG_MODELS, RESOURCES, Gate, constraints_for
from broker.rules.evaluator import evaluate, load_profile
from broker.rules.models import Action, Constraints, Verdict
from broker.taint import Contacts, MemoryTaintStore, Session

OWN = "me@home.test"
CONTACTS = tuple(f"colleague{i:02d}@work.test" for i in range(1, 13))
FIRST_DAY = datetime(2026, 11, 2, tzinfo=UTC)  # a Monday

# --- the generated day -------------------------------------------------------


@dataclass(frozen=True)
class Day:
    index: int
    messages: list[Message]
    events: list[Event]


def _message(rng: random.Random, day: datetime, n: int, kind: str) -> Message:
    minute = rng.randrange(0, 8 * 60 + 30)  # arrived between midnight and 08:30
    when = (day + timedelta(minutes=minute)).isoformat()
    if kind == "known":
        sender = rng.choice(CONTACTS)
        return Message(
            f"d{day.day}-{n}", sender, [OWN], f"Project update {n}", when,
            f"Quick update on item {n}", f"Quick update on item {n}. Thoughts?",
            auth_result="pass", thread_id=f"t{n % 9}",
        )  # fmt: skip
    if kind == "newsletter":
        sender = f"news@shop{n % 7}.test"
        return Message(
            f"d{day.day}-{n}", sender, [OWN], f"Deals {n}", when, f"This week's deals {n}",
            f"This week's deals {n}", auth_result="pass",
            list_unsubscribe=f"<mailto:unsub@shop{n % 7}.test>", precedence="bulk",
        )  # fmt: skip
    if kind == "vendor":
        sender = f"billing@vendor{n % 3}.test"
        return Message(
            f"d{day.day}-{n}", sender, [OWN], f"Invoice {n}", when, f"Invoice {n} is ready",
            f"Invoice {n} is ready", auth_result="pass",
        )  # fmt: skip
    sender = f"person{n}@elsewhere.test"
    return Message(
        f"d{day.day}-{n}", sender, [OWN], f"Hello {n}", when, f"Hi, reaching out about {n}",
        f"Hi, reaching out about {n}", auth_result=rng.choice(["pass", "unknown"]),
    )  # fmt: skip


def _events(day: datetime) -> list[Event]:
    def at(hour: int) -> str:
        return (day + timedelta(hours=hour)).isoformat()

    internal = [
        Event(f"e{day.day}-{i}", "primary", CONTACTS[i], f"Internal {i}", at(10 + i), at(11 + i),
              "Agenda in the doc.", [OWN, CONTACTS[i]])
        for i in range(4)
    ]  # fmt: skip
    outside = [
        Event(f"e{day.day}-4", "primary", CONTACTS[5], "Customer call", at(15), at(16),
              "Prep notes in the doc.", [OWN, CONTACTS[5], "buyer@customer.test"]),
        Event(f"e{day.day}-5", "primary", "events@vendor0.test", "Vendor demo", at(16), at(17),
              "Demo of the new release.", [OWN, "events@vendor0.test"]),
    ]  # fmt: skip
    return internal + outside


def generate_day(seed: int, index: int) -> Day:
    """About 60 inbound mails: 36 known, 12 newsletters, 6 vendors, 6 unknown people."""
    rng = random.Random(seed * 1000 + index)
    day = FIRST_DAY + timedelta(days=index)
    kinds = ["known"] * 36 + ["newsletter"] * 12 + ["vendor"] * 6 + ["unknown"] * 6
    rng.shuffle(kinds)
    messages = [_message(rng, day, n, kind) for n, kind in enumerate(kinds)]
    return Day(index, messages, _events(day))


# --- what one simulated day measured -----------------------------------------


@dataclass
class DayStats:
    day: int
    calls: int = 0
    prompts: int = 0
    taint_only_prompts: int = 0  # would not have asked in a clean session
    in_thread_known_send_prompts: int = 0  # sends replying in-thread to a known contact
    blocked: int = 0
    sessions_with_prompt: int = 0
    tainted_sessions: int = 0
    taint_reasons: list[str] = field(default_factory=list[str])


@dataclass
class Clock:
    now: datetime

    def __call__(self) -> datetime:
        return self.now


class Runner:
    """Drives one profile through several days. Taint persists across days via the store."""

    def __init__(self, profile: ProfileName, seed: int) -> None:
        self.seed = seed
        self.profile = load_profile(profile)
        self.config = BrokerConfig(own_address=OWN, known_contacts=CONTACTS, profile=profile)
        self.contacts = Contacts(OWN, frozenset(), frozenset(CONTACTS))
        self.store = MemoryTaintStore(timedelta(hours=self.config.taint_quiet_hours))
        self.clock = Clock(FIRST_DAY)
        self.log = AuditLog(Path(":memory:"))

    def run(self, days: int) -> list[DayStats]:
        return [self.run_day(generate_day(self.seed, i)) for i in range(days)]

    def run_day(self, day: Day) -> DayStats:
        stats = DayStats(day.index + 1)
        backend = FakeBackend(messages=list(day.messages), events=list(day.events))
        approver = FakeApprover(default=ApprovalOutcome.APPROVED, views_full_body=True)
        gate = Gate(self.profile, backend, approver, self.log, self.config)
        start = FIRST_DAY + timedelta(days=day.index)
        known_threads = self._morning(gate, stats, start + timedelta(hours=9), approver)
        self._afternoon(gate, stats, start + timedelta(hours=14), approver, known_threads)
        return stats

    # --- the scripted agent ---

    def _session(self, name: str, at: datetime) -> Session:
        self.clock.now = at
        return Session(name, "default", self.contacts, self.store, self.clock)

    def _morning(
        self, gate: Gate, stats: DayStats, at: datetime, approver: FakeApprover
    ) -> list[dict[str, Any]]:
        session = self._session(f"morning-{stats.day}", at)
        prompts_before = len(approver.requests)
        found = self._call(gate, session, stats, "search_mail", {"query": "", "limit": 20})
        rows: list[dict[str, Any]] = found.data or []
        for row in rows[:10]:
            self._call(gate, session, stats, "read_message", {"message_id": row["id"]})
        self._call(gate, session, stats, "list_events", {})
        known = [r for r in rows if session.is_known(r["sender"])]
        for row in known[:5]:
            args = {"message_id": row["id"], "body": "Thanks, will look today."}
            self._call(gate, session, stats, "draft_reply", args)
        self._end_session(session, stats, approver, prompts_before)
        return known

    def _afternoon(
        self,
        gate: Gate,
        stats: DayStats,
        at: datetime,
        approver: FakeApprover,
        known: list[dict[str, Any]],
    ) -> None:
        session = self._session(f"afternoon-{stats.day}", at)
        prompts_before = len(approver.requests)
        for row in known[:2]:
            args = {"to": [row["sender"]], "subject": f"Re: {row['subject']}", "body": "Done."}
            self._call(gate, session, stats, "send_mail", args, in_thread_known=True)
        day = at.replace(hour=0)
        slot = {"start": (day + timedelta(hours=17)).isoformat(),
                "end": (day + timedelta(hours=18)).isoformat()}  # fmt: skip
        internal = {"title": "1:1", "attendees": [CONTACTS[0]], **slot}
        external = {"title": "Follow-up", "attendees": [CONTACTS[1], "buyer@customer.test"], **slot}
        self._call(gate, session, stats, "create_event", internal)
        self._call(gate, session, stats, "create_event", external)
        self._end_session(session, stats, approver, prompts_before)

    def _call(
        self,
        gate: Gate,
        session: Session,
        stats: DayStats,
        tool: str,
        args: dict[str, Any],
        in_thread_known: bool = False,
    ) -> Any:
        clean_verdict = self._clean_verdict(session, tool, args)
        result = gate.handle(session, tool, args)
        stats.calls += 1
        if result.verdict == Verdict.DENY:
            stats.blocked += 1
        if result.verdict == Verdict.ASK:
            stats.prompts += 1
            stats.taint_only_prompts += clean_verdict not in (Verdict.ASK, Verdict.DENY)
            stats.in_thread_known_send_prompts += in_thread_known
        return result

    def _clean_verdict(self, session: Session, tool: str, args: dict[str, Any]) -> Verdict:
        """What the profile would say for this call if the session were not tainted."""
        parsed = ARG_MODELS[tool].model_validate(args)
        facts = constraints_for(session, parsed).model_dump()
        facts["tainted"] = False
        action = Action(tool=tool, resource=RESOURCES[tool], constraints=Constraints(**facts))
        return evaluate(self.profile, action).verdict

    def _end_session(
        self, session: Session, stats: DayStats, approver: FakeApprover, prompts_before: int
    ) -> None:
        stats.sessions_with_prompt += len(approver.requests) > prompts_before
        if session.tainted:
            stats.tainted_sessions += 1
            if session.taint_reason not in stats.taint_reasons:
                stats.taint_reasons.append(session.taint_reason)


def simulate(profile: ProfileName, days: int, seed: int = 7) -> list[DayStats]:
    return Runner(profile, seed).run(days)


def format_table(profile: str, rows: list[DayStats]) -> str:
    head = f"{'day':>3} {'calls':>5} {'prompts':>7} {'taint-only':>10} {'blocked':>7} " \
           f"{'tainted':>7}  tainted by"  # fmt: skip
    lines = [f"profile: {profile}", head]
    for r in rows:
        reasons = "; ".join(r.taint_reasons) or "-"
        lines.append(
            f"{r.day:>3} {r.calls:>5} {r.prompts:>7} {r.taint_only_prompts:>10} "
            f"{r.blocked:>7} {r.tainted_sessions:>5}/2  {reasons}"
        )
    n = len(rows) or 1
    avg = sum(r.prompts for r in rows) / n
    lines.append(f"avg prompts/day: {avg:.1f}  (target: under 5)")
    batched = sum(r.sessions_with_prompt for r in rows) / n
    thread = sum(r.prompts - r.in_thread_known_send_prompts for r in rows) / n
    no_taint = sum(r.prompts - r.taint_only_prompts for r in rows) / n
    lines.append(
        f"what-if avg/day: one prompt per session {batched:.1f}; "
        f"in-thread known replies exempt {thread:.1f}; no taint at all {no_taint:.1f}"
    )
    return "\n".join(lines)
