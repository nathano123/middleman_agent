"""Shared harness: builds a gate over the seeded fixture and checks invariants after each test.

Invariants checked after every test that used `world`:
- no message body, subject, snippet or event description from the fixture is in the log file;
- every mail the backend sent has an approved prompt showing exactly its recipients, subject
  and first 200 characters of body;
- every event created with outside attendees has such a prompt too;
- every approved prompt corresponds to something the backend actually did.
"""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from broker.approvals.base import BODY_PREVIEW_CHARS, ApprovalOutcome, ApprovalRequest
from broker.approvals.fake import FakeApprover
from broker.audit import AuditLog
from broker.backends.fake import FakeBackend
from broker.config import BrokerConfig, ProfileName
from broker.gate import Gate, Result
from broker.rules.evaluator import load_profile
from broker.taint import Contacts, MemoryTaintStore, Session, normalize_address

FIXTURE = Path(__file__).parent / "fixtures" / "mailbox.json"
OWN_ADDRESS = "me@home.test"
KNOWN_CONTACTS = frozenset({"alice@work.test", "bob@work.test", "carol@partner.test"})


START = datetime(2026, 10, 27, 9, 0, tzinfo=UTC)


@dataclass
class FakeClock:
    now: datetime = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, hours: float) -> None:
        self.now += timedelta(hours=hours)


@dataclass
class World:
    gate: Gate
    session: Session
    backend: FakeBackend
    approver: FakeApprover
    log: AuditLog
    log_path: Path
    config: BrokerConfig
    store: MemoryTaintStore
    clock: FakeClock

    def call(self, tool: str, **args: object) -> Result:
        return self.gate.handle(self.session, tool, dict(args))

    def reconnect(self) -> None:
        """Simulate the same agent opening a new connection: a fresh Session, same agent id."""
        old = self.session
        self.session = Session(
            f"{old.session_id}+", old.agent_id, old.contacts, self.store, self.clock
        )


WorldFactory = Callable[..., World]


def fixture_texts() -> list[str]:
    backend = FakeBackend.from_fixture(FIXTURE)
    texts = [t for m in backend.messages for t in (m.body, m.subject, m.snippet)]
    texts += [e.description for e in backend.events if e.description]
    return texts


def build_world(
    tmp_path: Path,
    profile: ProfileName = "working",
    messages: list[str] | None = None,
    events: list[str] | None = None,
    script: list[ApprovalOutcome] | None = None,
    default: ApprovalOutcome = ApprovalOutcome.DENIED,
    self_addresses: list[str] | None = None,
    views_full_body: bool = False,
) -> World:
    backend = FakeBackend.from_fixture(FIXTURE)
    if messages is not None:
        backend.messages = [m for m in backend.messages if m.id in messages]
    if events is not None:
        backend.events = [e for e in backend.events if e.id in events]
    approver = FakeApprover(
        script=list(script or []), default=default, views_full_body=views_full_body
    )
    log_path = tmp_path / f"audit-{profile}.db"
    log = AuditLog(log_path)
    config = BrokerConfig(
        own_address=OWN_ADDRESS,
        self_addresses=tuple(self_addresses or ()),
        known_contacts=tuple(sorted(KNOWN_CONTACTS)),
        profile=profile,
        state_dir=tmp_path,
    )
    contacts = Contacts(
        config.own_address, frozenset(config.self_addresses), frozenset(config.known_contacts)
    )
    store = MemoryTaintStore(timedelta(hours=config.taint_quiet_hours))
    clock = FakeClock()
    session = Session("sess-1", "default", contacts, store, clock)
    gate = Gate(load_profile(profile), backend, approver, log, config)
    return World(gate, session, backend, approver, log, log_path, config, store, clock)


def matches(req: ApprovalRequest, recipients: list[str], subject: str, body: str) -> bool:
    return (
        req.recipients == [normalize_address(r) for r in recipients]
        and req.subject == subject
        and req.body_preview == body[:BODY_PREVIEW_CHARS]
    )


def approved_requests(world: World) -> list[ApprovalRequest]:
    """Prompts the gate accepted: approved, and full body opened when that was required."""
    a = world.approver
    triples = zip(a.requests, a.answers, a.viewed, strict=True)
    return [
        req
        for req, answer, viewed in triples
        if answer == ApprovalOutcome.APPROVED and (viewed or not req.requires_full_view)
    ]


def check_invariants(world: World) -> None:
    raw = world.log_path.read_bytes()
    for text in fixture_texts():
        assert text.encode("utf-8") not in raw, f"fixture content leaked into log: {text[:40]!r}"

    approved = approved_requests(world)
    for mail in world.backend.sent:
        assert any(
            r.tool == "send_mail" and matches(r, mail.to + mail.cc, mail.subject, mail.body)
            for r in approved
        ), f"mail sent without a matching approved prompt: {mail.to}"
    for event in world.backend.created_events:
        outside = [a for a in event.attendees if not world.session.is_known(a)]
        if outside:
            assert any(
                r.tool == "create_event"
                and matches(r, event.attendees, event.title, event.description)
                for r in approved
            ), f"event with outside attendees created without approval: {outside}"
    for req in approved:
        did_send = any(matches(req, m.to + m.cc, m.subject, m.body) for m in world.backend.sent)
        did_create = any(
            matches(req, e.attendees, e.title, e.description) for e in world.backend.created_events
        )
        assert did_send or did_create, "approved prompt does not match any real action"


@pytest.fixture
def world(tmp_path: Path) -> Iterator[WorldFactory]:
    built: list[World] = []

    def factory(
        profile: ProfileName = "working",
        messages: list[str] | None = None,
        events: list[str] | None = None,
        script: list[ApprovalOutcome] | None = None,
        default: ApprovalOutcome = ApprovalOutcome.DENIED,
        self_addresses: list[str] | None = None,
        views_full_body: bool = False,
    ) -> World:
        w = build_world(
            tmp_path, profile, messages, events, script, default, self_addresses, views_full_body
        )
        built.append(w)
        return w

    yield factory
    for w in built:
        w.log.close()
        check_invariants(w)
