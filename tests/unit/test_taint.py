from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from broker.approvals.history import MemoryApprovalHistory
from broker.backends.base import AuthResult, Message
from broker.rules.evaluator import evaluate, load_profile
from broker.rules.models import Action, Constraints, Verdict
from broker.taint import (
    Contacts,
    MemoryTaintStore,
    Session,
    SQLiteTaintStore,
    TaintStore,
    distrust,
    normalize_address,
    taint_on_list_events,
    taint_on_read_message,
    taint_on_search,
)
from tests.conftest import FakeClock

CONTACTS = Contacts(
    own_address="me@home.test",
    self_addresses=frozenset({"me.work@office.test"}),
    known_contacts=frozenset({"Alice@Work.test", "bob@work.test"}),
)


def msg(
    sender: str,
    reply_to: str = "",
    auth: AuthResult = "unknown",
    snippet: str = "hi",
) -> Message:
    return Message(
        "m",
        sender,
        ["me@home.test"],
        "s",
        "d",
        snippet,
        "body",
        reply_to=reply_to,
        auth_result=auth,
    )


def new_session(store: TaintStore | None = None, clock: FakeClock | None = None) -> Session:
    store = store or MemoryTaintStore()
    return Session("s1", "default", CONTACTS, store, MemoryApprovalHistory(), clock or FakeClock())


# --- who is trusted ----------------------------------------------------------


def test_known_contact_own_address_and_alias_are_trusted() -> None:
    for sender in ("alice@work.test", '"Bob" <BOB@work.test>', "me@home.test"):
        assert distrust(CONTACTS, msg(sender)) is None
    assert distrust(CONTACTS, msg("me.work@office.test")) is None


def test_unknown_and_lookalike_senders_are_untrusted() -> None:
    assert distrust(CONTACTS, msg("stranger@evil.test")) == "from an unknown sender"
    assert distrust(CONTACTS, msg('"Alice" <alice@w0rk.test>')) == "from an unknown sender"
    assert distrust(CONTACTS, msg("")) == "from an unknown sender"


def test_auth_fail_makes_known_contact_untrusted() -> None:
    assert "failed authentication" in str(distrust(CONTACTS, msg("bob@work.test", auth="fail")))
    assert distrust(CONTACTS, msg("bob@work.test", auth="pass")) is None
    assert distrust(CONTACTS, msg("bob@work.test", auth="unknown")) is None


def test_reply_to_outside_makes_known_contact_untrusted() -> None:
    why = distrust(CONTACTS, msg("alice@work.test", reply_to="pay@evil.test"))
    assert why == "whose reply-to is an outside address"
    assert distrust(CONTACTS, msg("alice@work.test", reply_to="bob@work.test")) is None
    assert distrust(CONTACTS, msg("alice@work.test", reply_to="ALICE@work.test")) is None


def test_normalize_address() -> None:
    assert normalize_address('"X Y" <X@Y.test>') == "x@y.test"
    assert normalize_address("  a@b.test ") == "a@b.test"


# --- taint events ------------------------------------------------------------


def test_new_session_is_clean() -> None:
    session = new_session()
    assert not session.tainted
    assert session.taint_reason == ""


def test_taint_set_on_unknown_sender_not_on_known() -> None:
    session = new_session()
    taint_on_read_message(session, msg("alice@work.test"))
    assert not session.tainted
    taint_on_read_message(session, msg("stranger@evil.test"))
    assert session.taint_reason == "read a message from an unknown sender"


def test_first_reason_is_kept() -> None:
    session = new_session()
    session.mark_tainted("first")
    session.mark_tainted("second")
    assert session.taint_reason == "first"


def test_search_taints_on_untrusted_snippet_only() -> None:
    session = new_session()
    taint_on_search(session, [msg("alice@work.test"), msg("stranger@evil.test", snippet=" ")])
    assert not session.tainted
    taint_on_search(session, [msg("alice@work.test"), msg("stranger@evil.test")])
    assert "snippet" in session.taint_reason


def test_list_events_taints_on_outside_organizer() -> None:
    session = new_session()
    taint_on_list_events(session, ["alice@work.test"])
    assert not session.tainted
    taint_on_list_events(session, ["promo@outside.test"])
    assert session.tainted


# --- agent-level store -------------------------------------------------------


def stores(tmp_path: Path) -> list[TaintStore]:
    return [MemoryTaintStore(), SQLiteTaintStore(tmp_path / "taint.db")]


@pytest.mark.parametrize("kind", [0, 1])
def test_taint_shared_by_sessions_of_same_agent(tmp_path: Path, kind: int) -> None:
    store = stores(tmp_path)[kind]
    clock = FakeClock()
    first = new_session(store, clock)
    taint_on_read_message(first, msg("stranger@evil.test"))
    second = Session("s2", "default", CONTACTS, store, MemoryApprovalHistory(), clock)
    other_agent = Session("s3", "mail-bot", CONTACTS, store, MemoryApprovalHistory(), clock)
    assert second.tainted
    assert not other_agent.tainted


@pytest.mark.parametrize("kind", [0, 1])
def test_taint_expires_only_after_quiet_period(tmp_path: Path, kind: int) -> None:
    store = stores(tmp_path)[kind]
    clock = FakeClock()
    new_session(store, clock).mark_tainted("x")
    clock.advance(20)
    new_session(store, clock).mark_tainted("y")  # a new event restarts the clock
    clock.advance(23)
    assert new_session(store, clock).tainted
    assert new_session(store, clock).taint_reason == "x"
    clock.advance(1.01)
    assert not new_session(store, clock).tainted


@pytest.mark.parametrize("kind", [0, 1])
def test_clear_removes_agent_taint(tmp_path: Path, kind: int) -> None:
    store = stores(tmp_path)[kind]
    clock = FakeClock()
    new_session(store, clock).mark_tainted("x")
    assert store.clear("default")
    assert not store.clear("default")
    assert not new_session(store, clock).tainted


def test_taint_never_clears_inside_a_live_session() -> None:
    store = MemoryTaintStore()
    clock = FakeClock()
    session = new_session(store, clock)
    session.mark_tainted("x")
    store.clear("default")
    clock.advance(48)
    assert session.tainted  # the live session keeps it; a new connection starts clean
    assert not new_session(store, clock).tainted


def test_sqlite_store_survives_reopen(tmp_path: Path) -> None:
    now = datetime(2026, 10, 27, tzinfo=UTC)
    store = SQLiteTaintStore(tmp_path / "taint.db")
    store.mark("default", "x", now)
    store.close()
    reopened = SQLiteTaintStore(tmp_path / "taint.db", quiet=timedelta(hours=24))
    record = reopened.get("default", now + timedelta(hours=1))
    assert record is not None and record.reason == "x"


# --- taint changes decisions -------------------------------------------------


def _decide(profile: str, session: Session, tool: str, **facts: bool) -> Verdict:
    resource = "mail" if tool == "send_mail" else "calendar"
    constraints = Constraints(tainted=session.tainted, **facts)
    action = Action(tool=tool, resource=resource, constraints=constraints)
    return evaluate(load_profile(profile), action).verdict


def test_taint_changes_send_mail_decision() -> None:
    session = new_session()
    assert _decide("cautious", session, "send_mail") == Verdict.ASK
    taint_on_read_message(session, msg("stranger@evil.test"))
    assert _decide("cautious", session, "send_mail") == Verdict.DENY


def test_taint_changes_create_event_decision() -> None:
    session = new_session()
    assert _decide("working", session, "create_event", own_calendar=True) == Verdict.ALLOW
    taint_on_read_message(session, msg("stranger@evil.test"))
    assert _decide("working", session, "create_event", own_calendar=True) == Verdict.ASK
