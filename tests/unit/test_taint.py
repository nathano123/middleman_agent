from broker.rules.evaluator import evaluate, load_profile
from broker.rules.models import Action, Constraints, Verdict
from broker.taint import (
    Session,
    normalize_address,
    taint_on_list_events,
    taint_on_read_message,
    taint_on_search,
)


def new_session() -> Session:
    return Session(
        session_id="s1",
        own_address="me@home.test",
        known_contacts=frozenset({"Alice@Work.test", "bob@work.test"}),
    )


def test_new_session_is_clean() -> None:
    session = new_session()
    assert not session.tainted
    assert session.taint_reason == ""


def test_taint_set_on_unknown_sender() -> None:
    session = new_session()
    taint_on_read_message(session, "stranger@evil.test")
    assert session.tainted
    assert "unknown sender" in session.taint_reason


def test_taint_not_set_on_known_contact() -> None:
    session = new_session()
    taint_on_read_message(session, "alice@work.test")
    taint_on_read_message(session, '"Bob" <BOB@work.test>')
    taint_on_read_message(session, "me@home.test")
    assert not session.tainted


def test_display_name_is_ignored() -> None:
    session = new_session()
    taint_on_read_message(session, '"Alice" <alice@w0rk.test>')
    assert session.tainted


def test_empty_sender_taints() -> None:
    session = new_session()
    taint_on_read_message(session, "")
    assert session.tainted


def test_taint_survives_later_calls() -> None:
    session = new_session()
    taint_on_read_message(session, "stranger@evil.test")
    for _ in range(50):
        taint_on_read_message(session, "alice@work.test")
        taint_on_list_events(session, ["alice@work.test"])
    assert session.tainted
    assert "unknown sender" in session.taint_reason


def test_first_reason_is_kept() -> None:
    session = new_session()
    session.mark_tainted("first")
    session.mark_tainted("second")
    assert session.taint_reason == "first"


def test_list_events_taints_on_outside_organizer() -> None:
    session = new_session()
    taint_on_list_events(session, ["alice@work.test"])
    assert not session.tainted
    taint_on_list_events(session, ["alice@work.test", "promo@outside.test"])
    assert session.tainted


def test_normalize_address() -> None:
    assert normalize_address('"X Y" <X@Y.test>') == "x@y.test"
    assert normalize_address("  a@b.test ") == "a@b.test"


def _decide(session: Session, tool: str, **facts: bool) -> Verdict:
    resource = "mail" if tool == "send_mail" else "calendar"
    constraints = Constraints(tainted=session.tainted, **facts)
    action = Action(tool=tool, resource=resource, constraints=constraints)
    return evaluate(load_profile("working"), action).verdict


def test_taint_changes_send_mail_decision() -> None:
    cautious = load_profile("cautious")
    session = new_session()
    action = Action(tool="send_mail", resource="mail", constraints=Constraints(tainted=False))
    assert evaluate(cautious, action).verdict == Verdict.ASK
    taint_on_read_message(session, "stranger@evil.test")
    action = Action(tool="send_mail", resource="mail", constraints=Constraints(tainted=True))
    assert evaluate(cautious, action).verdict == Verdict.DENY


def test_taint_changes_create_event_decision() -> None:
    session = new_session()
    assert _decide(session, "create_event", own_calendar=True) == Verdict.ALLOW
    taint_on_read_message(session, "stranger@evil.test")
    assert _decide(session, "create_event", own_calendar=True) == Verdict.ASK
    assert (
        _decide(session, "create_event", own_calendar=True, outside_attendees=True) == Verdict.ASK
    )


def test_search_taints_on_unknown_sender_snippet() -> None:
    session = new_session()
    taint_on_search(session, ['"Alice" <alice@work.test>', "bob@work.test"])
    assert not session.tainted
    taint_on_search(session, ["alice@work.test", "stranger@evil.test"])
    assert session.tainted
    assert "snippet" in session.taint_reason


def test_empty_search_does_not_taint() -> None:
    session = new_session()
    taint_on_search(session, [])
    assert not session.tainted
