import sqlite3
from pathlib import Path

import pytest

from broker.approvals.base import ApprovalOutcome
from broker.audit import verify
from broker.config import ProfileName
from broker.rules.models import Verdict
from tests.conftest import WorldFactory, build_world, check_invariants


def log_rows(path: object) -> list[tuple[str, str]]:
    conn = sqlite3.connect(str(path))
    rows: list[tuple[str, str]] = conn.execute(
        "SELECT tool, decision FROM log ORDER BY id"
    ).fetchall()
    conn.close()
    return rows


def test_search_returns_minimized_headers(world: WorldFactory) -> None:
    w = world()
    result = w.call("search_mail", query="lunch")
    assert result.ok
    assert result.verdict == Verdict.ALLOW
    assert set(result.data[0]) == {"id", "sender", "subject", "date", "snippet"}


def test_read_known_contact_is_redacted_and_clean(world: WorldFactory) -> None:
    w = world()
    result = w.call("read_message", message_id="m_lunch")
    assert result.verdict == Verdict.ALLOW_REDACTED
    assert "555" not in result.data["body"]
    assert not w.session.tainted


def test_read_missing_message(world: WorldFactory) -> None:
    w = world()
    result = w.call("read_message", message_id="nope")
    assert not result.ok
    assert not w.session.tainted


def test_invalid_arguments_denied(world: WorldFactory) -> None:
    w = world()
    assert w.call("send_mail", to=[], subject="s", body="b").verdict == Verdict.DENY
    assert w.call("send_mail", to=["a@x.test"], subject="s", body="b", bcc=["x"]).verdict == (
        Verdict.DENY
    )
    assert w.call("search_mail", limit=10_000).verdict == Verdict.DENY
    assert w.approver.requests == []


def test_unknown_tool_denied_and_logged(world: WorldFactory) -> None:
    w = world()
    result = w.call("delete_message", message_id="m_lunch")
    assert result.verdict == Verdict.DENY
    assert log_rows(w.log_path) == [("delete_message", "deny")]


def test_send_asks_and_sends_only_when_approved(world: WorldFactory) -> None:
    w = world(script=[ApprovalOutcome.APPROVED, ApprovalOutcome.DENIED])
    first = w.call("send_mail", to=["alice@work.test"], subject="Lunch", body="Yes, 12:30.")
    second = w.call("send_mail", to=["alice@work.test"], subject="Lunch", body="Actually no.")
    assert first.ok and first.approval == ApprovalOutcome.APPROVED
    assert not second.ok and second.approval == ApprovalOutcome.DENIED
    assert [m.body for m in w.backend.sent] == ["Yes, 12:30."]


def test_draft_reply_never_sends(world: WorldFactory) -> None:
    w = world()
    result = w.call("draft_reply", message_id="m_lunch", body="Sounds good")
    assert result.ok
    assert w.backend.sent == []
    assert len(w.backend.drafts) == 1


def test_own_calendar_event_allowed_without_prompt(world: WorldFactory) -> None:
    w = world()
    result = w.call("create_event", title="Focus", start="s", end="e")
    assert result.ok
    assert w.approver.requests == []


def test_event_on_other_calendar_denied(world: WorldFactory) -> None:
    w = world()
    result = w.call("create_event", calendar_id="team", title="x", start="s", end="e")
    assert result.verdict == Verdict.DENY


def test_every_call_logged_and_chain_verifies(world: WorldFactory) -> None:
    w = world()
    w.call("search_mail")
    w.call("read_message", message_id="m_lunch")
    w.call("list_events")
    w.call("forward_message", message_id="m_lunch")
    w.call("send_mail", to=["alice@work.test"], subject="s", body="b")
    assert [tool for tool, _ in log_rows(w.log_path)] == [
        "search_mail",
        "read_message",
        "list_events",
        "forward_message",
        "send_mail",
    ]
    assert verify(w.log_path) is None


def test_invariant_checker_catches_unapproved_send(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    w.backend.send_message(["collect@evil.test"], [], "s", "b", None)  # bypasses the gate
    w.log.close()
    with pytest.raises(AssertionError, match="without a matching approved prompt"):
        check_invariants(w)


def test_invariant_checker_catches_content_in_log(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    w.log._conn.execute(  # pyright: ignore[reportPrivateUsage]
        "INSERT INTO log VALUES (99, 't', 's', 'x', 'allow', 'Lunch Thursday?', '{}', '', '')"
    )
    w.log._conn.commit()  # pyright: ignore[reportPrivateUsage]
    w.log.close()
    with pytest.raises(AssertionError, match="leaked into log"):
        check_invariants(w)


VALID_ARGS: dict[str, dict[str, object]] = {
    "search_mail": {"query": ""},
    "read_message": {"message_id": "m_lunch"},
    "list_events": {},
    "draft_reply": {"message_id": "m_lunch", "body": "ok"},
    "send_mail": {"to": ["alice@work.test"], "subject": "s", "body": "b"},
    "create_event": {"title": "t", "start": "s", "end": "e", "attendees": ["x@out.test"]},
}


@pytest.mark.parametrize("profile", ["cautious", "working", "autonomous"])
@pytest.mark.parametrize("tainted", [False, True])
@pytest.mark.parametrize("tool", sorted(VALID_ARGS))
def test_handle_never_raises_for_any_profile_tool_taint(
    tmp_path: Path, profile: ProfileName, tainted: bool, tool: str
) -> None:
    """Regression: cautious + tainted + draft_reply used to crash in the prompt builder.

    Built without the attack-invariant fixture: autonomous may send unprompted when clean.
    """
    w = build_world(tmp_path, profile, ["m_lunch", "m_forward"], None, None)
    if tainted:
        w.call("read_message", message_id="m_forward")
    w.call(tool, **VALID_ARGS[tool])
