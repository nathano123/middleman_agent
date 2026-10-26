from pathlib import Path

import pytest

from broker.rules.evaluator import (
    PROFILE_NAMES,
    ProfileError,
    evaluate,
    load_profile,
    load_profile_file,
)
from broker.rules.models import Action, Constraints, Profile, Resource, Rule, Verdict

ALLOW = Verdict.ALLOW
REDACTED = Verdict.ALLOW_REDACTED
ASK = Verdict.ASK
DENY = Verdict.DENY

RESOURCE: dict[str, Resource] = {
    "search_mail": "mail",
    "read_message": "mail",
    "draft_reply": "mail",
    "send_mail": "mail",
    "list_events": "calendar",
    "create_event": "calendar",
}


def act(tool: str, **facts: bool) -> Action:
    return Action(tool=tool, resource=RESOURCE.get(tool), constraints=Constraints(**facts))


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "p.yaml"
    path.write_text(text, encoding="utf-8")
    return path


# --- loading -----------------------------------------------------------------


@pytest.mark.parametrize("name", PROFILE_NAMES)
def test_every_profile_loads(name: str) -> None:
    profile = load_profile(name)
    assert profile.name == name
    assert profile.rules


def test_unknown_profile_name_refused() -> None:
    with pytest.raises(ProfileError):
        load_profile("yolo")


@pytest.mark.parametrize(
    "text",
    [
        "name: x\nrules: [",  # broken YAML syntax
        "just a string",  # not a mapping
        "name: x\nrules: []",  # no rules
        "name: x\nrules:\n  - {tool: send_mail, decision: maybe, reason: r}",  # bad verdict
        "name: x\nrules:\n  - {tool: forward_mail, decision: allow, reason: r}",  # unknown tool
        "name: x\nrules:\n  - {tool: send_mail, decision: allow, reason: r, when: {vip: true}}",
        "name: x\nrules:\n  - {tool: send_mail, decision: allow, reason: r, priority: 9}",
        "name: x\nrules:\n  - {tool: send_mail, decision: allow}",  # missing reason
        "name: x\nextra: 1\nrules:\n  - {tool: send_mail, decision: allow, reason: r}",
    ],
)
def test_malformed_yaml_refuses_to_load(tmp_path: Path, text: str) -> None:
    with pytest.raises(ProfileError):
        load_profile_file(write(tmp_path, text))


def test_missing_file_refuses_to_load(tmp_path: Path) -> None:
    with pytest.raises(ProfileError):
        load_profile_file(tmp_path / "nope.yaml")


# --- deny by default ---------------------------------------------------------


@pytest.mark.parametrize("name", PROFILE_NAMES)
@pytest.mark.parametrize("tool", ["forward_mail", "delete_message", "share_calendar", ""])
def test_unknown_tool_denied(name: str, tool: str) -> None:
    assert evaluate(load_profile(name), act(tool)).verdict == DENY


def test_unmatched_known_tool_denied() -> None:
    profile = Profile(name="t", rules=[Rule(tool="search_mail", decision=ALLOW, reason="r")])
    assert evaluate(profile, act("send_mail")).verdict == DENY


def test_resource_mismatch_denied() -> None:
    profile = Profile(
        name="t",
        rules=[Rule(tool="search_mail", resource="mail", decision=ALLOW, reason="r")],
    )
    action = Action(tool="search_mail", resource="calendar")
    assert evaluate(profile, action).verdict == DENY


def test_create_event_on_someone_elses_calendar_denied() -> None:
    assert evaluate(load_profile("working"), act("create_event")).verdict == DENY


# --- the working profile matches the v0 tool table ---------------------------


@pytest.mark.parametrize(
    ("tool", "facts", "expected"),
    [
        ("search_mail", {}, ALLOW),
        ("search_mail", {"tainted": True}, ALLOW),
        ("read_message", {}, REDACTED),
        ("read_message", {"tainted": True}, REDACTED),
        ("list_events", {}, ALLOW),
        ("draft_reply", {}, ALLOW),
        ("draft_reply", {"tainted": True}, ALLOW),
        ("send_mail", {}, ASK),
        ("send_mail", {"outside_recipients": True}, ASK),
        ("send_mail", {"tainted": True, "outside_recipients": True}, ASK),
        ("create_event", {"own_calendar": True}, ALLOW),
        ("create_event", {"own_calendar": True, "outside_attendees": True}, ASK),
        ("create_event", {"own_calendar": True, "tainted": True}, ASK),
        ("create_event", {"own_calendar": True, "tainted": True, "outside_attendees": True}, ASK),
    ],
)
def test_working_profile_matches_tool_table(
    tool: str, facts: dict[str, bool], expected: Verdict
) -> None:
    assert evaluate(load_profile("working"), act(tool, **facts)).verdict == expected


def test_cautious_denies_tainted_send() -> None:
    profile = load_profile("cautious")
    assert evaluate(profile, act("send_mail")).verdict == ASK
    assert evaluate(profile, act("send_mail", tainted=True)).verdict == DENY


def test_autonomous_never_lets_tainted_session_send_unapproved() -> None:
    profile = load_profile("autonomous")
    assert evaluate(profile, act("send_mail", outside_recipients=True)).verdict == ALLOW
    tainted = act("send_mail", tainted=True, outside_recipients=True)
    assert evaluate(profile, tainted).verdict == ASK


@pytest.mark.parametrize("name", PROFILE_NAMES)
def test_no_profile_lets_tainted_session_send_without_approval(name: str) -> None:
    for outside in (True, False):
        action = act("send_mail", tainted=True, outside_recipients=outside)
        assert evaluate(load_profile(name), action).verdict in (ASK, DENY)


# --- a rule can never widen another rule's deny ------------------------------


def test_allow_cannot_widen_deny_in_either_order() -> None:
    deny = Rule(tool="send_mail", decision=DENY, reason="no")
    allow = Rule(tool="send_mail", decision=ALLOW, reason="yes")
    for rules in ([deny, allow], [allow, deny]):
        decision = evaluate(Profile(name="t", rules=rules), act("send_mail"))
        assert decision.verdict == DENY
        assert decision.reason == "no"


def test_conditional_deny_beats_unconditional_allow() -> None:
    rules = [
        Rule(tool="send_mail", decision=ALLOW, reason="yes"),
        Rule(tool="send_mail", when={"tainted": True}, decision=DENY, reason="tainted"),
    ]
    profile = Profile(name="t", rules=rules)
    assert evaluate(profile, act("send_mail")).verdict == ALLOW
    assert evaluate(profile, act("send_mail", tainted=True)).verdict == DENY


def test_strictest_of_several_matches_wins() -> None:
    rules = [
        Rule(tool="read_message", decision=ALLOW, reason="a"),
        Rule(tool="read_message", decision=ASK, reason="b"),
        Rule(tool="read_message", decision=REDACTED, reason="c"),
    ]
    assert evaluate(Profile(name="t", rules=rules), act("read_message")).verdict == ASK


def test_decision_carries_reason() -> None:
    decision = evaluate(load_profile("working"), act("send_mail"))
    assert decision.reason == "every send needs approval"
