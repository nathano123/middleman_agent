from broker.cli import main
from broker.sim import CONTACTS, format_table, generate_day, simulate
from broker.taint import Contacts


def test_generated_day_has_the_stated_shape() -> None:
    day = generate_day(seed=7, index=0)
    assert len(day.messages) == 60
    contacts = Contacts("me@home.test", frozenset(), frozenset(CONTACTS))
    known = [m for m in day.messages if contacts.is_known(m.sender)]
    bulk = [m for m in day.messages if m.list_unsubscribe]
    assert len(known) == 36
    assert len(bulk) == 12
    assert len(day.events) == 6
    with_outside = [e for e in day.events if any(not contacts.is_known(a) for a in e.attendees)]
    assert len(with_outside) == 2


def test_generation_is_deterministic() -> None:
    assert generate_day(7, 3) == generate_day(7, 3)
    assert generate_day(7, 3) != generate_day(8, 3)


def test_every_profile_runs_the_full_script() -> None:
    for profile in ("cautious", "working", "autonomous"):
        rows = simulate(profile, days=2)
        assert len(rows) == 2
        assert all(r.calls == 21 for r in rows)  # 1 + 10 + 1 + 5 morning, 2 + 2 afternoon


def test_working_profile_stays_under_prompt_budget() -> None:
    """Regression guard for the validation target (under 5 prompts a day). A finding, not a law:
    if a safety fix pushes this over 5, report it rather than loosening the fix."""
    rows = simulate("working", days=7)
    assert sum(r.prompts for r in rows) / len(rows) < 5


def test_autonomous_tainted_sends_still_prompt() -> None:
    rows = simulate("autonomous", days=3)
    assert all(r.tainted_sessions > 0 for r in rows)
    assert all(r.prompts >= 2 for r in rows)  # the two sends
    assert all(r.blocked == 0 for r in rows)


def test_table_and_cli() -> None:
    text = format_table("working", simulate("working", days=1))
    assert "avg prompts/day" in text
    assert main(["simulate", "--profile", "all", "--days", "1"]) == 0
