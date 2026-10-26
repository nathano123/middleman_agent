from datetime import date
from pathlib import Path

import pytest

from broker.approvals.base import ApprovalOutcome
from broker.approvals.history import (
    ApprovalHistory,
    MemoryApprovalHistory,
    SQLiteApprovalHistory,
)
from tests.conftest import WorldFactory

DAY = date(2026, 10, 27)
NEXT = date(2026, 10, 28)


def histories(tmp_path: Path) -> list[ApprovalHistory]:
    return [MemoryApprovalHistory(), SQLiteApprovalHistory(tmp_path / "history.db")]


@pytest.mark.parametrize("kind", [0, 1])
def test_counts_per_agent_per_day(tmp_path: Path, kind: int) -> None:
    h = histories(tmp_path)[kind]
    for _ in range(3):
        h.record_prompt("default", DAY)
    h.record_prompt("mail-bot", DAY)
    assert h.prompts("default", DAY) == 3
    assert h.prompts("mail-bot", DAY) == 1
    assert h.prompts("default", NEXT) == 0


@pytest.mark.parametrize("kind", [0, 1])
def test_approved_recipients_per_agent_per_day(tmp_path: Path, kind: int) -> None:
    h = histories(tmp_path)[kind]
    h.add_approved("default", DAY, ["a@x.test", "b@x.test"])
    h.add_approved("default", DAY, ["a@x.test"])
    assert h.approved("default", DAY) == {"a@x.test", "b@x.test"}
    assert h.approved("mail-bot", DAY) == frozenset()
    assert h.approved("default", NEXT) == frozenset()


def test_sqlite_history_survives_reopen(tmp_path: Path) -> None:
    h = SQLiteApprovalHistory(tmp_path / "history.db")
    h.record_prompt("default", DAY)
    h.add_approved("default", DAY, ["a@x.test"])
    h.close()
    again = SQLiteApprovalHistory(tmp_path / "history.db")
    assert again.prompts("default", DAY) == 1
    assert again.approved("default", DAY) == {"a@x.test"}


def test_counter_starts_fresh_the_next_day(world: WorldFactory) -> None:
    w = world(default=ApprovalOutcome.APPROVED, views_full_body=True)
    for _ in range(11):
        w.call("send_mail", to=["alice@work.test"], subject="s", body="b")
    assert w.approver.requests[-1].approval_number == 11
    w.clock.advance(24)
    w.reconnect()
    w.call("send_mail", to=["alice@work.test"], subject="s", body="b")
    req = w.approver.requests[-1]
    assert req.approval_number == 1
    assert not req.requires_full_view
    assert req.new_recipients == ["alice@work.test"]
