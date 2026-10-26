import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from broker.approvals.base import ApprovalOutcome, ApprovalRequest
from broker.approvals.queue import ApprovalQueue, QueueApprover, QueueError
from broker.cli import main
from broker.rules.models import Verdict
from tests.conftest import build_world

T0 = datetime(2026, 10, 27, 9, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = T0
        self.on_tick: Callable[[datetime], None] | None = None

    def __call__(self) -> datetime:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)
        if self.on_tick:
            self.on_tick(self.now)


def req(body: str = "b", full_view: bool = False) -> ApprovalRequest:
    return ApprovalRequest(
        "s1", "send_mail", ["x@out.test"], "subj", body[:200], "why",
        full_body=body, requires_full_view=full_view,
        action_hash=hashlib.sha256(body.encode()).hexdigest(),
    )  # fmt: skip


def approver(tmp_path: Path, clock: Clock) -> tuple[ApprovalQueue, QueueApprover]:
    queue = ApprovalQueue(tmp_path / "approvals.db")
    return queue, QueueApprover(queue, "agt_1", wait_seconds=45, clock=clock, sleep=clock.sleep)


def test_answer_within_wait_is_returned(tmp_path: Path) -> None:
    clock = Clock()
    queue, appr = approver(tmp_path, clock)

    def user(now: datetime) -> None:
        if now >= T0 + timedelta(seconds=10):
            [item] = queue.pending(now)
            queue.decide(item.id, approve=True, now=now)
            clock.on_tick = None

    clock.on_tick = user
    response = appr.request(req())
    assert response.outcome == ApprovalOutcome.APPROVED
    assert response.new_prompt
    assert clock.now <= T0 + timedelta(seconds=11)


def test_no_answer_returns_pending_then_retry_finds_decision(tmp_path: Path) -> None:
    clock = Clock()
    queue, appr = approver(tmp_path, clock)
    first = appr.request(req())
    assert first.outcome == ApprovalOutcome.PENDING
    assert first.approval_id.startswith("apr_")
    queue.decide(first.approval_id, approve=True, now=clock())
    second = appr.request(req())  # the agent repeats the identical call
    assert second.outcome == ApprovalOutcome.APPROVED
    assert second.approval_id == first.approval_id
    assert not second.new_prompt


def test_approval_is_used_once(tmp_path: Path) -> None:
    clock = Clock()
    queue, appr = approver(tmp_path, clock)
    first = appr.request(req())
    queue.decide(first.approval_id, approve=True, now=clock())
    assert appr.request(req()).outcome == ApprovalOutcome.APPROVED
    again = appr.request(req())  # same action a second time: needs a new approval
    assert again.outcome == ApprovalOutcome.PENDING
    assert again.approval_id != first.approval_id
    assert again.new_prompt


def test_changed_arguments_are_a_new_request(tmp_path: Path) -> None:
    clock = Clock()
    queue, appr = approver(tmp_path, clock)
    first = appr.request(req("harmless"))
    queue.decide(first.approval_id, approve=True, now=clock())
    other = appr.request(req("the real payload"))
    assert other.outcome == ApprovalOutcome.PENDING
    assert other.approval_id != first.approval_id


def test_request_expires_after_five_minutes(tmp_path: Path) -> None:
    clock = Clock()
    queue, appr = approver(tmp_path, clock)
    first = appr.request(req())
    clock.now = T0 + timedelta(minutes=6)
    with pytest.raises(QueueError):
        queue.decide(first.approval_id, approve=True, now=clock())
    assert queue.get(first.approval_id).status == "expired"
    assert queue.get(first.approval_id).request is None  # content erased


def test_content_erased_once_used(tmp_path: Path) -> None:
    clock = Clock()
    queue, appr = approver(tmp_path, clock)
    first = appr.request(req("secret quarterly numbers"))
    queue.decide(first.approval_id, approve=False, now=clock())
    assert appr.request(req("secret quarterly numbers")).outcome == ApprovalOutcome.DENIED
    queue.close()
    assert b"secret quarterly numbers" not in (tmp_path / "approvals.db").read_bytes()


def write_config(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(f"own_address: me@home.test\nstate_dir: {tmp_path}\n", encoding="utf-8")
    return path


def test_cli_list_show_approve_with_full_view(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = write_config(tmp_path)
    queue = ApprovalQueue(tmp_path / "approvals.db")
    item, _ = queue.open("agt_1", req("z" * 3000, full_view=True), datetime.now(UTC))
    queue.close()
    assert main(["approvals", "list", "--config", str(config)]) == 0
    out = capsys.readouterr()
    assert item.id in out.out and "DEVELOPMENT ONLY" in out.err
    assert main(["approvals", "approve", item.id, "--config", str(config)]) == 1
    assert "open the full body first" in capsys.readouterr().out
    assert main(["approvals", "show", item.id, "--config", str(config)]) == 0
    assert "z" * 3000 in capsys.readouterr().out
    assert main(["approvals", "approve", item.id, "--config", str(config)]) == 0
    assert ApprovalQueue(tmp_path / "approvals.db").get(item.id).status == "approved"


def test_cli_help_carries_the_warning(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["approvals", "--help"])
    assert "DEVELOPMENT ONLY" in capsys.readouterr().out


def test_gate_returns_pending_then_sends_on_retry(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    clock = Clock()
    queue = ApprovalQueue(tmp_path / "approvals.db")
    w.gate.approver = QueueApprover(
        queue, "default", wait_seconds=45, clock=clock, sleep=clock.sleep
    )
    args = {"to": ["alice@work.test"], "subject": "s", "body": "b"}
    first = w.call("send_mail", **args)
    assert first.approval == ApprovalOutcome.PENDING
    assert first.data["status"] == "pending_approval"
    assert w.backend.sent == []
    queue.decide(first.data["approval_id"], approve=True, now=clock())
    second = w.call("send_mail", **args)
    assert second.ok and second.verdict == Verdict.ASK
    assert len(w.backend.sent) == 1
    assert w.history.prompts("default", w.clock.now.date()) == 1  # the retry was not a new prompt
