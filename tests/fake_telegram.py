"""In-memory stand-in for the Telegram Bot API calls the broker makes, plus a phone that taps."""

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from broker.approvals.base import ApprovalRequest
from broker.approvals.queue import ApprovalQueue, QueueApprover
from broker.approvals.telegram import TelegramChannel, TelegramError
from broker.audit import AuditLog
from broker.counters import Counters

OWNER = 424242
STRANGER = 999
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


@dataclass
class FakeTelegram:
    clock: Clock
    fail: set[str] = field(default_factory=set[str])
    sent: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    answers: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    edits: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    updates: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    on_poll: Callable[[], None] | None = None  # e.g. the user taps while the call waits
    _next_update: int = 1
    _next_message: int = 100

    def call(self, method: str, params: dict[str, Any], timeout: float = 15) -> Any:
        if method in self.fail:
            raise TelegramError("telegram_unreachable")
        if method == "sendMessage":
            message = {**params, "message_id": self._next_message}
            self._next_message += 1
            self.sent.append(message)
            return {"message_id": message["message_id"]}
        if method == "getUpdates":
            if self.on_poll:
                self.on_poll()
            offset = int(params.get("offset", 0))
            self.updates = [u for u in self.updates if u["update_id"] >= offset]  # confirmed
            self.clock.sleep(float(params.get("timeout", 0)))  # long poll
            return list(self.updates)
        if method == "answerCallbackQuery":
            self.answers.append(params)
            return True
        if method == "editMessageText":
            self.edits.append(params)
            return True
        if method == "getMe":
            return {"id": 1, "username": "test_broker_bot"}
        raise AssertionError(f"unexpected method {method}")

    def button(self, label: str, message: dict[str, Any] | None = None) -> str:
        message = message or self.sent[-1]
        row = message["reply_markup"]["inline_keyboard"][0]
        return next(b["callback_data"] for b in row if label in b["text"])

    def tap(
        self,
        label: str = "Approve",
        user: int = OWNER,
        message: dict[str, Any] | None = None,
        data: str | None = None,
    ) -> None:
        message = message or self.sent[-1]
        query = {
            "id": f"cq{self._next_update}",
            "from": {"id": user},
            "message": {"message_id": message["message_id"], "text": message["text"]},
        }
        if data is not None or label:
            query["data"] = data if data is not None else self.button(label, message)
        self.updates.append({"update_id": self._next_update, "callback_query": query})
        self._next_update += 1


def request(
    body: str = "hello", full_view: bool = False, subject: str = "Lunch"
) -> ApprovalRequest:
    return ApprovalRequest(
        "s1", "send_mail", ["x@out.test"], subject, body[:200], "outside recipient",
        body_length=len(body), body_sha256=hashlib.sha256(body.encode()).hexdigest()[:12],
        approval_number=1, outside_recipients=["x@out.test"], full_body=body,
        requires_full_view=full_view,
        action_hash=hashlib.sha256(f"{subject}|{body}".encode()).hexdigest(),
    )  # fmt: skip


@dataclass
class Phone:
    queue: ApprovalQueue
    telegram: FakeTelegram
    channel: TelegramChannel
    clock: Clock
    log: AuditLog
    counters: Counters

    def approver(self, agent_id: str = "agt_a", wait: float = 45) -> QueueApprover:
        return QueueApprover(
            self.queue, agent_id, wait_seconds=wait, poll_seconds=1, clock=self.clock,
            sleep=self.clock.sleep, channel=self.channel,
        )  # fmt: skip


def build_phone(tmp_path: Path) -> Phone:
    clock = Clock()
    queue = ApprovalQueue(tmp_path / "approvals.db")
    telegram = FakeTelegram(clock)
    log = AuditLog(tmp_path / "audit.db")
    counters = Counters(tmp_path / "counters.json")
    channel = TelegramChannel(
        telegram, OWNER, queue, tmp_path / "approvals.db", tmp_path / "phone.lock",
        log=log, counters=counters, clock=clock, sleep=clock.sleep,
    )  # fmt: skip
    return Phone(queue, telegram, channel, clock, log, counters)
