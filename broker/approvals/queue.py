"""SQLite approval queue, and an Approver that waits on it with a pending-and-retry fallback.

Why the fallback: Claude Desktop is reported to cancel MCP tool calls after about 60 seconds,
shorter than the 5-minute approval window. So a call waits `wait_seconds`, then returns
PENDING with an id. When the agent repeats the identical call, the request is found again by
its action hash and the decision (if any) is used. An approval is used at most once.

What is stored: the full ApprovalRequest (recipients, subject, the outgoing body) only while
the request is open. Once it is used or expires, the content is erased and only the hash,
status and timestamps stay.
"""

import json
import secrets
import sqlite3
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Protocol

from broker.approvals.base import ApprovalOutcome, ApprovalRequest, ApprovalResponse
from broker.files import private_file
from broker.taint import utc_now

EXPIRY = timedelta(seconds=300)

SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    status TEXT NOT NULL,          -- pending | approved | denied | expired
    viewed INTEGER NOT NULL DEFAULT 0,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    decided_at TEXT,
    request_json TEXT              -- erased once consumed or expired
)
"""


class QueueError(Exception):
    pass


@dataclass(frozen=True)
class QueueItem:
    id: str
    agent_id: str
    action_hash: str
    status: str
    viewed: bool
    consumed: bool
    created_at: datetime
    request: ApprovalRequest | None


def _item(row: sqlite3.Row) -> QueueItem:
    raw = row["request_json"]
    request = ApprovalRequest(**json.loads(raw)) if raw else None
    return QueueItem(
        row["id"],
        row["agent_id"],
        row["action_hash"],
        row["status"],
        bool(row["viewed"]),
        bool(row["consumed"]),
        datetime.fromisoformat(row["created_at"]),
        request,
    )


class ApprovalQueue:
    def __init__(self, path: Path, expiry: timedelta = EXPIRY) -> None:
        self.expiry = expiry
        self._conn = sqlite3.connect(private_file(path), timeout=10, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # Overwrite erased content with zeros; otherwise it lingers in free pages of the file.
        self._conn.execute("PRAGMA secure_delete = ON")
        self._conn.execute(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _write(self, sql: str, params: tuple[object, ...]) -> None:
        self._conn.execute(sql, params)
        self._conn.commit()

    def expire(self, now: datetime) -> None:
        cutoff = (now - self.expiry).isoformat()
        self._write(
            "UPDATE approvals SET status = 'expired', request_json = NULL "
            "WHERE status = 'pending' AND created_at <= ?",
            (cutoff,),
        )

    def get(self, item_id: str) -> QueueItem:
        row = self._conn.execute("SELECT * FROM approvals WHERE id = ?", (item_id,)).fetchone()
        if row is None:
            raise QueueError(f"no approval {item_id}")
        return _item(row)

    def open(self, agent_id: str, req: ApprovalRequest, now: datetime) -> tuple[QueueItem, bool]:
        """The open request for this exact action, or a new one. Returns (item, is_new)."""
        self.expire(now)
        row = self._conn.execute(
            "SELECT * FROM approvals WHERE agent_id = ? AND action_hash = ? AND consumed = 0 "
            "AND status != 'expired' ORDER BY created_at DESC LIMIT 1",
            (agent_id, req.action_hash),
        ).fetchone()
        if row is not None:
            return _item(row), False
        item_id = f"apr_{secrets.token_hex(4)}"
        self._write(
            "INSERT INTO approvals (id, agent_id, action_hash, status, created_at, request_json) "
            "VALUES (?, ?, ?, 'pending', ?, ?)",
            (item_id, agent_id, req.action_hash, now.isoformat(), json.dumps(asdict(req))),
        )
        return self.get(item_id), True

    def pending(self, now: datetime) -> list[QueueItem]:
        self.expire(now)
        rows = self._conn.execute(
            "SELECT * FROM approvals WHERE status = 'pending' ORDER BY created_at"
        ).fetchall()
        return [_item(r) for r in rows]

    def mark_viewed(self, item_id: str) -> QueueItem:
        self._write("UPDATE approvals SET viewed = 1 WHERE id = ?", (item_id,))
        return self.get(item_id)

    def decide(self, item_id: str, approve: bool, now: datetime) -> QueueItem:
        self.expire(now)
        item = self.get(item_id)
        if item.status != "pending":
            raise QueueError(f"approval {item_id} is {item.status}, not pending")
        status = "approved" if approve else "denied"
        self._write(
            "UPDATE approvals SET status = ?, decided_at = ? WHERE id = ?",
            (status, now.isoformat(), item_id),
        )
        return self.get(item_id)

    def consume(self, item_id: str) -> None:
        """Mark used (an approval works once) and erase the stored content."""
        self._write(
            "UPDATE approvals SET consumed = 1, request_json = NULL WHERE id = ?", (item_id,)
        )


OUTCOMES = {
    "approved": ApprovalOutcome.APPROVED,
    "denied": ApprovalOutcome.DENIED,
    "expired": ApprovalOutcome.TIMEOUT,
}


class PhoneChannel(Protocol):
    """Somewhere the owner answers away from the agent's reach (e.g. TelegramChannel)."""

    def notify(self, item: QueueItem, req: ApprovalRequest) -> None:
        """Show the request; called on every attempt, must send at most once per item."""
        ...

    def poll(self, wait: float) -> None:
        """Collect answers for up to `wait` seconds and write them into the queue."""
        ...


@dataclass
class QueueApprover:
    """Approver backed by the queue. Waits up to `wait_seconds`, then answers PENDING.

    With a phone channel the request is also sent to the phone, and the wait is spent
    polling it, so an answer within the window lets the first call go through.
    """

    queue: ApprovalQueue
    agent_id: str
    wait_seconds: float = 45.0
    poll_seconds: float = 1.0
    clock: Callable[[], datetime] = utc_now
    sleep: Callable[[float], None] = time.sleep
    channel: PhoneChannel | None = None

    def request(self, req: ApprovalRequest) -> ApprovalResponse:
        item, is_new = self.queue.open(self.agent_id, req, self.clock())
        if self.channel is not None and item.status == "pending":
            self.channel.notify(item, req)
        deadline = self.clock() + timedelta(seconds=self.wait_seconds)
        while item.status == "pending" and self.clock() < deadline:
            if self.channel is not None:
                self.channel.poll(self.poll_seconds)
            else:
                self.sleep(self.poll_seconds)
            self.queue.expire(self.clock())
            item = self.queue.get(item.id)
        if item.status == "pending":
            return ApprovalResponse(ApprovalOutcome.PENDING, approval_id=item.id, new_prompt=is_new)
        self.queue.consume(item.id)
        return ApprovalResponse(
            OUTCOMES[item.status], item.viewed, approval_id=item.id, new_prompt=is_new
        )
