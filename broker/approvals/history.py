"""Approval history per agent per day: how many prompts, and which recipients were approved.

Kept at agent level (like taint) so an agent cannot reset the full-view bar or make an
approved recipient look new again by reconnecting. Days are UTC dates from the gate's clock.
The SQLite store holds recipient addresses; it lives in the local state directory, never in
the audit log or the counters.
"""

import sqlite3
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Protocol

from broker.files import private_file


class ApprovalHistory(Protocol):
    def prompts(self, agent_id: str, day: date) -> int:
        """How many approval prompts this agent has caused today."""
        ...

    def record_prompt(self, agent_id: str, day: date) -> None: ...

    def approved(self, agent_id: str, day: date) -> frozenset[str]:
        """Recipients the user approved for this agent today."""
        ...

    def add_approved(self, agent_id: str, day: date, recipients: list[str]) -> None: ...


@dataclass
class MemoryApprovalHistory:
    counts: dict[tuple[str, date], int] = field(default_factory=dict[tuple[str, date], int])
    recipients: dict[tuple[str, date], set[str]] = field(
        default_factory=dict[tuple[str, date], set[str]]
    )

    def prompts(self, agent_id: str, day: date) -> int:
        return self.counts.get((agent_id, day), 0)

    def record_prompt(self, agent_id: str, day: date) -> None:
        self.counts[(agent_id, day)] = self.prompts(agent_id, day) + 1

    def approved(self, agent_id: str, day: date) -> frozenset[str]:
        return frozenset(self.recipients.get((agent_id, day), set()))

    def add_approved(self, agent_id: str, day: date, recipients: list[str]) -> None:
        self.recipients.setdefault((agent_id, day), set()).update(recipients)


class SQLiteApprovalHistory:
    def __init__(self, path: Path) -> None:
        self._conn = sqlite3.connect(private_file(path))
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS prompts ("
            "agent_id TEXT, day TEXT, count INTEGER NOT NULL, PRIMARY KEY (agent_id, day))"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS approved ("
            "agent_id TEXT, day TEXT, recipient TEXT, PRIMARY KEY (agent_id, day, recipient))"
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def prompts(self, agent_id: str, day: date) -> int:
        row: tuple[int] | None = self._conn.execute(
            "SELECT count FROM prompts WHERE agent_id = ? AND day = ?", (agent_id, day.isoformat())
        ).fetchone()
        return row[0] if row else 0

    def record_prompt(self, agent_id: str, day: date) -> None:
        self._conn.execute(
            "INSERT INTO prompts VALUES (?, ?, 1) "
            "ON CONFLICT (agent_id, day) DO UPDATE SET count = count + 1",
            (agent_id, day.isoformat()),
        )
        self._conn.commit()

    def approved(self, agent_id: str, day: date) -> frozenset[str]:
        rows: list[tuple[str]] = self._conn.execute(
            "SELECT recipient FROM approved WHERE agent_id = ? AND day = ?",
            (agent_id, day.isoformat()),
        ).fetchall()
        return frozenset(r[0] for r in rows)

    def add_approved(self, agent_id: str, day: date, recipients: list[str]) -> None:
        self._conn.executemany(
            "INSERT OR IGNORE INTO approved VALUES (?, ?, ?)",
            [(agent_id, day.isoformat(), r) for r in recipients],
        )
        self._conn.commit()
