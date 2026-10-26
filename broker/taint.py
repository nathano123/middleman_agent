"""Taint: once an agent has seen content from an untrusted sender, it is tainted.

Taint comes only from who wrote the content (address, Reply-To, authentication result),
never from what the content says. No classifier, keyword list or language check is involved.

Taint is stored per agent id in a TaintStore, not per connection, so reconnecting does not
clear it. It expires only after a quiet period with no new tainting event (default 24 h), or
when the user clears it with `broker taint clear`. Within one Session it never clears.
"""

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Protocol

from broker.approvals.history import ApprovalHistory
from broker.backends.base import Message, normalize_address
from broker.files import private_file


def utc_now() -> datetime:
    return datetime.now(UTC)


# --- who is trusted ----------------------------------------------------------


@dataclass(frozen=True)
class Contacts:
    own_address: str
    self_addresses: frozenset[str] = frozenset()
    known_contacts: frozenset[str] = frozenset()
    _known: frozenset[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        everyone = {self.own_address, *self.self_addresses, *self.known_contacts}
        known = frozenset(normalize_address(a) for a in everyone) - {""}
        object.__setattr__(self, "_known", known)

    def is_known(self, raw_address: str) -> bool:
        return normalize_address(raw_address) in self._known


def distrust(contacts: Contacts, message: Message) -> str | None:
    """Why this message's content is untrusted, or None if it is trusted."""
    if not contacts.is_known(message.sender):
        return "from an unknown sender"
    if message.auth_result == "fail":
        return "whose known sender failed authentication"
    reply_to = normalize_address(message.reply_to) if message.reply_to else ""
    sender = normalize_address(message.sender)
    if reply_to and reply_to != sender and not contacts.is_known(reply_to):
        return "whose reply-to is an outside address"
    actual = normalize_address(message.sender_header) if message.sender_header else ""
    if actual and actual != sender and not contacts.is_known(actual):
        return "whose Sender header is an outside address"
    return None


# --- where taint is kept -----------------------------------------------------


@dataclass(frozen=True)
class TaintRecord:
    reason: str
    first_at: datetime
    last_at: datetime


class TaintStore(Protocol):
    def get(self, agent_id: str, now: datetime) -> TaintRecord | None:
        """The active taint for this agent, or None if clean or expired."""
        ...

    def mark(self, agent_id: str, reason: str, now: datetime) -> None:
        """Taint the agent; if already tainted, keep the first reason and restart the clock."""
        ...

    def clear(self, agent_id: str) -> bool:
        """Remove taint. Returns True if there was a record to remove."""
        ...


def merged(old: TaintRecord | None, reason: str, now: datetime) -> TaintRecord:
    if old is None:
        return TaintRecord(reason, now, now)
    return TaintRecord(old.reason, old.first_at, now)


@dataclass
class MemoryTaintStore:
    quiet: timedelta = timedelta(hours=24)
    records: dict[str, TaintRecord] = field(default_factory=dict[str, TaintRecord])

    def get(self, agent_id: str, now: datetime) -> TaintRecord | None:
        record = self.records.get(agent_id)
        return record if record and now - record.last_at < self.quiet else None

    def mark(self, agent_id: str, reason: str, now: datetime) -> None:
        self.records[agent_id] = merged(self.get(agent_id, now), reason, now)

    def clear(self, agent_id: str) -> bool:
        return self.records.pop(agent_id, None) is not None


class SQLiteTaintStore:
    def __init__(self, path: Path, quiet: timedelta = timedelta(hours=24)) -> None:
        self.quiet = quiet
        self._conn = sqlite3.connect(private_file(path), check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS taint ("
            "agent_id TEXT PRIMARY KEY, reason TEXT NOT NULL,"
            " first_at TEXT NOT NULL, last_at TEXT NOT NULL)"
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def get(self, agent_id: str, now: datetime) -> TaintRecord | None:
        row: tuple[str, str, str] | None = self._conn.execute(
            "SELECT reason, first_at, last_at FROM taint WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        if row is None:
            return None
        record = TaintRecord(row[0], datetime.fromisoformat(row[1]), datetime.fromisoformat(row[2]))
        return record if now - record.last_at < self.quiet else None

    def mark(self, agent_id: str, reason: str, now: datetime) -> None:
        record = merged(self.get(agent_id, now), reason, now)
        self._conn.execute(
            "INSERT OR REPLACE INTO taint VALUES (?, ?, ?, ?)",
            (agent_id, record.reason, record.first_at.isoformat(), record.last_at.isoformat()),
        )
        self._conn.commit()

    def clear(self, agent_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM taint WHERE agent_id = ?", (agent_id,))
        self._conn.commit()
        return cur.rowcount > 0


# --- one connection ----------------------------------------------------------


@dataclass
class Session:
    """One agent connection. Taint is read from the agent-level store."""

    session_id: str
    agent_id: str
    contacts: Contacts
    store: TaintStore
    history: ApprovalHistory  # prompt count and approved recipients, per agent per day
    clock: Callable[[], datetime] = utc_now
    client_hint: str = ""  # what the MCP client says it is: logged, never used for decisions
    _held: TaintRecord | None = field(default=None, repr=False)

    def _current(self) -> TaintRecord | None:
        record = self.store.get(self.agent_id, self.clock())
        if record is not None:
            self._held = record
        return self._held  # once seen in this session, kept for the session's life

    @property
    def tainted(self) -> bool:
        return self._current() is not None

    @property
    def taint_reason(self) -> str:
        record = self._current()
        return record.reason if record else ""

    def is_known(self, raw_address: str) -> bool:
        return self.contacts.is_known(raw_address)

    def today(self) -> date:
        return self.clock().date()

    def mark_tainted(self, reason: str) -> None:
        self.store.mark(self.agent_id, reason, self.clock())
        self._current()  # hold it for the rest of this session


def taint_on_read_message(session: Session, message: Message) -> None:
    why = distrust(session.contacts, message)
    if why:
        session.mark_tainted(f"read a message {why}")


def taint_on_search(session: Session, messages: list[Message]) -> None:
    """Taint if any returned result carries snippet text from an untrusted sender."""
    for message in messages:
        why = distrust(session.contacts, message) if message.snippet.strip() else None
        if why:
            session.mark_tainted(f"search returned a snippet {why}")
            return


def taint_on_list_events(session: Session, organizers_with_description: list[str]) -> None:
    """Taint if any listed event has a description written by an outside organizer."""
    if any(not session.is_known(o) for o in organizers_with_description):
        session.mark_tainted("listed an event described by an outside organizer")
