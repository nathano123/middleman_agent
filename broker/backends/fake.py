"""In-memory inbox and calendar for development and tests. Never talks to the network."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from broker.backends.base import (
    Event,
    Message,
    check_approved,
    event_action_hash,
    mail_action_hash,
)


@dataclass(frozen=True)
class SentMail:
    id: str
    to: list[str]
    cc: list[str]
    subject: str
    body: str


@dataclass(frozen=True)
class Draft:
    id: str
    to: list[str]
    subject: str
    body: str
    in_reply_to: str


@dataclass
class FakeBackend:
    messages: list[Message] = field(default_factory=list[Message])
    events: list[Event] = field(default_factory=list[Event])
    sent: list[SentMail] = field(default_factory=list[SentMail])
    drafts: list[Draft] = field(default_factory=list[Draft])
    created_events: list[Event] = field(default_factory=list[Event])

    @classmethod
    def from_fixture(cls, path: Path) -> "FakeBackend":
        raw: dict[str, list[dict[str, Any]]] = json.loads(path.read_text(encoding="utf-8"))
        messages = [Message(**m) for m in raw.get("messages", [])]
        events = [Event(**e) for e in raw.get("events", [])]
        return cls(messages=messages, events=events)

    def search_messages(self, query: str, limit: int) -> list[Message]:
        needle = query.lower()
        hits = [m for m in self.messages if needle in f"{m.sender} {m.subject} {m.snippet}".lower()]
        return sorted(hits, key=lambda m: m.date, reverse=True)[:limit]

    def get_message(self, message_id: str) -> Message | None:
        return next((m for m in self.messages if m.id == message_id), None)

    def list_events(self, calendar_id: str, limit: int) -> list[Event]:
        return [e for e in self.events if e.calendar_id == calendar_id][:limit]

    def create_draft(self, to: list[str], subject: str, body: str, in_reply_to: str) -> str:
        draft = Draft(f"d{len(self.drafts) + 1}", list(to), subject, body, in_reply_to)
        self.drafts.append(draft)
        return draft.id

    def send_message(
        self, to: list[str], cc: list[str], subject: str, body: str, approved_hash: str | None
    ) -> str:
        check_approved(approved_hash, mail_action_hash(to, cc, subject, body))
        mail = SentMail(f"s{len(self.sent) + 1}", list(to), list(cc), subject, body)
        self.sent.append(mail)
        return mail.id

    def create_event(
        self,
        calendar_id: str,
        title: str,
        start: str,
        end: str,
        attendees: list[str],
        description: str,
        approved_hash: str | None,
    ) -> str:
        actual = event_action_hash(calendar_id, title, start, end, attendees, description)
        check_approved(approved_hash, actual)
        event_id = f"new{len(self.created_events) + 1}"
        event = Event(event_id, calendar_id, "", title, start, end, description, list(attendees))
        self.created_events.append(event)
        return event_id
