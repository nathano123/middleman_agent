"""The Backend interface the gate calls. The fake and (later) Google backends implement it."""

from dataclasses import dataclass, field
from typing import Literal, Protocol

AuthResult = Literal["pass", "fail", "unknown"]


@dataclass(frozen=True)
class Message:
    id: str
    sender: str  # raw From header, e.g. '"Alice" <alice@work.test>'
    to: list[str]
    subject: str
    date: str
    snippet: str
    body: str
    reply_to: str = ""  # raw Reply-To header, empty if absent
    auth_result: AuthResult = "unknown"  # SPF/DKIM/DMARC summary from Authentication-Results
    list_unsubscribe: str = ""  # List-Unsubscribe header: marks bulk mail
    precedence: str = ""  # Precedence header, e.g. "bulk" or "list"
    thread_id: str = ""


@dataclass(frozen=True)
class Event:
    id: str
    calendar_id: str
    organizer: str
    title: str
    start: str
    end: str
    description: str = ""
    attendees: list[str] = field(default_factory=list[str])


class Backend(Protocol):
    def search_messages(self, query: str, limit: int) -> list[Message]: ...

    def get_message(self, message_id: str) -> Message | None: ...

    def list_events(self, calendar_id: str, limit: int) -> list[Event]: ...

    def create_draft(self, to: list[str], subject: str, body: str, in_reply_to: str) -> str: ...

    def send_message(self, to: list[str], cc: list[str], subject: str, body: str) -> str: ...

    def create_event(
        self,
        calendar_id: str,
        title: str,
        start: str,
        end: str,
        attendees: list[str],
        description: str,
    ) -> str: ...
