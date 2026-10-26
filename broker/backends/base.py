"""The Backend interface the gate calls. The fake and (later) Google backends implement it."""

from dataclasses import dataclass, field
from email.utils import parseaddr
from typing import Literal, Protocol

from broker.approvals.base import action_hash

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


class BackendError(Exception):
    """A backend failure, described only by a stable code. Never carries message content."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def normalize_address(raw: str) -> str:
    """Return the bare lowercased address. Display names are dropped and never trusted."""
    _name, address = parseaddr(raw)
    return address.strip().lower()


def mail_action_hash(to: list[str], cc: list[str], subject: str, body: str) -> str:
    """The hash an approved send_mail must match (see approvals.base.action_hash)."""
    recipients = [normalize_address(a) for a in to + cc]
    return action_hash("send_mail", recipients, subject, body, False, {})


def event_action_hash(
    calendar_id: str, title: str, start: str, end: str, attendees: list[str], description: str
) -> str:
    details = {"calendar": calendar_id, "start": start, "end": end}
    recipients = [normalize_address(a) for a in attendees]
    return action_hash("create_event", recipients, title, description, bool(attendees), details)


def check_approved(approved_hash: str | None, actual_hash: str) -> None:
    """Refuse to act if an approval exists and does not match what is about to happen."""
    if approved_hash is not None and approved_hash != actual_hash:
        raise BackendError("approved_action_mismatch")


class Backend(Protocol):
    def search_messages(self, query: str, limit: int) -> list[Message]: ...

    def get_message(self, message_id: str) -> Message | None: ...

    def list_events(self, calendar_id: str, limit: int) -> list[Event]: ...

    def create_draft(self, to: list[str], subject: str, body: str, in_reply_to: str) -> str: ...

    def send_message(
        self, to: list[str], cc: list[str], subject: str, body: str, approved_hash: str | None
    ) -> str: ...

    def create_event(
        self,
        calendar_id: str,
        title: str,
        start: str,
        end: str,
        attendees: list[str],
        description: str,
        approved_hash: str | None,
    ) -> str: ...
