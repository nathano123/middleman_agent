"""Shape backend results down to the fields each tool needs, masking personal data in bodies.

The regexes are deliberately simple placeholders until Presidio arrives (M4). They will miss
things (names, street addresses, IBANs with letters split by spaces) and that is expected.
"""

import re
from typing import Any

from broker.backends.base import Event, Message

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
LONG_DIGITS_RE = re.compile(r"\d{6,}")


def mask(text: str) -> str:
    text = EMAIL_RE.sub("[email]", text)
    text = PHONE_RE.sub("[phone]", text)
    return LONG_DIGITS_RE.sub("[number]", text)


def message_header(message: Message) -> dict[str, Any]:
    return {
        "id": message.id,
        "sender": message.sender,
        "subject": message.subject,
        "date": message.date,
        "snippet": message.snippet,
    }


def minimize_search(messages: list[Message]) -> list[dict[str, Any]]:
    return [message_header(m) for m in messages]


def minimize_message(message: Message, redact: bool) -> dict[str, Any]:
    result = message_header(message)
    result["body"] = mask(message.body) if redact else message.body
    return result


def minimize_events(events: list[Event]) -> list[dict[str, Any]]:
    return [
        {
            "id": e.id,
            "title": e.title,
            "start": e.start,
            "end": e.end,
            "organizer": e.organizer,
            "attendee_count": len(e.attendees),
            "description": mask(e.description),
        }
        for e in events
    ]
