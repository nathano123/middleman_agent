# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false
# google-api-python-client ships no type information; this module is the typed boundary.
"""Gmail and Google Calendar behind the Backend interface (google-api-python-client 2.201.0).

Scopes: gmail.readonly, gmail.compose, calendar.events.owned (see google_auth.SCOPES).
Every API error becomes a BackendError with a stable code; HttpError text (which can include
the request URL and a search query) is never passed on. Retries: `execute(num_retries=3)`,
which in this library version retries 5xx, 429 and rate-limit 403s with backoff.
"""

import base64
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email import message_from_bytes
from email.message import EmailMessage
from email.policy import default as default_policy
from email.utils import getaddresses
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from google.auth.exceptions import RefreshError, TransportError
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from broker.audit import KeyringKeyStore
from broker.backends.base import (
    BackendError,
    Event,
    Message,
    check_approved,
    event_action_hash,
    mail_action_hash,
    normalize_address,
)
from broker.backends.gmail_parse import html_to_text, to_message
from broker.config import BrokerConfig, ConfigError
from broker.counters import Counters
from broker.files import write_private_text
from broker.google_auth import fresh_credentials, is_invalid_grant

OWN_CALENDAR = "primary"
METADATA_HEADERS = [
    "From", "Reply-To", "Sender", "To", "Cc", "Subject", "Date", "Message-ID",
    "List-Unsubscribe", "Precedence", "Authentication-Results",
]  # fmt: skip
LIST_WINDOW = timedelta(days=14)
SENT_SCAN_QUERY = "in:sent newer_than:12m"
SENT_SCAN_MAX = 300  # most recent sent messages read to build known contacts
CONTACTS_MAX_AGE = timedelta(hours=24)


def status_code(status: int) -> str:
    return {404: "google_not_found", 429: "google_rate_limited", 403: "google_forbidden"}.get(
        status, f"google_error_{status}"
    )


# --- outgoing mail -------------------------------------------------------------


def build_mail(own: str, to: list[str], cc: list[str], subject: str, body: str) -> EmailMessage:
    message = EmailMessage(policy=default_policy)
    try:
        message["From"] = own
        message["To"] = ", ".join(to)
        if cc:
            message["Cc"] = ", ".join(cc)
        message["Subject"] = subject
    except ValueError:  # e.g. a line break in a header (header injection)
        raise BackendError("invalid_header") from None
    message.set_content(body)
    return message


def _norm_body(text: str) -> str:
    return text.replace("\r\n", "\n").rstrip("\n")


def header_addresses(value: object) -> list[str]:
    """Addresses in a parsed header; an absent header gives [] (not [''])."""
    if value is None:
        return []
    return [addr.lower() for _n, addr in getaddresses([str(value)]) if addr]


def check_mime(raw: bytes, to: list[str], cc: list[str], subject: str, body: str) -> None:
    """Parse the bytes about to be sent and refuse if they differ from the approved fields."""
    parsed = message_from_bytes(raw, policy=default_policy)
    sent_to = header_addresses(parsed.get("To"))
    sent_cc = header_addresses(parsed.get("Cc"))
    content = parsed.get_content()
    same = (
        sent_to == [normalize_address(a) for a in to]
        and sent_cc == [normalize_address(a) for a in cc]
        and str(parsed.get("Subject", "")) == subject
        and parsed.get("Bcc") is None
        and _norm_body(str(content)) == _norm_body(body)
    )
    if not same:
        raise BackendError("mime_mismatch")


def raw_b64(message: EmailMessage) -> tuple[bytes, str]:
    data = message.as_bytes()
    return data, base64.urlsafe_b64encode(data).decode("ascii")


# --- events --------------------------------------------------------------------


def require_offset(value: str) -> None:
    """Event times must carry an explicit UTC offset, e.g. 2026-11-02T10:00:00+01:00."""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise BackendError("event_time_invalid") from None
    if parsed.tzinfo is None:
        raise BackendError("event_time_needs_offset")


def to_event(item: dict[str, Any]) -> Event:
    start: dict[str, str] = item.get("start") or {}
    end: dict[str, str] = item.get("end") or {}
    organizer = str((item.get("organizer") or {}).get("email", ""))
    creator = str((item.get("creator") or {}).get("email", ""))
    authors = list(dict.fromkeys(a for a in (organizer, creator) if a))
    description, hidden = html_to_text(str(item.get("description", "")))
    if hidden:
        description += f"\n[hidden text removed: {hidden} chars]"
    attendees: list[dict[str, Any]] = item.get("attendees") or []
    return Event(
        id=str(item.get("id", "")),
        calendar_id=OWN_CALENDAR,
        organizer=organizer,
        title=str(item.get("summary", "")),
        start=start.get("dateTime") or start.get("date", ""),
        end=end.get("dateTime") or end.get("date", ""),
        description=description,
        attendees=[str(a["email"]) for a in attendees if a.get("email")],
        description_authors=authors,
    )


def event_body(
    title: str, start: str, end: str, attendees: list[str], description: str
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "summary": title,
        "start": {"dateTime": start},
        "end": {"dateTime": end},
        "description": description,
    }
    if attendees:
        body["attendees"] = [{"email": a} for a in attendees]
    return body


# --- the backend -------------------------------------------------------------


class GoogleBackend:
    def __init__(
        self,
        gmail: Any,
        calendar: Any,
        own_address: str,
        timezone: str,
        contacts_cache: Path,
        on_reauth: Callable[[], None] = lambda: None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        num_retries: int = 3,
    ) -> None:
        self.gmail = gmail
        self.calendar = calendar
        self.own_address = own_address
        self.timezone = timezone
        self.contacts_cache = contacts_cache
        self.on_reauth = on_reauth
        self.clock = clock
        self.num_retries = num_retries

    def _execute(self, request: Any) -> Any:
        try:
            return request.execute(num_retries=self.num_retries)
        except HttpError as exc:
            raise BackendError(status_code(int(exc.resp.status))) from None
        except RefreshError as exc:
            if is_invalid_grant(exc):
                self.on_reauth()
                raise BackendError("google_reauth_required") from None
            raise BackendError("google_refresh_failed") from None
        except (TransportError, OSError):
            raise BackendError("google_unreachable") from None

    # --- mail ---

    def _metadata(self, message_id: str) -> Message:
        resource = self._execute(
            self.gmail.users()
            .messages()
            .get(userId="me", id=message_id, format="metadata", metadataHeaders=METADATA_HEADERS)
        )
        return to_message(resource)

    def search_messages(self, query: str, limit: int) -> list[Message]:
        listing = self._execute(
            self.gmail.users().messages().list(userId="me", q=query, maxResults=limit)
        )
        refs: list[dict[str, str]] = listing.get("messages") or []
        return [self._metadata(ref["id"]) for ref in refs[:limit]]

    def get_message(self, message_id: str) -> Message | None:
        try:
            resource = self._execute(
                self.gmail.users().messages().get(userId="me", id=message_id, format="full")
            )
        except BackendError as exc:
            if exc.code == "google_not_found":
                return None
            raise
        return to_message(resource)

    def create_draft(self, to: list[str], subject: str, body: str, in_reply_to: str) -> str:
        original = self._metadata(in_reply_to)
        message = build_mail(self.own_address, to, [], subject, body)
        if original.rfc_message_id:
            message["In-Reply-To"] = original.rfc_message_id
            message["References"] = original.rfc_message_id
        _raw, encoded = raw_b64(message)
        draft_message: dict[str, str] = {"raw": encoded}
        if original.thread_id:
            draft_message["threadId"] = original.thread_id
        created = self._execute(
            self.gmail.users().drafts().create(userId="me", body={"message": draft_message})
        )
        return str(created.get("id", ""))

    def send_message(
        self, to: list[str], cc: list[str], subject: str, body: str, approved_hash: str | None
    ) -> str:
        check_approved(approved_hash, mail_action_hash(to, cc, subject, body))
        message = build_mail(self.own_address, to, cc, subject, body)
        raw, encoded = raw_b64(message)
        check_mime(raw, to, cc, subject, body)
        sent = self._execute(self.gmail.users().messages().send(userId="me", body={"raw": encoded}))
        return str(sent.get("id", ""))

    # --- calendar ---

    def list_events(self, calendar_id: str, limit: int) -> list[Event]:
        if calendar_id != OWN_CALENDAR:
            raise BackendError("calendar_not_own")
        now = self.clock()
        listing = self._execute(
            self.calendar.events().list(
                calendarId=OWN_CALENDAR,
                timeMin=now.isoformat(),
                timeMax=(now + LIST_WINDOW).isoformat(),
                singleEvents=True,  # expand recurring events into instances
                orderBy="startTime",
                maxResults=limit,
                timeZone=self.timezone,
            )
        )
        items: list[dict[str, Any]] = listing.get("items") or []
        return [to_event(item) for item in items]

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
        if calendar_id != OWN_CALENDAR:
            raise BackendError("calendar_not_own")
        require_offset(start)
        require_offset(end)
        body = event_body(title, start, end, attendees, description)
        sent_attendees = [a["email"] for a in body.get("attendees", [])]
        actual = event_action_hash(
            calendar_id, body["summary"], body["start"]["dateTime"], body["end"]["dateTime"],
            sent_attendees, body["description"],
        )  # fmt: skip
        check_approved(approved_hash, actual)
        created = self._execute(
            self.calendar.events().insert(
                calendarId=OWN_CALENDAR,
                body=body,
                sendUpdates="all" if attendees else "none",
            )
        )
        return str(created.get("id", ""))

    # --- who is who ---

    def self_addresses(self) -> list[str]:
        profile = self._execute(self.gmail.users().getProfile(userId="me"))
        aliases = self._execute(self.gmail.users().settings().sendAs().list(userId="me"))
        found = [str(profile.get("emailAddress", ""))]
        found += [str(a.get("sendAsEmail", "")) for a in aliases.get("sendAs") or []]
        return sorted({a.lower() for a in found if a})

    def known_contacts(self) -> list[str]:
        cached = self._read_contacts_cache()
        if cached is not None:
            return cached
        found: set[str] = set()
        listing = self._execute(
            self.gmail.users()
            .messages()
            .list(userId="me", q=SENT_SCAN_QUERY, maxResults=SENT_SCAN_MAX)
        )
        for ref in (listing.get("messages") or [])[:SENT_SCAN_MAX]:
            sent = self._metadata(ref["id"])
            found.update(sent.to)
            found.update(sent.cc)
        contacts = sorted(found)
        payload = {"fetched_at": self.clock().isoformat(), "addresses": contacts}
        write_private_text(self.contacts_cache, json.dumps(payload))
        return contacts

    def _read_contacts_cache(self) -> list[str] | None:
        if not self.contacts_cache.exists():
            return None
        data = json.loads(self.contacts_cache.read_text(encoding="utf-8"))
        fetched = datetime.fromisoformat(str(data.get("fetched_at")))
        if self.clock() - fetched > CONTACTS_MAX_AGE:
            return None
        return [str(a) for a in data.get("addresses", [])]


def open_google_backend(config: BrokerConfig) -> GoogleBackend:
    try:
        ZoneInfo(config.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        raise ConfigError(f"unknown timezone {config.timezone!r}") from None
    counters = Counters(config.state_path("counters.json"))

    def on_reauth() -> None:
        counters.record_reconsent(datetime.now(UTC).date())

    creds = fresh_credentials(KeyringKeyStore(), on_reauth)
    gmail = build("gmail", "v1", credentials=creds, cache_discovery=False, static_discovery=True)
    calendar = build(
        "calendar", "v3", credentials=creds, cache_discovery=False, static_discovery=True
    )
    return GoogleBackend(
        gmail,
        calendar,
        config.own_address,
        config.timezone,
        config.state_path("contacts.json"),
        on_reauth=on_reauth,
    )
