from broker.backends.base import Event, Message
from broker.minimizer import mask, minimize_events, minimize_message, minimize_search

MSG = Message(
    id="m1",
    sender="alice@work.test",
    to=["me@home.test"],
    subject="Hi",
    date="2026-10-20",
    snippet="Hi there",
    body="Mail bob@x.test or call +1 (415) 555-0134, account 12345678, ref 42.",
)


def test_mask_emails_phones_and_long_digits() -> None:
    masked = mask(MSG.body)
    assert "bob@x.test" not in masked
    assert "555-0134" not in masked
    assert "12345678" not in masked
    assert "[email]" in masked
    assert "[phone]" in masked
    assert "[number]" in masked
    assert "ref 42" in masked  # short numbers are left alone


def test_search_returns_header_fields_only() -> None:
    [row] = minimize_search([MSG])
    assert set(row) == {"id", "sender", "subject", "date", "snippet"}


def test_read_redacted_masks_body() -> None:
    row = minimize_message(MSG, redact=True)
    assert set(row) == {"id", "sender", "subject", "date", "snippet", "body"}
    assert "12345678" not in row["body"]


def test_read_unredacted_keeps_body() -> None:
    assert minimize_message(MSG, redact=False)["body"] == MSG.body


def test_events_drop_attendee_addresses_and_mask_description() -> None:
    event = Event(
        "e1", "primary", "o@x.test", "T", "s", "e", "call 0123456789", ["a@x.test", "b@x.test"]
    )
    [row] = minimize_events([event])
    assert row["attendee_count"] == 2
    assert "attendees" not in row
    assert "0123456789" not in row["description"]


def test_read_redacted_masks_snippet_too() -> None:
    message = Message("m1", "a@x.test", [], "s", "d", "call +1 415 555 0134", "body")
    assert "555" not in minimize_message(message, redact=True)["snippet"]
