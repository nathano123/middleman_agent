# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false
"""Live checks against the real Google TEST account. Skipped unless BROKER_LIVE=1.

    BROKER_LIVE=1 uv run pytest tests/live -s

Uses the broker config (BROKER_CONFIG or ~/.agent-broker/config.yaml) and the token stored by
`broker auth`. Prints metadata only (ids, auth results, flags), never message content.
Writes: one draft, one mail to the account itself, one event without attendees.
"""

import os
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from broker.backends.base import event_action_hash, mail_action_hash
from broker.backends.google import GoogleBackend, open_google_backend
from broker.config import DEFAULT_CONFIG_PATH, load_config

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("BROKER_LIVE") != "1", reason="set BROKER_LIVE=1"),
]


@pytest.fixture(scope="module")
def google() -> GoogleBackend:
    config = load_config(Path(os.environ.get("BROKER_CONFIG", str(DEFAULT_CONFIG_PATH))))
    return open_google_backend(config)


def test_live_search_read_and_auth_results(google: GoogleBackend) -> None:
    found = google.search_messages("newer_than:30d", 25)
    assert found, "seed the test inbox first"
    stats: Counter[str] = Counter()
    for summary in found:
        message = google.get_message(summary.id)
        assert message is not None
        stats[message.auth_result] += 1
        print(
            f"{message.id} auth={message.auth_result} bulk={message.bulk} "
            f"reply_to={'yes' if message.reply_to else 'no'} "
            f"sender_hdr={'yes' if message.sender_header else 'no'} "
            f"attachments={len(message.attachments)} hidden_marker="
            f"{'[hidden text removed' in message.body}"
        )
    print("auth results:", dict(stats))


def test_live_identity(google: GoogleBackend) -> None:
    print("self addresses:", len(google.self_addresses()))
    print("known contacts:", len(google.known_contacts()))


def test_live_list_events(google: GoogleBackend) -> None:
    for event in google.list_events("primary", 20):
        print(f"{event.id} start={event.start} authors={len(event.description_authors)}")


def test_live_draft_send_to_self_and_event(google: GoogleBackend) -> None:
    latest = google.search_messages("", 1)
    if latest:
        print(
            "draft", google.create_draft([google.own_address], "Re: live test", "ok", latest[0].id)
        )
    to, subject, body = [google.own_address], "broker live test", "sent by tests/live"
    print(
        "sent", google.send_message(to, [], subject, body, mail_action_hash(to, [], subject, body))
    )
    start = (datetime.now(UTC) + timedelta(days=3)).replace(microsecond=0)
    s, e = start.isoformat(), (start + timedelta(minutes=30)).isoformat()
    approved = event_action_hash("primary", "broker live test", s, e, [], "")
    print("event", google.create_event("primary", "broker live test", s, e, [], "", approved))
