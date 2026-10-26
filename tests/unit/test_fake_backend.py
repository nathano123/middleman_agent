import pytest

from broker.backends.base import BackendError, event_action_hash, mail_action_hash
from broker.backends.fake import FakeBackend
from tests.conftest import FIXTURE


def test_fixture_loads() -> None:
    backend = FakeBackend.from_fixture(FIXTURE)
    assert len(backend.messages) >= 10
    assert len(backend.events) >= 3


def test_search_is_newest_first_and_limited() -> None:
    backend = FakeBackend.from_fixture(FIXTURE)
    hits = backend.search_messages("", limit=3)
    assert len(hits) == 3
    assert hits[0].date >= hits[1].date >= hits[2].date


def test_search_matches_subject() -> None:
    backend = FakeBackend.from_fixture(FIXTURE)
    assert [m.id for m in backend.search_messages("lunch", 10)] == ["m_lunch"]


def test_writes_are_recorded_not_sent_anywhere() -> None:
    backend = FakeBackend()
    backend.send_message(["a@x.test"], [], "s", "b", None)
    backend.create_draft(["a@x.test"], "s", "b", "m1")
    backend.create_event("primary", "t", "s", "e", [], "", None)
    assert len(backend.sent) == len(backend.drafts) == len(backend.created_events) == 1


def test_send_refused_when_approved_hash_does_not_match() -> None:
    backend = FakeBackend()
    approved = mail_action_hash(["a@x.test"], [], "s", "what the user approved")
    with pytest.raises(BackendError, match="approved_action_mismatch"):
        backend.send_message(["a@x.test"], [], "s", "something else", approved)
    with pytest.raises(BackendError):
        backend.send_message(["b@x.test"], [], "s", "what the user approved", approved)
    assert backend.sent == []
    backend.send_message(["A@x.test"], [], "s", "what the user approved", approved)
    assert len(backend.sent) == 1


def test_event_refused_when_approved_hash_does_not_match() -> None:
    backend = FakeBackend()
    approved = event_action_hash("primary", "t", "09:00", "10:00", ["x@out.test"], "")
    with pytest.raises(BackendError):
        backend.create_event("primary", "t", "09:00", "11:00", ["x@out.test"], "", approved)
    assert backend.created_events == []
