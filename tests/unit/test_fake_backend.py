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
    backend.send_message(["a@x.test"], [], "s", "b")
    backend.create_draft(["a@x.test"], "s", "b", "m1")
    backend.create_event("primary", "t", "s", "e", [], "")
    assert len(backend.sent) == len(backend.drafts) == len(backend.created_events) == 1
