"""Who a draft reply is addressed to (Milestone 3, dry-run finding 3)."""

from broker.backends.base import Message
from broker.gate import reply_address
from broker.taint import Contacts

CONTACTS = Contacts(
    "me@home.test", frozenset({"me.work@office.test"}), frozenset({"bob@work.test"})
)


def mail(sender: str, reply_to: str = "") -> Message:
    return Message("m", sender, ["me@home.test"], "s", "d", "", "", reply_to=reply_to)


def test_no_reply_to_uses_from() -> None:
    assert reply_address(CONTACTS, mail('"Alice" <Alice@Work.test>')) == ("alice@work.test", None)


def test_outside_reply_to_is_ignored_and_its_domain_reported() -> None:
    message = mail('"Alice" <alice@work.test>', "billing@alice-payments.test")
    assert reply_address(CONTACTS, message) == ("alice@work.test", "alice-payments.test")


def test_known_or_own_reply_to_is_followed() -> None:
    known = mail("a@x.test", "Bob <bob@work.test>")
    assert reply_address(CONTACTS, known) == ("bob@work.test", None)
    assert reply_address(CONTACTS, mail("a@x.test", "me.work@office.test")) == (
        "me.work@office.test",
        None,
    )


def test_reply_to_equal_to_from_is_fine() -> None:
    assert reply_address(CONTACTS, mail("a@x.test", "A@X.test")) == ("a@x.test", None)


def test_unknown_sender_with_unknown_reply_to_still_goes_to_from() -> None:
    message = mail("stranger@out.test", "collect@evil.test")
    assert reply_address(CONTACTS, message) == ("stranger@out.test", "evil.test")
