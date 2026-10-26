"""Per-session taint: once a session has read content from an unknown sender, it stays tainted.

Taint comes only from who wrote the content (by email address), never from what the content
says. No classifier, keyword list or language check is involved.
"""

from dataclasses import dataclass, field
from email.utils import parseaddr


def normalize_address(raw: str) -> str:
    """Return the bare lowercased address. Display names are dropped and never trusted."""
    _name, address = parseaddr(raw)
    return address.strip().lower()


@dataclass
class Session:
    session_id: str
    own_address: str
    known_contacts: frozenset[str]
    tainted: bool = False
    taint_reason: str = ""
    _known: frozenset[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        own = normalize_address(self.own_address)
        contacts = {normalize_address(c) for c in self.known_contacts}
        self._known = frozenset(contacts | {own}) - {""}

    def is_known(self, raw_address: str) -> bool:
        return normalize_address(raw_address) in self._known

    def mark_tainted(self, reason: str) -> None:
        """One-way: the first reason is kept and there is no way to clear taint."""
        if not self.tainted:
            self.tainted = True
            self.taint_reason = reason


def taint_on_read_message(session: Session, sender: str) -> None:
    if not session.is_known(sender):
        session.mark_tainted("read a message from an unknown sender")


def taint_on_list_events(session: Session, organizers_with_description: list[str]) -> None:
    """Taint if any listed event has a description written by an outside organizer."""
    if any(not session.is_known(o) for o in organizers_with_description):
        session.mark_tainted("listed an event described by an outside organizer")
