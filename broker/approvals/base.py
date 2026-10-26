"""Approval interface. A request is built only from the structured action the agent asked for."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

APPROVAL_TIMEOUT_SECONDS = 300
BODY_PREVIEW_CHARS = 200


class ApprovalOutcome(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class ApprovalRequest:
    session_id: str
    tool: str
    recipients: list[str]  # send_mail: to + cc; create_event: attendees
    subject: str  # send_mail: subject; create_event: title
    body_preview: str  # first BODY_PREVIEW_CHARS of the body / description being sent
    reason: str  # the rule's reason, plus the taint reason when tainted
    body_length: int = 0  # total characters in the body / description
    more_chars: int = 0  # characters not shown in body_preview
    body_sha256: str = ""  # short hash of the full body, to recognise repeats
    approval_number: int = 0  # 1-based count of prompts in this session, this one included
    outside_recipients: list[str] = field(default_factory=list[str])
    new_recipients: list[str] = field(default_factory=list[str])  # not approved before
    requires_full_view: bool = False  # plain Approve is not enough
    full_body: str = ""  # shown only when the user opens the full view


class Approver(Protocol):
    def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        """Block until the user answers. No answer within the timeout must return TIMEOUT."""
        ...
