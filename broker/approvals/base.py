"""Approval interface. A request is built only from the structured action the agent asked for."""

from dataclasses import dataclass
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


class Approver(Protocol):
    def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        """Block until the user answers. No answer within the timeout must return TIMEOUT."""
        ...
