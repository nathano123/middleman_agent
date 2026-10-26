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
    UNVIEWED = "unviewed"  # approved without opening a full body that had to be opened


@dataclass(frozen=True)
class ApprovalResponse:
    outcome: ApprovalOutcome
    viewed_full_body: bool = False


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
    approval_number: int = 0  # 1-based count of this agent's prompts today, this one included
    outside_recipients: list[str] = field(default_factory=list[str])
    new_recipients: list[str] = field(default_factory=list[str])  # not approved today
    requires_full_view: bool = False  # plain Approve is not enough
    full_body: str = ""  # shown only when the user opens the full view


class Approver(Protocol):
    def request(self, req: ApprovalRequest) -> ApprovalResponse:
        """Block until the user answers. No answer within the timeout must return TIMEOUT."""
        ...


def final_outcome(req: ApprovalRequest, response: ApprovalResponse) -> ApprovalOutcome:
    """A plain Approve is refused when the request needed the full body opened first."""
    approved = response.outcome == ApprovalOutcome.APPROVED
    if approved and req.requires_full_view and not response.viewed_full_body:
        return ApprovalOutcome.UNVIEWED
    return response.outcome


def render_prompt(req: ApprovalRequest) -> str:
    """The text a phone notification shows. Every line comes from the request fields."""
    lines = [f"{req.tool} (approval #{req.approval_number} today)"]
    lines.append(f"To: {', '.join(req.recipients) or '(nobody)'}")
    if req.outside_recipients:
        lines.append(f"OUTSIDE: {', '.join(req.outside_recipients)}")
    if req.new_recipients:
        lines.append(f"NEW today: {', '.join(req.new_recipients)}")
    lines.append(f"Subject: {req.subject}")
    lines.append(f"Body: {req.body_length} chars, sha256 {req.body_sha256}")
    lines.append(req.body_preview)
    if req.more_chars:
        lines.append(f"[+{req.more_chars} more characters not shown]")
    if req.requires_full_view:
        lines.append("Open the full body to approve.")
    lines.append(f"Why: {req.reason}")
    return "\n".join(lines)
