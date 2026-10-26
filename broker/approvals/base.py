"""Approval interface. A request is built only from the structured action the agent asked for."""

import hashlib
import json
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
    PENDING = "pending"  # no answer yet; the agent may retry the identical call


@dataclass(frozen=True)
class ApprovalResponse:
    outcome: ApprovalOutcome
    viewed_full_body: bool = False
    approval_id: str = ""  # set by queue-backed approvers
    new_prompt: bool = True  # False when this call re-used an earlier prompt (a retry)


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
    sends_invitations: bool = False  # create_event: Google will email the attendees
    details: dict[str, str] = field(default_factory=dict[str, str])  # e.g. event start/end
    action_hash: str = ""  # SHA-256 of exactly what will be done; see action_hash()


class Approver(Protocol):
    def request(self, req: ApprovalRequest) -> ApprovalResponse:
        """Block until the user answers. No answer within the timeout must return TIMEOUT."""
        ...


def action_hash(
    tool: str,
    recipients: list[str],
    subject: str,
    body: str,
    sends_invitations: bool,
    details: dict[str, str],
) -> str:
    """Full SHA-256 over the action's effect. The backend recomputes it from what it sends."""
    payload = {
        "tool": tool,
        "recipients": recipients,
        "subject": subject,
        "body": body,
        "sends_invitations": sends_invitations,
        "details": details,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
    lines.extend(f"{key}: {value}" for key, value in sorted(req.details.items()))
    lines.append(f"Body: {req.body_length} chars, sha256 {req.body_sha256}")
    lines.append(req.body_preview)
    if req.more_chars:
        lines.append(f"[+{req.more_chars} more characters not shown]")
    if req.sends_invitations:
        lines.append(f"Google will email invitations to: {', '.join(req.recipients)}")
    if req.requires_full_view:
        lines.append("Open the full body to approve.")
    lines.append(f"Why: {req.reason}")
    return "\n".join(lines)
