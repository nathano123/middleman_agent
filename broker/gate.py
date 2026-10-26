"""The single entry point for every tool call: rules → approval → backend → minimizer → log.

handle() never raises for agent input. Every call, allowed or not, writes exactly one log row.
"""

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from broker.approvals.base import (
    BODY_PREVIEW_CHARS,
    ApprovalOutcome,
    ApprovalRequest,
    Approver,
)
from broker.audit import AuditLog, MetadataValue
from broker.backends.base import Backend
from broker.minimizer import minimize_events, minimize_message, minimize_search
from broker.rules.evaluator import evaluate
from broker.rules.models import Action, Constraints, Decision, Profile, Resource, Verdict
from broker.taint import (
    Session,
    normalize_address,
    taint_on_list_events,
    taint_on_read_message,
    taint_on_search,
)

OWN_CALENDAR = "primary"

# --- tool arguments ----------------------------------------------------------


class Args(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class SearchMailArgs(Args):
    query: str = ""
    limit: int = Field(default=10, ge=1, le=50)


class ReadMessageArgs(Args):
    message_id: str


class ListEventsArgs(Args):
    calendar_id: str = OWN_CALENDAR
    limit: int = Field(default=20, ge=1, le=100)


class DraftReplyArgs(Args):
    message_id: str
    body: str


class SendMailArgs(Args):
    to: list[str] = Field(min_length=1)
    cc: list[str] = Field(default_factory=list[str])
    subject: str
    body: str


class CreateEventArgs(Args):
    calendar_id: str = OWN_CALENDAR
    title: str
    start: str
    end: str
    attendees: list[str] = Field(default_factory=list[str])
    description: str = ""


ARG_MODELS: dict[str, type[Args]] = {
    "search_mail": SearchMailArgs,
    "read_message": ReadMessageArgs,
    "list_events": ListEventsArgs,
    "draft_reply": DraftReplyArgs,
    "send_mail": SendMailArgs,
    "create_event": CreateEventArgs,
}

RESOURCES: dict[str, Resource] = {
    "search_mail": "mail",
    "read_message": "mail",
    "draft_reply": "mail",
    "send_mail": "mail",
    "list_events": "calendar",
    "create_event": "calendar",
}


@dataclass(frozen=True)
class Result:
    ok: bool
    verdict: Verdict
    reason: str
    data: Any = None
    approval: ApprovalOutcome | None = None


# --- small helpers -----------------------------------------------------------


def addresses(raw: list[str]) -> list[str]:
    return [normalize_address(a) for a in raw]


def domains(raw: list[str]) -> list[str]:
    return sorted({a.rpartition("@")[2] or "?" for a in addresses(raw)})


def any_outside(session: Session, raw: list[str]) -> bool:
    return any(not session.is_known(a) for a in raw)


def constraints_for(session: Session, args: Args) -> Constraints:
    outside_recipients = False
    outside_attendees = False
    own_calendar = False
    if isinstance(args, SendMailArgs):
        outside_recipients = any_outside(session, args.to + args.cc)
    if isinstance(args, CreateEventArgs):
        outside_attendees = any_outside(session, args.attendees)
        own_calendar = args.calendar_id == OWN_CALENDAR
    return Constraints(
        tainted=session.tainted,
        outside_recipients=outside_recipients,
        outside_attendees=outside_attendees,
        own_calendar=own_calendar,
    )


def approval_request(session: Session, args: Args, decision: Decision) -> ApprovalRequest:
    """Built only from the agent's structured arguments, never from any message text."""
    reason = decision.reason
    if session.tainted:
        reason = f"{reason}; session tainted: {session.taint_reason}"
    if isinstance(args, SendMailArgs):
        return ApprovalRequest(
            session_id=session.session_id,
            tool="send_mail",
            recipients=addresses(args.to + args.cc),
            subject=args.subject,
            body_preview=args.body[:BODY_PREVIEW_CHARS],
            reason=reason,
        )
    if isinstance(args, CreateEventArgs):
        return ApprovalRequest(
            session_id=session.session_id,
            tool="create_event",
            recipients=addresses(args.attendees),
            subject=args.title,
            body_preview=args.description[:BODY_PREVIEW_CHARS],
            reason=reason,
        )
    raise ValueError(f"no approval prompt defined for {type(args).__name__}")


def call_metadata(args: Args) -> dict[str, MetadataValue]:
    """Metadata safe to log: ids, counts and domains only."""
    if isinstance(args, ReadMessageArgs | DraftReplyArgs):
        return {"message_id": args.message_id}
    if isinstance(args, SendMailArgs):
        everyone = args.to + args.cc
        return {"recipient_count": len(everyone), "recipient_domains": domains(everyone)}
    if isinstance(args, CreateEventArgs):
        return {
            "calendar_own": args.calendar_id == OWN_CALENDAR,
            "attendee_count": len(args.attendees),
            "attendee_domains": domains(args.attendees),
        }
    return {}


# --- the gate ----------------------------------------------------------------


class Gate:
    def __init__(
        self, profile: Profile, backend: Backend, approver: Approver, log: AuditLog
    ) -> None:
        self.profile = profile
        self.backend = backend
        self.approver = approver
        self.log = log

    def handle(self, session: Session, tool: str, args: dict[str, Any]) -> Result:
        model = ARG_MODELS.get(tool)
        if model is None:
            decision = evaluate(self.profile, Action(tool=tool))
            return self._finish(session, tool, Result(False, decision.verdict, decision.reason))
        try:
            parsed = model.model_validate(args)
        except ValidationError:
            denied = Result(False, Verdict.DENY, "invalid arguments")
            return self._finish(session, tool, denied, {"error": "invalid_arguments"})
        return self._decide_and_run(session, tool, parsed)

    def _decide_and_run(self, session: Session, tool: str, args: Args) -> Result:
        action = Action(
            tool=tool, resource=RESOURCES[tool], constraints=constraints_for(session, args)
        )
        decision = evaluate(self.profile, action)
        meta = call_metadata(args)
        if decision.verdict == Verdict.DENY:
            return self._finish(session, tool, Result(False, Verdict.DENY, decision.reason), meta)
        approval: ApprovalOutcome | None = None
        if decision.verdict == Verdict.ASK:
            approval = self.approver.request(approval_request(session, args, decision))
            meta["approval"] = approval.value
            if approval != ApprovalOutcome.APPROVED:
                denied = Result(False, Verdict.ASK, decision.reason, approval=approval)
                return self._finish(session, tool, denied, meta)
        redact = decision.verdict == Verdict.ALLOW_REDACTED
        data, error = self._run(session, args, redact)
        if error:
            meta["error"] = error
        result = Result(error is None, decision.verdict, decision.reason, data, approval)
        return self._finish(session, tool, result, meta)

    def _run(self, session: Session, args: Args, redact: bool) -> tuple[Any, str | None]:
        """Call the backend and minimize. Applies taint after reads. Returns (data, error)."""
        b = self.backend
        if isinstance(args, SearchMailArgs):
            messages = b.search_messages(args.query, args.limit)
            taint_on_search(session, [m.sender for m in messages if m.snippet.strip()])
            return minimize_search(messages), None
        if isinstance(args, ReadMessageArgs):
            message = b.get_message(args.message_id)
            if message is None:
                return None, "not_found"
            taint_on_read_message(session, message.sender)
            return minimize_message(message, redact=redact), None
        if isinstance(args, ListEventsArgs):
            events = b.list_events(args.calendar_id, args.limit)
            taint_on_list_events(session, [e.organizer for e in events if e.description.strip()])
            return minimize_events(events), None
        if isinstance(args, DraftReplyArgs):
            message = b.get_message(args.message_id)
            if message is None:
                return None, "not_found"
            subject = f"Re: {message.subject}"
            draft_id = b.create_draft([message.sender], subject, args.body, message.id)
            return {"draft_id": draft_id}, None
        if isinstance(args, SendMailArgs):
            return {"sent_id": b.send_message(args.to, args.cc, args.subject, args.body)}, None
        if isinstance(args, CreateEventArgs):
            event_id = b.create_event(
                args.calendar_id, args.title, args.start, args.end, args.attendees, args.description
            )
            return {"event_id": event_id}, None
        raise ValueError(f"no runner for {type(args).__name__}")

    def _finish(
        self,
        session: Session,
        tool: str,
        result: Result,
        meta: dict[str, MetadataValue] | None = None,
    ) -> Result:
        row = dict(meta or {})
        row["profile"] = self.profile.name
        row["tainted"] = session.tainted
        if session.tainted:
            row["taint_reason"] = session.taint_reason
        self.log.append(session.session_id, tool[:64], result.verdict.value, result.reason, row)
        return result
