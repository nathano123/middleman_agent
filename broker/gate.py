"""The single entry point for every tool call: rules → approval → backend → minimizer → log.

handle() never raises for agent input. Every call, allowed or not, writes exactly one log row.
"""

import hashlib
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from broker.approvals.base import (
    BODY_PREVIEW_CHARS,
    ApprovalOutcome,
    ApprovalRequest,
    Approver,
    final_outcome,
)
from broker.audit import AuditLog, MetadataValue
from broker.backends.base import Backend
from broker.config import BrokerConfig
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


def prompt_fields(args: Args) -> tuple[str, list[str], str, str]:
    """(tool, recipients, subject, body) taken from the agent's own arguments."""
    if isinstance(args, SendMailArgs):
        return "send_mail", addresses(args.to + args.cc), args.subject, args.body
    if isinstance(args, CreateEventArgs):
        return "create_event", addresses(args.attendees), args.title, args.description
    raise ValueError(f"no approval prompt defined for {type(args).__name__}")


def approval_request(
    session: Session, args: Args, decision: Decision, config: BrokerConfig
) -> ApprovalRequest:
    """Built only from the agent's structured arguments and session counters.

    No Message or Event ever reaches this function; see tests/unit/test_prompt.py.
    """
    tool, recipients, subject, body = prompt_fields(args)
    reason = decision.reason
    if session.tainted:
        reason = f"{reason}; session tainted: {session.taint_reason}"
    number = session.approvals + 1
    long_and_tainted = session.tainted and len(body) > config.full_view_body_chars
    return ApprovalRequest(
        session_id=session.session_id,
        tool=tool,
        recipients=recipients,
        subject=subject,
        body_preview=body[:BODY_PREVIEW_CHARS],
        reason=reason,
        body_length=len(body),
        more_chars=max(0, len(body) - BODY_PREVIEW_CHARS),
        body_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest()[:12],
        approval_number=number,
        outside_recipients=[r for r in recipients if not session.is_known(r)],
        new_recipients=[r for r in recipients if r not in session.approved_recipients],
        requires_full_view=long_and_tainted or number > config.full_view_after_approvals,
        full_body=body,
    )


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
        self,
        profile: Profile,
        backend: Backend,
        approver: Approver,
        log: AuditLog,
        config: BrokerConfig,
    ) -> None:
        self.config = config
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
            approval = self._ask(session, args, decision)
            meta["approval"] = approval.value
            if approval != ApprovalOutcome.APPROVED:
                denied = Result(False, Verdict.ASK, decision.reason, approval=approval)
                return self._finish(session, tool, denied, meta)
        redact = decision.verdict == Verdict.ALLOW_REDACTED
        data, error = self._run(session, args, redact, meta)
        if error:
            meta["error"] = error
        result = Result(error is None, decision.verdict, decision.reason, data, approval)
        return self._finish(session, tool, result, meta)

    def _ask(self, session: Session, args: Args, decision: Decision) -> ApprovalOutcome:
        req = approval_request(session, args, decision, self.config)
        session.approvals = req.approval_number
        outcome = final_outcome(req, self.approver.request(req))
        if outcome == ApprovalOutcome.APPROVED:
            session.approved_recipients.update(req.recipients)
        return outcome

    def _run(
        self, session: Session, args: Args, redact: bool, meta: dict[str, MetadataValue]
    ) -> tuple[Any, str | None]:
        """Call the backend and minimize. Applies taint after reads. Returns (data, error)."""
        b = self.backend
        if isinstance(args, SearchMailArgs):
            messages = b.search_messages(args.query, args.limit)
            taint_on_search(session, messages)
            return minimize_search(messages), None
        if isinstance(args, ReadMessageArgs):
            message = b.get_message(args.message_id)
            if message is None:
                return None, "not_found"
            meta["auth_result"] = message.auth_result
            taint_on_read_message(session, message)
            return minimize_message(message, redact=redact), None
        if isinstance(args, ListEventsArgs):
            events = b.list_events(args.calendar_id, args.limit)
            taint_on_list_events(session, [e.organizer for e in events if e.description.strip()])
            return minimize_events(events), None
        if isinstance(args, DraftReplyArgs):
            message = b.get_message(args.message_id)
            if message is None:
                return None, "not_found"
            to = normalize_address(message.reply_to or message.sender)
            draft_id = b.create_draft([to], f"Re: {message.subject}", args.body, message.id)
            return {"draft_id": draft_id, "to": [to]}, None
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
        row["agent_id"] = session.agent_id[:64]
        row["tainted"] = session.tainted
        if session.tainted:
            row["taint_reason"] = session.taint_reason
        self.log.append(session.session_id, tool[:64], result.verdict.value, result.reason, row)
        return result
