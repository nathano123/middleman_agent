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
    action_hash,
    final_outcome,
)
from broker.audit import AuditLog, MetadataValue
from broker.backends.base import Backend, BackendError, Event, Message
from broker.config import BrokerConfig
from broker.counters import Counters
from broker.minimizer import minimize_events, minimize_message, minimize_search
from broker.rules.evaluator import evaluate
from broker.rules.models import Action, Constraints, Decision, Profile, Resource, Verdict
from broker.taint import (
    Contacts,
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
    would_have: Verdict | None = None  # watch mode only: what enforce mode would have done
    error: str | None = None  # stable code when the call could not run (never content)


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


PromptFields = tuple[str, list[str], str, str, dict[str, str]]


def prompt_fields(args: Args) -> PromptFields:
    """(tool, recipients, subject, body, details) taken from the agent's own arguments."""
    if isinstance(args, SendMailArgs):
        return "send_mail", addresses(args.to + args.cc), args.subject, args.body, {}
    if isinstance(args, CreateEventArgs):
        details = {"calendar": args.calendar_id, "start": args.start, "end": args.end}
        return "create_event", addresses(args.attendees), args.title, args.description, details
    if isinstance(args, DraftReplyArgs):
        # The draft's recipient comes from the stored message, so it is not shown here.
        subject = f"draft reply to message {args.message_id}"
        return "draft_reply", [], subject, args.body, {}
    raise ValueError(f"no approval prompt defined for {type(args).__name__}")


def sends_invitations(args: Args) -> bool:
    return isinstance(args, CreateEventArgs) and bool(args.attendees)


def approval_request(
    session: Session, args: Args, decision: Decision, config: BrokerConfig
) -> ApprovalRequest:
    """Built only from the agent's structured arguments and the agent's approval history.

    No Message or Event ever reaches this function; see tests/unit/test_prompt.py.
    """
    tool, recipients, subject, body, details = prompt_fields(args)
    invites = sends_invitations(args)
    reason = decision.reason
    if session.tainted:
        reason = f"{reason}; session tainted: {session.taint_reason}"
    day = session.today()
    number = session.history.prompts(session.agent_id, day) + 1
    approved_before = session.history.approved(session.agent_id, day)
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
        new_recipients=[r for r in recipients if r not in approved_before],
        requires_full_view=long_and_tainted or number > config.full_view_after_approvals,
        full_body=body,
        sends_invitations=invites,
        details=details,
        action_hash=action_hash(tool, recipients, subject, body, invites, details),
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


def description_authors(event: Event) -> list[str]:
    return event.description_authors or [event.organizer]


def reply_address(contacts: Contacts, message: Message) -> tuple[str, str | None]:
    """Where a draft reply goes: the From address, or Reply-To only if it is a known contact or
    one of your own addresses. Returns (address, domain of an ignored Reply-To or None)."""
    sender = normalize_address(message.sender)
    reply_to = normalize_address(message.reply_to) if message.reply_to else ""
    if not reply_to or reply_to == sender or contacts.is_known(reply_to):
        return reply_to or sender, None
    return sender, reply_to.rpartition("@")[2]


def pending_data(approval_id: str) -> dict[str, str]:
    return {
        "status": "pending",
        "done": "no",
        "approval_id": approval_id,
        "next_step": (
            "Tell the user to approve it on their device, then call the same tool again with "
            "identical arguments."
        ),
    }


# --- the gate ----------------------------------------------------------------


class Gate:
    def __init__(
        self,
        profile: Profile,
        backend: Backend,
        approver: Approver,
        log: AuditLog,
        config: BrokerConfig,
        counters: Counters | None = None,
    ) -> None:
        self.config = config
        self._mode = config.mode  # fixed at start-up; no tool call can change it
        self.profile = profile
        self.backend = backend
        self.approver = approver
        self.log = log
        self.counters = counters

    @property
    def mode(self) -> str:
        return self._mode

    def handle(self, session: Session, tool: str, args: dict[str, Any]) -> Result:
        model = ARG_MODELS.get(tool)
        if model is None:
            decision = evaluate(self.profile, Action(tool=tool))
            return self._finish(session, tool, Result(False, decision.verdict, decision.reason))
        try:
            parsed = model.model_validate(args)
        except ValidationError:
            denied = Result(False, Verdict.DENY, "invalid arguments", error="invalid_arguments")
            return self._finish(session, tool, denied, {"error": "invalid_arguments"})
        return self._decide_and_run(session, tool, parsed)

    def _decide_and_run(self, session: Session, tool: str, args: Args) -> Result:
        action = Action(
            tool=tool, resource=RESOURCES[tool], constraints=constraints_for(session, args)
        )
        decision = evaluate(self.profile, action)
        meta = call_metadata(args)
        if self._mode == "watch":
            return self._watch(session, tool, args, decision, meta)
        if decision.verdict == Verdict.DENY:
            return self._finish(session, tool, Result(False, Verdict.DENY, decision.reason), meta)
        approval: ApprovalOutcome | None = None
        approved_hash: str | None = None
        if decision.verdict == Verdict.ASK:
            approval, approval_id, approved_hash = self._ask(session, args, decision)
            meta["approval"] = approval.value
            if approval != ApprovalOutcome.APPROVED:
                data = pending_data(approval_id) if approval == ApprovalOutcome.PENDING else None
                denied = Result(False, Verdict.ASK, decision.reason, data, approval=approval)
                return self._finish(session, tool, denied, meta)
        redact = decision.verdict == Verdict.ALLOW_REDACTED
        data, error = self._run(session, args, redact, meta, approved_hash)
        if error:
            meta["error"] = error
        result = Result(
            error is None, decision.verdict, decision.reason, data, approval, None, error
        )
        return self._finish(session, tool, result, meta)

    def _watch(
        self,
        session: Session,
        tool: str,
        args: Args,
        decision: Decision,
        meta: dict[str, MetadataValue],
    ) -> Result:
        """Trial days 1-3: log what enforce mode would have done, then run the call anyway."""
        meta["would_have"] = decision.verdict.value
        redact = decision.verdict == Verdict.ALLOW_REDACTED
        data, error = self._run(session, args, redact, meta, None)
        if error:
            meta["error"] = error
        reason = f"watch mode; would have {decision.verdict.value}: {decision.reason}"
        result = Result(
            error is None, Verdict.ALLOW, reason, data, would_have=decision.verdict, error=error
        )
        return self._finish(session, tool, result, meta)

    def _ask(
        self, session: Session, args: Args, decision: Decision
    ) -> tuple[ApprovalOutcome, str, str]:
        """Returns (outcome, approval id, approved action hash)."""
        req = approval_request(session, args, decision, self.config)
        day = session.today()
        response = self.approver.request(req)
        if response.new_prompt:  # a retry of a queued request is not a new prompt
            session.history.record_prompt(session.agent_id, day)
        outcome = final_outcome(req, response)
        if outcome == ApprovalOutcome.APPROVED:
            session.history.add_approved(session.agent_id, day, req.recipients)
        return outcome, response.approval_id, req.action_hash

    def _run(
        self,
        session: Session,
        args: Args,
        redact: bool,
        meta: dict[str, MetadataValue],
        approved_hash: str | None,
    ) -> tuple[Any, str | None]:
        """Call the backend; backend errors become a content-free error code."""
        try:
            return self._call_backend(session, args, redact, meta, approved_hash)
        except BackendError as exc:
            return None, exc.code

    def _call_backend(
        self,
        session: Session,
        args: Args,
        redact: bool,
        meta: dict[str, MetadataValue],
        approved_hash: str | None,
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
            meta["bulk"] = message.bulk
            taint_on_read_message(session, message)
            return minimize_message(message, redact=redact), None
        if isinstance(args, ListEventsArgs):
            events = b.list_events(args.calendar_id, args.limit)
            authors = [a for e in events if e.description.strip() for a in description_authors(e)]
            taint_on_list_events(session, authors)
            return minimize_events(events), None
        if isinstance(args, DraftReplyArgs):
            message = b.get_message(args.message_id)
            if message is None:
                return None, "not_found"
            to, ignored = reply_address(session.contacts, message)
            draft_id = b.create_draft([to], f"Re: {message.subject}", args.body, message.id)
            data: dict[str, Any] = {"draft_id": draft_id, "to": [to]}
            if ignored:
                meta["reply_to_ignored"] = True
                data["reply_to_ignored"] = (
                    f"Reply-To pointed to an outside address at {ignored}; the draft is "
                    "addressed to the sender instead."
                )
            return data, None
        if isinstance(args, SendMailArgs):
            sent = b.send_message(args.to, args.cc, args.subject, args.body, approved_hash)
            return {"sent_id": sent}, None
        if isinstance(args, CreateEventArgs):
            event_id = b.create_event(
                args.calendar_id,
                args.title,
                args.start,
                args.end,
                args.attendees,
                args.description,
                approved_hash,
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
        row["mode"] = self._mode
        row["agent_id"] = session.agent_id[:64]
        if session.client_hint:
            row["client_hint"] = session.client_hint[:64]
        row["tainted"] = session.tainted
        if session.tainted:
            row["taint_reason"] = session.taint_reason
        self.log.append(session.session_id, tool[:64], result.verdict.value, result.reason, row)
        if self.counters is not None:
            day = session.clock().date()
            self.counters.record(day, result.verdict, result.approval, result.would_have)
        return result
