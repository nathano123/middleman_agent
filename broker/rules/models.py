"""Data types for the rules engine: what an agent wants to do, and what the gate says."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# The only tools v0 offers. Anything else is denied before rules are even read.
KNOWN_TOOLS: frozenset[str] = frozenset(
    {"search_mail", "read_message", "list_events", "draft_reply", "send_mail", "create_event"}
)

Resource = Literal["mail", "calendar"]

# Condition names a rule may test. Each one is a plain bool computed in Python.
Condition = Literal["tainted", "outside_recipients", "outside_attendees", "own_calendar"]


class Verdict(StrEnum):
    ALLOW = "allow"
    ALLOW_REDACTED = "allow_redacted"
    ASK = "ask"
    DENY = "deny"


# Higher number = stricter. When several rules match, the strictest wins.
STRICTNESS: dict[Verdict, int] = {
    Verdict.ALLOW: 0,
    Verdict.ALLOW_REDACTED: 1,
    Verdict.ASK: 2,
    Verdict.DENY: 3,
}


class Constraints(BaseModel):
    """Facts about one call, computed by the gate from the call's structured arguments."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tainted: bool = False
    outside_recipients: bool = False
    outside_attendees: bool = False
    own_calendar: bool = False


class Action(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str
    resource: Resource | None = None
    constraints: Constraints = Field(default_factory=Constraints)


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: Verdict
    reason: str


class Rule(BaseModel):
    """One profile line: if tool (and resource) match and every `when` holds, say `decision`."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str
    resource: Resource | None = None
    when: dict[Condition, bool] = Field(default_factory=dict[Condition, bool])
    decision: Verdict
    reason: str = Field(min_length=1)

    @field_validator("tool")
    @classmethod
    def tool_must_be_known(cls, value: str) -> str:
        if value not in KNOWN_TOOLS:
            raise ValueError(f"unknown tool {value!r}")
        return value


class Profile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)
    description: str = ""
    rules: list[Rule] = Field(min_length=1)
