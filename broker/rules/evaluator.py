"""Deny-by-default rule evaluator and YAML profile loader.

How a decision is made:
1. A tool outside KNOWN_TOOLS is denied.
2. Every rule whose tool, resource and `when` conditions match is collected.
3. No match: deny. Otherwise the strictest matching decision wins
   (deny > ask > allow_redacted > allow), so no rule can widen another rule's deny.
"""

from pathlib import Path

import yaml
from pydantic import ValidationError

from broker.config import ProfileName
from broker.rules.models import KNOWN_TOOLS, STRICTNESS, Action, Decision, Profile, Rule, Verdict

PROFILES_DIR = Path(__file__).parent / "profiles"
PROFILE_NAMES: tuple[ProfileName, ...] = ("cautious", "working", "autonomous")


class ProfileError(Exception):
    """A profile file is missing, not valid YAML, or does not match the schema."""


def load_profile_file(path: Path) -> Profile:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ProfileError(f"cannot read profile {path}: {exc}") from exc
    try:
        return Profile.model_validate(raw)
    except ValidationError as exc:
        raise ProfileError(f"invalid profile {path}: {exc}") from exc


def load_profile(name: str) -> Profile:
    if name not in PROFILE_NAMES:
        raise ProfileError(f"unknown profile {name!r}; choose one of {', '.join(PROFILE_NAMES)}")
    return load_profile_file(PROFILES_DIR / f"{name}.yaml")


def rule_matches(rule: Rule, action: Action) -> bool:
    if rule.tool != action.tool:
        return False
    if rule.resource is not None and rule.resource != action.resource:
        return False
    facts = action.constraints.model_dump()
    return all(facts[condition] == expected for condition, expected in rule.when.items())


def evaluate(profile: Profile, action: Action) -> Decision:
    if action.tool not in KNOWN_TOOLS:
        return Decision(verdict=Verdict.DENY, reason=f"tool {action.tool!r} is not offered")
    matches = [rule for rule in profile.rules if rule_matches(rule, action)]
    if not matches:
        return Decision(verdict=Verdict.DENY, reason="no rule allows this action")
    strictest = max(matches, key=lambda rule: STRICTNESS[rule.decision])
    return Decision(verdict=strictest.decision, reason=strictest.reason)
