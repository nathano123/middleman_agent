"""Local usage counters: numbers per day, no content. Written to a JSON file, never sent anywhere.

record() accepts only enums, booleans and a date, so a subject, body, address or snippet has
no way in. `broker report` reads the file and prints the weekly summary a tester sends back.
"""

import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from broker.approvals.base import ApprovalOutcome
from broker.rules.models import Verdict


def empty_day() -> dict[str, Any]:
    return {
        "calls": 0,
        "decisions": {v.value: 0 for v in Verdict},
        "prompts": 0,
        "approvals": {o.value: 0 for o in ApprovalOutcome},
        "watch_would_have": {v.value: 0 for v in Verdict},
    }


class Counters:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.days: dict[str, dict[str, Any]] = {}
        if path.exists():
            self.days = json.loads(path.read_text(encoding="utf-8")).get("days", {})

    def record(
        self,
        day: date,
        decision: Verdict,
        approval: ApprovalOutcome | None,
        would_have: Verdict | None,
    ) -> None:
        row = self.days.setdefault(day.isoformat(), empty_day())
        row["calls"] += 1
        row["decisions"][Verdict(decision).value] += 1
        if approval is not None:
            row["prompts"] += 1
            row["approvals"][ApprovalOutcome(approval).value] += 1
        if would_have is not None:
            row["watch_would_have"][Verdict(would_have).value] += 1
        self.save()

    def save(self) -> None:
        payload = {"version": 1, "days": self.days}
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def weekly_report(counters: Counters, end: date) -> str:
    start = end - timedelta(days=6)
    window = [
        counters.days.get((start + timedelta(days=i)).isoformat(), empty_day()) for i in range(7)
    ]
    active = [d for d in window if d["calls"] > 0]
    calls = sum(d["calls"] for d in window)
    prompts = sum(d["prompts"] for d in window)

    def total(section: str, key: str) -> int:
        return sum(d[section][key] for d in window)

    refused = sum(total("approvals", o) for o in ("denied", "timeout", "unviewed"))
    lines = [
        f"Agent broker weekly report {start.isoformat()} to {end.isoformat()}",
        f"days with at least one call: {len(active)} of 7",
        f"calls: {calls}",
        f"prompts: {prompts} ({prompts / max(len(active), 1):.1f} per active day; target < 5)",
        f"approved: {total('approvals', 'approved')}, refused: {refused} "
        f"(denied {total('approvals', 'denied')}, timeout {total('approvals', 'timeout')}, "
        f"unviewed {total('approvals', 'unviewed')})",
        "decisions: " + ", ".join(f"{v.value} {total('decisions', v.value)}" for v in Verdict),
        "watch mode would have: "
        + ", ".join(f"{v.value} {total('watch_would_have', v.value)}" for v in Verdict),
    ]
    return "\n".join(lines)
