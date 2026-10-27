"""Local usage counters: numbers per day, no content. Written to a JSON file, never sent anywhere.

record() accepts only enums, booleans and a date, so a subject, body, address or snippet has
no way in. `broker report` reads the file and prints the weekly summary a tester sends back.
"""

import json
import statistics
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from broker.approvals.base import ApprovalOutcome
from broker.files import write_private_text
from broker.rules.models import Verdict


def empty_day() -> dict[str, Any]:
    return {
        "calls": 0,
        "decisions": {v.value: 0 for v in Verdict},
        "prompts": 0,
        "approvals": {o.value: 0 for o in ApprovalOutcome},
        "watch_would_have": {v.value: 0 for v in Verdict},
        "reconsents": 0,  # times Google refused the stored grant (testing mode: every 7 days)
        "approval_latency_seconds": [],  # phone: message sent -> answer received
    }


class Counters:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.days: dict[str, dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        """Re-read before each change: several broker processes (one per agent) share the file.
        This narrows lost updates to near-simultaneous writes; it does not remove them."""
        if self.path.exists():
            self.days = json.loads(self.path.read_text(encoding="utf-8")).get("days", {})

    def record(
        self,
        day: date,
        decision: Verdict,
        approval: ApprovalOutcome | None,
        would_have: Verdict | None,
    ) -> None:
        self.reload()
        row = self.days.setdefault(day.isoformat(), empty_day())
        row["calls"] += 1
        row["decisions"][Verdict(decision).value] += 1
        if approval is not None:
            row["prompts"] += 1
            row["approvals"][ApprovalOutcome(approval).value] += 1
        if would_have is not None:
            row["watch_would_have"][Verdict(would_have).value] += 1
        self.save()

    def record_reconsent(self, day: date) -> None:
        self.reload()
        row = self.days.setdefault(day.isoformat(), empty_day())
        row["reconsents"] = row.get("reconsents", 0) + 1
        self.save()

    def record_latency(self, day: date, seconds: float) -> None:
        self.reload()
        row = self.days.setdefault(day.isoformat(), empty_day())
        row.setdefault("approval_latency_seconds", []).append(round(float(seconds), 1))
        self.save()

    def save(self) -> None:
        payload = {"version": 1, "days": self.days}
        write_private_text(self.path, json.dumps(payload, indent=2, sort_keys=True))


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
        f"Google re-consents needed: {sum(d.get('reconsents', 0) for d in window)}",
        latency_line([s for d in window for s in d.get("approval_latency_seconds", [])]),
    ]
    return "\n".join(lines)


def latency_line(samples: list[float]) -> str:
    if not samples:
        return "phone approval latency: no phone answers"
    return (
        f"phone approval latency: median {statistics.median(samples):.1f}s, "
        f"max {max(samples):.1f}s over {len(samples)} answers"
    )
