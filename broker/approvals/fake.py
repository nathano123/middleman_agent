"""Scriptable approver for tests: answers from a queue, then falls back to a default."""

from dataclasses import dataclass, field

from broker.approvals.base import ApprovalOutcome, ApprovalRequest


@dataclass
class FakeApprover:
    script: list[ApprovalOutcome] = field(default_factory=list[ApprovalOutcome])
    default: ApprovalOutcome = ApprovalOutcome.DENIED
    views_full_body: bool = False  # simulates the user opening the full body before answering
    requests: list[ApprovalRequest] = field(default_factory=list[ApprovalRequest])
    answers: list[ApprovalOutcome] = field(default_factory=list[ApprovalOutcome])

    def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        self.requests.append(req)
        answer = self.script.pop(0) if self.script else self.default
        self.answers.append(answer)
        return answer
