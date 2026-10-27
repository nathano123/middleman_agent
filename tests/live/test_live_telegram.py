"""Live phone check: one real Telegram message to the owner, then wait for a tap.

    BROKER_LIVE_PHONE=1 uv run pytest tests/live/test_live_telegram.py -s

Needs `broker phone setup` done (token and owner id in the keychain). Sends dummy text only
(no mail content, a made-up recipient) and uses a throwaway queue in a temp directory.
Tap Approve on your phone within 2 minutes.
"""

import os
import time
from pathlib import Path

import pytest

from broker.approvals.base import ApprovalOutcome
from broker.approvals.queue import ApprovalQueue, QueueApprover
from broker.approvals.telegram import OWNER_ENTRY, TOKEN_ENTRY, HttpTelegram, TelegramChannel
from broker.audit import KeyringKeyStore
from broker.counters import Counters
from tests.fake_telegram import request

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("BROKER_LIVE_PHONE") != "1", reason="set BROKER_LIVE_PHONE=1"
    ),
]


def test_live_round_trip_to_phone(tmp_path: Path) -> None:
    keys = KeyringKeyStore()
    token, owner = keys.get(TOKEN_ENTRY), keys.get(OWNER_ENTRY)
    assert token and owner, "run `broker phone setup` first"
    queue = ApprovalQueue(tmp_path / "approvals.db")
    counters = Counters(tmp_path / "counters.json")
    channel = TelegramChannel(
        HttpTelegram(token), int(owner), queue, tmp_path / "approvals.db",
        tmp_path / "phone.lock", counters=counters,
    )  # fmt: skip
    approver = QueueApprover(queue, "agt_live", wait_seconds=120, channel=channel)
    started = time.monotonic()
    print("\nSent. Tap ✅ Approve on your phone.")
    response = approver.request(request("live test body (dummy)", subject="Live phone test"))
    elapsed = time.monotonic() - started
    latency = [s for d in counters.days.values() for s in d["approval_latency_seconds"]]
    print(f"outcome={response.outcome} call took {elapsed:.1f}s, message-to-tap {latency}")
    assert response.outcome == ApprovalOutcome.APPROVED
