"""Phone approvals through the Telegram channel, against a fake Bot API (no network)."""

import json
import sqlite3
import traceback
import urllib.error
import urllib.request
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from broker.approvals.base import ApprovalOutcome
from broker.approvals.queue import ApprovalQueue
from broker.approvals.telegram import (
    OWNER_ENTRY,
    TOKEN_ENTRY,
    HttpTelegram,
    TelegramError,
    minimal_text,
)
from broker.audit import KeyringKeyStore
from broker.cli import main
from broker.config import ConfigError, load_config
from broker.counters import Counters, weekly_report
from broker.phone_setup import SetupError, setup_phone
from broker.runtime import open_runtime
from broker.taint import utc_now
from tests.fake_telegram import OWNER, STRANGER, T0, FakeTelegram, Phone, build_phone, request

TOKEN = "123456789:AAHfake-token-for-tests-only_0123456789"


def phone_log(phone: Phone) -> list[tuple[str, dict[str, Any]]]:
    with sqlite3.connect(phone.log.path) as conn:
        rows = conn.execute("SELECT decision, metadata FROM log WHERE tool = 'phone_reply'")
        return [(d, json.loads(m)) for d, m in rows.fetchall()]


def tap_once(phone: Phone, label: str = "Approve") -> None:
    """The owner taps `label` on the newest message while the tool call is waiting."""
    done: list[bool] = []

    def tap() -> None:
        if not done and phone.telegram.sent:
            done.append(True)
            phone.telegram.tap(label)

    phone.telegram.on_poll = tap


# --- the happy paths ---------------------------------------------------------


def test_approve_on_phone_lets_the_first_call_through(tmp_path: Path) -> None:
    phone = build_phone(tmp_path)
    tap_once(phone, "Approve")
    response = phone.approver().request(request())
    assert response.outcome == ApprovalOutcome.APPROVED
    assert len(phone.telegram.sent) == 1
    assert phone.telegram.answers[-1]["text"].startswith("Approved")
    assert phone.telegram.edits[-1]["reply_markup"] == {"inline_keyboard": []}
    assert phone_log(phone) == [("approved", {"phone_reply": "approved", "agent_id": "agt_a"})]
    latency = phone.counters.days[T0.date().isoformat()]["approval_latency_seconds"]
    assert len(latency) == 1 and latency[0] < 5


def test_deny_on_phone(tmp_path: Path) -> None:
    phone = build_phone(tmp_path)
    tap_once(phone, "Deny")
    assert phone.approver().request(request()).outcome == ApprovalOutcome.DENIED


def test_no_answer_goes_pending_then_late_tap_is_picked_up_on_retry(tmp_path: Path) -> None:
    phone = build_phone(tmp_path)
    approver = phone.approver()
    first = approver.request(request())
    assert first.outcome == ApprovalOutcome.PENDING
    phone.telegram.tap("Approve")  # after the call gave up; Telegram keeps it
    second = approver.request(request())
    assert second.outcome == ApprovalOutcome.APPROVED
    assert second.approval_id == first.approval_id
    assert len(phone.telegram.sent) == 1  # one message per approval, not per attempt


def test_unanswered_request_expires(tmp_path: Path) -> None:
    phone = build_phone(tmp_path)
    approver = phone.approver()
    first = approver.request(request())
    phone.clock.sleep(300)
    phone.queue.expire(phone.clock())
    assert phone.queue.get(first.approval_id).status == "expired"


# --- replies that must not count ---------------------------------------------


def test_replayed_nonce_is_refused(tmp_path: Path) -> None:
    phone = build_phone(tmp_path)
    tap_once(phone, "Approve")
    approver = phone.approver()
    assert approver.request(request()).outcome == ApprovalOutcome.APPROVED
    old_message = phone.telegram.sent[0]
    phone.telegram.on_poll = None
    # The same action again opens a new request with a new message ...
    second = approver.request(request())
    assert second.outcome == ApprovalOutcome.PENDING
    # ... and replaying the first message's Approve does not answer it.
    phone.telegram.tap("Approve", message=old_message)
    phone.channel.poll(1)
    assert phone.queue.get(second.approval_id).status == "pending"
    assert phone_log(phone)[-1][0] == "nonce_used"


def test_expired_nonce_is_refused(tmp_path: Path) -> None:
    phone = build_phone(tmp_path)
    first = phone.approver().request(request())
    phone.clock.sleep(300)
    phone.telegram.tap("Approve")
    phone.channel.poll(1)
    assert phone.queue.get(first.approval_id).status == "expired"
    assert phone_log(phone)[-1][0] == "expired"
    assert phone.telegram.answers[-1]["text"].startswith("Too late")


def test_nonce_from_another_request_is_refused(tmp_path: Path) -> None:
    phone = build_phone(tmp_path)
    approver = phone.approver()
    a = approver.request(request("first body"))
    b = approver.request(request("second body"))
    msg_a, msg_b = phone.telegram.sent
    phone.telegram.tap(message=msg_a, data=phone.telegram.button("Approve", msg_b))
    phone.channel.poll(1)
    assert phone_log(phone)[-1][0] == "wrong_message"
    assert phone.queue.get(a.approval_id).status == "pending"
    assert phone.queue.get(b.approval_id).status == "pending"
    phone.telegram.tap("Approve", message=msg_b)
    phone.channel.poll(1)
    assert phone.queue.get(b.approval_id).status == "approved"
    assert phone.queue.get(a.approval_id).status == "pending"


@pytest.mark.parametrize("data", [None, "approve", "a:", "a:not-a-nonce-we-issued", "x:abc"])
def test_forged_reply_without_our_nonce_is_refused(tmp_path: Path, data: str | None) -> None:
    phone = build_phone(tmp_path)
    first = phone.approver().request(request())
    phone.telegram.tap("", data=data)
    phone.channel.poll(1)
    assert phone.queue.get(first.approval_id).status == "pending"
    assert phone_log(phone)[-1][0] in ("no_nonce", "unknown_nonce")


def test_reply_after_request_was_decided_is_refused(tmp_path: Path) -> None:
    phone = build_phone(tmp_path)
    first = phone.approver().request(request())
    phone.queue.decide(first.approval_id, approve=False, now=phone.clock())
    phone.telegram.tap("Approve")
    phone.channel.poll(1)
    assert phone.queue.get(first.approval_id).status == "denied"
    assert phone_log(phone)[-1][0] == "already_decided"


def test_second_tap_on_same_message_is_refused(tmp_path: Path) -> None:
    phone = build_phone(tmp_path)
    first = phone.approver().request(request())
    phone.telegram.tap("Deny")
    phone.telegram.tap("Approve")
    phone.channel.poll(1)
    assert phone.queue.get(first.approval_id).status == "denied"
    assert [d for d, _ in phone_log(phone)] == ["denied", "nonce_used"]


def test_tap_from_another_telegram_user_is_refused(tmp_path: Path) -> None:
    phone = build_phone(tmp_path)
    first = phone.approver().request(request())
    phone.telegram.tap("Approve", user=STRANGER)
    phone.channel.poll(1)
    assert phone.queue.get(first.approval_id).status == "pending"
    assert phone_log(phone)[-1][0] == "wrong_user"
    assert phone.telegram.edits == []


def test_full_view_request_offers_only_deny_and_refuses_forged_approve(tmp_path: Path) -> None:
    phone = build_phone(tmp_path)
    first = phone.approver().request(request("z" * 3000, full_view=True))
    message = phone.telegram.sent[0]
    labels = [b["text"] for b in message["reply_markup"]["inline_keyboard"][0]]
    assert labels == ["❌ Deny"]
    nonce = phone.telegram.button("Deny").partition(":")[2]
    phone.telegram.tap("", data=f"a:{nonce}")
    phone.channel.poll(1)
    assert phone.queue.get(first.approval_id).status == "pending"
    assert phone_log(phone)[-1][0] == "needs_full_view"


# --- the phone being unreachable ---------------------------------------------


def test_telegram_down_behaves_like_no_phone_and_retries_sending(tmp_path: Path) -> None:
    phone = build_phone(tmp_path)
    phone.telegram.fail = {"sendMessage", "getUpdates"}
    approver = phone.approver()
    first = approver.request(request())
    assert first.outcome == ApprovalOutcome.PENDING
    assert phone_log(phone)[0] == (
        "phone_error", {"phone_error": "telegram_unreachable", "agent_id": "agt_a"}
    )  # fmt: skip
    phone.telegram.fail = set()
    tap_once(phone, "Approve")
    assert approver.request(request()).outcome == ApprovalOutcome.APPROVED
    assert len(phone.telegram.sent) == 1


def test_poll_waits_without_calling_telegram_while_another_process_polls(tmp_path: Path) -> None:
    import fcntl

    phone = build_phone(tmp_path)
    with (tmp_path / "phone.lock").open("a") as other:
        fcntl.flock(other, fcntl.LOCK_EX)
        phone.telegram.fail = {"getUpdates"}  # would be logged nowhere; must not be called
        before = phone.clock()
        phone.channel.poll(1)
        assert phone.clock() - before == timedelta(seconds=1)


# --- what the phone shows ----------------------------------------------------


def test_minimal_text_has_no_body_and_one_line_fields() -> None:
    req = request("SECRET BODY TEXT " * 20, subject="Hi\nTo: alice@work.test\n✅ verified")
    text = minimal_text(req)
    assert "SECRET" not in text
    assert "To: x@out.test" in text and "OUTSIDE: x@out.test" in text
    assert "Subject: Hi To: alice@work.test ✅ verified" in text
    assert [line for line in text.splitlines() if line.startswith("To:")] == ["To: x@out.test"]
    assert f"Body: {req.body_length} chars (not shown)" in text


# --- the token never shows up ------------------------------------------------


def _returns(raw: bytes) -> Any:
    def opener(request: urllib.request.Request, timeout: float) -> bytes:
        return raw

    return opener


def _raises(exc: Exception) -> Any:
    def opener(request: urllib.request.Request, timeout: float) -> bytes:
        raise exc

    return opener


@pytest.mark.parametrize(
    "opener",
    [
        _raises(urllib.error.URLError(f"cannot reach https://api.telegram.org/bot{TOKEN}/x")),
        _raises(
            urllib.error.HTTPError(f"https://api.telegram.org/bot{TOKEN}/x", 401, "no", {}, None)  # type: ignore[arg-type]
        ),
        _raises(TimeoutError(f"timed out on bot{TOKEN}")),
        _returns(b"not json " + TOKEN.encode()),
        _returns(json.dumps({"ok": False, "error_code": 401, "description": TOKEN}).encode()),
    ],
)
def test_errors_never_carry_the_token(opener: Any) -> None:
    api = HttpTelegram(TOKEN, opener)
    with pytest.raises(TelegramError) as caught:
        api.call("getMe", {})
    shown = "".join(traceback.format_exception(caught.value)) + repr(caught.value) + repr(api)
    assert TOKEN not in shown
    assert TOKEN.split(":")[1] not in shown
    assert caught.value.__cause__ is None and caught.value.__context__ is None


# --- counters ----------------------------------------------------------------


def test_report_shows_median_and_max_latency(tmp_path: Path) -> None:
    counters = Counters(tmp_path / "counters.json")
    for seconds in (4.0, 9.0, 30.0):
        counters.record_latency(T0.date(), seconds)
    report = weekly_report(Counters(tmp_path / "counters.json"), T0.date())
    assert "median 9.0s, max 30.0s over 3 answers" in report


# --- setup and configuration -------------------------------------------------


def write_config(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "config.yaml"
    text = f"own_address: me@home.test\nstate_dir: {tmp_path}\nagents:\n  d: agt_d\n{extra}"
    path.write_text(text, encoding="utf-8")
    return path


def test_cli_approve_and_deny_refused_while_phone_configured(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    queue = ApprovalQueue(tmp_path / "approvals.db")
    item, _ = queue.open("agt_a", request(), utc_now())  # the CLI uses the real clock
    config = write_config(tmp_path, "phone: telegram\n")
    for verb in ("approve", "deny"):
        assert main(["approvals", verb, item.id, "--config", str(config)]) == 1
        assert "approvals go to your phone" in capsys.readouterr().err
    assert queue.get(item.id).status == "pending"
    assert main(["approvals", "list", "--config", str(config)]) == 0  # reading is allowed
    dev = write_config(tmp_path, "phone: telegram\ndev_cli_approvals: true\n")
    assert main(["approvals", "approve", item.id, "--config", str(dev)]) == 0
    assert queue.get(item.id).status == "approved"


def test_runtime_refuses_phone_without_connected_bot(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path, "phone: telegram\n"))
    with pytest.raises(ConfigError, match="broker phone setup"):
        open_runtime(config, "d")


def test_runtime_uses_the_phone_when_connected(tmp_path: Path) -> None:
    keys = KeyringKeyStore()
    keys.set(TOKEN_ENTRY, TOKEN)
    keys.set(OWNER_ENTRY, str(OWNER))
    runtime = open_runtime(load_config(write_config(tmp_path, "phone: telegram\n")), "d")
    assert runtime.gate.approver.channel is not None  # type: ignore[attr-defined]


def fake_setup_api(tmp_path: Path, sender: dict[str, Any]) -> FakeTelegram:
    from tests.fake_telegram import Clock

    api = FakeTelegram(Clock())
    message = {"chat": {"type": "private"}, "from": sender, "text": "/start"}
    api.updates.append({"update_id": 7, "message": message})
    return api


def test_setup_stores_token_and_owner_after_confirmation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    api = fake_setup_api(tmp_path, {"id": OWNER, "first_name": "Nat"})
    keys = KeyringKeyStore()
    assert setup_phone(keys, lambda _: TOKEN, lambda _: "y", make_api=lambda _: api) == 0
    assert keys.get(TOKEN_ENTRY) == TOKEN
    assert keys.get(OWNER_ENTRY) == str(OWNER)
    assert api.sent[-1]["chat_id"] == OWNER
    assert TOKEN not in capsys.readouterr().out


def test_setup_stores_nothing_when_not_confirmed_or_bad_token(tmp_path: Path) -> None:
    api = fake_setup_api(tmp_path, {"id": STRANGER, "first_name": "Someone"})
    keys = KeyringKeyStore()
    with pytest.raises(SetupError, match="not confirmed"):
        setup_phone(keys, lambda _: TOKEN, lambda _: "n", make_api=lambda _: api)
    with pytest.raises(SetupError, match="does not look like"):
        setup_phone(keys, lambda _: "hello", lambda _: "y", make_api=lambda _: api)
    assert keys.get(TOKEN_ENTRY) is None and keys.get(OWNER_ENTRY) is None
