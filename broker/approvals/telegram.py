"""Phone approvals through a Telegram bot (Milestone 3).

Flow: the queue opens a request; notify() sends the owner a Telegram message with the minimal
prompt and Approve / Deny buttons; poll() reads button taps with getUpdates (the laptop only
makes outgoing calls, so it can sit behind a home router) and writes accepted answers into the
same SQLite queue the terminal used. The waiting tool call sees the decision on its next check.

A tap counts only if all of these hold, otherwise it is refused and logged (metadata only):
- it comes from the owner's Telegram user id (set by Telegram, stored in the keychain);
- its button carries a nonce we issued, that nonce has not been used, and the tap is on the
  message we sent it in;
- the nonce's action hash still matches the queued request, which is still pending and less
  than five minutes old.

What Telegram sees: minimal_text() only (tool, recipients, subject, body length, short hash,
approval number, flags, reason). Never the body. Bot chats are not end-to-end encrypted.

Bot API facts relied on (core.telegram.org/bots/api, Bot API 10.3, read 2026-10-27):
callback_data is 1-64 bytes; getUpdates(offset, timeout, allowed_updates) confirms every update
below `offset`, keeps unconfirmed updates up to 24 hours, remembers allowed_updates between
calls, and does not work while a webhook is set; the client keeps a progress bar until
answerCallbackQuery is called; editMessageText(chat_id, message_id, text, reply_markup).
"""

import contextlib
import fcntl
import json
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import IO, Any, Protocol, cast

from broker.approvals.base import ApprovalRequest
from broker.approvals.queue import EXPIRY, ApprovalQueue, QueueError, QueueItem
from broker.audit import AuditLog
from broker.counters import Counters
from broker.files import private_file
from broker.taint import utc_now

API = "https://api.telegram.org"
TOKEN_ENTRY = "telegram-bot-token"
OWNER_ENTRY = "telegram-owner-id"
SUBJECT_CHARS = 120

SCHEMA = """
CREATE TABLE IF NOT EXISTS phone_nonces (
    nonce TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,      -- when the message was sent (latency starts here)
    message_id INTEGER,
    used_at TEXT
);
CREATE TABLE IF NOT EXISTS phone_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

# Answers a tap can get. Only the first two change anything.
ACCEPTED = ("approved", "denied")
TAP_MESSAGES = {
    "approved": "Approved. The agent can go ahead.",
    "denied": "Denied. The action will not be done.",
    "wrong_user": "Not accepted.",
    "no_nonce": "Not accepted: this button is not from Agent Broker.",
    "unknown_nonce": "Not accepted: unknown request.",
    "wrong_message": "Not accepted: button does not belong to this message.",
    "nonce_used": "Already answered.",
    "wrong_action": "Not accepted: the request changed.",
    "expired": "Too late: this request expired.",
    "already_decided": "Already answered.",
    "needs_full_view": "Not accepted: this request needs the full body.",
}


class TelegramError(Exception):
    """Carries a short code only: never the URL (it contains the token) or the server's text."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class TelegramAPI(Protocol):
    def call(self, method: str, params: dict[str, Any], timeout: float = 15) -> Any: ...


Opener = Callable[[urllib.request.Request, float], bytes]


def default_open(request: urllib.request.Request, timeout: float) -> bytes:
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


class HttpTelegram:
    """Bot API over HTTPS with the standard library. The token is in every URL, so no
    exception raised here carries the URL, the request, or a chained cause."""

    def __init__(self, token: str, opener: Opener = default_open) -> None:
        self._token = token
        self._open = opener

    def __repr__(self) -> str:
        return "HttpTelegram(token=<hidden>)"

    def call(self, method: str, params: dict[str, Any], timeout: float = 15) -> Any:
        request = urllib.request.Request(
            f"{API}/bot{self._token}/{method}",
            json.dumps(params).encode(),
            {"Content-Type": "application/json"},
        )
        raw, code = b"", ""
        try:
            raw = self._open(request, timeout + 10)
        except urllib.error.HTTPError as exc:  # body ignored: it may echo the request
            code = f"telegram_http_{exc.code}"
        except (OSError, ValueError):  # URLError, timeouts, TLS errors
            code = "telegram_unreachable"
        if code:  # raised outside the except block, so nothing is chained
            raise TelegramError(code)
        try:
            reply = obj(json.loads(raw))
        except ValueError:
            reply = {}
        if not reply:
            raise TelegramError("telegram_bad_reply")
        if not reply.get("ok"):
            raise TelegramError(f"telegram_error_{int(reply.get('error_code') or 0)}")
        return reply.get("result")


def obj(value: object) -> dict[str, Any]:
    """A JSON object from Telegram, or {} for anything else."""
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def items(value: object) -> list[object]:
    """A JSON array from Telegram, or [] for anything else."""
    return cast(list[object], value) if isinstance(value, list) else []


def one_line(text: str, limit: int) -> str:
    """Collapse newlines and invisible characters so a field cannot fake extra prompt lines."""
    flat = "".join(c for c in " ".join(text.split()) if c.isprintable())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def minimal_text(req: ApprovalRequest) -> str:
    """The `minimal` privacy level: everything the user needs to decide, except the body."""
    lines = [f"Approval needed: {req.tool} (#{req.approval_number} today)"]
    lines.append("To: " + one_line(", ".join(req.recipients) or "(nobody)", 400))
    if req.outside_recipients:
        lines.append("⚠️ OUTSIDE: " + one_line(", ".join(req.outside_recipients), 400))
    if req.new_recipients:
        lines.append("NEW today: " + one_line(", ".join(req.new_recipients), 400))
    lines.append("Subject: " + one_line(req.subject, SUBJECT_CHARS))
    lines.extend(f"{k}: {one_line(v, 80)}" for k, v in sorted(req.details.items()))
    lines.append(f"Body: {req.body_length} chars (not shown), sha256 {req.body_sha256}")
    if req.sends_invitations:
        lines.append("Google will email invitations to the recipients.")
    lines.append("Why: " + one_line(req.reason, 200))
    if req.requires_full_view:
        lines.append(
            "This request needs the full body, which is not sent to Telegram. "
            "You can only deny it here."
        )
    return "\n".join(lines)


class TelegramChannel:
    """Sends approval requests to the owner and turns their taps into queue decisions."""

    def __init__(
        self,
        api: TelegramAPI,
        owner_id: int,
        queue: ApprovalQueue,
        db_path: Path,
        lock_path: Path,
        log: AuditLog | None = None,
        counters: Counters | None = None,
        clock: Callable[[], datetime] = utc_now,
        sleep: Callable[[float], None] = time.sleep,
        expiry: timedelta = EXPIRY,
    ) -> None:
        self.api = api
        self.owner_id = owner_id
        self.queue = queue
        self.lock_path = lock_path
        self.log = log
        self.counters = counters
        self.clock = clock
        self.sleep = sleep
        self.expiry = expiry
        self._conn = sqlite3.connect(private_file(db_path), timeout=10, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # --- sending -------------------------------------------------------------

    def notify(self, item: QueueItem, req: ApprovalRequest) -> None:
        """Send the request once per approval id. Errors are logged, never raised: the
        approval then simply stays pending, as without a phone."""
        sent = self._conn.execute(
            "SELECT 1 FROM phone_nonces WHERE approval_id = ? AND message_id IS NOT NULL",
            (item.id,),
        ).fetchone()
        if sent is not None:
            return
        nonce = secrets.token_urlsafe(16)
        buttons: list[dict[str, str]] = []
        if not req.requires_full_view:
            buttons.append({"text": "✅ Approve", "callback_data": f"a:{nonce}"})
        buttons.append({"text": "❌ Deny", "callback_data": f"d:{nonce}"})
        params = {
            "chat_id": self.owner_id,
            "text": minimal_text(req),
            "reply_markup": {"inline_keyboard": [buttons]},
        }
        try:
            message = self.api.call("sendMessage", params)
        except TelegramError as exc:
            self._log("phone_error", item.agent_id, {"phone_error": exc.code})
            return
        self._conn.execute(
            "INSERT INTO phone_nonces (nonce, approval_id, action_hash, created_at, message_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (nonce, item.id, item.action_hash, self.clock().isoformat(), message["message_id"]),
        )
        self._conn.commit()

    # --- receiving -----------------------------------------------------------

    def _try_lock(self) -> IO[str] | None:
        """Telegram allows one getUpdates at a time per bot; each agent runs its own broker
        process, so they take turns. Whoever holds the lock writes decisions for everyone."""
        handle = private_file(self.lock_path).open("a")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            return None
        return handle

    def poll(self, wait: float) -> None:
        """Read taps for up to `wait` seconds (long polling). Never raises."""
        lock = self._try_lock()
        if lock is None:
            self.sleep(wait)
            return
        try:
            offset = int(self._state("offset") or 0)
            params = {"offset": offset, "timeout": max(int(wait), 0),
                      "allowed_updates": ["callback_query"]}  # fmt: skip
            try:
                updates = self.api.call("getUpdates", params, timeout=wait)
            except TelegramError:
                self.sleep(wait)
                return
            for raw in items(updates):
                update = obj(raw)
                self._set_state("offset", str(int(update.get("update_id", 0)) + 1))
                query = obj(update.get("callback_query"))
                if query:
                    self.handle(query)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()

    def handle(self, query: dict[str, Any]) -> str:
        """Check one tap, decide the queued request if it is valid, and tell the phone."""
        result, agent_id = self._check_and_decide(query)
        self._log(result, agent_id, {"phone_reply": result})
        self._quietly("answerCallbackQuery", {
            "callback_query_id": str(query.get("id", "")),
            "text": TAP_MESSAGES[result],
        })  # fmt: skip
        message = obj(query.get("message"))
        if result in ACCEPTED or result in ("nonce_used", "expired", "already_decided"):
            if not message.get("message_id"):
                return result
            stamp = self.clock().strftime("%H:%M:%S UTC")
            text = f"{message.get('text', '')}\n\n→ {TAP_MESSAGES[result]} ({stamp})"
            self._quietly("editMessageText", {
                "chat_id": self.owner_id,
                "message_id": message["message_id"],
                "text": text[:4096],
                "reply_markup": {"inline_keyboard": []},
            })  # fmt: skip
        return result

    def _check_and_decide(self, query: dict[str, Any]) -> tuple[str, str]:
        sender = obj(query.get("from"))
        if sender.get("id") != self.owner_id:
            return "wrong_user", ""
        verb, _, nonce = str(query.get("data") or "").partition(":")
        if verb not in ("a", "d") or not nonce:
            return "no_nonce", ""
        row = self._conn.execute("SELECT * FROM phone_nonces WHERE nonce = ?", (nonce,)).fetchone()
        if row is None:
            return "unknown_nonce", ""
        message = obj(query.get("message"))
        if message.get("message_id") != row["message_id"]:
            return "wrong_message", ""
        if row["used_at"] is not None:
            return "nonce_used", ""
        now = self.clock()
        self.queue.expire(now)
        try:
            item = self.queue.get(row["approval_id"])
        except QueueError:
            return "unknown_nonce", ""
        if item.action_hash != row["action_hash"]:
            return "wrong_action", item.agent_id
        if item.status == "expired" or now - item.created_at >= self.expiry:
            return "expired", item.agent_id
        if item.status != "pending":
            return "already_decided", item.agent_id
        approve = verb == "a"
        if approve and item.request is not None and item.request.requires_full_view:
            return "needs_full_view", item.agent_id
        claimed = self._conn.execute(
            "UPDATE phone_nonces SET used_at = ? WHERE nonce = ? AND used_at IS NULL",
            (now.isoformat(), nonce),
        )
        self._conn.commit()
        if claimed.rowcount != 1:
            return "nonce_used", item.agent_id
        try:
            self.queue.decide(item.id, approve=approve, now=now)
        except QueueError:  # another process decided or expired it in between
            return "already_decided", item.agent_id
        if self.counters is not None:
            shown = datetime.fromisoformat(row["created_at"])
            self.counters.record_latency(now.date(), (now - shown).total_seconds())
        return ("approved" if approve else "denied"), item.agent_id

    # --- helpers -------------------------------------------------------------

    def _quietly(self, method: str, params: dict[str, Any]) -> None:
        with contextlib.suppress(TelegramError):  # cosmetic: the decision is already recorded
            self.api.call(method, params)

    def _log(self, decision: str, agent_id: str, meta: dict[str, Any]) -> None:
        if self.log is None:
            return
        if agent_id:
            meta = {**meta, "agent_id": agent_id}
        self.log.append("phone", "phone_reply", decision, "", meta)

    def _state(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM phone_state WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row["value"])

    def _set_state(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO phone_state (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self._conn.commit()
