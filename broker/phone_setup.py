"""`broker phone setup`: connect a Telegram bot as the approval phone.

The token is typed with hidden input and goes straight to the OS keychain. It is never
printed, logged or written to the config. The owner is whoever messages the bot, after the
person at the terminal confirms the name shown.
"""

import getpass
import re
import time
from collections.abc import Callable
from typing import Any

from broker.approvals.telegram import (
    OWNER_ENTRY,
    TOKEN_ENTRY,
    HttpTelegram,
    TelegramAPI,
    TelegramError,
    items,
    obj,
)
from broker.audit import KeyStore

TOKEN_SHAPE = re.compile(r"^\d{5,15}:[A-Za-z0-9_-]{30,64}$")
CONNECTED_TEXT = (
    "Agent Broker is connected. Approval requests from your computer will arrive here "
    "with Approve and Deny buttons."
)


class SetupError(Exception):
    pass


def find_owner(
    api: TelegramAPI,
    wait_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, Any], int]:
    """The first private-chat sender, and the offset that confirms what was read."""
    offset = 0
    deadline = monotonic() + wait_seconds
    while monotonic() < deadline:
        params = {"offset": offset, "timeout": 10, "allowed_updates": ["message"]}
        updates = api.call("getUpdates", params, timeout=10)
        for raw in items(updates):
            update = obj(raw)
            offset = int(update.get("update_id", 0)) + 1
            message = obj(update.get("message"))
            if obj(message.get("chat")).get("type") == "private" and obj(message.get("from")):
                return obj(message.get("from")), offset
    raise SetupError("no message reached the bot; open it in Telegram, tap Start, try again")


def describe(user: dict[str, Any]) -> str:
    name = " ".join(str(user.get(k, "")) for k in ("first_name", "last_name")).strip()
    handle = f" (@{user['username']})" if user.get("username") else ""
    return f"{name or 'unnamed user'}{handle}, Telegram id {user.get('id')}"


def setup_phone(
    keys: KeyStore,
    read_token: Callable[[str], str] = getpass.getpass,
    ask: Callable[[str], str] = input,
    say: Callable[[str], None] = print,
    make_api: Callable[[str], TelegramAPI] = HttpTelegram,
    wait_seconds: float = 120,
) -> int:
    token = read_token("Bot token from @BotFather (typing is hidden): ").strip()
    if not TOKEN_SHAPE.match(token):
        raise SetupError("that does not look like a bot token (expected <digits>:<letters>)")
    api = make_api(token)
    try:
        bot = obj(api.call("getMe", {}))
    except TelegramError as exc:
        raise SetupError(f"Telegram refused the token ({exc.code})") from None
    say(f"Bot: @{bot.get('username')}")
    say(f"On your phone open https://t.me/{bot.get('username')}, tap Start (or send any text).")
    say(f"Waiting up to {int(wait_seconds)} seconds...")
    try:
        user, offset = find_owner(api, wait_seconds)
        api.call("getUpdates", {"offset": offset, "timeout": 0}, timeout=5)  # confirm them
    except TelegramError as exc:
        hint = " (a webhook is set on this bot; remove it)" if exc.code.endswith("409") else ""
        raise SetupError(f"could not read messages ({exc.code}){hint}") from None
    if ask(f"Message came from {describe(user)}. Is this you? [y/N] ").strip().lower() != "y":
        raise SetupError("not confirmed; nothing stored")
    owner_id = int(user["id"])
    try:
        api.call("sendMessage", {"chat_id": owner_id, "text": CONNECTED_TEXT})
    except TelegramError as exc:
        raise SetupError(f"could not message you ({exc.code}); nothing stored") from None
    keys.set(TOKEN_ENTRY, token)
    keys.set(OWNER_ENTRY, str(owner_id))
    say("Connected. Token and your Telegram id are in the OS keychain.")
    say("Set `phone: telegram` in the config and restart Claude Desktop to use it.")
    return 0
