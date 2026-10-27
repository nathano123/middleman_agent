"""Milestone 3 spike: does an ntfy action button get an answer back to this laptop?

Dummy text only: no mail content, no addresses. Topic names are random and kept in
secrets/ntfy_spike.json (git-ignored, 0600), never printed to logs or committed.

    uv run python scripts/ntfy_spike.py setup          # make topics, print the one to subscribe to
    uv run python scripts/ntfy_spike.py send [--wait 300]   # notify, wait for a tap, time it

Pattern under test: the phone cannot reach the laptop, so each button is an `http` action
that POSTs to a second private topic (the reply topic); this script subscribes to it.
"""

import argparse
import json
import secrets
import sys
import time
import urllib.request
from pathlib import Path

from broker.files import private_dir, write_private_text

SERVER = "https://ntfy.sh"
STATE = Path(__file__).parents[1] / "secrets" / "ntfy_spike.json"


def post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
    data = json.dumps(payload).encode()
    request = urllib.request.Request(url, data, {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read())


def setup() -> None:
    state = {
        "request_topic": "abr-" + secrets.token_urlsafe(24),
        "reply_topic": "abr-" + secrets.token_urlsafe(24),
    }
    private_dir(STATE.parent)
    write_private_text(STATE, json.dumps(state))
    print(f"Subscribe in the ntfy app (server {SERVER}) to this topic:")
    print(state["request_topic"])


def wait_for_reply(topic: str, nonce: str, since: int, wait: int) -> tuple[str, dict[str, object]]:
    deadline = time.monotonic() + wait
    url = f"{SERVER}/{topic}/json?since={since}"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=min(60, wait)) as stream:
                for raw in stream:
                    if time.monotonic() > deadline:  # keepalives keep the stream open
                        break
                    event = json.loads(raw)
                    if event.get("event") != "message":
                        continue
                    answer, _, got = str(event.get("message", "")).partition(" ")
                    if got == nonce:
                        return answer, event
        except TimeoutError:
            continue
    return "none", {}


def send(wait: int) -> None:
    state = json.loads(STATE.read_text())
    nonce = secrets.token_urlsafe(16)
    reply_url = f"{SERVER}/{state['reply_topic']}"
    actions = [
        {"action": "http", "label": label, "url": reply_url, "body": f"{word} {nonce}",
         "clear": True}
        for label, word in (("Approve", "approve"), ("Deny", "deny"))
    ]  # fmt: skip
    started = time.time()
    published = post_json(SERVER, {
        "topic": state["request_topic"],
        "title": "Agent Broker spike",
        "message": "Test only, no mail content. Tap Approve or Deny.",
        "priority": 4,
        "actions": actions,
    })  # fmt: skip
    print(
        f"published id={published.get('id')} in {time.time() - started:.2f}s; waiting {wait}s",
        flush=True,
    )
    answer, event = wait_for_reply(state["reply_topic"], nonce, int(started) - 1, wait)
    latency = time.time() - started
    print(f"answer={answer} latency={latency:.1f}s")
    if event:
        print("reply event fields:", sorted(event))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["setup", "send"])
    parser.add_argument("--wait", type=int, default=300)
    args = parser.parse_args(argv)
    if args.command == "setup":
        setup()
    else:
        send(args.wait)
    return 0


if __name__ == "__main__":
    sys.exit(main())
