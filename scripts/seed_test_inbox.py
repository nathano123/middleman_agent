# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false
"""Seed the TEST account with the hostile fixtures, sent for real from the ATTACKER account.

Refuses to run unless both the target (own_address in the broker config) and the attacker
appear in a local allow-list file (default secrets/allowed_test_accounts, one address per
line, git-ignored). Never run this against a real mailbox.

    uv run python scripts/seed_test_inbox.py auth-attacker   # consent as the attacker
    uv run python scripts/seed_test_inbox.py plan            # show what would be sent
    uv run python scripts/seed_test_inbox.py seed            # send mails and invites

The attacker token (gmail.send + calendar.events.owned + openid email) is kept in the
keychain under its own entry. Gmail sends from the attacker's real address, so fixtures whose
point is a forged From (spoofed known contact, alias) cannot be reproduced; `plan` lists them.
"""

import argparse
import base64
import json
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.policy import default as default_policy
from email.utils import formataddr, parseaddr
from pathlib import Path
from typing import Any

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from broker.audit import KeyringKeyStore
from broker.config import DEFAULT_CONFIG_PATH, BrokerConfig, load_config

ATTACKER_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar.events.owned",
]
ATTACKER_TOKEN = "google-oauth-token-attacker"
FIXTURE = Path(__file__).parents[1] / "tests" / "fixtures" / "mailbox.json"
DEFAULT_ALLOWED = Path(__file__).parents[1] / "secrets" / "allowed_test_accounts"

# Fixtures that only make sense with a forged From or a known-contact sender.
NOT_LIVE = {
    "m_lunch": "benign known contact; the test account's own contacts play this role",
    "m_hebrew_known": "needs a known-contact sender: add the attacker to known_contacts",
    "m_alias": "needs mail from the user's own alias; send it from the alias by hand",
    "m_spoof": "needs a forged From with failing DMARC; Gmail cannot send that",
    "m_auth_unknown": "needs a message with no Authentication-Results; not producible",
}
HTML_FIXTURES = {"m_hidden"}
INVITE_FIXTURES = ("e_vendor", "e_hidden")


class SeedError(Exception):
    pass


def read_allowed(path: Path) -> set[str]:
    if not path.exists():
        raise SeedError(f"no allow-list at {path}; create it with one test address per line")
    lines = path.read_text(encoding="utf-8").splitlines()
    return {line.strip().lower() for line in lines if line.strip() and not line.startswith("#")}


def check_allowed(target: str, attacker: str, allowed: set[str]) -> None:
    """Both accounts must be listed, and they must differ."""
    target, attacker = target.lower(), attacker.lower()
    if target not in allowed:
        raise SeedError(f"target {target} is not in the allow-list; refusing")
    if attacker not in allowed:
        raise SeedError(f"attacker {attacker} is not in the allow-list; refusing")
    if target == attacker:
        raise SeedError("target and attacker must be different accounts")


@dataclass(frozen=True)
class Planned:
    fixture_id: str
    kind: str  # mail | invite
    summary: str


def plan(fixture: dict[str, Any]) -> tuple[list[Planned], dict[str, str]]:
    mails = [
        Planned(m["id"], "mail", m["subject"])
        for m in fixture["messages"]
        if m["id"] not in NOT_LIVE
    ]
    invites = [
        Planned(e["id"], "invite", e["title"])
        for e in fixture["events"]
        if e["id"] in INVITE_FIXTURES
    ]
    return mails + invites, dict(NOT_LIVE)


def build_mail(message: dict[str, Any], attacker: str, target: str) -> EmailMessage:
    """From shows the fixture's display name over the attacker's real address."""
    display, _addr = parseaddr(message["sender"])
    mail = EmailMessage(policy=default_policy)
    mail["From"] = formataddr((display, attacker))
    mail["To"] = target
    mail["Subject"] = message["subject"]
    if message.get("reply_to"):
        mail["Reply-To"] = message["reply_to"]
    if message["id"] in HTML_FIXTURES:
        mail.set_content("This message is best viewed in HTML.")
        mail.add_alternative(message["body"], subtype="html")
    else:
        mail.set_content(message["body"])
    return mail


def invite_body(event: dict[str, Any], target: str, start: datetime) -> dict[str, Any]:
    return {
        "summary": event["title"],
        "description": event["description"],
        "start": {"dateTime": start.isoformat()},
        "end": {"dateTime": (start + timedelta(hours=1)).isoformat()},
        "attendees": [{"email": target}],
    }


def attacker_email(creds: Credentials) -> str:
    """Email claim from the ID token Google returned with the attacker's consent."""
    token = str(creds.id_token or "")
    if token.count(".") != 2:
        raise SeedError("attacker token has no ID token; run auth-attacker again")
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return str(claims.get("email", "")).lower()


def load_attacker() -> Credentials:
    raw = KeyringKeyStore().get(ATTACKER_TOKEN)
    if not raw:
        raise SeedError("no attacker token; run: seed_test_inbox.py auth-attacker")
    return Credentials.from_authorized_user_info(json.loads(raw), ATTACKER_SCOPES)


def cmd_auth_attacker(config: BrokerConfig) -> None:
    if config.google_client_file is None:
        raise SeedError("set google_client_file in the config first")
    flow = InstalledAppFlow.from_client_secrets_file(
        str(config.google_client_file.expanduser()), ATTACKER_SCOPES
    )
    creds = flow.run_local_server(port=0, open_browser=True, timeout_seconds=300)
    if not isinstance(creds, Credentials):
        raise SeedError("unexpected credential type from the consent flow")
    KeyringKeyStore().set(ATTACKER_TOKEN, creds.to_json())
    print(f"attacker authorized as {attacker_email(creds)}")


def cmd_seed(config: BrokerConfig, allowed: set[str], dry_run: bool) -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    planned, skipped = plan(fixture)
    creds = load_attacker()
    attacker = attacker_email(creds)
    check_allowed(config.own_address, attacker, allowed)
    for item in planned:
        print(f"{item.kind:6} {item.fixture_id:16} {item.summary}")
    for fixture_id, why in skipped.items():
        print(f"skip   {fixture_id:16} {why}")
    if dry_run:
        return
    gmail = build("gmail", "v1", credentials=creds, static_discovery=True)
    calendar = build("calendar", "v3", credentials=creds, static_discovery=True)
    messages = {m["id"]: m for m in fixture["messages"]}
    events = {e["id"]: e for e in fixture["events"]}
    start = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) + timedelta(days=2)
    for n, item in enumerate(planned):
        if item.kind == "mail":
            mail = build_mail(messages[item.fixture_id], attacker, config.own_address)
            raw = base64.urlsafe_b64encode(mail.as_bytes()).decode()
            gmail.users().messages().send(userId="me", body={"raw": raw}).execute()
        else:
            body = invite_body(
                events[item.fixture_id], config.own_address, start + timedelta(hours=n)
            )
            calendar.events().insert(calendarId="primary", body=body, sendUpdates="all").execute()
        time.sleep(1)
    print(f"seeded {len(planned)} items from {attacker} into {config.own_address}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["auth-attacker", "plan", "seed"])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--allowed", type=Path, default=DEFAULT_ALLOWED)
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "auth-attacker":
            cmd_auth_attacker(config)
        else:
            cmd_seed(config, read_allowed(args.allowed), dry_run=args.command == "plan")
    except SeedError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
