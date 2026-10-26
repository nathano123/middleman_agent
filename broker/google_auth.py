# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false
# google-auth-oauthlib ships no type information; this module is the typed boundary.
"""Google OAuth for the broker: installed-app flow with a loopback redirect, token in the keychain.

Checked in google-auth-oauthlib 1.5.0 / google-auth 2.62.0:
`InstalledAppFlow.from_client_secrets_file(path, scopes).run_local_server(...)` returns
`google.oauth2.credentials.Credentials`; its loopback handler overrides `log_message`, so the
redirect (which carries the auth code) is not logged. `Credentials.to_json()` /
`from_authorized_user_info(info, scopes)` round-trip the token; `refresh(Request())` raises
`google.auth.exceptions.RefreshError` (e.g. `invalid_grant` when a testing-mode grant expires
after seven days).

Nothing here ever prints, logs or raises with a token, client secret or auth code in it.
"""

import json
from collections.abc import Callable
from pathlib import Path

from google.auth.exceptions import RefreshError, TransportError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

from broker.audit import KeyStore
from broker.backends.base import BackendError

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/calendar.events.owned",
]
TOKEN_ENTRY = "google-oauth-token"
REAUTH_HINT = "Google authorization expired or was revoked: run `broker auth` again"


def run_consent(client_file: Path) -> Credentials:
    """Opens the browser for consent and waits (up to 5 minutes) for the loopback redirect."""
    flow = InstalledAppFlow.from_client_secrets_file(str(client_file.expanduser()), SCOPES)
    creds = flow.run_local_server(
        host="localhost",
        port=0,
        open_browser=True,
        authorization_prompt_message="Opening the browser for Google consent: {url}",
        success_message="Authorized. You can close this window and return to the terminal.",
        timeout_seconds=300,
    )
    if not isinstance(creds, Credentials):
        raise BackendError("google_unexpected_credentials")
    return creds


def save_credentials(keys: KeyStore, creds: Credentials) -> None:
    keys.set(TOKEN_ENTRY, creds.to_json())


def forget_credentials(keys: KeyStore) -> None:
    keys.set(TOKEN_ENTRY, "")


def load_credentials(keys: KeyStore) -> Credentials:
    raw = keys.get(TOKEN_ENTRY)
    if not raw:
        raise BackendError("google_not_authorized")
    try:
        return Credentials.from_authorized_user_info(json.loads(raw), SCOPES)
    except (ValueError, KeyError):
        raise BackendError("google_token_unreadable") from None


def fresh_credentials(keys: KeyStore, on_reconsent: Callable[[], None]) -> Credentials:
    """Valid credentials, refreshed if needed. Expired grants raise google_reauth_required."""
    creds = load_credentials(keys)
    if creds.valid:
        return creds
    try:
        creds.refresh(Request())
    except RefreshError as exc:
        if is_invalid_grant(exc):
            on_reconsent()
            raise BackendError("google_reauth_required") from None
        raise BackendError("google_refresh_failed") from None
    except TransportError:
        raise BackendError("google_unreachable") from None
    save_credentials(keys, creds)
    return creds


def is_invalid_grant(exc: RefreshError) -> bool:
    """RefreshError args carry the error text and the parsed response; look for invalid_grant."""
    return any("invalid_grant" in str(arg) for arg in exc.args)
