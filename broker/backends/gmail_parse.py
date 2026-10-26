"""Turn Gmail API message resources into the broker's Message model. Pure functions, no I/O.

Decisions (see DECISIONS.md):
- HTML is preferred over a text/plain alternative, because HTML is what the user sees in Gmail.
  Visually hidden HTML (comments, display:none, visibility:hidden, tiny or zero font,
  opacity 0, white text, <script>/<style>/<head>) is dropped and replaced by one marker
  "[hidden text removed: N chars]", so the agent reads what a human would see and the
  removal itself is visible.
- Bodies longer than MAX_BODY_CHARS are cut and marked. Attachments: names and sizes only.
- Authentication: only an Authentication-Results header whose authserv-id is mx.google.com
  counts. Senders can add their own Authentication-Results headers; Gmail adds its own on
  receipt.
"""

import base64
import html
import re
from dataclasses import dataclass, field
from email.utils import getaddresses
from html.parser import HTMLParser
from typing import Any

from broker.backends.base import AuthResult, Message

MAX_BODY_CHARS = 50_000
GOOGLE_AUTHSERV = "mx.google.com"
VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source",
    "track", "wbr",
}  # fmt: skip
ALWAYS_HIDDEN_TAGS = {"script", "style", "head", "title", "template", "noscript"}
BLOCK_TAGS = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table"}
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(\.0+)?\s*(;|$)"
    r"|font-size\s*:\s*[01](\.\d+)?\s*(px|pt|em|rem)?\s*(;|$)"
    r"|(?<![-\w])color\s*:\s*(#fff\b|#ffffff\b|white\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))",
    re.IGNORECASE,
)

Headers = list[dict[str, str]]


# --- headers -----------------------------------------------------------------


def header(headers: Headers, name: str) -> str:
    """First value of a header (case-insensitive), or ''."""
    for item in headers:
        if item.get("name", "").lower() == name.lower():
            return item.get("value", "")
    return ""


def all_headers(headers: Headers, name: str) -> list[str]:
    return [h.get("value", "") for h in headers if h.get("name", "").lower() == name.lower()]


def addresses(value: str) -> list[str]:
    return [addr.lower() for _name, addr in getaddresses([value]) if addr]


def auth_result(headers: Headers) -> AuthResult:
    """pass only on dmarc=pass; fail on dmarc=fail, or no DMARC result with SPF failing and
    DKIM not passing; otherwise unknown. Uses only Gmail's own Authentication-Results."""
    for value in all_headers(headers, "Authentication-Results"):
        authserv = value.split(";", 1)[0].strip().lower()
        if authserv != GOOGLE_AUTHSERV:
            continue
        results = dict(re.findall(r"\b(spf|dkim|dmarc)=([a-z]+)", value.lower()))
        dmarc = results.get("dmarc")
        if dmarc == "pass":
            return "pass"
        if dmarc == "fail":
            return "fail"
        spf_bad = results.get("spf") in ("fail", "softfail")
        if dmarc is None and spf_bad and results.get("dkim") != "pass":
            return "fail"
        return "unknown"
    return "unknown"


# --- bodies ------------------------------------------------------------------


class _VisibleText(HTMLParser):
    """Collect the text a human would see; count characters that are hidden."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden_chars = 0
        self.stack: list[tuple[str, bool]] = []  # (tag, hidden)

    def _hidden(self) -> bool:
        return any(hidden for _tag, hidden in self.stack)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in BLOCK_TAGS:
            self.parts.append("\n")
        if tag in VOID_TAGS:
            return
        values = dict(attrs)
        style = values.get("style") or ""
        hidden = tag in ALWAYS_HIDDEN_TAGS or "hidden" in values or bool(HIDDEN_STYLE.search(style))
        self.stack.append((tag, hidden))

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break
        if tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._hidden():
            self.hidden_chars += len(data.strip())
        else:
            self.parts.append(data)

    def handle_comment(self, data: str) -> None:
        self.hidden_chars += len(data.strip())


def html_to_text(markup: str) -> tuple[str, int]:
    """(visible text, number of hidden characters dropped)."""
    parser = _VisibleText()
    parser.feed(markup)
    parser.close()
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(parser.parts))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return text, parser.hidden_chars


def _decode(data: str, charset: str) -> str:
    raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    try:
        return raw.decode(charset or "utf-8", errors="replace")
    except LookupError:  # unknown charset name
        return raw.decode("utf-8", errors="replace")


def _charset(part: dict[str, Any]) -> str:
    content_type = header(part.get("headers", []), "Content-Type")
    found = re.search(r"charset\s*=\s*\"?([\w.-]+)", content_type, re.IGNORECASE)
    return found.group(1) if found else "utf-8"


@dataclass
class _Parts:
    plain: str | None = None
    html: str | None = None
    too_large: bool = False
    attachments: list[tuple[str, int]] = field(default_factory=list[tuple[str, int]])


def _walk(part: dict[str, Any], found: _Parts) -> None:
    mime = str(part.get("mimeType", "")).lower()
    body: dict[str, Any] = part.get("body") or {}
    if part.get("filename"):
        found.attachments.append((str(part["filename"]), int(body.get("size", 0))))
        return
    if mime in ("text/plain", "text/html"):
        if "data" not in body:
            found.too_large = found.too_large or bool(body.get("attachmentId"))
            return
        text = _decode(str(body["data"]), _charset(part))
        if mime == "text/plain" and found.plain is None:
            found.plain = text
        if mime == "text/html" and found.html is None:
            found.html = text
    children: list[dict[str, Any]] = part.get("parts") or []
    for child in children:
        _walk(child, found)


def body_text(payload: dict[str, Any]) -> tuple[str, list[tuple[str, int]]]:
    """(body as the agent will see it, attachments as (name, size))."""
    found = _Parts()
    _walk(payload, found)
    hidden = 0
    if found.html is not None:
        text, hidden = html_to_text(found.html)
    else:
        text = found.plain or ""
    if found.too_large:
        text += "\n[part of the body was too large to fetch and is not shown]"
    if hidden:
        text += f"\n[hidden text removed: {hidden} chars]"
    if len(text) > MAX_BODY_CHARS:
        cut = len(text) - MAX_BODY_CHARS
        text = text[:MAX_BODY_CHARS] + f"\n[truncated: {cut} more chars not shown]"
    return text, found.attachments


# --- whole message -----------------------------------------------------------


def to_message(resource: dict[str, Any]) -> Message:
    """Map a users.messages.get resource (format=full or metadata) to Message."""
    payload: dict[str, Any] = resource.get("payload", {}) or {}
    headers: Headers = payload.get("headers", []) or []
    body, attachments = body_text(payload) if "parts" in payload or "body" in payload else ("", [])
    precedence = header(headers, "Precedence").strip().lower()
    return Message(
        id=str(resource.get("id", "")),
        sender=header(headers, "From"),
        to=addresses(header(headers, "To")),
        subject=header(headers, "Subject"),
        date=header(headers, "Date"),
        snippet=html.unescape(str(resource.get("snippet", ""))),
        body=body,
        reply_to=header(headers, "Reply-To"),
        auth_result=auth_result(headers),
        list_unsubscribe=header(headers, "List-Unsubscribe"),
        precedence=precedence,
        thread_id=str(resource.get("threadId", "")),
        sender_header=header(headers, "Sender"),
        cc=addresses(header(headers, "Cc")),
        attachments=attachments,
        rfc_message_id=header(headers, "Message-ID") or header(headers, "Message-Id"),
    )
