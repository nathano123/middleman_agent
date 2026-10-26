"""Append-only, hash-chained activity log in SQLite.

Each row's hash is SHA-256 over the canonical JSON of the row (including its id) plus the
previous row's hash. verify() walks the chain and returns the id of the first row that does
not fit. Editing, deleting or reordering any row except the newest one is detected; removing
rows from the end is not (see README).

Only metadata is accepted: metadata keys outside ALLOWED_METADATA_KEYS are refused, so a
caller cannot write a subject, body, snippet or description into the log by accident.
"""

import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import keyring

from broker.files import private_file

GENESIS_HASH = "0" * 64
MAX_METADATA_STRING = 128

MetadataValue = str | int | bool | list[str]

ALLOWED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "profile",
        "tainted",
        "taint_reason",
        "message_id",
        "event_id",
        "calendar_own",
        "result_count",
        "recipient_count",
        "recipient_domains",
        "attendee_count",
        "attendee_domains",
        "approval",
        "error",
        "agent_id",
        "client_hint",
        "auth_result",
        "mode",
        "would_have",
    }
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS log (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    session_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    metadata TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
)
"""

ROW_FIELDS = ("id", "ts", "session_id", "tool", "decision", "reason", "metadata", "prev_hash")


class AuditError(Exception):
    pass


def check_metadata(metadata: dict[str, MetadataValue]) -> None:
    for key, value in metadata.items():
        if key not in ALLOWED_METADATA_KEYS:
            raise AuditError(f"metadata key {key!r} is not allowed in the log")
        strings = value if isinstance(value, list) else [value]
        for item in strings:
            if isinstance(item, str) and len(item) > MAX_METADATA_STRING:
                raise AuditError(f"metadata value for {key!r} is too long for the log")


def row_hash(row: dict[str, object], key: bytes | None = None) -> str:
    """SHA-256 (or HMAC-SHA-256 with a key) over the row's fields, as sorted compact JSON."""
    payload = {name: row[name] for name in ROW_FIELDS}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if key is None:
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


# --- keys and head anchor, kept outside the log file (OS keychain) -----------


class KeyStore(Protocol):
    def get(self, name: str) -> str | None: ...

    def set(self, name: str, value: str) -> None: ...


class KeyringKeyStore:
    """OS keychain via `keyring` (25.x: get_password/set_password(service, username))."""

    service = "agent-broker"

    def get(self, name: str) -> str | None:
        return keyring.get_password(self.service, name)

    def set(self, name: str, value: str) -> None:
        keyring.set_password(self.service, name, value)


def log_key(keys: KeyStore, create: bool) -> bytes | None:
    found = keys.get("audit-hmac-key")
    if found is None and create:
        found = secrets.token_hex(32)
        keys.set("audit-hmac-key", found)
    return bytes.fromhex(found) if found else None


def anchor_name(path: Path) -> str:
    """Keychain entry holding the newest row's "id:hash" for this log file."""
    digest = hashlib.sha256(str(path.expanduser().resolve()).encode()).hexdigest()[:16]
    return f"audit-head-{digest}"


class AuditLog:
    def __init__(self, path: Path, keys: KeyStore | None = None) -> None:
        self.path = path
        self.keys = keys
        self._key = log_key(keys, create=True) if keys else None
        self._conn = sqlite3.connect(private_file(path))
        self._conn.execute(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _last(self) -> tuple[int, str]:
        cur = self._conn.execute("SELECT id, hash FROM log ORDER BY id DESC LIMIT 1")
        found: tuple[int, str] | None = cur.fetchone()
        return found if found is not None else (0, GENESIS_HASH)

    def append(
        self,
        session_id: str,
        tool: str,
        decision: str,
        reason: str,
        metadata: dict[str, MetadataValue],
    ) -> int:
        check_metadata(metadata)
        last_id, last_hash = self._last()
        row: dict[str, object] = {
            "id": last_id + 1,
            "ts": datetime.now(UTC).isoformat(),
            "session_id": session_id,
            "tool": tool,
            "decision": decision,
            "reason": reason,
            "metadata": json.dumps(metadata, sort_keys=True, ensure_ascii=False),
            "prev_hash": last_hash,
        }
        row["hash"] = row_hash(row, self._key)
        columns = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        self._conn.execute(f"INSERT INTO log ({columns}) VALUES ({marks})", tuple(row.values()))
        self._conn.commit()
        if self.keys is not None:
            self.keys.set(anchor_name(self.path), f"{last_id + 1}:{row['hash']}")
        return last_id + 1


def verify(path: Path, keys: KeyStore | None = None) -> int | None:
    """Return the id of the first row that breaks the chain, or None if the chain is intact.

    With `keys`, rows are checked as HMACs and the newest row must match the head anchor in
    the key store; a missing newest row is reported as the anchored id.
    """
    if not path.exists():
        raise AuditError(f"no log at {path}")
    key = log_key(keys, create=False) if keys else None
    if keys is not None and key is None:
        raise AuditError("no audit key in the key store")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM log ORDER BY id").fetchall()
    finally:
        conn.close()
    expected_prev = GENESIS_HASH
    last_id = 0
    for found in rows:
        row: dict[str, object] = dict(found)
        if row["prev_hash"] != expected_prev or row_hash(row, key) != row["hash"]:
            return int(str(row["id"]))
        expected_prev = str(row["hash"])
        last_id = int(str(row["id"]))
    head = keys.get(anchor_name(path)) if keys else None
    if head is not None and head != f"{last_id}:{expected_prev}":
        return int(head.split(":", 1)[0]) if last_id < int(head.split(":", 1)[0]) else last_id
    return None
