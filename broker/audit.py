"""Append-only, hash-chained activity log in SQLite.

Each row's hash is SHA-256 over the canonical JSON of the row (including its id) plus the
previous row's hash. verify() walks the chain and returns the id of the first row that does
not fit. Editing, deleting or reordering any row except the newest one is detected; removing
rows from the end is not (see README).

Only metadata is accepted: metadata keys outside ALLOWED_METADATA_KEYS are refused, so a
caller cannot write a subject, body, snippet or description into the log by accident.
"""

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

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


def row_hash(row: dict[str, object]) -> str:
    """SHA-256 over the row's fields (prev_hash included), as sorted compact JSON."""
    payload = {name: row[name] for name in ROW_FIELDS}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._conn = sqlite3.connect(path)
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
        row["hash"] = row_hash(row)
        columns = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        self._conn.execute(f"INSERT INTO log ({columns}) VALUES ({marks})", tuple(row.values()))
        self._conn.commit()
        return last_id + 1


def verify(path: Path) -> int | None:
    """Return the id of the first row that breaks the chain, or None if the chain is intact."""
    if not path.exists():
        raise AuditError(f"no log at {path}")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM log ORDER BY id").fetchall()
    finally:
        conn.close()
    expected_prev = GENESIS_HASH
    for found in rows:
        row: dict[str, object] = dict(found)
        if row["prev_hash"] != expected_prev or row_hash(row) != row["hash"]:
            return int(str(row["id"]))
        expected_prev = str(row["hash"])
    return None
