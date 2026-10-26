"""Print the activity log as a table for LIVE_RUN.md: metadata only, no message content.

uv run python scripts/live_report.py ~/.agent-broker/audit.db [--since 2026-10-27T10:00]
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path


def rows(path: Path, since: str) -> list[tuple[str, str, str, str, dict[str, object]]]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        found = conn.execute(
            "SELECT ts, tool, decision, reason, metadata FROM log WHERE ts >= ? ORDER BY id",
            (since,),
        ).fetchall()
    finally:
        conn.close()
    return [
        (ts, tool, decision, reason, json.loads(meta)) for ts, tool, decision, reason, meta in found
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("--since", default="")
    args = parser.parse_args(argv)
    print("| time | tool | decision | would_have | approval | tainted | taint reason | error |")
    print("|---|---|---|---|---|---|---|---|")
    for ts, tool, decision, _reason, meta in rows(args.log.expanduser(), args.since):
        cells = [
            ts[11:19], tool, decision, str(meta.get("would_have", "")),
            str(meta.get("approval", "")), str(meta.get("tainted", "")),
            str(meta.get("taint_reason", "")), str(meta.get("error", "")),
        ]  # fmt: skip
        print("| " + " | ".join(cells) + " |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
