"""End-to-end through the MCP protocol with an in-process client and the fake backend."""

import json
import sqlite3
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import anyio
import mcp_types as types
from mcp.client import Client
from mcp.server import NotificationOptions

from broker.approvals.queue import ApprovalQueue
from broker.config import BrokerConfig
from broker.mcp_server import build_server
from broker.runtime import Runtime, open_runtime
from broker.taint import utc_now
from tests.conftest import FIXTURE, KNOWN_CONTACTS, OWN_ADDRESS

SIX = {"search_mail", "read_message", "list_events", "draft_reply", "send_mail", "create_event"}


def make_runtime(tmp_path: Path, wait: float = 0.2) -> Runtime:
    config = BrokerConfig(
        own_address=OWN_ADDRESS,
        known_contacts=tuple(sorted(KNOWN_CONTACTS)),
        state_dir=tmp_path,
        fake_fixture=FIXTURE,
        agents={"desktop": "agt_test"},
        approval_wait_seconds=wait,
    )
    return open_runtime(config, "desktop")


def run(
    runtime: Runtime, body: Callable[[Client], Awaitable[Any]], name: str = "claude-test"
) -> Any:
    async def main() -> Any:
        info = types.Implementation(name=name, version="1")
        async with Client(build_server(runtime), client_info=info) as client:
            return await body(client)

    return anyio.run(main)


def call(runtime: Runtime, tool: str, args: dict[str, Any]) -> types.CallToolResult:
    async def body(client: Client) -> types.CallToolResult:
        return await client.call_tool(tool, args)

    return run(runtime, body)


def text(result: types.CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, types.TextContent)
    return block.text


def test_exactly_six_tools_with_strict_schemas(tmp_path: Path) -> None:
    async def body(client: Client) -> types.ListToolsResult:
        return await client.list_tools()

    tools = run(make_runtime(tmp_path), body).tools
    assert {t.name for t in tools} == SIX
    for tool in tools:
        assert tool.input_schema.get("additionalProperties") is False, tool.name


def test_no_resources_or_prompts(tmp_path: Path) -> None:
    server = build_server(make_runtime(tmp_path))
    caps = server.get_capabilities(NotificationOptions(), {})
    assert caps.resources is None
    assert caps.prompts is None
    assert caps.tools is not None


def test_search_returns_minimized_fields_only(tmp_path: Path) -> None:
    result = call(make_runtime(tmp_path), "search_mail", {"query": ""})
    assert not result.is_error
    rows = result.structured_content["result"]
    assert rows and all(set(r) == {"id", "sender", "subject", "date", "snippet"} for r in rows)
    assert "body" not in text(result)


def test_read_and_list_never_return_removed_fields(tmp_path: Path) -> None:
    runtime = make_runtime(tmp_path)
    read = call(runtime, "read_message", {"message_id": "m_lunch"})
    assert set(read.structured_content["result"]) == {
        "id", "sender", "subject", "date", "snippet", "body", "bulk", "attachments",
    }  # fmt: skip
    assert "555" not in text(read)  # masked phone number
    events = call(runtime, "list_events", {})
    for event in events.structured_content["result"]:
        assert "attendees" not in event
    assert "events@vendor-demo.test, me@home.test" not in text(events)


def test_denied_call_is_short_with_stable_code(tmp_path: Path) -> None:
    runtime = make_runtime(tmp_path)
    unknown = call(runtime, "forward_message", {"message_id": "m_lunch"})
    assert unknown.is_error
    assert text(unknown) == "Denied by policy (code: policy_deny)"
    bad = call(runtime, "send_mail", {"to": [], "subject": "s", "body": "b"})
    assert text(bad) == "Denied by policy (code: invalid_arguments)"
    other_cal = call(runtime, "create_event", {
        "calendar_id": "team", "title": "t", "start": "s", "end": "e",
    })  # fmt: skip
    assert text(other_cal) == "Denied by policy (code: policy_deny)"
    assert "rule" not in text(other_cal)


def test_send_goes_pending_then_succeeds_after_approval(tmp_path: Path) -> None:
    runtime = make_runtime(tmp_path)
    args = {"to": ["alice@work.test"], "subject": "Lunch", "body": "Yes"}

    async def body(client: Client) -> tuple[types.CallToolResult, types.CallToolResult]:
        first = await client.call_tool("send_mail", args)
        queue = ApprovalQueue(tmp_path / "approvals.db")
        approval_id = first.structured_content["approval_id"]
        queue.decide(approval_id, approve=True, now=utc_now())
        queue.close()
        second = await client.call_tool("send_mail", args)
        return first, second

    first, second = run(runtime, body)
    assert "Pending approval" in text(first)
    assert not second.is_error
    assert "sent_id" in second.structured_content["result"]


def test_client_name_is_logged_as_hint_only(tmp_path: Path) -> None:
    runtime = make_runtime(tmp_path)

    async def body(client: Client) -> None:
        await client.call_tool("read_message", {"message_id": "m_forward"})

    run(runtime, body, name="totally-different-agent")
    session = runtime.new_session("x")
    assert session.agent_id == "agt_test"
    assert session.tainted  # taint stored under the launch identity, whatever the client said
    conn = sqlite3.connect(tmp_path / "audit.db")
    meta = [json.loads(r[0]) for r in conn.execute("SELECT metadata FROM log")]
    conn.close()
    assert meta[-1]["client_hint"] == "totally-different-agent"
    assert meta[-1]["agent_id"] == "agt_test"


def test_real_stdio_subprocess(tmp_path: Path) -> None:
    """`broker serve` over real stdio: tools list, a call, and nothing stray on stdout."""
    import os
    import sys

    from mcp.client.stdio import StdioServerParameters

    config = tmp_path / "config.yaml"
    config.write_text(
        f"own_address: {OWN_ADDRESS}\nstate_dir: {tmp_path}\nfake_fixture: {FIXTURE}\n"
        "agents:\n  desktop: agt_stdio\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    env = dict(os.environ, PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "broker.cli", "serve", "--agent", "desktop", "--config", str(config)],
        env=env,
    )

    async def main() -> tuple[set[str], types.CallToolResult]:
        async with Client(params) as client:
            tools = {t.name for t in (await client.list_tools()).tools}
            return tools, await client.call_tool("search_mail", {"query": "lunch"})

    tools, result = anyio.run(main)
    assert tools == SIX
    assert result.structured_content["result"][0]["id"] == "m_lunch"
