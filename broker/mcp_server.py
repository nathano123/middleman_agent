"""MCP server over stdio: exactly six tools, each call goes to Gate.handle and nothing else.

No resources, no prompts. Tool input schemas are the gate's own argument models (unknown
fields rejected). A refused call returns "Denied by policy (code: ...)" with a stable code,
not rule internals. Successful results are the minimized data the gate returned.

stdout carries the MCP protocol, so this module never prints; warnings go to stderr.
"""

import json
import sys
import threading
from pathlib import Path
from typing import Any

import anyio
import mcp_types as types
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server

from broker.approvals.base import ApprovalOutcome
from broker.config import load_config
from broker.files import config_warnings
from broker.gate import ARG_MODELS, Result
from broker.rules.models import Verdict
from broker.runtime import Runtime, open_runtime
from broker.taint import Session

DESCRIPTIONS = {
    "search_mail": "Search mail. Returns id, sender, subject, date and a short snippet only.",
    "read_message": "Read one message by id. Personal data in the body may be masked.",
    "list_events": "List upcoming events on your own (primary) calendar.",
    "draft_reply": "Create a draft reply to a message. Never sends.",
    "send_mail": "Send an email. Usually needs the user's approval; may return pending.",
    "create_event": "Create an event on your own calendar. Invitations may need approval.",
}

APPROVAL_CODES = {
    ApprovalOutcome.DENIED: "approval_denied",
    ApprovalOutcome.TIMEOUT: "approval_timeout",
    ApprovalOutcome.UNVIEWED: "approval_needs_full_view",
}


def tool_list() -> list[types.Tool]:
    return [
        types.Tool(
            name=name,
            description=DESCRIPTIONS[name],
            input_schema=ARG_MODELS[name].model_json_schema(),
        )
        for name in DESCRIPTIONS
    ]


def text_result(text: str, data: Any, is_error: bool) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(text=text)], structured_content=data, is_error=is_error
    )


def denial_code(result: Result) -> str:
    if result.error:
        return result.error
    if result.verdict == Verdict.ASK and result.approval is not None:
        return APPROVAL_CODES.get(result.approval, "policy_deny")
    return "policy_deny"


def to_tool_result(result: Result) -> types.CallToolResult:
    if result.ok:
        data = {"result": result.data}
        return text_result(json.dumps(result.data, ensure_ascii=False), data, False)
    if result.approval == ApprovalOutcome.PENDING:
        data = dict(result.data or {})
        text = (
            f"Pending approval (id {data.get('approval_id')}). Call the same tool again with "
            "exactly the same arguments to get the answer."
        )
        return text_result(text, data, False)
    code = denial_code(result)
    return text_result(f"Denied by policy (code: {code})", {"denied": True, "code": code}, True)


def client_name(ctx: ServerRequestContext[Any, Any]) -> str:
    params = ctx.session.client_params
    info = params.client_info if params is not None else None
    return str(getattr(info, "name", "") or "")


def build_server(runtime: Runtime) -> Server[Any]:
    sessions: dict[int, Session] = {}
    # One gate call at a time per agent process: the SQLite stores are shared, and taint or
    # approval history written by one call must be seen by the next. A call waiting for an
    # approval therefore holds later calls until it returns (at most approval_wait_seconds).
    gate_lock = threading.Lock()

    def handle(session: Session, tool: str, args: dict[str, Any]) -> Result:
        with gate_lock:
            try:
                return runtime.gate.handle(session, tool, args)
            except Exception:  # never echo exception text: it could carry content
                return Result(False, Verdict.DENY, "internal error", error="internal_error")

    def session_for(ctx: ServerRequestContext[Any, Any]) -> Session:
        key = id(ctx.session)
        if key not in sessions:
            sessions[key] = runtime.new_session(client_hint=client_name(ctx))
        return sessions[key]

    async def list_tools(
        ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=tool_list())

    async def call_tool(
        ctx: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        session = session_for(ctx)
        args = dict(params.arguments or {})
        # Gate.handle blocks while it waits for an approval, so run it off the event loop.
        result = await anyio.to_thread.run_sync(handle, session, params.name, args)
        return to_tool_result(result)

    return Server(
        "agent-broker",
        version="0.0.1",
        instructions="Mail and calendar through a local policy gate. Some actions need approval.",
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )


async def run_stdio(runtime: Runtime) -> None:
    server = build_server(runtime)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def serve(config_path: Path, label: str) -> int:
    for warning in config_warnings(config_path):
        print(f"agent-broker warning: {warning}", file=sys.stderr)
    config = load_config(config_path)
    runtime = open_runtime(config, label)
    print(
        f"agent-broker: serving agent {label!r} in {config.mode} mode, profile {config.profile}",
        file=sys.stderr,
    )
    anyio.run(run_stdio, runtime)
    return 0
