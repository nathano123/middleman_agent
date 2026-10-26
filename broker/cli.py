"""Command line: verify-log, profiles, taint clear, agents, approvals, simulate, report."""

import argparse
import json
import shutil
import sys
from datetime import date
from pathlib import Path

from broker.approvals.base import render_prompt
from broker.approvals.queue import ApprovalQueue, QueueError
from broker.audit import AuditError, AuditLog, KeyringKeyStore, verify
from broker.config import DEFAULT_CONFIG_PATH, ConfigError, add_agent, load_config
from broker.counters import Counters, weekly_report
from broker.files import private_dir
from broker.rules.evaluator import PROFILE_NAMES, ProfileError, load_profile
from broker.sim import format_table, simulate
from broker.taint import SQLiteTaintStore, utc_now


def cmd_verify_log(path: Path) -> int:
    keys = KeyringKeyStore()
    keyed = keys.get("audit-hmac-key") is not None
    try:
        bad = verify(path, keys if keyed else None)
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if bad is None:
        print(f"ok: chain intact in {path}")
        if keyed:
            print("checked: HMAC chain and newest-row anchor from the OS keychain")
        else:
            print("warning: no key in the OS keychain; checked as a plain hash chain, which")
            print("cannot detect a rewritten chain or rows removed from the end")
        return 0
    print(f"TAMPERED: first bad row id {bad} in {path}")
    return 1


def cmd_profiles() -> int:
    status = 0
    for name in PROFILE_NAMES:
        try:
            profile = load_profile(name)
        except ProfileError as exc:
            print(f"{name}: FAILED TO LOAD: {exc}", file=sys.stderr)
            status = 1
            continue
        print(f"{name} ({len(profile.rules)} rules): {profile.description}")
    return status


def cmd_taint_clear(config_path: Path, label: str) -> int:
    try:
        config = load_config(config_path)
        agent_id = config.agent_id_for(label)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    private_dir(config.state_path(""))
    store = SQLiteTaintStore(config.state_path("taint.db"))
    cleared = store.clear(agent_id)
    store.close()
    log = AuditLog(config.state_path("audit.db"), KeyringKeyStore())
    reason = "taint cleared by user" if cleared else "taint clear requested; agent was clean"
    log.append("cli", "taint_clear", "allow", reason, {"agent_id": agent_id[:64]})
    log.close()
    print(f"{label}: {'taint cleared' if cleared else 'was not tainted'} (logged)")
    print("note: connections already open keep their taint until they reconnect")
    return 0


def cmd_simulate(profile: str, days: int, seed: int) -> int:
    for name in PROFILE_NAMES:
        if profile in (name, "all"):
            print(format_table(name, simulate(name, days, seed)))
            print()
    return 0


def cmd_report(config_path: Path, end: date) -> int:
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(weekly_report(Counters(config.state_path("counters.json")), end))
    return 0


def cmd_agents_add(config_path: Path, label: str) -> int:
    try:
        agent_id = add_agent(config_path, label)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"registered agent {label!r} (id {agent_id})")
    print(setup_snippets(label, config_path))
    return 0


def setup_snippets(label: str, config_path: Path) -> str:
    """Copy-paste MCP client config for one agent, with absolute paths."""
    uv = shutil.which("uv") or "/ABSOLUTE/PATH/TO/uv"
    repo = str(Path(__file__).resolve().parents[1])
    config = str(config_path.expanduser().resolve())
    args = ["--directory", repo, "run", "broker", "serve", "--agent", label, "--config", config]
    desktop = {"mcpServers": {f"agent-broker-{label}": {"command": uv, "args": args}}}
    return "\n".join(
        [
            "",
            "Claude Desktop: add this entry to claude_desktop_config.json, then quit and restart",
            "(macOS: ~/Library/Application Support/Claude/claude_desktop_config.json):",
            json.dumps(desktop, indent=2),
            "",
            "Claude Code (stdio):",
            f"  claude mcp add --transport stdio agent-broker-{label} -- {uv} {' '.join(args)}",
        ]
    )


DEV_WARNING = (
    "WARNING - DEVELOPMENT ONLY: any program running as you, including an AI agent with a "
    "shell (e.g. Claude Code), can run this command and approve its own requests. Use it "
    "only on a test account. Approvals the agent cannot reach arrive in Milestone 3."
)


def cmd_approvals(config_path: Path, action: str, item_id: str | None) -> int:
    print(DEV_WARNING, file=sys.stderr)
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    queue = ApprovalQueue(config.state_path("approvals.db"))
    try:
        return approvals_action(queue, action, item_id)
    except QueueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        queue.close()


def approvals_action(queue: ApprovalQueue, action: str, item_id: str | None) -> int:
    now = utc_now()
    if action == "list":
        items = queue.pending(now)
        for item in items:
            age = int((now - item.created_at).total_seconds())
            print(f"--- {item.id} (agent {item.agent_id}, {age}s old)")
            if item.request is not None:
                print(render_prompt(item.request))
        print(f"{len(items)} pending")
        return 0
    assert item_id is not None
    item = queue.get(item_id)
    if action == "show":
        item = queue.mark_viewed(item_id)
        if item.request is not None:
            print(render_prompt(item.request))
            print("----- full body -----")
            print(item.request.full_body)
        return 0
    needs_view = item.request is not None and item.request.requires_full_view
    if action == "approve" and needs_view and not item.viewed:
        print(f"refused: open the full body first: broker approvals show {item_id}")
        return 1
    decided = queue.decide(item_id, approve=action == "approve", now=now)
    print(f"{item_id}: {decided.status}")
    return 0


def cmd_auth(config_path: Path) -> int:
    """Run Google consent for the configured test account and keep the token in the keychain."""
    from broker.backends.base import BackendError
    from broker.backends.google import open_google_backend
    from broker.google_auth import forget_credentials, run_consent, save_credentials

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if config.google_client_file is None:
        print("error: set google_client_file in the config first", file=sys.stderr)
        return 2
    keys = KeyringKeyStore()
    try:
        save_credentials(keys, run_consent(config.google_client_file))
        account = open_google_backend(config).self_addresses()
    except BackendError as exc:
        print(f"error: Google sign-in failed ({exc.code})", file=sys.stderr)
        return 1
    if config.own_address.lower() not in account:
        forget_credentials(keys)
        print(
            "error: the account you authorized is not own_address in the config; "
            "token discarded. Sign in with the test account.",
            file=sys.stderr,
        )
        return 1
    print(f"authorized {config.own_address}; token stored in the OS keychain")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="broker", description="Agent Access Broker (v0)")
    sub = parser.add_subparsers(dest="command", required=True)
    verify_cmd = sub.add_parser("verify-log", help="check the audit log hash chain")
    verify_cmd.add_argument("path", type=Path)
    sub.add_parser("profiles", help="list the bundled rule profiles")
    taint = sub.add_parser("taint", help="manage agent taint")
    taint_sub = taint.add_subparsers(dest="taint_command", required=True)
    clear = taint_sub.add_parser("clear", help="clear an agent's taint and log it")
    clear.add_argument("--agent", required=True, help="agent label from `broker agents add`")
    clear.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    agents = sub.add_parser("agents", help="register agents (one MCP server entry each)")
    agents_sub = agents.add_subparsers(dest="agents_command", required=True)
    agents_add = agents_sub.add_parser("add", help="register a new agent label")
    agents_add.add_argument("label")
    agents_add.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    auth_cmd = sub.add_parser("auth", help="sign in to Google (test account) and store the token")
    auth_cmd.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    serve_cmd = sub.add_parser("serve", help="run the MCP server (stdio) for one agent")
    serve_cmd.add_argument("--agent", required=True, help="label from `broker agents add`")
    serve_cmd.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    approvals = sub.add_parser(
        "approvals", help="answer pending approvals (DEVELOPMENT ONLY)", description=DEV_WARNING
    )
    approvals_sub = approvals.add_subparsers(dest="approvals_command", required=True)
    for name, text in (
        ("list", "show pending requests"),
        ("show", "show one request with its full body (counts as opening it)"),
        ("approve", "approve a request"),
        ("deny", "deny a request"),
    ):
        cmd = approvals_sub.add_parser(name, help=text, description=DEV_WARNING)
        if name != "list":
            cmd.add_argument("id")
        cmd.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    sim = sub.add_parser("simulate", help="replay fake workdays and count prompts")
    sim.add_argument("--profile", choices=[*PROFILE_NAMES, "all"], default="working")
    sim.add_argument("--days", type=int, default=7)
    sim.add_argument("--seed", type=int, default=7)
    report = sub.add_parser("report", help="print the weekly usage summary (counts only)")
    report.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    report.add_argument("--end", type=date.fromisoformat, default=date.today())
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "verify-log":
        return cmd_verify_log(args.path)
    if args.command == "taint":
        return cmd_taint_clear(args.config, args.agent)
    if args.command == "auth":
        return cmd_auth(args.config)
    if args.command == "serve":
        from broker.mcp_server import serve  # MCP imports only when serving

        try:
            return serve(args.config, args.agent)
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.command == "approvals":
        return cmd_approvals(args.config, args.approvals_command, getattr(args, "id", None))
    if args.command == "agents":
        return cmd_agents_add(args.config, args.label)
    if args.command == "simulate":
        return cmd_simulate(args.profile, args.days, args.seed)
    if args.command == "report":
        return cmd_report(args.config, args.end)
    return cmd_profiles()


if __name__ == "__main__":
    sys.exit(main())
