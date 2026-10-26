"""Command line: verify-log, profiles, taint clear, simulate, report."""

import argparse
import sys
from datetime import date
from pathlib import Path

from broker.audit import AuditError, AuditLog, KeyringKeyStore, verify
from broker.config import DEFAULT_AGENT, DEFAULT_CONFIG_PATH, ConfigError, load_config
from broker.counters import Counters, weekly_report
from broker.rules.evaluator import PROFILE_NAMES, ProfileError, load_profile
from broker.sim import format_table, simulate
from broker.taint import SQLiteTaintStore


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


def cmd_taint_clear(config_path: Path, agent_id: str) -> int:
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    config.state_path("").mkdir(parents=True, exist_ok=True)
    store = SQLiteTaintStore(config.state_path("taint.db"))
    cleared = store.clear(agent_id)
    store.close()
    log = AuditLog(config.state_path("audit.db"), KeyringKeyStore())
    reason = "taint cleared by user" if cleared else "taint clear requested; agent was clean"
    log.append("cli", "taint_clear", "allow", reason, {"agent_id": agent_id[:64]})
    log.close()
    print(f"{agent_id}: {'taint cleared' if cleared else 'was not tainted'} (logged)")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="broker", description="Agent Access Broker (v0)")
    sub = parser.add_subparsers(dest="command", required=True)
    verify_cmd = sub.add_parser("verify-log", help="check the audit log hash chain")
    verify_cmd.add_argument("path", type=Path)
    sub.add_parser("profiles", help="list the bundled rule profiles")
    taint = sub.add_parser("taint", help="manage agent taint")
    taint_sub = taint.add_subparsers(dest="taint_command", required=True)
    clear = taint_sub.add_parser("clear", help="clear an agent's taint and log it")
    clear.add_argument("--agent", default=DEFAULT_AGENT)
    clear.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
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
    if args.command == "simulate":
        return cmd_simulate(args.profile, args.days, args.seed)
    if args.command == "report":
        return cmd_report(args.config, args.end)
    return cmd_profiles()


if __name__ == "__main__":
    sys.exit(main())
