"""Command line: `broker verify-log <path>` and `broker profiles`."""

import argparse
import sys
from pathlib import Path

from broker.audit import AuditError, verify
from broker.rules.evaluator import PROFILE_NAMES, ProfileError, load_profile


def cmd_verify_log(path: Path) -> int:
    try:
        bad = verify(path)
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if bad is None:
        print(f"ok: chain intact in {path}")
        print("note: rows removed from the end of the log cannot be detected by the chain alone")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="broker", description="Agent Access Broker (v0)")
    sub = parser.add_subparsers(dest="command", required=True)
    verify_cmd = sub.add_parser("verify-log", help="check the audit log hash chain")
    verify_cmd.add_argument("path", type=Path)
    sub.add_parser("profiles", help="list the bundled rule profiles")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "verify-log":
        return cmd_verify_log(args.path)
    return cmd_profiles()


if __name__ == "__main__":
    sys.exit(main())
