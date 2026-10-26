import os
import stat
from datetime import date
from pathlib import Path

from broker.approvals.history import SQLiteApprovalHistory
from broker.audit import AuditLog
from broker.counters import Counters
from broker.files import config_warnings, private_dir
from broker.rules.models import Verdict
from broker.taint import SQLiteTaintStore


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_every_state_file_is_0600(tmp_path: Path) -> None:
    old = os.umask(0o022)  # a typical umask that would otherwise give 0644
    try:
        AuditLog(tmp_path / "audit.db").close()
        SQLiteTaintStore(tmp_path / "taint.db").close()
        SQLiteApprovalHistory(tmp_path / "history.db").close()
        Counters(tmp_path / "counters.json").record(date(2026, 1, 1), Verdict.ASK, None, None)
    finally:
        os.umask(old)
    for name in ("audit.db", "taint.db", "history.db", "counters.json"):
        assert mode(tmp_path / name) == 0o600, name


def test_existing_loose_file_is_tightened(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    path.touch()
    path.chmod(0o644)
    AuditLog(path).close()
    assert mode(path) == 0o600


def test_state_dir_is_0700(tmp_path: Path) -> None:
    assert mode(private_dir(tmp_path / "state")) == 0o700


def test_config_warning_when_writable_by_others(tmp_path: Path) -> None:
    folder = private_dir(tmp_path / "cfg")
    config = folder / "config.yaml"
    config.write_text("own_address: me@home.test\n", encoding="utf-8")
    config.chmod(0o600)
    assert config_warnings(config) == []
    config.chmod(0o666)
    assert any("writable by other users" in w for w in config_warnings(config))
    config.chmod(0o600)
    folder.chmod(0o777)
    assert any("config folder" in w for w in config_warnings(config))
