import sqlite3
from pathlib import Path

import pytest

from broker.audit import AuditLog
from broker.cli import main


def make_log(tmp_path: Path) -> Path:
    path = tmp_path / "audit.db"
    log = AuditLog(path)
    for _ in range(3):
        log.append("s1", "search_mail", "allow", "r", {})
    log.close()
    return path


def test_profiles_lists_all_three(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["profiles"]) == 0
    out = capsys.readouterr().out
    assert "cautious" in out and "working" in out and "autonomous" in out


def test_verify_log_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify-log", str(make_log(tmp_path))]) == 0
    assert "ok" in capsys.readouterr().out


def test_verify_log_tampered(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = make_log(tmp_path)
    conn = sqlite3.connect(path)
    conn.execute("UPDATE log SET decision = 'deny' WHERE id = 2")
    conn.commit()
    conn.close()
    assert main(["verify-log", str(path)]) == 1
    assert "first bad row id 2" in capsys.readouterr().out


def test_verify_log_missing(tmp_path: Path) -> None:
    assert main(["verify-log", str(tmp_path / "nope.db")]) == 2
