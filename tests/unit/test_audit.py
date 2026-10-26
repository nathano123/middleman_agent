import sqlite3
from pathlib import Path

import pytest

from broker.audit import AuditError, AuditLog, verify


def make_log(tmp_path: Path, rows: int = 5) -> Path:
    path = tmp_path / "audit.db"
    log = AuditLog(path)
    for i in range(rows):
        log.append(
            session_id="s1",
            tool="search_mail",
            decision="allow",
            reason="search returns headers and snippet only",
            metadata={"result_count": i, "tainted": False},
        )
    log.close()
    return path


def run_sql(path: Path, sql: str, params: tuple[object, ...] = ()) -> None:
    conn = sqlite3.connect(path)
    conn.execute(sql, params)
    conn.commit()
    conn.close()


def test_clean_chain_verifies(tmp_path: Path) -> None:
    assert verify(make_log(tmp_path)) is None


def test_empty_log_verifies(tmp_path: Path) -> None:
    assert verify(make_log(tmp_path, rows=0)) is None


def test_reopened_log_continues_chain(tmp_path: Path) -> None:
    path = make_log(tmp_path, rows=2)
    log = AuditLog(path)
    assert log.append("s2", "list_events", "allow", "r", {}) == 3
    log.close()
    assert verify(path) is None


@pytest.mark.parametrize("column", ["ts", "session_id", "tool", "decision", "reason", "metadata"])
@pytest.mark.parametrize("row_id", [1, 3, 5])
def test_editing_any_field_of_any_row_is_detected(tmp_path: Path, column: str, row_id: int) -> None:
    path = make_log(tmp_path)
    run_sql(path, f"UPDATE log SET {column} = 'tampered' WHERE id = ?", (row_id,))
    assert verify(path) == row_id


def test_edit_with_recomputed_hash_is_caught_at_next_row(tmp_path: Path) -> None:
    from broker.audit import row_hash

    path = make_log(tmp_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    row = dict(conn.execute("SELECT * FROM log WHERE id = 2").fetchone())
    row["decision"] = "deny"
    conn.execute("UPDATE log SET decision = ?, hash = ? WHERE id = 2", ("deny", row_hash(row)))
    conn.commit()
    conn.close()
    assert verify(path) == 3


def test_deleting_middle_row_is_detected(tmp_path: Path) -> None:
    path = make_log(tmp_path)
    run_sql(path, "DELETE FROM log WHERE id = 3")
    assert verify(path) == 4


def test_deleting_first_row_is_detected(tmp_path: Path) -> None:
    path = make_log(tmp_path)
    run_sql(path, "DELETE FROM log WHERE id = 1")
    assert verify(path) == 2


def test_reordering_rows_is_detected(tmp_path: Path) -> None:
    path = make_log(tmp_path)
    run_sql(path, "UPDATE log SET id = 100 WHERE id = 2")
    run_sql(path, "UPDATE log SET id = 2 WHERE id = 4")
    run_sql(path, "UPDATE log SET id = 4 WHERE id = 100")
    assert verify(path) == 2


def test_truncating_the_tail_is_not_detected(tmp_path: Path) -> None:
    """Known limit, documented in README: a hash chain alone cannot see a removed last row."""
    path = make_log(tmp_path)
    run_sql(path, "DELETE FROM log WHERE id = 5")
    assert verify(path) is None


def test_verify_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(AuditError):
        verify(tmp_path / "missing.db")
    assert not (tmp_path / "missing.db").exists()


@pytest.mark.parametrize("key", ["body", "subject", "snippet", "description", "text"])
def test_content_keys_are_refused(tmp_path: Path, key: str) -> None:
    log = AuditLog(tmp_path / "audit.db")
    with pytest.raises(AuditError):
        log.append("s1", "read_message", "allow", "r", {key: "hello"})
    log.close()


def test_long_strings_are_refused(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.db")
    with pytest.raises(AuditError):
        log.append("s1", "read_message", "allow", "r", {"message_id": "x" * 500})
    with pytest.raises(AuditError):
        log.append("s1", "send_mail", "ask", "r", {"recipient_domains": ["y" * 500]})
    log.close()


def test_no_message_content_is_written(tmp_path: Path) -> None:
    body = "Please wire 40,000 EUR to IBAN DE89370400440532013000 today"
    path = tmp_path / "audit.db"
    log = AuditLog(path)
    log.append(
        "s1",
        "send_mail",
        "ask",
        "every send needs approval",
        {"recipient_count": 1, "recipient_domains": ["evil.test"], "approval": "denied"},
    )
    log.close()
    raw = path.read_bytes()
    assert body.encode() not in raw
    assert b"IBAN" not in raw


# --- keyed chain with a head anchor (keychain) -------------------------------


class DictKeys:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def set(self, name: str, value: str) -> None:
        self.values[name] = value


def make_keyed_log(tmp_path: Path, keys: DictKeys, rows: int = 5) -> Path:
    path = tmp_path / "keyed.db"
    log = AuditLog(path, keys)
    for i in range(rows):
        log.append("s1", "search_mail", "allow", "r", {"result_count": i})
    log.close()
    return path


def test_keyed_chain_verifies(tmp_path: Path) -> None:
    keys = DictKeys()
    assert verify(make_keyed_log(tmp_path, keys), keys) is None


def test_keyed_chain_detects_tail_truncation(tmp_path: Path) -> None:
    keys = DictKeys()
    path = make_keyed_log(tmp_path, keys)
    run_sql(path, "DELETE FROM log WHERE id >= 4")
    assert verify(path, keys) == 5


def test_keyed_chain_detects_rewrite_without_the_key(tmp_path: Path) -> None:
    """An attacker recomputes every hash (plain SHA-256 or a guessed key): row 1 fails."""
    from broker.audit import GENESIS_HASH, row_hash

    keys = DictKeys()
    path = make_keyed_log(tmp_path, keys)
    for guess in (None, b"wrong-key"):
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        prev = GENESIS_HASH
        for found in conn.execute("SELECT * FROM log ORDER BY id").fetchall():
            row = dict(found)
            row["decision"], row["prev_hash"] = "deny", prev
            prev = row_hash(row, guess)
            conn.execute(
                "UPDATE log SET decision = ?, prev_hash = ?, hash = ? WHERE id = ?",
                ("deny", row["prev_hash"], prev, row["id"]),
            )
        conn.commit()
        conn.close()
        assert verify(path) is None or guess is not None  # plain check is fooled
        assert verify(path, keys) == 1


def test_keyed_verify_without_key_refuses(tmp_path: Path) -> None:
    path = make_keyed_log(tmp_path, DictKeys())
    with pytest.raises(AuditError):
        verify(path, DictKeys())


def test_cli_uses_keychain_and_reports_truncation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from broker.audit import KeyringKeyStore
    from broker.cli import main

    path = tmp_path / "audit.db"
    log = AuditLog(path, KeyringKeyStore())  # the autouse fixture makes this an in-memory keyring
    for _ in range(3):
        log.append("s1", "search_mail", "allow", "r", {})
    log.close()
    assert main(["verify-log", str(path)]) == 0
    assert "HMAC chain" in capsys.readouterr().out
    run_sql(path, "DELETE FROM log WHERE id = 3")
    assert main(["verify-log", str(path)]) == 1


def test_tests_never_touch_the_real_keychain() -> None:
    import keyring

    from tests.conftest import MemoryKeyring

    assert isinstance(keyring.get_keyring(), MemoryKeyring)
