from pathlib import Path

import pytest
from pydantic import ValidationError

from broker.audit import KeyringKeyStore, verify
from broker.cli import main
from broker.config import BrokerConfig, ConfigError, load_config
from broker.taint import SQLiteTaintStore
from tests.conftest import START

EXAMPLE = Path(__file__).parents[2] / "broker.example.yaml"


def write_config(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(f"own_address: me@home.test\nstate_dir: {tmp_path}\n", encoding="utf-8")
    return path


def test_example_config_loads() -> None:
    config = load_config(EXAMPLE)
    assert config.mode == "enforce"
    assert "me.work@office.test" in config.self_addresses


@pytest.mark.parametrize(
    "text",
    [
        "own_address: [",
        "mode: watch",
        "own_address: a@b.test\nmode: off",
        "own_address: a@b.test\nx: 1",
    ],
)
def test_malformed_config_refused(tmp_path: Path, text: str) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_config_is_frozen() -> None:
    config = BrokerConfig(own_address="me@home.test")
    with pytest.raises(ValidationError):
        config.mode = "watch"  # type: ignore[misc]


def test_unregistered_clients_share_default_agent() -> None:
    config = BrokerConfig(own_address="me@home.test", agents={"mail-bot": "bot"})
    assert config.agent_id_for("claude-desktop") == "default"
    assert config.agent_id_for("some-other-client") == "default"
    assert config.agent_id_for("mail-bot") == "bot"


def test_cli_taint_clear_clears_and_logs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path = write_config(tmp_path)
    store = SQLiteTaintStore(tmp_path / "taint.db")
    store.mark("default", "read a message from an unknown sender", START)
    store.close()
    assert main(["taint", "clear", "--config", str(config_path)]) == 0
    assert "taint cleared" in capsys.readouterr().out
    assert SQLiteTaintStore(tmp_path / "taint.db").get("default", START) is None
    assert verify(tmp_path / "audit.db", KeyringKeyStore()) is None
    import sqlite3

    conn = sqlite3.connect(tmp_path / "audit.db")
    rows = conn.execute("SELECT tool, reason FROM log").fetchall()
    conn.close()
    assert rows == [("taint_clear", "taint cleared by user")]


def test_cli_taint_clear_when_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["taint", "clear", "--config", str(write_config(tmp_path))]) == 0
    assert "was not tainted" in capsys.readouterr().out
