from pathlib import Path

import pytest
from pydantic import ValidationError

from broker.audit import KeyringKeyStore, verify
from broker.cli import main
from broker.config import BrokerConfig, ConfigError, add_agent, load_config
from broker.taint import SQLiteTaintStore
from tests.conftest import START

EXAMPLE = Path(__file__).parents[2] / "broker.example.yaml"


def write_config(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(
        f"own_address: me@home.test\nstate_dir: {tmp_path}\nagents:\n  desktop: agt_1\n",
        encoding="utf-8",
    )
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


def test_only_registered_labels_resolve() -> None:
    config = BrokerConfig(own_address="me@home.test", agents={"desktop": "agt_1"})
    assert config.agent_id_for("desktop") == "agt_1"
    with pytest.raises(ConfigError):
        config.agent_id_for("claude-desktop")


def test_agents_add_registers_random_id(tmp_path: Path) -> None:
    path = write_config(tmp_path)
    first = add_agent(path, "laptop")
    second = add_agent(path, "code")
    assert first.startswith("agt_") and first != second
    config = load_config(path)
    assert config.agents == {"desktop": "agt_1", "laptop": first, "code": second}
    assert config.own_address == "me@home.test"
    assert (path.stat().st_mode & 0o777) == 0o600


@pytest.mark.parametrize("label", ["Desktop", "", "a b", "x" * 40, "-lead"])
def test_agents_add_refuses_bad_labels(tmp_path: Path, label: str) -> None:
    with pytest.raises(ConfigError):
        add_agent(write_config(tmp_path), label)


def test_agents_add_refuses_duplicates(tmp_path: Path) -> None:
    path = write_config(tmp_path)
    with pytest.raises(ConfigError):
        add_agent(path, "desktop")  # already registered by write_config


def test_cli_agents_add_prints_launch_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_config(tmp_path)
    assert main(["agents", "add", "laptop", "--config", str(path)]) == 0
    assert "broker serve --agent laptop" in capsys.readouterr().out


def test_cli_taint_clear_clears_and_logs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path = write_config(tmp_path)
    store = SQLiteTaintStore(tmp_path / "taint.db")
    store.mark("agt_1", "read a message from an unknown sender", START)
    store.close()
    assert main(["taint", "clear", "--agent", "desktop", "--config", str(config_path)]) == 0
    assert "taint cleared" in capsys.readouterr().out
    assert SQLiteTaintStore(tmp_path / "taint.db").get("agt_1", START) is None
    assert verify(tmp_path / "audit.db", KeyringKeyStore()) is None
    import sqlite3

    conn = sqlite3.connect(tmp_path / "audit.db")
    rows = conn.execute("SELECT tool, reason FROM log").fetchall()
    conn.close()
    assert rows == [("taint_clear", "taint cleared by user")]


def test_cli_taint_clear_when_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(["taint", "clear", "--agent", "desktop", "--config", str(write_config(tmp_path))]) == 0
    )
    assert "was not tainted" in capsys.readouterr().out


def test_cli_taint_clear_refuses_unregistered_agent(tmp_path: Path) -> None:
    assert (
        main(["taint", "clear", "--agent", "nobody", "--config", str(write_config(tmp_path))]) == 2
    )
