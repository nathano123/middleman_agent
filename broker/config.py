"""Broker settings, loaded once from a YAML file. Rules stay in the profile files.

The config is frozen after loading. Nothing an agent sends can change it: the only way to
change mode, contacts or limits is to edit the file and restart the broker.
"""

import re
import secrets
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from broker.files import write_private_text

ProfileName = Literal["cautious", "working", "autonomous"]
AGENT_LABEL = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
DEFAULT_CONFIG_PATH = Path("~/.agent-broker/config.yaml")


class ConfigError(Exception):
    pass


class BrokerConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    own_address: str = Field(min_length=3)
    self_addresses: tuple[str, ...] = ()  # the user's other addresses (aliases)
    known_contacts: tuple[str, ...] = ()
    profile: ProfileName = "working"
    mode: Literal["enforce", "watch"] = "enforce"
    # Agent label -> random agent id, written by `broker agents add`. The MCP server is
    # launched with `--agent <label>`; the id never comes from anything the agent sends.
    agents: dict[str, str] = Field(default_factory=dict[str, str])
    taint_quiet_hours: float = Field(default=24.0, gt=0)
    full_view_body_chars: int = Field(default=2000, ge=1)
    full_view_after_approvals: int = Field(default=10, ge=1)
    state_dir: Path = Path("~/.agent-broker")
    backend: Literal["fake", "google"] = "fake"
    fake_fixture: Path | None = None  # JSON inbox for backend: fake (development)
    approval_wait_seconds: float = Field(default=45.0, gt=0, le=300)
    timezone: str = "UTC"  # IANA name; used for calendar listing and event times
    google_client_file: Path | None = None  # OAuth "Desktop app" client JSON (keep out of git)
    # Where approval requests go besides the local queue. "telegram": a bot connected with
    # `broker phone setup`; its token and the owner's user id live in the OS keychain.
    phone: Literal["none", "telegram"] = "none"
    # Lets `broker approvals approve/deny` answer requests while a phone is configured.
    # Development only: any program running as you can run that command.
    dev_cli_approvals: bool = False

    def agent_id_for(self, label: str) -> str:
        """The registered id for a launch label. Unregistered labels are refused."""
        if label not in self.agents:
            raise ConfigError(f"agent {label!r} is not registered; run `broker agents add {label}`")
        return self.agents[label]

    def state_path(self, name: str) -> Path:
        return self.state_dir.expanduser() / name


def load_config(path: Path) -> BrokerConfig:
    try:
        raw = yaml.safe_load(path.expanduser().read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    try:
        return BrokerConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid config {path}: {exc}") from exc


def add_agent(path: Path, label: str) -> str:
    """Register a new agent label in the config file with a random id. Returns the id.

    The file is rewritten from its parsed YAML, so comments in it are not kept.
    """
    if not AGENT_LABEL.match(label):
        raise ConfigError("agent label must be 1-32 chars of a-z, 0-9 and '-'")
    path = path.expanduser()
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    load_config(path)  # refuse to touch a config that does not load
    agents: dict[str, str] = dict(raw.get("agents") or {})
    if label in agents:
        raise ConfigError(f"agent {label!r} already exists")
    agents[label] = f"agt_{secrets.token_hex(8)}"
    raw["agents"] = agents
    write_private_text(path, yaml.safe_dump(raw, sort_keys=False))
    return agents[label]
