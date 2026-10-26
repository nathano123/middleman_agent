"""Broker settings, loaded once from a YAML file. Rules stay in the profile files.

The config is frozen after loading. Nothing an agent sends can change it: the only way to
change mode, contacts or limits is to edit the file and restart the broker.
"""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

ProfileName = Literal["cautious", "working", "autonomous"]
DEFAULT_AGENT = "default"
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
    # MCP client name -> agent id. Clients not listed all share the "default" agent id,
    # so taint cannot be shed by connecting under a different client name.
    agents: dict[str, str] = Field(default_factory=dict[str, str])
    taint_quiet_hours: float = Field(default=24.0, gt=0)
    full_view_body_chars: int = Field(default=2000, ge=1)
    full_view_after_approvals: int = Field(default=10, ge=1)
    state_dir: Path = Path("~/.agent-broker")

    def agent_id_for(self, client_name: str) -> str:
        return self.agents.get(client_name, DEFAULT_AGENT)

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
