"""Builds a running broker for one agent: config, stores, approver, backend and gate.

Used by the MCP server (`broker serve --agent <label>`). The agent id comes from the
registered launch label, never from the client.
"""

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Protocol, runtime_checkable

from broker.approvals.history import SQLiteApprovalHistory
from broker.approvals.queue import ApprovalQueue, QueueApprover
from broker.audit import AuditLog, KeyringKeyStore
from broker.backends.base import Backend
from broker.backends.fake import FakeBackend
from broker.config import BrokerConfig, ConfigError
from broker.counters import Counters
from broker.files import private_dir
from broker.gate import Gate
from broker.rules.evaluator import load_profile
from broker.taint import Contacts, Session, SQLiteTaintStore


def make_backend(config: BrokerConfig) -> Backend:
    if config.backend == "fake":
        if config.fake_fixture is None:
            return FakeBackend()
        return FakeBackend.from_fixture(config.fake_fixture.expanduser())
    raise ConfigError("backend: google is not available yet (Milestone 2, step 5)")


@dataclass
class Runtime:
    config: BrokerConfig
    agent_id: str
    gate: Gate
    contacts: Contacts
    store: SQLiteTaintStore
    history: SQLiteApprovalHistory
    sessions: int = field(default=0)

    def new_session(self, client_hint: str) -> Session:
        """One Session per MCP connection. `client_hint` is logged, never trusted."""
        self.sessions += 1
        return Session(
            f"{self.agent_id}-{self.sessions}",
            self.agent_id,
            self.contacts,
            self.store,
            self.history,
            client_hint=client_hint,
        )


def open_runtime(config: BrokerConfig, label: str, backend: Backend | None = None) -> Runtime:
    agent_id = config.agent_id_for(label)  # raises ConfigError for unregistered labels
    state = private_dir(config.state_path(""))
    if not state.is_dir():
        raise ConfigError(f"state directory {state} is not usable")
    backend = backend or make_backend(config)
    contacts = Contacts(
        config.own_address,
        frozenset(config.self_addresses) | frozenset(backend_self_addresses(backend)),
        frozenset(config.known_contacts) | frozenset(backend_known_contacts(backend)),
    )
    queue = ApprovalQueue(config.state_path("approvals.db"))
    approver = QueueApprover(queue, agent_id, wait_seconds=config.approval_wait_seconds)
    log = AuditLog(config.state_path("audit.db"), KeyringKeyStore())
    counters = Counters(config.state_path("counters.json"))
    gate = Gate(load_profile(config.profile), backend, approver, log, config, counters)
    store = SQLiteTaintStore(
        config.state_path("taint.db"), timedelta(hours=config.taint_quiet_hours)
    )
    history = SQLiteApprovalHistory(config.state_path("history.db"))
    return Runtime(config, agent_id, gate, contacts, store, history)


@runtime_checkable
class ContactSource(Protocol):
    """Optional backend extra: addresses derived from the account (Gmail backend)."""

    def self_addresses(self) -> list[str]: ...

    def known_contacts(self) -> list[str]: ...


def backend_self_addresses(backend: Backend) -> list[str]:
    return backend.self_addresses() if isinstance(backend, ContactSource) else []


def backend_known_contacts(backend: Backend) -> list[str]:
    return backend.known_contacts() if isinstance(backend, ContactSource) else []
