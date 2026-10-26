"""Architecture guard: only broker/gate.py may call Backend methods.

The future MCP server (and anything else) must go through Gate.handle, so rules, taint,
approval and logging cannot be skipped.
"""

import ast
import inspect
from pathlib import Path

from broker.backends.base import Backend

PACKAGE = Path(__file__).parents[2] / "broker"
BACKEND_METHODS = {
    name for name, _ in inspect.getmembers(Backend, inspect.isfunction) if not name.startswith("_")
}
ALLOWED = {PACKAGE / "gate.py"} | set((PACKAGE / "backends").glob("*.py"))


def backend_calls(source: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in BACKEND_METHODS:
            found.append((node.lineno, func.attr))
        if isinstance(func, ast.Name) and func.id == "getattr":  # getattr(b, "send_message")
            for arg in node.args[1:2]:
                if isinstance(arg, ast.Constant) and arg.value in BACKEND_METHODS:
                    found.append((node.lineno, str(arg.value)))
    return found


def test_backend_methods_are_known() -> None:
    assert {"send_message", "create_event", "get_message", "search_messages"} <= BACKEND_METHODS


def test_only_gate_calls_backend_methods() -> None:
    offenders: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if path in ALLOWED:
            continue
        for line, name in backend_calls(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(PACKAGE.parent)}:{line} calls {name}")
    assert offenders == []


def test_guard_catches_direct_and_getattr_calls() -> None:
    sample = "def f(b):\n    b.send_message([], [], 's', 'b')\n    getattr(b, 'create_event')()\n"
    assert [name for _, name in backend_calls(sample)] == ["send_message", "create_event"]
