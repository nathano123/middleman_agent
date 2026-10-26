"""Private files for broker state: 0700 directories, 0600 files, and a config permission check.

This keeps other OS users out. It does not keep out an agent that runs as the same user with
a shell; see THREAT_MODEL.md.
"""

import os
import stat
from pathlib import Path

PRIVATE_DIR = 0o700
PRIVATE_FILE = 0o600


def is_memory(path: Path) -> bool:
    return str(path) == ":memory:"


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR)
    path.chmod(PRIVATE_DIR)
    return path


def private_file(path: Path) -> Path:
    """Create the file if missing (0600 from the start) and force 0600 if it already exists.

    SQLite gives its journal and WAL files the same permissions as the database file.
    """
    if is_memory(path):
        return path
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, PRIVATE_FILE)
    os.close(fd)
    path.chmod(PRIVATE_FILE)
    return path


def write_private_text(path: Path, text: str) -> None:
    """Write via a 0600 temp file and an atomic rename, so the file is never world-readable."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, PRIVATE_FILE)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, path)
    path.chmod(PRIVATE_FILE)


def config_warnings(path: Path) -> list[str]:
    """Reasons the config file could be changed by someone other than the user."""
    warnings: list[str] = []
    path = path.expanduser()
    if not path.exists():
        return warnings
    for target in (path, path.parent):
        info = target.stat()
        kind = "config file" if target == path else "config folder"
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            warnings.append(f"{kind} {target} is writable by other users (chmod go-w)")
        if info.st_uid != os.getuid():
            warnings.append(f"{kind} {target} is owned by another user")
    return warnings
