"""Runtime path configuration.

The default data directory remains ``~/.ops_cmd_generator``. Tests and
advanced users can point the application at an isolated directory with
``OPS_CMD_DATA_DIR``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PathConfig:
    base: Path
    servers: Path
    templates: Path
    delay_rules: Path
    history: Path
    target_sets: Path
    output: Path
    key: Path

    @classmethod
    def from_base(cls, base: Path) -> PathConfig:
        base = Path(base).expanduser()
        return cls(
            base=base,
            servers=base / "servers.json",
            templates=base / "templates.json",
            delay_rules=base / "delay_rules.json",
            history=base / "history.jsonl",
            target_sets=base / "target_sets.json",
            output=base / "output",
            key=base / ".secret.key",
        )


def get_paths() -> PathConfig:
    configured = os.environ.get("OPS_CMD_DATA_DIR")
    base = Path(configured) if configured else Path.home() / ".ops_cmd_generator"
    return PathConfig.from_base(base)


# Compatibility constants for modules that have not yet moved to PathConfig.
_DEFAULT = get_paths()
BASE_DIR = os.fspath(_DEFAULT.base)
SERVERS_FILE = os.fspath(_DEFAULT.servers)
TEMPLATES_FILE = os.fspath(_DEFAULT.templates)
DELAY_RULES_FILE = os.fspath(_DEFAULT.delay_rules)
HISTORY_FILE = os.fspath(_DEFAULT.history)
TARGET_SETS_FILE = os.fspath(_DEFAULT.target_sets)
KEY_FILE = os.fspath(_DEFAULT.key)
OUTPUT_DIR = os.fspath(_DEFAULT.output)


def ensure_dirs(config: PathConfig | None = None) -> PathConfig:
    selected = config or get_paths()
    selected.base.mkdir(parents=True, exist_ok=True, mode=0o700)
    selected.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        selected.base.chmod(0o700)
        selected.output.chmod(0o700)
    return selected
