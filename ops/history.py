"""Private, restorable command history without rendered credentials."""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import UTC, datetime

from .paths import PathConfig, ensure_dirs


class HistoryStore:
    def __init__(self, config: PathConfig) -> None:
        self.config = config
        self.path = config.history
        self._lock = threading.RLock()

    def append(self, record: dict) -> str:
        if not isinstance(record, dict):
            raise ValueError("history record must be an object")
        if {"rendered_command", "rendered_commands", "blocks", "list_text"} & set(record):
            raise ValueError("history must not contain rendered command content")
        if not isinstance(record.get("raw_cmd"), str):
            raise ValueError("history raw_cmd must be a string")
        if not isinstance(record.get("targets", []), list):
            raise ValueError("history targets must be a list")
        if not isinstance(record.get("delay", {}), dict):
            raise ValueError("history delay must be an object")
        saved = dict(record)
        saved["id"] = str(saved.get("id") or uuid.uuid4())
        saved.setdefault("created_at", datetime.now(UTC).isoformat())
        encoded = (json.dumps(saved, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        with self._lock:
            ensure_dirs(self.config)
            descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                if os.name == "posix":
                    os.fchmod(descriptor, 0o600)
                os.write(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return saved["id"]

    def list(self, limit: int = 50) -> dict:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("history limit must be a positive integer")
        if not self.path.exists():
            return {"records": [], "warnings": []}
        if os.name == "posix":
            self.path.chmod(0o600)
        records, warnings = [], []
        with self._lock, self.path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                        raise ValueError
                except (json.JSONDecodeError, ValueError):
                    warnings.append({"line": line_number, "code": "invalid_history_line"})
                    continue
                records.append(record)
        return {"records": records[-limit:][::-1], "warnings": warnings}

    def restore(self, record_id: str, snapshot: dict) -> dict:
        record = next((row for row in self.list(10_000)["records"] if row["id"] == record_id), None)
        if record is None:
            raise KeyError(record_id)
        available = {row["id"] for row in snapshot.get("servers", []) if isinstance(row, dict)}
        target_ids, missing = [], []
        for target in record.get("targets", []):
            if not isinstance(target, dict) or not isinstance(target.get("id"), str):
                continue
            if target["id"] in available:
                target_ids.append(target["id"])
            else:
                missing.append({"id": target["id"], "ip": target.get("ip", "")})
        return {
            "id": record["id"],
            "raw_cmd": record["raw_cmd"],
            "target_ids": target_ids,
            "missing": missing,
            "delay": record.get("delay", {"mode": "auto", "value": 0}),
            "asset_revision": record.get("asset_revision"),
        }
