"""Saved ordered execution target sets."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid

from .paths import PathConfig, ensure_dirs


class TargetSetStore:
    def __init__(self, config: PathConfig) -> None:
        self.config = config
        self.path = config.target_sets
        self._lock = threading.RLock()

    def list(self, snapshot: dict | None = None) -> list[dict]:
        with self._lock:
            rows = self._load()
        available = (
            {row["id"] for row in snapshot.get("servers", []) if isinstance(row, dict)}
            if snapshot is not None
            else None
        )
        result = []
        for row in rows:
            copy = {**row, "target_ids": list(row["target_ids"])}
            if available is not None:
                copy["missing"] = [
                    target_id for target_id in copy["target_ids"] if target_id not in available
                ]
            result.append(copy)
        return result

    def save(self, name: str, target_ids: list[str]) -> dict:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("target set name must not be empty")
        if not isinstance(target_ids, list) or any(
            not isinstance(value, str) or not value for value in target_ids
        ):
            raise ValueError("target ids must be a list of strings")
        deduped = list(dict.fromkeys(target_ids))
        row = {"id": str(uuid.uuid4()), "name": name.strip(), "target_ids": deduped}
        with self._lock:
            rows = self._load()
            rows.append(row)
            self._write(rows)
        return {**row, "target_ids": list(deduped)}

    def delete(self, target_set_id: str) -> bool:
        with self._lock:
            rows = self._load()
            remaining = [row for row in rows if row["id"] != target_set_id]
            if len(remaining) == len(rows):
                return False
            self._write(remaining)
        return True

    def _load(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            with self.path.open(encoding="utf-8") as handle:
                rows = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("target sets data is invalid") from exc
        if not isinstance(rows, list) or any(
            not isinstance(row, dict)
            or not isinstance(row.get("id"), str)
            or not isinstance(row.get("name"), str)
            or not isinstance(row.get("target_ids"), list)
            for row in rows
        ):
            raise ValueError("target sets data is invalid")
        return rows

    def _write(self, rows: list[dict]) -> None:
        ensure_dirs(self.config)
        descriptor, temporary = tempfile.mkstemp(
            dir=self.config.base, prefix=".target-sets-", suffix=".tmp"
        )
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(rows, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            if os.name == "posix":
                self.path.chmod(0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
