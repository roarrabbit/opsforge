"""Version-stable command template CRUD."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid

from .paths import PathConfig, ensure_dirs

# 内置命令模板（仅 templates.json 不存在的首次运行写入）
DEFAULT_TEMPLATES = [
    {"name": "重启 nginx 并检查状态", "category": "服务管理",
     "content": "systemctl restart nginx && systemctl is-active nginx"},
    {"name": "重启应用服务", "category": "服务管理",
     "content": "systemctl restart {name} && systemctl status {name} --no-pager -l"},
    {"name": "磁盘使用率检查", "category": "巡检",
     "content": "df -h | grep -v tmpfs"},
    {"name": "清理 7 天前日志", "category": "日志",
     "content": "find /var/log -name '*.log' -mtime +7 -delete"},
    {"name": "查看服务监听端口", "category": "巡检",
     "content": "ss -tlnp"},
    {"name": "时间同步状态检查", "category": "巡检",
     "content": "timedatectl status && chronyc sources 2>/dev/null || ntpq -p 2>/dev/null"},
    {
        "name": "查看最近登录失败记录",
        "category": "安全",
        "content": (
            "lastb -n 20 2>/dev/null || journalctl -u sshd --since today "
            "| grep -i failed | tail -20"
        ),
    },
    {"name": "内存与负载概览", "category": "巡检",
     "content": "free -h && uptime"},
]


class TemplateStore:
    FIELDS = ("name", "category", "content")

    def __init__(self, config: PathConfig) -> None:
        self.config = config
        self.path = config.templates
        self._lock = threading.RLock()

    def list(self) -> list[dict]:
        with self._lock:
            rows, migrated = self._load()
            if migrated:
                self._write(rows)
            return [dict(row) for row in rows]

    def create(self, values: dict) -> dict:
        row = {"id": str(uuid.uuid4()), **self._validate(values, require_all=True)}
        with self._lock:
            rows, _ = self._load()
            rows.append(row)
            self._write(rows)
        return dict(row)

    def update(self, template_id: str, values: dict) -> dict:
        changes = self._validate(values, require_all=False)
        if not changes:
            raise ValueError("template update cannot be empty")
        with self._lock:
            rows, _ = self._load()
            for row in rows:
                if row["id"] == template_id:
                    row.update(changes)
                    self._write(rows)
                    return dict(row)
        raise KeyError(template_id)

    def delete(self, template_id: str) -> bool:
        with self._lock:
            rows, _ = self._load()
            remaining = [row for row in rows if row["id"] != template_id]
            if len(remaining) == len(rows):
                return False
            self._write(remaining)
        return True

    def _validate(self, values: dict, *, require_all: bool) -> dict:
        if not isinstance(values, dict):
            raise ValueError("template values must be an object")
        unknown = set(values) - set(self.FIELDS)
        if unknown:
            raise ValueError("template has unknown fields")
        if require_all and set(values) != set(self.FIELDS):
            raise ValueError("template requires name, category, and content")
        if any(not isinstance(value, str) for value in values.values()):
            raise ValueError("template fields must be strings")
        return dict(values)

    def _load(self) -> tuple[list[dict], bool]:
        if not self.path.exists():
            seeded = [{"id": str(uuid.uuid4()), **row} for row in DEFAULT_TEMPLATES]
            return seeded, True
        try:
            with self.path.open(encoding="utf-8") as handle:
                rows = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("templates data is invalid") from exc
        if not isinstance(rows, list):
            raise ValueError("templates data is invalid")
        migrated = False
        normalized = []
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("templates data is invalid")
            data = {field: row.get(field) for field in self.FIELDS}
            self._validate(data, require_all=True)
            template_id = row.get("id")
            if not isinstance(template_id, str) or not template_id:
                template_id = str(uuid.uuid4())
                migrated = True
            normalized.append({"id": template_id, **data})
        return normalized, migrated

    def _write(self, rows: list[dict]) -> None:
        ensure_dirs(self.config)
        descriptor, temporary = tempfile.mkstemp(
            dir=self.config.base, prefix=".templates-", suffix=".tmp"
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
