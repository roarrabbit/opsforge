"""标签分组配置：属性组（单选）与标签组（多选）。

- groups.json 存于数据目录，首次运行写入默认值
- 组内 items 是"值 → 组"的归属关系；同一值可同时挂在多个组下
- 属性组的单选约束由 storage 层在写入机器 tags 时执行
"""
from __future__ import annotations

import json
import os
import tempfile
import threading

from .paths import PathConfig, ensure_dirs

ATTRIBUTE = "attribute"
TAG = "tag"
GROUP_TYPES = (ATTRIBUTE, TAG)

DEFAULT_TAG_GROUPS = [
    {"name": "角色", "type": ATTRIBUTE,
     "items": ["应用服务器", "前置机服务器", "数据库", "web服务器",
               "AI推理服务器", "中间件服务器"]},
    {"name": "业务层", "type": TAG, "items": ["前端", "后端"]},
    {"name": "平台", "type": TAG, "items": ["国产", "非国产"]},
]


class TagGroupStore:
    FIELDS = ("name", "type", "items")

    def __init__(self, config: PathConfig) -> None:
        self.config = config
        self.path = config.base / "groups.json"
        self._lock = threading.RLock()

    def list(self) -> list[dict]:
        """读取全部分组；文件不存在时写入默认值。"""
        with self._lock:
            if not self.path.exists():
                groups = [dict(g) for g in DEFAULT_TAG_GROUPS]
                self._write(groups)
                return groups
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return [dict(g) for g in DEFAULT_TAG_GROUPS]
            if not isinstance(raw, list):
                return [dict(g) for g in DEFAULT_TAG_GROUPS]
            return [self._normalize(g) for g in raw if isinstance(g, dict)]

    def save(self, groups: list[dict]) -> None:
        with self._lock:
            cleaned = []
            seen = set()
            for g in groups or []:
                item = self._normalize(g)
                if not item["name"] or item["name"] in seen:
                    continue
                seen.add(item["name"])
                # 成员去重保序
                deduped = list(dict.fromkeys(item["items"]))
                item["items"] = deduped
                cleaned.append(item)
            self._write(cleaned)

    def rename_value(self, old: str, new: str) -> int:
        """值重命名时同步所有组内成员，返回受影响组数。"""
        with self._lock:
            groups = self.list()
            affected = 0
            for g in groups:
                if old in g["items"]:
                    g["items"] = list(dict.fromkeys(new if x == old else x for x in g["items"]))
                    affected += 1
            if affected:
                self.save(groups)
            return affected

    def remove_value(self, value: str) -> int:
        """值被全局删除时从所有组移除，返回受影响组数。"""
        with self._lock:
            groups = self.list()
            affected = 0
            for g in groups:
                if value in g["items"]:
                    g["items"] = [x for x in g["items"] if x != value]
                    affected += 1
            if affected:
                self.save(groups)
            return affected

    def attribute_index(self) -> dict[str, str]:
        """属性组成员 → 所属属性组名（多组归属时先注册者优先）。"""
        index: dict[str, str] = {}
        for g in self.list():
            if g["type"] == ATTRIBUTE:
                for item in g["items"]:
                    index.setdefault(item, g["name"])
        return index

    def _normalize(self, g: dict) -> dict:
        name = str(g.get("name") or "").strip()
        gtype = str(g.get("type") or TAG).strip()
        if gtype not in GROUP_TYPES:
            gtype = TAG
        items = [str(x).strip() for x in (g.get("items") or []) if str(x).strip()]
        return {"name": name, "type": gtype, "items": items}

    def _write(self, groups: list[dict]) -> None:
        ensure_dirs(self.config)
        descriptor, temporary = tempfile.mkstemp(
            dir=self.config.base, prefix=".groups-", suffix=".tmp"
        )
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(groups, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            if os.name == "posix":
                self.path.chmod(0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


_STORES: dict[str, TagGroupStore] = {}
_LOCK = threading.Lock()


def get_tag_group_store(config: PathConfig | None = None) -> TagGroupStore:
    from . import paths as paths_mod

    selected = config or paths_mod.get_paths()
    key = str(selected.base.resolve())
    with _LOCK:
        store = _STORES.get(key)
        if store is None:
            store = TagGroupStore(selected)
            _STORES[key] = store
        return store
