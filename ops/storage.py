"""
数据层：服务器 / 命令模板 / 生成历史 / 延时规则 的读写
- servers.json    服务器列表（含 name/tags 字段，自动迁移老格式）
- templates.json  命令模板库
- history.jsonl   生成历史（追加写）
- delay_rules.json 延时规则（首次运行写入默认值，用户可编辑）
"""
import copy
import csv
import io
import json
import os
import re
import tempfile
import threading
import time
import uuid
from pathlib import Path

from . import paths
from .crypto import PasswordCipher
from .errors import DataCorruptionError, RevisionConflict, ValidationError

# ---------------- 预置标签维度（可自由增删，仅作建议） ----------------
PRESET_TAG_GROUPS = {
    "业务层": ["前端", "后端"],
    "角色": ["应用服务器", "前置机服务器", "数据库", "web服务器", "AI推理服务器", "中间件服务器"],
    "平台": ["国产", "非国产"],
}

# ---------------- 内置命令模板（首次运行写入） ----------------
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


def _load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path, data):
    # 原子写：先写临时文件再 os.replace 替换，避免并发/中断时文件被截断或损坏成多段 JSON
    import tempfile
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


# ==================== 服务器 ====================


class AssetRepository:
    """Versioned, encrypted, atomic storage for server assets."""

    SCHEMA_VERSION = 3
    ASSET_FIELDS = ("ip", "name", "tags", "port", "user", "remark")

    def __init__(self, config: paths.PathConfig, cipher: PasswordCipher) -> None:
        self.paths = config
        self.cipher = cipher
        self._lock = threading.RLock()

    def snapshot(self, reveal_passwords: bool = False) -> dict:
        with self._lock:
            document = self._load_and_migrate()
            return self._snapshot(document, reveal_passwords=reveal_passwords)

    def commit(self, expected_revision: int, operations: list[dict]) -> dict:
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
            raise ValidationError("revision 必须是整数")
        if not isinstance(operations, list):
            raise ValidationError("operations 必须是数组")
        with self._lock:
            document = self._load_and_migrate()
            if document["revision"] != expected_revision:
                raise RevisionConflict(expected_revision, document["revision"])
            candidate = copy.deepcopy(document)
            self._apply_all(candidate, operations)
            self._validate_document(candidate)
            candidate["revision"] += 1
            if self.paths.servers.exists():
                self._atomic_write(document, self.paths.servers.with_suffix(".json.bak"))
            self._atomic_write(candidate, self.paths.servers)
            return self._snapshot(candidate, reveal_passwords=False)

    def _empty_document(self) -> dict:
        return {"schema_version": self.SCHEMA_VERSION, "revision": 0, "servers": []}

    def _load_and_migrate(self) -> dict:
        if not self.paths.servers.exists():
            return self._empty_document()
        try:
            with self.paths.servers.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except json.JSONDecodeError as exc:
            raise DataCorruptionError(f"无法解析 {self.paths.servers}，原文件已保留") from exc
        except OSError as exc:
            raise DataCorruptionError(f"无法读取 {self.paths.servers}") from exc

        if isinstance(raw, list):
            migrated = self._migrate_legacy(raw)
            self._validate_document(migrated)
            self._atomic_write(migrated, self.paths.servers)
            return migrated
        if not isinstance(raw, dict):
            raise DataCorruptionError("servers.json 顶层必须是数组或版本化对象")
        self._validate_document(raw)
        return raw

    def _migrate_legacy(self, rows: list) -> dict:
        migrated = []
        for index, row in enumerate(rows, 1):
            if not isinstance(row, dict):
                raise DataCorruptionError(f"旧资产第 {index} 行不是对象")
            ip = row.get("ip")
            hostname = row.get("hostname", "")
            name = row.get("name", "" if hostname == ip else hostname)
            password = row.get("password", "")
            if not isinstance(password, str):
                raise DataCorruptionError(f"旧资产第 {index} 行密码不是字符串")
            if password and not self.cipher.is_encrypted(password):
                password = self.cipher.encrypt(password)
            asset = {
                "id": str(row.get("id") or uuid.uuid4()),
                "ip": ip,
                "name": name or "",
                "tags": row.get("tags", []),
                "port": str(row.get("port", "22")),
                "user": row.get("user", "root"),
                "password": password,
                "remark": row.get("remark", ""),
            }
            migrated.append(asset)
        return {"schema_version": self.SCHEMA_VERSION, "revision": 1, "servers": migrated}

    def _validate_document(self, document: dict) -> None:
        if document.get("schema_version") != self.SCHEMA_VERSION:
            raise DataCorruptionError("不支持的 servers.json schema_version")
        revision = document.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
            raise DataCorruptionError("servers.json revision 无效")
        servers = document.get("servers")
        if not isinstance(servers, list):
            raise DataCorruptionError("servers.json servers 必须是数组")

        ids: set[str] = set()
        ips: set[str] = set()
        for index, asset in enumerate(servers, 1):
            if not isinstance(asset, dict):
                raise DataCorruptionError(f"资产第 {index} 行不是对象")
            asset_id = asset.get("id")
            if not isinstance(asset_id, str) or not asset_id or asset_id in ids:
                raise DataCorruptionError(f"资产第 {index} 行 id 缺失或重复")
            ids.add(asset_id)
            ip = asset.get("ip")
            if not validate_ip(ip) or ip in ips:
                raise DataCorruptionError(f"资产第 {index} 行 IP 无效或重复")
            ips.add(ip)
            self._validate_asset_fields(asset, index, corruption=True)
            password = asset.get("password")
            if not isinstance(password, str):
                raise DataCorruptionError(f"资产第 {index} 行密码不是字符串")
            if password:
                if not self.cipher.is_encrypted(password):
                    raise DataCorruptionError(f"资产第 {index} 行密码未加密")
                self.cipher.decrypt(password)

    def _validate_asset_fields(self, asset: dict, index: int, *, corruption: bool) -> None:
        error_type = DataCorruptionError if corruption else ValidationError
        for field in ("name", "user", "remark"):
            if not isinstance(asset.get(field), str):
                raise error_type(f"资产第 {index} 行 {field} 必须是字符串")
        tags = asset.get("tags")
        if not isinstance(tags, list) or any(not isinstance(tag, str) or not tag for tag in tags):
            raise error_type(f"资产第 {index} 行 tags 必须是非空字符串数组")
        port = asset.get("port")
        if not isinstance(port, str) or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise error_type(f"资产第 {index} 行 port 必须是 1-65535")

    def _apply_all(self, document: dict, operations: list[dict]) -> None:
        by_id = {asset["id"]: asset for asset in document["servers"]}
        order = [asset["id"] for asset in document["servers"]]
        for op_index, operation in enumerate(operations, 1):
            if not isinstance(operation, dict):
                raise ValidationError(f"第 {op_index} 个操作必须是对象")
            action = operation.get("op")
            asset_id = operation.get("id")
            if action == "delete":
                if not isinstance(asset_id, str) or asset_id not in by_id:
                    raise ValidationError(f"第 {op_index} 个删除操作目标不存在")
                del by_id[asset_id]
                order.remove(asset_id)
                continue
            if action != "upsert":
                raise ValidationError(f"第 {op_index} 个操作类型无效")

            is_new = asset_id is None
            if is_new:
                asset_id = str(uuid.uuid4())
                asset = {
                    "id": asset_id,
                    "ip": "",
                    "name": "",
                    "tags": [],
                    "port": "22",
                    "user": "root",
                    "password": "",
                    "remark": "",
                }
                order.append(asset_id)
            elif not isinstance(asset_id, str) or asset_id not in by_id:
                raise ValidationError(f"第 {op_index} 个更新操作目标不存在")
            else:
                asset = copy.deepcopy(by_id[asset_id])

            values = operation.get("values", {})
            if not isinstance(values, dict):
                raise ValidationError(f"第 {op_index} 个操作 values 必须是对象")
            unknown = set(values) - set(self.ASSET_FIELDS)
            if unknown:
                fields = ", ".join(sorted(unknown))
                raise ValidationError(f"第 {op_index} 个操作包含未知字段: {fields}")
            for field, value in values.items():
                asset[field] = str(value) if field == "port" else copy.deepcopy(value)

            password_op = operation.get("password", {"action": "keep"})
            if not isinstance(password_op, dict):
                raise ValidationError(f"第 {op_index} 个操作 password 必须是对象")
            password_action = password_op.get("action")
            if password_action == "set":
                password_value = password_op.get("value")
                if not isinstance(password_value, str):
                    raise ValidationError(f"第 {op_index} 个操作密码必须是字符串")
                asset["password"] = self.cipher.encrypt(password_value)
            elif password_action == "clear":
                asset["password"] = ""
            elif password_action != "keep":
                raise ValidationError(f"第 {op_index} 个操作密码动作无效")

            by_id[asset_id] = asset

        document["servers"] = [by_id[asset_id] for asset_id in order]
        self._validate_candidate(document)

    def _validate_candidate(self, document: dict) -> None:
        ips: set[str] = set()
        for index, asset in enumerate(document["servers"], 1):
            if not validate_ip(asset.get("ip")):
                raise ValidationError(f"资产第 {index} 行 IP 无效")
            if asset["ip"] in ips:
                raise ValidationError(f"资产第 {index} 行 IP 重复")
            ips.add(asset["ip"])
            self._validate_asset_fields(asset, index, corruption=False)

    def _snapshot(self, document: dict, *, reveal_passwords: bool) -> dict:
        result = {
            "schema_version": self.SCHEMA_VERSION,
            "revision": document["revision"],
            "servers": [],
        }
        for stored in document["servers"]:
            asset = {
                key: copy.deepcopy(value)
                for key, value in stored.items()
                if key != "password"
            }
            if reveal_passwords:
                asset["password"] = self.cipher.decrypt(stored["password"])
            else:
                asset["password_set"] = bool(stored["password"])
            result["servers"].append(asset)
        return result

    def _atomic_write(self, document: dict, destination: Path) -> None:
        paths.ensure_dirs(self.paths)
        descriptor, temporary = tempfile.mkstemp(
            dir=self.paths.base,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary)
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(document, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, destination)
            if os.name == "posix":
                destination.chmod(0o600)
                directory_fd = os.open(self.paths.base, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except Exception:
            try:
                temporary_path.unlink()
            except OSError:
                pass
            raise


_REPOSITORIES: dict[Path, AssetRepository] = {}
_REPOSITORIES_LOCK = threading.Lock()


def get_asset_repository(config: paths.PathConfig | None = None) -> AssetRepository:
    selected = config or paths.get_paths()
    key = selected.base.resolve()
    with _REPOSITORIES_LOCK:
        repository = _REPOSITORIES.get(key)
        if repository is None:
            repository = AssetRepository(selected, PasswordCipher(selected.key))
            _REPOSITORIES[key] = repository
        return repository

def validate_ip(ip: str) -> bool:
    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip or ""):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))


# ---------------- 示例服务器（仅 servers.json 不存在的首次运行写入） ----------------
DEMO_SERVERS = [
    {"ip": "192.168.1.11", "name": "web-01", "tags": ["前端", "web服务器"],
     "port": "22", "user": "root", "password": "", "remark": "示例机器，可修改或删除"},
    {"ip": "192.168.1.12", "name": "web-02", "tags": ["前端", "web服务器"],
     "port": "22", "user": "root", "password": "", "remark": "示例机器，可修改或删除"},
    {"ip": "192.168.1.21", "name": "app-01", "tags": ["后端", "应用服务器"],
     "port": "22", "user": "root", "password": "", "remark": "示例机器，可修改或删除"},
    {"ip": "192.168.1.22", "name": "app-02", "tags": ["后端", "应用服务器"],
     "port": "22", "user": "root", "password": "", "remark": "示例机器，可修改或删除"},
    {"ip": "192.168.1.31", "name": "db-01", "tags": ["后端", "数据库", "国产"],
     "port": "22", "user": "root", "password": "", "remark": "示例机器，可修改或删除"},
]


def load_servers() -> list:
    """Compatibility view for the GUI. Seeds demo servers on the very first run."""
    if not os.path.exists(paths.SERVERS_FILE):
        save_servers([dict(row) for row in DEMO_SERVERS])
    return get_asset_repository().snapshot(reveal_passwords=True)["servers"]


def save_servers(servers: list):
    """Replace the compatibility view through one revisioned commit."""
    repository = get_asset_repository()
    snapshot = repository.snapshot(reveal_passwords=True)
    existing_by_id = {row["id"]: row for row in snapshot["servers"]}
    existing_by_ip = {row["ip"]: row for row in snapshot["servers"]}
    kept_ids = set()
    operations = []
    for row in servers:
        asset_id = row.get("id")
        existing = existing_by_id.get(asset_id) if asset_id else existing_by_ip.get(row.get("ip"))
        if existing:
            asset_id = existing["id"]
            kept_ids.add(asset_id)
        values = {
            field: copy.deepcopy(row.get(field))
            for field in AssetRepository.ASSET_FIELDS
            if field in row
        }
        password = row.get("password", existing.get("password", "") if existing else "")
        if existing and password == existing.get("password", ""):
            password_op = {"action": "keep"}
        elif password == "":
            password_op = {"action": "clear"}
        else:
            password_op = {"action": "set", "value": password}
        operations.append({
            "op": "upsert",
            "id": asset_id if existing else None,
            "values": values,
            "password": password_op,
        })
    for asset_id in existing_by_id:
        if asset_id not in kept_ids:
            operations.append({"op": "delete", "id": asset_id})
    repository.commit(snapshot["revision"], operations)


def add_server(ip, name="", tags=None, port="22", user="root", password="", remark=""):
    servers = load_servers()
    if any(s["ip"] == ip for s in servers):
        return False, f"IP {ip} 已存在"
    servers.append({
        "ip": ip, "name": name,
        "tags": apply_single_choice(list(tags or [])),
        "port": str(port), "user": user, "password": password, "remark": remark,
    })
    save_servers(servers)
    return True, "ok"


def update_server(current_ip, **fields):
    if "tags" in fields and isinstance(fields["tags"], list):
        fields = {**fields, "tags": apply_single_choice(list(fields["tags"]))}
    servers = load_servers()
    # IP 是主键，允许变更但必须合法且不与其他行冲突
    new_ip = str(fields.get("ip") or "").strip() if "ip" in fields else ""
    if new_ip and new_ip != current_ip:
        if not validate_ip(new_ip):
            raise ValidationError(f"无效 IP 地址: {new_ip}")
        if any(s["ip"] == new_ip for s in servers):
            raise ValidationError(f"IP {new_ip} 已存在")
    for s in servers:
        if s["ip"] == current_ip:
            if new_ip:
                s["ip"] = new_ip
            for k in ("name", "tags", "port", "user", "password", "remark"):
                if k in fields:
                    s[k] = fields[k]
            save_servers(servers)
            return True
    return False


def remove_servers(ips: list) -> int:
    servers = load_servers()
    before = len(servers)
    servers = [s for s in servers if s["ip"] not in set(ips)]
    save_servers(servers)
    return before - len(servers)


def clear_servers():
    """一键清空所有服务器"""
    save_servers([])


def all_tags() -> list:
    """汇总所有已用标签（去重，保持出现顺序）"""
    tags = []
    for s in load_servers():
        for t in s.get("tags", []):
            if t not in tags:
                tags.append(t)
    return tags


def _attribute_group_index() -> dict:
    from .tag_groups import get_tag_group_store

    return get_tag_group_store().attribute_index()


def apply_single_choice(tags: list) -> list:
    """属性组单选约束：每个属性组仅保留最后一次出现的成员（新值胜出）。"""
    index = _attribute_group_index()
    if not index:
        return list(tags)
    last_pos: dict = {}
    for i, t in enumerate(tags):
        g = index.get(t)
        if g:
            last_pos[g] = i
    keep = set(last_pos.values())
    return [t for i, t in enumerate(tags) if not index.get(t) or i in keep]


def rename_tag(old: str, new: str) -> int:
    """重命名标签：把所有服务器上的 old 标签改为 new，返回受影响服务器数
    若 new 已存在于某服务器，合并去重；同时同步分组配置内的成员。
    重命名可能让新值落入某属性组，故改名后重新执行属性单选约束。"""
    if not old or not new or old == new:
        return 0
    servers = load_servers()
    affected = 0
    for s in servers:
        tags = s.get("tags", [])
        if old in tags:
            seen, deduped = set(), []
            for t in tags:
                nt = new if t == old else t
                if nt not in seen:
                    seen.add(nt)
                    deduped.append(nt)
            s["tags"] = deduped
            affected += 1
    if affected:
        save_servers(servers)
        # 属性单选约束以最新分组配置为准，统一再收敛一遍
        cleaned = load_servers()
        for row in cleaned:
            row["tags"] = apply_single_choice(row["tags"])
        save_servers(cleaned)
    from .tag_groups import get_tag_group_store

    get_tag_group_store().rename_value(old, new)
    return affected


def remove_tag(tag: str) -> int:
    """从所有服务器移除某标签，返回受影响服务器数；同时从分组配置移除"""
    servers = load_servers()
    affected = 0
    for s in servers:
        if tag in s.get("tags", []):
            s["tags"] = [t for t in s["tags"] if t != tag]
            affected += 1
    if affected:
        save_servers(servers)
    from .tag_groups import get_tag_group_store

    get_tag_group_store().remove_value(tag)
    return affected


def batch_add_tags(ips: list, tags: list) -> int:
    """给多台服务器批量追加标签（去重 + 属性组单选约束），返回受影响服务器数"""
    if not ips or not tags:
        return 0
    servers = load_servers()
    ipset = set(ips)
    n = 0
    for s in servers:
        if s["ip"] in ipset:
            cur = list(s.get("tags", []))
            for t in tags:
                if t not in cur:
                    cur.append(t)
            s["tags"] = apply_single_choice(cur)
            n += 1
    save_servers(servers)
    return n


def batch_remove_tags(ips: list, tags: list) -> int:
    """从多台服务器批量移除标签，返回受影响服务器数"""
    if not ips or not tags:
        return 0
    servers = load_servers()
    ipset = set(ips)
    tagset = set(tags)
    n = 0
    for s in servers:
        if s["ip"] in ipset:
            before = len(s.get("tags", []))
            s["tags"] = [t for t in s.get("tags", []) if t not in tagset]
            if len(s["tags"]) != before:
                n += 1
    if n:
        save_servers(servers)
    return n


def filter_servers(tag=None, name_kw=None, ip_kw=None) -> list:
    """按标签 / 命名关键字 / IP 关键字筛选（条件之间为 AND；tag 可传列表，OR 语义）"""
    result = []
    tags = [tag] if isinstance(tag, str) else (tag or [])
    for s in load_servers():
        if tags and not any(t in s.get("tags", []) for t in tags):
            continue
        if name_kw and name_kw.lower() not in (s.get("name") or "").lower():
            continue
        if ip_kw and ip_kw not in s["ip"]:
            continue
        result.append(s)
    return result


CSV_HEADERS = ["命名", "IP", "账号", "密码", "标签", "端口", "备注"]


def export_csv() -> str:
    """导出为带表头 CSV（UTF-8 BOM，Excel 双击直接打开不乱码）。

    ⚠ 密码列为明文，导出文件请妥善保管。
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_HEADERS)
    for s in load_servers():
        writer.writerow([
            s.get("name") or "-",
            s["ip"],
            s.get("user", "root"),
            s.get("password") or "",
            ",".join(s.get("tags") or []),
            str(s.get("port") or "22"),
            s.get("remark") or "",
        ])
    return "\ufeff" + buf.getvalue()


# 表头名 → 字段 的映射（导入时识别表头行用）
_HEADER_ALIASES = {
    "命名": "name", "名称": "name", "别名": "name", "name": "name",
    "ip": "ip", "地址": "ip",
    "账号": "user", "用户": "user", "用户名": "user", "user": "user",
    "密码": "password", "password": "password",
    "标签": "tags", "tag": "tags", "tags": "tags",
    "端口": "port", "port": "port",
    "备注": "remark", "说明": "remark", "remark": "remark",
}


def _parse_import_rows(text: str) -> list[list[str]]:
    """把粘贴文本解析为行列数组。逐行识别三种格式（可混合），跳过注释与空行：
    - 含 Tab → TSV（Excel 直接粘贴）
    - 首个逗号出现在首个空格之前（或无空格）→ CSV（引号转义生效）
    - 其余 → 最老的空格分隔格式：命名 IP 账号 密码 标签1,标签2
    """
    stripped = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    tsv_lines, csv_lines, space_rows = [], [], []
    for ln in stripped:
        if "\t" in ln:
            tsv_lines.append(ln)
            continue
        fc, fs = ln.find(","), ln.find(" ")
        if fc != -1 and (fs == -1 or fc < fs):
            csv_lines.append(ln)
            continue
        parts = ln.split()
        tags = parts[4].split(",") if len(parts) > 4 else []
        space_rows.append(parts[:4] + [",".join(t for t in tags if t)])
    out: list[list[str]] = []
    for lines, delim in ((tsv_lines, "\t"), (csv_lines, ",")):
        if not lines:
            continue
        for row in csv.reader(io.StringIO("\n".join(lines)), delimiter=delim):
            cells = [c.strip() for c in row]
            if any(cells):
                out.append(cells)
    out.extend(space_rows)
    return out


def import_text(text: str):
    """从文本批量导入服务器。支持：
    - 带表头 CSV/TSV：命名,IP,账号,密码,标签,端口,备注（列序按表头识别；从 Excel 直接粘贴即可）
    - 无表头 CSV：命名,IP,账号,密码,标签1,标签2,...（旧格式兼容；引号转义生效）
    - 空格分隔旧格式
    # 开头为注释。与 export_csv 的产物直接互导。返回 (added, skipped)。
    """
    if text.startswith("\ufeff"):
        text = text[1:]          # 兼容导出 CSV 自带的 UTF-8 BOM
    added, skipped = 0, []
    rows = _parse_import_rows(text)
    if not rows:
        return 0, ["没有可导入的内容"]

    col_map: dict | None = None
    first = [h.strip().lower() for h in rows[0]]
    if "ip" in first and any(_HEADER_ALIASES.get(h) == "name" for h in first):
        col_map = {}
        for idx, raw in enumerate(rows[0]):
            field = _HEADER_ALIASES.get(raw.strip().lower())
            if field and field not in col_map:
                col_map[field] = idx
        rows = rows[1:]

    for row in rows:
        def cell(field, default="", _row=row, _map=col_map):   # 默认参数绑定当前行，避免闭包陷阱
            if _map is None:
                return ""
            v = _row[_map[field]] if field in _map and _map[field] < len(_row) else ""
            return v if v else default

        if col_map is not None:
            name = cell("name")
            ip = cell("ip")
            user = cell("user", "root")
            password = cell("password")
            port = cell("port", "22")
            remark = cell("remark")
            tags = [t.strip() for t in cell("tags").split(",") if t.strip()]
        else:
            if len(row) < 2:
                skipped.append(f"格式错误(需 命名,IP,...): {' '.join(row)[:40]}")
                continue
            name, ip = row[0], row[1]
            user = row[2] if len(row) > 2 and row[2] else "root"
            password = row[3] if len(row) > 3 else ""
            tags = [t for t in row[4:] if t]
            port, remark = "22", ""

        if ip == "-" or not validate_ip(ip):
            skipped.append(f"无效IP: {','.join(row)[:40]}")
            continue
        ok, msg = add_server(ip, name=name, tags=tags, user=user, password=password,
                             port=port, remark=remark)
        if ok:
            added += 1
        else:
            skipped.append(f"{ip}: {msg}")
    return added, skipped


def export_text() -> str:
    """导出为逗号分隔格式：命名,IP,账号,密码,标签1,标签2,..."""
    lines = ["# 命名,IP,账号,密码,标签1,标签2,..."]
    for s in load_servers():
        row = [s.get("name") or "-", s["ip"], s.get("user", "root"), s.get("password") or "-"]
        tags = s.get("tags") or []
        if tags:
            row += tags
        lines.append(",".join(row))
    return "\n".join(lines) + "\n"


# ==================== 命令模板 ====================

def load_templates() -> list:
    tpls = _load_json(paths.TEMPLATES_FILE, None)
    if tpls is None:
        tpls = DEFAULT_TEMPLATES[:]
        save_templates(tpls)
    return tpls


def save_templates(tpls: list):
    _save_json(paths.TEMPLATES_FILE, tpls)


# ==================== 生成历史 ====================

def append_history(record: dict):
    record = dict(record)
    record["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(paths.HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_history(limit=50) -> list:
    if not os.path.exists(paths.HISTORY_FILE):
        return []
    with open(paths.HISTORY_FILE, encoding="utf-8") as f:
        lines = f.read().strip().splitlines()
    records = []
    for line in lines[-limit:][::-1]:
        try:
            records.append(json.loads(line))
        except Exception:
            continue
    return records


# ==================== 延时规则 ====================

def load_delay_rules() -> list:
    """返回 [{pattern, min, suggest, reason}, ...]，首次运行写入默认"""
    rules = _load_json(paths.DELAY_RULES_FILE, None)
    if rules is None:
        from .delay import DEFAULT_DELAY_RULES
        rules = DEFAULT_DELAY_RULES
        _save_json(paths.DELAY_RULES_FILE, rules)
    return rules
