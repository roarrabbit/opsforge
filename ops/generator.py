"""
生成器：纯命令清单 / 批量 bash 脚本
- 脚本不内含 ssh 连接逻辑（工具不直连服务器），内容按台分段组织，
  方便整体保存或分段复制到第三方入口执行。
"""

import hashlib
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import paths, storage
from .danger import detect
from .delay import analyze
from .template import render

# 单条命令延时超过该值，提示"建议分段复制"
BIG_DELAY_THRESHOLD = 30


@dataclass(frozen=True)
class GeneratedResult:
    """A process-scoped generated result whose files are private to the owner."""

    id: str
    blocks: list[dict]
    list_text: str
    list_name: str
    script_name: str
    revision: int
    snapshot_hash: str
    danger_total: int


def build_blocks(selected: list, raw_cmd: str) -> list:
    """为每台服务器构建命令块：渲染变量 + 危险标注 + 单台延时分析"""
    blocks = []
    for idx, server in enumerate(selected):
        rendered = render(raw_cmd, server, idx)
        blocks.append(
            {
                "id": server.get("id", ""),
                "idx": idx + 1,
                "ip": server["ip"],
                "name": server.get("name") or "",
                "tags": server.get("tags", []),
                "cmd": rendered,
                "delay": analyze(rendered),
                "danger": detect(rendered),
            }
        )
    return blocks


def _block_header(b: dict, total: int) -> str:
    label = b["name"] or b["ip"]
    tag_str = f"  标签: {','.join(b['tags'])}" if b["tags"] else ""
    return f"# ===== [{b['idx']}/{total}] {label} ({b['ip']}){tag_str} ====="


def generate_list(blocks: list) -> str:
    """A 模式：纯命令清单文本"""
    lines = []
    for b in blocks:
        # lines.append(_block_header(b, total))
        for d in b["danger"]:
            lines.append(f"# ⚠ 高危: {d['desc']}")
        lines.append(b["cmd"])
        if b["delay"]["total_suggest"] > 0:
            lines.append(f"# ↑ 建议执行后等待 {b['delay']['total_suggest']}s")
        lines.append("")
    return "\n".join(lines)


def _script_text(blocks: list[dict], global_delay: int) -> str:
    """Build the bash text without deciding where it will be stored."""
    total = len(blocks)
    all_danger = [danger for block in blocks for danger in block["danger"]]
    big_delay_blocks = [
        block for block in blocks if block["delay"]["total_suggest"] >= BIG_DELAY_THRESHOLD
    ]
    lines = [
        "#!/bin/bash",
        f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# 目标服务器: {total} 台",
        f"# 建议平台下发间隔: {global_delay} 秒",
    ]
    if all_danger:
        lines.append(f"# ⚠ 包含 {len(all_danger)} 处危险命令，执行前请人工复核！")
    if big_delay_blocks:
        ips = ", ".join(block["ip"] for block in big_delay_blocks)
        lines.append(
            f"# ⚠ 以下服务器命令延时较大(≥{BIG_DELAY_THRESHOLD}s)，"
            f"建议分段复制、手动控制节奏: {ips}"
        )
    lines.append("")
    for block in blocks:
        for danger in block["danger"]:
            lines.append(f"# ⚠ 高危: {danger['desc']}  [命中: {danger['line'][:60]}]")
        lines.append(block["cmd"])
        suggested = block["delay"]["total_suggest"]
        if suggested > 0:
            lines.append(f"# [等待建议] 本台命令预计耗时 {suggested}s")
        lines.append("")
    lines.extend([f"# ===== 全部 {total} 台结束 =====", ""])
    return "\n".join(lines)


def _write_exclusive(output_dir: Path, suffix: str, content: str, mode: int) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        output_dir.chmod(0o700)
    for _ in range(20):
        name = f"ops_{time.time_ns()}_{secrets.token_hex(4)}{suffix}"
        destination = output_dir / name
        try:
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        except FileExistsError:
            continue
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "posix":
                destination.chmod(mode)
            return destination
        except Exception:
            destination.unlink(missing_ok=True)
            raise
    raise RuntimeError("无法分配唯一的生成文件")


def _snapshot_hash(targets: list[dict], command: str, delay: int, revision: int) -> str:
    stable_targets = [
        {
            key: target.get(key, "")
            for key in ("id", "ip", "name", "tags", "port", "user", "password", "remark")
        }
        for target in targets
    ]
    payload = json.dumps(
        {"targets": stable_targets, "command": command, "delay": delay, "revision": revision},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def generate(
    command: str,
    targets: list[dict],
    delay: int,
    output_dir: Path,
    revision: int,
) -> GeneratedResult:
    """Create immutable private list/script artifacts from one ordered target snapshot."""
    blocks = build_blocks(targets, command)
    list_text = generate_list(blocks)
    list_path = _write_exclusive(Path(output_dir), ".txt", list_text, 0o600)
    script_path = _write_exclusive(Path(output_dir), ".sh", _script_text(blocks, delay), 0o700)
    return GeneratedResult(
        id=str(uuid.uuid4()),
        blocks=blocks,
        list_text=list_text,
        list_name=list_path.name,
        script_name=script_path.name,
        revision=revision,
        snapshot_hash=_snapshot_hash(targets, command, delay, revision),
        danger_total=sum(len(block["danger"]) for block in blocks),
    )


def generate_bash(blocks: list, raw_cmd: str, global_delay: int) -> str:
    """B 模式：批量 bash 脚本，写入 output 目录，返回文件路径"""
    output = Path(paths.OUTPUT_DIR)
    return os.fspath(_write_exclusive(output, ".sh", _script_text(blocks, global_delay), 0o700))


def record_history(selected: list, raw_cmd: str, delay: int, mode: str, output_file: str = ""):
    storage.append_history(
        {
            "servers": [s["ip"] for s in selected],
            "server_names": {s["ip"]: (s.get("name") or "") for s in selected},
            "raw_cmd": raw_cmd,
            "delay": delay,
            "mode": mode,
            "output_file": output_file,
        }
    )
