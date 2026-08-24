"""
延时分析：
- 按行拆分（跳过空行/注释/sleep 本身）
- 每行先按 && ; || 切成「串行段」，段间延时累加
- 每段内再按 | 切「管道」，管道内各命令并行，取最大延时
- 规则来自 delay_rules.json（可用户编辑），此处只放默认值
"""

import re

from .errors import ValidationError

# 默认延时规则：pattern -> min/suggest 秒 + 原因（首次运行写入 delay_rules.json）
DEFAULT_DELAY_RULES = [
    # systemctl 系列
    {
        "pattern": r"systemctl\s+(start|restart|reload)\b",
        "min": 3,
        "suggest": 5,
        "reason": "服务启动/重启需等待进程就绪",
    },
    {"pattern": r"systemctl\s+stop\b", "min": 2, "suggest": 3, "reason": "服务停止需等待进程退出"},
    {
        "pattern": r"systemctl\s+daemon-reload\b",
        "min": 2,
        "suggest": 3,
        "reason": "systemd 配置重载",
    },
    # service 系列
    {
        "pattern": r"service\s+\w+\s+(start|restart|reload)\b",
        "min": 3,
        "suggest": 5,
        "reason": "service 启动/重启",
    },
    {"pattern": r"service\s+\w+\s+stop\b", "min": 2, "suggest": 3, "reason": "service 停止"},
    # 包管理
    {
        "pattern": r"\b(yum|dnf)\s+(install|update|upgrade|remove)\b",
        "min": 10,
        "suggest": 30,
        "reason": "包管理操作依赖网络与仓库响应",
    },
    {
        "pattern": r"\bapt(-get)?\s+(install|update|upgrade|remove|autoremove)\b",
        "min": 10,
        "suggest": 30,
        "reason": "apt 包操作依赖网络与仓库响应",
    },
    {
        "pattern": r"\bpip3?\s+(install|uninstall)\b",
        "min": 5,
        "suggest": 15,
        "reason": "pip 包安装",
    },
    # Docker
    {
        "pattern": r"docker\s+(pull|build|push)\b",
        "min": 10,
        "suggest": 30,
        "reason": "Docker 镜像拉取/构建/推送",
    },
    {
        "pattern": r"docker\s+(run|start|restart)\b",
        "min": 3,
        "suggest": 5,
        "reason": "Docker 容器启动",
    },
    {
        "pattern": r"docker(-|\s+)compose\s+up\b",
        "min": 5,
        "suggest": 10,
        "reason": "Docker Compose 启动",
    },
    # 文件操作
    {
        "pattern": r"\bfind\s+",
        "min": 3,
        "suggest": 10,
        "reason": "find 遍历文件系统，耗时取决于目录大小",
    },
    {"pattern": r"\bdu\s+", "min": 2, "suggest": 8, "reason": "du 统计目录大小"},
    {
        "pattern": r"\btar\s+.*\.(tar|gz|tgz|bz2|xz|zip)",
        "min": 5,
        "suggest": 15,
        "reason": "压缩/解压大文件耗时",
    },
    {"pattern": r"\b(rsync|scp)\s+", "min": 5, "suggest": 20, "reason": "文件传输耗时取决于数据量"},
    {"pattern": r"\bdd\s+", "min": 10, "suggest": 60, "reason": "dd 磁盘操作耗时"},
    {"pattern": r"\brm\s+-[rf]{1,2}", "min": 2, "suggest": 10, "reason": "rm -rf 大量文件删除耗时"},
    # 网络下载
    {
        "pattern": r"\bwget\s+",
        "min": 5,
        "suggest": 30,
        "reason": "wget 下载耗时取决于文件大小与网速",
    },
    {"pattern": r"\bcurl\s+.*\s-O\b", "min": 5, "suggest": 30, "reason": "curl 下载耗时"},
    # 系统级
    {"pattern": r"\breboot\b", "min": 30, "suggest": 60, "reason": "服务器重启需等待系统完全启动"},
    {"pattern": r"\bshutdown\b", "min": 30, "suggest": 60, "reason": "关机/重启"},
    {"pattern": r"\bfsck\b", "min": 30, "suggest": 120, "reason": "文件系统检查耗时较长"},
    {"pattern": r"mkfs\.", "min": 5, "suggest": 20, "reason": "格式化文件系统"},
    # 数据库
    {"pattern": r"\bmysqldump\b", "min": 5, "suggest": 30, "reason": "MySQL 备份耗时取决于数据量"},
    {"pattern": r"\bpg_dump\b", "min": 5, "suggest": 30, "reason": "PostgreSQL 备份耗时"},
    # 编译/构建
    {
        "pattern": r"\bmake\b(?!.*install)",
        "min": 10,
        "suggest": 60,
        "reason": "make 编译耗时取决于项目规模",
    },
    {
        "pattern": r"\b(npm|pnpm|yarn)\s+(install|ci)\b",
        "min": 10,
        "suggest": 60,
        "reason": "前端依赖安装耗时",
    },
    # 其他
    {
        "pattern": r"\bgit\s+clone\b",
        "min": 5,
        "suggest": 30,
        "reason": "git clone 耗时取决于仓库大小",
    },
    {
        "pattern": r"\bkubectl\s+(apply|delete)\b",
        "min": 3,
        "suggest": 10,
        "reason": "k8s 资源变更耗时",
    },
    {
        "pattern": r"\bansible-playbook\b",
        "min": 10,
        "suggest": 60,
        "reason": "Ansible Playbook 执行耗时",
    },
]

_SERIAL_SPLIT = re.compile(r"&&|\|\||;")
_PIPE_SPLIT = re.compile(r"\|")
_SLEEP_RE = re.compile(r"^\s*sleep\b")


def compile_rules(rules: list[dict]) -> list[tuple[re.Pattern, dict]]:
    """Validate and compile user-editable delay rules with row-level feedback."""
    if not isinstance(rules, list):
        raise ValidationError("延时规则必须是数组")

    compiled = []
    field_errors = []
    for row, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            field_errors.append({"row": row, "field": "rule", "message": "规则必须是对象"})
            continue

        pattern = rule.get("pattern")
        minimum = rule.get("min")
        suggest = rule.get("suggest")
        reason = rule.get("reason")
        if not isinstance(pattern, str) or not pattern:
            field_errors.append({"row": row, "field": "pattern", "message": "匹配规则不能为空"})
            continue
        if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 0:
            field_errors.append({"row": row, "field": "min", "message": "最小延时必须是非负整数"})
            continue
        if not isinstance(suggest, int) or isinstance(suggest, bool) or suggest < minimum:
            field_errors.append(
                {"row": row, "field": "suggest", "message": "建议延时必须是不小于最小延时的整数"}
            )
            continue
        if not isinstance(reason, str) or not reason.strip():
            field_errors.append({"row": row, "field": "reason", "message": "原因不能为空"})
            continue
        try:
            compiled.append((re.compile(pattern, re.IGNORECASE), rule))
        except re.error:
            field_errors.append({"row": row, "field": "pattern", "message": "正则表达式无效"})

    if field_errors:
        raise ValidationError("延时规则无效", field_errors)
    return compiled


def _segment_delay(seg: str, compiled):
    """单个串行段的延时：内部管道并行取 max；返回 (min, suggest, 命中描述)"""
    best = None  # (min, suggest, pattern_desc, reason)
    for part in _PIPE_SPLIT.split(seg):
        part = part.strip()
        if not part or _SLEEP_RE.match(part):
            continue
        for rx, rule in compiled:
            if rx.search(part):
                cand = (rule["min"], rule["suggest"], part.strip(), rule["reason"])
                if best is None or cand[1] > best[1]:
                    best = cand
                break  # 一个管道命令只取第一条命中的规则
    return best


def analyze(cmd: str, rules: list = None):
    """
    分析命令延时需求。
    返回 dict: {total_min, total_suggest, details: [{segment, reason, min, suggest}]}
    """
    if rules is None:
        from .storage import load_delay_rules

        rules = load_delay_rules()
    compiled = compile_rules(rules)

    total_min, total_suggest, details = 0, 0, []
    for line in cmd.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or _SLEEP_RE.match(line):
            continue
        for seg in _SERIAL_SPLIT.split(line):
            seg = seg.strip()
            if not seg:
                continue
            hit = _segment_delay(seg, compiled)
            if hit:
                total_min += hit[0]
                total_suggest += hit[1]
                details.append(
                    {
                        "segment": hit[2][:80],
                        "reason": hit[3],
                        "min": hit[0],
                        "suggest": hit[1],
                    }
                )
    return {"total_min": total_min, "total_suggest": total_suggest, "details": details}
