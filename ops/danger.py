"""危险命令检测：高亮标注 + toast 提醒，不阻断生成"""

import re

# (pattern, level, 说明)  level: high=红 / medium=黄
DANGER_RULES = [
    (
        r"rm\s+-[a-z]*[rf][a-z]*\s+(-[a-z]+\s+)*(/\*|/\s*$|/\s)",
        "high",
        "rm -rf 根目录删除，毁灭性操作",
    ),
    (r"rm\s+-[a-z]*[rf]", "high", "rm -rf 递归强制删除"),
    (r"mkfs\.", "high", "格式化文件系统，数据将丢失"),
    (r"dd\s+.*of=/dev/", "high", "dd 直接写磁盘设备"),
    (r">\s*/dev/sd[a-z]", "high", "重定向直接写磁盘设备"),
    (r"\bwipefs\b", "high", "擦除磁盘/分区签名"),
    (r":\(\)\s*\{[^}]*:\s*\|\s*:\s*&[^}]*\}\s*;\s*:", "high", "fork 炸弹"),
    (r"chmod\s+-[a-z]*R[a-z]*\s+777\s+/(\s|$)", "high", "对根路径递归 777，权限灾难"),
    (r"chown\s+-[a-z]*R[a-z]*\s+\S+\s+/(\s|$)", "high", "对根路径递归 chown"),
    (r"\breboot\b", "medium", "重启服务器，连接将中断"),
    (r"\bshutdown\b|\bpoweroff\b|\bhalt\b", "medium", "关机操作，连接将中断"),
    (r"\binit\s+[06]\b", "medium", "切换运行级别（关机/重启）"),
    (r"\bsystemctl\s+restart\b", "medium", "重启服务可能短暂中断业务"),
    (r"iptables\s+-F\b", "medium", "清空防火墙规则，可能导致断连"),
    (
        r"systemctl\s+(stop|disable|mask)\s+(sshd?|network|NetworkManager)\b",
        "medium",
        "停止 SSH/网络服务，可能导致断连",
    ),
    (r"kill\s+-9\s+-1\b", "medium", "杀死所有进程"),
    (r"\bkillall\b", "medium", "按名称杀死所有匹配进程"),
    (r"\buserdel\b|\buseradd\b|\bpasswd\b", "medium", "账号变更操作"),
    (r"\b(crontab|at)\s+.*-r\b", "medium", "删除定时任务"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), lv, desc) for p, lv, desc in DANGER_RULES]


def detect(cmd: str) -> list:
    """返回 [{level, line, desc}]，一行同一规则只报一次"""
    hits = []
    for line in cmd.split("\n"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        for rx, level, desc in _COMPILED:
            if rx.search(s):
                hits.append({"level": level, "line": s[:100], "desc": desc})
                break
    return hits
