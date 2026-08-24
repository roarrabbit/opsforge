"""命令模板变量插值"""

import re

# 编辑栏展示的变量（保持精简；历史旧变量在下方 render() 中保留渲染兼容，但不再暴露）
TEMPLATE_VARS = {
    "{ip}": "服务器完整 IP",
    "{ip_prefix}": "网段前缀（前三段含点），如 192.0.2.",
    "{ip_last}": "IP 末段，如 22",
    "{name}": "服务器命名（别名）",
    "{user}": "登录账号",
    "{password}": "登录密码",
    "{port}": "端口",
    "{date}": "当天日期，如 20260824",
}

# 历史变量 → 等价新变量（仅用于老模板渲染兜底与数据迁移，不再对外展示）
LEGACY_VARS = {
    "{hostname}": "{name}",
    "{idx}": None,      # 无等价物，渲染为空由 mapping 兜底
    "{idx0}": None,
    "{tag}": None,
    "{tags}": None,
    "{ip_3rd}": None,
    "{ip_2nd}": None,
    "{ip_1st}": None,
}


def editor_vars() -> dict:
    """命令编辑器中展示的变量（历史版本曾隐藏部分变量，现全量即展示集）"""
    return dict(TEMPLATE_VARS)


_SSH_RE = re.compile(r"^ssh\s+(\S+?)@([\d.]+):(\d+)\s*$")


def script_to_template(text: str) -> str:
    """把多服务器交互式脚本转成带变量的模板。

    规则：
      - ``ssh user@ip:port``       -> ``ssh {user}@{ip}:{port}``
      - ``ssh`` 之后首个非空行      -> ``{password}``
      - ``sudo -i`` 之后首个非空行  -> ``{password}``
      - 其余行原样保留
    这样每个服务器块都被变量化，生成时按服务器 {ip}/{password}/{user}/{port} 绑定，
    日后只需在服务器管理中更新密码即可重新批量生成。
    """
    out, prev = [], None
    for raw in text.splitlines():
        line = raw.rstrip()
        m = _SSH_RE.match(line)
        if m:
            out.append("ssh {user}@{ip}:{port}")
            prev = "ssh"
            continue
        s = line.strip()
        if s == "sudo -i":
            out.append("sudo -i")
            prev = "sudo"
            continue
        if not s:
            out.append(line)
            continue
        if s and prev == "ssh":
            out.append("{password}")
            prev = "pw"
            continue
        if s and prev == "sudo":
            out.append("{password}")
            prev = "pw"
            continue
        out.append(line)
        prev = "other"
    return "\n".join(out)


def render(cmd: str, server: dict, idx: int) -> str:
    """把命令中的变量替换为指定服务器的实际值。

    当前变量之外的历史变量同样可解析（老模板兼容），无对应值的渲染为空串。
    """
    parts = server["ip"].split(".")
    tags = server.get("tags", [])
    name = server.get("name") or server["ip"]
    import datetime

    today = datetime.date.today().strftime("%Y%m%d")
    mapping = {
        # 当前变量
        "{ip}": server["ip"],
        "{ip_prefix}": ".".join(parts[:3]) + ".",
        "{ip_last}": parts[3],
        "{name}": name,
        "{user}": server.get("user", "root"),
        "{password}": server.get("password", ""),
        "{port}": str(server.get("port", "22")),
        "{date}": today,
        # 历史变量兜底（老模板兼容）
        "{hostname}": name,
        "{tag}": tags[0] if tags else "",
        "{tags}": ",".join(tags),
        "{idx}": str(idx + 1),
        "{idx0}": str(idx),
        "{ip_3rd}": parts[2],
        "{ip_2nd}": parts[1],
        "{ip_1st}": parts[0],
    }
    result = cmd
    for var, val in mapping.items():
        result = result.replace(var, val)
    return result
