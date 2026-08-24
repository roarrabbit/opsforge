# OpsForge

本地优先的多服务器运维命令生成器：**选机器 → 写命令 → 看延时 → 生成**，把产物复制到任意下发平台执行。

OpsForge 不连接服务器、不执行命令，只负责把一份带变量的命令模板逐台渲染成每台机器自己的命令清单或批量脚本。

## 特性

- **一屏式 Web GUI**：选服务器、写命令、看分析、拿结果一屏完成
- **灵活选机器**：标签分组（属性单选 / 标签多选）、IP 网段、命名搜索，支持拖拽框选
- **变量插值**：`{ip}` `{name}` `{user}` 等逐台替换，常用变量一键插入
- **延时智能分析**：识别耗时命令自动计算下发间隔，规则可自定义
- **危险命令检测**：rm -rf、reboot 等红底标注 + toast 提醒
- **模板库 & 生成历史**：常用命令存为模板，每次生成留档可追溯
- **密码加密存储**：Fernet 加密落盘，密钥与本机数据权限隔离（0600/0700）

## 快速开始

要求 Python **3.10+**，唯一第三方依赖 [cryptography](https://cryptography.io/)。

```bash
pip install .          # 提供 opsforge 命令
opsforge               # 自动打开 http://127.0.0.1:18663

# 或不安装直接跑
pip install cryptography && python3 ops_gui.py
```

首次启动自带 5 台示例服务器和常用模板，可直接体验完整流程；正式使用前在「服务器管理」中替换即可。

## 使用要点

- **录入**：管理表格底部空行直接填 IP 新建；支持从 Excel 复制区域粘贴、拖拽框选批量编辑
- **标签体系**：「属性」每台只能选一个，「标签」可多选；左侧 ⚙ 分组管理 可自由增删改分组
- **产物**：`~/.ops_cmd_generator/output/` 下生成清单 `.txt` 与批量脚本 `.sh`
- **导入导出**：CSV 格式（带表头），导出的文件可直接回导

## 数据与安全

数据全部位于本机 `~/.ops_cmd_generator/`：

| 文件 | 说明 |
|---|---|
| `servers.json` | 台账（密码字段已加密） |
| `.secret.key` | 加密密钥，丢失则已存密码无法恢复 |
| `groups.json` / `delay_rules.json` | 分组与延时规则，可直接编辑 |
| `history.jsonl` / `output/` | 生成历史与产物 |

安全边界：GUI 默认仅监听 `127.0.0.1` 并校验 Host；`--listen-lan` 仅限可信内网，公网请走 SSH 隧道或反向代理。请勿分享 `servers.json`、`.secret.key` 与 `output/` 产物。

## 开发

```bash
pip install -e ".[dev]"
ruff check .
```

## License

本项目基于 [AGPL-3.0](LICENSE) 开源。
