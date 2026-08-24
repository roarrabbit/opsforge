#!/usr/bin/env python3
"""
OpsForge Web GUI v1.0
用法：python3 ops_gui.py [--port 18663]
启动后浏览器访问 http://127.0.0.1:18663
   /|,  molo
 (°~ 。7       
  |,~\\
  UU_,)/
"""

import argparse
import csv
import io
import json
import mimetypes
import os
import re
import socket
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from ops import generator, paths, storage, template
from ops.danger import detect
from ops.delay import analyze
from ops.errors import RevisionConflict, ValidationError
from ops.history import HistoryStore
from ops.http_security import ApiError, ApiResponse, SessionGuard, error_response
from ops.importer import preview_assets
from ops.paths import PathConfig
from ops.preflight import preflight
from ops.storage import AssetRepository
from ops.tag_groups import get_tag_group_store
from ops.target_sets import TargetSetStore
from ops.template import TEMPLATE_VARS
from ops.templates import TemplateStore

BASE = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE, "web")


@dataclass(frozen=True)
class LaunchConfig:
    bind_host: str
    display_hosts: list[str]
    allowed_hosts: set[str]
    warnings: list[str]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="运维命令生成器 Web GUI")
    parser.add_argument("--port", type=int, default=18663)
    parser.add_argument("--listen-lan", action="store_true", help="显式允许可信内网访问")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    return parser.parse_args(argv)


def _lan_ipv4_addresses() -> list[str]:
    addresses: set[str] = set()
    try:
        entries = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except socket.gaierror:
        entries = []
    for entry in entries:
        address = entry[4][0]
        if address != "127.0.0.1":
            addresses.add(address)
    return sorted(addresses)


def build_launch_config(
    args: argparse.Namespace, *, lan_hosts: list[str] | None = None
) -> LaunchConfig:
    loopback_hosts = {"127.0.0.1", "localhost"}
    if not args.listen_lan:
        return LaunchConfig(
            bind_host="127.0.0.1",
            display_hosts=["127.0.0.1"],
            allowed_hosts=loopback_hosts,
            warnings=[],
        )
    lan_hosts = lan_hosts if lan_hosts is not None else _lan_ipv4_addresses()
    if not lan_hosts:
        raise RuntimeError("未检测到可用于 LAN 模式的本机 IPv4 地址")
    return LaunchConfig(
        bind_host=lan_hosts[0],
        display_hosts=[lan_hosts[0]],
        allowed_hosts=loopback_hosts | set(lan_hosts),
        warnings=[
            "LAN 模式仅适用于可信内网：同一网络内能访问此地址的人可操作本工具。",
            "公网或不可信网络请使用 SSH 隧道/HTTPS 反向代理，不要直接暴露本服务。",
        ],
    )


class OpsApplication:
    """Pure API router with injected storage and a process-local session."""

    def __init__(
        self,
        repository: AssetRepository,
        config: PathConfig,
        *,
        listen_lan: bool,
        allowed_hosts: set[str] | None = None,
    ) -> None:
        self.repository = repository
        self.paths = config
        self.listen_lan = listen_lan
        self.guard = SessionGuard(allowed_hosts or {"127.0.0.1", "localhost"})
        self.generated_results: dict[str, dict[str, Path]] = {}
        self.history = HistoryStore(config)
        self.target_sets = TargetSetStore(config)
        self.templates = TemplateStore(config)

    def dispatch(self, method: str, path: str, body: dict, query: dict) -> ApiResponse:
        try:
            return self._dispatch(method.upper(), path, body or {}, query or {})
        except Exception as exc:
            return error_response(exc)

    def _dispatch(self, method: str, path: str, body: dict, query: dict) -> ApiResponse:
        route = (method, path)
        if route == ("GET", "/api/bootstrap"):
            snapshot = self.repository.snapshot()
            return ApiResponse(
                200,
                {
                    "schema_version": snapshot["schema_version"],
                    "revision": snapshot["revision"],
                    "assets": snapshot["servers"],
                    "preset_tag_groups": get_tag_group_store(self.paths).list(),
                    "template_vars": TEMPLATE_VARS,
                    "editor_vars": template.editor_vars(),
                    "version": "3.0.0",
                    "listen_mode": "lan" if self.listen_lan else "local",
                },
            )

        if route == ("POST", "/api/assets/preview"):
            mode = _require_string(body, "mode")
            text = _require_string(body, "text")
            options = body.get("options", {})
            if not isinstance(options, dict):
                raise ValidationError("options 必须是对象")
            preview = preview_assets(
                mode=mode,
                text=text,
                snapshot=self.repository.snapshot(),
                options=options,
            )
            return ApiResponse(200, preview)

        if route == ("POST", "/api/assets/commit"):
            revision = _require_integer(body, "revision")
            operations = body.get("operations")
            if not isinstance(operations, list):
                raise ValidationError("operations 必须是数组")
            saved = self.repository.commit(revision, operations)
            counts = {
                "added": sum(
                    op.get("op") == "upsert" and op.get("id") is None for op in operations
                ),
                "updated": sum(
                    op.get("op") == "upsert" and op.get("id") is not None for op in operations
                ),
                "deleted": sum(op.get("op") == "delete" for op in operations),
            }
            return ApiResponse(
                200,
                {
                    "revision": saved["revision"],
                    "assets": saved["servers"],
                    "counts": counts,
                },
            )

        if route == ("POST", "/api/preflight"):
            command = _require_string(body, "command")
            target_ids = body.get("target_ids")
            if not isinstance(target_ids, list) or any(
                not isinstance(asset_id, str) for asset_id in target_ids
            ):
                raise ValidationError("target_ids 必须是字符串数组")
            delay = body.get("delay", {"mode": "auto", "value": None})
            if not isinstance(delay, dict):
                raise ValidationError("delay 必须是对象")
            mode = delay.get("mode", "auto")
            if not isinstance(mode, str):
                raise ValidationError("delay.mode 必须是字符串")
            assets = {
                row["id"]: row for row in self.repository.snapshot(reveal_passwords=True)["servers"]
            }
            missing_ids = [asset_id for asset_id in target_ids if asset_id not in assets]
            selected = [assets[asset_id] for asset_id in target_ids if asset_id in assets]
            result = preflight(command, selected, mode, delay.get("value"))
            if missing_ids:
                result["blocking"].insert(0, {"code": "missing_target", "target_ids": missing_ids})
            return ApiResponse(200, result)

        if route == ("POST", "/api/generate"):
            legacy_request = "ips" in body or "cmd" in body
            command = _require_string(body, "cmd" if legacy_request else "command")
            if not command.strip():
                raise ValidationError("命令不能为空")
            snapshot = self.repository.snapshot(reveal_passwords=True)
            if legacy_request:
                ips = body.get("ips")
                if not isinstance(ips, list) or any(not isinstance(ip, str) for ip in ips):
                    raise ValidationError("ips 必须是字符串数组")
                assets = {row["ip"]: row for row in snapshot["servers"]}
                missing_ips = [ip for ip in ips if ip not in assets]
                if missing_ips:
                    raise ValidationError("所选资产已不存在", [{"ips": missing_ips}])
                selected = [assets[ip] for ip in ips]
                revision = snapshot["revision"]
                legacy_delay = body.get("delay")
                if (
                    isinstance(legacy_delay, int)
                    and not isinstance(legacy_delay, bool)
                    and legacy_delay >= 0
                ):
                    delay = {"mode": "manual", "value": legacy_delay}
                else:
                    delay = {"mode": "auto", "value": None}
            else:
                revision = _require_integer(body, "revision")
                target_ids = body.get("target_ids")
                if not isinstance(target_ids, list) or any(
                    not isinstance(asset_id, str) for asset_id in target_ids
                ):
                    raise ValidationError("target_ids 必须是字符串数组")
                delay = body.get("delay", {"mode": "auto", "value": None})
                if not isinstance(delay, dict) or not isinstance(delay.get("mode", "auto"), str):
                    raise ValidationError("delay 必须是包含 mode 的对象")
                if revision != snapshot["revision"]:
                    raise RevisionConflict(revision, snapshot["revision"])
                assets = {row["id"]: row for row in snapshot["servers"]}
                missing_ids = [asset_id for asset_id in target_ids if asset_id not in assets]
                if missing_ids:
                    raise ValidationError("所选资产已不存在", [{"target_ids": missing_ids}])
                selected = [assets[asset_id] for asset_id in target_ids]
            checked = preflight(command, selected, delay.get("mode", "auto"), delay.get("value"))
            if checked["blocking"]:
                raise ValidationError("生成前检查未通过", checked["blocking"])
            result = generator.generate(
                command,
                selected,
                checked["delay"]["value"],
                self.paths.output,
                revision,
            )
            self.history.append(
                {
                    "raw_cmd": command,
                    "targets": [{"id": asset["id"], "ip": asset["ip"]} for asset in selected],
                    "delay": {
                        "mode": checked["delay"]["mode"],
                        "value": checked["delay"]["value"],
                    },
                    "asset_revision": revision,
                    "result_id": result.id,
                }
            )
            self.generated_results[result.id] = {
                "path": self.paths.output / result.script_name,
                "filename": Path(result.script_name),
            }
            if legacy_request:
                return ApiResponse(
                    200,
                    {
                        "blocks": result.blocks,
                        "list_text": result.list_text,
                        "delay": checked["delay"]["value"],
                        "script_file": result.script_name,
                        "danger_total": result.danger_total,
                        "big_delay": checked["delay"]["value"] >= generator.BIG_DELAY_THRESHOLD,
                    },
                )
            return ApiResponse(
                200,
                {
                    "id": result.id,
                    "blocks": result.blocks,
                    "list_text": result.list_text,
                    "list_name": result.list_name,
                    "script_name": result.script_name,
                    "revision": result.revision,
                    "snapshot_hash": result.snapshot_hash,
                    "danger_total": result.danger_total,
                    "delay": checked["delay"],
                },
            )

        download_match = re.fullmatch(r"/api/download/([A-Za-z0-9_-]+)", path)
        if method == "GET" and download_match:
            result = self.generated_results.get(download_match.group(1))
            if result is None:
                raise ApiError(404, "result_not_found", "生成结果不存在或已过期")
            content = result["path"].read_text(encoding="utf-8")
            return ApiResponse(
                200,
                {
                    "__download__": True,
                    "filename": result["filename"].name,
                    "content": content,
                },
                {"Cache-Control": "no-store"},
            )

        if route == ("GET", "/api/history"):
            return ApiResponse(200, self.history.list(50))

        history_match = re.fullmatch(r"/api/history/([0-9a-fA-F-]+)/restore", path)
        if method == "POST" and history_match:
            try:
                restored = self.history.restore(history_match.group(1), self.repository.snapshot())
            except KeyError as exc:
                raise ApiError(404, "history_not_found", "历史记录不存在") from exc
            return ApiResponse(200, restored)

        if route == ("GET", "/api/target-sets"):
            return ApiResponse(
                200,
                {"target_sets": self.target_sets.list(self.repository.snapshot())},
            )

        if route == ("POST", "/api/target-sets"):
            try:
                target_set = self.target_sets.save(body.get("name"), body.get("target_ids"))
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            return ApiResponse(200, {"target_set": target_set})

        target_set_match = re.fullmatch(r"/api/target-sets/([0-9a-fA-F-]+)", path)
        if method == "DELETE" and target_set_match:
            if not self.target_sets.delete(target_set_match.group(1)):
                raise ApiError(404, "target_set_not_found", "常用清单不存在")
            return ApiResponse(200, {"deleted": True})

        if route == ("GET", "/api/templates"):
            return ApiResponse(200, {"templates": self.templates.list()})

        if route == ("POST", "/api/templates"):
            try:
                created = self.templates.create(body)
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            return ApiResponse(200, {"template": created})

        template_match = re.fullmatch(r"/api/templates/([0-9a-fA-F-]+)", path)
        if method == "PUT" and template_match:
            try:
                updated = self.templates.update(template_match.group(1), body)
            except KeyError as exc:
                raise ApiError(404, "template_not_found", "模板不存在") from exc
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            return ApiResponse(200, {"template": updated})

        if method == "DELETE" and template_match:
            if not self.templates.delete(template_match.group(1)):
                raise ApiError(404, "template_not_found", "模板不存在")
            return ApiResponse(200, {"deleted": True})

        password_match = re.fullmatch(r"/api/assets/([0-9a-fA-F-]+)/password", path)
        if method == "GET" and password_match:
            asset_id = password_match.group(1)
            snapshot = self.repository.snapshot(reveal_passwords=True)
            asset = next((row for row in snapshot["servers"] if row["id"] == asset_id), None)
            if asset is None:
                raise ApiError(404, "asset_not_found", "资产不存在")
            return ApiResponse(
                200,
                {"id": asset_id, "password": asset["password"]},
                {"Cache-Control": "no-store"},
            )

        if route == ("GET", "/api/assets/export"):
            text = _export_assets(self.repository.snapshot()["servers"], include_passwords=False)
            return ApiResponse(200, {"filename": "assets.csv", "text": text, "sensitive": False})

        if route == ("POST", "/api/assets/export-with-credentials"):
            if body.get("confirm") is not True:
                raise ValidationError("含凭据导出需要明确确认")
            text = _export_assets(
                self.repository.snapshot(reveal_passwords=True)["servers"],
                include_passwords=True,
            )
            return ApiResponse(
                200,
                {"filename": "assets-with-credentials.csv", "text": text, "sensitive": True},
                {"Cache-Control": "no-store"},
            )

        status, payload = api_dispatch(method, path, body, query)
        return ApiResponse(status, payload)


def _require_string(body: dict, key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str):
        raise ValidationError(f"{key} 必须是字符串")
    return value


def _require_integer(body: dict, key: str) -> int:
    value = body.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{key} 必须是整数")
    return value


def _export_assets(assets: list[dict], *, include_passwords: bool) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    if include_passwords:
        writer.writerow(["命名", "IP", "账号", "密码", "标签", "端口", "备注"])
    else:
        writer.writerow(["命名", "IP", "账号", "标签", "端口", "备注"])
    for asset in assets:
        prefix = [asset.get("name", ""), asset["ip"], asset.get("user", "root")]
        suffix = [",".join(asset.get("tags", [])), asset.get("port", "22"), asset.get("remark", "")]
        if include_passwords:
            writer.writerow([*prefix, asset.get("password", ""), *suffix])
        else:
            writer.writerow([*prefix, *suffix])
    return output.getvalue()


def _json_body(handler) -> dict:
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


def api_dispatch(method, path, body, query):
    """返回 (status, data)；data 会被 JSON 序列化"""
    # ---------- 服务器 ----------
    if path == "/api/servers" and method == "GET":
        return 200, {
            "servers": storage.load_servers(),
            "all_tags": storage.all_tags(),
            "groups": get_tag_group_store().list(),
        }

    if path == "/api/servers" and method == "POST":
        ip = (body.get("ip") or "").strip()
        if not storage.validate_ip(ip):
            return 400, {"error": "无效 IP 地址"}
        ok, msg = storage.add_server(
            ip,
            name=body.get("name", ""),
            tags=body.get("tags", []),
            port=body.get("port", "22"),
            user=body.get("user", "root"),
            remark=body.get("remark", ""),
        )
        return (200 if ok else 400), ({"ok": True} if ok else {"error": msg})

    m = re.fullmatch(r"/api/servers/([\d.]+)", path)
    if m and method == "PUT":
        ip = m.group(1)
        fields = {
            k: body[k]
            for k in ("name", "tags", "port", "user", "password", "remark", "ip")
            if k in body
        }
        try:
            ok = storage.update_server(ip, **fields)
        except ValidationError as exc:
            return 400, {"error": str(exc)}
        return (200 if ok else 404), ({"ok": True} if ok else {"error": "服务器不存在"})

    if m and method == "DELETE":
        n = storage.remove_servers([m.group(1)])
        return 200, {"ok": True, "removed": n}

    if path == "/api/servers/import" and method == "POST":
        added, skipped = storage.import_text(body.get("text", ""))
        return 200, {"added": added, "skipped": skipped}

    if path == "/api/servers/export" and method == "GET":
        return 200, {"text": storage.export_csv()}

    if path == "/api/servers/clear" and method == "POST":
        storage.clear_servers()
        return 200, {"ok": True}

    # ---------- 标签分组 ----------
    if path == "/api/tag-groups" and method == "GET":
        return 200, {"groups": get_tag_group_store().list()}

    if path == "/api/tag-groups" and method == "PUT":
        groups = body.get("groups", [])
        if not isinstance(groups, list):
            return 400, {"error": "groups 必须是数组"}
        get_tag_group_store().save(groups)
        return 200, {"ok": True, "groups": get_tag_group_store().list()}

    # ---------- 标签管理 ----------
    if path == "/api/tags/rename" and method == "POST":
        n = storage.rename_tag(body.get("old", ""), body.get("new", ""))
        return 200, {"ok": True, "affected": n}

    if path == "/api/tags/remove" and method == "POST":
        n = storage.remove_tag(body.get("tag", ""))
        return 200, {"ok": True, "affected": n}

    if path == "/api/tags/batch-add" and method == "POST":
        n = storage.batch_add_tags(body.get("ips", []), body.get("tags", []))
        return 200, {"ok": True, "affected": n}

    if path == "/api/tags/batch-remove" and method == "POST":
        n = storage.batch_remove_tags(body.get("ips", []), body.get("tags", []))
        return 200, {"ok": True, "affected": n}

    # ---------- 元数据 ----------
    if path == "/api/meta" and method == "GET":
        return 200, {
            "template_vars": TEMPLATE_VARS,
            "editor_vars": template.editor_vars(),
            "version": "2.0.0",
        }

    # ---------- 模板库 ----------
    if path == "/api/templates" and method == "GET":
        return 200, {"templates": storage.load_templates()}

    if path == "/api/templates" and method == "POST":
        tpls = storage.load_templates()
        tpls.append(
            {
                "name": body.get("name", "未命名"),
                "category": body.get("category", "未分类"),
                "content": body.get("content", ""),
            }
        )
        storage.save_templates(tpls)
        return 200, {"ok": True, "index": len(tpls) - 1}

    if path == "/api/templates/convert" and method == "POST":
        content = template.script_to_template(body.get("text", ""))
        return 200, {"ok": True, "content": content}

    m = re.fullmatch(r"/api/templates/(\d+)", path)
    if m and method == "PUT":
        i = int(m.group(1))
        tpls = storage.load_templates()
        if not (0 <= i < len(tpls)):
            return 404, {"error": "模板不存在"}
        for k in ("name", "category", "content"):
            if k in body:
                tpls[i][k] = body[k]
        storage.save_templates(tpls)
        return 200, {"ok": True}

    if m and method == "DELETE":
        i = int(m.group(1))
        tpls = storage.load_templates()
        if not (0 <= i < len(tpls)):
            return 404, {"error": "模板不存在"}
        tpls.pop(i)
        storage.save_templates(tpls)
        return 200, {"ok": True}

    # ---------- 实时分析（延时 + 危险） ----------
    if path == "/api/analyze" and method == "POST":
        cmd = body.get("cmd", "")
        return 200, {"delay": analyze(cmd), "danger": detect(cmd)}

    # ---------- 生成 ----------
    if path == "/api/generate" and method == "POST":
        ips = body.get("ips", [])
        cmd = body.get("cmd", "")
        if not ips:
            return 400, {"error": "未选择服务器"}
        if not cmd.strip():
            return 400, {"error": "命令为空"}
        all_servers = {s["ip"]: s for s in storage.load_servers()}
        selected = [all_servers[ip] for ip in ips if ip in all_servers]
        if not selected:
            return 400, {"error": "所选服务器均不存在"}
        blocks = generator.build_blocks(selected, cmd)
        default_delay = analyze(cmd)["total_suggest"]
        delay = body.get("delay")
        delay = (
            int(delay)
            if isinstance(delay, int) or (isinstance(delay, str) and delay.isdigit())
            else default_delay
        )
        list_text = generator.generate_list(blocks)
        script_path = generator.generate_bash(blocks, cmd, delay)
        generator.record_history(selected, cmd, delay, mode="gui", output_file=script_path)
        danger_total = sum(len(b["danger"]) for b in blocks)
        return 200, {
            "blocks": blocks,
            "list_text": list_text,
            "delay": delay,
            "script_file": os.path.basename(script_path),
            "danger_total": danger_total,
            "big_delay": delay >= generator.BIG_DELAY_THRESHOLD,
        }

    # ---------- 历史 ----------
    if path == "/api/history" and method == "GET":
        return 200, {"history": storage.load_history(50)}

    # ---------- 下载产物 ----------
    m = re.fullmatch(r"/api/download/([\w.-]+)", path)
    if m and method == "GET":
        fname = os.path.basename(m.group(1))  # 防目录穿越
        fpath = os.path.join(paths.OUTPUT_DIR, fname)
        if not os.path.isfile(fpath):
            return 404, {"error": "文件不存在"}
        with open(fpath, encoding="utf-8") as f:
            return 200, {"__download__": True, "filename": fname, "content": f.read()}

    return 404, {"error": "接口不存在"}


def build_handler(application: OpsApplication) -> type[BaseHTTPRequestHandler]:
    """Bind an application instance to a standard-library HTTP handler."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "OpsCmdGen/3.0"

        def log_message(self, fmt, *args):
            pass

        def _send_api_response(self, response: ApiResponse) -> None:
            data = response.payload
            if data.get("__download__") is True:
                payload = data["content"].encode("utf-8")
                content_type = "application/octet-stream"
                extra = {"Content-Disposition": f"attachment; filename={data['filename']}"}
            else:
                payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
                content_type = "application/json; charset=utf-8"
                extra = {}
            self.send_response(response.status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", response.headers.get("Cache-Control", "no-store"))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in {**extra, **response.headers}.items():
                if key.lower() != "cache-control":
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)

        def _send_static(self, request_path: str) -> None:
            relative = (
                "index.html" if request_path in {"/", "/index.html"} else request_path.lstrip("/")
            )
            web_root = Path(WEB_DIR).resolve()
            candidate = (web_root / relative).resolve()
            if candidate != web_root and web_root not in candidate.parents:
                self.send_error(404)
                return
            if not candidate.is_file():
                self.send_error(404)
                return
            payload = candidate.read_bytes()
            content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            if candidate.suffix == ".html":
                content_type = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(payload)

        def _content_length(self) -> int:
            raw = self.headers.get("Content-Length", "0")
            try:
                value = int(raw)
            except ValueError as exc:
                raise ApiError(400, "invalid_content_length", "Content-Length 无效") from exc
            if value < 0:
                raise ApiError(400, "invalid_content_length", "Content-Length 无效")
            return value

        def _read_json(self, length: int) -> dict:
            if length == 0:
                return {}
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ApiError(400, "invalid_json", "请求 JSON 无效") from exc
            if not isinstance(value, dict):
                raise ApiError(400, "json_object_required", "请求 JSON 顶层必须是对象")
            return value

        def _handle(self, method: str) -> None:
            parsed = urlsplit(self.path)
            path = parsed.path
            if not path.startswith("/api/"):
                if method == "GET":
                    self._send_static(path)
                else:
                    self.send_error(404)
                return
            try:
                length = self._content_length()
                application.guard.authorize(method, path, self.headers, length)
                body = self._read_json(length) if method in SessionGuard.WRITE_METHODS else {}
                query = parse_qs(parsed.query, keep_blank_values=True)
                response = application.dispatch(method, path, body, query)
            except Exception as exc:
                response = error_response(exc)
            self._send_api_response(response)

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_PUT(self):
            self._handle("PUT")

        def do_DELETE(self):
            self._handle("DELETE")

    return Handler


def main():
    print("""
   /|,  molo
 (°~ 。7       
  |,~\\
  UU_,)/   
    """)
    args = parse_args()
    launch = build_launch_config(args)

    config = paths.ensure_dirs()
    application = OpsApplication(
        storage.get_asset_repository(config),
        config,
        listen_lan=args.listen_lan,
        allowed_hosts=launch.allowed_hosts,
    )
    server = ThreadingHTTPServer((launch.bind_host, args.port), build_handler(application))
    url = f"http://{launch.display_hosts[0]}:{args.port}/"
    print(f"✓ 运维命令生成器 GUI 已启动: {url}   (Ctrl+C 停止)")
    for warning in launch.warnings:
        print(f"! {warning}")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
