"""Authoritative CSV/TSV parsing and asset-difference previews."""
from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterable

from .storage import validate_ip

GUI_COLUMNS = ("name", "ip", "user", "password", "tags", "port", "remark")

HEADER_ALIASES = {
    "name": {"命名", "名称", "name", "hostname"},
    "ip": {"ip", "ip地址", "地址"},
    "user": {"账号", "用户", "user", "username"},
    "password": {"密码", "password", "passwd", "pwd"},
    "tags": {"标签", "tags", "tag"},
    "port": {"端口", "port"},
    "remark": {"备注", "remark", "note", "说明"},
}


def _normalize_header(value: str) -> str:
    return re.sub(r"[\s_-]+", "", value).lower()


_NORMALIZED_ALIASES = {
    field: {_normalize_header(alias) for alias in aliases}
    for field, aliases in HEADER_ALIASES.items()
}


def _password_operation(value: str, empty_policy: str) -> dict:
    if value != "":
        return {"action": "set", "value": value}
    if empty_policy == "clear":
        return {"action": "clear"}
    if empty_policy != "keep":
        raise ValueError("empty password policy must be keep or clear")
    return {"action": "keep"}


def preview_password_column(
    text: str,
    visible_ids: list[str],
    start: int,
    assets: list[dict],
    empty_policy: str = "keep",
) -> dict:
    """Map one pasted password column to visible asset IDs without trimming values."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    values = normalized.split("\n")
    if values and values[-1] == "":
        values.pop()
    if start < 0:
        raise ValueError("start must be non-negative")

    targets = visible_ids[start:]
    mapped_count = min(len(values), len(targets))
    asset_by_id = {asset["id"]: asset for asset in assets}
    operations = []
    rows = []
    errors = []
    counts = {"added": 0, "updated": 0, "unchanged": 0, "conflicts": 0, "invalid": 0}

    for offset in range(mapped_count):
        asset_id = targets[offset]
        asset = asset_by_id.get(asset_id)
        if asset is None:
            counts["invalid"] += 1
            error = {"row": offset + 1, "field": "id", "message": "资产不存在"}
            errors.append(error)
            rows.append({"row": offset + 1, "id": asset_id, "status": "invalid"})
            continue
        password = _password_operation(values[offset], empty_policy)
        operations.append({"op": "upsert", "id": asset_id, "values": {}, "password": password})
        changed = password["action"] == "set" or (
            password["action"] == "clear" and asset.get("password_set", False)
        )
        status = "updated" if changed else "unchanged"
        counts[status] += 1
        rows.append({"row": offset + 1, "id": asset_id, "ip": asset["ip"], "status": status})

    mapped_assets = [
        asset_by_id[asset_id]
        for asset_id in targets[:mapped_count]
        if asset_id in asset_by_id
    ]
    return {
        "operations": operations,
        "counts": counts,
        "rows": rows,
        "errors": errors,
        "first_ip": mapped_assets[0]["ip"] if mapped_assets else None,
        "last_ip": mapped_assets[-1]["ip"] if mapped_assets else None,
        "overflow": max(0, len(values) - len(targets)),
    }


def _read_matrix(text: str, source: str) -> list[list[str]]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if source == "clipboard":
        delimiter = "\t"
    elif source == "csv":
        delimiter = ","
    else:
        raise ValueError("source must be clipboard or csv")
    rows = list(csv.reader(io.StringIO(normalized), delimiter=delimiter))
    while rows and not any(rows[-1]):
        rows.pop()
    return rows


def _header_mapping(row: list[str]) -> dict[str, int] | None:
    mapping: dict[str, int] = {}
    for index, cell in enumerate(row):
        normalized = _normalize_header(cell)
        for field, aliases in _NORMALIZED_ALIASES.items():
            if normalized in aliases:
                if field in mapping:
                    return None
                mapping[field] = index
                break
    return mapping if "ip" in mapping else {}


def _cell(row: list[str], mapping: dict[str, int], field: str) -> tuple[bool, str]:
    index = mapping.get(field)
    if index is None or index >= len(row):
        return False, ""
    return True, row[index]


def _tags(value: str) -> list[str]:
    return [part.strip() for part in re.split(r"[,，]", value) if part.strip()]


def _values_from_row(row: list[str], mapping: dict[str, int], existing: dict | None) -> dict:
    values = {}
    for field in ("name", "ip", "user", "tags", "port", "remark"):
        present, raw = _cell(row, mapping, field)
        if not present:
            continue
        if field == "tags":
            values[field] = _tags(raw)
        elif field == "port":
            stripped = raw.strip()
            if stripped:
                values[field] = stripped
        else:
            values[field] = raw.strip()
    if existing is None:
        values.setdefault("name", "")
        values.setdefault("tags", [])
        values.setdefault("port", "22")
        values.setdefault("user", "root")
        values.setdefault("remark", "")
    return values


def _changed(existing: dict, values: dict, password: dict) -> bool:
    if password["action"] == "set":
        return True
    if password["action"] == "clear" and existing.get("password_set", False):
        return True
    return any(existing.get(field) != value for field, value in values.items())


def _preview_result(rows: list[dict], operations: list[dict], errors: list[dict]) -> dict:
    counts = {"added": 0, "updated": 0, "unchanged": 0, "conflicts": 0, "invalid": 0}
    for row in rows:
        counts[row["status"] + ("s" if row["status"] == "conflict" else "")] += 1
    valid_ips = [
        row["ip"]
        for row in rows
        if row.get("ip") and row["status"] not in {"invalid", "conflict"}
    ]
    return {
        "operations": operations,
        "counts": counts,
        "rows": rows,
        "errors": errors,
        "first_ip": valid_ips[0] if valid_ips else None,
        "last_ip": valid_ips[-1] if valid_ips else None,
        "overflow": 0,
    }


def preview_asset_table(
    text: str,
    assets: list[dict],
    source: str = "clipboard",
    empty_password_policy: str = "keep",
) -> dict:
    """Parse a full table and produce upsert operations plus a user-facing diff."""
    matrix = _read_matrix(text, source)
    if not matrix:
        return _preview_result([], [], [])

    detected = _header_mapping(matrix[0])
    if detected is None:
        row = {"row": 1, "status": "conflict", "message": "表头字段重复"}
        error = {"row": 1, "field": "header", "message": "表头字段重复"}
        return _preview_result([row], [], [error])
    if detected:
        mapping = detected
        data_rows: Iterable[tuple[int, list[str]]] = enumerate(matrix[1:], 2)
    else:
        mapping = {field: index for index, field in enumerate(GUI_COLUMNS)}
        data_rows = enumerate(matrix, 1)

    existing_by_ip = {asset["ip"]: asset for asset in assets}
    seen_ips: set[str] = set()
    rows = []
    operations = []
    errors = []

    for row_number, source_row in data_rows:
        if not any(source_row):
            continue
        _, raw_ip = _cell(source_row, mapping, "ip")
        ip = raw_ip.strip()
        if not validate_ip(ip):
            message = "IP 地址无效"
            rows.append({"row": row_number, "ip": ip, "status": "invalid", "message": message})
            errors.append({"row": row_number, "field": "ip", "message": message})
            continue
        if ip in seen_ips:
            message = "粘贴内容中 IP 重复"
            rows.append({"row": row_number, "ip": ip, "status": "conflict", "message": message})
            errors.append({"row": row_number, "field": "ip", "message": message})
            continue
        seen_ips.add(ip)

        existing = existing_by_ip.get(ip)
        values = _values_from_row(source_row, mapping, existing)
        values["ip"] = ip
        password_present, password_value = _cell(source_row, mapping, "password")
        password = (
            _password_operation(password_value, empty_password_policy)
            if password_present
            else {"action": "keep"}
        )

        if existing is None:
            status = "added"
            operation = {"op": "upsert", "id": None, "values": values, "password": password}
            operations.append(operation)
        elif _changed(existing, values, password):
            status = "updated"
            operation = {
                "op": "upsert",
                "id": existing["id"],
                "values": values,
                "password": password,
            }
            operations.append(operation)
        else:
            status = "unchanged"
        rows.append({
            "row": row_number,
            "ip": ip,
            "id": existing.get("id") if existing else None,
            "status": status,
        })

    return _preview_result(rows, operations, errors)


def preview_assets(*, mode: str, text: str, snapshot: dict, options: dict | None = None) -> dict:
    """Dispatch an API preview request to the authoritative parser."""
    options = options or {}
    assets = snapshot["servers"]
    if mode == "password_column":
        return preview_password_column(
            text,
            options.get("visible_ids", []),
            options.get("start", 0),
            assets,
            options.get("empty_password_policy", "keep"),
        )
    if mode in {"table", "csv"}:
        return preview_asset_table(
            text,
            assets,
            source="csv" if mode == "csv" else "clipboard",
            empty_password_policy=options.get("empty_password_policy", "keep"),
        )
    raise ValueError("unsupported preview mode")
