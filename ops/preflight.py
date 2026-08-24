"""Non-mutating command checks shared by the API and future GUI clients."""

from __future__ import annotations

import re
from typing import Any

from .danger import detect
from .delay import analyze
from .errors import ValidationError
from .template import TEMPLATE_VARS

_VARIABLE_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_REQUIRED_ASSET_FIELDS = {"ip", "port", "user", "password"}


def resolve_delay(command: str, mode: str, value: Any) -> dict:
    """Return a validated explicit delay choice plus the rule-based suggestion."""
    analysis = analyze(command)
    if mode == "auto":
        selected = analysis["total_suggest"]
    elif mode == "manual":
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValidationError("手动延时必须是非负整数")
        selected = value
    else:
        raise ValidationError("延时模式必须为 auto 或 manual")
    return {
        "mode": mode,
        "value": selected,
        "min": analysis["total_min"],
        "suggest": analysis["total_suggest"],
        "details": analysis["details"],
    }


def preflight(command: str, targets: list[dict], delay_mode: str, delay_value: Any) -> dict:
    """Check a command without producing output or exposing any password values."""
    if not isinstance(command, str):
        raise ValidationError("命令必须是字符串")
    if not isinstance(targets, list):
        raise ValidationError("目标必须是数组")

    known_variables = {key[1:-1] for key in TEMPLATE_VARS}
    used_variables = _VARIABLE_RE.findall(command)
    unknown = sorted(set(used_variables) - known_variables)
    blocking: list[dict] = []
    if not targets:
        blocking.append({"code": "empty_targets"})
    if unknown:
        blocking.append({"code": "unknown_variable", "variables": unknown})

    for field in sorted(set(used_variables) & _REQUIRED_ASSET_FIELDS):
        missing_ids = [str(target.get("id", "")) for target in targets if not target.get(field)]
        if missing_ids:
            if field == "password":
                blocking.append({"code": "missing_password", "target_ids": missing_ids})
            else:
                blocking.append(
                    {"code": "missing_field", "field": field, "target_ids": missing_ids}
                )

    return {
        "blocking": blocking,
        "warnings": [],
        "danger": detect(command),
        "delay": resolve_delay(command, delay_mode, delay_value),
        "target_count": len(targets),
    }
