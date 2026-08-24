"""HTTP request authorization and stable API error responses."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .errors import (
    DataCorruptionError,
    DecryptionError,
    KeyProtectionError,
    RevisionConflict,
    ValidationError,
)


class ApiError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        field_errors: list[dict] | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.field_errors = list(field_errors or [])
        super().__init__(message)


@dataclass(frozen=True)
class ApiResponse:
    status: int
    payload: dict
    headers: dict[str, str] = field(default_factory=dict)


class SessionGuard:
    """Enforce same-host requests and safe JSON request boundaries."""

    WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    def __init__(
        self,
        allowed_hosts: set[str],
        max_body_bytes: int = 1_048_576,
    ) -> None:
        self.allowed_hosts = {host.lower() for host in allowed_hosts}
        self.max_body_bytes = max_body_bytes

    def authorize(
        self,
        method: str,
        path: str,
        headers,
        content_length: int,
    ) -> None:
        if not path.startswith("/api/"):
            return
        normalized = {str(key).lower(): str(value) for key, value in headers.items()}
        host_header = normalized.get("host", "")
        host = urlsplit(f"//{host_header}").hostname
        if not host or host.lower() not in self.allowed_hosts:
            raise ApiError(403, "invalid_host", "请求 Host 不受信任")

        origin_header = normalized.get("origin")
        if origin_header:
            origin = urlsplit(origin_header)
            if (
                origin.scheme not in {"http", "https"}
                or not origin.hostname
                or origin.hostname.lower() not in self.allowed_hosts
                or origin.netloc.lower() != host_header.lower()
            ):
                raise ApiError(403, "invalid_origin", "请求来源不受信任")

        if content_length < 0 or content_length > self.max_body_bytes:
            raise ApiError(413, "body_too_large", "请求内容超过大小限制")

        if method.upper() in self.WRITE_METHODS:
            content_type = normalized.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise ApiError(415, "json_required", "写入接口只接受 application/json")


def _payload(code: str, message: str, field_errors: list[dict] | None = None) -> dict:
    return {
        "error": {
            "code": code,
            "message": message,
            "field_errors": list(field_errors or []),
        }
    }


def error_response(error: Exception) -> ApiResponse:
    """Map expected domain errors without exposing local paths or tracebacks."""
    if isinstance(error, ApiError):
        return ApiResponse(
            error.status,
            _payload(error.code, str(error), error.field_errors),
        )
    if isinstance(error, RevisionConflict):
        return ApiResponse(409, _payload("revision_conflict", str(error)))
    if isinstance(error, ValidationError):
        return ApiResponse(400, _payload("validation_error", str(error), error.field_errors))
    if isinstance(error, DataCorruptionError):
        return ApiResponse(
            503,
            _payload("data_unavailable", "资产数据不可用，请在本机检查数据文件或恢复备份"),
        )
    if isinstance(error, (KeyProtectionError, DecryptionError)):
        return ApiResponse(
            503,
            _payload("credentials_unavailable", "密码密钥不可用，已停止读取和写入凭据"),
        )
    return ApiResponse(
        500,
        _payload("internal_error", "操作失败，请查看本地诊断日志"),
    )
