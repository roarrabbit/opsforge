"""Versioned local password encryption using Fernet."""
from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .errors import DecryptionError, KeyProtectionError


class PasswordCipher:
    """Encrypt and decrypt password fields with a local, private key file."""

    PREFIX = "enc:v1:"

    def __init__(self, key_path: Path) -> None:
        self.key_path = Path(key_path)

    @classmethod
    def is_encrypted(cls, value: str) -> bool:
        return isinstance(value, str) and value.startswith(cls.PREFIX)

    def encrypt(self, value: str) -> str:
        if value == "":
            return ""
        if not isinstance(value, str):
            raise TypeError("password must be a string")
        token = self._fernet(create=True).encrypt(value.encode("utf-8")).decode("ascii")
        return self.PREFIX + token

    def decrypt(self, value: str) -> str:
        if value == "":
            return ""
        if not self.is_encrypted(value):
            raise DecryptionError("密码字段未加密，已拒绝直接读取")
        try:
            clear = self._fernet(create=False).decrypt(
                value.removeprefix(self.PREFIX).encode("ascii")
            )
        except (InvalidToken, ValueError, UnicodeEncodeError) as exc:
            raise DecryptionError("密码密文校验失败，可能已损坏或密钥不匹配") from exc
        try:
            return clear.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecryptionError("密码密文不是有效 UTF-8 数据") from exc

    def _fernet(self, *, create: bool) -> Fernet:
        key = self._load_or_create_key(create=create)
        try:
            return Fernet(key)
        except (TypeError, ValueError) as exc:
            raise KeyProtectionError("本地密钥格式无效") from exc

    def _load_or_create_key(self, *, create: bool) -> bytes:
        if self.key_path.exists():
            self._validate_permissions()
            try:
                return self.key_path.read_bytes().strip()
            except OSError as exc:
                raise KeyProtectionError("无法读取本地密码密钥") from exc
        if not create:
            raise KeyProtectionError("本地密码密钥缺失，已拒绝生成替代密钥")

        self._prepare_parent()
        key = Fernet.generate_key()
        try:
            descriptor = os.open(
                self.key_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            return self._load_or_create_key(create=False)
        except OSError as exc:
            raise KeyProtectionError("无法创建本地密码密钥") from exc

        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                self.key_path.unlink()
            except OSError:
                pass
            raise
        self._validate_permissions()
        return key

    def _prepare_parent(self) -> None:
        try:
            self.key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.name == "posix":
                self.key_path.parent.chmod(0o700)
        except OSError as exc:
            raise KeyProtectionError("无法创建受保护的本地数据目录") from exc

    def _validate_permissions(self) -> None:
        if os.name != "posix":
            return
        try:
            key_mode = stat.S_IMODE(self.key_path.stat().st_mode)
            parent_mode = stat.S_IMODE(self.key_path.parent.stat().st_mode)
        except OSError as exc:
            raise KeyProtectionError("无法验证本地密钥权限") from exc
        if key_mode & 0o077:
            raise KeyProtectionError("本地密钥权限过宽，必须限制为 0600")
        if parent_mode & 0o077:
            raise KeyProtectionError("本地数据目录权限过宽，必须限制为 0700")
