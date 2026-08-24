"""Domain errors shared by storage, API, and user interfaces."""
from __future__ import annotations


class OpsError(Exception):
    """Base class for expected application errors."""


class DataCorruptionError(OpsError):
    """Persistent data exists but cannot be safely parsed or validated."""


class KeyProtectionError(OpsError):
    """The local encryption key is missing or insufficiently protected."""


class DecryptionError(OpsError):
    """A password value cannot be authenticated and decrypted."""


class RevisionConflict(OpsError):
    """A caller attempted to update an asset snapshot that is no longer current."""

    def __init__(self, expected: int, current: int) -> None:
        self.expected = expected
        self.current = current
        super().__init__(f"资产版本已变化（提交 {expected}，当前 {current}）")


class ValidationError(OpsError):
    """User supplied data failed structured validation."""

    def __init__(self, message: str, field_errors: list[dict] | None = None) -> None:
        self.field_errors = list(field_errors or [])
        super().__init__(message)
