"""Named failures that cross the RangeSpec CLI and library boundaries."""

from __future__ import annotations

from typing import Any


class RangeSpecError(Exception):
    """Describe one expected, user-actionable RangeSpec failure.

    Args:
        code: Stable machine-readable identifier.
        message: Plain-English explanation and corrective direction.
        path: JSON Pointer or filesystem path related to the failure.
        details: Optional structured context safe to print.

    Side effects:
        None. Rendering and exit-code selection belong to the CLI boundary.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.path = path
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation of this failure."""

        result: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "path": self.path,
        }
        if self.details:
            result["details"] = self.details
        return result


class InputError(RangeSpecError):
    """Indicate that an input cannot be read or safely interpreted."""


class OutputError(RangeSpecError):
    """Indicate that a requested output cannot be written or verified."""


class ProviderError(RangeSpecError):
    """Indicate that an advisory provider cannot return a trusted result."""
