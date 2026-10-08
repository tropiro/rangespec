"""Advisory review types and deterministic provider-independent validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, cast

from jsonschema import Draft202012Validator

from rangespec.types import JSONObject

ADVISORY_SCHEMA: JSONObject = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "issues", "assumptions"],
    "properties": {
        "summary": {"type": "string", "minLength": 1, "maxLength": 1000},
        "issues": {
            "type": "array",
            "maxItems": 50,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["severity", "code", "path", "message", "recommendation"],
                "properties": {
                    "severity": {"enum": ["info", "warning", "critical"]},
                    "code": {
                        "type": "string",
                        "pattern": "^[A-Z][A-Z0-9_]{2,80}$",
                    },
                    "path": {"type": "string", "maxLength": 500},
                    "message": {"type": "string", "minLength": 1, "maxLength": 1000},
                    "recommendation": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 1000,
                    },
                },
            },
        },
        "assumptions": {
            "type": "array",
            "maxItems": 50,
            "items": {"type": "string", "minLength": 1, "maxLength": 1000},
        },
    },
}


@dataclass(frozen=True)
class AdvisoryIssue:
    """One non-authoritative completeness observation."""

    severity: str
    code: str
    path: str
    message: str
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-safe issue."""

        return cast(dict[str, str], asdict(self))


@dataclass(frozen=True)
class AdvisoryReport:
    """A provider review that cannot alter manifest validity or approval."""

    provider: str
    model: str | None
    source_sha256: str
    summary: str
    issues: tuple[AdvisoryIssue, ...]
    assumptions: tuple[str, ...]
    generated_at: str
    request_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe report with explicit advisory status."""

        return {
            "report_version": "0.1",
            "authority": "advisory-only",
            "provider": self.provider,
            "model": self.model,
            "source_sha256": self.source_sha256,
            "summary": self.summary,
            "issues": [issue.to_dict() for issue in self.issues],
            "assumptions": list(self.assumptions),
            "generated_at": self.generated_at,
            "request_id": self.request_id,
        }


def now_utc_text() -> str:
    """Return a second-precision UTC timestamp for report provenance."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_advisory_payload(payload: JSONObject) -> None:
    """Raise ``ValueError`` when provider data violates the advisory contract."""

    errors = sorted(
        Draft202012Validator(ADVISORY_SCHEMA).iter_errors(payload),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        path = "/" + "/".join(str(part) for part in first.absolute_path)
        raise ValueError(f"Advisory payload invalid at {path or '/'}: {first.message}")


def report_from_payload(
    payload: JSONObject,
    *,
    provider: str,
    model: str | None,
    source_sha256: str,
    request_id: str | None = None,
) -> AdvisoryReport:
    """Validate provider data and create an immutable advisory report."""

    validate_advisory_payload(payload)
    raw_issues = cast(list[dict[str, str]], payload["issues"])
    return AdvisoryReport(
        provider=provider,
        model=model,
        source_sha256=source_sha256,
        summary=cast(str, payload["summary"]),
        issues=tuple(AdvisoryIssue(**issue) for issue in raw_issues),
        assumptions=tuple(cast(list[str], payload["assumptions"])),
        generated_at=now_utc_text(),
        request_id=request_id,
    )
