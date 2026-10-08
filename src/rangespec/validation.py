"""Schema and cross-field validation for RangeSpec manifests."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from rangespec.schema import load_schema
from rangespec.types import JSONObject, JSONValue


@dataclass(frozen=True, order=True)
class Issue:
    """One deterministic validation result.

    Attributes:
        code: Stable machine-readable failure name.
        path: RFC 6901 JSON Pointer into the manifest.
        message: Plain-English explanation.
        severity: ``error`` prevents readiness; ``warning`` is advisory.
    """

    code: str
    path: str
    message: str
    severity: str = "error"

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-safe representation with stable keys."""

        return cast(dict[str, str], asdict(self))


@dataclass(frozen=True)
class ValidationReport:
    """Aggregate validation outcome for one manifest."""

    valid: bool
    execution_ready: bool
    issues: tuple[Issue, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe report suitable for CLI output."""

        return {
            "valid": self.valid,
            "execution_ready": self.execution_ready,
            "issues": [issue.to_dict() for issue in self.issues],
        }


def _pointer(parts: list[str | int]) -> str:
    """Convert path components to an RFC 6901 JSON Pointer."""

    if not parts:
        return ""
    encoded = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(encoded)


def _schema_issue(error: ValidationError) -> Issue:
    """Translate a jsonschema failure into a stable RangeSpec issue."""

    codes = {
        "additionalProperties": "UNDECLARED_FIELD",
        "const": "FIXED_VALUE_MISMATCH",
        "enum": "VALUE_NOT_ALLOWED",
        "format": "VALUE_FORMAT_INVALID",
        "maxItems": "TOO_MANY_ITEMS",
        "maxLength": "VALUE_TOO_LONG",
        "maximum": "VALUE_TOO_LARGE",
        "minItems": "TOO_FEW_ITEMS",
        "minLength": "VALUE_TOO_SHORT",
        "minimum": "VALUE_TOO_SMALL",
        "pattern": "VALUE_PATTERN_INVALID",
        "required": "REQUIRED_FIELD_MISSING",
        "type": "VALUE_TYPE_INVALID",
        "uniqueItems": "DUPLICATE_ITEMS",
    }
    validator_name = error.validator if isinstance(error.validator, str) else ""
    return Issue(
        code=codes.get(validator_name, "SCHEMA_INVALID"),
        path=_pointer(list(error.absolute_path)),
        message=error.message,
    )


def _parse_datetime(value: str) -> datetime:
    """Parse an ISO 8601 timestamp and normalize it to UTC."""

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a UTC offset.")
    return parsed.astimezone(timezone.utc)


def _parse_manifest_datetime(value: str, path: str, issues: list[Issue]) -> datetime | None:
    """Parse a manifest timestamp and append a stable format issue on failure."""

    try:
        return _parse_datetime(value)
    except ValueError:
        issues.append(
            Issue(
                "VALUE_FORMAT_INVALID",
                path,
                "Timestamp must be a real ISO 8601 date-time with a UTC offset.",
            )
        )
        return None


def _find_duplicates(values: list[str]) -> set[str]:
    """Return strings that occur more than once."""

    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return duplicates


def _semantic_issues(
    manifest: JSONObject,
    *,
    require_execution_ready: bool,
    at: datetime,
) -> list[Issue]:
    """Check relationships and readiness rules JSON Schema cannot express."""

    issues: list[Issue] = []
    validity = cast(dict[str, str], manifest["validity"])
    not_before = _parse_manifest_datetime(validity["not_before"], "/validity/not_before", issues)
    not_after = _parse_manifest_datetime(validity["not_after"], "/validity/not_after", issues)
    if not_before is not None and not_after is not None and not_before >= not_after:
        issues.append(
            Issue(
                "TIME_WINDOW_INVALID",
                "/validity",
                "not_before must be earlier than not_after.",
            )
        )

    targets = cast(list[dict[str, Any]], manifest["targets"])
    target_ids = [cast(str, target["target_id"]) for target in targets]
    for duplicate in sorted(_find_duplicates(target_ids)):
        issues.append(
            Issue(
                "TARGET_ID_DUPLICATE",
                "/targets",
                f"Target ID {duplicate!r} appears more than once.",
            )
        )
    target_by_id = {cast(str, target["target_id"]): target for target in targets}

    for target_index, target in enumerate(targets):
        seen_ports: set[tuple[str, int]] = set()
        for port_index, port in enumerate(cast(list[dict[str, Any]], target["ports"])):
            port_key = (cast(str, port["transport"]), cast(int, port["port"]))
            if port_key in seen_ports:
                issues.append(
                    Issue(
                        "TARGET_PORT_DUPLICATE",
                        f"/targets/{target_index}/ports/{port_index}",
                        f"Port {port_key[0]}/{port_key[1]} is declared more than once.",
                    )
                )
            seen_ports.add(port_key)

        for address_index, address in enumerate(cast(list[str], target["addresses"])):
            try:
                network = ipaddress.ip_network(address, strict=False)
            except ValueError:
                issues.append(
                    Issue(
                        "TARGET_ADDRESS_INVALID",
                        f"/targets/{target_index}/addresses/{address_index}",
                        f"Address {address!r} is not an IP address or network.",
                    )
                )
                continue
            if network.is_multicast or network.is_unspecified:
                issues.append(
                    Issue(
                        "TARGET_ADDRESS_UNSAFE",
                        f"/targets/{target_index}/addresses/{address_index}",
                        "Multicast and unspecified target networks are not allowed.",
                    )
                )
            if require_execution_ready and network.is_global:
                issues.append(
                    Issue(
                        "PUBLIC_TARGET_FORBIDDEN",
                        f"/targets/{target_index}/addresses/{address_index}",
                        "Execution-ready manifests may not target globally routable networks.",
                    )
                )

    actions = cast(list[dict[str, Any]], manifest["allowed_actions"])
    action_ids = [cast(str, action["action_id"]) for action in actions]
    for duplicate in sorted(_find_duplicates(action_ids)):
        issues.append(
            Issue(
                "ACTION_ID_DUPLICATE",
                "/allowed_actions",
                f"Action ID {duplicate!r} appears more than once.",
            )
        )
    for action_index, action in enumerate(actions):
        target_id = cast(str, action["target_id"])
        action_target = target_by_id.get(target_id)
        if action_target is None:
            issues.append(
                Issue(
                    "ACTION_TARGET_UNKNOWN",
                    f"/allowed_actions/{action_index}/target_id",
                    f"Action references unknown target {target_id!r}.",
                )
            )
            continue
        protocol = cast(str, action["protocol"])
        target_protocols = cast(list[str], action_target["protocols"])
        if protocol not in target_protocols:
            issues.append(
                Issue(
                    "ACTION_PROTOCOL_UNDECLARED",
                    f"/allowed_actions/{action_index}/protocol",
                    f"Protocol {protocol!r} is not declared by target {target_id!r}.",
                )
            )

    approvals = cast(list[dict[str, Any]], manifest["approvals"])
    approval_times = {
        index: _parse_manifest_datetime(
            cast(str, approval["approved_at"]),
            f"/approvals/{index}/approved_at",
            issues,
        )
        for index, approval in enumerate(approvals)
    }
    approval_ids = [cast(str, approval["approval_id"]) for approval in approvals]
    for duplicate in sorted(_find_duplicates(approval_ids)):
        issues.append(
            Issue(
                "APPROVAL_ID_DUPLICATE",
                "/approvals",
                f"Approval ID {duplicate!r} appears more than once.",
            )
        )

    recovery = cast(dict[str, Any], manifest["recovery"])
    recovered_at = _parse_manifest_datetime(
        cast(str, recovery["last_verified_at"]),
        "/recovery/last_verified_at",
        issues,
    )

    execution = cast(dict[str, Any], manifest["execution"])
    if not_before is not None and not_after is not None:
        available_seconds = max(0, int((not_after - not_before).total_seconds()))
    else:
        available_seconds = 0
    if (
        not_before is not None
        and not_after is not None
        and cast(int, execution["max_duration_seconds"]) > available_seconds
    ):
        issues.append(
            Issue(
                "DURATION_EXCEEDS_WINDOW",
                "/execution/max_duration_seconds",
                "Maximum execution duration exceeds the authorization window.",
            )
        )

    if require_execution_ready:
        if manifest["status"] != "approved":
            issues.append(
                Issue(
                    "APPROVAL_MISSING",
                    "/status",
                    "Execution-ready validation requires status 'approved'.",
                )
            )
        inactive_approvals = [
            (index, approval)
            for index, approval in enumerate(approvals)
            if approval["decision"] != "approved"
        ]
        for approval_index, approval in inactive_approvals:
            issues.append(
                Issue(
                    "APPROVAL_NOT_ACTIVE",
                    f"/approvals/{approval_index}/decision",
                    f"Approval decision {approval['decision']!r} prevents execution readiness.",
                )
            )
        active_approvals = [
            (index, approval)
            for index, approval in enumerate(approvals)
            if approval["decision"] == "approved"
        ]
        if not active_approvals:
            issues.append(
                Issue(
                    "APPROVAL_MISSING",
                    "/approvals",
                    "At least one affirmative approval is required for execution.",
                )
            )
        for approval_index, _approval in active_approvals:
            approved_at = approval_times[approval_index]
            if approved_at is not None and approved_at > at:
                issues.append(
                    Issue(
                        "APPROVAL_NOT_YET_EFFECTIVE",
                        f"/approvals/{approval_index}/approved_at",
                        "Approval timestamp is later than the evaluation time.",
                    )
                )
        if not_before is not None and at < not_before:
            issues.append(
                Issue(
                    "SCOPE_NOT_YET_ACTIVE",
                    "/validity/not_before",
                    "Authorization window has not started.",
                )
            )
        if not_after is not None and at > not_after:
            issues.append(
                Issue(
                    "SCOPE_EXPIRED",
                    "/validity/not_after",
                    "Authorization window has expired.",
                )
            )
        if recovered_at is not None and recovered_at > at:
            issues.append(
                Issue(
                    "RECOVERY_VERIFICATION_IN_FUTURE",
                    "/recovery/last_verified_at",
                    "Recovery verification timestamp is later than the evaluation time.",
                )
            )
        capture = cast(dict[str, Any], manifest["evidence"])["capture"]
        required_capture = {"approvals", "commands", "device-logs"}
        missing_capture = sorted(required_capture - set(cast(list[str], capture)))
        if missing_capture:
            issues.append(
                Issue(
                    "EVIDENCE_CAPTURE_INCOMPLETE",
                    "/evidence/capture",
                    "Execution-ready manifests must capture: " + ", ".join(missing_capture) + ".",
                )
            )

    return issues


def validate_manifest(
    manifest: JSONObject,
    *,
    require_execution_ready: bool = False,
    at: datetime | None = None,
) -> ValidationReport:
    """Validate a manifest against the schema and cross-field rules.

    Args:
        manifest: Parsed JSON object.
        require_execution_ready: Apply time, approval, evidence, and public
            target gates needed before a separate runner may consider execution.
        at: Evaluation time; defaults to the current UTC time.

    Returns:
        A deterministic report sorted by path and code.

    Side effects:
        None. The input object is never mutated.
    """

    validator = Draft202012Validator(load_schema())
    schema_issues = [_schema_issue(error) for error in validator.iter_errors(manifest)]
    if schema_issues:
        ordered = tuple(sorted(schema_issues, key=lambda issue: (issue.path, issue.code)))
        return ValidationReport(valid=False, execution_ready=False, issues=ordered)

    evaluation_time = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    semantic_issues = _semantic_issues(
        manifest,
        require_execution_ready=require_execution_ready,
        at=evaluation_time,
    )
    ordered = tuple(sorted(semantic_issues, key=lambda issue: (issue.path, issue.code)))
    valid = not any(issue.severity == "error" for issue in ordered)
    return ValidationReport(
        valid=valid,
        execution_ready=valid and require_execution_ready,
        issues=ordered,
    )


def parse_evaluation_time(value: str) -> datetime:
    """Parse a CLI evaluation time or raise ``ValueError`` with one cause."""

    return _parse_datetime(value)


def json_pointer_get(document: JSONValue, pointer: str) -> JSONValue:
    """Resolve one RFC 6901 pointer for tests and integrations.

    Raises:
        KeyError: If an object token does not exist.
        IndexError: If a list index does not exist.
        ValueError: If the pointer syntax or container type is invalid.
    """

    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise ValueError("JSON Pointer must be empty or start with '/'.")
    current = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit():
                raise ValueError(f"List token {token!r} is not a non-negative index.")
            current = current[int(token)]
        else:
            raise ValueError(f"Pointer descends through scalar at token {token!r}.")
    return current
