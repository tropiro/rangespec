"""Behavior tests for schema and execution-readiness validation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, cast

from rangespec.types import JSONObject
from rangespec.validation import validate_manifest

AT = datetime(2026, 10, 8, 20, 0, tzinfo=timezone.utc)


def _codes(manifest: JSONObject, *, execution_ready: bool = False) -> set[str]:
    """Return issue codes for focused assertions."""

    report = validate_manifest(manifest, require_execution_ready=execution_ready, at=AT)
    return {issue.code for issue in report.issues}


def test_valid_example_is_execution_ready(valid_manifest: JSONObject) -> None:
    """The reviewed training example demonstrates the complete happy path."""

    report = validate_manifest(valid_manifest, require_execution_ready=True, at=AT)
    assert report.valid is True
    assert report.execution_ready is True
    assert report.issues == ()


def test_unknown_fields_fail_schema(valid_manifest: JSONObject) -> None:
    """Undeclared fields cannot create a second unreviewed interpretation path."""

    valid_manifest["quiet_fallback"] = True
    assert "UNDECLARED_FIELD" in _codes(valid_manifest)


def test_expired_window_is_not_execution_ready(valid_manifest: JSONObject) -> None:
    """A structurally valid historical manifest cannot authorize current work."""

    at = datetime(2026, 10, 9, 1, 0, tzinfo=timezone.utc)
    report = validate_manifest(valid_manifest, require_execution_ready=True, at=at)
    assert report.valid is False
    assert report.execution_ready is False
    assert "SCOPE_EXPIRED" in {issue.code for issue in report.issues}


def test_public_target_is_rejected_for_execution(valid_manifest: JSONObject) -> None:
    """Execution-ready manifests remain confined to non-global networks."""

    targets = cast(list[dict[str, Any]], valid_manifest["targets"])
    targets[0]["addresses"] = ["8.8.8.8/32"]
    assert "PUBLIC_TARGET_FORBIDDEN" in _codes(valid_manifest, execution_ready=True)


def test_action_must_use_target_protocol(valid_manifest: JSONObject) -> None:
    """An action cannot smuggle in a protocol absent from its target boundary."""

    actions = cast(list[dict[str, Any]], valid_manifest["allowed_actions"])
    actions[0]["protocol"] = "ssh"
    assert "ACTION_PROTOCOL_UNDECLARED" in _codes(valid_manifest)


def test_duplicate_action_ids_are_rejected(valid_manifest: JSONObject) -> None:
    """Action identifiers remain unambiguous for approvals and evidence."""

    actions = cast(list[dict[str, Any]], valid_manifest["allowed_actions"])
    actions[1]["action_id"] = actions[0]["action_id"]
    assert "ACTION_ID_DUPLICATE" in _codes(valid_manifest)


def test_revoked_approval_prevents_execution(valid_manifest: JSONObject) -> None:
    """A manifest containing an explicit revocation cannot be execution-ready."""

    approvals = cast(list[dict[str, Any]], valid_manifest["approvals"])
    approvals[0]["decision"] = "revoked"
    codes = _codes(valid_manifest, execution_ready=True)
    assert "APPROVAL_NOT_ACTIVE" in codes
    assert "APPROVAL_MISSING" in codes


def test_invalid_timestamp_fails_base_validation(valid_manifest: JSONObject) -> None:
    """Timestamp checking does not depend on optional jsonschema format extras."""

    validity = cast(dict[str, Any], valid_manifest["validity"])
    validity["not_after"] = "not-a-date"
    assert "VALUE_FORMAT_INVALID" in _codes(valid_manifest)
