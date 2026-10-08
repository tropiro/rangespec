"""Behavior tests for fingerprints, redaction, and semantic diffs."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, cast

import pytest

from rangespec.canonical import fingerprint
from rangespec.diffing import diff_manifests
from rangespec.errors import InputError
from rangespec.redaction import REDACTED, redact_manifest
from rangespec.types import JSONObject


def test_fingerprint_ignores_object_order_and_whitespace(valid_manifest: JSONObject) -> None:
    """Formatting changes do not change the scope fingerprint."""

    serialized = json.dumps(valid_manifest, indent=7)
    reordered = cast(JSONObject, json.loads(serialized))
    reordered = dict(reversed(list(reordered.items())))
    assert fingerprint(valid_manifest) == fingerprint(reordered)


def test_redaction_does_not_mutate_source(valid_manifest: JSONObject) -> None:
    """Exports hide declared names while source evidence remains unchanged."""

    original = deepcopy(valid_manifest)
    redacted = redact_manifest(valid_manifest)
    owners = cast(list[dict[str, Any]], redacted["owners"])
    approvals = cast(list[dict[str, Any]], redacted["approvals"])
    assert owners[0]["name"] == REDACTED
    assert approvals[0]["approved_by"] == REDACTED
    assert valid_manifest == original


def test_missing_redaction_path_fails_closed(valid_manifest: JSONObject) -> None:
    """A stale redaction policy cannot silently export an unredacted document."""

    evidence = cast(dict[str, Any], valid_manifest["evidence"])
    evidence["redact_paths"] = ["/missing/value"]
    with pytest.raises(InputError) as failure:
        redact_manifest(valid_manifest)
    assert failure.value.code == "REDACTION_PATH_MISSING"


def test_diff_never_exposes_redacted_identity(valid_manifest: JSONObject) -> None:
    """Identity changes are represented only by the redaction placeholder."""

    revised = deepcopy(valid_manifest)
    owners = cast(list[dict[str, Any]], revised["owners"])
    owners[0]["name"] = "Private Replacement"
    result = diff_manifests(valid_manifest, revised)
    serialized = json.dumps(result)
    assert "Private Replacement" not in serialized
    assert "Example Range Owner" not in serialized
    assert cast(list[Any], result["changes"]) == []
