"""Behavior tests for local and Claude advisory provider boundaries."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest

from rangespec.canonical import fingerprint
from rangespec.errors import ProviderError
from rangespec.providers.anthropic import MAX_PROVIDER_INPUT_BYTES, AnthropicAdvisoryProvider
from rangespec.providers.local import LocalAdvisoryProvider
from rangespec.redaction import redact_manifest
from rangespec.types import JSONObject


def test_local_review_is_clean_for_reviewed_example(valid_manifest: JSONObject) -> None:
    """The complete example triggers no deterministic completeness suggestion."""

    report = LocalAdvisoryProvider().review(
        redact_manifest(valid_manifest),
        source_sha256=fingerprint(valid_manifest),
    )
    assert report.provider == "local"
    assert report.issues == ()
    assert report.to_dict()["authority"] == "advisory-only"


def test_local_review_detects_missing_network_capture(valid_manifest: JSONObject) -> None:
    """Network protocol actions should preserve corresponding network evidence."""

    evidence = cast(dict[str, Any], valid_manifest["evidence"])
    evidence["capture"] = [
        item for item in cast(list[str], evidence["capture"]) if item != "network"
    ]
    report = LocalAdvisoryProvider().review(
        redact_manifest(valid_manifest),
        source_sha256=fingerprint(valid_manifest),
    )
    assert "NETWORK_EVIDENCE_NOT_CAPTURED" in {issue.code for issue in report.issues}


def test_anthropic_provider_validates_structured_result(valid_manifest: JSONObject) -> None:
    """A structured fake proves the live adapter contract without a network call."""

    payload = {
        "summary": "One assumption should be made explicit.",
        "issues": [
            {
                "severity": "info",
                "code": "TIME_SOURCE_UNSTATED",
                "path": "/evidence",
                "message": "The evidence clock source is not stated.",
                "recommendation": "Name the local time authority used by all evidence sources.",
            }
        ],
        "assumptions": ["The supplied document is already redacted."],
    }

    class FakeMessages:
        """Capture the request and return one SDK-shaped text block."""

        def __init__(self) -> None:
            self.kwargs: dict[str, Any] = {}

        def create(self, **kwargs: Any) -> SimpleNamespace:
            """Return schema-compatible JSON without external I/O."""

            self.kwargs = kwargs
            block = SimpleNamespace(type="text", text=json.dumps(payload))
            return SimpleNamespace(content=[block], _request_id="req_test")

    messages = FakeMessages()
    client = SimpleNamespace(messages=messages)
    provider = AnthropicAdvisoryProvider(
        model="claude-test",
        client_factory=lambda: client,
    )
    safe_manifest = redact_manifest(valid_manifest)
    report = provider.review(safe_manifest, source_sha256=fingerprint(valid_manifest))

    assert report.provider == "anthropic"
    assert report.model == "claude-test"
    assert report.request_id == "req_test"
    assert report.issues[0].code == "TIME_SOURCE_UNSTATED"
    assert messages.kwargs["output_config"]["format"]["type"] == "json_schema"
    assert "Example Range Owner" not in cast(str, messages.kwargs["messages"][0]["content"])


def test_anthropic_provider_caps_redacted_input() -> None:
    """A metered provider never receives an unbounded manifest payload."""

    provider = AnthropicAdvisoryProvider(
        model="claude-test",
        client_factory=lambda: SimpleNamespace(),
    )
    oversized = cast(JSONObject, {"blob": "x" * (MAX_PROVIDER_INPUT_BYTES + 1)})
    with pytest.raises(ProviderError) as failure:
        provider.review(oversized, source_sha256="0" * 64)
    assert failure.value.code == "PROVIDER_INPUT_TOO_LARGE"
