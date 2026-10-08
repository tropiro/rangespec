"""Optional Claude structured-output advisory provider."""

from __future__ import annotations

import importlib
import json
import os
from collections.abc import Callable
from typing import Any, cast

from rangespec.advisory import ADVISORY_SCHEMA, AdvisoryReport, report_from_payload
from rangespec.canonical import canonical_bytes
from rangespec.errors import ProviderError
from rangespec.types import JSONObject

ClientFactory = Callable[[], Any]
MAX_PROVIDER_INPUT_BYTES = 131_072


class AnthropicAdvisoryProvider:
    """Ask Claude for a structured, non-authoritative completeness review.

    The caller must redact the manifest first. This class never accepts an API
    key argument, preventing credentials from entering command history or report
    provenance. The official SDK reads ``ANTHROPIC_API_KEY`` from the process
    environment.
    """

    name = "anthropic"

    def __init__(
        self,
        *,
        model: str | None = None,
        client_factory: ClientFactory | None = None,
    ) -> None:
        """Configure a model and optional injected client for isolated tests."""

        self.model = model or os.environ.get("ANTHROPIC_MODEL")
        self._client_factory = client_factory

    def _client(self) -> Any:
        """Create the official SDK client lazily or return an injected fake."""

        if self._client_factory is not None:
            return self._client_factory()
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise ProviderError(
                "PROVIDER_CREDENTIAL_MISSING",
                "ANTHROPIC_API_KEY is not set in the environment.",
            )
        try:
            module = importlib.import_module("anthropic")
        except ModuleNotFoundError as error:
            raise ProviderError(
                "PROVIDER_NOT_INSTALLED",
                "Install the 'anthropic' optional dependency before using this provider.",
            ) from error
        return module.Anthropic(max_retries=2, timeout=30.0)

    def _output_schema(self) -> JSONObject:
        """Return the SDK-normalized schema used for constrained generation."""

        if self._client_factory is not None:
            return ADVISORY_SCHEMA
        module = importlib.import_module("anthropic")
        return cast(JSONObject, module.transform_schema(ADVISORY_SCHEMA))

    def review(self, manifest: JSONObject, *, source_sha256: str) -> AdvisoryReport:
        """Send a redacted manifest to Claude and validate the structured result.

        Raises:
            ProviderError: For missing configuration, SDK/API failure, missing
                text output, invalid JSON, or a schema-invalid response.

        Side effects:
            Makes one metered API request. It writes no local file.
        """

        if not self.model:
            raise ProviderError(
                "PROVIDER_MODEL_MISSING",
                "Pass --model or set ANTHROPIC_MODEL; no model is selected silently.",
            )
        manifest_bytes = canonical_bytes(manifest)
        if len(manifest_bytes) > MAX_PROVIDER_INPUT_BYTES:
            raise ProviderError(
                "PROVIDER_INPUT_TOO_LARGE",
                f"Redacted provider input exceeds {MAX_PROVIDER_INPUT_BYTES} bytes.",
                details={
                    "actual_bytes": len(manifest_bytes),
                    "max_bytes": MAX_PROVIDER_INPUT_BYTES,
                },
            )
        prompt = (
            "Review this redacted RangeSpec manifest only for incomplete assumptions, "
            "contradictory limits, missing stop/recovery detail, and weak evidence coverage. "
            "Do not authorize execution, propose exploit steps, or infer facts not present.\n\n"
            + manifest_bytes.decode("utf-8")
        )
        try:
            response = self._client().messages.create(
                model=self.model,
                max_tokens=1800,
                system=(
                    "You are an advisory reviewer for controlled security-range manifests. "
                    "Your output is non-authoritative and must remain within the supplied scope."
                ),
                messages=[{"role": "user", "content": prompt}],
                output_config={
                    "format": {
                        "type": "json_schema",
                        "schema": self._output_schema(),
                    }
                },
            )
        except ProviderError:
            raise
        except Exception as error:  # The SDK exposes several transport and API exception types.
            raise ProviderError(
                "PROVIDER_REQUEST_FAILED",
                f"Anthropic request failed with {type(error).__name__}.",
            ) from error

        try:
            text_blocks = [
                cast(str, block.text)
                for block in cast(list[Any], response.content)
                if getattr(block, "type", None) == "text"
            ]
            if len(text_blocks) != 1:
                raise ValueError("Expected exactly one structured text block.")
            payload = cast(JSONObject, json.loads(text_blocks[0]))
            report = report_from_payload(
                payload,
                provider=self.name,
                model=self.model,
                source_sha256=source_sha256,
                request_id=getattr(response, "_request_id", None),
            )
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise ProviderError(
                "PROVIDER_RESPONSE_INVALID",
                "Anthropic response did not satisfy the advisory schema.",
            ) from error
        return report
