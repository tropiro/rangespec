"""Fail-closed manifest redaction for exports and advisory providers."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, cast

from rangespec.canonical import fingerprint
from rangespec.errors import InputError
from rangespec.types import JSONObject, JSONValue

REDACTED = "[REDACTED]"
SENSITIVE_KEY_FRAGMENTS = {
    "api_key",
    "credential",
    "passphrase",
    "password",
    "private_key",
    "secret",
    "token",
}


def _decode_pointer(pointer: str) -> list[str]:
    """Decode one RFC 6901 JSON Pointer into tokens."""

    if not pointer.startswith("/"):
        raise InputError(
            "REDACTION_PATH_INVALID",
            "Redaction paths must start with '/'.",
            path=pointer,
        )
    return [token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")]


def _redact_pointer(document: JSONValue, pointer: str) -> None:
    """Replace the value at one pointer or fail if it cannot be resolved."""

    tokens = _decode_pointer(pointer)
    if not tokens:
        raise InputError(
            "REDACTION_PATH_INVALID",
            "Redacting the entire document is not supported.",
            path=pointer,
        )
    current = document
    for token in tokens[:-1]:
        if isinstance(current, dict):
            if token not in current:
                raise InputError(
                    "REDACTION_PATH_MISSING",
                    "Declared redaction path does not exist.",
                    path=pointer,
                )
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or int(token) >= len(current):
                raise InputError(
                    "REDACTION_PATH_MISSING",
                    "Declared redaction list index does not exist.",
                    path=pointer,
                )
            current = current[int(token)]
        else:
            raise InputError(
                "REDACTION_PATH_MISSING",
                "Declared redaction path descends through a scalar value.",
                path=pointer,
            )

    final = tokens[-1]
    if isinstance(current, dict):
        if final not in current:
            raise InputError(
                "REDACTION_PATH_MISSING",
                "Declared redaction path does not exist.",
                path=pointer,
            )
        current[final] = REDACTED
    elif isinstance(current, list):
        if not final.isdigit() or int(final) >= len(current):
            raise InputError(
                "REDACTION_PATH_MISSING",
                "Declared redaction list index does not exist.",
                path=pointer,
            )
        current[int(final)] = REDACTED
    else:
        raise InputError(
            "REDACTION_PATH_MISSING",
            "Declared redaction path resolves through a scalar value.",
            path=pointer,
        )


def _redact_sensitive_keys(value: JSONValue) -> None:
    """Replace values whose normalized key name indicates a secret."""

    if isinstance(value, dict):
        for key in list(value):
            normalized = key.casefold().replace("-", "_")
            if any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS):
                value[key] = REDACTED
            else:
                _redact_sensitive_keys(value[key])
    elif isinstance(value, list):
        for item in value:
            _redact_sensitive_keys(item)


def redact_manifest(manifest: JSONObject) -> JSONObject:
    """Return a deep-copied manifest with all declared redactions applied.

    Raises:
        InputError: If a declared path is missing or invalid. Failing closed
            prevents a stale redaction rule from silently exporting data.

    Side effects:
        None. ``manifest`` is never mutated.
    """

    redacted = deepcopy(manifest)
    evidence = cast(dict[str, Any], redacted["evidence"])
    for pointer in cast(list[str], evidence["redact_paths"]):
        _redact_pointer(redacted, pointer)
    _redact_sensitive_keys(redacted)
    return redacted


def redacted_export(manifest: JSONObject) -> JSONObject:
    """Wrap a redacted manifest with the source fingerprint for attribution."""

    return {
        "export_version": "0.1",
        "source_sha256": fingerprint(manifest),
        "redacted_manifest": redact_manifest(manifest),
    }
