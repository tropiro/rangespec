"""Deterministic JSON serialization and content fingerprints."""

from __future__ import annotations

import hashlib
import json

from rangespec.types import JSONValue


def canonical_bytes(value: JSONValue) -> bytes:
    """Serialize one JSON value into stable UTF-8 bytes.

    Object keys are sorted, insignificant whitespace is removed, Unicode remains
    readable, and non-standard numbers are refused. List order remains semantic.
    """

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def pretty_bytes(value: JSONValue) -> bytes:
    """Serialize one JSON value for reviewed files with a trailing newline."""

    text = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    )
    return f"{text}\n".encode()


def fingerprint(value: JSONValue) -> str:
    """Return the lowercase SHA-256 digest of canonical JSON bytes."""

    return hashlib.sha256(canonical_bytes(value)).hexdigest()
