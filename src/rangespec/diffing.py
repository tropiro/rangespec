"""Semantic comparison of two manifests after fail-closed redaction."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, cast

from rangespec.canonical import fingerprint
from rangespec.redaction import redact_manifest
from rangespec.types import JSONObject, JSONValue


@dataclass(frozen=True)
class Change:
    """One added, removed, or changed JSON value."""

    path: str
    kind: str
    before: JSONValue = None
    after: JSONValue = None

    def to_dict(self) -> dict[str, JSONValue]:
        """Return the change in a stable JSON-safe shape."""

        return cast(dict[str, JSONValue], asdict(self))


def _token(value: str | int) -> str:
    """Encode one path component as an RFC 6901 token."""

    return str(value).replace("~", "~0").replace("/", "~1")


def _walk(before: JSONValue, after: JSONValue, path: str, changes: list[Change]) -> None:
    """Recursively append semantic differences without mutating either input."""

    if type(before) is not type(after):
        changes.append(Change(path=path, kind="changed", before=before, after=after))
        return
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(before.keys() - after.keys()):
            changes.append(Change(path=f"{path}/{_token(key)}", kind="removed", before=before[key]))
        for key in sorted(after.keys() - before.keys()):
            changes.append(Change(path=f"{path}/{_token(key)}", kind="added", after=after[key]))
        for key in sorted(before.keys() & after.keys()):
            _walk(before[key], after[key], f"{path}/{_token(key)}", changes)
        return
    if isinstance(before, list) and isinstance(after, list):
        shared_length = min(len(before), len(after))
        for index in range(shared_length):
            _walk(before[index], after[index], f"{path}/{index}", changes)
        for index in range(shared_length, len(before)):
            changes.append(Change(path=f"{path}/{index}", kind="removed", before=before[index]))
        for index in range(shared_length, len(after)):
            changes.append(Change(path=f"{path}/{index}", kind="added", after=after[index]))
        return
    if before != after:
        changes.append(Change(path=path, kind="changed", before=before, after=after))


def diff_manifests(before: JSONObject, after: JSONObject) -> JSONObject:
    """Compare two manifests after applying each one's redaction policy.

    Returns:
        Source fingerprints plus ordered, redacted changes.

    Raises:
        InputError: Propagated when either redaction policy names a missing path.
    """

    safe_before = redact_manifest(before)
    safe_after = redact_manifest(after)
    changes: list[Change] = []
    _walk(safe_before, safe_after, "", changes)
    return {
        "diff_version": "0.1",
        "before_sha256": fingerprint(before),
        "after_sha256": fingerprint(after),
        "changes": [change.to_dict() for change in changes],
    }


def human_diff(result: JSONObject) -> str:
    """Render a redacted diff as compact review text."""

    changes = cast(list[dict[str, Any]], result["changes"])
    if not changes:
        return "No semantic changes."
    lines: list[str] = []
    for change in changes:
        path = cast(str, change["path"]) or "/"
        lines.append(f"{cast(str, change['kind']).upper():7} {path}")
    return "\n".join(lines)
