"""Behavior tests for bounded JSON input and atomic output."""

from __future__ import annotations

from io import BytesIO

import pytest

from rangespec.errors import InputError, OutputError
from rangespec.io import load_json, write_atomic


def test_load_json_rejects_duplicate_keys() -> None:
    """A duplicate scope key must never be silently resolved."""

    with pytest.raises(InputError, match="Duplicate JSON key") as failure:
        load_json("-", stdin=BytesIO(b'{"status":"draft","status":"approved"}'))
    assert failure.value.code == "INPUT_DUPLICATE_KEY"


def test_load_json_rejects_oversized_input() -> None:
    """The size cap is enforced before parsing or allocating nested structures."""

    with pytest.raises(InputError) as failure:
        load_json("-", stdin=BytesIO(b'{"value":"12345"}'), max_bytes=8)
    assert failure.value.code == "INPUT_TOO_LARGE"


def test_load_json_rejects_non_object_root() -> None:
    """A manifest root must be an object rather than an ambiguous list."""

    with pytest.raises(InputError) as failure:
        load_json("-", stdin=BytesIO(b"[]"))
    assert failure.value.code == "INPUT_ROOT_NOT_OBJECT"


def test_atomic_write_requires_explicit_replace(tmp_path: object) -> None:
    """Existing output is preserved unless the caller explicitly passes force."""

    path = tmp_path / "manifest.json"  # type: ignore[operator]
    path.write_bytes(b"old")
    with pytest.raises(OutputError) as failure:
        write_atomic(path, b"new")
    assert failure.value.code == "OUTPUT_EXISTS"
    assert path.read_bytes() == b"old"

    write_atomic(path, b"new", force=True)
    assert path.read_bytes() == b"new"
