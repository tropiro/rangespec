"""Bounded JSON input and verified atomic output primitives."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import BinaryIO, TextIO, cast

from rangespec.errors import InputError, OutputError
from rangespec.types import JSONObject, JSONValue

MAX_INPUT_BYTES = 1_048_576
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 20_000


def _reject_duplicate_keys(pairs: Iterable[tuple[str, JSONValue]]) -> JSONObject:
    """Build one object while refusing duplicate keys.

    JSON parsers commonly keep the last duplicate key, which can let a reviewer
    and an executor interpret different scope. This boundary rejects ambiguity.
    """

    result: JSONObject = {}
    for key, value in pairs:
        if key in result:
            raise InputError(
                "INPUT_DUPLICATE_KEY",
                f"Duplicate JSON key {key!r} is not allowed.",
                path=f"/{_escape_pointer_token(key)}",
            )
        result[key] = value
    return result


def _escape_pointer_token(token: str) -> str:
    """Encode one token using RFC 6901 JSON Pointer escaping."""

    return token.replace("~", "~0").replace("/", "~1")


def _read_bounded(stream: BinaryIO, *, source: str, max_bytes: int) -> bytes:
    """Read at most ``max_bytes`` plus one detection byte from a stream."""

    content = stream.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise InputError(
            "INPUT_TOO_LARGE",
            f"Input exceeds the {max_bytes}-byte limit.",
            path=source,
            details={"max_bytes": max_bytes},
        )
    return content


def _measure_json(value: JSONValue) -> tuple[int, int]:
    """Return maximum nesting depth and total node count without recursion."""

    max_depth = 0
    nodes = 0
    stack: list[tuple[JSONValue, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        max_depth = max(max_depth, depth)
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return max_depth, nodes


def load_json(
    source: str | Path,
    *,
    stdin: BinaryIO | None = None,
    max_bytes: int = MAX_INPUT_BYTES,
) -> JSONObject:
    """Load one bounded UTF-8 JSON object from a file or ``-`` for stdin.

    Args:
        source: Filesystem path or ``-``.
        stdin: Binary input used for ``-``; defaults to ``sys.stdin.buffer``.
        max_bytes: Hard input cap applied before JSON parsing.

    Returns:
        The parsed top-level object.

    Raises:
        InputError: For missing files, invalid UTF-8/JSON, duplicate keys,
            excessive depth or node count, or a non-object root.

    Side effects:
        Reads one input stream. It never modifies the source.
    """

    source_text = str(source)
    try:
        if source_text == "-":
            stream = stdin or sys.stdin.buffer
            content = _read_bounded(stream, source="<stdin>", max_bytes=max_bytes)
            display_path = "<stdin>"
        else:
            path = Path(source_text)
            stat = path.stat()
            if stat.st_size > max_bytes:
                raise InputError(
                    "INPUT_TOO_LARGE",
                    f"Input exceeds the {max_bytes}-byte limit.",
                    path=str(path),
                    details={"actual_bytes": stat.st_size, "max_bytes": max_bytes},
                )
            with path.open("rb") as handle:
                content = _read_bounded(handle, source=str(path), max_bytes=max_bytes)
            display_path = str(path)
    except InputError:
        raise
    except OSError as error:
        raise InputError(
            "INPUT_UNREADABLE",
            f"Cannot read input: {error.strerror or error}.",
            path=source_text,
        ) from error

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InputError(
            "INPUT_NOT_UTF8",
            "Input must be valid UTF-8.",
            path=display_path,
            details={"byte_offset": error.start},
        ) from error

    try:
        parsed = cast(
            JSONValue,
            json.loads(
                text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda value: _raise_invalid_number(value),
            ),
        )
    except InputError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        details: dict[str, int] = {}
        if isinstance(error, json.JSONDecodeError):
            details = {"line": error.lineno, "column": error.colno}
        raise InputError(
            "INPUT_INVALID_JSON",
            "Input is not valid JSON.",
            path=display_path,
            details=details,
        ) from error

    if not isinstance(parsed, dict):
        raise InputError(
            "INPUT_ROOT_NOT_OBJECT",
            "A RangeSpec manifest must be a JSON object.",
            path=display_path,
        )

    depth, nodes = _measure_json(parsed)
    if depth > MAX_JSON_DEPTH:
        raise InputError(
            "INPUT_TOO_DEEP",
            f"JSON nesting exceeds the depth limit of {MAX_JSON_DEPTH}.",
            path=display_path,
            details={"actual_depth": depth, "max_depth": MAX_JSON_DEPTH},
        )
    if nodes > MAX_JSON_NODES:
        raise InputError(
            "INPUT_TOO_COMPLEX",
            f"JSON node count exceeds the limit of {MAX_JSON_NODES}.",
            path=display_path,
            details={"actual_nodes": nodes, "max_nodes": MAX_JSON_NODES},
        )
    return parsed


def _raise_invalid_number(value: str) -> None:
    """Reject non-standard JSON constants such as NaN and Infinity."""

    raise InputError(
        "INPUT_INVALID_NUMBER",
        f"Non-standard JSON number {value!r} is not allowed.",
    )


def write_atomic(
    destination: str | Path,
    content: bytes,
    *,
    force: bool = False,
) -> None:
    """Atomically replace a file and verify its bytes after the rename.

    Args:
        destination: File to create or replace.
        content: Exact bytes to persist.
        force: Permit replacement when the destination already exists.

    Raises:
        OutputError: If the destination exists without ``force``, its parent is
            missing, the write fails, or read-back differs.

    Side effects:
        Creates a same-directory temporary file, replaces ``destination``, and
        synchronizes both file and parent directory metadata.
    """

    path = Path(destination)
    parent = path.parent
    if path.exists() and not force:
        raise OutputError(
            "OUTPUT_EXISTS",
            "Output already exists; pass --force to replace it.",
            path=str(path),
        )
    if not parent.is_dir():
        raise OutputError(
            "OUTPUT_PARENT_MISSING",
            "Output parent directory does not exist.",
            path=str(parent),
        )

    temporary_path: Path | None = None
    try:
        file_descriptor, temporary_name = tempfile.mkstemp(
            dir=parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(file_descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        temporary_path = None
        if os.name != "nt":
            directory_descriptor = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        if path.read_bytes() != content:
            raise OutputError(
                "OUTPUT_VERIFY_FAILED",
                "Output bytes changed during persistence.",
                path=str(path),
            )
    except OutputError:
        raise
    except OSError as error:
        raise OutputError(
            "OUTPUT_WRITE_FAILED",
            f"Cannot persist output: {error.strerror or error}.",
            path=str(path),
        ) from error
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def write_text(stream: TextIO, content: str) -> None:
    """Write text to a supplied stream and ensure exactly one trailing newline."""

    stream.write(content.rstrip("\n"))
    stream.write("\n")
