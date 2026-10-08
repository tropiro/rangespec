"""Command-line boundary for RangeSpec validation and artifact operations."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any, cast

from rangespec import __version__
from rangespec.canonical import fingerprint, pretty_bytes
from rangespec.diffing import diff_manifests, human_diff
from rangespec.errors import InputError, OutputError, ProviderError, RangeSpecError
from rangespec.io import load_json, write_atomic, write_text
from rangespec.providers.anthropic import AnthropicAdvisoryProvider
from rangespec.providers.base import AdvisoryProvider
from rangespec.providers.local import LocalAdvisoryProvider
from rangespec.redaction import redact_manifest, redacted_export
from rangespec.schema import schema_text
from rangespec.types import JSONObject
from rangespec.validation import parse_evaluation_time, validate_manifest

EXIT_SUCCESS = 0
EXIT_INTERNAL = 1
EXIT_INVALID = 2
EXIT_IO = 3
EXIT_PROVIDER = 4


def _json_text(value: Any) -> str:
    """Render stable reviewed JSON for CLI output."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)


def _build_parser() -> argparse.ArgumentParser:
    """Create the complete CLI parser without reading process state."""

    parser = argparse.ArgumentParser(
        prog="rangespec",
        description="Validate and review bounded authorization manifests for security ranges.",
        epilog=(
            "Exit codes: 0 success, 1 internal failure, 2 invalid manifest, "
            "3 input/output failure, 4 advisory-provider failure."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="Validate one manifest.")
    validate.add_argument("manifest", help="JSON manifest path or '-' for stdin.")
    validate.add_argument(
        "--execution-ready",
        action="store_true",
        help="Require active approval, non-public targets, evidence, and time-window readiness.",
    )
    validate.add_argument(
        "--at",
        help="Evaluate readiness at this ISO 8601 timestamp instead of the current clock.",
    )
    validate.add_argument("--json", action="store_true", help="Emit a machine-readable report.")

    normalize = subparsers.add_parser("normalize", help="Write stable reviewed JSON.")
    normalize.add_argument("manifest", help="JSON manifest path or '-' for stdin.")
    normalize.add_argument("--output", "-o", help="Output path; default is stdout.")
    normalize.add_argument("--force", action="store_true", help="Replace an existing output file.")

    fingerprint_parser = subparsers.add_parser(
        "fingerprint", help="Print the canonical SHA-256 fingerprint."
    )
    fingerprint_parser.add_argument("manifest", help="JSON manifest path or '-' for stdin.")
    fingerprint_parser.add_argument(
        "--json", action="store_true", help="Emit a machine-readable result."
    )

    redact = subparsers.add_parser("redact", help="Create a fail-closed redacted export.")
    redact.add_argument("manifest", help="JSON manifest path or '-' for stdin.")
    redact.add_argument("--output", "-o", help="Output path; default is stdout.")
    redact.add_argument("--force", action="store_true", help="Replace an existing output file.")

    diff = subparsers.add_parser("diff", help="Compare two manifests after redaction.")
    diff.add_argument("before", help="Earlier JSON manifest path.")
    diff.add_argument("after", help="Later JSON manifest path.")
    diff.add_argument("--json", action="store_true", help="Emit redacted values and metadata.")

    review = subparsers.add_parser("review", help="Run an advisory-only completeness review.")
    review.add_argument("manifest", help="JSON manifest path or '-' for stdin.")
    review.add_argument(
        "--provider",
        choices=("local", "anthropic"),
        default="local",
        help="Review provider; local is deterministic and performs no network request.",
    )
    review.add_argument(
        "--model",
        help="Anthropic model ID. Defaults to ANTHROPIC_MODEL; never selected silently.",
    )
    review.add_argument("--output", "-o", help="Output path; default is stdout.")
    review.add_argument("--force", action="store_true", help="Replace an existing output file.")

    subparsers.add_parser("schema", help="Print the bundled version 0.1 JSON Schema.")
    return parser


def _load_schema_valid_manifest(source: str) -> JSONObject:
    """Load a manifest and refuse operations when base validation fails."""

    manifest = load_json(source)
    report = validate_manifest(manifest)
    if not report.valid:
        raise InputError(
            "MANIFEST_INVALID",
            "Manifest must pass validation before this operation.",
            path=source,
            details={"issues": [issue.to_dict() for issue in report.issues]},
        )
    return manifest


def _persist_or_print(value: JSONObject, *, output: str | None, force: bool) -> None:
    """Print reviewed JSON or atomically persist it to the requested path."""

    content = pretty_bytes(value)
    if output is None:
        sys.stdout.buffer.write(content)
        return
    write_atomic(output, content, force=force)


def _command_validate(args: argparse.Namespace) -> int:
    """Execute the validate command and return its process status."""

    manifest = load_json(cast(str, args.manifest))
    evaluation_time = None
    if args.at:
        try:
            evaluation_time = parse_evaluation_time(cast(str, args.at))
        except ValueError as error:
            raise InputError(
                "EVALUATION_TIME_INVALID",
                "--at must be an ISO 8601 timestamp with a UTC offset.",
                path="--at",
            ) from error
    report = validate_manifest(
        manifest,
        require_execution_ready=cast(bool, args.execution_ready),
        at=evaluation_time,
    )
    if args.json:
        write_text(sys.stdout, _json_text(report.to_dict()))
    elif report.valid:
        state = "execution-ready" if report.execution_ready else "valid"
        write_text(sys.stdout, f"VALID {state}: {args.manifest}")
    else:
        for issue in report.issues:
            path = issue.path or "/"
            write_text(sys.stderr, f"{issue.code} {path}: {issue.message}")
    return EXIT_SUCCESS if report.valid else EXIT_INVALID


def _command_normalize(args: argparse.Namespace) -> int:
    """Execute deterministic normalization."""

    manifest = _load_schema_valid_manifest(cast(str, args.manifest))
    _persist_or_print(
        manifest,
        output=cast(str | None, args.output),
        force=cast(bool, args.force),
    )
    return EXIT_SUCCESS


def _command_fingerprint(args: argparse.Namespace) -> int:
    """Execute canonical fingerprinting."""

    manifest = _load_schema_valid_manifest(cast(str, args.manifest))
    digest = fingerprint(manifest)
    if args.json:
        write_text(sys.stdout, _json_text({"algorithm": "sha256", "sha256": digest}))
    else:
        write_text(sys.stdout, digest)
    return EXIT_SUCCESS


def _command_redact(args: argparse.Namespace) -> int:
    """Execute fail-closed redaction and wrapped export generation."""

    manifest = _load_schema_valid_manifest(cast(str, args.manifest))
    _persist_or_print(
        redacted_export(manifest),
        output=cast(str | None, args.output),
        force=cast(bool, args.force),
    )
    return EXIT_SUCCESS


def _command_diff(args: argparse.Namespace) -> int:
    """Execute redacted semantic comparison."""

    before = _load_schema_valid_manifest(cast(str, args.before))
    after = _load_schema_valid_manifest(cast(str, args.after))
    result = diff_manifests(before, after)
    if args.json:
        write_text(sys.stdout, _json_text(result))
    else:
        write_text(sys.stdout, human_diff(result))
    return EXIT_SUCCESS


def _provider(name: str, model: str | None) -> AdvisoryProvider:
    """Construct one declared advisory provider without silent fallback."""

    if name == "local":
        return LocalAdvisoryProvider()
    if name == "anthropic":
        return AnthropicAdvisoryProvider(model=model)
    raise ProviderError("PROVIDER_UNKNOWN", f"Unknown provider {name!r}.")


def _command_review(args: argparse.Namespace) -> int:
    """Execute advisory review after validation and redaction."""

    manifest = _load_schema_valid_manifest(cast(str, args.manifest))
    safe_manifest = redact_manifest(manifest)
    report = _provider(cast(str, args.provider), cast(str | None, args.model)).review(
        safe_manifest,
        source_sha256=fingerprint(manifest),
    )
    _persist_or_print(
        cast(JSONObject, report.to_dict()),
        output=cast(str | None, args.output),
        force=cast(bool, args.force),
    )
    return EXIT_SUCCESS


def _emit_expected_error(error: RangeSpecError) -> None:
    """Render one expected failure without a traceback or sensitive context."""

    path = f" {error.path}" if error.path else ""
    write_text(sys.stderr, f"{error.code}{path}: {error.message}")
    if error.details:
        write_text(sys.stderr, _json_text(error.details))


def main(argv: Sequence[str] | None = None) -> int:
    """Run the RangeSpec CLI and convert named failures to stable exit codes.

    Args:
        argv: Arguments without the executable name; defaults to ``sys.argv``.

    Returns:
        A documented process exit code. This function does not call ``sys.exit``
        so it remains directly testable.
    """

    parser = _build_parser()
    args = parser.parse_args(argv)
    commands = {
        "validate": _command_validate,
        "normalize": _command_normalize,
        "fingerprint": _command_fingerprint,
        "redact": _command_redact,
        "diff": _command_diff,
        "review": _command_review,
    }
    if args.command == "schema":
        write_text(sys.stdout, schema_text())
        return EXIT_SUCCESS
    try:
        command = commands[cast(str, args.command)]
        return command(args)
    except ProviderError as error:
        _emit_expected_error(error)
        return EXIT_PROVIDER
    except (InputError, OutputError) as error:
        _emit_expected_error(error)
        return EXIT_IO
    except (KeyError, TypeError, ValueError) as error:
        # Valid schema inputs should make these paths unreachable. Keeping the
        # top-level boundary named avoids exposing a traceback in automation.
        write_text(sys.stderr, f"INTERNAL_ERROR: {type(error).__name__}")
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
