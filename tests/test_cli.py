"""End-to-end CLI behavior through the installed command boundary."""

from __future__ import annotations

from pathlib import Path

from rangespec.cli import EXIT_INVALID, EXIT_SUCCESS, main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VALID = PROJECT_ROOT / "examples" / "gateway-valid.json"
REVISED = PROJECT_ROOT / "examples" / "gateway-revised.json"


def test_validate_cli_reports_execution_ready(capsys: object) -> None:
    """The documented fixed-time example succeeds through the real CLI."""

    result = main(
        [
            "validate",
            str(VALID),
            "--execution-ready",
            "--at",
            "2026-10-08T20:00:00Z",
        ]
    )
    assert result == EXIT_SUCCESS
    output = capsys.readouterr()  # type: ignore[attr-defined]
    assert "VALID execution-ready" in output.out


def test_validate_cli_reports_invalid_status(capsys: object) -> None:
    """A fixed post-window evaluation fails without depending on the wall clock."""

    result = main(
        [
            "validate",
            str(VALID),
            "--execution-ready",
            "--at",
            "2026-10-09T01:00:00Z",
        ]
    )
    assert result == EXIT_INVALID
    output = capsys.readouterr()  # type: ignore[attr-defined]
    assert "SCOPE_EXPIRED" in output.err


def test_diff_cli_reports_bounded_changes(capsys: object) -> None:
    """The revised example produces human-readable redacted paths."""

    result = main(["diff", str(VALID), str(REVISED)])
    assert result == EXIT_SUCCESS
    output = capsys.readouterr()  # type: ignore[attr-defined]
    assert "CHANGED /execution/max_duration_seconds" in output.out
    assert "Different Private Reviewer" not in output.out


def test_normalize_cli_writes_verified_output(tmp_path: object) -> None:
    """The CLI persists normalized output without modifying the source."""

    destination = tmp_path / "normalized.json"  # type: ignore[operator]
    result = main(["normalize", str(VALID), "--output", str(destination)])
    assert result == EXIT_SUCCESS
    assert destination.read_text(encoding="utf-8").endswith("\n")
