"""Deterministic offline advisory rules used without an AI provider."""

from __future__ import annotations

from typing import Any, cast

from rangespec.advisory import AdvisoryIssue, AdvisoryReport, now_utc_text
from rangespec.types import JSONObject


class LocalAdvisoryProvider:
    """Produce deterministic suggestions that never alter validation results."""

    name = "local"

    def review(self, manifest: JSONObject, *, source_sha256: str) -> AdvisoryReport:
        """Review evidence breadth and explicit limits using local rules.

        Args:
            manifest: Already-redacted, schema-valid manifest.
            source_sha256: Fingerprint of the unredacted source.

        Returns:
            An advisory-only report. Empty issues means no local rule fired, not
            that the authorization is safe or complete.
        """

        issues: list[AdvisoryIssue] = []
        actions = cast(list[dict[str, Any]], manifest["allowed_actions"])
        effects = {cast(str, action["effect"]) for action in actions}
        evidence = cast(dict[str, Any], manifest["evidence"])
        captures = set(cast(list[str], evidence["capture"]))

        if (
            effects & {"write", "configure", "update", "reboot"}
            and "simulator-state" not in captures
        ):
            issues.append(
                AdvisoryIssue(
                    severity="warning",
                    code="SIMULATOR_STATE_NOT_CAPTURED",
                    path="/evidence/capture",
                    message="State-changing actions lack simulator-state evidence.",
                    recommendation="Capture simulator state before, during, and after each action.",
                )
            )
        if any(action["protocol"] != "local" for action in actions) and "network" not in captures:
            issues.append(
                AdvisoryIssue(
                    severity="warning",
                    code="NETWORK_EVIDENCE_NOT_CAPTURED",
                    path="/evidence/capture",
                    message="Network protocols are in scope but network evidence is not captured.",
                    recommendation=(
                        "Add network capture or document why another source is authoritative."
                    ),
                )
            )
        prohibited = cast(list[str], manifest["prohibited_actions"])
        if len(prohibited) < 2:
            issues.append(
                AdvisoryIssue(
                    severity="info",
                    code="PROHIBITIONS_NARROW",
                    path="/prohibited_actions",
                    message="Only one prohibited action is explicit.",
                    recommendation=(
                        "Review destructive, availability, external-service, "
                        "and live-system exclusions."
                    ),
                )
            )
        retention_days = cast(int, evidence["retention_days"])
        if retention_days > 365:
            issues.append(
                AdvisoryIssue(
                    severity="info",
                    code="RETENTION_LONG",
                    path="/evidence/retention_days",
                    message="Evidence retention exceeds one year.",
                    recommendation=(
                        "Confirm the duration is necessary for this evidence classification."
                    ),
                )
            )

        summary = (
            f"Local advisory review found {len(issues)} completeness issue(s). "
            "This result does not authorize execution."
        )
        return AdvisoryReport(
            provider=self.name,
            model=None,
            source_sha256=source_sha256,
            summary=summary,
            issues=tuple(issues),
            assumptions=(
                "The manifest passed schema validation before review.",
                "The reviewer has not verified approver identity or legal authority.",
            ),
            generated_at=now_utc_text(),
        )
