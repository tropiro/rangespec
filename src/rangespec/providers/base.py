"""Provider protocol for advisory-only manifest reviews."""

from __future__ import annotations

from typing import Protocol

from rangespec.advisory import AdvisoryReport
from rangespec.types import JSONObject


class AdvisoryProvider(Protocol):
    """Review a redacted manifest without changing authorization state."""

    def review(self, manifest: JSONObject, *, source_sha256: str) -> AdvisoryReport:
        """Return a completeness review for one redacted manifest."""
